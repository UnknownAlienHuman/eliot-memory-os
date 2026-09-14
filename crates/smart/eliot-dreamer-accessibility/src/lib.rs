//! Single-axis accessibility/influence adjustment candidate (A-29).
//!
//! Pure candidate-only owner of one reversible adjustment to exactly one
//! axis: accessibility/retrievability/exposure, or allowed influence within
//! an exact scope. The handler proposes; it never persists, mutates graph,
//! index, Context, or cue state, revokes grants, erases, queries stores or
//! providers, or exercises authority, effects, or finish semantics.
//!
//! Cell `smart.dreamer.accessibility`, order 29. Inputs are immutable and
//! caller-supplied; every clock observation, policy binding, and digest is
//! explicit. The A-05 receipt and the seven preservation dimensions are
//! checked intrinsically and never re-executed here.

#![forbid(unsafe_code)]

use eliot_contracts::{StateFence, canonical_json_bytes, sha256_hex};
use eliot_dreamer_contracts::CurationRejectionCode;
use eliot_dreamer_contracts::{
    CurationKind, GroundedDreamDraft, PreservationReport, TargetDenominator, ValidatedCurationItem,
    ValidationReceipt, is_hex64_lower,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Independent bounds (no cross-subsidy between dimensions).
// ---------------------------------------------------------------------------

/// Maximum affected projections/decisions/dependents admitted in one request.
pub const MAX_AFFECTED: usize = 64;
/// Maximum protection reasons admitted in one request.
pub const MAX_PROTECTIONS: usize = 32;
/// Maximum negative-memory entries admitted in one request.
pub const MAX_NEGATIVE_ENTRIES: usize = 32;
/// Maximum closure dependent refs admitted in one request.
pub const MAX_CLOSURE_REFS: usize = 256;
/// Maximum bytes for any single text field.
pub const MAX_TEXT_BYTES: usize = 1024;
/// Maximum bytes for any handle field.
pub const MAX_HANDLE_BYTES: usize = 128;
/// Maximum aggregate input bytes across all text fields.
pub const MAX_TOTAL_BYTES: usize = 1_048_576;
/// Redaction ceiling for values echoed into errors and notes.
pub const MAX_REDACTED_CHARS: usize = 128;

// ---------------------------------------------------------------------------
// Small pure helpers (no ambient clock, no allocation of authority).
// ---------------------------------------------------------------------------

fn has_control(value: &str) -> bool {
    value.chars().any(char::is_control)
}

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

fn is_sorted_unique(values: &[String]) -> bool {
    let mut index = 0usize;
    while index < values.len() {
        if index > 0 {
            if let (Some(prev), Some(cur)) = (values.get(index - 1), values.get(index)) {
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

fn contains_handle(values: &[String], handle: &str) -> bool {
    values.iter().any(|v| v == handle)
}

fn sorted_set_eq(left: &[String], right: &[String]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    let mut index = 0usize;
    while index < left.len() {
        if left.get(index) != right.get(index) {
            return false;
        }
        index = index.saturating_add(1);
    }
    true
}

fn mentions_authority_grant(note: &str) -> bool {
    let lowered = note.to_lowercase();
    lowered.contains("authoriz")
        || lowered.contains("approv")
        || lowered.contains("mandates use")
        || lowered.contains("guaranteed")
}

// ---------------------------------------------------------------------------
// Public vocabulary.
// ---------------------------------------------------------------------------

/// The single axis this proposal is allowed to move.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
pub enum Axis {
    /// Retrievability, exposure, and surfacing of one subject.
    Accessibility,
    /// Allowed influence of one subject within an exact scope.
    Influence,
}

/// Closed operation applied to the selected axis.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
pub enum AdjustmentOperation {
    /// Raise exposure or widen allowed influence within ceilings.
    Increase,
    /// Lower exposure or narrow allowed influence without deletion.
    Decrease,
    /// Narrow the surfacing or decision scope laterally.
    Narrow,
    /// Restore a named prior revision of the selected axis.
    Restore,
}

/// Closed direction of the proposed move.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
pub enum AdjustmentDirection {
    /// Visibility or influence moves up.
    Raise,
    /// Visibility or influence moves down.
    Lower,
    /// Scope moves laterally without a vertical change.
    Lateral,
}

/// Closed accessibility standing of one subject.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
pub enum AccessibilityStanding {
    /// Fully exposed on every admitted surface.
    Exposed,
    /// Discoverable through query surfaces only.
    Discoverable,
    /// Gated behind verifier-checked access.
    Restricted,
    /// Parked with provenance retained; never a deletion.
    Dormant,
}

/// Closed allowed-influence standing of one subject within its scope.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
pub enum InfluenceStanding {
    /// Full allowed influence within scope and ceilings.
    Full,
    /// Bounded influence with named limits.
    Bounded,
    /// Minimal influence; subject persists with other axes intact.
    Minimal,
    /// Influence withheld; subject and history persist.
    Withheld,
}

/// Closed subject classes admitted to single-axis adjustment.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
pub enum SubjectKind {
    /// One stored memory record.
    StoredRecord,
    /// One derived view over stored records.
    DerivedView,
    /// One index entry pointing at stored records.
    IndexEntry,
    /// One assembled Context entry.
    ContextEntry,
}

/// Closed kinds of affected paths that need exactly one disposition.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
pub enum AffectedPathKind {
    /// A downstream derived artifact.
    Derivative,
    /// A recorded decision that loaded on the subject.
    Decision,
    /// A procedure that consumes the subject.
    Procedure,
    /// A plan that references the subject.
    Plan,
    /// An activation cue bound to the subject.
    Cue,
    /// An assembled Context holding the subject.
    Context,
    /// An operational recovery path for the subject.
    Recovery,
    /// An independent review checkpoint over the subject.
    Review,
}

/// Disposition of one affected path under the proposed adjustment.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
pub enum DependentDispositionKind {
    /// Kept as-is with supporting evidence cited.
    UnchangedWithEvidence,
    /// Adjusted within the owning axis by its owner.
    Adjust,
    /// Must be revalidated against the proposed state.
    Revalidate,
    /// Must be rebuilt against the proposed state.
    Rebuild,
    /// Reconciled against both before and proposed states by its owner.
    ReconcileByOwner,
    /// Cannot be disposed; blocks completeness.
    Blocked,
}

/// Local mirror of the B-SEC1 influence standing (no `eliot-influence` dep).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
pub enum LocalClosureStanding {
    /// Closure reports active influence.
    Active,
    /// Closure reports quarantined influence.
    Quarantined,
    /// Closure reports revoked influence with a reason.
    Revoked,
    /// Closure standing is unknown; never completes.
    Unknown,
}

/// Local mirror of the B-SEC1 revocation reason (no `eliot-influence` dep).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
pub enum LocalRevocationClass {
    /// Origin was revoked.
    SourceRevoked,
    /// Influence was exercised outside its scope.
    WrongScope,
    /// Taint was confirmed.
    Poisoned,
    /// A verifier rejected the lineage.
    VerifierInvalid,
    /// Policy changed under the closure.
    PolicyChanged,
    /// Erasure completed for the origin.
    Erasure,
}

/// Terminal outcome of one single-axis adjustment proposal.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
pub enum AdjustmentOutcome {
    /// Exactly one axis moves with complete evidence and closure.
    Complete,
    /// Non-load-bearing gaps remain with named conditions.
    Partial,
    /// A required protection, closure, inverse, or verifier blocks the move.
    Blocked,
    /// The request is not a single-axis accessibility/influence adjustment.
    Rejected,
    /// Frozen state, closure revision, or before state moved.
    Stale,
    /// Evidence is unknown or partial; the cell abstains.
    Abstention,
}

/// Separate owner references for every axis; ownership never moves here.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AxisOwnerRefs {
    /// Owner of the existence/lifecycle axis.
    pub existence_owner: String,
    /// Owner of the support/assertability axis.
    pub support_owner: String,
    /// Owner of the accessibility axis.
    pub accessibility_owner: String,
    /// Owner of the influence axis.
    pub influence_owner: String,
    /// Owner of the privacy/retention axis.
    pub privacy_owner: String,
    /// Owner of the source-assurance axis.
    pub assurance_owner: String,
}

/// Before/proposed snapshot of the two governed axes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AxisStateSnapshot {
    /// Accessibility standing in this snapshot.
    pub accessibility: AccessibilityStanding,
    /// Influence standing in this snapshot.
    pub influence: InfluenceStanding,
}

/// Exact current projection of one subject across every axis.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CurrentAxisProjection {
    /// Subject handle under adjustment.
    pub subject_handle: String,
    /// Closed subject class.
    pub subject_kind: SubjectKind,
    /// Exact current revision of the subject.
    pub subject_revision: String,
    /// Scope the subject is projected in.
    pub scope_id: String,
    /// Task the subject is projected for.
    pub task_id: String,
    /// Policy the projection is bound to.
    pub policy_id: String,
    /// State fence of the projection.
    pub state_fence: StateFence,
    /// Separate owner reference per axis.
    pub owners: AxisOwnerRefs,
    /// Current accessibility standing (before state).
    pub accessibility: AccessibilityStanding,
    /// Current influence standing (before state).
    pub influence: InfluenceStanding,
}

/// Surfacing footprint an accessibility change touches.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AccessibilitySurface {
    /// Scope the surfacing change applies to.
    pub scope: String,
    /// Audience the surfacing change applies to.
    pub audience: String,
    /// Query surface touched by the change.
    pub query_surface: String,
    /// Assembled-Context surface touched by the change.
    pub context_surface: String,
    /// Index surface touched by the change.
    pub index_surface: String,
}

/// The accessibility half of a single-axis proposal.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
#[allow(clippy::struct_excessive_bools)]
pub struct AccessibilityChange {
    /// Accessibility owner at the before revision.
    pub before_owner: String,
    /// Revision the before state was read at.
    pub before_revision: String,
    /// Standing before the proposed move.
    pub before_state: AccessibilityStanding,
    /// Standing proposed by this move.
    pub proposed_state: AccessibilityStanding,
    /// Surfacing footprint of the move.
    pub surface: AccessibilitySurface,
    /// Grounded reason naming the triggering evidence.
    pub grounded_reason: String,
    /// Protected verifier that retains access after the move.
    pub protected_verifier_access: String,
    /// Privacy ceiling the move stays within.
    pub privacy_ceiling: String,
    /// Expected observable proving the move took effect.
    pub observable: String,
    /// Observation window the observable is checked in.
    pub window_note: String,
    /// Exact inverse restoring the before state.
    pub inverse_note: String,
    /// Explicit expiry; unknown expiry is never filled in.
    pub expiry_ms: Option<u64>,
    /// Per-projection plan naming what each surface shows after the move.
    pub projection_plan: String,
    /// True only for a global dormant parking of the subject.
    pub global_scope: bool,
    /// Raising visibility widens privacy.
    pub widens_privacy: bool,
    /// Raising visibility widens support or assertability.
    pub widens_support: bool,
    /// Raising visibility widens influence.
    pub widens_influence: bool,
    /// Raising visibility widens effect or delivery.
    pub widens_effect: bool,
    /// Lowering visibility hides provenance.
    pub hides_provenance: bool,
    /// Lowering visibility hides audit records.
    pub hides_audit: bool,
    /// Lowering visibility hides counterevidence.
    pub hides_counterevidence: bool,
}

/// The influence half of a single-axis proposal.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
#[allow(clippy::struct_excessive_bools)]
pub struct InfluenceChange {
    /// Influence standing before the proposed move.
    pub current_standing: InfluenceStanding,
    /// Policy the current standing was admitted under.
    pub current_policy_id: String,
    /// Graph note naming the consumed dependency graph.
    pub current_graph_note: String,
    /// Standing proposed by this move.
    pub proposed_standing: InfluenceStanding,
    /// Exact scope the influence move applies to.
    pub scope: String,
    /// Decision record the move is evaluated against.
    pub decision_ref: String,
    /// Effect note bounding what the move may change downstream.
    pub effect_note: String,
    /// Independent review owner for the move.
    pub review_owner_ref: String,
    /// Decision owner accountable for the move.
    pub decision_owner_ref: String,
    /// Note naming how every other axis is preserved.
    pub preserved_other_axes_note: String,
    /// True when an increase stays within every ceiling.
    pub within_ceilings: bool,
    /// True when the move deletes the subject; always rejected.
    pub deletes_subject: bool,
    /// True when one success is claimed as system-wide; always blocked.
    pub claims_system_wide: bool,
}

/// Usage and outcome evidence with explicit denominators.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct UsageAndOutcomeEvidence {
    /// Retrieval attempts observed (denominator for successes).
    pub retrieval_attempts: u64,
    /// Successful retrievals out of `retrieval_attempts`.
    pub retrieval_successes: u64,
    /// Independent outcome observations (denominator for outcome claims).
    pub outcome_observations: u64,
    /// Successful outcomes out of `outcome_observations`.
    pub outcome_successes: u64,
    /// Writer utility note; never authoritative, never counted as evidence.
    pub writer_utility_note: String,
    /// Window the usage counts were observed in.
    pub usage_window_note: String,
    /// True when usage is unknown; unknown usage is never non-use.
    pub unknown_usage: bool,
}

/// One protection reason evaluated by this proposal.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ProtectionReason {
    /// Stable protection identity.
    pub reason_id: String,
    /// Exact trigger naming when the protection applies.
    pub trigger: String,
    /// Mandatory protections fail closed when missing or unknown.
    pub mandatory: bool,
    /// True when the protection requirement is satisfied.
    pub satisfied: bool,
    /// True when the protection state is unknown.
    pub unknown: bool,
    /// Counterevidence ref retained for this protection, if any.
    pub counterevidence_ref: Option<String>,
}

/// One exact-trigger negative-memory entry.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct NegativeMemoryEntry {
    /// Exact trigger; only byte-exact matches retain or extinguish.
    pub trigger: String,
    /// True only with owner-qualified extinction evidence.
    pub extinguished: bool,
    /// Extinction evidence ref; required when `extinguished`.
    pub extinction_evidence_ref: Option<String>,
    /// Reopen evidence ref; keeps the trigger visible with conditions.
    pub reopen_evidence_ref: Option<String>,
}

/// Protection and negative-memory evidence evaluated together.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ProtectionAndNegativeMemory {
    /// Every protection reason in scope (sorted by `reason_id`, unique).
    pub protections: Vec<ProtectionReason>,
    /// Every negative-memory trigger in scope (sorted by `trigger`, unique).
    pub negative_memory: Vec<NegativeMemoryEntry>,
    /// Counterevidence refs retained verbatim (sorted, unique).
    pub retained_counterevidence_refs: Vec<String>,
}

/// Local mirror of the B-SEC1 dependency closure (no `eliot-influence` dep).
///
/// Shape-mirrors `InfluenceDependencyClosure`: identity, root, dependents,
/// optional invalidation reason, current standing, fence, and revision, plus
/// the completeness attestation this cell checks without traversing or
/// revoking anything itself.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct LocalInfluenceClosure {
    /// Closure identity.
    pub closure_id: String,
    /// Root subject the closure covers; must equal the projected subject.
    pub root_ref: String,
    /// Dependent refs covered (sorted, unique).
    pub dependent_refs: Vec<String>,
    /// Invalidation reason when standing is not active.
    pub invalidation_reason: Option<LocalRevocationClass>,
    /// Current standing reported by the closure.
    pub current_standing: LocalClosureStanding,
    /// Scope the closure was computed in.
    pub scope_id: String,
    /// Policy the closure was computed under.
    pub policy_id: String,
    /// Subject revision the closure was computed at.
    pub closure_revision: String,
    /// State fence the closure was computed under.
    pub state_fence: StateFence,
    /// Caller attests the closure covers every affected path.
    pub complete: bool,
    /// True when the closure revision moved; always stale.
    pub stale: bool,
    /// Unknown gaps; any entry blocks completeness.
    pub unknown_gaps: Vec<String>,
}

/// Closed policy governing one single-axis adjustment.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AdjustmentPolicy {
    /// Policy identity; binds receipt, projection, and closure.
    pub policy_id: String,
    /// The single axis allowed to move.
    pub axis: Axis,
    /// Closed operation applied to the axis.
    pub operation: AdjustmentOperation,
    /// Closed direction of the move.
    pub direction: AdjustmentDirection,
    /// Subject the policy authorizes; must equal the projected subject.
    pub target_subject: String,
    /// True when risk stays task-local; false means material wider risk.
    pub task_local_only: bool,
    /// Minimum independent outcome observations for a complete move.
    pub evidence_minimum: u32,
    /// Visibility that must remain after the move (provenance, audit).
    pub mandatory_visibility: String,
    /// Visibility ceiling the move stays within.
    pub visibility_ceiling: String,
    /// Influence ceiling the move stays within.
    pub influence_ceiling: String,
    /// Privacy ceiling the move stays within.
    pub privacy_ceiling: String,
    /// Verifier that checks the observable.
    pub verifier: String,
    /// Observation window the observable is checked in.
    pub observation_window_note: String,
    /// Exact inverse restoring the before state.
    pub inverse_note: String,
    /// Explicit expiry; unknown expiry is never filled in.
    pub expiry_ms: Option<u64>,
    /// Renewal condition naming what reopens review.
    pub renewal_condition: String,
    /// Bound on affected paths admitted in one request.
    pub max_affected: u32,
    /// Bound on independent evidence items admitted in one request.
    pub max_evidence_items: u32,
}

/// One affected projection, decision, or dependent.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AffectedPath {
    /// Affected handle.
    pub handle: String,
    /// Closed kind of the affected path.
    pub kind: AffectedPathKind,
    /// Owner accountable for the path disposition.
    pub owner: String,
    /// Required paths block completeness when undisposed.
    pub required: bool,
}

/// Exactly one disposition for one affected path.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PathDisposition {
    /// Affected handle this disposition covers.
    pub handle: String,
    /// Exactly one disposition kind.
    pub disposition: DependentDispositionKind,
    /// Identity before the proposed move.
    pub before_identity: String,
    /// Identity proposed by the move.
    pub proposed_identity: String,
    /// Owner accountable for this disposition.
    pub owner: String,
    /// Bounded reason naming the evidence or blocker.
    pub reason: String,
    /// Verifier that checks this disposition.
    pub verifier: String,
    /// Inverse restoring the before identity.
    pub inverse_note: String,
}

/// Full immutable input for one single-axis adjustment proposal.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AdjustmentRequest {
    /// Validated A-03 curation item; kind must be accessibility.
    pub item: ValidatedCurationItem,
    /// Grounded draft the item digest binds.
    pub grounded: GroundedDreamDraft,
    /// Frozen bundle digest; must equal the receipt bundle digest.
    pub frozen_bundle_digest: String,
    /// Frozen manifest digest; must equal the receipt manifest digest.
    pub frozen_manifest_digest: String,
    /// Exact current projection of the subject across every axis.
    pub projection: CurrentAxisProjection,
    /// Usage and outcome evidence with explicit denominators.
    pub usage: UsageAndOutcomeEvidence,
    /// Protection and negative-memory evidence.
    pub protection: ProtectionAndNegativeMemory,
    /// Complete influence closure; required for material influence moves.
    pub influence_closure: Option<LocalInfluenceClosure>,
    /// Closed policy governing the move.
    pub policy: AdjustmentPolicy,
    /// Accessibility half; exactly one half is present.
    pub accessibility: Option<AccessibilityChange>,
    /// Influence half; exactly one half is present.
    pub influence: Option<InfluenceChange>,
    /// Affected paths (sorted by handle, unique).
    pub affected: Vec<AffectedPath>,
    /// One disposition per affected path (sorted by handle).
    pub dispositions: Vec<PathDisposition>,
    /// Seven-dimension preservation report from the caller.
    pub preservation: PreservationReport,
    /// A-05 receipt checked intrinsically, never re-executed.
    pub receipt: ValidationReceipt,
    /// Denominator covering exactly the affected handles.
    pub closure_denominator: TargetDenominator,
}

/// Complete proposal envelope: outcome plus bindings, never an applied receipt.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AdjustmentProposal {
    /// Terminal outcome for this request.
    pub outcome: AdjustmentOutcome,
    /// The single axis this proposal moves.
    pub axis: Axis,
    /// Subject handle under adjustment.
    pub subject_handle: String,
    /// Subject revision the proposal binds.
    pub subject_revision: String,
    /// Axis standings before the move.
    pub before_snapshot: AxisStateSnapshot,
    /// Axis standings proposed by the move.
    pub proposed_snapshot: AxisStateSnapshot,
    /// Owner refs before the move.
    pub before_owners: AxisOwnerRefs,
    /// Owner refs proposed by the move; ownership never moves here.
    pub proposed_owners: AxisOwnerRefs,
    /// One disposition per affected path, in handle order.
    pub dispositions: Vec<PathDisposition>,
    /// Expected observable proving the move took effect.
    pub observable: String,
    /// Verifier that checks the observable.
    pub verifier: String,
    /// Observation window the observable is checked in.
    pub window_note: String,
    /// Exact inverse restoring the before state.
    pub inverse_note: String,
    /// Explicit expiry of the proposal.
    pub expiry_ms: Option<u64>,
    /// Renewal condition naming what reopens review.
    pub renewal_condition: String,
    /// Deterministic digest binding the proposal inputs.
    pub proposal_digest: String,
    /// Bounded machine-readable note.
    pub note: String,
}

/// Typed fail-closed error. Malformed input only; semantic shortfalls are outcomes.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
pub enum AccessibilityError {
    /// A bound or shape check failed in the named phase.
    Bounds {
        /// Phase that failed its bound.
        phase: String,
        /// Bounded detail.
        detail: String,
    },
    /// Deterministic ordering was violated in the named phase.
    Order {
        /// Phase that failed ordering.
        phase: String,
        /// Bounded detail.
        detail: String,
    },
    /// An affected path record is malformed.
    Path {
        /// Path handle (redacted).
        handle: String,
        /// Bounded detail.
        detail: String,
    },
    /// A protection or negative-memory record is malformed.
    Protection {
        /// Reason or trigger identity (redacted).
        reason: String,
        /// Bounded detail.
        detail: String,
    },
    /// Generic malformed input in the named phase.
    Malformed {
        /// Phase that failed.
        phase: String,
        /// Bounded detail.
        detail: String,
    },
    /// The bundled A-05 receipt or curation item is intrinsically invalid.
    Receipt {
        /// Bounded detail.
        detail: String,
    },
    /// The preservation report shape is invalid.
    Preservation {
        /// Bounded detail.
        detail: String,
    },
    /// The closure denominator shape is invalid.
    Denominator {
        /// Bounded detail.
        detail: String,
    },
}

impl core::fmt::Display for AccessibilityError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Bounds { phase, detail } => {
                write!(f, "bounds[{phase}]: {detail}")
            }
            Self::Order { phase, detail } => {
                write!(f, "order[{phase}]: {detail}")
            }
            Self::Path { handle, detail } => {
                write!(f, "path[{handle}]: {detail}")
            }
            Self::Protection { reason, detail } => {
                write!(f, "protection[{reason}]: {detail}")
            }
            Self::Malformed { phase, detail } => {
                write!(f, "malformed[{phase}]: {detail}")
            }
            Self::Receipt { detail } => write!(f, "receipt: {detail}"),
            Self::Preservation { detail } => write!(f, "preservation: {detail}"),
            Self::Denominator { detail } => write!(f, "denominator: {detail}"),
        }
    }
}

impl core::error::Error for AccessibilityError {}

// ---------------------------------------------------------------------------
// Validation phases (all pure, all bounded, none panicking).
// ---------------------------------------------------------------------------

fn check_text(value: &str, field: &str, max: usize) -> Result<(), AccessibilityError> {
    if value.trim().is_empty() {
        return Err(AccessibilityError::Bounds {
            phase: field.to_owned(),
            detail: "blank text is not admitted".to_owned(),
        });
    }
    if has_control(value) {
        return Err(AccessibilityError::Malformed {
            phase: field.to_owned(),
            detail: "control characters are not admitted".to_owned(),
        });
    }
    if value.len() > max {
        return Err(AccessibilityError::Bounds {
            phase: field.to_owned(),
            detail: "text exceeds its byte bound".to_owned(),
        });
    }
    Ok(())
}

fn check_handle(value: &str, field: &str) -> Result<(), AccessibilityError> {
    check_text(value, field, MAX_HANDLE_BYTES)
}

fn check_digest_shape(value: &str, field: &str) -> Result<(), AccessibilityError> {
    if !is_hex64_lower(value) {
        return Err(AccessibilityError::Malformed {
            phase: field.to_owned(),
            detail: "digest must be 64 lowercase hex".to_owned(),
        });
    }
    Ok(())
}

fn total_bytes(request: &AdjustmentRequest) -> usize {
    let mut total = 0usize;
    let mut add = |n: usize| {
        total = total.saturating_add(n);
    };
    add(request.projection.subject_handle.len());
    add(request.projection.subject_revision.len());
    add(request.projection.scope_id.len());
    add(request.projection.task_id.len());
    add(request.projection.policy_id.len());
    for path in &request.affected {
        add(path.handle.len());
        add(path.owner.len());
    }
    for outcome in &request.dispositions {
        add(outcome.handle.len());
        add(outcome.before_identity.len());
        add(outcome.proposed_identity.len());
        add(outcome.owner.len());
        add(outcome.reason.len());
        add(outcome.verifier.len());
        add(outcome.inverse_note.len());
    }
    for protection in &request.protection.protections {
        add(protection.reason_id.len());
        add(protection.trigger.len());
    }
    for entry in &request.protection.negative_memory {
        add(entry.trigger.len());
    }
    for handle in &request.protection.retained_counterevidence_refs {
        add(handle.len());
    }
    if let Some(change) = request.accessibility.as_ref() {
        add(change.before_owner.len());
        add(change.before_revision.len());
        add(change.grounded_reason.len());
        add(change.protected_verifier_access.len());
        add(change.privacy_ceiling.len());
        add(change.observable.len());
        add(change.window_note.len());
        add(change.inverse_note.len());
        add(change.projection_plan.len());
        add(change.surface.scope.len());
        add(change.surface.audience.len());
        add(change.surface.query_surface.len());
        add(change.surface.context_surface.len());
        add(change.surface.index_surface.len());
    }
    if let Some(change) = request.influence.as_ref() {
        add(change.current_policy_id.len());
        add(change.current_graph_note.len());
        add(change.scope.len());
        add(change.decision_ref.len());
        add(change.effect_note.len());
        add(change.review_owner_ref.len());
        add(change.decision_owner_ref.len());
        add(change.preserved_other_axes_note.len());
    }
    if let Some(closure) = request.influence_closure.as_ref() {
        add(closure.closure_id.len());
        add(closure.root_ref.len());
        for handle in &closure.dependent_refs {
            add(handle.len());
        }
        add(closure.scope_id.len());
        add(closure.policy_id.len());
        add(closure.closure_revision.len());
        for gap in &closure.unknown_gaps {
            add(gap.len());
        }
    }
    add(request.policy.policy_id.len());
    add(request.policy.target_subject.len());
    add(request.policy.mandatory_visibility.len());
    add(request.policy.visibility_ceiling.len());
    add(request.policy.influence_ceiling.len());
    add(request.policy.privacy_ceiling.len());
    add(request.policy.verifier.len());
    add(request.policy.observation_window_note.len());
    add(request.policy.inverse_note.len());
    add(request.policy.renewal_condition.len());
    add(request.usage.writer_utility_note.len());
    add(request.usage.usage_window_note.len());
    total
}

fn preflight_bounds(request: &AdjustmentRequest) -> Result<(), AccessibilityError> {
    let bound = |phase: &str, got: usize, max: usize| -> Result<(), AccessibilityError> {
        if got > max {
            return Err(AccessibilityError::Bounds {
                phase: phase.to_owned(),
                detail: "cardinality exceeds its independent bound".to_owned(),
            });
        }
        Ok(())
    };
    let max_affected = usize::try_from(request.policy.max_affected).unwrap_or(usize::MAX);
    let admitted_max = if max_affected < MAX_AFFECTED {
        max_affected
    } else {
        MAX_AFFECTED
    };
    bound("affected", request.affected.len(), admitted_max)?;
    bound("dispositions", request.dispositions.len(), admitted_max)?;
    bound(
        "protections",
        request.protection.protections.len(),
        MAX_PROTECTIONS,
    )?;
    bound(
        "negative_memory",
        request.protection.negative_memory.len(),
        MAX_NEGATIVE_ENTRIES,
    )?;
    bound(
        "retained_counterevidence",
        request.protection.retained_counterevidence_refs.len(),
        MAX_CLOSURE_REFS,
    )?;
    if let Some(closure) = request.influence_closure.as_ref() {
        bound(
            "closure_refs",
            closure.dependent_refs.len(),
            MAX_CLOSURE_REFS,
        )?;
        bound("closure_gaps", closure.unknown_gaps.len(), MAX_CLOSURE_REFS)?;
    }
    if request.affected.is_empty() {
        return Err(AccessibilityError::Bounds {
            phase: "affected".to_owned(),
            detail: "at least one affected path is required".to_owned(),
        });
    }
    if request.usage.retrieval_successes > request.usage.retrieval_attempts {
        return Err(AccessibilityError::Bounds {
            phase: "usage".to_owned(),
            detail: "retrieval successes exceed retrieval attempts".to_owned(),
        });
    }
    if request.usage.outcome_successes > request.usage.outcome_observations {
        return Err(AccessibilityError::Bounds {
            phase: "usage".to_owned(),
            detail: "outcome successes exceed outcome observations".to_owned(),
        });
    }
    if total_bytes(request) > MAX_TOTAL_BYTES {
        return Err(AccessibilityError::Bounds {
            phase: "bytes".to_owned(),
            detail: "aggregate input exceeds its byte bound".to_owned(),
        });
    }
    Ok(())
}

fn validate_owner_refs(owners: &AxisOwnerRefs) -> Result<(), AccessibilityError> {
    if owners.existence_owner.trim().is_empty()
        || has_control(&owners.existence_owner)
        || owners.existence_owner.len() > MAX_HANDLE_BYTES
    {
        return Err(AccessibilityError::Malformed {
            phase: "axis_owners".to_owned(),
            detail: "owner for axis existence is not a bounded handle".to_owned(),
        });
    }
    if owners.support_owner.trim().is_empty()
        || has_control(&owners.support_owner)
        || owners.support_owner.len() > MAX_HANDLE_BYTES
    {
        return Err(AccessibilityError::Malformed {
            phase: "axis_owners".to_owned(),
            detail: "owner for axis support is not a bounded handle".to_owned(),
        });
    }
    if owners.accessibility_owner.trim().is_empty()
        || has_control(&owners.accessibility_owner)
        || owners.accessibility_owner.len() > MAX_HANDLE_BYTES
    {
        return Err(AccessibilityError::Malformed {
            phase: "axis_owners".to_owned(),
            detail: "owner for axis accessibility is not a bounded handle".to_owned(),
        });
    }
    if owners.influence_owner.trim().is_empty()
        || has_control(&owners.influence_owner)
        || owners.influence_owner.len() > MAX_HANDLE_BYTES
    {
        return Err(AccessibilityError::Malformed {
            phase: "axis_owners".to_owned(),
            detail: "owner for axis influence is not a bounded handle".to_owned(),
        });
    }
    if owners.privacy_owner.trim().is_empty()
        || has_control(&owners.privacy_owner)
        || owners.privacy_owner.len() > MAX_HANDLE_BYTES
    {
        return Err(AccessibilityError::Malformed {
            phase: "axis_owners".to_owned(),
            detail: "owner for axis privacy is not a bounded handle".to_owned(),
        });
    }
    if owners.assurance_owner.trim().is_empty()
        || has_control(&owners.assurance_owner)
        || owners.assurance_owner.len() > MAX_HANDLE_BYTES
    {
        return Err(AccessibilityError::Malformed {
            phase: "axis_owners".to_owned(),
            detail: "owner for axis assurance is not a bounded handle".to_owned(),
        });
    }
    Ok(())
}

fn validate_accessibility_shapes(change: &AccessibilityChange) -> Result<(), AccessibilityError> {
    check_handle(&change.before_owner, "accessibility.before_owner")?;
    check_text(
        &change.before_revision,
        "accessibility.before_revision",
        MAX_HANDLE_BYTES,
    )?;
    check_text(
        &change.grounded_reason,
        "accessibility.grounded_reason",
        MAX_TEXT_BYTES,
    )?;
    check_text(
        &change.protected_verifier_access,
        "accessibility.verifier_access",
        MAX_TEXT_BYTES,
    )?;
    check_text(
        &change.privacy_ceiling,
        "accessibility.privacy_ceiling",
        MAX_TEXT_BYTES,
    )?;
    check_text(
        &change.observable,
        "accessibility.observable",
        MAX_TEXT_BYTES,
    )?;
    check_text(&change.window_note, "accessibility.window", MAX_TEXT_BYTES)?;
    check_text(
        &change.inverse_note,
        "accessibility.inverse",
        MAX_TEXT_BYTES,
    )?;
    check_text(
        &change.projection_plan,
        "accessibility.projection_plan",
        MAX_TEXT_BYTES,
    )?;
    check_handle(&change.surface.scope, "surface.scope")?;
    check_text(
        &change.surface.audience,
        "surface.audience",
        MAX_HANDLE_BYTES,
    )?;
    check_text(
        &change.surface.query_surface,
        "surface.query",
        MAX_HANDLE_BYTES,
    )?;
    check_text(
        &change.surface.context_surface,
        "surface.Context",
        MAX_HANDLE_BYTES,
    )?;
    check_text(
        &change.surface.index_surface,
        "surface.index",
        MAX_HANDLE_BYTES,
    )?;
    Ok(())
}

fn validate_influence_shapes(change: &InfluenceChange) -> Result<(), AccessibilityError> {
    check_text(
        &change.current_policy_id,
        "influence.current_policy",
        MAX_HANDLE_BYTES,
    )?;
    check_text(
        &change.current_graph_note,
        "influence.current_graph",
        MAX_TEXT_BYTES,
    )?;
    check_handle(&change.scope, "influence.scope")?;
    check_handle(&change.decision_ref, "influence.decision")?;
    check_text(&change.effect_note, "influence.effect", MAX_TEXT_BYTES)?;
    check_handle(&change.review_owner_ref, "influence.review_owner")?;
    check_handle(&change.decision_owner_ref, "influence.decision_owner")?;
    check_text(
        &change.preserved_other_axes_note,
        "influence.preserved_axes",
        MAX_TEXT_BYTES,
    )?;
    Ok(())
}

fn validate_closure_shapes(closure: &LocalInfluenceClosure) -> Result<(), AccessibilityError> {
    check_handle(&closure.closure_id, "closure.id")?;
    check_handle(&closure.root_ref, "closure.root")?;
    for handle in &closure.dependent_refs {
        check_handle(handle, "closure.dependent")?;
    }
    if closure.dependent_refs.is_empty() {
        return Err(AccessibilityError::Bounds {
            phase: "closure_refs".to_owned(),
            detail: "closure covers no dependent refs".to_owned(),
        });
    }
    let mut refs = closure.dependent_refs.clone();
    refs.sort_unstable();
    if !is_sorted_unique(&refs) {
        return Err(AccessibilityError::Order {
            phase: "closure_refs".to_owned(),
            detail: "closure dependent refs must be sorted and unique".to_owned(),
        });
    }
    if closure.dependent_refs != refs {
        return Err(AccessibilityError::Order {
            phase: "closure_refs".to_owned(),
            detail: "closure dependent refs must arrive sorted and unique".to_owned(),
        });
    }
    check_handle(&closure.scope_id, "closure.scope")?;
    check_handle(&closure.policy_id, "closure.policy")?;
    check_text(
        &closure.closure_revision,
        "closure.revision",
        MAX_HANDLE_BYTES,
    )?;
    for gap in &closure.unknown_gaps {
        check_handle(gap, "closure.gap")?;
    }
    // Mirror of the B-SEC1 closure invariant: revoked needs a reason, and a
    // reason with an active standing is incoherent.
    if closure.current_standing == LocalClosureStanding::Revoked
        && closure.invalidation_reason.is_none()
    {
        return Err(AccessibilityError::Malformed {
            phase: "closure".to_owned(),
            detail: "revoked closure needs an invalidation reason".to_owned(),
        });
    }
    if closure.invalidation_reason.is_some()
        && closure.current_standing == LocalClosureStanding::Active
    {
        return Err(AccessibilityError::Malformed {
            phase: "closure".to_owned(),
            detail: "active closure carries no invalidation reason".to_owned(),
        });
    }
    Ok(())
}

fn validate_projection_policy_shapes(
    request: &AdjustmentRequest,
) -> Result<(), AccessibilityError> {
    check_handle(&request.projection.subject_handle, "subject.handle")?;
    check_text(
        &request.projection.subject_revision,
        "subject.revision",
        MAX_HANDLE_BYTES,
    )?;
    check_handle(&request.projection.scope_id, "subject.scope")?;
    check_handle(&request.projection.task_id, "subject.task")?;
    check_handle(&request.projection.policy_id, "subject.policy")?;
    validate_owner_refs(&request.projection.owners)?;
    check_digest_shape(&request.frozen_bundle_digest, "frozen.bundle")?;
    check_digest_shape(&request.frozen_manifest_digest, "frozen.manifest")?;
    check_text(
        &request.usage.writer_utility_note,
        "usage.writer_utility",
        MAX_TEXT_BYTES,
    )?;
    check_text(
        &request.usage.usage_window_note,
        "usage.window",
        MAX_TEXT_BYTES,
    )?;
    check_handle(&request.policy.policy_id, "policy.id")?;
    check_handle(&request.policy.target_subject, "policy.target")?;
    check_text(
        &request.policy.mandatory_visibility,
        "policy.mandatory_visibility",
        MAX_TEXT_BYTES,
    )?;
    check_text(
        &request.policy.visibility_ceiling,
        "policy.visibility_ceiling",
        MAX_TEXT_BYTES,
    )?;
    check_text(
        &request.policy.influence_ceiling,
        "policy.influence_ceiling",
        MAX_TEXT_BYTES,
    )?;
    check_text(
        &request.policy.privacy_ceiling,
        "policy.privacy_ceiling",
        MAX_TEXT_BYTES,
    )?;
    check_text(&request.policy.verifier, "policy.verifier", MAX_TEXT_BYTES)?;
    check_text(
        &request.policy.observation_window_note,
        "policy.window",
        MAX_TEXT_BYTES,
    )?;
    check_text(
        &request.policy.inverse_note,
        "policy.inverse",
        MAX_TEXT_BYTES,
    )?;
    check_text(
        &request.policy.renewal_condition,
        "policy.renewal",
        MAX_TEXT_BYTES,
    )?;
    // Operation and direction must agree: increases raise, decreases lower,
    // narrow and restore moves are lateral. Plain boolean conjunctions keep
    // each legal pair exact; no pair is merged across axes.
    let operation = request.policy.operation;
    let direction = request.policy.direction;
    let direction_ok = (operation == AdjustmentOperation::Increase
        && direction == AdjustmentDirection::Raise)
        || (operation == AdjustmentOperation::Decrease && direction == AdjustmentDirection::Lower)
        || (operation == AdjustmentOperation::Narrow && direction == AdjustmentDirection::Lateral)
        || (operation == AdjustmentOperation::Restore && direction == AdjustmentDirection::Lateral);
    if !direction_ok {
        return Err(AccessibilityError::Malformed {
            phase: "policy".to_owned(),
            detail: "operation and direction disagree".to_owned(),
        });
    }
    Ok(())
}

fn validate_half_shapes(request: &AdjustmentRequest) -> Result<(), AccessibilityError> {
    // Exactly one half is present; the cell never applies a multi-axis patch.
    if request.accessibility.is_some() == request.influence.is_some() {
        return Err(AccessibilityError::Malformed {
            phase: "halves".to_owned(),
            detail: "exactly one accessibility or influence half is required".to_owned(),
        });
    }
    if let Some(change) = request.accessibility.as_ref() {
        validate_accessibility_shapes(change)?;
    }
    if let Some(change) = request.influence.as_ref() {
        validate_influence_shapes(change)?;
    }
    if let Some(closure) = request.influence_closure.as_ref() {
        validate_closure_shapes(closure)?;
    }
    Ok(())
}

fn validate_affected_shapes(request: &AdjustmentRequest) -> Result<(), AccessibilityError> {
    let mut handles: Vec<String> = Vec::new();
    for path in &request.affected {
        check_handle(&path.handle, "affected.handle")?;
        check_handle(&path.owner, "affected.owner")?;
        handles.push(path.handle.clone());
    }
    if !is_sorted_unique(&handles) {
        return Err(AccessibilityError::Order {
            phase: "affected".to_owned(),
            detail: "affected handles must be sorted and unique".to_owned(),
        });
    }
    let mut outcome_handles: Vec<String> = Vec::new();
    for outcome in &request.dispositions {
        check_handle(&outcome.handle, "disposition.handle")?;
        check_text(
            &outcome.before_identity,
            "disposition.before",
            MAX_TEXT_BYTES,
        )?;
        check_text(
            &outcome.proposed_identity,
            "disposition.proposed",
            MAX_TEXT_BYTES,
        )?;
        check_handle(&outcome.owner, "disposition.owner")?;
        check_text(&outcome.reason, "disposition.reason", MAX_TEXT_BYTES)?;
        check_text(&outcome.verifier, "disposition.verifier", MAX_TEXT_BYTES)?;
        check_text(&outcome.inverse_note, "disposition.inverse", MAX_TEXT_BYTES)?;
        outcome_handles.push(outcome.handle.clone());
    }
    if !is_sorted_unique(&outcome_handles) {
        return Err(AccessibilityError::Order {
            phase: "dispositions".to_owned(),
            detail: "disposition handles must be sorted and unique".to_owned(),
        });
    }
    Ok(())
}

fn validate_protection_shapes(request: &AdjustmentRequest) -> Result<(), AccessibilityError> {
    let mut reason_ids: Vec<String> = Vec::new();
    for protection in &request.protection.protections {
        check_handle(&protection.reason_id, "protection.reason")?;
        check_text(&protection.trigger, "protection.trigger", MAX_TEXT_BYTES)?;
        if let Some(counter) = protection.counterevidence_ref.as_ref() {
            check_handle(counter, "protection.counterevidence")?;
        }
        reason_ids.push(protection.reason_id.clone());
    }
    if !is_sorted_unique(&reason_ids) {
        return Err(AccessibilityError::Order {
            phase: "protections".to_owned(),
            detail: "protection reason ids must be sorted and unique".to_owned(),
        });
    }
    let mut triggers: Vec<String> = Vec::new();
    for entry in &request.protection.negative_memory {
        check_text(&entry.trigger, "negative.trigger", MAX_TEXT_BYTES)?;
        if let Some(extinction) = entry.extinction_evidence_ref.as_ref() {
            check_handle(extinction, "negative.extinction")?;
        }
        if let Some(reopen) = entry.reopen_evidence_ref.as_ref() {
            check_text(reopen, "negative.reopen", MAX_TEXT_BYTES)?;
        }
        triggers.push(entry.trigger.clone());
    }
    if !is_sorted_unique(&triggers) {
        return Err(AccessibilityError::Order {
            phase: "negative_memory".to_owned(),
            detail: "negative-memory triggers must be sorted and unique".to_owned(),
        });
    }
    if !is_sorted_unique(&request.protection.retained_counterevidence_refs) {
        return Err(AccessibilityError::Order {
            phase: "retained_counterevidence".to_owned(),
            detail: "retained counterevidence refs must be sorted and unique".to_owned(),
        });
    }
    for handle in &request.protection.retained_counterevidence_refs {
        check_handle(handle, "retained.counterevidence")?;
    }
    Ok(())
}

fn validate_shapes(request: &AdjustmentRequest) -> Result<(), AccessibilityError> {
    validate_projection_policy_shapes(request)?;
    validate_half_shapes(request)?;
    validate_affected_shapes(request)?;
    validate_protection_shapes(request)
}

// ---------------------------------------------------------------------------
// Outcome helpers.
// ---------------------------------------------------------------------------

/// String bindings carried into one settled proposal outcome.
struct Settlement<'a> {
    /// Terminal outcome for the settled proposal.
    outcome: AdjustmentOutcome,
    /// Expected observable proving the move took effect.
    observable: &'a str,
    /// Verifier that checks the observable.
    verifier: &'a str,
    /// Observation window the observable is checked in.
    window_note: &'a str,
    /// Exact inverse restoring the before state.
    inverse_note: &'a str,
    /// Explicit expiry of the proposal.
    expiry_ms: Option<u64>,
    /// Renewal condition naming what reopens review.
    renewal_condition: &'a str,
    /// Deterministic digest binding the proposal inputs.
    digest: &'a str,
    /// Bounded machine-readable note.
    note: &'a str,
}

fn ok_proposal(
    request: &AdjustmentRequest,
    before: AxisStateSnapshot,
    proposed: AxisStateSnapshot,
    settlement: &Settlement<'_>,
) -> AdjustmentProposal {
    AdjustmentProposal {
        outcome: settlement.outcome,
        axis: request.policy.axis,
        subject_handle: request.projection.subject_handle.clone(),
        subject_revision: request.projection.subject_revision.clone(),
        before_snapshot: before,
        proposed_snapshot: proposed,
        before_owners: request.projection.owners.clone(),
        proposed_owners: request.projection.owners.clone(),
        dispositions: request.dispositions.clone(),
        observable: redact(settlement.observable),
        verifier: redact(settlement.verifier),
        window_note: redact(settlement.window_note),
        inverse_note: redact(settlement.inverse_note),
        expiry_ms: settlement.expiry_ms,
        renewal_condition: redact(settlement.renewal_condition),
        proposal_digest: settlement.digest.to_owned(),
        note: redact(settlement.note),
    }
}

/// Settles a proposal where the move never started: snapshots stay unchanged
/// and every string binding is empty except the computed digest and note.
fn unchanged_proposal(
    request: &AdjustmentRequest,
    outcome: AdjustmentOutcome,
    note: &str,
) -> Result<AdjustmentProposal, AccessibilityError> {
    let snapshot = AxisStateSnapshot {
        accessibility: request.projection.accessibility,
        influence: request.projection.influence,
    };
    let digest = proposal_digest(request, snapshot, snapshot, "", "", "", None)?;
    Ok(ok_proposal(
        request,
        snapshot,
        snapshot,
        &Settlement {
            outcome,
            observable: "",
            verifier: "",
            window_note: "",
            inverse_note: "",
            expiry_ms: None,
            renewal_condition: "",
            digest: &digest,
            note,
        },
    ))
}

/// Canonical digest view binding every identity the proposal depends on.
#[derive(Serialize)]
struct DigestView<'a> {
    subject_handle: &'a str,
    subject_revision: &'a str,
    scope_id: &'a str,
    task_id: &'a str,
    policy_id: &'a str,
    axis: &'a Axis,
    operation: &'a AdjustmentOperation,
    direction: &'a AdjustmentDirection,
    before_accessibility: &'a AccessibilityStanding,
    before_influence: &'a InfluenceStanding,
    proposed_accessibility: &'a AccessibilityStanding,
    proposed_influence: &'a InfluenceStanding,
    owners: &'a AxisOwnerRefs,
    disposition_handles: Vec<&'a str>,
    observable: &'a str,
    verifier: &'a str,
    inverse_note: &'a str,
    expiry_ms: Option<u64>,
}

fn proposal_digest(
    request: &AdjustmentRequest,
    before: AxisStateSnapshot,
    proposed: AxisStateSnapshot,
    observable: &str,
    verifier: &str,
    inverse_note: &str,
    expiry_ms: Option<u64>,
) -> Result<String, AccessibilityError> {
    let mut disposition_handles: Vec<&str> = request
        .dispositions
        .iter()
        .map(|outcome| outcome.handle.as_str())
        .collect();
    disposition_handles.sort_unstable();
    let view = DigestView {
        subject_handle: request.projection.subject_handle.as_str(),
        subject_revision: request.projection.subject_revision.as_str(),
        scope_id: request.projection.scope_id.as_str(),
        task_id: request.projection.task_id.as_str(),
        policy_id: request.policy.policy_id.as_str(),
        axis: &request.policy.axis,
        operation: &request.policy.operation,
        direction: &request.policy.direction,
        before_accessibility: &before.accessibility,
        before_influence: &before.influence,
        proposed_accessibility: &proposed.accessibility,
        proposed_influence: &proposed.influence,
        owners: &request.projection.owners,
        disposition_handles,
        observable,
        verifier,
        inverse_note,
        expiry_ms,
    };
    canonical_json_bytes(&view)
        .map(|bytes| sha256_hex(&bytes))
        .map_err(|_| AccessibilityError::Malformed {
            phase: "digest".to_owned(),
            detail: "proposal inputs cannot be canonically serialized".to_owned(),
        })
}

// ---------------------------------------------------------------------------
// Protection and negative-memory evaluation (fail-closed).
// ---------------------------------------------------------------------------

/// Outcome of evaluating every protection reason and negative-memory entry.
enum ProtectionVerdict {
    /// Every mandatory protection holds and every trigger is retained.
    Clear,
    /// A non-load-bearing gap remains with a named condition.
    Partial(String),
    /// A mandatory protection or exact trigger blocks the move.
    Blocked(String),
}

fn evaluate_protections(request: &AdjustmentRequest) -> ProtectionVerdict {
    for protection in &request.protection.protections {
        if protection.unknown {
            if protection.mandatory {
                if request.policy.task_local_only {
                    return ProtectionVerdict::Partial(
                        "unknown mandatory protection holds the move task-local".to_owned(),
                    );
                }
                return ProtectionVerdict::Blocked(
                    "unknown mandatory protection blocks a material move".to_owned(),
                );
            }
            continue;
        }
        if protection.mandatory && !protection.satisfied {
            if request.policy.task_local_only {
                return ProtectionVerdict::Partial(
                    "unsatisfied mandatory protection holds the move task-local".to_owned(),
                );
            }
            return ProtectionVerdict::Blocked(
                "missing mandatory protection blocks a material move".to_owned(),
            );
        }
        if let Some(counter) = protection.counterevidence_ref.as_ref()
            && !contains_handle(&request.protection.retained_counterevidence_refs, counter)
        {
            return ProtectionVerdict::Blocked("named counterevidence is not retained".to_owned());
        }
    }
    for entry in &request.protection.negative_memory {
        if entry.extinguished {
            if entry.extinction_evidence_ref.is_none() {
                return ProtectionVerdict::Blocked(
                    "extinguished trigger needs extinction evidence".to_owned(),
                );
            }
            continue;
        }
        // Exact triggers only: similarity or low use never suppresses a live
        // trigger, because retention is checked by byte-exact match.
        if !contains_handle(
            &request.protection.retained_counterevidence_refs,
            &entry.trigger,
        ) {
            return ProtectionVerdict::Blocked(
                "live exact-trigger negative memory is not retained".to_owned(),
            );
        }
    }
    ProtectionVerdict::Clear
}

// ---------------------------------------------------------------------------
// Half-specific semantic checks.
// ---------------------------------------------------------------------------

/// Semantic shortfall inside the accessibility half, if any.
fn check_accessibility_semantics(
    request: &AdjustmentRequest,
    change: &AccessibilityChange,
) -> Option<(AdjustmentOutcome, String)> {
    if change.before_owner != request.projection.owners.accessibility_owner {
        return Some((
            AdjustmentOutcome::Stale,
            "accessibility before owner does not match the projected owner".to_owned(),
        ));
    }
    if change.before_revision != request.projection.subject_revision {
        return Some((
            AdjustmentOutcome::Stale,
            "accessibility before revision does not match the current revision".to_owned(),
        ));
    }
    if change.before_state != request.projection.accessibility {
        return Some((
            AdjustmentOutcome::Stale,
            "accessibility before state does not match the projected state".to_owned(),
        ));
    }
    if change.proposed_state == change.before_state
        && request.policy.operation != AdjustmentOperation::Narrow
    {
        return Some((
            AdjustmentOutcome::Rejected,
            "accessibility move proposes no standing change".to_owned(),
        ));
    }
    let raising = matches!(request.policy.operation, AdjustmentOperation::Increase)
        || matches!(request.policy.direction, AdjustmentDirection::Raise);
    let lowering = matches!(request.policy.operation, AdjustmentOperation::Decrease)
        || matches!(request.policy.direction, AdjustmentDirection::Lower);
    if raising
        && (change.widens_privacy
            || change.widens_support
            || change.widens_influence
            || change.widens_effect)
    {
        return Some((
            AdjustmentOutcome::Blocked,
            "raising visibility cannot widen privacy, support, influence, or effect".to_owned(),
        ));
    }
    if lowering && (change.hides_provenance || change.hides_audit || change.hides_counterevidence) {
        return Some((
            AdjustmentOutcome::Blocked,
            "lowering visibility cannot hide provenance, audit, or counterevidence".to_owned(),
        ));
    }
    if change.expiry_ms.is_none() {
        return Some((
            AdjustmentOutcome::Blocked,
            "accessibility move needs an exact expiry".to_owned(),
        ));
    }
    if change.proposed_state == AccessibilityStanding::Dormant
        && change.global_scope
        && request.usage.outcome_observations == 0
    {
        return Some((
            AdjustmentOutcome::Blocked,
            "non-use alone cannot justify global dormancy".to_owned(),
        ));
    }
    if change.proposed_state == AccessibilityStanding::Dormant
        && change.global_scope
        && request.usage.unknown_usage
    {
        return Some((
            AdjustmentOutcome::Blocked,
            "unknown usage is not non-use and cannot justify dormancy".to_owned(),
        ));
    }
    if mentions_authority_grant(&request.usage.writer_utility_note) {
        return Some((
            AdjustmentOutcome::Blocked,
            "writer utility never authorizes an accessibility move".to_owned(),
        ));
    }
    None
}

/// Semantic shortfall inside the influence half, if any.
fn check_influence_semantics(
    request: &AdjustmentRequest,
    change: &InfluenceChange,
) -> Option<(AdjustmentOutcome, String)> {
    if change.current_standing != request.projection.influence {
        return Some((
            AdjustmentOutcome::Stale,
            "influence current standing does not match the projected standing".to_owned(),
        ));
    }
    if change.current_policy_id != request.projection.policy_id {
        return Some((
            AdjustmentOutcome::Stale,
            "influence current policy does not match the projected policy".to_owned(),
        ));
    }
    if change.proposed_standing == change.current_standing {
        return Some((
            AdjustmentOutcome::Rejected,
            "influence move proposes no standing change".to_owned(),
        ));
    }
    if change.deletes_subject {
        return Some((
            AdjustmentOutcome::Rejected,
            "influence decrease is not deletion".to_owned(),
        ));
    }
    if change.claims_system_wide {
        return Some((
            AdjustmentOutcome::Blocked,
            "one success is not system-wide influence".to_owned(),
        ));
    }
    if matches!(request.policy.operation, AdjustmentOperation::Increase) && !change.within_ceilings
    {
        return Some((
            AdjustmentOutcome::Blocked,
            "influence increase exceeds its ceilings".to_owned(),
        ));
    }
    if change.scope != request.projection.scope_id {
        return Some((
            AdjustmentOutcome::Rejected,
            "influence scope does not match the projected scope".to_owned(),
        ));
    }
    if mentions_authority_grant(&request.usage.writer_utility_note) {
        return Some((
            AdjustmentOutcome::Blocked,
            "writer utility never authorizes an influence move".to_owned(),
        ));
    }
    None
}

/// Completeness of the mirrored influence closure for a material move.
fn check_closure_completeness(request: &AdjustmentRequest) -> Option<(AdjustmentOutcome, String)> {
    let Some(closure) = request.influence_closure.as_ref() else {
        return Some((
            AdjustmentOutcome::Blocked,
            "material influence move needs the complete closure".to_owned(),
        ));
    };
    if closure.stale || closure.closure_revision != request.projection.subject_revision {
        return Some((
            AdjustmentOutcome::Stale,
            "influence closure revision moved".to_owned(),
        ));
    }
    if closure.root_ref != request.projection.subject_handle {
        return Some((
            AdjustmentOutcome::Rejected,
            "influence closure root does not match the subject".to_owned(),
        ));
    }
    if closure.scope_id != request.projection.scope_id {
        return Some((
            AdjustmentOutcome::Rejected,
            "influence closure scope does not match the projected scope".to_owned(),
        ));
    }
    if closure.policy_id != request.policy.policy_id {
        return Some((
            AdjustmentOutcome::Rejected,
            "influence closure policy does not match the governing policy".to_owned(),
        ));
    }
    if closure.state_fence != request.projection.state_fence {
        return Some((
            AdjustmentOutcome::Stale,
            "influence closure fence does not match the projected fence".to_owned(),
        ));
    }
    if closure.current_standing == LocalClosureStanding::Unknown {
        return Some((
            AdjustmentOutcome::Blocked,
            "unknown closure standing never completes".to_owned(),
        ));
    }
    for path in &request.affected {
        if !contains_handle(&closure.dependent_refs, &path.handle) {
            return Some((
                AdjustmentOutcome::Blocked,
                "closure does not cover every affected path".to_owned(),
            ));
        }
    }
    if !closure.unknown_gaps.is_empty() {
        return Some((
            AdjustmentOutcome::Blocked,
            "closure with unknown gaps never completes".to_owned(),
        ));
    }
    if !closure.complete {
        return Some((
            AdjustmentOutcome::Partial,
            "incomplete closure attestation holds the move partial".to_owned(),
        ));
    }
    None
}

// ---------------------------------------------------------------------------
// Public entry point.
// ---------------------------------------------------------------------------

/// Proposes one reversible single-axis adjustment from immutable inputs.
///
/// The function is pure and synchronous: it reads only `request`, allocates
/// nothing, persists nothing, traverses no graph, revokes no grant, and
/// fills no unknown time from any clock. Semantic shortfalls become
/// [`AdjustmentOutcome`] values inside [`Ok`]; only malformed or
/// out-of-bound input becomes [`Err`].
///
/// Exactly one axis moves: the half selected by `policy.axis` must be the
/// only half present, and the unselected axis keeps its exact projected
/// standing and owner references in the returned proposal.
///
/// # Errors
///
/// Returns [`AccessibilityError`] when any bound, shape, ordering, receipt,
/// curation-item, preservation, or denominator check fails closed.
#[allow(clippy::too_many_lines)]
pub fn propose_accessibility_or_influence_adjustment(
    request: &AdjustmentRequest,
) -> Result<AdjustmentProposal, AccessibilityError> {
    preflight_bounds(request)?;
    validate_shapes(request)?;

    // Intrinsic A-05 receipt and curation-item checks; never re-executed.
    request
        .receipt
        .validate()
        .map_err(|err| AccessibilityError::Receipt {
            detail: redact(&err.to_string()),
        })?;
    request
        .item
        .validate()
        .map_err(|err| AccessibilityError::Receipt {
            detail: redact(&err.to_string()),
        })?;
    request
        .grounded
        .validate()
        .map_err(|err| AccessibilityError::Receipt {
            detail: redact(&err.to_string()),
        })?;
    if request.receipt.terminal_disposition != "accepted"
        && request.receipt.terminal_disposition != "partial"
    {
        return unchanged_proposal(
            request,
            AdjustmentOutcome::Rejected,
            "a-05 receipt is not accepted or partial",
        );
    }
    if request.receipt.validator_policy != request.policy.policy_id {
        return unchanged_proposal(
            request,
            AdjustmentOutcome::Abstention,
            "receipt policy does not bind the governing policy",
        );
    }
    if request.item.payload.kind() != CurationKind::Accessibility {
        return unchanged_proposal(
            request,
            AdjustmentOutcome::Rejected,
            "curation item is not the accessibility kind",
        );
    }
    // The A-03 accessibility payload names the subject it adjusts.
    let payload_handle =
        if let eliot_dreamer_contracts::curation::CurationPayload::Accessibility(payload) =
            &request.item.payload
        {
            payload.handle.clone()
        } else {
            return unchanged_proposal(
                request,
                AdjustmentOutcome::Rejected,
                "curation payload does not carry an accessibility handle",
            );
        };
    if payload_handle != request.projection.subject_handle {
        return unchanged_proposal(
            request,
            AdjustmentOutcome::Rejected,
            "curation subject does not bind the projected subject",
        );
    }
    if request.frozen_bundle_digest != request.receipt.bundle_digest
        || request.frozen_manifest_digest != request.receipt.manifest_digest
    {
        return unchanged_proposal(
            request,
            AdjustmentOutcome::Stale,
            "frozen bundle no longer matches the receipt bundle",
        );
    }
    if request.item.task_id != request.projection.task_id
        || request.item.scope_id != request.projection.scope_id
    {
        return unchanged_proposal(
            request,
            AdjustmentOutcome::Stale,
            "curation task or scope moved from the projection",
        );
    }
    if request.policy.target_subject != request.projection.subject_handle {
        return unchanged_proposal(
            request,
            AdjustmentOutcome::Rejected,
            "policy target does not name the projected subject",
        );
    }
    if request.policy.policy_id != request.projection.policy_id {
        return unchanged_proposal(
            request,
            AdjustmentOutcome::Stale,
            "governing policy moved from the projection",
        );
    }

    // The policy-selected half must be the only half present.
    let axis_half_ok = match request.policy.axis {
        Axis::Accessibility => request.accessibility.is_some(),
        Axis::Influence => request.influence.is_some(),
    };
    if !axis_half_ok {
        return unchanged_proposal(
            request,
            AdjustmentOutcome::Rejected,
            "policy axis does not select the supplied half",
        );
    }

    // Seven preservation dimensions, judged intrinsically with no averaging
    // and without invoking any post-handler.
    request
        .preservation
        .validate()
        .map_err(|err| AccessibilityError::Preservation {
            detail: redact(&err.to_string()),
        })?;
    if request.preservation.overall().is_err() {
        return unchanged_proposal(
            request,
            AdjustmentOutcome::Blocked,
            "preservation is judged per dimension with no averaging",
        );
    }

    // The closure denominator must cover exactly the affected handles.
    request
        .closure_denominator
        .validate()
        .map_err(|err| AccessibilityError::Denominator {
            detail: redact(&err.to_string()),
        })?;
    {
        let mut affected_handles: Vec<String> = request
            .affected
            .iter()
            .map(|path| path.handle.clone())
            .collect();
        affected_handles.sort_unstable();
        let mut denominator_members = request.closure_denominator.members.clone();
        denominator_members.sort_unstable();
        if !sorted_set_eq(&affected_handles, &denominator_members) {
            return unchanged_proposal(
                request,
                AdjustmentOutcome::Blocked,
                "closure denominator must cover exactly the affected handles",
            );
        }
    }

    // Build the before/proposed snapshots: only the selected axis may differ.
    let before = AxisStateSnapshot {
        accessibility: request.projection.accessibility,
        influence: request.projection.influence,
    };
    let mut proposed = before;
    let (observable, verifier, window_note, inverse_note, expiry_ms, renewal_condition) =
        match request.policy.axis {
            Axis::Accessibility => {
                let Some(change) = request.accessibility.as_ref() else {
                    return unchanged_proposal(
                        request,
                        AdjustmentOutcome::Rejected,
                        "policy selects accessibility but the half is absent",
                    );
                };
                proposed.accessibility = change.proposed_state;
                (
                    change.observable.clone(),
                    request.policy.verifier.clone(),
                    change.window_note.clone(),
                    change.inverse_note.clone(),
                    change.expiry_ms,
                    request.policy.renewal_condition.clone(),
                )
            }
            Axis::Influence => {
                let Some(change) = request.influence.as_ref() else {
                    return unchanged_proposal(
                        request,
                        AdjustmentOutcome::Rejected,
                        "policy selects influence but the half is absent",
                    );
                };
                proposed.influence = change.proposed_standing;
                (
                    change.effect_note.clone(),
                    request.policy.verifier.clone(),
                    request.policy.observation_window_note.clone(),
                    request.policy.inverse_note.clone(),
                    request.policy.expiry_ms,
                    request.policy.renewal_condition.clone(),
                )
            }
        };
    let digest = proposal_digest(
        request,
        before,
        proposed,
        &observable,
        &verifier,
        &inverse_note,
        expiry_ms,
    )?;
    let settle = |outcome: AdjustmentOutcome,
                  note: &str|
     -> Result<AdjustmentProposal, AccessibilityError> {
        Ok(ok_proposal(
            request,
            before,
            proposed,
            &Settlement {
                outcome,
                observable: &observable,
                verifier: &verifier,
                window_note: &window_note,
                inverse_note: &inverse_note,
                expiry_ms,
                renewal_condition: &renewal_condition,
                digest: &digest,
                note,
            },
        ))
    };

    // Half-specific semantics run before protections so the returned note
    // names the tightest blocker first. The half present always matches the
    // policy axis here: shapes require exactly one half and the axis check
    // above rejects a policy that selects the absent half.
    if let Some(change) = request.accessibility.as_ref()
        && let Some((outcome, note)) = check_accessibility_semantics(request, change)
    {
        return settle(outcome, &note);
    }
    if let Some(change) = request.influence.as_ref()
        && let Some((outcome, note)) = check_influence_semantics(request, change)
    {
        return settle(outcome, &note);
    }
    if request.influence.is_some()
        && let Some((outcome, note)) = check_closure_completeness(request)
    {
        return settle(outcome, &note);
    }
    if request.influence.is_some() && request.policy.expiry_ms.is_none() {
        return settle(
            AdjustmentOutcome::Blocked,
            "influence move needs an exact expiry",
        );
    }

    // Every protection reason is evaluated; missing or unknown mandatory
    // protection fails closed on material moves.
    match evaluate_protections(request) {
        ProtectionVerdict::Clear => {}
        ProtectionVerdict::Partial(note) => return settle(AdjustmentOutcome::Partial, &note),
        ProtectionVerdict::Blocked(note) => return settle(AdjustmentOutcome::Blocked, &note),
    }

    // Independent evidence minimum: writer utility never counts, because the
    // count below only admits independent outcome observations.
    if u64::from(request.policy.evidence_minimum) > request.usage.outcome_observations {
        return settle(
            AdjustmentOutcome::Partial,
            "independent outcome evidence is below the policy minimum",
        );
    }

    // Every affected path needs exactly one disposition, and no disposition
    // may invent or drop a path.
    {
        let mut affected_handles: Vec<String> = request
            .affected
            .iter()
            .map(|path| path.handle.clone())
            .collect();
        affected_handles.sort_unstable();
        let mut disposition_handles: Vec<String> = request
            .dispositions
            .iter()
            .map(|outcome| outcome.handle.clone())
            .collect();
        disposition_handles.sort_unstable();
        if !sorted_set_eq(&affected_handles, &disposition_handles) {
            return settle(
                AdjustmentOutcome::Blocked,
                "every affected path needs exactly one disposition",
            );
        }
    }
    for path in &request.affected {
        let Some(outcome) = request
            .dispositions
            .iter()
            .find(|outcome| outcome.handle == path.handle)
        else {
            if path.required {
                return settle(
                    AdjustmentOutcome::Blocked,
                    "missing required path disposition blocks completeness",
                );
            }
            continue;
        };
        if outcome.owner != path.owner {
            return settle(
                AdjustmentOutcome::Blocked,
                "path disposition owner does not match the affected owner",
            );
        }
        if outcome.disposition == DependentDispositionKind::Blocked {
            return settle(
                AdjustmentOutcome::Blocked,
                "blocked path disposition blocks completeness",
            );
        }
    }

    // Restore moves must name the prior revision they return to.
    if matches!(request.policy.operation, AdjustmentOperation::Restore) {
        let restores = match request.policy.axis {
            Axis::Accessibility => request.accessibility.as_ref().is_some_and(|change| {
                change.before_revision == request.projection.subject_revision
            }),
            Axis::Influence => request
                .influence
                .as_ref()
                .is_some_and(|change| change.current_policy_id == request.projection.policy_id),
        };
        if !restores {
            return settle(
                AdjustmentOutcome::Blocked,
                "restore needs the exact prior revision binding",
            );
        }
    }

    settle(
        AdjustmentOutcome::Complete,
        "single-axis adjustment proposed with complete evidence",
    )
}

/// Maps a terminal outcome to the closest A-05 hint without re-running validation.
///
/// Returns `None` for [`AdjustmentOutcome::Complete`]; every other outcome
/// maps to the rejection class a downstream gate would most likely record.
/// The mapping is diagnostic only and never executes validation.
#[must_use]
pub fn outcome_rejection_hint(outcome: &AdjustmentOutcome) -> Option<CurationRejectionCode> {
    match outcome {
        AdjustmentOutcome::Complete => None,
        AdjustmentOutcome::Partial | AdjustmentOutcome::Blocked => {
            Some(CurationRejectionCode::PreservationFailed)
        }
        AdjustmentOutcome::Abstention => Some(CurationRejectionCode::LineageMismatch),
        AdjustmentOutcome::Stale | AdjustmentOutcome::Rejected => {
            Some(CurationRejectionCode::IdentityMismatch)
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use eliot_contracts::{EpochId, EpochLineageId, ResourceGeneration};
    use std::num::NonZeroU64;
    use eliot_dreamer_contracts::candidate::{DimensionVerdict, PreservationDimension};
    use eliot_dreamer_contracts::curation::{AccessibilityPayload, TargetEvidence};
    use eliot_dreamer_contracts::{
        AtomicityMode, ClaimResidue, Requester, RequesterOrigin, SupportState, kind_family,
    };

    fn test_fence() -> StateFence {
        let epoch = EpochId::new(
            EpochLineageId::new("550e8400-e29b-41d4-a716-446655440000")
                .expect("canonical test lineage-A"),
            NonZeroU64::new(1).expect("non-zero test sequence"),
        )
        .expect("valid test epoch");
        StateFence::new(epoch, ResourceGeneration::genesis())
    }

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

    fn test_preservation() -> PreservationReport {
        let dimensions = [
            PreservationDimension::Coverage,
            PreservationDimension::Faithfulness,
            PreservationDimension::Lineage,
            PreservationDimension::Reversibility,
            PreservationDimension::AuthorityCeiling,
            PreservationDimension::DependencyClosure,
            PreservationDimension::ProvenanceRetention,
        ];
        PreservationReport {
            verdicts: dimensions
                .iter()
                .map(|dimension| DimensionVerdict {
                    dimension: *dimension,
                    passed: true,
                    known: true,
                    note: "holds for this candidate".to_owned(),
                })
                .collect(),
        }
    }

    fn test_grounded() -> GroundedDreamDraft {
        GroundedDreamDraft {
            schema_version: 1,
            job_id: "job-1".to_owned(),
            draft_digest: "a".repeat(64),
            residues: vec![ClaimResidue {
                claim: "warm keys stay retrievable".to_owned(),
                state: SupportState::Supported,
                detail: "obs-1 shows warm-key retrieval".to_owned(),
            }],
            coverage_note: "one claim accounted".to_owned(),
        }
    }

    fn test_item() -> ValidatedCurationItem {
        let payload =
            eliot_dreamer_contracts::CurationPayload::Accessibility(AccessibilityPayload {
                handle: "mem-1".to_owned(),
                note: "captioned".to_owned(),
                target_evidence: TargetEvidence {
                    targets: vec!["mem-1".to_owned()],
                    evidence_refs: vec!["e-1".to_owned()],
                },
            });
        ValidatedCurationItem {
            receipt: test_receipt(),
            kind_spelling: "accessibility".to_owned(),
            family_spelling: kind_family(CurationKind::Accessibility).to_owned(),
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

    fn test_owners() -> AxisOwnerRefs {
        AxisOwnerRefs {
            existence_owner: "owner-existence".to_owned(),
            support_owner: "owner-support".to_owned(),
            accessibility_owner: "owner-access".to_owned(),
            influence_owner: "owner-influence".to_owned(),
            privacy_owner: "owner-privacy".to_owned(),
            assurance_owner: "owner-assurance".to_owned(),
        }
    }

    fn test_projection() -> CurrentAxisProjection {
        CurrentAxisProjection {
            subject_handle: "mem-1".to_owned(),
            subject_kind: SubjectKind::StoredRecord,
            subject_revision: "rev-2".to_owned(),
            scope_id: "scope-1".to_owned(),
            task_id: "task-1".to_owned(),
            policy_id: "policy-7".to_owned(),
            state_fence: test_fence(),
            owners: test_owners(),
            accessibility: AccessibilityStanding::Exposed,
            influence: InfluenceStanding::Full,
        }
    }

    fn test_usage() -> UsageAndOutcomeEvidence {
        UsageAndOutcomeEvidence {
            retrieval_attempts: 40,
            retrieval_successes: 31,
            outcome_observations: 3,
            outcome_successes: 2,
            writer_utility_note: "writer finds the record handy".to_owned(),
            usage_window_note: "window w-9".to_owned(),
            unknown_usage: false,
        }
    }

    fn test_protection() -> ProtectionAndNegativeMemory {
        ProtectionAndNegativeMemory {
            protections: vec![ProtectionReason {
                reason_id: "minority-evidence".to_owned(),
                trigger: "minority report m-1".to_owned(),
                mandatory: true,
                satisfied: true,
                unknown: false,
                counterevidence_ref: Some("m-1".to_owned()),
            }],
            negative_memory: vec![NegativeMemoryEntry {
                trigger: "m-1".to_owned(),
                extinguished: false,
                extinction_evidence_ref: None,
                reopen_evidence_ref: None,
            }],
            retained_counterevidence_refs: vec!["m-1".to_owned()],
        }
    }

    fn test_policy() -> AdjustmentPolicy {
        AdjustmentPolicy {
            policy_id: "policy-7".to_owned(),
            axis: Axis::Accessibility,
            operation: AdjustmentOperation::Decrease,
            direction: AdjustmentDirection::Lower,
            target_subject: "mem-1".to_owned(),
            task_local_only: false,
            evidence_minimum: 2,
            mandatory_visibility: "provenance and audit stay visible".to_owned(),
            visibility_ceiling: "no global broadcast".to_owned(),
            influence_ceiling: "no new decisions".to_owned(),
            privacy_ceiling: "no wider audience".to_owned(),
            verifier: "verifier-7".to_owned(),
            observation_window_note: "window w-10".to_owned(),
            inverse_note: "restore rev-2 exposure".to_owned(),
            expiry_ms: Some(1_800_000_000_000),
            renewal_condition: "reopen when scope-1 frontier advances".to_owned(),
            max_affected: 64,
            max_evidence_items: 64,
        }
    }

    fn test_affected() -> Vec<AffectedPath> {
        vec![AffectedPath {
            handle: "dep-1".to_owned(),
            kind: AffectedPathKind::Derivative,
            owner: "owner-access".to_owned(),
            required: true,
        }]
    }

    fn test_dispositions() -> Vec<PathDisposition> {
        vec![PathDisposition {
            handle: "dep-1".to_owned(),
            disposition: DependentDispositionKind::Revalidate,
            before_identity: "dep-1@rev-2".to_owned(),
            proposed_identity: "dep-1@rev-3".to_owned(),
            owner: "owner-access".to_owned(),
            reason: "revalidate derivative against restricted surfacing".to_owned(),
            verifier: "verifier-7".to_owned(),
            inverse_note: "restore dep-1@rev-2".to_owned(),
        }]
    }

    fn valid_request() -> AdjustmentRequest {
        let receipt = test_receipt();
        AdjustmentRequest {
            item: test_item(),
            grounded: test_grounded(),
            frozen_bundle_digest: receipt.bundle_digest.clone(),
            frozen_manifest_digest: receipt.manifest_digest.clone(),
            projection: test_projection(),
            usage: test_usage(),
            protection: test_protection(),
            influence_closure: None,
            policy: test_policy(),
            accessibility: Some(AccessibilityChange {
                before_owner: "owner-access".to_owned(),
                before_revision: "rev-2".to_owned(),
                before_state: AccessibilityStanding::Exposed,
                proposed_state: AccessibilityStanding::Restricted,
                surface: AccessibilitySurface {
                    scope: "scope-1".to_owned(),
                    audience: "reviewers".to_owned(),
                    query_surface: "query-1".to_owned(),
                    context_surface: "ctx-1".to_owned(),
                    index_surface: "idx-1".to_owned(),
                },
                grounded_reason: "obs-1 shows over-exposure".to_owned(),
                protected_verifier_access: "verifier-7 retains read".to_owned(),
                privacy_ceiling: "no wider audience".to_owned(),
                observable: "query-1 no longer lists mem-1".to_owned(),
                window_note: "window w-10".to_owned(),
                inverse_note: "restore rev-2 exposure".to_owned(),
                expiry_ms: Some(1_800_000_000_000),
                projection_plan: "ctx-1 keeps provenance and audit".to_owned(),
                global_scope: false,
                widens_privacy: false,
                widens_support: false,
                widens_influence: false,
                widens_effect: false,
                hides_provenance: false,
                hides_audit: false,
                hides_counterevidence: false,
            }),
            influence: None,
            affected: test_affected(),
            dispositions: test_dispositions(),
            preservation: test_preservation(),
            receipt,
            closure_denominator: TargetDenominator {
                mode: AtomicityMode::PerMember,
                members: vec!["dep-1".to_owned()],
                expected_total: 1,
            },
        }
    }

    fn valid_influence_request() -> AdjustmentRequest {
        let mut request = valid_request();
        request.policy.axis = Axis::Influence;
        request.policy.operation = AdjustmentOperation::Decrease;
        request.policy.direction = AdjustmentDirection::Lower;
        request.accessibility = None;
        request.influence = Some(InfluenceChange {
            current_standing: InfluenceStanding::Full,
            current_policy_id: "policy-7".to_owned(),
            current_graph_note: "graph g-1".to_owned(),
            proposed_standing: InfluenceStanding::Bounded,
            scope: "scope-1".to_owned(),
            decision_ref: "dec-1".to_owned(),
            effect_note: "bounds downstream ranking only".to_owned(),
            review_owner_ref: "owner-review".to_owned(),
            decision_owner_ref: "owner-decision".to_owned(),
            preserved_other_axes_note: "support, privacy, and assurance untouched".to_owned(),
            within_ceilings: true,
            deletes_subject: false,
            claims_system_wide: false,
        });
        request.affected = vec![
            AffectedPath {
                handle: "dec-1".to_owned(),
                kind: AffectedPathKind::Decision,
                owner: "owner-decision".to_owned(),
                required: true,
            },
            AffectedPath {
                handle: "dep-1".to_owned(),
                kind: AffectedPathKind::Derivative,
                owner: "owner-access".to_owned(),
                required: true,
            },
        ];
        request.dispositions = vec![
            PathDisposition {
                handle: "dec-1".to_owned(),
                disposition: DependentDispositionKind::ReconcileByOwner,
                before_identity: "dec-1@rev-2".to_owned(),
                proposed_identity: "dec-1@rev-3".to_owned(),
                owner: "owner-decision".to_owned(),
                reason: "reconcile decision against bounded influence".to_owned(),
                verifier: "verifier-7".to_owned(),
                inverse_note: "restore dec-1@rev-2".to_owned(),
            },
            PathDisposition {
                handle: "dep-1".to_owned(),
                disposition: DependentDispositionKind::Revalidate,
                before_identity: "dep-1@rev-2".to_owned(),
                proposed_identity: "dep-1@rev-3".to_owned(),
                owner: "owner-access".to_owned(),
                reason: "revalidate derivative against bounded influence".to_owned(),
                verifier: "verifier-7".to_owned(),
                inverse_note: "restore dep-1@rev-2".to_owned(),
            },
        ];
        request.closure_denominator = TargetDenominator {
            mode: AtomicityMode::PerMember,
            members: vec!["dec-1".to_owned(), "dep-1".to_owned()],
            expected_total: 2,
        };
        request.influence_closure = Some(LocalInfluenceClosure {
            closure_id: "closure-1".to_owned(),
            root_ref: "mem-1".to_owned(),
            dependent_refs: vec!["dec-1".to_owned(), "dep-1".to_owned()],
            invalidation_reason: None,
            current_standing: LocalClosureStanding::Active,
            scope_id: "scope-1".to_owned(),
            policy_id: "policy-7".to_owned(),
            closure_revision: "rev-2".to_owned(),
            state_fence: test_fence(),
            complete: true,
            stale: false,
            unknown_gaps: Vec::new(),
        });
        request
    }

    // WORK_UNIT_CASE: 669/1
    #[test]
    fn case_01_accessibility_only_typed_payload_completes() {
        let request = valid_request();
        assert_eq!(request.item.payload.kind(), CurationKind::Accessibility);
        let result =
            propose_accessibility_or_influence_adjustment(&request).expect("valid request parses");
        assert_eq!(result.outcome, AdjustmentOutcome::Complete);
        assert_eq!(result.axis, Axis::Accessibility);
        assert_eq!(result.subject_handle, "mem-1");
        assert_eq!(result.subject_revision, "rev-2");
        assert_eq!(
            result.before_snapshot.accessibility,
            AccessibilityStanding::Exposed
        );
        assert_eq!(
            result.proposed_snapshot.accessibility,
            AccessibilityStanding::Restricted
        );
        assert!(is_hex64_lower(&result.proposal_digest));
        assert_eq!(outcome_rejection_hint(&result.outcome), None);
        // Deterministic replay binds the same digest; a moved subject rebinds.
        let again = propose_accessibility_or_influence_adjustment(&request).expect("replay parses");
        assert_eq!(again.proposal_digest, result.proposal_digest);
        let mut moved = request.clone();
        moved.projection.subject_revision = "rev-3".to_owned();
        let rebound =
            propose_accessibility_or_influence_adjustment(&moved).expect("moved revision parses");
        assert_ne!(rebound.proposal_digest, result.proposal_digest);
    }

    // WORK_UNIT_CASE: 669/4
    #[test]
    fn case_04_exactly_one_axis_differs() {
        let request = valid_request();
        let result =
            propose_accessibility_or_influence_adjustment(&request).expect("valid request parses");
        assert_eq!(
            result.before_snapshot.accessibility,
            AccessibilityStanding::Exposed
        );
        assert_eq!(
            result.proposed_snapshot.accessibility,
            AccessibilityStanding::Restricted
        );
        assert_ne!(
            result.before_snapshot.accessibility,
            result.proposed_snapshot.accessibility
        );
        assert_eq!(
            result.before_snapshot.influence,
            result.proposed_snapshot.influence
        );
        // A multi-axis patch is malformed, never a proposal.
        let mut both = request.clone();
        both.influence = Some(InfluenceChange {
            current_standing: InfluenceStanding::Full,
            current_policy_id: "policy-7".to_owned(),
            current_graph_note: "graph g-1".to_owned(),
            proposed_standing: InfluenceStanding::Bounded,
            scope: "scope-1".to_owned(),
            decision_ref: "dec-1".to_owned(),
            effect_note: "bounds ranking".to_owned(),
            review_owner_ref: "owner-review".to_owned(),
            decision_owner_ref: "owner-decision".to_owned(),
            preserved_other_axes_note: "other axes untouched".to_owned(),
            within_ceilings: true,
            deletes_subject: false,
            claims_system_wide: false,
        });
        assert!(propose_accessibility_or_influence_adjustment(&both).is_err());
        // A policy that selects the absent half is rejected, not completed.
        let mut mismatched = request.clone();
        mismatched.policy.axis = Axis::Influence;
        let result = propose_accessibility_or_influence_adjustment(&mismatched)
            .expect("axis mismatch is an outcome");
        assert_eq!(result.outcome, AdjustmentOutcome::Rejected);
    }

    // WORK_UNIT_CASE: 669/9
    #[test]
    fn case_09_unselected_axes_retain_exact_owner_refs() {
        let request = valid_request();
        let frozen = request.clone();
        let result =
            propose_accessibility_or_influence_adjustment(&request).expect("valid request parses");
        assert_eq!(request, frozen, "pure handler never mutates its inputs");
        assert_eq!(result.before_owners, test_owners());
        assert_eq!(result.proposed_owners, result.before_owners);
        assert_eq!(result.proposed_owners.existence_owner, "owner-existence");
        assert_eq!(result.proposed_owners.support_owner, "owner-support");
        assert_eq!(result.proposed_owners.accessibility_owner, "owner-access");
        assert_eq!(result.proposed_owners.influence_owner, "owner-influence");
        assert_eq!(result.proposed_owners.privacy_owner, "owner-privacy");
        assert_eq!(result.proposed_owners.assurance_owner, "owner-assurance");
        assert_eq!(result.before_snapshot.influence, InfluenceStanding::Full);
        assert_eq!(result.proposed_snapshot.influence, InfluenceStanding::Full);
        // The influence half retains its refs too.
        let influence = valid_influence_request();
        let result = propose_accessibility_or_influence_adjustment(&influence)
            .expect("valid influence parses");
        assert_eq!(result.outcome, AdjustmentOutcome::Complete);
        assert_eq!(result.proposed_owners, test_owners());
        assert_eq!(
            result.before_snapshot.accessibility,
            result.proposed_snapshot.accessibility
        );
    }

    // WORK_UNIT_CASE: 669/23
    #[test]
    fn case_23_partial_closure_never_completes_influence() {
        let complete = valid_influence_request();
        let result = propose_accessibility_or_influence_adjustment(&complete)
            .expect("complete closure parses");
        assert_eq!(result.outcome, AdjustmentOutcome::Complete);
        // An unattested closure holds the move partial, never complete.
        let mut partial = complete.clone();
        if let Some(closure) = partial.influence_closure.as_mut() {
            closure.complete = false;
        }
        let result = propose_accessibility_or_influence_adjustment(&partial)
            .expect("partial closure is an outcome");
        assert_eq!(result.outcome, AdjustmentOutcome::Partial);
        assert_ne!(result.outcome, AdjustmentOutcome::Complete);
        // Unknown gaps block the move outright.
        let mut gapped = complete.clone();
        if let Some(closure) = gapped.influence_closure.as_mut() {
            closure.unknown_gaps = vec!["cue-9".to_owned()];
        }
        let result = propose_accessibility_or_influence_adjustment(&gapped)
            .expect("gapped closure is an outcome");
        assert_eq!(result.outcome, AdjustmentOutcome::Blocked);
        // A stale closure revision is stale, never complete.
        let mut stale = complete.clone();
        if let Some(closure) = stale.influence_closure.as_mut() {
            closure.stale = true;
        }
        let result = propose_accessibility_or_influence_adjustment(&stale)
            .expect("stale closure is an outcome");
        assert_eq!(result.outcome, AdjustmentOutcome::Stale);
        // A missing closure blocks a material influence move.
        let mut missing = complete.clone();
        missing.influence_closure = None;
        let result = propose_accessibility_or_influence_adjustment(&missing)
            .expect("missing closure is an outcome");
        assert_eq!(result.outcome, AdjustmentOutcome::Blocked);
    }

    // WORK_UNIT_CASE: 669/34
    #[test]
    fn case_34_missing_mandatory_protection_fails_closed() {
        let mut request = valid_request();
        request.protection.protections[0].satisfied = false;
        let result = propose_accessibility_or_influence_adjustment(&request)
            .expect("missing protection is an outcome");
        assert_eq!(result.outcome, AdjustmentOutcome::Blocked);
        assert_eq!(result.axis, Axis::Accessibility);
        // Unknown mandatory protection fails closed on material moves too.
        let mut unknown = valid_request();
        unknown.protection.protections[0].satisfied = false;
        unknown.protection.protections[0].unknown = true;
        let result = propose_accessibility_or_influence_adjustment(&unknown)
            .expect("unknown protection is an outcome");
        assert_eq!(result.outcome, AdjustmentOutcome::Blocked);
        // A task-local move degrades to partial instead of completing.
        let mut local = unknown.clone();
        local.policy.task_local_only = true;
        let result = propose_accessibility_or_influence_adjustment(&local)
            .expect("task-local gap is an outcome");
        assert_eq!(result.outcome, AdjustmentOutcome::Partial);
        assert_ne!(result.outcome, AdjustmentOutcome::Complete);
    }

    // WORK_UNIT_CASE: 669/41
    #[test]
    fn case_41_global_dormancy_on_non_use_alone_is_blocked() {
        let mut request = valid_request();
        if let Some(change) = request.accessibility.as_mut() {
            change.proposed_state = AccessibilityStanding::Dormant;
            change.global_scope = true;
        }
        request.usage.outcome_observations = 0;
        request.usage.outcome_successes = 0;
        let result = propose_accessibility_or_influence_adjustment(&request)
            .expect("dormancy shortfall is an outcome");
        assert_eq!(result.outcome, AdjustmentOutcome::Blocked);
        // Genuine outcome evidence lifts the dormancy block.
        let mut grounded = request.clone();
        grounded.usage.outcome_observations = 2;
        grounded.usage.outcome_successes = 2;
        let result = propose_accessibility_or_influence_adjustment(&grounded)
            .expect("grounded dormancy parses");
        assert_eq!(result.outcome, AdjustmentOutcome::Complete);
        assert_eq!(
            result.proposed_snapshot.accessibility,
            AccessibilityStanding::Dormant
        );
    }
}
