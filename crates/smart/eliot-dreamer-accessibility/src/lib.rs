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
    use eliot_dreamer_contracts::candidate::{DimensionVerdict, PreservationDimension};
    use eliot_dreamer_contracts::curation::{AccessibilityPayload, RepairPayload, TargetEvidence};
    use eliot_dreamer_contracts::{
        AtomicityMode, ClaimResidue, Requester, RequesterOrigin, SupportState, kind_family,
    };
    use std::num::NonZeroU64;

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

    // Shared builders for the remaining matrix cases; the six cases above are
    // intentionally left byte-identical.

    fn test_fence_seq(sequence: u64) -> StateFence {
        let epoch = EpochId::new(
            EpochLineageId::new("550e8400-e29b-41d4-a716-446655440000")
                .expect("canonical test lineage-B"),
            NonZeroU64::new(sequence).expect("non-zero test sequence"),
        )
        .expect("valid test epoch");
        StateFence::new(epoch, ResourceGeneration::genesis())
    }

    fn many_sorted(prefix: &str, count: usize) -> Vec<String> {
        (0..count)
            .map(|index| format!("{prefix}-{index:04}"))
            .collect()
    }

    fn path_with(handle: &str, kind: AffectedPathKind) -> AffectedPath {
        AffectedPath {
            handle: handle.to_owned(),
            kind,
            owner: "owner-access".to_owned(),
            required: true,
        }
    }

    fn disposition_with(handle: &str, disposition: DependentDispositionKind) -> PathDisposition {
        PathDisposition {
            handle: handle.to_owned(),
            disposition,
            before_identity: format!("{handle}@rev-2"),
            proposed_identity: format!("{handle}@rev-3"),
            owner: "owner-access".to_owned(),
            reason: format!("reconcile {handle} against the proposed state"),
            verifier: "verifier-7".to_owned(),
            inverse_note: format!("restore {handle}@rev-2"),
        }
    }

    fn two_path_request() -> AdjustmentRequest {
        let mut request = valid_request();
        request.affected = vec![
            path_with("ctx-1", AffectedPathKind::Context),
            path_with("dep-1", AffectedPathKind::Derivative),
        ];
        request.dispositions = vec![
            disposition_with("ctx-1", DependentDispositionKind::Revalidate),
            disposition_with("dep-1", DependentDispositionKind::Revalidate),
        ];
        request.closure_denominator = TargetDenominator {
            mode: AtomicityMode::PerMember,
            members: vec!["ctx-1".to_owned(), "dep-1".to_owned()],
            expected_total: 2,
        };
        request
    }

    fn accessibility_increase_request() -> AdjustmentRequest {
        let mut request = valid_request();
        request.projection.accessibility = AccessibilityStanding::Restricted;
        request.policy.operation = AdjustmentOperation::Increase;
        request.policy.direction = AdjustmentDirection::Raise;
        request.policy.task_local_only = true;
        if let Some(change) = request.accessibility.as_mut() {
            change.before_state = AccessibilityStanding::Restricted;
            change.proposed_state = AccessibilityStanding::Exposed;
        }
        request
    }

    fn influence_half() -> InfluenceChange {
        InfluenceChange {
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
        }
    }

    fn influence_increase_request() -> AdjustmentRequest {
        let mut request = valid_influence_request();
        request.projection.influence = InfluenceStanding::Bounded;
        request.policy.operation = AdjustmentOperation::Increase;
        request.policy.direction = AdjustmentDirection::Raise;
        if let Some(change) = request.influence.as_mut() {
            change.current_standing = InfluenceStanding::Bounded;
            change.proposed_standing = InfluenceStanding::Full;
            change.within_ceilings = true;
        }
        request
    }

    fn repair_item() -> ValidatedCurationItem {
        let mut item = test_item();
        item.kind_spelling = "repair".to_owned();
        item.family_spelling = kind_family(CurationKind::Repair).to_owned();
        item.payload = eliot_dreamer_contracts::CurationPayload::Repair(RepairPayload {
            target: "mem-1".to_owned(),
            repair: "relink".to_owned(),
            target_evidence: TargetEvidence {
                targets: vec!["mem-1".to_owned()],
                evidence_refs: vec!["e-1".to_owned()],
            },
        });
        item
    }

    // WORK_UNIT_CASE: 669/2
    #[test]
    fn case_02_wrong_curation_subtype_is_rejected() {
        let mut request = valid_request();
        request.item = repair_item();
        request
            .item
            .validate()
            .expect("repair item stays intrinsically valid");
        assert_eq!(request.item.payload.kind(), CurationKind::Repair);
        let result = propose_accessibility_or_influence_adjustment(&request)
            .expect("wrong subtype is an outcome");
        assert_eq!(result.outcome, AdjustmentOutcome::Rejected);
        assert_ne!(result.outcome, AdjustmentOutcome::Complete);
        // Kind/payload drift never reaches an outcome: it fails closed first.
        let mut drifted = valid_request();
        drifted.item = repair_item();
        drifted.item.kind_spelling = "accessibility".to_owned();
        assert!(drifted.item.validate().is_err());
        assert!(propose_accessibility_or_influence_adjustment(&drifted).is_err());
    }

    // WORK_UNIT_CASE: 669/3
    #[test]
    fn case_03_missing_or_multiple_axes_are_malformed() {
        let mut neither = valid_request();
        neither.accessibility = None;
        let err = propose_accessibility_or_influence_adjustment(&neither)
            .expect_err("missing half is malformed");
        assert!(matches!(err, AccessibilityError::Malformed { phase, .. } if phase == "halves"));
        let mut both = valid_request();
        both.influence = Some(influence_half());
        let err = propose_accessibility_or_influence_adjustment(&both)
            .expect_err("multiple halves are malformed");
        assert!(matches!(err, AccessibilityError::Malformed { phase, .. } if phase == "halves"));
    }

    // WORK_UNIT_CASE: 669/5
    #[test]
    fn case_05_axes_stay_independent_across_halves() {
        let access = valid_request();
        let result =
            propose_accessibility_or_influence_adjustment(&access).expect("accessibility parses");
        assert_eq!(result.outcome, AdjustmentOutcome::Complete);
        assert_eq!(
            result.before_snapshot.influence,
            result.proposed_snapshot.influence
        );
        let influence = valid_influence_request();
        let result =
            propose_accessibility_or_influence_adjustment(&influence).expect("influence parses");
        assert_eq!(result.outcome, AdjustmentOutcome::Complete);
        assert_eq!(
            result.before_snapshot.accessibility,
            result.proposed_snapshot.accessibility
        );
        assert_eq!(result.before_owners.existence_owner, "owner-existence");
        assert_eq!(result.before_owners.support_owner, "owner-support");
        assert_eq!(result.before_owners.privacy_owner, "owner-privacy");
        assert_eq!(result.before_owners.assurance_owner, "owner-assurance");
        assert_eq!(result.proposed_owners, result.before_owners);
    }

    // WORK_UNIT_CASE: 669/6
    #[test]
    fn case_06_task_scope_bundle_manifest_grounding_mismatch_fails_safe() {
        let mut task = valid_request();
        task.item.task_id = "task-9".to_owned();
        task.item.receipt.task_id = "task-9".to_owned();
        let result =
            propose_accessibility_or_influence_adjustment(&task).expect("task drift is an outcome");
        assert_eq!(result.outcome, AdjustmentOutcome::Stale);
        let mut scope = valid_request();
        scope.item.scope_id = "scope-9".to_owned();
        scope.item.receipt.scope_id = "scope-9".to_owned();
        let result = propose_accessibility_or_influence_adjustment(&scope)
            .expect("scope drift is an outcome");
        assert_eq!(result.outcome, AdjustmentOutcome::Stale);
        let mut bundle = valid_request();
        bundle.frozen_bundle_digest = "0".repeat(64);
        let result = propose_accessibility_or_influence_adjustment(&bundle)
            .expect("bundle drift is an outcome");
        assert_eq!(result.outcome, AdjustmentOutcome::Stale);
        let mut manifest = valid_request();
        manifest.frozen_manifest_digest = "0".repeat(64);
        let result = propose_accessibility_or_influence_adjustment(&manifest)
            .expect("manifest drift is an outcome");
        assert_eq!(result.outcome, AdjustmentOutcome::Stale);
        let mut grounded = valid_request();
        grounded.grounded.residues.clear();
        assert!(propose_accessibility_or_influence_adjustment(&grounded).is_err());
    }

    // WORK_UNIT_CASE: 669/7
    #[test]
    fn case_07_replay_is_deterministic_and_changed_ids_conflict() {
        let request = valid_request();
        let first =
            propose_accessibility_or_influence_adjustment(&request).expect("baseline parses");
        let second =
            propose_accessibility_or_influence_adjustment(&request).expect("replay parses");
        assert_eq!(first.proposal_digest, second.proposal_digest);
        let mut moved = request.clone();
        moved.projection.subject_revision = "rev-3".to_owned();
        let stale = propose_accessibility_or_influence_adjustment(&moved)
            .expect("moved revision is an outcome");
        assert_eq!(stale.outcome, AdjustmentOutcome::Stale);
        assert_ne!(stale.proposal_digest, first.proposal_digest);
        let mut rescoped = valid_influence_request();
        if let Some(change) = rescoped.influence.as_mut() {
            change.scope = "scope-9".to_owned();
        }
        let result = propose_accessibility_or_influence_adjustment(&rescoped)
            .expect("rescoped influence is an outcome");
        assert_eq!(result.outcome, AdjustmentOutcome::Rejected);
    }

    // WORK_UNIT_CASE: 669/8
    #[test]
    fn case_08_pure_call_never_mutates_inputs() {
        let access = valid_request();
        let frozen_access = access.clone();
        let first =
            propose_accessibility_or_influence_adjustment(&access).expect("accessibility parses");
        let second = propose_accessibility_or_influence_adjustment(&access).expect("replay parses");
        assert_eq!(access, frozen_access);
        assert_eq!(first.proposal_digest, second.proposal_digest);
        let influence = valid_influence_request();
        let frozen_influence = influence.clone();
        let third =
            propose_accessibility_or_influence_adjustment(&influence).expect("influence parses");
        let fourth =
            propose_accessibility_or_influence_adjustment(&influence).expect("replay parses");
        assert_eq!(influence, frozen_influence);
        assert_eq!(third.proposal_digest, fourth.proposal_digest);
    }

    // WORK_UNIT_CASE: 669/10
    #[test]
    fn case_10_scoped_dormancy_with_grounded_evidence_completes() {
        let mut request = valid_request();
        if let Some(change) = request.accessibility.as_mut() {
            change.proposed_state = AccessibilityStanding::Dormant;
            change.global_scope = false;
        }
        let result = propose_accessibility_or_influence_adjustment(&request)
            .expect("scoped dormancy parses");
        assert_eq!(result.outcome, AdjustmentOutcome::Complete);
        assert_eq!(
            result.proposed_snapshot.accessibility,
            AccessibilityStanding::Dormant
        );
        assert_eq!(
            result.before_snapshot.accessibility,
            AccessibilityStanding::Exposed
        );
    }

    // WORK_UNIT_CASE: 669/11
    #[test]
    fn case_11_protected_verifier_visibility_is_required_and_kept() {
        let mut blank_access = valid_request();
        if let Some(change) = blank_access.accessibility.as_mut() {
            change.protected_verifier_access = String::new();
        }
        assert!(propose_accessibility_or_influence_adjustment(&blank_access).is_err());
        let mut blank_verifier = valid_request();
        blank_verifier.policy.verifier = String::new();
        assert!(propose_accessibility_or_influence_adjustment(&blank_verifier).is_err());
        let request = valid_request();
        let result =
            propose_accessibility_or_influence_adjustment(&request).expect("guarded move parses");
        assert_eq!(result.outcome, AdjustmentOutcome::Complete);
        assert_eq!(result.verifier, "verifier-7");
        assert!(!result.observable.is_empty());
    }

    // WORK_UNIT_CASE: 669/12
    #[test]
    fn case_12_task_local_increase_completes_but_never_widens_ceilings() {
        let request = accessibility_increase_request();
        let result = propose_accessibility_or_influence_adjustment(&request)
            .expect("task-local increase parses");
        assert_eq!(result.outcome, AdjustmentOutcome::Complete);
        assert_eq!(
            result.proposed_snapshot.accessibility,
            AccessibilityStanding::Exposed
        );
        for flag in 0..4 {
            let mut widened = request.clone();
            if let Some(change) = widened.accessibility.as_mut() {
                match flag {
                    0 => change.widens_privacy = true,
                    1 => change.widens_support = true,
                    2 => change.widens_influence = true,
                    _ => change.widens_effect = true,
                }
            }
            let result = propose_accessibility_or_influence_adjustment(&widened)
                .expect("widening is an outcome");
            assert_eq!(result.outcome, AdjustmentOutcome::Blocked);
        }
    }

    // WORK_UNIT_CASE: 669/13
    #[test]
    fn case_13_decrease_never_hides_provenance_audit_or_counterevidence() {
        let request = valid_request();
        let result =
            propose_accessibility_or_influence_adjustment(&request).expect("plain decrease parses");
        assert_eq!(result.outcome, AdjustmentOutcome::Complete);
        for flag in 0..3 {
            let mut hidden = request.clone();
            if let Some(change) = hidden.accessibility.as_mut() {
                match flag {
                    0 => change.hides_provenance = true,
                    1 => change.hides_audit = true,
                    _ => change.hides_counterevidence = true,
                }
            }
            let result = propose_accessibility_or_influence_adjustment(&hidden)
                .expect("hiding is an outcome");
            assert_eq!(result.outcome, AdjustmentOutcome::Blocked);
        }
    }

    // WORK_UNIT_CASE: 669/14
    #[test]
    fn case_14_zero_or_unknown_use_never_justifies_global_dormancy() {
        let mut zero = valid_request();
        zero.usage.retrieval_attempts = 0;
        zero.usage.retrieval_successes = 0;
        zero.usage.outcome_observations = 0;
        zero.usage.outcome_successes = 0;
        if let Some(change) = zero.accessibility.as_mut() {
            change.proposed_state = AccessibilityStanding::Dormant;
            change.global_scope = true;
        }
        let result = propose_accessibility_or_influence_adjustment(&zero)
            .expect("zero-use dormancy is an outcome");
        assert_eq!(result.outcome, AdjustmentOutcome::Blocked);
        let mut unknown = valid_request();
        unknown.usage.unknown_usage = true;
        if let Some(change) = unknown.accessibility.as_mut() {
            change.proposed_state = AccessibilityStanding::Dormant;
            change.global_scope = true;
        }
        let result = propose_accessibility_or_influence_adjustment(&unknown)
            .expect("unknown-use dormancy is an outcome");
        assert_eq!(result.outcome, AdjustmentOutcome::Blocked);
    }

    // WORK_UNIT_CASE: 669/15
    #[test]
    fn case_15_observation_denominator_bounds_completeness() {
        let mut thin = valid_request();
        thin.policy.evidence_minimum = 9;
        let result = propose_accessibility_or_influence_adjustment(&thin)
            .expect("thin evidence is an outcome");
        assert_eq!(result.outcome, AdjustmentOutcome::Partial);
        let mut met = valid_request();
        met.policy.evidence_minimum = 3;
        let result =
            propose_accessibility_or_influence_adjustment(&met).expect("met minimum parses");
        assert_eq!(result.outcome, AdjustmentOutcome::Complete);
        let mut over_retrieved = valid_request();
        over_retrieved.usage.retrieval_successes = 41;
        assert!(propose_accessibility_or_influence_adjustment(&over_retrieved).is_err());
        let mut over_outcome = valid_request();
        over_outcome.usage.outcome_successes = 4;
        assert!(propose_accessibility_or_influence_adjustment(&over_outcome).is_err());
    }

    // WORK_UNIT_CASE: 669/16
    #[test]
    fn case_16_mixed_outcomes_permit_bounded_refinement_only() {
        let mut mixed = valid_request();
        mixed.usage.outcome_successes = 1;
        let result =
            propose_accessibility_or_influence_adjustment(&mixed).expect("mixed evidence parses");
        assert_eq!(result.outcome, AdjustmentOutcome::Complete);
        let mut raised = mixed.clone();
        raised.policy.evidence_minimum = 9;
        let result = propose_accessibility_or_influence_adjustment(&raised)
            .expect("raised minimum is an outcome");
        assert_eq!(result.outcome, AdjustmentOutcome::Partial);
        assert_ne!(result.outcome, AdjustmentOutcome::Complete);
    }

    // WORK_UNIT_CASE: 669/17
    #[test]
    fn case_17_reopen_keeps_live_triggers_visible_with_conditions() {
        let mut reopened = valid_request();
        reopened.protection.negative_memory[0].reopen_evidence_ref = Some("reopen-1".to_owned());
        let result = propose_accessibility_or_influence_adjustment(&reopened)
            .expect("reopened trigger parses");
        assert_eq!(result.outcome, AdjustmentOutcome::Complete);
        let mut dropped = reopened.clone();
        dropped.protection.retained_counterevidence_refs.clear();
        let result = propose_accessibility_or_influence_adjustment(&dropped)
            .expect("dropped trigger is an outcome");
        assert_eq!(result.outcome, AdjustmentOutcome::Blocked);
    }

    // WORK_UNIT_CASE: 669/18
    #[test]
    fn case_18_affected_surfaces_carry_an_exact_plan() {
        let mut request = valid_request();
        request.affected = vec![
            path_with("ctx-1", AffectedPathKind::Context),
            path_with("cue-1", AffectedPathKind::Cue),
            path_with("dep-1", AffectedPathKind::Derivative),
        ];
        request.dispositions = vec![
            disposition_with("ctx-1", DependentDispositionKind::Revalidate),
            disposition_with("cue-1", DependentDispositionKind::ReconcileByOwner),
            disposition_with("dep-1", DependentDispositionKind::Adjust),
        ];
        request.closure_denominator = TargetDenominator {
            mode: AtomicityMode::PerMember,
            members: vec!["ctx-1".to_owned(), "cue-1".to_owned(), "dep-1".to_owned()],
            expected_total: 3,
        };
        let result =
            propose_accessibility_or_influence_adjustment(&request).expect("surfaced plan parses");
        assert_eq!(result.outcome, AdjustmentOutcome::Complete);
        assert_eq!(result.dispositions.len(), 3);
        let mut unplanned = request.clone();
        if let Some(change) = unplanned.accessibility.as_mut() {
            change.projection_plan = String::new();
        }
        assert!(propose_accessibility_or_influence_adjustment(&unplanned).is_err());
    }

    // WORK_UNIT_CASE: 669/19
    #[test]
    fn case_19_exact_inverse_and_expiry_are_mandatory() {
        let mut no_access_expiry = valid_request();
        if let Some(change) = no_access_expiry.accessibility.as_mut() {
            change.expiry_ms = None;
        }
        let result = propose_accessibility_or_influence_adjustment(&no_access_expiry)
            .expect("missing accessibility expiry is an outcome");
        assert_eq!(result.outcome, AdjustmentOutcome::Blocked);
        let mut no_influence_expiry = valid_influence_request();
        no_influence_expiry.policy.expiry_ms = None;
        let result = propose_accessibility_or_influence_adjustment(&no_influence_expiry)
            .expect("missing influence expiry is an outcome");
        assert_eq!(result.outcome, AdjustmentOutcome::Blocked);
        let mut no_inverse = valid_request();
        if let Some(change) = no_inverse.accessibility.as_mut() {
            change.inverse_note = String::new();
        }
        assert!(propose_accessibility_or_influence_adjustment(&no_inverse).is_err());
        let mut no_policy_inverse = valid_request();
        no_policy_inverse.policy.inverse_note = String::new();
        assert!(propose_accessibility_or_influence_adjustment(&no_policy_inverse).is_err());
    }

    // WORK_UNIT_CASE: 669/20
    #[test]
    fn case_20_rejected_candidates_apply_nothing() {
        let mut request = valid_request();
        request.policy.target_subject = "other-subject".to_owned();
        let result = propose_accessibility_or_influence_adjustment(&request)
            .expect("off-target policy is an outcome");
        assert_eq!(result.outcome, AdjustmentOutcome::Rejected);
        assert_eq!(result.before_snapshot, result.proposed_snapshot);
        assert_eq!(result.before_owners, result.proposed_owners);
        assert!(result.observable.is_empty());
        assert!(result.verifier.is_empty());
        assert_eq!(result.expiry_ms, None);
        assert!(is_hex64_lower(&result.proposal_digest));
        assert_eq!(
            outcome_rejection_hint(&result.outcome),
            Some(CurationRejectionCode::IdentityMismatch)
        );
    }

    // WORK_UNIT_CASE: 669/21
    #[test]
    fn case_21_bounded_influence_increase_respects_source_ceilings() {
        let request = influence_increase_request();
        let result = propose_accessibility_or_influence_adjustment(&request)
            .expect("ceiled increase parses");
        assert_eq!(result.outcome, AdjustmentOutcome::Complete);
        assert_eq!(result.proposed_snapshot.influence, InfluenceStanding::Full);
        let mut over = request.clone();
        if let Some(change) = over.influence.as_mut() {
            change.within_ceilings = false;
        }
        let result = propose_accessibility_or_influence_adjustment(&over)
            .expect("over-ceiling increase is an outcome");
        assert_eq!(result.outcome, AdjustmentOutcome::Blocked);
    }

    // WORK_UNIT_CASE: 669/22
    #[test]
    fn case_22_quarantined_decrease_is_a_review_candidate_only() {
        let mut request = valid_influence_request();
        if let Some(change) = request.influence.as_mut() {
            change.proposed_standing = InfluenceStanding::Minimal;
        }
        if let Some(closure) = request.influence_closure.as_mut() {
            closure.current_standing = LocalClosureStanding::Quarantined;
            closure.invalidation_reason = Some(LocalRevocationClass::WrongScope);
        }
        let frozen = request.clone();
        let result = propose_accessibility_or_influence_adjustment(&request)
            .expect("quarantined decrease parses");
        assert_eq!(result.outcome, AdjustmentOutcome::Complete);
        assert_eq!(result.axis, Axis::Influence);
        assert_eq!(
            result.proposed_snapshot.influence,
            InfluenceStanding::Minimal
        );
        assert_eq!(request, frozen, "quarantine review never mutates inputs");
    }

    // WORK_UNIT_CASE: 669/24
    #[test]
    fn case_24_unknown_stale_or_mismatched_closure_never_completes() {
        let mut unknown = valid_influence_request();
        if let Some(closure) = unknown.influence_closure.as_mut() {
            closure.current_standing = LocalClosureStanding::Unknown;
        }
        let result = propose_accessibility_or_influence_adjustment(&unknown)
            .expect("unknown standing is an outcome");
        assert_eq!(result.outcome, AdjustmentOutcome::Blocked);
        let mut revised = valid_influence_request();
        if let Some(closure) = revised.influence_closure.as_mut() {
            closure.closure_revision = "rev-9".to_owned();
        }
        let result = propose_accessibility_or_influence_adjustment(&revised)
            .expect("moved closure revision is an outcome");
        assert_eq!(result.outcome, AdjustmentOutcome::Stale);
        let mut rerooted = valid_influence_request();
        if let Some(closure) = rerooted.influence_closure.as_mut() {
            closure.root_ref = "other-subject".to_owned();
        }
        let result = propose_accessibility_or_influence_adjustment(&rerooted)
            .expect("rerooted closure is an outcome");
        assert_eq!(result.outcome, AdjustmentOutcome::Rejected);
        let mut rescoped = valid_influence_request();
        if let Some(closure) = rescoped.influence_closure.as_mut() {
            closure.scope_id = "scope-9".to_owned();
        }
        let result = propose_accessibility_or_influence_adjustment(&rescoped)
            .expect("rescoped closure is an outcome");
        assert_eq!(result.outcome, AdjustmentOutcome::Rejected);
        let mut repointed = valid_influence_request();
        if let Some(closure) = repointed.influence_closure.as_mut() {
            closure.policy_id = "policy-9".to_owned();
        }
        let result = propose_accessibility_or_influence_adjustment(&repointed)
            .expect("repointed closure is an outcome");
        assert_eq!(result.outcome, AdjustmentOutcome::Rejected);
        let mut refenced = valid_influence_request();
        if let Some(closure) = refenced.influence_closure.as_mut() {
            closure.state_fence = test_fence_seq(2);
        }
        let result = propose_accessibility_or_influence_adjustment(&refenced)
            .expect("refenced closure is an outcome");
        assert_eq!(result.outcome, AdjustmentOutcome::Stale);
    }

    // WORK_UNIT_CASE: 669/25
    #[test]
    fn case_25_every_member_is_accounted_or_the_move_blocks() {
        let mut uncovered = valid_influence_request();
        if let Some(closure) = uncovered.influence_closure.as_mut() {
            closure.dependent_refs = vec!["dec-1".to_owned()];
        }
        let result = propose_accessibility_or_influence_adjustment(&uncovered)
            .expect("uncovered member is an outcome");
        assert_eq!(result.outcome, AdjustmentOutcome::Blocked);
        let mut short_denom = valid_influence_request();
        short_denom.closure_denominator = TargetDenominator {
            mode: AtomicityMode::PerMember,
            members: vec!["dep-1".to_owned()],
            expected_total: 1,
        };
        let result = propose_accessibility_or_influence_adjustment(&short_denom)
            .expect("short denominator is an outcome");
        assert_eq!(result.outcome, AdjustmentOutcome::Blocked);
        let mut short_disp = valid_influence_request();
        short_disp
            .dispositions
            .retain(|outcome| outcome.handle == "dep-1");
        let result = propose_accessibility_or_influence_adjustment(&short_disp)
            .expect("short dispositions are an outcome");
        assert_eq!(result.outcome, AdjustmentOutcome::Blocked);
        let mut extra_denom = valid_influence_request();
        extra_denom.closure_denominator = TargetDenominator {
            mode: AtomicityMode::PerMember,
            members: vec!["dec-1".to_owned(), "dep-1".to_owned(), "extra-1".to_owned()],
            expected_total: 3,
        };
        let result = propose_accessibility_or_influence_adjustment(&extra_denom)
            .expect("unknown member is an outcome");
        assert_eq!(result.outcome, AdjustmentOutcome::Blocked);
    }

    // WORK_UNIT_CASE: 669/26
    #[test]
    fn case_26_review_and_decision_owners_are_required() {
        let mut no_review = valid_influence_request();
        if let Some(change) = no_review.influence.as_mut() {
            change.review_owner_ref = String::new();
        }
        assert!(propose_accessibility_or_influence_adjustment(&no_review).is_err());
        let mut no_decision = valid_influence_request();
        if let Some(change) = no_decision.influence.as_mut() {
            change.decision_owner_ref = String::new();
        }
        assert!(propose_accessibility_or_influence_adjustment(&no_decision).is_err());
        let control = valid_influence_request();
        let result =
            propose_accessibility_or_influence_adjustment(&control).expect("owned review parses");
        assert_eq!(result.outcome, AdjustmentOutcome::Complete);
    }

    // WORK_UNIT_CASE: 669/27
    #[test]
    fn case_27_retrieval_and_model_agreement_never_raise_influence() {
        let mut retrieved = influence_increase_request();
        retrieved.usage.retrieval_attempts = 100;
        retrieved.usage.retrieval_successes = 100;
        retrieved.usage.outcome_observations = 1;
        retrieved.usage.outcome_successes = 1;
        let result = propose_accessibility_or_influence_adjustment(&retrieved)
            .expect("retrieval-heavy increase is an outcome");
        assert_eq!(result.outcome, AdjustmentOutcome::Partial);
        let mut agreed = influence_increase_request();
        agreed.usage.writer_utility_note = "approved by model agreement for wider use".to_owned();
        let result = propose_accessibility_or_influence_adjustment(&agreed)
            .expect("model agreement is an outcome");
        assert_eq!(result.outcome, AdjustmentOutcome::Blocked);
    }

    // WORK_UNIT_CASE: 669/28
    #[test]
    fn case_28_influence_decrease_never_deletes_or_shifts_other_axes() {
        let mut deleting = valid_influence_request();
        if let Some(change) = deleting.influence.as_mut() {
            change.deletes_subject = true;
        }
        let result = propose_accessibility_or_influence_adjustment(&deleting)
            .expect("deleting decrease is an outcome");
        assert_eq!(result.outcome, AdjustmentOutcome::Rejected);
        let request = valid_influence_request();
        let result =
            propose_accessibility_or_influence_adjustment(&request).expect("plain decrease parses");
        assert_eq!(result.outcome, AdjustmentOutcome::Complete);
        assert_eq!(
            result.before_snapshot.accessibility,
            result.proposed_snapshot.accessibility
        );
        assert_eq!(result.before_owners, result.proposed_owners);
    }

    // WORK_UNIT_CASE: 669/29
    #[test]
    fn case_29_single_success_never_creates_system_wide_influence() {
        let mut wide = valid_influence_request();
        if let Some(change) = wide.influence.as_mut() {
            change.claims_system_wide = true;
        }
        let result = propose_accessibility_or_influence_adjustment(&wide)
            .expect("system-wide claim is an outcome");
        assert_eq!(result.outcome, AdjustmentOutcome::Blocked);
        let request = valid_influence_request();
        let result = propose_accessibility_or_influence_adjustment(&request)
            .expect("scoped decrease parses");
        assert_eq!(result.outcome, AdjustmentOutcome::Complete);
        assert_eq!(
            result.proposed_snapshot.influence,
            InfluenceStanding::Bounded
        );
    }

    // WORK_UNIT_CASE: 669/30
    #[test]
    fn case_30_revoked_closure_needs_a_reason_and_stays_a_candidate() {
        let mut request = valid_influence_request();
        if let Some(closure) = request.influence_closure.as_mut() {
            closure.current_standing = LocalClosureStanding::Revoked;
            closure.invalidation_reason = Some(LocalRevocationClass::SourceRevoked);
        }
        let frozen = request.clone();
        let result = propose_accessibility_or_influence_adjustment(&request)
            .expect("reasoned revocation parses");
        assert_eq!(result.outcome, AdjustmentOutcome::Complete);
        assert_eq!(request, frozen, "revocation review never mutates inputs");
        let mut reasonless = valid_influence_request();
        if let Some(closure) = reasonless.influence_closure.as_mut() {
            closure.current_standing = LocalClosureStanding::Revoked;
        }
        assert!(propose_accessibility_or_influence_adjustment(&reasonless).is_err());
    }

    // WORK_UNIT_CASE: 669/31
    #[test]
    fn case_31_quarantine_preserves_history_branch_and_renewal() {
        let mut request = valid_influence_request();
        if let Some(closure) = request.influence_closure.as_mut() {
            closure.current_standing = LocalClosureStanding::Quarantined;
            closure.invalidation_reason = Some(LocalRevocationClass::Poisoned);
        }
        let result = propose_accessibility_or_influence_adjustment(&request)
            .expect("quarantined move parses");
        assert_eq!(result.outcome, AdjustmentOutcome::Complete);
        assert_eq!(
            result.renewal_condition,
            "reopen when scope-1 frontier advances"
        );
        assert_eq!(result.expiry_ms, Some(1_800_000_000_000));
        assert_eq!(
            request
                .influence_closure
                .as_ref()
                .expect("closure present")
                .invalidation_reason,
            Some(LocalRevocationClass::Poisoned)
        );
        let mut no_renewal = valid_request();
        no_renewal.policy.renewal_condition = String::new();
        assert!(propose_accessibility_or_influence_adjustment(&no_renewal).is_err());
    }

    // WORK_UNIT_CASE: 669/32
    #[test]
    fn case_32_no_traversal_or_applied_revocation_receipt_exists() {
        let mut request = valid_influence_request();
        if let Some(closure) = request.influence_closure.as_mut() {
            closure.current_standing = LocalClosureStanding::Revoked;
            closure.invalidation_reason = Some(LocalRevocationClass::SourceRevoked);
        }
        let frozen = request.clone();
        let first = propose_accessibility_or_influence_adjustment(&request)
            .expect("revocation review parses");
        let second =
            propose_accessibility_or_influence_adjustment(&request).expect("replay parses");
        assert_eq!(request, frozen, "no traversal mutates the closure");
        assert_eq!(first.proposal_digest, second.proposal_digest);
        assert_eq!(first.outcome, AdjustmentOutcome::Complete);
    }

    // WORK_UNIT_CASE: 669/33
    #[test]
    fn case_33_every_protection_class_blocks_or_narrows_unsafe_moves() {
        let mut missing = valid_request();
        missing.protection.protections[0].satisfied = false;
        let result = propose_accessibility_or_influence_adjustment(&missing)
            .expect("missing mandatory is an outcome");
        assert_eq!(result.outcome, AdjustmentOutcome::Blocked);
        let mut narrowed = valid_request();
        narrowed.protection.protections[0].mandatory = false;
        narrowed.protection.protections[0].satisfied = false;
        let result =
            propose_accessibility_or_influence_adjustment(&narrowed).expect("optional gap parses");
        assert_eq!(result.outcome, AdjustmentOutcome::Complete);
        let mut unretained = valid_request();
        unretained.protection.protections.push(ProtectionReason {
            reason_id: "extra-evidence".to_owned(),
            trigger: "rival report r-2".to_owned(),
            mandatory: false,
            satisfied: true,
            unknown: false,
            counterevidence_ref: Some("r-2".to_owned()),
        });
        unretained
            .protection
            .protections
            .sort_by(|left, right| left.reason_id.cmp(&right.reason_id));
        let result = propose_accessibility_or_influence_adjustment(&unretained)
            .expect("unretained counterevidence is an outcome");
        assert_eq!(result.outcome, AdjustmentOutcome::Blocked);
    }

    // WORK_UNIT_CASE: 669/35
    #[test]
    fn case_35_exact_triggers_persist_until_extinction_or_reopen() {
        let mut extinct = valid_request();
        extinct.protection.negative_memory[0].extinguished = true;
        extinct.protection.negative_memory[0].extinction_evidence_ref = Some("ext-1".to_owned());
        let result = propose_accessibility_or_influence_adjustment(&extinct)
            .expect("extinguished trigger parses");
        assert_eq!(result.outcome, AdjustmentOutcome::Complete);
        let mut unevidenced = valid_request();
        unevidenced.protection.negative_memory[0].extinguished = true;
        let result = propose_accessibility_or_influence_adjustment(&unevidenced)
            .expect("unevidenced extinction is an outcome");
        assert_eq!(result.outcome, AdjustmentOutcome::Blocked);
        let live = valid_request();
        let result = propose_accessibility_or_influence_adjustment(&live)
            .expect("retained live trigger parses");
        assert_eq!(result.outcome, AdjustmentOutcome::Complete);
    }

    // WORK_UNIT_CASE: 669/36
    #[test]
    fn case_36_prefix_similarity_and_case_never_suppress_exact_triggers() {
        let mut prefixed = valid_request();
        prefixed.protection.retained_counterevidence_refs = vec!["m-1-prefix".to_owned()];
        let result = propose_accessibility_or_influence_adjustment(&prefixed)
            .expect("prefix-only retention is an outcome");
        assert_eq!(result.outcome, AdjustmentOutcome::Blocked);
        let mut cased = valid_request();
        cased.protection.retained_counterevidence_refs = vec!["M-1".to_owned()];
        let result = propose_accessibility_or_influence_adjustment(&cased)
            .expect("case drift is an outcome");
        assert_eq!(result.outcome, AdjustmentOutcome::Blocked);
        let mut exact = valid_request();
        exact.protection.retained_counterevidence_refs =
            vec!["m-1".to_owned(), "m-1-prefix".to_owned()];
        let result =
            propose_accessibility_or_influence_adjustment(&exact).expect("exact retention parses");
        assert_eq!(result.outcome, AdjustmentOutcome::Complete);
    }

    // WORK_UNIT_CASE: 669/37
    #[test]
    fn case_37_extinction_review_never_deletes_history() {
        let mut request = valid_request();
        request.protection.negative_memory[0].extinguished = true;
        request.protection.negative_memory[0].extinction_evidence_ref = Some("ext-1".to_owned());
        let result = propose_accessibility_or_influence_adjustment(&request)
            .expect("extinction review parses");
        assert_eq!(result.outcome, AdjustmentOutcome::Complete);
        assert_eq!(request.protection.negative_memory.len(), 1);
        assert_eq!(request.protection.negative_memory[0].trigger, "m-1");
        let mut reopened = valid_request();
        reopened.protection.negative_memory[0].reopen_evidence_ref = Some("reopen-9".to_owned());
        let result =
            propose_accessibility_or_influence_adjustment(&reopened).expect("reopen review parses");
        assert_eq!(result.outcome, AdjustmentOutcome::Complete);
    }

    // WORK_UNIT_CASE: 669/38
    #[test]
    fn case_38_activation_use_and_benefit_are_distinct_evidence() {
        let mut benefitless = valid_request();
        benefitless.usage.outcome_successes = 0;
        let result = propose_accessibility_or_influence_adjustment(&benefitless)
            .expect("benefitless use parses");
        assert_eq!(result.outcome, AdjustmentOutcome::Complete);
        let mut thin = valid_request();
        thin.usage.outcome_observations = 1;
        thin.usage.outcome_successes = 1;
        let result = propose_accessibility_or_influence_adjustment(&thin)
            .expect("thin outcomes are an outcome");
        assert_eq!(result.outcome, AdjustmentOutcome::Partial);
    }

    // WORK_UNIT_CASE: 669/39
    #[test]
    fn case_39_self_report_and_guarantee_language_never_authorize() {
        let mut guaranteed = valid_request();
        guaranteed.usage.writer_utility_note =
            "writer reports guaranteed benefit across scopes".to_owned();
        let result = propose_accessibility_or_influence_adjustment(&guaranteed)
            .expect("guarantee language is an outcome");
        assert_eq!(result.outcome, AdjustmentOutcome::Blocked);
        let mut mandated = valid_request();
        mandated.usage.writer_utility_note = "downstream results mandates use elsewhere".to_owned();
        let result = propose_accessibility_or_influence_adjustment(&mandated)
            .expect("mandate language is an outcome");
        assert_eq!(result.outcome, AdjustmentOutcome::Blocked);
        let request = valid_request();
        let result = propose_accessibility_or_influence_adjustment(&request)
            .expect("neutral utility parses");
        assert_eq!(result.outcome, AdjustmentOutcome::Complete);
    }

    // WORK_UNIT_CASE: 669/40
    #[test]
    fn case_40_named_counterevidence_must_stay_retained() {
        let mut dropped = valid_request();
        dropped.protection.protections[0].counterevidence_ref = Some("m-2".to_owned());
        let result = propose_accessibility_or_influence_adjustment(&dropped)
            .expect("dropped counterevidence is an outcome");
        assert_eq!(result.outcome, AdjustmentOutcome::Blocked);
        let mut restored = dropped.clone();
        restored.protection.retained_counterevidence_refs =
            vec!["m-1".to_owned(), "m-2".to_owned()];
        let result = propose_accessibility_or_influence_adjustment(&restored)
            .expect("restored counterevidence parses");
        assert_eq!(result.outcome, AdjustmentOutcome::Complete);
    }

    // WORK_UNIT_CASE: 669/42
    #[test]
    fn case_42_dimensions_stay_independent_with_no_averaging() {
        let mut failed = valid_request();
        failed.preservation.verdicts[0].passed = false;
        let result = propose_accessibility_or_influence_adjustment(&failed)
            .expect("failed dimension is an outcome");
        assert_eq!(result.outcome, AdjustmentOutcome::Blocked);
        let mut unknown = valid_request();
        unknown.preservation.verdicts[3].known = false;
        let result = propose_accessibility_or_influence_adjustment(&unknown)
            .expect("unknown dimension is an outcome");
        assert_eq!(result.outcome, AdjustmentOutcome::Blocked);
        let request = valid_request();
        let result = propose_accessibility_or_influence_adjustment(&request)
            .expect("passing dimensions parse");
        assert_eq!(result.outcome, AdjustmentOutcome::Complete);
    }

    // WORK_UNIT_CASE: 669/43
    #[test]
    fn case_43_restore_needs_exact_prior_revision_bindings() {
        let mut restore = valid_request();
        restore.policy.operation = AdjustmentOperation::Restore;
        restore.policy.direction = AdjustmentDirection::Lateral;
        if let Some(change) = restore.accessibility.as_mut() {
            change.proposed_state = AccessibilityStanding::Restricted;
        }
        let result =
            propose_accessibility_or_influence_adjustment(&restore).expect("bound restore parses");
        assert_eq!(result.outcome, AdjustmentOutcome::Complete);
        assert_eq!(
            result.proposed_snapshot.accessibility,
            AccessibilityStanding::Restricted
        );
        let mut same = valid_request();
        same.policy.operation = AdjustmentOperation::Restore;
        same.policy.direction = AdjustmentDirection::Lateral;
        if let Some(change) = same.accessibility.as_mut() {
            change.proposed_state = AccessibilityStanding::Exposed;
        }
        let result = propose_accessibility_or_influence_adjustment(&same)
            .expect("same-state restore is an outcome");
        assert_eq!(result.outcome, AdjustmentOutcome::Rejected);
        let mut rebound = restore.clone();
        if let Some(change) = rebound.accessibility.as_mut() {
            change.before_owner = "other-owner".to_owned();
        }
        let result = propose_accessibility_or_influence_adjustment(&rebound)
            .expect("rebound restore is an outcome");
        assert_eq!(result.outcome, AdjustmentOutcome::Stale);
    }

    // WORK_UNIT_CASE: 669/44
    #[test]
    fn case_44_missing_inverse_blocks_and_lateral_refinement_passes() {
        let mut no_inverse = valid_request();
        if let Some(change) = no_inverse.accessibility.as_mut() {
            change.inverse_note = String::new();
        }
        assert!(propose_accessibility_or_influence_adjustment(&no_inverse).is_err());
        let mut no_policy_inverse = valid_request();
        no_policy_inverse.policy.inverse_note = String::new();
        assert!(propose_accessibility_or_influence_adjustment(&no_policy_inverse).is_err());
        let mut lateral = valid_request();
        lateral.policy.operation = AdjustmentOperation::Narrow;
        lateral.policy.direction = AdjustmentDirection::Lateral;
        if let Some(change) = lateral.accessibility.as_mut() {
            change.proposed_state = AccessibilityStanding::Exposed;
        }
        let result = propose_accessibility_or_influence_adjustment(&lateral)
            .expect("lateral refinement parses");
        assert_eq!(result.outcome, AdjustmentOutcome::Complete);
        assert_eq!(result.before_snapshot, result.proposed_snapshot);
    }

    // WORK_UNIT_CASE: 669/45
    #[test]
    fn case_45_expiry_and_renewal_are_carried_exactly_never_filled() {
        let request = valid_request();
        let result =
            propose_accessibility_or_influence_adjustment(&request).expect("valid expiry parses");
        assert_eq!(result.expiry_ms, Some(1_800_000_000_000));
        assert_eq!(
            result.renewal_condition,
            "reopen when scope-1 frontier advances"
        );
        assert_eq!(result.window_note, "window w-10");
        let mut custom = valid_request();
        if let Some(change) = custom.accessibility.as_mut() {
            change.expiry_ms = Some(42);
        }
        let result =
            propose_accessibility_or_influence_adjustment(&custom).expect("custom expiry parses");
        assert_eq!(result.expiry_ms, Some(42));
        let mut missing = valid_request();
        if let Some(change) = missing.accessibility.as_mut() {
            change.expiry_ms = None;
        }
        let result = propose_accessibility_or_influence_adjustment(&missing)
            .expect("missing expiry is an outcome");
        assert_eq!(result.outcome, AdjustmentOutcome::Blocked);
    }

    // WORK_UNIT_CASE: 669/46
    #[test]
    fn case_46_all_seven_dimensions_must_pass() {
        let request = valid_request();
        assert_eq!(request.preservation.verdicts.len(), 7);
        let result = propose_accessibility_or_influence_adjustment(&request)
            .expect("seven passing dimensions parse");
        assert_eq!(result.outcome, AdjustmentOutcome::Complete);
        let mut short = valid_request();
        short.preservation.verdicts.pop();
        assert!(propose_accessibility_or_influence_adjustment(&short).is_err());
    }

    // WORK_UNIT_CASE: 669/47
    #[test]
    fn case_47_each_failed_or_unknown_dimension_blocks_without_revalidation() {
        for index in 0..7 {
            let mut failed = valid_request();
            failed.preservation.verdicts[index].passed = false;
            let frozen = failed.clone();
            let result = propose_accessibility_or_influence_adjustment(&failed)
                .expect("failed dimension is an outcome");
            assert_eq!(result.outcome, AdjustmentOutcome::Blocked);
            assert_eq!(failed, frozen, "dimension review never revalidates inputs");
            let mut unknown = valid_request();
            unknown.preservation.verdicts[index].known = false;
            let result = propose_accessibility_or_influence_adjustment(&unknown)
                .expect("unknown dimension is an outcome");
            assert_eq!(result.outcome, AdjustmentOutcome::Blocked);
        }
    }

    // WORK_UNIT_CASE: 669/48
    #[test]
    fn case_48_no_outcome_applies_owner_write_effect_or_finish_state() {
        let mut rejected = valid_request();
        rejected.policy.target_subject = "other-subject".to_owned();
        let result = propose_accessibility_or_influence_adjustment(&rejected)
            .expect("rejected move is an outcome");
        assert_eq!(result.outcome, AdjustmentOutcome::Rejected);
        assert_eq!(result.before_owners, result.proposed_owners);
        assert_eq!(result.before_owners, test_owners());
        let mut blocked = valid_influence_request();
        blocked.protection.protections[0].satisfied = false;
        let result = propose_accessibility_or_influence_adjustment(&blocked)
            .expect("blocked move is an outcome");
        assert_eq!(result.outcome, AdjustmentOutcome::Blocked);
        assert_eq!(result.before_owners, result.proposed_owners);
        assert_eq!(result.proposed_owners, test_owners());
    }

    // WORK_UNIT_CASE: 669/49
    #[test]
    fn case_49_terminal_outcomes_stay_distinct_with_exact_hints() {
        let complete = propose_accessibility_or_influence_adjustment(&valid_request())
            .expect("baseline parses");
        assert_eq!(complete.outcome, AdjustmentOutcome::Complete);
        assert_eq!(outcome_rejection_hint(&complete.outcome), None);
        let mut thin = valid_request();
        thin.policy.evidence_minimum = 9;
        let partial = propose_accessibility_or_influence_adjustment(&thin)
            .expect("thin evidence is an outcome");
        assert_eq!(partial.outcome, AdjustmentOutcome::Partial);
        assert_eq!(
            outcome_rejection_hint(&partial.outcome),
            Some(CurationRejectionCode::PreservationFailed)
        );
        let mut unauthorized = valid_request();
        unauthorized.receipt.validator_policy = "policy-9".to_owned();
        let abstention = propose_accessibility_or_influence_adjustment(&unauthorized)
            .expect("expired authorization is an outcome");
        assert_eq!(abstention.outcome, AdjustmentOutcome::Abstention);
        assert_eq!(
            outcome_rejection_hint(&abstention.outcome),
            Some(CurationRejectionCode::LineageMismatch)
        );
        let mut moved = valid_request();
        if let Some(change) = moved.accessibility.as_mut() {
            change.before_revision = "rev-9".to_owned();
        }
        let stale = propose_accessibility_or_influence_adjustment(&moved)
            .expect("moved revision is an outcome");
        assert_eq!(stale.outcome, AdjustmentOutcome::Stale);
        assert_eq!(
            outcome_rejection_hint(&stale.outcome),
            Some(CurationRejectionCode::IdentityMismatch)
        );
        let mut off_target = valid_request();
        off_target.policy.target_subject = "other-subject".to_owned();
        let rejected = propose_accessibility_or_influence_adjustment(&off_target)
            .expect("off-target policy is an outcome");
        assert_eq!(rejected.outcome, AdjustmentOutcome::Rejected);
        assert_eq!(
            outcome_rejection_hint(&rejected.outcome),
            Some(CurationRejectionCode::IdentityMismatch)
        );
        let mut unguarded = valid_request();
        unguarded.protection.protections[0].satisfied = false;
        let blocked = propose_accessibility_or_influence_adjustment(&unguarded)
            .expect("unguarded move is an outcome");
        assert_eq!(blocked.outcome, AdjustmentOutcome::Blocked);
        assert_eq!(
            outcome_rejection_hint(&blocked.outcome),
            Some(CurationRejectionCode::PreservationFailed)
        );
        let outcomes = [
            complete.outcome,
            partial.outcome,
            abstention.outcome,
            stale.outcome,
            rejected.outcome,
            blocked.outcome,
        ];
        let mut seen = std::collections::HashSet::new();
        for outcome in outcomes {
            assert!(seen.insert(outcome), "terminal outcomes stay distinct");
        }
    }

    // WORK_UNIT_CASE: 669/50
    #[test]
    fn case_50_set_order_is_deterministic_and_unsorted_input_fails() {
        let request = two_path_request();
        let first =
            propose_accessibility_or_influence_adjustment(&request).expect("two-path parses");
        assert_eq!(first.outcome, AdjustmentOutcome::Complete);
        let second =
            propose_accessibility_or_influence_adjustment(&request).expect("replay parses");
        assert_eq!(first.proposal_digest, second.proposal_digest);
        assert_eq!(first.dispositions, request.dispositions);
        let mut shuffled_paths = request.clone();
        shuffled_paths.affected.reverse();
        assert!(propose_accessibility_or_influence_adjustment(&shuffled_paths).is_err());
        let mut shuffled_disp = request.clone();
        shuffled_disp.dispositions.reverse();
        assert!(propose_accessibility_or_influence_adjustment(&shuffled_disp).is_err());
        let mut shuffled_refs = valid_request();
        shuffled_refs.protection.retained_counterevidence_refs =
            vec!["m-2".to_owned(), "m-1".to_owned()];
        assert!(propose_accessibility_or_influence_adjustment(&shuffled_refs).is_err());
        let mut shuffled_closure = valid_influence_request();
        if let Some(closure) = shuffled_closure.influence_closure.as_mut() {
            closure.dependent_refs.reverse();
        }
        assert!(propose_accessibility_or_influence_adjustment(&shuffled_closure).is_err());
    }

    // WORK_UNIT_CASE: 669/51
    #[test]
    fn case_51_every_independent_bound_fails_closed_one_over() {
        let mut many_affected = valid_request();
        let affected_handles = many_sorted("aff", MAX_AFFECTED + 1);
        many_affected.affected = affected_handles
            .iter()
            .map(|handle| path_with(handle, AffectedPathKind::Derivative))
            .collect();
        assert!(propose_accessibility_or_influence_adjustment(&many_affected).is_err());
        let mut many_disp = valid_request();
        let disp_handles = many_sorted("disp", MAX_AFFECTED + 1);
        many_disp.dispositions = disp_handles
            .iter()
            .map(|handle| disposition_with(handle, DependentDispositionKind::Revalidate))
            .collect();
        assert!(propose_accessibility_or_influence_adjustment(&many_disp).is_err());
        let mut many_prot = valid_request();
        many_prot.protection.protections = (0..=MAX_PROTECTIONS)
            .map(|index| ProtectionReason {
                reason_id: format!("prot-{index:04}"),
                trigger: "trigger".to_owned(),
                mandatory: false,
                satisfied: true,
                unknown: false,
                counterevidence_ref: None,
            })
            .collect();
        assert!(propose_accessibility_or_influence_adjustment(&many_prot).is_err());
        let mut many_neg = valid_request();
        many_neg.protection.negative_memory = (0..=MAX_NEGATIVE_ENTRIES)
            .map(|index| NegativeMemoryEntry {
                trigger: format!("trig-{index:04}"),
                extinguished: true,
                extinction_evidence_ref: Some("ext-1".to_owned()),
                reopen_evidence_ref: None,
            })
            .collect();
        assert!(propose_accessibility_or_influence_adjustment(&many_neg).is_err());
        let mut many_refs = valid_influence_request();
        if let Some(closure) = many_refs.influence_closure.as_mut() {
            closure.dependent_refs = many_sorted("dep", MAX_CLOSURE_REFS + 1);
        }
        assert!(propose_accessibility_or_influence_adjustment(&many_refs).is_err());
        let mut many_retained = valid_request();
        many_retained.protection.retained_counterevidence_refs =
            many_sorted("m", MAX_CLOSURE_REFS + 1);
        assert!(propose_accessibility_or_influence_adjustment(&many_retained).is_err());
        let mut many_gaps = valid_influence_request();
        if let Some(closure) = many_gaps.influence_closure.as_mut() {
            closure.unknown_gaps = many_sorted("gap", MAX_CLOSURE_REFS + 1);
        }
        assert!(propose_accessibility_or_influence_adjustment(&many_gaps).is_err());
        let mut over_retrieved = valid_request();
        over_retrieved.usage.retrieval_successes = 41;
        assert!(propose_accessibility_or_influence_adjustment(&over_retrieved).is_err());
        let mut over_outcome = valid_request();
        over_outcome.usage.outcome_successes = 4;
        assert!(propose_accessibility_or_influence_adjustment(&over_outcome).is_err());
        let mut empty = valid_request();
        empty.affected.clear();
        assert!(propose_accessibility_or_influence_adjustment(&empty).is_err());
        let mut long = valid_request();
        long.projection.subject_handle = "h".repeat(MAX_HANDLE_BYTES + 1);
        assert!(propose_accessibility_or_influence_adjustment(&long).is_err());
        let mut controlled = valid_request();
        controlled.projection.task_id = "task-\n1".to_owned();
        assert!(propose_accessibility_or_influence_adjustment(&controlled).is_err());
        let mut bad_digest = valid_request();
        bad_digest.frozen_bundle_digest = "not-hex".to_owned();
        assert!(propose_accessibility_or_influence_adjustment(&bad_digest).is_err());
        let mut capped = two_path_request();
        capped.policy.max_affected = 1;
        assert!(propose_accessibility_or_influence_adjustment(&capped).is_err());
    }

    // WORK_UNIT_CASE: 669/52
    #[test]
    fn case_52_cancelled_deadline_and_moved_policy_stay_stale_or_rejected() {
        let mut cancelled = valid_request();
        cancelled.receipt.terminal_disposition = "rejected".to_owned();
        let result = propose_accessibility_or_influence_adjustment(&cancelled)
            .expect("cancelled receipt is an outcome");
        assert_eq!(result.outcome, AdjustmentOutcome::Rejected);
        let mut unauthorized = valid_request();
        unauthorized.receipt.validator_policy = "policy-9".to_owned();
        let result = propose_accessibility_or_influence_adjustment(&unauthorized)
            .expect("expired authorization is an outcome");
        assert_eq!(result.outcome, AdjustmentOutcome::Abstention);
        let mut moved = valid_request();
        moved.receipt.validator_policy = "policy-9".to_owned();
        moved.policy.policy_id = "policy-9".to_owned();
        let result = propose_accessibility_or_influence_adjustment(&moved)
            .expect("moved policy is an outcome");
        assert_eq!(result.outcome, AdjustmentOutcome::Stale);
    }

    // WORK_UNIT_CASE: 669/53
    #[test]
    fn case_53_long_values_redact_and_control_chars_reject() {
        let mut long = valid_request();
        if let Some(change) = long.accessibility.as_mut() {
            change.observable = "o".repeat(200);
        }
        let result =
            propose_accessibility_or_influence_adjustment(&long).expect("long observable parses");
        assert_eq!(result.outcome, AdjustmentOutcome::Complete);
        assert_eq!(result.observable, format!("{}...", "o".repeat(128)));
        assert!(result.observable.len() <= MAX_REDACTED_CHARS + 3);
        let mut controlled = valid_request();
        if let Some(change) = controlled.accessibility.as_mut() {
            change.observable = "line one\nline two".to_owned();
        }
        assert!(propose_accessibility_or_influence_adjustment(&controlled).is_err());
    }

    // WORK_UNIT_CASE: 669/54
    #[test]
    fn case_54_valid_candidates_move_exactly_one_axis() {
        let influence = valid_influence_request();
        let result =
            propose_accessibility_or_influence_adjustment(&influence).expect("influence parses");
        assert_eq!(result.outcome, AdjustmentOutcome::Complete);
        assert_ne!(
            result.before_snapshot.influence,
            result.proposed_snapshot.influence
        );
        assert_eq!(
            result.before_snapshot.accessibility,
            result.proposed_snapshot.accessibility
        );
        let mut restore = valid_request();
        restore.policy.operation = AdjustmentOperation::Restore;
        restore.policy.direction = AdjustmentDirection::Lateral;
        if let Some(change) = restore.accessibility.as_mut() {
            change.proposed_state = AccessibilityStanding::Restricted;
        }
        let result =
            propose_accessibility_or_influence_adjustment(&restore).expect("restore move parses");
        assert_eq!(result.outcome, AdjustmentOutcome::Complete);
        assert_ne!(
            result.before_snapshot.accessibility,
            result.proposed_snapshot.accessibility
        );
        assert_eq!(
            result.before_snapshot.influence,
            result.proposed_snapshot.influence
        );
        assert_eq!(result.before_owners, result.proposed_owners);
    }

    // WORK_UNIT_CASE: 669/55
    #[test]
    fn case_55_unselected_axes_keep_exact_owner_refs_on_every_outcome() {
        let mut blocked = valid_request();
        blocked.protection.protections[0].satisfied = false;
        let result = propose_accessibility_or_influence_adjustment(&blocked)
            .expect("blocked move is an outcome");
        assert_eq!(result.outcome, AdjustmentOutcome::Blocked);
        assert_eq!(result.proposed_owners, test_owners());
        let mut partial = valid_request();
        partial.policy.task_local_only = true;
        partial.protection.protections[0].unknown = true;
        partial.protection.protections[0].satisfied = false;
        let result = propose_accessibility_or_influence_adjustment(&partial)
            .expect("partial move is an outcome");
        assert_eq!(result.outcome, AdjustmentOutcome::Partial);
        assert_eq!(result.proposed_owners, test_owners());
        let mut rejected = valid_influence_request();
        if let Some(change) = rejected.influence.as_mut() {
            change.scope = "scope-9".to_owned();
        }
        let result = propose_accessibility_or_influence_adjustment(&rejected)
            .expect("rejected move is an outcome");
        assert_eq!(result.outcome, AdjustmentOutcome::Rejected);
        assert_eq!(result.proposed_owners, test_owners());
    }

    // WORK_UNIT_CASE: 669/56
    #[test]
    fn case_56_complete_influence_binds_full_matching_closure_and_members() {
        let request = valid_influence_request();
        let result = propose_accessibility_or_influence_adjustment(&request)
            .expect("closed influence parses");
        assert_eq!(result.outcome, AdjustmentOutcome::Complete);
        let closure = request.influence_closure.as_ref().expect("closure present");
        assert_eq!(closure.root_ref, request.projection.subject_handle);
        assert_eq!(closure.scope_id, request.projection.scope_id);
        assert_eq!(closure.policy_id, request.policy.policy_id);
        assert_eq!(
            closure.closure_revision,
            request.projection.subject_revision
        );
        assert!(closure.complete);
        assert!(closure.unknown_gaps.is_empty());
        for path in &request.affected {
            assert!(closure.dependent_refs.contains(&path.handle));
        }
        let mut affected: Vec<String> = request
            .affected
            .iter()
            .map(|path| path.handle.clone())
            .collect();
        affected.sort_unstable();
        let mut members = request.closure_denominator.members.clone();
        members.sort_unstable();
        assert_eq!(affected, members);
        let mut disposed: Vec<String> = result
            .dispositions
            .iter()
            .map(|outcome| outcome.handle.clone())
            .collect();
        disposed.sort_unstable();
        assert_eq!(affected, disposed);
    }

    // WORK_UNIT_CASE: 669/57
    #[test]
    fn case_57_no_move_widens_source_or_owner_allowance() {
        let mut unstated = valid_request();
        if let Some(change) = unstated.accessibility.as_mut() {
            change.privacy_ceiling = String::new();
        }
        assert!(propose_accessibility_or_influence_adjustment(&unstated).is_err());
        let mut over = influence_increase_request();
        if let Some(change) = over.influence.as_mut() {
            change.within_ceilings = false;
        }
        let result = propose_accessibility_or_influence_adjustment(&over)
            .expect("over-ceiling move is an outcome");
        assert_eq!(result.outcome, AdjustmentOutcome::Blocked);
        let request = accessibility_increase_request();
        let result = propose_accessibility_or_influence_adjustment(&request)
            .expect("ceiled increase parses");
        assert_eq!(result.outcome, AdjustmentOutcome::Complete);
        assert_eq!(
            result.proposed_snapshot.accessibility,
            AccessibilityStanding::Exposed
        );
    }

    // WORK_UNIT_CASE: 669/58
    #[test]
    fn case_58_every_valid_candidate_names_verifier_inverse_and_expiry() {
        let access = propose_accessibility_or_influence_adjustment(&valid_request())
            .expect("accessibility parses");
        assert_eq!(access.outcome, AdjustmentOutcome::Complete);
        assert!(!access.observable.is_empty());
        assert!(!access.verifier.is_empty());
        assert!(!access.window_note.is_empty());
        assert!(!access.inverse_note.is_empty());
        assert!(access.expiry_ms.is_some());
        assert!(!access.renewal_condition.is_empty());
        assert_eq!(access.dispositions.len(), 1);
        for outcome in &access.dispositions {
            assert!(!outcome.owner.is_empty());
            assert!(!outcome.verifier.is_empty());
            assert!(!outcome.inverse_note.is_empty());
            assert!(!outcome.before_identity.is_empty());
            assert!(!outcome.proposed_identity.is_empty());
        }
        let influence = propose_accessibility_or_influence_adjustment(&valid_influence_request())
            .expect("influence parses");
        assert_eq!(influence.outcome, AdjustmentOutcome::Complete);
        assert!(!influence.observable.is_empty());
        assert!(!influence.verifier.is_empty());
        assert!(!influence.window_note.is_empty());
        assert!(!influence.inverse_note.is_empty());
        assert!(influence.expiry_ms.is_some());
        assert!(!influence.renewal_condition.is_empty());
        assert_eq!(influence.dispositions.len(), 2);
    }

    // WORK_UNIT_CASE: 669/59
    #[test]
    fn case_59_bounded_malformed_input_neither_panics_nor_applies() {
        let mut blank = valid_request();
        blank.projection.subject_handle = String::new();
        assert!(propose_accessibility_or_influence_adjustment(&blank).is_err());
        let mut huge = valid_request();
        huge.usage.usage_window_note = "w".repeat(2000);
        assert!(propose_accessibility_or_influence_adjustment(&huge).is_err());
        let mut crossed = valid_request();
        crossed.policy.operation = AdjustmentOperation::Increase;
        crossed.policy.direction = AdjustmentDirection::Lower;
        assert!(propose_accessibility_or_influence_adjustment(&crossed).is_err());
        let mut duplicated = two_path_request();
        duplicated.affected[1].handle = "ctx-1".to_owned();
        assert!(propose_accessibility_or_influence_adjustment(&duplicated).is_err());
        let mut flooded = valid_request();
        flooded.usage.retrieval_successes = u64::MAX;
        let frozen = flooded.clone();
        assert!(propose_accessibility_or_influence_adjustment(&flooded).is_err());
        assert_eq!(flooded, frozen, "malformed input never applies");
    }
}
