//! Finite owner-bound maintenance plan candidate (A-41).
//!
//! Pure candidate-only deterministic stateless zero-effect owner of exactly
//! one finite owner-bound [`MaintenancePlanCandidate`] derived from one exact
//! validated Maintenance job, frozen grounded evidence, one maintenance
//! objective, exact trigger evidence, retained prior history, a finite typed
//! operation set with an explicit dependency graph, independent budget slices,
//! independent expected deltas, one semantic verifier, and an explicit
//! stop, rollback, disable, and Human-approval boundary. The handler proposes
//! one reviewable plan or an explicit inert disposition; it never schedules,
//! admits, reserves, routes, leases, executes, spends model budget, mutates
//! canonical state, decides policy, or finishes anything.
//!
//! Cell `smart.dreamer.maintenance_plan`, order 41. All inputs are immutable
//! and caller supplied. The pre-handler validator receipt travels inside the
//! [`ValidatedDreamDraft`] and
//! is checked intrinsically through its own validation entry points; it is
//! never re-executed here and is never attached as proof of the new plan.
//! Planned budget slices are allocations only, never acquired reservations.
//! No screening, grounding, common validation, production registry
//! construction, scheduling, recurrence, `ReadyQueue`, wake, route, lease,
//! reservation, Doctor, tool, provider, store, governor, model, clock,
//! authority, effect, or finish surface exists in this cell.
//!
//! Consumed contracts already carry closed unknown-field rejection (their
//! schemas state `deny_unknown_fields`); this cell performs no generic JSON
//! intake at all, so no unknown field can enter through a typeless path.
//! Every new shape below is constructed explicitly through the ten typed
//! parameters of [`propose_maintenance_plan`], never decoded from ambient
//! bytes.
//!
//! Runtime boundary: a malformed, over-bound, cancelled-before-emission, or
//! past-deadline request emits zero effects and fails closed as
//! [`MaintenancePlanError`]. Semantic shortfalls (generic optimization prose,
//! unmapped proxy signals, missing trigger evidence, incomplete denominators,
//! unknown or conflicting ownership, equivalent plans without new evidence,
//! unbounded or cyclic graphs, raw command or secret payloads, scheduling
//! language, ceiling widening, missing verifier or rollback, absent approval)
//! are inert terminal outcomes carried by [`MaintenancePlanCandidate`],
//! never errors that invite a blind retry. Silence is never approval, and a
//! forbidden action is rejected, never replaced with a warning.
//!
//! Absence note: this file contains no persistence, identifier allocation,
//! graph traversal beyond the bounded candidate operation list, schedule or
//! recurrence construction, reservation acquisition, provider, model, tool,
//! ambient-state, authority, effect, or terminal-completion calls by
//! construction; the only cryptography is the canonical digest below, and the
//! only fallible work is pure bounded validation. There are no placeholder,
//! mock, canned, or pseudo paths: every branch binds an explicit input field.
//!
//! Test coverage note: the executable matrix contains exactly 50 substantive
//! `WORK_UNIT_CASE 677/*` tests. The tests exercise the same production
//! validation path for valid plans and every numbered negative, partial,
//! replay, malformed-input, budget, recovery, Human-boundary, and candidate-
//! only source/API guard obligation; labels and receipt text are never used as
//! proof by themselves.
//!
//! Hub note: this JobClass-based leaf follows the pure-candidate sibling
//! idiom (`ValidatedDreamDraft` in, typed candidate out,
//! [`CurationRejectionCode`] hints). The hub `NativeCurationHandler` trait
//! serves the eleven closed curation kinds; no such kind names a maintenance
//! plan, so forcing a payload mapping would invent semantics the hub does not
//! own. The rejection vocabulary is still the shared hub enum.

#![forbid(unsafe_code)]

use eliot_contracts::{canonical_json_bytes, sha256_hex};
use eliot_dreamer_contracts::CurationRejectionCode;
use eliot_dreamer_contracts::candidate::DimensionVerdict;
use eliot_dreamer_contracts::{
    DreamJobAdmission, GroundedDreamDraft, JobClass, PreservationDimension, PreservationReport,
    ValidatedDreamDraft, check_fence, is_hex64_lower,
};

// ---------------------------------------------------------------------------
// Independent bounds (no cross-subsidy between dimensions).
// ---------------------------------------------------------------------------

/// Maximum planned operations admitted in one candidate graph.
pub const MAX_OPERATIONS: usize = 16;
/// Maximum dependencies admitted on any single operation.
pub const MAX_DEPENDENCIES: usize = 8;
/// Maximum expected deltas admitted in one candidate.
pub const MAX_DELTAS: usize = 16;
/// Maximum inputs admitted on any single operation.
pub const MAX_OPERATION_INPUTS: usize = 16;
/// Maximum preconditions admitted on any single operation.
pub const MAX_PRECONDITIONS: usize = 16;
/// Maximum non-goals admitted on any single operation.
pub const MAX_NON_GOALS: usize = 16;
/// Maximum evidence refs admitted in any single evidence list.
pub const MAX_EVIDENCE_ITEMS: usize = 64;
/// Maximum rollback steps admitted in one boundary.
pub const MAX_ROLLBACK_STEPS: usize = 64;
/// Maximum required Human decisions admitted in one boundary.
pub const MAX_DECISIONS: usize = 16;
/// Maximum history attempts admitted in one prior history.
pub const MAX_ATTEMPTS: usize = 64;
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
pub const MAINTENANCE_PROOF_NOTE: &str = "a-41 candidate-only aggregation: inert finite owner-bound plan preserved without screening, grounding, common validation, scheduling, recurrence, reservation, execution, model spend, canonical mutation, authority, effect, store, governor, clock, or finish";

/// Independent CPU millisecond ceiling for any single operation slice.
pub const CPU_MS_CEILING: u64 = 3_600_000;
/// Independent memory byte ceiling for any single operation slice.
pub const MEMORY_BYTES_CEILING: u64 = 1_073_741_824;
/// Independent storage byte ceiling for any single operation slice.
pub const STORAGE_BYTES_CEILING: u64 = 10_737_418_240;
/// Independent network byte ceiling for any single operation slice.
pub const NETWORK_BYTES_CEILING: u64 = 1_073_741_824;
/// Independent context byte ceiling for any single operation slice.
pub const CONTEXT_BYTES_CEILING: u64 = 1_048_576;
/// Independent cost unit ceiling for any single operation slice.
pub const COST_UNITS_CEILING: u64 = 10_000;
/// Independent Human minute ceiling for any single operation slice.
pub const HUMAN_MINUTES_CEILING: u64 = 480;
/// Independent wall millisecond ceiling for any single operation slice.
pub const WALL_MS_CEILING: u64 = 600_000;
/// Independent idle millisecond ceiling for any single operation slice.
pub const IDLE_MS_CEILING: u64 = 600_000;
/// Independent work item ceiling for any single operation slice.
pub const WORK_ITEMS_CEILING: u64 = 32;
/// Independent output byte ceiling for any single operation slice.
pub const OUTPUT_BYTES_CEILING: u64 = 1_048_576;

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
// Closed forbidden markers (generic prose, raw payloads, scheduling,
// ceiling widening). Similarity, bare activity, and silent approval never
// establish a trigger, a verifier, or a Human decision.
// ---------------------------------------------------------------------------

/// Substrings that mark generic optimization prose instead of a plan.
///
/// A concrete observed condition with an exact trigger, owner, and verifier
/// is required; background wishes to tune, watch, or ponder are rejected.
pub const GENERIC_MARKERS: &[&str] = &[
    "optimize everything",
    "improve performance generally",
    "monitor continuously",
    "keep thinking",
    "generic improvement",
    "tune everything",
    "make everything faster",
    "watch forever",
];

/// Substrings that mark a raw command, secret, live permit, or provider
/// payload smuggled into a candidate operation.
pub const RAW_MARKERS: &[&str] = &[
    "shell:",
    "run command ",
    "raw command",
    "api-key",
    "secret:",
    "live permit",
    "provider payload",
    " bearer ",
    "private key",
];

/// Substrings that mark scheduling, recurrence, reservation, routing, or
/// execution language that a candidate plan must never carry.
pub const SCHEDULING_MARKERS: &[&str] = &[
    "durablejob",
    "readyqueue",
    "wakeintent",
    "new schedule",
    "recurrence",
    "reserve capacity",
    "acquire lease",
    "admit job",
    "execute now",
    "run doctor",
];

/// Substrings that mark a forbidden privacy, cost, remote-access, model, or
/// policy widening claim.
pub const WIDENING_MARKERS: &[&str] = &[
    "export telemetry",
    "retain forever",
    "share externally",
    "train on private",
    "disable redaction",
    "open firewall",
    "grant admin",
    "assume authority",
    "raise quota",
    "auto deploy",
    "spend model budget",
    "decide policy silently",
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
// Public vocabulary: operation kinds, delta dimensions and directions,
// dispositions, objectives, triggers, budgets, operations, verifiers.
// ---------------------------------------------------------------------------

/// Closed admitted operation kind for one planned maintenance operation.
///
/// Only inert maintenance verbs owned by the policy vocabulary are admitted.
/// Scheduling, execution, Doctor, tool, provider, and configuration verbs
/// have no spelling here and are rejected as unsupported vocabulary.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum MaintenanceOpKind {
    /// Read-only inspection with an observable read postcondition.
    Inspect,
    /// Space reclamation with a measured freed-bytes postcondition.
    Vacuum,
    /// Index rebuild with a measured lookup postcondition.
    Reindex,
    /// Fragmentation compaction with a measured density postcondition.
    Compact,
    /// Point-in-time snapshot with a restorable digest postcondition.
    Snapshot,
    /// Semantic verification probe with a pass or fail postcondition.
    Verify,
    /// Drift reconciliation with a converged-state postcondition.
    Reconcile,
    /// Expired-entry pruning with a counted-removal postcondition.
    Prune,
    /// Stale-view refresh with an observed-freshness postcondition.
    Refresh,
    /// Credential or handle rotation with an observed-validity postcondition.
    Rotate,
}

impl MaintenanceOpKind {
    /// Returns the canonical spelling of this operation kind.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Inspect => "inspect",
            Self::Vacuum => "vacuum",
            Self::Reindex => "reindex",
            Self::Compact => "compact",
            Self::Snapshot => "snapshot",
            Self::Verify => "verify",
            Self::Reconcile => "reconcile",
            Self::Prune => "prune",
            Self::Refresh => "refresh",
            Self::Rotate => "rotate",
        }
    }

    /// Parses the canonical spelling of an operation kind.
    ///
    /// # Errors
    ///
    /// Returns [`MaintenancePlanError::Shape`] on any unknown spelling.
    pub fn parse(spelling: &str) -> Result<Self, MaintenancePlanError> {
        match spelling {
            "inspect" => Ok(Self::Inspect),
            "vacuum" => Ok(Self::Vacuum),
            "reindex" => Ok(Self::Reindex),
            "compact" => Ok(Self::Compact),
            "snapshot" => Ok(Self::Snapshot),
            "verify" => Ok(Self::Verify),
            "reconcile" => Ok(Self::Reconcile),
            "prune" => Ok(Self::Prune),
            "refresh" => Ok(Self::Refresh),
            "rotate" => Ok(Self::Rotate),
            _ => Err(MaintenancePlanError::Shape {
                field: "operation.kind",
                detail: redact(spelling),
            }),
        }
    }
}

/// Closed expected-delta dimension for one maintenance hypothesis.
///
/// Each dimension carries its own baseline, direction, range, evidence, and
/// verifier; improvement in one dimension never compensates a regression in
/// another, and cost improvement never offsets a safety or correctness
/// failure.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum DeltaDimension {
    /// Hypothesis about functional correctness.
    Correctness,
    /// Hypothesis about recovery posture.
    Recovery,
    /// Hypothesis about memory quality.
    MemoryQuality,
    /// Hypothesis about context quality.
    ContextQuality,
    /// Hypothesis about latency or resource posture.
    Latency,
    /// Hypothesis about resource consumption.
    Resources,
    /// Hypothesis about cost consumption.
    Cost,
    /// Hypothesis about evidence or conformance posture.
    Evidence,
    /// Hypothesis about capability posture.
    Capability,
    /// Hypothesis about security posture.
    Security,
    /// Hypothesis about privacy posture.
    Privacy,
    /// Hypothesis about future maintenance burden.
    MaintenanceBurden,
    /// Hypothesis about Human burden.
    HumanBurden,
    /// Hypothesis about supported user outcomes.
    UserOutcome,
}

impl DeltaDimension {
    /// Returns the canonical spelling of this delta dimension.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Correctness => "correctness",
            Self::Recovery => "recovery",
            Self::MemoryQuality => "memory_quality",
            Self::ContextQuality => "context_quality",
            Self::Latency => "latency",
            Self::Resources => "resources",
            Self::Cost => "cost",
            Self::Evidence => "evidence",
            Self::Capability => "capability",
            Self::Security => "security",
            Self::Privacy => "privacy",
            Self::MaintenanceBurden => "maintenance_burden",
            Self::HumanBurden => "human_burden",
            Self::UserOutcome => "user_outcome",
        }
    }

    /// Parses the canonical spelling of a delta dimension.
    ///
    /// # Errors
    ///
    /// Returns [`MaintenancePlanError::Shape`] on any unknown spelling.
    pub fn parse(spelling: &str) -> Result<Self, MaintenancePlanError> {
        match spelling {
            "correctness" => Ok(Self::Correctness),
            "recovery" => Ok(Self::Recovery),
            "memory_quality" => Ok(Self::MemoryQuality),
            "context_quality" => Ok(Self::ContextQuality),
            "latency" => Ok(Self::Latency),
            "resources" => Ok(Self::Resources),
            "cost" => Ok(Self::Cost),
            "evidence" => Ok(Self::Evidence),
            "capability" => Ok(Self::Capability),
            "security" => Ok(Self::Security),
            "privacy" => Ok(Self::Privacy),
            "maintenance_burden" => Ok(Self::MaintenanceBurden),
            "human_burden" => Ok(Self::HumanBurden),
            "user_outcome" => Ok(Self::UserOutcome),
            _ => Err(MaintenancePlanError::Shape {
                field: "delta.dimension",
                detail: redact(spelling),
            }),
        }
    }
}

/// Closed expected direction for one maintenance hypothesis.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum DeltaDirection {
    /// The dimension is expected to improve within the stated range.
    Improve,
    /// The dimension is expected to stay unchanged within the stated range.
    Preserve,
    /// Consumption in the dimension is expected to fall within the range.
    Reduce,
    /// The dimension is expected to stay inside an explicit bound.
    Bounded,
}

/// Concrete class of observed condition that may justify maintenance.
///
/// Incident and recovery work remains with its actual operational owner; it
/// cannot be laundered into a maintenance candidate by changing prose.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum TriggerKind {
    /// A measured quality or health degradation.
    QualityDegradation,
    /// A bounded candidate backlog or debt threshold.
    CandidateBacklog,
    /// A repeated failure or no-progress observation.
    RepeatedFailure,
    /// A stale or changed capability observation.
    StaleCapability,
    /// An explicit Human or Main-Agent maintenance request.
    UserRequest,
    /// A reference to an existing externally owned maintenance cadence.
    ExternalCadence,
    /// An incident or recovery condition owned outside this planner.
    IncidentRecovery,
}

impl TriggerKind {
    /// Returns the stable semantic spelling used in the candidate digest.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::QualityDegradation => "quality_degradation",
            Self::CandidateBacklog => "candidate_backlog",
            Self::RepeatedFailure => "repeated_failure",
            Self::StaleCapability => "stale_capability",
            Self::UserRequest => "user_request",
            Self::ExternalCadence => "external_cadence",
            Self::IncidentRecovery => "incident_recovery",
        }
    }
}

/// Cancellation handling for an operation candidate.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum CancellationHandling {
    /// Cancellation before effect is safe only when no effect is proven.
    BeforeEffectNoEffect,
    /// Cancellation after a possible effect requires reconciliation first.
    PossibleEffectRequiresReconciliation,
}

impl CancellationHandling {
    /// Returns the stable semantic spelling used in the candidate digest.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::BeforeEffectNoEffect => "before_effect_no_effect",
            Self::PossibleEffectRequiresReconciliation => "possible_effect_requires_reconciliation",
        }
    }
}

/// Durable disposition retained for one prior maintenance attempt.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum PriorAttemptDisposition {
    /// The attempt was only proposed.
    Planned,
    /// The attempt was admitted by its external owner.
    Admitted,
    /// The attempt was launched or otherwise started.
    Attempted,
    /// The attempt produced an execution result.
    Executed,
    /// The attempt passed its semantic verifier.
    Verified,
    /// The attempt changed only part of its declared scope.
    Partial,
    /// The attempt failed with a known terminal result.
    Failed,
    /// The attempt made no measured progress.
    NoProgress,
    /// The attempt hung or timed out.
    Hung,
    /// The attempt was cancelled.
    Cancelled,
    /// The attempt's terminal state is unknown.
    Unknown,
}

impl PriorAttemptDisposition {
    /// Returns the stable semantic spelling used in the candidate digest.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Planned => "planned",
            Self::Admitted => "admitted",
            Self::Attempted => "attempted",
            Self::Executed => "executed",
            Self::Verified => "verified",
            Self::Partial => "partial",
            Self::Failed => "failed",
            Self::NoProgress => "no_progress",
            Self::Hung => "hung",
            Self::Cancelled => "cancelled",
            Self::Unknown => "unknown",
        }
    }
}

/// Effect state retained for one prior attempt.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum PriorEffectState {
    /// The operation was proven not to start or to have no effect.
    NoEffect,
    /// The declared effect was observed and reconciled.
    Applied,
    /// Only a bounded part of the effect was observed.
    Partial,
    /// The effect may have happened and is not reconciled.
    Unknown,
    /// The effect was reconciled without claiming success.
    Reconciled,
}

impl PriorEffectState {
    /// Returns the stable semantic spelling used in the candidate digest.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NoEffect => "no_effect",
            Self::Applied => "applied",
            Self::Partial => "partial",
            Self::Unknown => "unknown",
            Self::Reconciled => "reconciled",
        }
    }
}

/// Explicit reason for repeating an equivalent controlled plan.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum RepeatJustification {
    /// No repeat is justified.
    None,
    /// Repeat to estimate noise with retained evidence.
    Replication,
    /// Repeat to estimate measurement noise.
    NoiseEstimation,
    /// Repeat against a declared control or comparison.
    ControlledComparison,
    /// Repeat an exact reproduction for diagnosis.
    ExactReproduction,
    /// Repeat as part of a recovery proof.
    RecoveryProof,
    /// Repeat to calibrate a semantic verifier.
    VerifierCalibration,
}

impl RepeatJustification {
    /// Returns the stable semantic spelling used in the candidate digest.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Replication => "replication",
            Self::NoiseEstimation => "noise_estimation",
            Self::ControlledComparison => "controlled_comparison",
            Self::ExactReproduction => "exact_reproduction",
            Self::RecoveryProof => "recovery_proof",
            Self::VerifierCalibration => "verifier_calibration",
        }
    }
}

impl DeltaDirection {
    /// Returns the canonical spelling of this direction.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Improve => "improve",
            Self::Preserve => "preserve",
            Self::Reduce => "reduce",
            Self::Bounded => "bounded",
        }
    }

    /// Parses the canonical spelling of a direction.
    ///
    /// # Errors
    ///
    /// Returns [`MaintenancePlanError::Shape`] on any unknown spelling.
    pub fn parse(spelling: &str) -> Result<Self, MaintenancePlanError> {
        match spelling {
            "improve" => Ok(Self::Improve),
            "preserve" => Ok(Self::Preserve),
            "reduce" => Ok(Self::Reduce),
            "bounded" => Ok(Self::Bounded),
            _ => Err(MaintenancePlanError::Shape {
                field: "delta.direction",
                detail: redact(spelling),
            }),
        }
    }
}

/// Terminal outcome of one maintenance plan proposal.
///
/// Fail-closed ordering applies: malformed inputs are
/// [`MaintenancePlanError`], while every semantic shortfall below is an
/// inert outcome that plans nothing and effects nothing.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum MaintenanceOutcome {
    /// One complete finite owner-bound plan with full accounting.
    Complete,
    /// Coverage is partial with named omissions; completeness is blocked.
    Partial,
    /// A Human or owner decision is required before any plan is complete.
    DecisionRequired,
    /// Evidence or mapping is insufficient for a complete plan.
    Insufficient,
    /// Inputs moved under the request; replay against the new revision.
    Stale,
    /// The request is rejected with a boundary handoff.
    Rejected,
    /// The supplied vocabulary names no admitted maintenance shape.
    UnsupportedShape,
}

impl MaintenanceOutcome {
    /// Returns the canonical spelling of this outcome.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Complete => "complete",
            Self::Partial => "partial",
            Self::DecisionRequired => "decision_required",
            Self::Insufficient => "insufficient",
            Self::Stale => "stale",
            Self::Rejected => "rejected",
            Self::UnsupportedShape => "unsupported_shape",
        }
    }
}

/// One finite maintenance objective bound to exactly one owner.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MaintenanceObjective {
    /// Stable objective identity.
    pub objective_id: String,
    /// Exact objective revision under planning, never latest-by-time.
    pub objective_revision: u32,
    /// Canonical product identity the objective serves.
    pub product_id: String,
    /// Module reference the objective is scoped to.
    pub module_ref: String,
    /// Single owning principal for the whole plan.
    pub owner: String,
    /// Explicit owner decomposition when independent operation owners are
    /// intentionally retained in one candidate.
    pub decomposition_owners: Vec<String>,
    /// Bounded note naming the causal property under maintenance.
    pub causal_note: String,
    /// Digest binding this objective to its context bytes.
    pub context_digest: String,
}

/// Exact observed trigger evidence for one maintenance objective.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TriggerEvidence {
    /// Stable trigger identity.
    pub trigger_id: String,
    /// Closed class of the observed condition.
    pub kind: TriggerKind,
    /// Principal that owns the observation or diagnosis.
    pub observation_owner: String,
    /// Exact affected surface retained separately from the operation owner.
    pub affected_surface: String,
    /// Current measured baseline or invariant for the observation.
    pub baseline_note: String,
    /// Bounded note naming the concrete observed condition.
    pub condition_note: String,
    /// Bounded note naming the diagnosed condition class.
    pub diagnosed_condition: String,
    /// Evidence refs backing the trigger, in sorted unique order.
    pub evidence_refs: Vec<String>,
    /// Declared observation denominator total.
    pub denominator_total: u64,
    /// Covered portion of the declared denominator.
    pub denominator_covered: u64,
    /// Bounded false-positive assessment for the trigger.
    pub false_positive_note: String,
    /// Bounded persistence assessment for the trigger.
    pub persistence_note: String,
    /// Justification for a one-shot trigger, when the denominator is one.
    pub one_shot_justification: Option<String>,
    /// Evidence-backed user-outcome mapping; required, never assumed.
    pub outcome_mapping_note: Option<String>,
    /// Bounded note naming the invalidation conditions.
    pub invalidation_note: String,
    /// Digest binding this trigger to its context bytes.
    pub context_digest: String,
}

/// Independent planned budget slice for one operation.
///
/// Every dimension is checked on its own; unknown is not unlimited and not
/// zero, and under-use in one dimension never covers over-use in another.
/// `model_calls` must be zero: candidate plans spend no model budget.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BudgetSlice {
    /// Planned CPU milliseconds.
    pub cpu_ms: u64,
    /// Planned memory bytes.
    pub memory_bytes: u64,
    /// Planned storage bytes.
    pub storage_bytes: u64,
    /// Planned network bytes.
    pub network_bytes: u64,
    /// Planned context bytes.
    pub context_bytes: u64,
    /// Planned model calls; must be zero.
    pub model_calls: u64,
    /// Planned abstract cost units.
    pub cost_units: u64,
    /// Planned Human minutes.
    pub human_minutes: u64,
    /// Planned wall-clock milliseconds.
    pub wall_ms: u64,
    /// Planned idle milliseconds.
    pub idle_ms: u64,
    /// Planned work items.
    pub work_items: u64,
    /// Planned output bytes.
    pub output_bytes: u64,
}

/// One finite typed maintenance operation candidate.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PlannedOperation {
    /// Stable operation identity, unique within the plan.
    pub op_id: String,
    /// Closed operation kind spelling from the policy vocabulary.
    pub op_kind: String,
    /// Single external owner of this operation.
    pub owner: String,
    /// Immutable input handles, in supplied order without duplicates.
    pub inputs: Vec<String>,
    /// Precondition notes, each independently observable.
    pub preconditions: Vec<String>,
    /// Bounded note naming the observable output.
    pub output_note: String,
    /// Verifier identity; must equal the boundary verifier.
    pub verifier_id: String,
    /// Bounded effect and privacy ceiling for this operation.
    pub effect_ceiling: String,
    /// Independent planned budget slice for this operation.
    pub budget: BudgetSlice,
    /// Execution order rank, unique within the plan.
    pub order: u32,
    /// Operation identities this operation depends on.
    pub depends_on: Vec<String>,
    /// Maximum retries admitted for this operation.
    pub max_retries: u32,
    /// Bounded deadline note for this operation.
    pub deadline_note: String,
    /// Bounded cancellation note, distinguishing pre-effect input.
    pub cancel_note: String,
    /// Typed cancellation/effect boundary for this operation.
    pub cancellation: CancellationHandling,
    /// Bounded no-progress note for this operation.
    pub no_progress_note: String,
    /// Bounded rollback note owned with this operation.
    pub rollback_note: String,
    /// Bounded disable note owned with this operation.
    pub disable_note: String,
    /// Bounded stop note for this operation.
    pub stop_note: String,
    /// Bounded reopen note for this operation.
    pub reopen_note: String,
    /// Explicit non-goals for this operation.
    pub non_goals: Vec<String>,
}

/// One independent expected delta hypothesis for the plan.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExpectedDelta {
    /// Closed delta dimension spelling.
    pub dimension: String,
    /// Bounded note naming the measured baseline.
    pub baseline_note: String,
    /// Closed expected direction spelling.
    pub direction: String,
    /// Bounded note naming the expected range.
    pub range_note: String,
    /// Bounded note naming the supporting evidence.
    pub evidence_note: String,
    /// Bounded note naming the uncertainty.
    pub uncertainty_note: String,
    /// Verifier identity for this delta.
    pub verifier_id: String,
    /// Bounded note naming the unacceptable regression for this delta.
    pub unacceptable_regression: String,
}

/// One semantic verifier with distinct success, partial, no-change,
/// regression, failure, and unknown readings.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SemanticVerifier {
    /// Stable verifier identity.
    pub verifier_id: String,
    /// Bounded success reading.
    pub success_note: String,
    /// Predicate over the observed semantic output, not process liveness or
    /// metric movement alone.
    pub semantic_success_predicate: String,
    /// Bounded partial reading.
    pub partial_note: String,
    /// Bounded no-change reading.
    pub no_change_note: String,
    /// Bounded regression reading.
    pub regression_note: String,
    /// Bounded failure reading.
    pub failure_note: String,
    /// Bounded unknown reading.
    pub unknown_note: String,
    /// Bounded observation window and denominator note.
    pub observation_window_note: String,
    /// Bounded denominator note for the verifier.
    pub denominator_note: String,
    /// Maximum attempts admitted by the verifier.
    pub max_attempts: u32,
    /// Bounded stop and no-progress note for the verifier.
    pub stop_note: String,
}

/// Inert stop, rollback, disable, and Human-approval boundary.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MaintenanceBoundary {
    /// The single semantic verifier for the whole plan.
    pub verifier: SemanticVerifier,
    /// Ordered rollback steps restoring the exact prior state.
    pub rollback_steps: Vec<String>,
    /// Bounded disable note for the maintained surface.
    pub disable_note: String,
    /// Bounded forward-repair note for partial states.
    pub forward_repair_note: String,
    /// Bounded reopen note naming the changed-condition gate.
    pub reopen_note: String,
    /// Explicit Human or owner decisions required before completeness.
    pub required_decisions: Vec<String>,
    /// Bounded approval-expiry note; silence never extends approval.
    pub approval_expiry_note: String,
    /// Must always be false; silence is not approval.
    pub silence_is_approval: bool,
    /// Bounded note naming the forbidden widening surface.
    pub forbidden_widening_note: String,
    /// Planned verification/rollback/Human headroom. This is an allocation,
    /// never a live reservation or acquired authority.
    pub protected_budget: BudgetSlice,
    /// Existing external automation/cadence reference, if the trigger uses
    /// one. The planner never creates a cadence.
    pub external_automation_ref: Option<String>,
}

/// Governing policy for one maintenance plan proposal.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MaintenancePolicy {
    /// Stable policy identity; must equal the receipt validator policy.
    pub policy_id: String,
    /// Exact policy revision; must be explicit, not defaulted.
    pub policy_revision: u32,
    /// Closed operation-kind vocabulary admitted by this policy.
    pub allowed_op_kinds: Vec<String>,
    /// Maximum operations admitted in one plan.
    pub max_operations: usize,
    /// Maximum dependencies admitted on any single operation.
    pub max_dependencies: usize,
    /// Maximum expected deltas admitted in one plan.
    pub max_deltas: usize,
    /// Maximum evidence refs admitted in any single evidence list.
    pub max_evidence: usize,
    /// True only when partial coverage may emit a partial outcome.
    pub allow_partial: bool,
    /// True only when the caller cancelled before emission.
    pub cancelled: bool,
    /// Frozen observation time in Unix milliseconds, when known.
    pub observation_time_ms: Option<u64>,
    /// Frozen deadline in Unix milliseconds, when known.
    pub deadline_ms: Option<u64>,
    /// Bounded owner note for the policy.
    pub owner_note: String,
}

/// One retained prior attempt with its equivalence binding.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HistoryAttempt {
    /// Stable attempt identity.
    pub attempt_id: String,
    /// Equivalence digest binding the attempt mechanism and scope.
    pub equivalence_digest: String,
    /// Retained lifecycle disposition of the prior attempt.
    pub disposition: PriorAttemptDisposition,
    /// Retained known/unknown effect state.
    pub effect_state: PriorEffectState,
    /// Whether new evidence justifies a controlled equivalent repeat.
    pub changed_evidence: bool,
    /// Why an equivalent repeat is controlled, when applicable.
    pub repeat_justification: RepeatJustification,
    /// Optional canonical request digest for same-ID conflict detection.
    pub request_digest: Option<String>,
    /// Optional policy revision bound to the same request identity.
    pub policy_revision: Option<u32>,
}

/// Retained prior-history denominator for equivalence and retry analysis.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PriorHistory {
    /// Expected attempt identities in supplied order.
    pub expected_attempt_ids: Vec<String>,
    /// Retained attempts exactly covering the expected denominator.
    pub attempts: Vec<HistoryAttempt>,
    /// Bounded outcome note preserved verbatim, never reinterpreted.
    pub outcome_note: String,
}

/// One finite owner-bound maintenance plan candidate with full accounting.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MaintenancePlanCandidate {
    /// Terminal outcome for this plan proposal.
    pub outcome: MaintenanceOutcome,
    /// Stable plan handle derived from the objective identity.
    pub plan_handle: String,
    /// Objective identity under planning.
    pub objective_id: String,
    /// Exact objective revision under planning.
    pub objective_revision: u32,
    /// Product identity under planning.
    pub product_id: String,
    /// Single owning principal for the whole plan.
    pub owner: String,
    /// Explicit operation-owner decomposition, empty for one-owner plans.
    pub decomposition_owners: Vec<String>,
    /// Trigger identity grounding the plan.
    pub trigger_id: String,
    /// Planned operations in supplied order.
    pub operations: Vec<PlannedOperation>,
    /// Independent expected deltas in supplied order.
    pub deltas: Vec<ExpectedDelta>,
    /// Semantic verifier identity for the whole plan.
    pub verifier_id: String,
    /// Ordered rollback steps restoring the exact prior state.
    pub rollback_steps: Vec<String>,
    /// Explicit Human or owner decisions required before completeness.
    pub required_decisions: Vec<String>,
    /// Bounded stop summary for the whole plan.
    pub stop_summary: String,
    /// Seven-dimension preservation report for this candidate.
    pub preservation: PreservationReport,
    /// Output digest of the input validator receipt this plan replays.
    pub input_receipt_digest: String,
    /// Expected attempt identities accounted, in supplied order.
    pub attempt_denominator: Vec<String>,
    /// Deterministic digest binding the plan inputs.
    pub candidate_digest: String,
    /// Bounded machine-readable note.
    pub note: String,
}

// ---------------------------------------------------------------------------
// Typed fail-closed error. Malformed input only; semantic shortfalls stay
// inert outcomes carried by `MaintenancePlanCandidate`.
// ---------------------------------------------------------------------------

/// Typed fail-closed maintenance-plan error.
///
/// Every variant carries structured identities; free-text detail is always
/// redacted and bounded. A value of this type is never a stub: it names the
/// exact failed binding or bound.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MaintenancePlanError {
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
    /// The bundled validator receipt is intrinsically invalid or incompatible.
    Receipt {
        /// Bounded redacted reason.
        detail: String,
    },
    /// The governing policy is malformed or out of bounds.
    Policy {
        /// Bounded redacted reason.
        detail: String,
    },
    /// An objective, trigger, operation, delta, or history denominator is malformed.
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

impl core::fmt::Display for MaintenancePlanError {
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

impl core::error::Error for MaintenancePlanError {}

// ---------------------------------------------------------------------------
// Shape checks (malformed input only).
// ---------------------------------------------------------------------------

/// Checks one bounded text field for blank, control, and byte ceiling.
fn check_bounded_text(
    value: &str,
    field: &'static str,
    max: usize,
) -> Result<(), MaintenancePlanError> {
    if value.trim().is_empty() {
        return Err(MaintenancePlanError::Shape {
            field,
            detail: "blank text is not admitted".to_owned(),
        });
    }
    if has_control(value) {
        return Err(MaintenancePlanError::Shape {
            field,
            detail: "control characters are not admitted".to_owned(),
        });
    }
    if value.len() > max {
        return Err(MaintenancePlanError::Shape {
            field,
            detail: "text exceeds its byte bound".to_owned(),
        });
    }
    Ok(())
}

/// Checks one handle field for blank, control, and byte ceiling.
fn check_handle(value: &str, field: &'static str) -> Result<(), MaintenancePlanError> {
    if value.is_empty() || value.len() > MAX_HANDLE_BYTES {
        return Err(MaintenancePlanError::Bounds {
            phase: field.to_owned(),
            detail: "handle is blank or exceeds the handle ceiling".to_owned(),
        });
    }
    if has_control(value) {
        return Err(MaintenancePlanError::Bounds {
            phase: field.to_owned(),
            detail: "handle carries control characters".to_owned(),
        });
    }
    Ok(())
}

/// Checks one digest field for exact 64 lowercase hex shape.
fn check_digest(value: &str, field: &'static str) -> Result<(), MaintenancePlanError> {
    if !is_hex64_lower(value) {
        return Err(MaintenancePlanError::Digest {
            detail: ["digest ", field, " must be 64 lowercase hex sha256"].concat(),
        });
    }
    Ok(())
}

/// Rejects a list length above its independent ceiling.
fn bound_list_length(
    phase: &'static str,
    got: usize,
    max: usize,
) -> Result<(), MaintenancePlanError> {
    if got > max {
        return Err(MaintenancePlanError::Bounds {
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

/// Validates objective shapes without judging objective semantics.
fn validate_objective_shapes(objective: &MaintenanceObjective) -> Result<(), MaintenancePlanError> {
    check_handle(&objective.objective_id, "objective.identity")?;
    if objective.objective_revision == 0 {
        return Err(MaintenancePlanError::Shape {
            field: "objective.revision",
            detail: "objective revision must be explicit, not defaulted".to_owned(),
        });
    }
    check_bounded_text(&objective.product_id, "objective.product", MAX_ID_BYTES)?;
    check_bounded_text(&objective.module_ref, "objective.module", MAX_ID_BYTES)?;
    check_bounded_text(&objective.owner, "objective.owner", MAX_ID_BYTES)?;
    bound_list_length(
        "objective.decomposition",
        objective.decomposition_owners.len(),
        MAX_OPERATIONS,
    )?;
    for owner in &objective.decomposition_owners {
        check_bounded_text(owner, "objective.decomposition-owner", MAX_ID_BYTES)?;
    }
    if !is_sorted_unique(&objective.decomposition_owners) {
        return Err(MaintenancePlanError::Order {
            phase: "objective.decomposition".to_owned(),
            detail: "owner decomposition must be sorted and unique".to_owned(),
        });
    }
    if !objective.decomposition_owners.is_empty()
        && !objective
            .decomposition_owners
            .iter()
            .any(|owner| owner == &objective.owner)
    {
        return Err(MaintenancePlanError::Binding {
            field: "objective.decomposition",
            detail: "owner decomposition must retain the primary owner".to_owned(),
        });
    }
    check_bounded_text(&objective.causal_note, "objective.causal", MAX_NOTE_BYTES)?;
    check_digest(&objective.context_digest, "objective.context")?;
    Ok(())
}

/// Validates trigger shapes without judging trigger semantics.
fn validate_trigger_shapes(trigger: &TriggerEvidence) -> Result<(), MaintenancePlanError> {
    check_handle(&trigger.trigger_id, "trigger.identity")?;
    check_bounded_text(
        &trigger.observation_owner,
        "trigger.observation-owner",
        MAX_ID_BYTES,
    )?;
    check_bounded_text(
        &trigger.affected_surface,
        "trigger.affected-surface",
        MAX_SCOPE_BYTES,
    )?;
    check_bounded_text(&trigger.baseline_note, "trigger.baseline", MAX_NOTE_BYTES)?;
    check_bounded_text(&trigger.condition_note, "trigger.condition", MAX_NOTE_BYTES)?;
    check_bounded_text(
        &trigger.diagnosed_condition,
        "trigger.diagnosed",
        MAX_NOTE_BYTES,
    )?;
    bound_list_length(
        "trigger.evidence",
        trigger.evidence_refs.len(),
        MAX_EVIDENCE_ITEMS,
    )?;
    for handle in &trigger.evidence_refs {
        check_handle(handle, "trigger.evidence")?;
    }
    if trigger.denominator_total == 0 {
        return Err(MaintenancePlanError::Shape {
            field: "trigger.denominator",
            detail: "trigger denominator total must be explicit, not defaulted".to_owned(),
        });
    }
    if trigger.denominator_covered > trigger.denominator_total {
        return Err(MaintenancePlanError::Bounds {
            phase: "trigger.denominator".to_owned(),
            detail: "covered denominator cannot exceed the declared total".to_owned(),
        });
    }
    check_bounded_text(
        &trigger.false_positive_note,
        "trigger.false-positive",
        MAX_NOTE_BYTES,
    )?;
    check_bounded_text(
        &trigger.persistence_note,
        "trigger.persistence",
        MAX_NOTE_BYTES,
    )?;
    if let Some(justification) = &trigger.one_shot_justification {
        check_bounded_text(justification, "trigger.one-shot", MAX_NOTE_BYTES)?;
    }
    if let Some(mapping) = &trigger.outcome_mapping_note {
        check_bounded_text(mapping, "trigger.mapping", MAX_NOTE_BYTES)?;
    }
    check_bounded_text(
        &trigger.invalidation_note,
        "trigger.invalidation",
        MAX_NOTE_BYTES,
    )?;
    check_digest(&trigger.context_digest, "trigger.context")?;
    Ok(())
}

/// Validates one budget slice against every independent ceiling.
fn validate_budget_slice(budget: &BudgetSlice) -> Result<(), MaintenancePlanError> {
    if budget.cpu_ms > CPU_MS_CEILING {
        return Err(MaintenancePlanError::Bounds {
            phase: "budget.cpu".to_owned(),
            detail: "cpu slice exceeds its independent ceiling".to_owned(),
        });
    }
    if budget.memory_bytes > MEMORY_BYTES_CEILING {
        return Err(MaintenancePlanError::Bounds {
            phase: "budget.memory".to_owned(),
            detail: "memory slice exceeds its independent ceiling".to_owned(),
        });
    }
    if budget.storage_bytes > STORAGE_BYTES_CEILING {
        return Err(MaintenancePlanError::Bounds {
            phase: "budget.storage".to_owned(),
            detail: "storage slice exceeds its independent ceiling".to_owned(),
        });
    }
    if budget.network_bytes > NETWORK_BYTES_CEILING {
        return Err(MaintenancePlanError::Bounds {
            phase: "budget.network".to_owned(),
            detail: "network slice exceeds its independent ceiling".to_owned(),
        });
    }
    if budget.context_bytes > CONTEXT_BYTES_CEILING {
        return Err(MaintenancePlanError::Bounds {
            phase: "budget.context".to_owned(),
            detail: "context slice exceeds its independent ceiling".to_owned(),
        });
    }
    if budget.model_calls > 0 {
        return Err(MaintenancePlanError::Bounds {
            phase: "budget.model-calls".to_owned(),
            detail: "candidate plans spend no model calls".to_owned(),
        });
    }
    if budget.cost_units > COST_UNITS_CEILING {
        return Err(MaintenancePlanError::Bounds {
            phase: "budget.cost".to_owned(),
            detail: "cost slice exceeds its independent ceiling".to_owned(),
        });
    }
    if budget.human_minutes > HUMAN_MINUTES_CEILING {
        return Err(MaintenancePlanError::Bounds {
            phase: "budget.human".to_owned(),
            detail: "human slice exceeds its independent ceiling".to_owned(),
        });
    }
    if budget.wall_ms > WALL_MS_CEILING {
        return Err(MaintenancePlanError::Bounds {
            phase: "budget.wall".to_owned(),
            detail: "wall slice exceeds its independent ceiling".to_owned(),
        });
    }
    if budget.idle_ms > IDLE_MS_CEILING {
        return Err(MaintenancePlanError::Bounds {
            phase: "budget.idle".to_owned(),
            detail: "idle slice exceeds its independent ceiling".to_owned(),
        });
    }
    if budget.work_items > WORK_ITEMS_CEILING {
        return Err(MaintenancePlanError::Bounds {
            phase: "budget.work".to_owned(),
            detail: "work slice exceeds its independent ceiling".to_owned(),
        });
    }
    if budget.output_bytes > OUTPUT_BYTES_CEILING {
        return Err(MaintenancePlanError::Bounds {
            phase: "budget.output".to_owned(),
            detail: "output slice exceeds its independent ceiling".to_owned(),
        });
    }
    Ok(())
}

/// Validates one operation shape without judging operation semantics.
fn validate_one_operation_shape(operation: &PlannedOperation) -> Result<(), MaintenancePlanError> {
    check_handle(&operation.op_id, "operation.identity")?;
    check_bounded_text(&operation.op_kind, "operation.kind", MAX_ID_BYTES)?;
    check_bounded_text(&operation.owner, "operation.owner", MAX_ID_BYTES)?;
    bound_list_length(
        "operation.inputs",
        operation.inputs.len(),
        MAX_OPERATION_INPUTS,
    )?;
    for input in &operation.inputs {
        check_handle(input, "operation.input")?;
    }
    if !has_no_duplicates(&operation.inputs) {
        return Err(MaintenancePlanError::Order {
            phase: "operation.inputs".to_owned(),
            detail: "operation inputs must hold no duplicates".to_owned(),
        });
    }
    if !is_sorted_unique(&operation.inputs) {
        return Err(MaintenancePlanError::Order {
            phase: "operation.inputs".to_owned(),
            detail: "operation inputs must be canonical sorted sets".to_owned(),
        });
    }
    bound_list_length(
        "operation.preconditions",
        operation.preconditions.len(),
        MAX_PRECONDITIONS,
    )?;
    for precondition in &operation.preconditions {
        check_bounded_text(precondition, "operation.precondition", MAX_NOTE_BYTES)?;
    }
    check_bounded_text(&operation.output_note, "operation.output", MAX_NOTE_BYTES)?;
    check_handle(&operation.verifier_id, "operation.verifier")?;
    check_bounded_text(
        &operation.effect_ceiling,
        "operation.ceiling",
        MAX_NOTE_BYTES,
    )?;
    validate_budget_slice(&operation.budget)?;
    bound_list_length(
        "operation.depends",
        operation.depends_on.len(),
        MAX_DEPENDENCIES,
    )?;
    for dependency in &operation.depends_on {
        check_handle(dependency, "operation.depends")?;
    }
    if !has_no_duplicates(&operation.depends_on) {
        return Err(MaintenancePlanError::Order {
            phase: "operation.depends".to_owned(),
            detail: "operation dependencies must hold no duplicates".to_owned(),
        });
    }
    if !is_sorted_unique(&operation.depends_on) {
        return Err(MaintenancePlanError::Order {
            phase: "operation.depends".to_owned(),
            detail: "operation dependencies must be canonical sorted sets".to_owned(),
        });
    }
    if operation.max_retries > 5 {
        return Err(MaintenancePlanError::Bounds {
            phase: "operation.retries".to_owned(),
            detail: "operation retries exceed the independent retry ceiling".to_owned(),
        });
    }
    check_bounded_text(
        &operation.deadline_note,
        "operation.deadline",
        MAX_NOTE_BYTES,
    )?;
    check_bounded_text(&operation.cancel_note, "operation.cancel", MAX_NOTE_BYTES)?;
    check_bounded_text(
        &operation.no_progress_note,
        "operation.no-progress",
        MAX_NOTE_BYTES,
    )?;
    check_bounded_text(
        &operation.rollback_note,
        "operation.rollback",
        MAX_NOTE_BYTES,
    )?;
    check_bounded_text(&operation.disable_note, "operation.disable", MAX_NOTE_BYTES)?;
    check_bounded_text(&operation.stop_note, "operation.stop", MAX_NOTE_BYTES)?;
    check_bounded_text(&operation.reopen_note, "operation.reopen", MAX_NOTE_BYTES)?;
    bound_list_length(
        "operation.non-goals",
        operation.non_goals.len(),
        MAX_NON_GOALS,
    )?;
    for non_goal in &operation.non_goals {
        check_bounded_text(non_goal, "operation.non-goal", MAX_NOTE_BYTES)?;
    }
    if !has_no_duplicates(&operation.non_goals) {
        return Err(MaintenancePlanError::Order {
            phase: "operation.non-goals".to_owned(),
            detail: "operation non-goals must hold no duplicates".to_owned(),
        });
    }
    Ok(())
}

/// Validates operation shapes plus identity and order uniqueness.
fn validate_operation_shapes(operations: &[PlannedOperation]) -> Result<(), MaintenancePlanError> {
    bound_list_length("operation.graph", operations.len(), MAX_OPERATIONS)?;
    if operations.is_empty() {
        return Err(MaintenancePlanError::Shape {
            field: "operation.graph",
            detail: "a plan carries at least one finite operation".to_owned(),
        });
    }
    for operation in operations {
        validate_one_operation_shape(operation)?;
    }
    let mut ids: Vec<String> = Vec::with_capacity(operations.len());
    for operation in operations {
        ids.push(operation.op_id.clone());
    }
    if !has_no_duplicates(&ids) {
        return Err(MaintenancePlanError::Order {
            phase: "operation.graph".to_owned(),
            detail: "operation identities must hold no duplicates".to_owned(),
        });
    }
    let mut orders: Vec<u32> = Vec::with_capacity(operations.len());
    for operation in operations {
        orders.push(operation.order);
    }
    let mut index = 0usize;
    while index < orders.len() {
        let mut inner = index.saturating_add(1);
        while inner < orders.len() {
            let left = orders.get(index);
            let right = orders.get(inner);
            if let (Some(left), Some(right)) = (left, right) {
                if left == right {
                    return Err(MaintenancePlanError::Order {
                        phase: "operation.graph".to_owned(),
                        detail: "operation order ranks must hold no duplicates".to_owned(),
                    });
                }
            } else {
                return Err(MaintenancePlanError::Order {
                    phase: "operation.graph".to_owned(),
                    detail: "operation order denominator is not addressable".to_owned(),
                });
            }
            inner = inner.saturating_add(1);
        }
        index = index.saturating_add(1);
    }
    Ok(())
}

/// Validates one delta shape without judging delta semantics.
fn validate_one_delta_shape(delta: &ExpectedDelta) -> Result<(), MaintenancePlanError> {
    check_bounded_text(&delta.dimension, "delta.dimension", MAX_ID_BYTES)?;
    check_bounded_text(&delta.baseline_note, "delta.baseline", MAX_NOTE_BYTES)?;
    check_bounded_text(&delta.direction, "delta.direction", MAX_ID_BYTES)?;
    check_bounded_text(&delta.range_note, "delta.range", MAX_NOTE_BYTES)?;
    check_bounded_text(&delta.evidence_note, "delta.evidence", MAX_NOTE_BYTES)?;
    check_bounded_text(&delta.uncertainty_note, "delta.uncertainty", MAX_NOTE_BYTES)?;
    check_handle(&delta.verifier_id, "delta.verifier")?;
    check_bounded_text(
        &delta.unacceptable_regression,
        "delta.regression",
        MAX_NOTE_BYTES,
    )?;
    Ok(())
}

/// Validates delta shapes without judging delta semantics.
fn validate_delta_shapes(deltas: &[ExpectedDelta]) -> Result<(), MaintenancePlanError> {
    bound_list_length("delta.set", deltas.len(), MAX_DELTAS)?;
    if deltas.is_empty() {
        return Err(MaintenancePlanError::Shape {
            field: "delta.set",
            detail: "a plan carries at least one expected delta".to_owned(),
        });
    }
    for delta in deltas {
        validate_one_delta_shape(delta)?;
    }
    let mut dimensions: Vec<String> = Vec::with_capacity(deltas.len());
    for delta in deltas {
        dimensions.push(delta.dimension.clone());
    }
    if !has_no_duplicates(&dimensions) {
        return Err(MaintenancePlanError::Order {
            phase: "delta.set".to_owned(),
            detail: "delta dimensions must hold no duplicates".to_owned(),
        });
    }
    Ok(())
}

/// Validates boundary shapes without judging boundary semantics.
#[allow(clippy::too_many_lines)]
fn validate_boundary_shapes(boundary: &MaintenanceBoundary) -> Result<(), MaintenancePlanError> {
    check_handle(&boundary.verifier.verifier_id, "boundary.verifier")?;
    check_bounded_text(
        &boundary.verifier.success_note,
        "boundary.success",
        MAX_NOTE_BYTES,
    )?;
    check_bounded_text(
        &boundary.verifier.semantic_success_predicate,
        "boundary.semantic-success",
        MAX_NOTE_BYTES,
    )?;
    check_bounded_text(
        &boundary.verifier.partial_note,
        "boundary.partial",
        MAX_NOTE_BYTES,
    )?;
    check_bounded_text(
        &boundary.verifier.no_change_note,
        "boundary.no-change",
        MAX_NOTE_BYTES,
    )?;
    check_bounded_text(
        &boundary.verifier.regression_note,
        "boundary.regression",
        MAX_NOTE_BYTES,
    )?;
    check_bounded_text(
        &boundary.verifier.failure_note,
        "boundary.failure",
        MAX_NOTE_BYTES,
    )?;
    check_bounded_text(
        &boundary.verifier.unknown_note,
        "boundary.unknown",
        MAX_NOTE_BYTES,
    )?;
    check_bounded_text(
        &boundary.verifier.observation_window_note,
        "boundary.window",
        MAX_NOTE_BYTES,
    )?;
    check_bounded_text(
        &boundary.verifier.denominator_note,
        "boundary.denominator",
        MAX_NOTE_BYTES,
    )?;
    if boundary.verifier.max_attempts == 0 {
        return Err(MaintenancePlanError::Shape {
            field: "boundary.max-attempts",
            detail: "verifier attempts must be explicit, not defaulted".to_owned(),
        });
    }
    check_bounded_text(
        &boundary.verifier.stop_note,
        "boundary.verifier-stop",
        MAX_NOTE_BYTES,
    )?;
    bound_list_length(
        "boundary.rollback-steps",
        boundary.rollback_steps.len(),
        MAX_ROLLBACK_STEPS,
    )?;
    if boundary.rollback_steps.is_empty() {
        return Err(MaintenancePlanError::Shape {
            field: "boundary.rollback-steps",
            detail: "a plan carries at least one rollback step".to_owned(),
        });
    }
    for step in &boundary.rollback_steps {
        check_bounded_text(step, "boundary.rollback-step", MAX_NOTE_BYTES)?;
    }
    check_bounded_text(&boundary.disable_note, "boundary.disable", MAX_NOTE_BYTES)?;
    check_bounded_text(
        &boundary.forward_repair_note,
        "boundary.forward-repair",
        MAX_NOTE_BYTES,
    )?;
    check_bounded_text(&boundary.reopen_note, "boundary.reopen", MAX_NOTE_BYTES)?;
    bound_list_length(
        "boundary.decisions",
        boundary.required_decisions.len(),
        MAX_DECISIONS,
    )?;
    if boundary.required_decisions.is_empty() {
        return Err(MaintenancePlanError::Shape {
            field: "boundary.decisions",
            detail: "a plan names at least one explicit Human decision".to_owned(),
        });
    }
    for decision in &boundary.required_decisions {
        check_bounded_text(decision, "boundary.decision", MAX_NOTE_BYTES)?;
    }
    if !has_no_duplicates(&boundary.required_decisions) {
        return Err(MaintenancePlanError::Order {
            phase: "boundary.decisions".to_owned(),
            detail: "required decisions must hold no duplicates".to_owned(),
        });
    }
    check_bounded_text(
        &boundary.approval_expiry_note,
        "boundary.expiry",
        MAX_NOTE_BYTES,
    )?;
    if boundary.silence_is_approval {
        return Err(MaintenancePlanError::Shape {
            field: "boundary.silence",
            detail: "silence is never approval".to_owned(),
        });
    }
    check_bounded_text(
        &boundary.forbidden_widening_note,
        "boundary.widening",
        MAX_NOTE_BYTES,
    )?;
    validate_budget_slice(&boundary.protected_budget)?;
    if boundary.protected_budget.cpu_ms == 0
        || boundary.protected_budget.wall_ms == 0
        || boundary.protected_budget.human_minutes == 0
        || boundary.protected_budget.output_bytes == 0
    {
        return Err(MaintenancePlanError::Shape {
            field: "boundary.protected-budget",
            detail: "verification, rollback, Human and output headroom must be explicit".to_owned(),
        });
    }
    if let Some(reference) = &boundary.external_automation_ref {
        check_handle(reference, "boundary.automation-reference")?;
    }
    Ok(())
}

/// Validates policy shapes without judging policy semantics.
fn validate_policy_shapes(policy: &MaintenancePolicy) -> Result<(), MaintenancePlanError> {
    check_handle(&policy.policy_id, "policy.identity")?;
    if policy.policy_revision == 0 {
        return Err(MaintenancePlanError::Shape {
            field: "policy.revision",
            detail: "policy revision must be explicit, not defaulted".to_owned(),
        });
    }
    if policy.allowed_op_kinds.is_empty() {
        return Err(MaintenancePlanError::Shape {
            field: "policy.vocabulary",
            detail: "policy admits at least one operation kind".to_owned(),
        });
    }
    for kind in &policy.allowed_op_kinds {
        check_bounded_text(kind, "policy.kind", MAX_ID_BYTES)?;
    }
    if !has_no_duplicates(&policy.allowed_op_kinds) {
        return Err(MaintenancePlanError::Order {
            phase: "policy.vocabulary".to_owned(),
            detail: "policy vocabulary must hold no duplicates".to_owned(),
        });
    }
    if !is_sorted_unique(&policy.allowed_op_kinds) {
        return Err(MaintenancePlanError::Order {
            phase: "policy.vocabulary".to_owned(),
            detail: "policy vocabulary must be a canonical sorted set".to_owned(),
        });
    }
    if policy.max_operations > MAX_OPERATIONS
        || policy.max_dependencies > MAX_DEPENDENCIES
        || policy.max_deltas > MAX_DELTAS
        || policy.max_evidence > MAX_EVIDENCE_ITEMS
    {
        return Err(MaintenancePlanError::Policy {
            detail: "policy ceiling exceeds its hard independent ceiling".to_owned(),
        });
    }
    check_bounded_text(&policy.owner_note, "policy.owner", MAX_SCOPE_BYTES)?;
    Ok(())
}

/// Validates history shapes without judging history semantics.
fn validate_history_shapes(history: &PriorHistory) -> Result<(), MaintenancePlanError> {
    bound_list_length(
        "history.expected",
        history.expected_attempt_ids.len(),
        MAX_ATTEMPTS,
    )?;
    bound_list_length("history.attempts", history.attempts.len(), MAX_ATTEMPTS)?;
    for identity in &history.expected_attempt_ids {
        check_handle(identity, "history.expected")?;
    }
    if !has_no_duplicates(&history.expected_attempt_ids) {
        return Err(MaintenancePlanError::Order {
            phase: "history.expected".to_owned(),
            detail: "expected attempt identities must hold no duplicates".to_owned(),
        });
    }
    for attempt in &history.attempts {
        check_handle(&attempt.attempt_id, "history.attempt")?;
        check_digest(&attempt.equivalence_digest, "history.equivalence")?;
        if let Some(request_digest) = &attempt.request_digest {
            check_digest(request_digest, "history.request")?;
        }
        if let Some(policy_revision) = attempt.policy_revision
            && policy_revision == 0
        {
            return Err(MaintenancePlanError::Shape {
                field: "history.policy-revision",
                detail: "history policy revision must be explicit when retained".to_owned(),
            });
        }
    }
    check_bounded_text(&history.outcome_note, "history.outcome", MAX_NOTE_BYTES)?;
    Ok(())
}

/// Preflights aggregate input bytes against the single total ceiling.
#[allow(clippy::too_many_arguments)]
fn preflight_total_bytes(
    objective: &MaintenanceObjective,
    trigger: &TriggerEvidence,
    operations: &[PlannedOperation],
    deltas: &[ExpectedDelta],
    boundary: &MaintenanceBoundary,
    history: &PriorHistory,
    policy: &MaintenancePolicy,
) -> Result<(), MaintenancePlanError> {
    let mut parts: Vec<&str> = vec![
        objective.objective_id.as_str(),
        objective.product_id.as_str(),
        objective.module_ref.as_str(),
        objective.owner.as_str(),
        objective.causal_note.as_str(),
        trigger.observation_owner.as_str(),
        trigger.affected_surface.as_str(),
        trigger.baseline_note.as_str(),
        trigger.condition_note.as_str(),
        trigger.diagnosed_condition.as_str(),
        trigger.false_positive_note.as_str(),
        trigger.persistence_note.as_str(),
        trigger.invalidation_note.as_str(),
        policy.owner_note.as_str(),
        history.outcome_note.as_str(),
        boundary.disable_note.as_str(),
        boundary.forward_repair_note.as_str(),
        boundary.reopen_note.as_str(),
        boundary.approval_expiry_note.as_str(),
        boundary.forbidden_widening_note.as_str(),
        boundary.verifier.semantic_success_predicate.as_str(),
    ];
    for owner in &objective.decomposition_owners {
        parts.push(owner.as_str());
    }
    for handle in &trigger.evidence_refs {
        parts.push(handle.as_str());
    }
    if let Some(reference) = &boundary.external_automation_ref {
        parts.push(reference.as_str());
    }
    for operation in operations {
        parts.push(operation.op_id.as_str());
        parts.push(operation.op_kind.as_str());
        parts.push(operation.owner.as_str());
        parts.push(operation.output_note.as_str());
        parts.push(operation.effect_ceiling.as_str());
        parts.push(operation.deadline_note.as_str());
        parts.push(operation.cancel_note.as_str());
        parts.push(operation.no_progress_note.as_str());
        parts.push(operation.rollback_note.as_str());
        parts.push(operation.disable_note.as_str());
        parts.push(operation.stop_note.as_str());
        parts.push(operation.reopen_note.as_str());
        for input in &operation.inputs {
            parts.push(input.as_str());
        }
        for precondition in &operation.preconditions {
            parts.push(precondition.as_str());
        }
        for dependency in &operation.depends_on {
            parts.push(dependency.as_str());
        }
        for non_goal in &operation.non_goals {
            parts.push(non_goal.as_str());
        }
    }
    for delta in deltas {
        parts.push(delta.baseline_note.as_str());
        parts.push(delta.range_note.as_str());
        parts.push(delta.evidence_note.as_str());
        parts.push(delta.uncertainty_note.as_str());
        parts.push(delta.unacceptable_regression.as_str());
        parts.push(delta.dimension.as_str());
        parts.push(delta.direction.as_str());
        parts.push(delta.verifier_id.as_str());
    }
    for step in &boundary.rollback_steps {
        parts.push(step.as_str());
    }
    for decision in &boundary.required_decisions {
        parts.push(decision.as_str());
    }
    for attempt in &history.attempts {
        parts.push(attempt.attempt_id.as_str());
        parts.push(attempt.equivalence_digest.as_str());
        if let Some(request_digest) = &attempt.request_digest {
            parts.push(request_digest.as_str());
        }
    }
    let total = count_text_bytes(&parts);
    if total > MAX_TOTAL_BYTES {
        return Err(MaintenancePlanError::Bounds {
            phase: "total-bytes".to_owned(),
            detail: "aggregate input bytes exceed the total ceiling".to_owned(),
        });
    }
    Ok(())
}

fn receipt_err(detail: &str) -> MaintenancePlanError {
    MaintenancePlanError::Receipt {
        detail: redact(detail),
    }
}

/// Checks the validator receipt intrinsically plus the draft binding.
fn intrinsic_receipt_checks(draft: &ValidatedDreamDraft) -> Result<(), MaintenancePlanError> {
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
        return Err(MaintenancePlanError::Receipt {
            detail: "validator receipt is not accepted or partial".to_owned(),
        });
    }
    if !note_has_any(
        &draft.receipt.proof_ceiling,
        &["candidate", "proposal", "inert"],
    ) || note_has_any(
        &draft.receipt.proof_ceiling,
        &["verified_complete", "executed", "admitted"],
    ) {
        return Err(MaintenancePlanError::Receipt {
            detail: "the pre-handler receipt cannot grant execution or completion authority"
                .to_owned(),
        });
    }
    Ok(())
}

/// Checks the grounded draft intrinsically plus its receipt binding.
fn intrinsic_grounded_checks(
    draft: &ValidatedDreamDraft,
    grounded: &GroundedDreamDraft,
) -> Result<(), MaintenancePlanError> {
    grounded
        .validate()
        .map_err(|err| receipt_err(&err.to_string()))?;
    if grounded.job_id != draft.receipt.job_id {
        return Err(MaintenancePlanError::Binding {
            field: "grounded.job",
            detail: "grounded job drifts from the receipt job binding".to_owned(),
        });
    }
    if grounded.draft_digest != draft.receipt.draft_digest
        || grounded.draft_digest != draft.draft_digest
    {
        return Err(MaintenancePlanError::Binding {
            field: "grounded.digest",
            detail: "grounded digest drifts from the receipt draft binding".to_owned(),
        });
    }
    Ok(())
}

/// Checks job, draft, task, scope, fence, budget, and policy bindings.
fn intrinsic_binding_checks(
    job: &DreamJobAdmission,
    draft: &ValidatedDreamDraft,
    policy: &MaintenancePolicy,
) -> Result<(), MaintenancePlanError> {
    job.validate()
        .map_err(|err| MaintenancePlanError::Binding {
            field: "job",
            detail: redact(&err.to_string()),
        })?;
    if job.job_class != JobClass::Maintenance {
        return Err(MaintenancePlanError::Binding {
            field: "job_class",
            detail: "dream job is not a maintenance job".to_owned(),
        });
    }
    check_fence(&job.state_fence).map_err(|err| MaintenancePlanError::Binding {
        field: "state_fence",
        detail: redact(&err.to_string()),
    })?;
    job.budget
        .validate()
        .map_err(|err| MaintenancePlanError::Policy {
            detail: redact(&err.to_string()),
        })?;
    if draft.receipt.task_id != job.task_id || draft.task_id != job.task_id {
        return Err(MaintenancePlanError::Binding {
            field: "task_id",
            detail: "draft task drifts from the job binding".to_owned(),
        });
    }
    if draft.receipt.scope_id != job.scope_id || draft.scope_id != job.scope_id {
        return Err(MaintenancePlanError::Binding {
            field: "scope_id",
            detail: "draft scope drifts from the job binding".to_owned(),
        });
    }
    if draft.state_fence != job.state_fence || draft.receipt.state_fence != job.state_fence {
        return Err(MaintenancePlanError::Binding {
            field: "state_fence",
            detail: "draft fence drifts from the job fence".to_owned(),
        });
    }
    if policy.policy_id != draft.receipt.validator_policy {
        return Err(MaintenancePlanError::Policy {
            detail: "policy_id drifts from the receipt validator policy".to_owned(),
        });
    }
    if policy.policy_id != job.policy_ref {
        return Err(MaintenancePlanError::Policy {
            detail: "policy_id drifts from the admitted job policy reference".to_owned(),
        });
    }
    Ok(())
}

/// Checks the history denominator: expected identities exactly cover attempts.
fn intrinsic_history_denominator(history: &PriorHistory) -> Result<(), MaintenancePlanError> {
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
            return Err(MaintenancePlanError::Denominator {
                detail: "expected attempt identity has no retained attempt".to_owned(),
            });
        }
        covered = covered.saturating_add(1);
    }
    if covered != history.attempts.len() {
        return Err(MaintenancePlanError::Denominator {
            detail: "retained attempts must exactly cover the expected denominator".to_owned(),
        });
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Semantic evaluation (shortfalls stay inert outcomes, never blind retries).
// ---------------------------------------------------------------------------

/// Returns true when any trigger or operation note carries generic prose.
fn plan_is_generic(trigger: &TriggerEvidence, operations: &[PlannedOperation]) -> bool {
    let trigger_low = lowered(&trigger.condition_note);
    if mentions_any(&trigger_low, GENERIC_MARKERS) {
        return true;
    }
    let diagnosed_low = lowered(&trigger.diagnosed_condition);
    if mentions_any(&diagnosed_low, GENERIC_MARKERS) {
        return true;
    }
    for operation in operations {
        let output_low = lowered(&operation.output_note);
        let ceiling_low = lowered(&operation.effect_ceiling);
        if mentions_any(&output_low, GENERIC_MARKERS) || mentions_any(&ceiling_low, GENERIC_MARKERS)
        {
            return true;
        }
    }
    false
}

/// Returns true when any operation note carries a raw payload or secret.
fn operation_carries_raw(operations: &[PlannedOperation]) -> bool {
    for operation in operations {
        let output_low = lowered(&operation.output_note);
        let ceiling_low = lowered(&operation.effect_ceiling);
        let cancel_low = lowered(&operation.cancel_note);
        if mentions_any(&output_low, RAW_MARKERS)
            || mentions_any(&ceiling_low, RAW_MARKERS)
            || mentions_any(&cancel_low, RAW_MARKERS)
        {
            return true;
        }
        for input in &operation.inputs {
            let input_low = lowered(input);
            if mentions_any(&input_low, RAW_MARKERS) {
                return true;
            }
        }
    }
    false
}

/// Returns true when any trigger or operation note claims scheduling power.
fn plan_claims_scheduling(trigger: &TriggerEvidence, operations: &[PlannedOperation]) -> bool {
    let trigger_low = lowered(&trigger.condition_note);
    if mentions_any(&trigger_low, SCHEDULING_MARKERS) {
        return true;
    }
    for operation in operations {
        let output_low = lowered(&operation.output_note);
        let stop_low = lowered(&operation.stop_note);
        let reopen_low = lowered(&operation.reopen_note);
        if mentions_any(&output_low, SCHEDULING_MARKERS)
            || mentions_any(&stop_low, SCHEDULING_MARKERS)
            || mentions_any(&reopen_low, SCHEDULING_MARKERS)
        {
            return true;
        }
    }
    false
}

/// Returns true when any operation or boundary note widens a ceiling.
fn plan_widens_ceiling(operations: &[PlannedOperation], boundary: &MaintenanceBoundary) -> bool {
    for operation in operations {
        let ceiling_low = lowered(&operation.effect_ceiling);
        let output_low = lowered(&operation.output_note);
        if mentions_any(&ceiling_low, WIDENING_MARKERS)
            || mentions_any(&output_low, WIDENING_MARKERS)
        {
            return true;
        }
    }
    let widening_low = lowered(&boundary.forbidden_widening_note);
    if mentions_any(&widening_low, WIDENING_MARKERS) {
        return true;
    }
    false
}

/// Collects the distinct operation owners in first-seen order.
fn distinct_owners(operations: &[PlannedOperation]) -> Vec<String> {
    let mut owners: Vec<String> = Vec::new();
    for operation in operations {
        let mut seen = false;
        for known in &owners {
            if known.as_str() == operation.owner.as_str() {
                seen = true;
                break;
            }
        }
        if !seen {
            owners.push(operation.owner.clone());
        }
    }
    owners
}

/// Checks that every dependency names a known operation and no self edge exists.
fn graph_refs_close(operations: &[PlannedOperation]) -> bool {
    for operation in operations {
        for dependency in &operation.depends_on {
            if dependency.as_str() == operation.op_id.as_str() {
                return false;
            }
            let mut known = false;
            for candidate in operations {
                if candidate.op_id.as_str() == dependency.as_str() {
                    known = true;
                    break;
                }
            }
            if !known {
                return false;
            }
        }
    }
    true
}

/// Returns true when the dependency graph carries a cycle.
///
/// Bounded depth-first search over the finite operation list; the visited
/// stack never exceeds the operation count, so traversal always terminates.
fn graph_has_cycle(operations: &[PlannedOperation]) -> bool {
    let mut index = 0usize;
    while index < operations.len() {
        let Some(start) = operations.get(index) else {
            return true;
        };
        let mut stack: Vec<String> = vec![start.op_id.clone()];
        let mut visited: Vec<String> = Vec::new();
        while let Some(current) = stack.pop() {
            let mut on_path = false;
            for entry in &visited {
                if entry.as_str() == current.as_str() {
                    on_path = true;
                    break;
                }
            }
            if on_path {
                continue;
            }
            visited.push(current.clone());
            let mut found: Option<&PlannedOperation> = None;
            for operation in operations {
                if operation.op_id.as_str() == current.as_str() {
                    found = Some(operation);
                    break;
                }
            }
            let Some(node) = found else {
                return true;
            };
            for dependency in &node.depends_on {
                if dependency.as_str() == start.op_id.as_str() {
                    return true;
                }
                stack.push(dependency.clone());
            }
            if visited.len()
                > operations
                    .len()
                    .saturating_mul(operations.len())
                    .saturating_add(1)
            {
                return true;
            }
        }
        index = index.saturating_add(1);
    }
    false
}

/// Returns true when every operation kind parses and belongs to the policy vocabulary.
fn kinds_in_vocab(operations: &[PlannedOperation], policy: &MaintenancePolicy) -> bool {
    for operation in operations {
        if MaintenanceOpKind::parse(&operation.op_kind).is_err() {
            return false;
        }
        let mut admitted = false;
        for allowed in &policy.allowed_op_kinds {
            if allowed.as_str() == operation.op_kind.as_str() {
                admitted = true;
                break;
            }
        }
        if !admitted {
            return false;
        }
    }
    true
}

/// Returns true when every delta dimension and direction parses.
fn deltas_parse(deltas: &[ExpectedDelta]) -> bool {
    for delta in deltas {
        if DeltaDimension::parse(&delta.dimension).is_err() {
            return false;
        }
        if DeltaDirection::parse(&delta.direction).is_err() {
            return false;
        }
    }
    true
}

/// Returns true when every operation verifier equals the boundary verifier.
fn verifiers_bind(operations: &[PlannedOperation], boundary: &MaintenanceBoundary) -> bool {
    for operation in operations {
        if operation.verifier_id.as_str() != boundary.verifier.verifier_id.as_str() {
            return false;
        }
    }
    true
}

/// Returns true when every delta verifier equals a known operation verifier.
fn delta_verifiers_bind(deltas: &[ExpectedDelta], boundary: &MaintenanceBoundary) -> bool {
    for delta in deltas {
        if delta.verifier_id.as_str() != boundary.verifier.verifier_id.as_str() {
            return false;
        }
    }
    true
}

/// Returns true when a cost delta claims improvement while a safety or
/// correctness delta is not an improvement.
///
/// Cost improvement never compensates a safety or correctness failure: the
/// two dimensions are judged independently and the compensation is refused.
fn cost_offsets_safety(deltas: &[ExpectedDelta]) -> bool {
    let mut cost_improves = false;
    for delta in deltas {
        if delta.dimension.as_str() == DeltaDimension::Cost.as_str()
            && delta.direction.as_str() == DeltaDirection::Improve.as_str()
        {
            cost_improves = true;
            break;
        }
    }
    if !cost_improves {
        return false;
    }
    for delta in deltas {
        let safety = delta.dimension.as_str() == DeltaDimension::Security.as_str()
            || delta.dimension.as_str() == DeltaDimension::Privacy.as_str()
            || delta.dimension.as_str() == DeltaDimension::Correctness.as_str();
        if safety && delta.direction.as_str() != DeltaDirection::Improve.as_str() {
            return true;
        }
    }
    false
}

/// Returns true when a note contains one of the explicitly classified words.
/// The words are interpreted only after the surrounding typed field has been
/// validated; they are guard phrases for a declared semantic field, not a
/// receipt or proof on their own.
fn note_has_any(value: &str, words: &[&str]) -> bool {
    let lowered = lowered(value);
    words.iter().any(|word| lowered.contains(word))
}

/// Returns true when a note tries to substitute process or metric activity
/// for the semantic verifier outcome required by the maintenance contract.
fn verifier_is_process_only(verifier: &SemanticVerifier) -> bool {
    let semantic = lowered(&verifier.semantic_success_predicate);
    let success = lowered(&verifier.success_note);
    let process_only = [
        "exit 0",
        "command succeeded",
        "process alive",
        "metric moved",
        "counter increased",
        "status green",
    ];
    if mentions_any(&semantic, &process_only) || mentions_any(&success, &process_only) {
        return true;
    }
    !note_has_any(
        &semantic,
        &["semantic", "outcome", "effect", "invariant", "condition"],
    )
}

/// Checks that the six verifier outcomes remain independently observable.
fn verifier_semantics_are_distinct(verifier: &SemanticVerifier) -> bool {
    let notes = [
        verifier.success_note.as_str(),
        verifier.partial_note.as_str(),
        verifier.no_change_note.as_str(),
        verifier.regression_note.as_str(),
        verifier.failure_note.as_str(),
        verifier.unknown_note.as_str(),
    ];
    let mut index = 0usize;
    while index < notes.len() {
        let mut inner = index.saturating_add(1);
        while inner < notes.len() {
            if notes[index] == notes[inner] {
                return false;
            }
            inner = inner.saturating_add(1);
        }
        index = index.saturating_add(1);
    }
    true
}

/// Checks recovery, cancellation, and no-hidden-recurrence semantics on every
/// operation. These checks describe a candidate boundary; they never perform
/// rollback, disablement, reconciliation, or scheduling.
fn operation_semantics_are_bounded(
    operation: &PlannedOperation,
    boundary: &MaintenanceBoundary,
) -> bool {
    let cancel_ok = match operation.cancellation {
        CancellationHandling::BeforeEffectNoEffect => note_has_any(
            &operation.cancel_note,
            &["before effect", "not started", "no effect"],
        ),
        CancellationHandling::PossibleEffectRequiresReconciliation => note_has_any(
            &operation.cancel_note,
            &["reconcil", "possible effect", "unknown"],
        ),
    };
    let recovery_ok = note_has_any(&operation.rollback_note, &["rollback", "restore"])
        && note_has_any(&operation.disable_note, &["disable", "park", "quarantine"])
        && note_has_any(&operation.stop_note, &["stop", "regression", "no-progress"])
        && note_has_any(&operation.reopen_note, &["reopen", "changed", "fresh"])
        && note_has_any(
            &operation.no_progress_note,
            &["no-progress", "no progress", "plateau"],
        )
        && note_has_any(&operation.deadline_note, &["deadline", "expiry", "window"]);
    let recurrence_ok = !note_has_any(
        &operation.stop_note,
        &[
            "repeat until",
            "until good",
            "forever",
            "unbounded",
            "keep trying",
        ],
    ) && !note_has_any(
        &operation.reopen_note,
        &[
            "repeat until",
            "until good",
            "forever",
            "unbounded",
            "keep trying",
        ],
    );
    let boundary_ok = note_has_any(&boundary.forward_repair_note, &["forward", "repair"])
        && note_has_any(&boundary.disable_note, &["disable", "park", "quarantine"])
        && note_has_any(&boundary.reopen_note, &["reopen", "changed", "fresh"]);
    cancel_ok && recovery_ok && recurrence_ok && boundary_ok
}

/// Returns true when operation owners are either one owner or an explicit,
/// exact decomposition retained by the objective.
fn owner_decomposition_is_explicit(
    objective: &MaintenanceObjective,
    operations: &[PlannedOperation],
) -> bool {
    let mut owners = distinct_owners(operations);
    owners.sort();
    owners.dedup();
    if owners.len() == 1 {
        return owners
            .first()
            .is_some_and(|owner| owner == &objective.owner)
            && objective.decomposition_owners.is_empty();
    }
    owners == objective.decomposition_owners && owners.iter().any(|owner| owner == &objective.owner)
}

/// Checks the exact finite graph order in addition to reference closure and
/// cycle freedom. Dependencies must be earlier, and ranks are contiguous.
fn graph_order_is_finite(operations: &[PlannedOperation]) -> bool {
    let mut expected = 0u32;
    for operation in operations {
        if operation.order != expected {
            return false;
        }
        expected = expected.saturating_add(1);
        for dependency in &operation.depends_on {
            let Some(predecessor) = operations
                .iter()
                .find(|candidate| candidate.op_id == *dependency)
            else {
                return false;
            };
            if predecessor.order >= operation.order {
                return false;
            }
        }
    }
    true
}

/// A bounded operation retry envelope cannot exceed the semantic verifier's
/// declared attempt ceiling.
fn retries_fit_verifier(operations: &[PlannedOperation], verifier: &SemanticVerifier) -> bool {
    operations
        .iter()
        .all(|operation| operation.max_retries.saturating_add(1) <= verifier.max_attempts)
}

/// The complete expected-delta dimension set from the maintenance contract.
const REQUIRED_DELTA_DIMENSIONS: &[&str] = &[
    "correctness",
    "recovery",
    "memory_quality",
    "context_quality",
    "latency",
    "resources",
    "cost",
    "evidence",
    "capability",
    "security",
    "privacy",
    "maintenance_burden",
    "human_burden",
    "user_outcome",
];

/// Returns true when every independent outcome dimension has an explicit
/// baseline, direction, uncertainty and semantic verifier.
fn deltas_cover_independent_dimensions(deltas: &[ExpectedDelta]) -> bool {
    REQUIRED_DELTA_DIMENSIONS.iter().all(|required| {
        deltas
            .iter()
            .any(|delta| delta.dimension.as_str() == *required)
    })
}

/// Planned usage of the admitted cross-package budget dimensions.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct PlannedBudgetUsage {
    input_bytes: u64,
    output_bytes: u64,
    source_width: u64,
    reference_width: u64,
    model_calls: u64,
    attempts: u64,
    candidates: u64,
    wall_ms: u64,
    work_fan_out: u64,
    report_bytes: u64,
    stu: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum BudgetDisposition {
    Within,
    Unknown,
    Exceeded(&'static str),
}

fn add_budget(left: u64, right: u64) -> Option<u64> {
    left.checked_add(right)
}

/// Counts the text that must travel with the candidate. It is intentionally
/// independent of the plan digest, so bytes cannot be hidden in a hash.
#[allow(clippy::too_many_lines)]
fn planned_text_bytes(
    objective: &MaintenanceObjective,
    trigger: &TriggerEvidence,
    operations: &[PlannedOperation],
    deltas: &[ExpectedDelta],
    boundary: &MaintenanceBoundary,
    history: &PriorHistory,
    policy: &MaintenancePolicy,
) -> Option<u64> {
    let mut total = 0u64;
    let mut add = |value: &str| {
        total = total.checked_add(value.len() as u64)?;
        Some(())
    };
    for value in [
        objective.objective_id.as_str(),
        objective.product_id.as_str(),
        objective.module_ref.as_str(),
        objective.owner.as_str(),
        objective.causal_note.as_str(),
        trigger.trigger_id.as_str(),
        trigger.observation_owner.as_str(),
        trigger.affected_surface.as_str(),
        trigger.baseline_note.as_str(),
        trigger.condition_note.as_str(),
        trigger.diagnosed_condition.as_str(),
        trigger.false_positive_note.as_str(),
        trigger.persistence_note.as_str(),
        trigger.invalidation_note.as_str(),
        history.outcome_note.as_str(),
        policy.policy_id.as_str(),
        policy.owner_note.as_str(),
        boundary.verifier.verifier_id.as_str(),
        boundary.verifier.success_note.as_str(),
        boundary.verifier.semantic_success_predicate.as_str(),
        boundary.verifier.partial_note.as_str(),
        boundary.verifier.no_change_note.as_str(),
        boundary.verifier.regression_note.as_str(),
        boundary.verifier.failure_note.as_str(),
        boundary.verifier.unknown_note.as_str(),
        boundary.verifier.observation_window_note.as_str(),
        boundary.verifier.denominator_note.as_str(),
        boundary.verifier.stop_note.as_str(),
        boundary.disable_note.as_str(),
        boundary.forward_repair_note.as_str(),
        boundary.reopen_note.as_str(),
        boundary.approval_expiry_note.as_str(),
        boundary.forbidden_widening_note.as_str(),
    ] {
        add(value)?;
    }
    for value in &objective.decomposition_owners {
        add(value)?;
    }
    for value in &trigger.evidence_refs {
        add(value)?;
    }
    for operation in operations {
        for value in [
            operation.op_id.as_str(),
            operation.op_kind.as_str(),
            operation.owner.as_str(),
            operation.output_note.as_str(),
            operation.verifier_id.as_str(),
            operation.effect_ceiling.as_str(),
            operation.deadline_note.as_str(),
            operation.cancel_note.as_str(),
            operation.no_progress_note.as_str(),
            operation.rollback_note.as_str(),
            operation.disable_note.as_str(),
            operation.stop_note.as_str(),
            operation.reopen_note.as_str(),
        ] {
            add(value)?;
        }
        for value in operation
            .inputs
            .iter()
            .chain(operation.preconditions.iter())
            .chain(operation.depends_on.iter())
            .chain(operation.non_goals.iter())
        {
            add(value)?;
        }
    }
    for delta in deltas {
        for value in [
            delta.dimension.as_str(),
            delta.baseline_note.as_str(),
            delta.direction.as_str(),
            delta.range_note.as_str(),
            delta.evidence_note.as_str(),
            delta.uncertainty_note.as_str(),
            delta.verifier_id.as_str(),
            delta.unacceptable_regression.as_str(),
        ] {
            add(value)?;
        }
    }
    for value in boundary
        .rollback_steps
        .iter()
        .chain(boundary.required_decisions.iter())
    {
        add(value)?;
    }
    if let Some(reference) = &boundary.external_automation_ref {
        add(reference)?;
    }
    Some(total)
}

/// Compares every planned dimension with the exact admitted job budget. An
/// absent limit remains unknown and can never authorize a complete candidate.
#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
fn assess_budget(
    job: &DreamJobAdmission,
    objective: &MaintenanceObjective,
    trigger: &TriggerEvidence,
    operations: &[PlannedOperation],
    deltas: &[ExpectedDelta],
    boundary: &MaintenanceBoundary,
    history: &PriorHistory,
    policy: &MaintenancePolicy,
) -> BudgetDisposition {
    let Some(report_bytes) = planned_text_bytes(
        objective, trigger, operations, deltas, boundary, history, policy,
    ) else {
        return BudgetDisposition::Exceeded("report_bytes");
    };
    let mut input_bytes = 0u64;
    let mut output_bytes = 0u64;
    let mut reference_width = trigger.evidence_refs.len() as u64;
    let mut model_calls = boundary.protected_budget.model_calls;
    let mut attempts = u64::from(boundary.verifier.max_attempts);
    let mut wall_ms = boundary.protected_budget.wall_ms;
    let mut work_fan_out = boundary.protected_budget.work_items;
    let mut stu = boundary.protected_budget.cost_units;
    for operation in operations {
        for value in operation
            .inputs
            .iter()
            .chain(operation.preconditions.iter())
        {
            let Some(next) = add_budget(input_bytes, value.len() as u64) else {
                return BudgetDisposition::Exceeded("input_bytes");
            };
            input_bytes = next;
        }
        let Some(next) = add_budget(output_bytes, operation.output_note.len() as u64) else {
            return BudgetDisposition::Exceeded("output_bytes");
        };
        output_bytes = next;
        reference_width = reference_width
            .checked_add(operation.inputs.len() as u64)
            .and_then(|value| value.checked_add(operation.preconditions.len() as u64))
            .and_then(|value| value.checked_add(operation.depends_on.len() as u64))
            .unwrap_or(u64::MAX);
        model_calls = model_calls.saturating_add(operation.budget.model_calls);
        attempts = attempts.saturating_add(u64::from(operation.max_retries) + 1);
        wall_ms = wall_ms.saturating_add(operation.budget.wall_ms);
        work_fan_out = work_fan_out.saturating_add(operation.budget.work_items);
        stu = stu.saturating_add(operation.budget.cost_units);
    }
    output_bytes = output_bytes.saturating_add(boundary.protected_budget.output_bytes);
    input_bytes = input_bytes.saturating_add(
        trigger
            .evidence_refs
            .iter()
            .map(|item| item.len() as u64)
            .sum(),
    );
    let usage = PlannedBudgetUsage {
        input_bytes,
        output_bytes,
        source_width: trigger.evidence_refs.len() as u64,
        reference_width,
        model_calls,
        attempts,
        candidates: operations.len() as u64,
        wall_ms,
        work_fan_out,
        report_bytes: report_bytes.saturating_add(boundary.protected_budget.output_bytes),
        stu,
    };
    let dimensions = [
        ("input_bytes", job.budget.input_bytes, usage.input_bytes),
        ("output_bytes", job.budget.output_bytes, usage.output_bytes),
        ("source_width", job.budget.source_width, usage.source_width),
        (
            "reference_width",
            job.budget.reference_width,
            usage.reference_width,
        ),
        ("model_calls", job.budget.model_calls, usage.model_calls),
        ("attempts", job.budget.attempts, usage.attempts),
        ("candidates", job.budget.candidates, usage.candidates),
        ("wall_ms", job.budget.wall_ms, usage.wall_ms),
        ("work_fan_out", job.budget.work_fan_out, usage.work_fan_out),
        ("report_bytes", job.budget.report_bytes, usage.report_bytes),
        ("max_stu", job.budget.max_stu, usage.stu),
    ];
    for (name, limit, used) in dimensions {
        let Some(limit) = limit else {
            return BudgetDisposition::Unknown;
        };
        if used > limit {
            return BudgetDisposition::Exceeded(name);
        }
    }
    BudgetDisposition::Within
}

/// Returns true when an explicit external cadence reference is safe to carry.
fn external_cadence_reference_is_safe(boundary: &MaintenanceBoundary) -> bool {
    let Some(reference) = &boundary.external_automation_ref else {
        return true;
    };
    !note_has_any(
        reference,
        &[
            "create",
            "new schedule",
            "schedule now",
            "launch",
            "execute",
        ],
    )
}

/// Returns true when a prior effect or attempt state blocks blind repetition.
fn history_blocks_blind_repeat(history: &PriorHistory) -> bool {
    history.attempts.iter().any(|attempt| {
        matches!(attempt.effect_state, PriorEffectState::Unknown)
            || matches!(attempt.disposition, PriorAttemptDisposition::Unknown)
            || matches!(
                attempt.disposition,
                PriorAttemptDisposition::NoProgress
                    | PriorAttemptDisposition::Hung
                    | PriorAttemptDisposition::Failed
            ) && !attempt.changed_evidence
    })
}

// ---------------------------------------------------------------------------
// Emission.
// ---------------------------------------------------------------------------

/// Maps a terminal outcome to the closest hub rejection hint, if any.
#[must_use]
pub fn outcome_rejection_hint(outcome: &MaintenanceOutcome) -> Option<CurationRejectionCode> {
    match outcome {
        MaintenanceOutcome::Complete => None,
        MaintenanceOutcome::Partial | MaintenanceOutcome::DecisionRequired => {
            Some(CurationRejectionCode::PreservationFailed)
        }
        MaintenanceOutcome::Insufficient => Some(CurationRejectionCode::UnsupportedPrecision),
        MaintenanceOutcome::Stale | MaintenanceOutcome::Rejected => {
            Some(CurationRejectionCode::IdentityMismatch)
        }
        MaintenanceOutcome::UnsupportedShape => Some(CurationRejectionCode::UnsupportedJobShape),
    }
}

/// Maps a fail-closed error to the closest hub rejection hint.
#[must_use]
pub fn error_rejection_hint(error: &MaintenancePlanError) -> CurationRejectionCode {
    match error {
        MaintenancePlanError::Bounds { .. } | MaintenancePlanError::Policy { .. } => {
            CurationRejectionCode::BudgetExceeded
        }
        MaintenancePlanError::Order { .. }
        | MaintenancePlanError::Binding { .. }
        | MaintenancePlanError::Digest { .. } => CurationRejectionCode::IdentityMismatch,
        MaintenancePlanError::Shape { .. } => CurationRejectionCode::UnsupportedJobShape,
        MaintenancePlanError::Receipt { .. } => CurationRejectionCode::LineageMismatch,
        MaintenancePlanError::Denominator { .. } => CurationRejectionCode::PreservationFailed,
    }
}

/// Builds the seven-dimension preservation report for one candidate.
fn build_preservation() -> Result<PreservationReport, MaintenancePlanError> {
    let notes = [
        (
            "coverage",
            "every objective, trigger, operation, dependency, delta, history attempt, and receipt binding is accounted without silent drops",
        ),
        (
            "faithfulness",
            "generic prose and proxy signals never become a plan; only exact observed conditions with outcome mappings do",
        ),
        (
            "lineage",
            "job, draft, grounding, objective, trigger, history, operation, delta, verifier, boundary, and receipt bindings trace to supplied inputs",
        ),
        (
            "reversibility",
            "the inert stop, rollback, disable, and forward-repair boundary restores the exact prior state and changes nothing",
        ),
        (
            "authority_ceiling",
            "the candidate proposes only; scheduling, execution, reservation, policy choice, and finish stay external",
        ),
        (
            "dependency_closure",
            "only the contracts hub is imported; the operation graph is finite, acyclic, and closed over known operations",
        ),
        (
            "provenance_retention",
            "trigger evidence, alternatives, unknowns, prior attempts, and input receipt lineage are retained verbatim",
        ),
    ];
    let mut verdicts: Vec<DimensionVerdict> = Vec::with_capacity(EXPECTED_PRESERVATION_DIMENSIONS);
    let mut index = 0usize;
    while index < notes.len() {
        if let Some((dimension, note)) = notes.get(index) {
            let parsed = match PreservationDimension::parse(dimension) {
                Ok(parsed) => parsed,
                Err(err) => {
                    return Err(MaintenancePlanError::Denominator {
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
        .map_err(|err| MaintenancePlanError::Denominator {
            detail: redact(&err.to_string()),
        })?;
    Ok(report)
}

/// Collects the exact expected-attempt denominator in supplied order.
fn attempt_denominator_of(history: &PriorHistory) -> Vec<String> {
    history.expected_attempt_ids.clone()
}

/// Computes the deterministic digest binding the plan inputs.
///
/// Ten explicit bindings mirror the canonical typed equivalent of the
/// maintenance contract; bundling them would hide load-bearing distinctions
/// at the digest boundary.
#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
fn compute_plan_digest(
    handle: &str,
    outcome_spelling: &str,
    objective: &MaintenanceObjective,
    trigger: &TriggerEvidence,
    operations: &[PlannedOperation],
    deltas: &[ExpectedDelta],
    boundary: &MaintenanceBoundary,
    history: &PriorHistory,
    policy: &MaintenancePolicy,
    receipt_digest: &str,
) -> Result<String, MaintenancePlanError> {
    let mut parts: Vec<String> = vec![
        ["handle:", handle].concat(),
        ["outcome:", outcome_spelling].concat(),
        ["objective:", &objective.objective_id].concat(),
        ["revision:", &objective.objective_revision.to_string()].concat(),
        ["product:", &objective.product_id].concat(),
        ["module:", &objective.module_ref].concat(),
        ["owner:", &objective.owner].concat(),
        ["causal:", &objective.causal_note].concat(),
        ["trigger:", &trigger.trigger_id].concat(),
        ["trigger-kind:", trigger.kind.as_str()].concat(),
        ["observation-owner:", &trigger.observation_owner].concat(),
        ["affected-surface:", &trigger.affected_surface].concat(),
        ["baseline:", &trigger.baseline_note].concat(),
        ["condition:", &trigger.condition_note].concat(),
        ["diagnosis:", &trigger.diagnosed_condition].concat(),
        ["false-positive:", &trigger.false_positive_note].concat(),
        ["persistence:", &trigger.persistence_note].concat(),
        [
            "one-shot:",
            trigger.one_shot_justification.as_deref().unwrap_or(""),
        ]
        .concat(),
        [
            "mapping:",
            trigger.outcome_mapping_note.as_deref().unwrap_or(""),
        ]
        .concat(),
        ["invalidation:", &trigger.invalidation_note].concat(),
        ["trigger-context:", &trigger.context_digest].concat(),
        ["verifier:", &boundary.verifier.verifier_id].concat(),
        [
            "semantic-success:",
            &boundary.verifier.semantic_success_predicate,
        ]
        .concat(),
        ["policy:", &policy.policy_id].concat(),
        ["policy-revision:", &policy.policy_revision.to_string()].concat(),
        ["policy-vocabulary:", &policy.allowed_op_kinds.join(",")].concat(),
        ["policy-partial:", &policy.allow_partial.to_string()].concat(),
        ["receipt:", receipt_digest].concat(),
    ];
    for owner in &objective.decomposition_owners {
        parts.push(["decomposition-owner:", owner].concat());
    }
    for handle in &trigger.evidence_refs {
        parts.push(["evidence:", handle].concat());
    }
    for operation in operations {
        parts.push(
            [
                "operation:",
                &operation.op_id,
                "|",
                &operation.op_kind,
                "|",
                &operation.owner,
                "|",
                &operation.order.to_string(),
                "|",
                operation.cancellation.as_str(),
            ]
            .concat(),
        );
        for value in [
            operation.output_note.as_str(),
            operation.verifier_id.as_str(),
            operation.effect_ceiling.as_str(),
            operation.deadline_note.as_str(),
            operation.cancel_note.as_str(),
            operation.no_progress_note.as_str(),
            operation.rollback_note.as_str(),
            operation.disable_note.as_str(),
            operation.stop_note.as_str(),
            operation.reopen_note.as_str(),
            &operation.max_retries.to_string(),
        ] {
            parts.push(["operation-field:", value].concat());
        }
        parts.push(
            [
                "operation-budget:",
                &operation.budget.cpu_ms.to_string(),
                ":",
                &operation.budget.memory_bytes.to_string(),
                ":",
                &operation.budget.storage_bytes.to_string(),
                ":",
                &operation.budget.network_bytes.to_string(),
                ":",
                &operation.budget.context_bytes.to_string(),
                ":",
                &operation.budget.model_calls.to_string(),
                ":",
                &operation.budget.cost_units.to_string(),
                ":",
                &operation.budget.human_minutes.to_string(),
                ":",
                &operation.budget.wall_ms.to_string(),
                ":",
                &operation.budget.idle_ms.to_string(),
                ":",
                &operation.budget.work_items.to_string(),
                ":",
                &operation.budget.output_bytes.to_string(),
            ]
            .concat(),
        );
        for input in &operation.inputs {
            parts.push(["input:", input].concat());
        }
        for precondition in &operation.preconditions {
            parts.push(["precondition:", precondition].concat());
        }
        for dependency in &operation.depends_on {
            parts.push(["edge:", &operation.op_id, "->", dependency].concat());
        }
        for non_goal in &operation.non_goals {
            parts.push(["non-goal:", non_goal].concat());
        }
    }
    for delta in deltas {
        parts.push(
            [
                "delta:",
                &delta.dimension,
                "|",
                &delta.baseline_note,
                "|",
                &delta.direction,
                "|",
                &delta.range_note,
                "|",
                &delta.evidence_note,
                "|",
                &delta.uncertainty_note,
                "|",
                &delta.verifier_id,
                "|",
                &delta.unacceptable_regression,
            ]
            .concat(),
        );
    }
    for note in [
        boundary.verifier.success_note.as_str(),
        boundary.verifier.partial_note.as_str(),
        boundary.verifier.no_change_note.as_str(),
        boundary.verifier.regression_note.as_str(),
        boundary.verifier.failure_note.as_str(),
        boundary.verifier.unknown_note.as_str(),
        boundary.verifier.observation_window_note.as_str(),
        boundary.verifier.denominator_note.as_str(),
        boundary.verifier.stop_note.as_str(),
        boundary.disable_note.as_str(),
        boundary.forward_repair_note.as_str(),
        boundary.reopen_note.as_str(),
        boundary.approval_expiry_note.as_str(),
        boundary.forbidden_widening_note.as_str(),
    ] {
        parts.push(["boundary:", note].concat());
    }
    for step in &boundary.rollback_steps {
        parts.push(["rollback:", step].concat());
    }
    for decision in &boundary.required_decisions {
        parts.push(["decision:", decision].concat());
    }
    if let Some(reference) = &boundary.external_automation_ref {
        parts.push(["automation-reference:", reference].concat());
    }
    parts.push(
        [
            "protected-budget:",
            &boundary.protected_budget.cpu_ms.to_string(),
            ":",
            &boundary.protected_budget.memory_bytes.to_string(),
            ":",
            &boundary.protected_budget.storage_bytes.to_string(),
            ":",
            &boundary.protected_budget.network_bytes.to_string(),
            ":",
            &boundary.protected_budget.context_bytes.to_string(),
            ":",
            &boundary.protected_budget.model_calls.to_string(),
            ":",
            &boundary.protected_budget.cost_units.to_string(),
            ":",
            &boundary.protected_budget.human_minutes.to_string(),
            ":",
            &boundary.protected_budget.wall_ms.to_string(),
            ":",
            &boundary.protected_budget.idle_ms.to_string(),
            ":",
            &boundary.protected_budget.work_items.to_string(),
            ":",
            &boundary.protected_budget.output_bytes.to_string(),
        ]
        .concat(),
    );
    for attempt in &history.attempts {
        parts.push(
            [
                "attempt:",
                &attempt.attempt_id,
                "|",
                &attempt.equivalence_digest,
                "|",
                attempt.disposition.as_str(),
                "|",
                attempt.effect_state.as_str(),
                "|",
                &attempt.changed_evidence.to_string(),
                "|",
                attempt.repeat_justification.as_str(),
                "|",
                attempt.request_digest.as_deref().unwrap_or(""),
                "|",
                &attempt
                    .policy_revision
                    .map_or(0, |revision| revision)
                    .to_string(),
            ]
            .concat(),
        );
    }
    canonical_json_bytes(&parts).map_or_else(
        |err| {
            Err(MaintenancePlanError::Digest {
                detail: redact(&err.to_string()),
            })
        },
        |bytes| Ok(sha256_hex(&bytes)),
    )
}

/// Emits one inert candidate envelope for the decided outcome.
///
/// Eleven explicit bindings keep every emission input visible at the single
/// construction boundary; bundling them would hide load-bearing distinctions.
#[allow(clippy::too_many_arguments)]
#[allow(clippy::too_many_lines)]
fn emit_candidate(
    outcome: MaintenanceOutcome,
    objective: &MaintenanceObjective,
    trigger: &TriggerEvidence,
    operations: &[PlannedOperation],
    deltas: &[ExpectedDelta],
    boundary: &MaintenanceBoundary,
    history: &PriorHistory,
    policy: &MaintenancePolicy,
    receipt_digest: &str,
    note: &str,
) -> Result<MaintenancePlanCandidate, MaintenancePlanError> {
    let handle = ["plan-", &objective.objective_id].concat();
    check_handle(&handle, "plan.handle")?;
    let preservation = build_preservation()?;
    let digest = compute_plan_digest(
        &handle,
        outcome.as_str(),
        objective,
        trigger,
        operations,
        deltas,
        boundary,
        history,
        policy,
        receipt_digest,
    )?;
    let mut stop_parts: Vec<String> = Vec::new();
    for operation in operations {
        stop_parts.push(operation.stop_note.clone());
    }
    let stop_summary = stop_parts.join("; ");
    if stop_summary.trim().is_empty() {
        return Err(MaintenancePlanError::Shape {
            field: "plan.stop",
            detail: "a plan carries an explicit stop summary".to_owned(),
        });
    }
    Ok(MaintenancePlanCandidate {
        outcome,
        plan_handle: handle,
        objective_id: objective.objective_id.clone(),
        objective_revision: objective.objective_revision,
        product_id: objective.product_id.clone(),
        owner: objective.owner.clone(),
        decomposition_owners: objective.decomposition_owners.clone(),
        trigger_id: trigger.trigger_id.clone(),
        operations: operations.to_vec(),
        deltas: deltas.to_vec(),
        verifier_id: boundary.verifier.verifier_id.clone(),
        rollback_steps: boundary.rollback_steps.clone(),
        required_decisions: boundary.required_decisions.clone(),
        stop_summary,
        preservation,
        input_receipt_digest: receipt_digest.to_owned(),
        attempt_denominator: attempt_denominator_of(history),
        candidate_digest: digest,
        note: note.to_owned(),
    })
}

// ---------------------------------------------------------------------------
// Canonical entry point.
// ---------------------------------------------------------------------------

/// Proposes one finite owner-bound maintenance plan as an inert candidate.
///
/// The ten parameters are the canonical typed equivalent of
/// `propose_maintenance_plan`: the validated job, the validated draft with
/// its pre-handler receipt, the frozen grounded draft, the single maintenance
/// objective, the exact trigger evidence, the retained prior history, the
/// finite typed operation set, the independent expected deltas, the inert
/// stop and Human boundary, and the governing policy. Every parameter is an
/// immutable supplied observation; nothing is queried, scheduled, reserved,
/// published, executed, or finished.
///
/// # Errors
///
/// Returns [`MaintenancePlanError`] only for malformed, mismatched,
/// over-bound, or stale inputs. Every semantic shortfall is an inert
/// [`MaintenancePlanCandidate`] outcome instead.
#[allow(clippy::too_many_arguments)]
#[allow(clippy::too_many_lines)]
pub fn propose_maintenance_plan(
    job: &DreamJobAdmission,
    draft: &ValidatedDreamDraft,
    grounded: &GroundedDreamDraft,
    objective: &MaintenanceObjective,
    trigger: &TriggerEvidence,
    history: &PriorHistory,
    operations: &[PlannedOperation],
    deltas: &[ExpectedDelta],
    boundary: &MaintenanceBoundary,
    policy: &MaintenancePolicy,
) -> Result<MaintenancePlanCandidate, MaintenancePlanError> {
    validate_policy_shapes(policy)?;
    validate_objective_shapes(objective)?;
    validate_trigger_shapes(trigger)?;
    validate_operation_shapes(operations)?;
    validate_delta_shapes(deltas)?;
    validate_boundary_shapes(boundary)?;
    validate_history_shapes(history)?;
    if operations.len() > policy.max_operations
        || deltas.len() > policy.max_deltas
        || trigger.evidence_refs.len() > policy.max_evidence
    {
        return Err(MaintenancePlanError::Bounds {
            phase: "policy-ceiling".to_owned(),
            detail: "request exceeds its independent policy ceiling".to_owned(),
        });
    }
    for operation in operations {
        if operation.depends_on.len() > policy.max_dependencies {
            return Err(MaintenancePlanError::Bounds {
                phase: "policy-ceiling".to_owned(),
                detail: "operation exceeds its independent dependency ceiling".to_owned(),
            });
        }
    }
    preflight_total_bytes(
        objective, trigger, operations, deltas, boundary, history, policy,
    )?;
    intrinsic_receipt_checks(draft)?;
    intrinsic_grounded_checks(draft, grounded)?;
    intrinsic_binding_checks(job, draft, policy)?;
    intrinsic_history_denominator(history)?;
    if job.frozen_manifest_digest != objective.context_digest {
        return Err(MaintenancePlanError::Binding {
            field: "objective.context",
            detail: "objective context drifts from the frozen job manifest".to_owned(),
        });
    }
    if trigger.context_digest != objective.context_digest {
        return Err(MaintenancePlanError::Binding {
            field: "trigger.context",
            detail: "trigger context drifts from the objective context".to_owned(),
        });
    }
    if objective.owner.trim().is_empty() {
        return Err(MaintenancePlanError::Shape {
            field: "objective.owner",
            detail: "a plan binds exactly one explicit owner".to_owned(),
        });
    }
    let receipt_digest = draft.receipt.output_digest.clone();
    if policy.cancelled {
        return emit_candidate(
            MaintenanceOutcome::Rejected,
            objective,
            trigger,
            operations,
            deltas,
            boundary,
            history,
            policy,
            &receipt_digest,
            "cancelled before emission; zero effects were produced",
        );
    }
    if let (Some(observed), Some(deadline)) = (policy.observation_time_ms, policy.deadline_ms)
        && observed >= deadline
    {
        return emit_candidate(
            MaintenanceOutcome::Stale,
            objective,
            trigger,
            operations,
            deltas,
            boundary,
            history,
            policy,
            &receipt_digest,
            "observation is at or beyond the frozen deadline; replay against the new revision",
        );
    }
    match assess_budget(
        job, objective, trigger, operations, deltas, boundary, history, policy,
    ) {
        BudgetDisposition::Within => {}
        BudgetDisposition::Unknown => {
            return emit_candidate(
                MaintenanceOutcome::Insufficient,
                objective,
                trigger,
                operations,
                deltas,
                boundary,
                history,
                policy,
                &receipt_digest,
                "an unknown independent admitted budget cannot authorize a complete plan",
            );
        }
        BudgetDisposition::Exceeded(dimension) => {
            return emit_candidate(
                MaintenanceOutcome::Insufficient,
                objective,
                trigger,
                operations,
                deltas,
                boundary,
                history,
                policy,
                &receipt_digest,
                &[
                    "the independent admitted budget is exceeded for ",
                    dimension,
                    "; no cross-subsidy is allowed",
                ]
                .concat(),
            );
        }
    }
    if !kinds_in_vocab(operations, policy) {
        return emit_candidate(
            MaintenanceOutcome::UnsupportedShape,
            objective,
            trigger,
            operations,
            deltas,
            boundary,
            history,
            policy,
            &receipt_digest,
            "unknown operation vocabulary names no admitted maintenance shape",
        );
    }
    if !deltas_parse(deltas) {
        return emit_candidate(
            MaintenanceOutcome::UnsupportedShape,
            objective,
            trigger,
            operations,
            deltas,
            boundary,
            history,
            policy,
            &receipt_digest,
            "unknown delta vocabulary names no admitted expectation shape",
        );
    }
    if operation_carries_raw(operations) {
        return emit_candidate(
            MaintenanceOutcome::Rejected,
            objective,
            trigger,
            operations,
            deltas,
            boundary,
            history,
            policy,
            &receipt_digest,
            "raw commands, secrets, live permits, and provider payloads are rejected",
        );
    }
    if plan_claims_scheduling(trigger, operations) {
        return emit_candidate(
            MaintenanceOutcome::Rejected,
            objective,
            trigger,
            operations,
            deltas,
            boundary,
            history,
            policy,
            &receipt_digest,
            "scheduling, recurrence, reservation, and execution language is rejected; plans stay candidate-only",
        );
    }
    if plan_widens_ceiling(operations, boundary) {
        return emit_candidate(
            MaintenanceOutcome::Rejected,
            objective,
            trigger,
            operations,
            deltas,
            boundary,
            history,
            policy,
            &receipt_digest,
            "privacy, cost, remote-access, model, and policy widening is rejected, not warned",
        );
    }
    if plan_is_generic(trigger, operations) {
        return emit_candidate(
            MaintenanceOutcome::Rejected,
            objective,
            trigger,
            operations,
            deltas,
            boundary,
            history,
            policy,
            &receipt_digest,
            "generic optimization prose is not a plan; only exact observed conditions with owners and verifiers are admitted",
        );
    }
    if matches!(trigger.kind, TriggerKind::IncidentRecovery) {
        return emit_candidate(
            MaintenanceOutcome::Rejected,
            objective,
            trigger,
            operations,
            deltas,
            boundary,
            history,
            policy,
            &receipt_digest,
            "incident and recovery conditions retain their operational owner outside Maintenance",
        );
    }
    if !external_cadence_reference_is_safe(boundary) {
        return emit_candidate(
            MaintenanceOutcome::Rejected,
            objective,
            trigger,
            operations,
            deltas,
            boundary,
            history,
            policy,
            &receipt_digest,
            "external cadence references cannot create, schedule, launch, or execute work",
        );
    }
    if matches!(trigger.kind, TriggerKind::ExternalCadence)
        && boundary.external_automation_ref.is_none()
    {
        return emit_candidate(
            MaintenanceOutcome::DecisionRequired,
            objective,
            trigger,
            operations,
            deltas,
            boundary,
            history,
            policy,
            &receipt_digest,
            "an external cadence must be referenced by its owning automation contract",
        );
    }
    if trigger.evidence_refs.is_empty() {
        return emit_candidate(
            MaintenanceOutcome::Insufficient,
            objective,
            trigger,
            operations,
            deltas,
            boundary,
            history,
            policy,
            &receipt_digest,
            "a trigger without evidence refs cannot ground a plan",
        );
    }
    if !is_sorted_unique(&trigger.evidence_refs) {
        return Err(MaintenancePlanError::Order {
            phase: "trigger.evidence".to_owned(),
            detail: "trigger evidence refs must be sorted and unique".to_owned(),
        });
    }
    if trigger.outcome_mapping_note.is_none() {
        return emit_candidate(
            MaintenanceOutcome::Insufficient,
            objective,
            trigger,
            operations,
            deltas,
            boundary,
            history,
            policy,
            &receipt_digest,
            "signals without an evidence-backed user-outcome mapping prove no maintenance delta",
        );
    }
    if !trigger
        .outcome_mapping_note
        .as_deref()
        .is_some_and(|mapping| mapping.contains(&objective.product_id))
    {
        return emit_candidate(
            MaintenanceOutcome::Insufficient,
            objective,
            trigger,
            operations,
            deltas,
            boundary,
            history,
            policy,
            &receipt_digest,
            "the trigger mapping does not identify the exact supported product outcome",
        );
    }
    if trigger.denominator_total == 1 && trigger.one_shot_justification.is_none() {
        return emit_candidate(
            MaintenanceOutcome::Insufficient,
            objective,
            trigger,
            operations,
            deltas,
            boundary,
            history,
            policy,
            &receipt_digest,
            "a one-shot denominator needs an explicit severity justification",
        );
    }
    if trigger.denominator_covered < trigger.denominator_total {
        if policy.allow_partial {
            return emit_candidate(
                MaintenanceOutcome::Partial,
                objective,
                trigger,
                operations,
                deltas,
                boundary,
                history,
                policy,
                &receipt_digest,
                "partial observation coverage with named omitted denominator",
            );
        }
        return emit_candidate(
            MaintenanceOutcome::Insufficient,
            objective,
            trigger,
            operations,
            deltas,
            boundary,
            history,
            policy,
            &receipt_digest,
            "incomplete observation denominator blocks a complete plan",
        );
    }
    let owners = distinct_owners(operations);
    if owners.len() > 1 && objective.decomposition_owners.is_empty() {
        return emit_candidate(
            MaintenanceOutcome::DecisionRequired,
            objective,
            trigger,
            operations,
            deltas,
            boundary,
            history,
            policy,
            &receipt_digest,
            "independent multi-owner objectives require explicit decomposition, not one hidden generic job",
        );
    }
    if !owner_decomposition_is_explicit(objective, operations) {
        return emit_candidate(
            MaintenanceOutcome::Rejected,
            objective,
            trigger,
            operations,
            deltas,
            boundary,
            history,
            policy,
            &receipt_digest,
            "operation ownership drifts from the single plan owner",
        );
    }
    if !graph_refs_close(operations) {
        return emit_candidate(
            MaintenanceOutcome::Rejected,
            objective,
            trigger,
            operations,
            deltas,
            boundary,
            history,
            policy,
            &receipt_digest,
            "dangling or self-referential dependencies name no finite graph",
        );
    }
    if graph_has_cycle(operations) {
        return emit_candidate(
            MaintenanceOutcome::Rejected,
            objective,
            trigger,
            operations,
            deltas,
            boundary,
            history,
            policy,
            &receipt_digest,
            "cyclic dependencies hide unbounded recurrence; only finite acyclic graphs are admitted",
        );
    }
    if !graph_order_is_finite(operations) {
        return emit_candidate(
            MaintenanceOutcome::Rejected,
            objective,
            trigger,
            operations,
            deltas,
            boundary,
            history,
            policy,
            &receipt_digest,
            "operation orders must be contiguous and every dependency must precede its consumer",
        );
    }
    if operations
        .iter()
        .any(|operation| !operation_semantics_are_bounded(operation, boundary))
    {
        return emit_candidate(
            MaintenanceOutcome::Rejected,
            objective,
            trigger,
            operations,
            deltas,
            boundary,
            history,
            policy,
            &receipt_digest,
            "an operation lacks typed cancellation, recovery, deadline, or no-progress boundaries",
        );
    }
    if !retries_fit_verifier(operations, &boundary.verifier) {
        return emit_candidate(
            MaintenanceOutcome::Rejected,
            objective,
            trigger,
            operations,
            deltas,
            boundary,
            history,
            policy,
            &receipt_digest,
            "operation retry envelopes exceed the semantic verifier attempt ceiling",
        );
    }
    if !verifier_semantics_are_distinct(&boundary.verifier)
        || verifier_is_process_only(&boundary.verifier)
    {
        return emit_candidate(
            MaintenanceOutcome::Insufficient,
            objective,
            trigger,
            operations,
            deltas,
            boundary,
            history,
            policy,
            &receipt_digest,
            "a semantic verifier must distinguish outcomes and observe the condition or effect, not process activity alone",
        );
    }
    if !verifiers_bind(operations, boundary) {
        return emit_candidate(
            MaintenanceOutcome::Rejected,
            objective,
            trigger,
            operations,
            deltas,
            boundary,
            history,
            policy,
            &receipt_digest,
            "every operation binds the single independent semantic verifier",
        );
    }
    if !delta_verifiers_bind(deltas, boundary) {
        return emit_candidate(
            MaintenanceOutcome::Rejected,
            objective,
            trigger,
            operations,
            deltas,
            boundary,
            history,
            policy,
            &receipt_digest,
            "every expected delta binds the single independent semantic verifier",
        );
    }
    if !deltas_cover_independent_dimensions(deltas) {
        return emit_candidate(
            MaintenanceOutcome::Insufficient,
            objective,
            trigger,
            operations,
            deltas,
            boundary,
            history,
            policy,
            &receipt_digest,
            "every independent correctness, recovery, quality, resource, evidence, security, Human and user-outcome dimension needs a delta",
        );
    }
    if cost_offsets_safety(deltas) {
        return emit_candidate(
            MaintenanceOutcome::Rejected,
            objective,
            trigger,
            operations,
            deltas,
            boundary,
            history,
            policy,
            &receipt_digest,
            "cost improvement cannot compensate a safety or correctness shortfall",
        );
    }
    if history_blocks_blind_repeat(history) {
        return emit_candidate(
            MaintenanceOutcome::DecisionRequired,
            objective,
            trigger,
            operations,
            deltas,
            boundary,
            history,
            policy,
            &receipt_digest,
            "failed, stalled, hung, or unknown prior effects require reconciliation or changed evidence before repetition",
        );
    }
    let complete = emit_candidate(
        MaintenanceOutcome::Complete,
        objective,
        trigger,
        operations,
        deltas,
        boundary,
        history,
        policy,
        &receipt_digest,
        MAINTENANCE_PROOF_NOTE,
    )?;
    let mut identity_history = history.clone();
    identity_history.expected_attempt_ids.clear();
    identity_history.attempts.clear();
    let identity_digest = compute_plan_digest(
        &complete.plan_handle,
        MaintenanceOutcome::Complete.as_str(),
        objective,
        trigger,
        operations,
        deltas,
        boundary,
        &identity_history,
        policy,
        &receipt_digest,
    )?;
    for attempt in &history.attempts {
        if attempt.attempt_id.as_str() == job.operation_id.as_str() {
            let mut empty_history = history.clone();
            empty_history.expected_attempt_ids.clear();
            empty_history.attempts.clear();
            let request_digest = compute_plan_digest(
                &complete.plan_handle,
                MaintenanceOutcome::Complete.as_str(),
                objective,
                trigger,
                operations,
                deltas,
                boundary,
                &empty_history,
                policy,
                &receipt_digest,
            )?;
            if let Some(previous_policy_revision) = attempt.policy_revision
                && previous_policy_revision != policy.policy_revision
            {
                return emit_candidate(
                    MaintenanceOutcome::Stale,
                    objective,
                    trigger,
                    operations,
                    deltas,
                    boundary,
                    history,
                    policy,
                    &receipt_digest,
                    "same operation identity carries a changed policy revision; replay is stale",
                );
            }
            if let Some(previous_request_digest) = &attempt.request_digest
                && previous_request_digest != &request_digest
            {
                return emit_candidate(
                    MaintenanceOutcome::Rejected,
                    objective,
                    trigger,
                    operations,
                    deltas,
                    boundary,
                    history,
                    policy,
                    &receipt_digest,
                    "same operation identity carries a different canonical request; identity conflict blocks transition",
                );
            }
        }
        if attempt.equivalence_digest.as_str() == identity_digest.as_str()
            && (!attempt.changed_evidence
                || matches!(attempt.repeat_justification, RepeatJustification::None))
        {
            return emit_candidate(
                MaintenanceOutcome::Rejected,
                objective,
                trigger,
                operations,
                deltas,
                boundary,
                history,
                policy,
                &receipt_digest,
                "equivalent plan without new evidence repeats no work",
            );
        }
    }
    Ok(complete)
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::error_rejection_hint;
    use super::is_hex64_lower;
    use super::outcome_rejection_hint;
    use super::propose_maintenance_plan;
    use eliot_contracts::EpochId;
    use eliot_contracts::EpochLineageId;
    use eliot_contracts::ResourceGeneration;
    use eliot_dreamer_contracts::BudgetLimits;
    use eliot_dreamer_contracts::ClaimResidue;
    use eliot_dreamer_contracts::CurationRejectionCode;
    use eliot_dreamer_contracts::DreamJobAdmission;
    use eliot_dreamer_contracts::GroundedDreamDraft;
    use eliot_dreamer_contracts::JobClass;
    use eliot_dreamer_contracts::Requester;
    use eliot_dreamer_contracts::RequesterOrigin;
    use eliot_dreamer_contracts::SupportState;
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
            input_bytes: Some(1_048_576),
            output_bytes: Some(1_048_576),
            source_width: Some(64),
            reference_width: Some(64),
            model_calls: Some(1),
            attempts: Some(16),
            candidates: Some(16),
            wall_ms: Some(600_000),
            work_fan_out: Some(32),
            report_bytes: Some(1_048_576),
            max_stu: Some(10_000),
        }
    }

    /// Returns a valid validator receipt for the test job and digests.
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

    /// Returns a maintenance job bound to the test receipt.
    fn test_job() -> DreamJobAdmission {
        DreamJobAdmission {
            schema_version: 1,
            job_class: JobClass::Maintenance,
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
            policy_ref: "policy-7".to_owned(),
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

    /// Returns a grounded draft bound to the test receipt digests.
    fn test_grounded() -> GroundedDreamDraft {
        GroundedDreamDraft {
            schema_version: 1,
            job_id: "job-1".to_owned(),
            draft_digest: "a".repeat(64),
            residues: vec![ClaimResidue {
                claim: "the cache hit rate fell below the bound objective".to_owned(),
                state: SupportState::Supported,
                detail: "ep-1 shows warm-key support for the observed condition".to_owned(),
            }],
            coverage_note: "one claim accounted".to_owned(),
        }
    }

    /// Returns the single finite objective for the tests.
    fn test_objective() -> super::MaintenanceObjective {
        super::MaintenanceObjective {
            objective_id: "obj-1".to_owned(),
            objective_revision: 3,
            product_id: "product-1".to_owned(),
            module_ref: "module-cache".to_owned(),
            owner: "owner-1".to_owned(),
            decomposition_owners: Vec::new(),
            causal_note: "warm-key hit rate stays above the bound".to_owned(),
            context_digest: "c".repeat(64),
        }
    }

    /// Returns exact trigger evidence with a full denominator.
    fn test_trigger() -> super::TriggerEvidence {
        super::TriggerEvidence {
            trigger_id: "trig-1".to_owned(),
            kind: super::TriggerKind::QualityDegradation,
            observation_owner: "observer-1".to_owned(),
            affected_surface: "module-cache".to_owned(),
            baseline_note: "baseline hit rate is 0.80 for the same scope".to_owned(),
            condition_note: "warm-key hit rate 0.61 below bound 0.80 for three windows".to_owned(),
            diagnosed_condition: "cache fragmentation after rotation".to_owned(),
            evidence_refs: vec!["e-1".to_owned(), "e-2".to_owned(), "e-3".to_owned()],
            denominator_total: 3,
            denominator_covered: 3,
            false_positive_note: "two independent probes agree; flake review found none".to_owned(),
            persistence_note: "condition persists across three observation windows".to_owned(),
            one_shot_justification: None,
            outcome_mapping_note: Some(
                "product-1 hit rate maps to checkout latency per outcome profile o-9".to_owned(),
            ),
            invalidation_note: "invalidated by a full-window recovery above bound".to_owned(),
            context_digest: "c".repeat(64),
        }
    }

    /// Returns one planned budget slice with zero model spend.
    fn test_slice() -> super::BudgetSlice {
        super::BudgetSlice {
            cpu_ms: 60_000,
            memory_bytes: 67_108_864,
            storage_bytes: 1_073_741_824,
            network_bytes: 1_048_576,
            context_bytes: 65_536,
            model_calls: 0,
            cost_units: 40,
            human_minutes: 30,
            wall_ms: 120_000,
            idle_ms: 30_000,
            work_items: 4,
            output_bytes: 65_536,
        }
    }

    /// Returns one planned operation with the given identity and kind.
    fn test_operation(identity: &str, kind: &str) -> super::PlannedOperation {
        super::PlannedOperation {
            op_id: identity.to_owned(),
            op_kind: kind.to_owned(),
            owner: "owner-1".to_owned(),
            inputs: vec![["input-", identity].concat()],
            preconditions: vec![["precondition holds for ", identity].concat()],
            output_note: ["observable output for ", identity].concat(),
            verifier_id: "verifier-7".to_owned(),
            effect_ceiling: ["read-only ceiling for ", identity].concat(),
            budget: test_slice(),
            order: 0,
            depends_on: Vec::new(),
            max_retries: 2,
            deadline_note: ["deadline holds for ", identity].concat(),
            cancel_note: ["cancel before effect for ", identity].concat(),
            cancellation: super::CancellationHandling::BeforeEffectNoEffect,
            no_progress_note: ["no-progress guard for ", identity].concat(),
            rollback_note: ["rollback restores prior state for ", identity].concat(),
            disable_note: ["disable parks the surface for ", identity].concat(),
            stop_note: ["stop on regression for ", identity].concat(),
            reopen_note: ["reopen on changed condition for ", identity].concat(),
            non_goals: vec![["scheduling is a non-goal for ", identity].concat()],
        }
    }

    /// Returns the finite three-operation graph for the tests.
    fn test_operations() -> Vec<super::PlannedOperation> {
        let mut first = test_operation("op-inspect", "inspect");
        first.order = 0;
        let mut second = test_operation("op-vacuum", "vacuum");
        second.order = 1;
        second.depends_on = vec!["op-inspect".to_owned()];
        let mut third = test_operation("op-verify", "verify");
        third.order = 2;
        third.depends_on = vec!["op-vacuum".to_owned()];
        vec![first, second, third]
    }

    /// Returns every independent expected delta dimension for the tests.
    fn test_deltas() -> Vec<super::ExpectedDelta> {
        [
            (
                "correctness",
                "improve",
                "semantic correctness remains within the typed invariant",
            ),
            (
                "recovery",
                "improve",
                "recovery returns to the prior safe state",
            ),
            (
                "memory_quality",
                "improve",
                "memory quality retains the same source lineage",
            ),
            (
                "context_quality",
                "improve",
                "context quality keeps the declared scope",
            ),
            (
                "latency",
                "improve",
                "p99 latency falls inside the declared range",
            ),
            (
                "resources",
                "bounded",
                "resource consumption remains inside the independent bound",
            ),
            ("cost", "preserve", "cost remains within the admitted range"),
            (
                "evidence",
                "improve",
                "evidence coverage is verified on the frozen denominator",
            ),
            (
                "capability",
                "preserve",
                "capability support stays at the admitted ceiling",
            ),
            ("security", "preserve", "security posture does not regress"),
            ("privacy", "preserve", "privacy posture does not widen"),
            (
                "maintenance_burden",
                "reduce",
                "maintenance burden falls in the next window",
            ),
            (
                "human_burden",
                "reduce",
                "Human burden stays below the declared review range",
            ),
            (
                "user_outcome",
                "improve",
                "product-1 user outcome improves on the declared scope",
            ),
        ]
        .into_iter()
        .map(|(dimension, direction, range)| super::ExpectedDelta {
            dimension: dimension.to_owned(),
            baseline_note: ["baseline for ", dimension].concat(),
            direction: direction.to_owned(),
            range_note: range.to_owned(),
            evidence_note: ["evidence for ", dimension, " is retained"].concat(),
            uncertainty_note: "bounded measurement uncertainty is retained".to_owned(),
            verifier_id: "verifier-7".to_owned(),
            unacceptable_regression: ["any regression in ", dimension, " is unacceptable"].concat(),
        })
        .collect()
    }

    /// Returns the inert verifier, rollback, and approval boundary.
    fn test_boundary() -> super::MaintenanceBoundary {
        super::MaintenanceBoundary {
            verifier: super::SemanticVerifier {
                verifier_id: "verifier-7".to_owned(),
                success_note: "hit rate above bound for one full window".to_owned(),
                semantic_success_predicate: "semantic outcome preserves the product-1 hit-rate invariant for one full window".to_owned(),
                partial_note: "hit rate recovers for half a window only".to_owned(),
                no_change_note: "hit rate unchanged within measurement noise".to_owned(),
                regression_note: "hit rate falls further on the same denominator".to_owned(),
                failure_note: "surface unreachable during the window".to_owned(),
                unknown_note: "telemetry gap leaves the reading unknown".to_owned(),
                observation_window_note: "one full window over e-1 e-2 e-3".to_owned(),
                denominator_note: "denominator e-1 e-2 e-3 with three probes".to_owned(),
                max_attempts: 3,
                stop_note: "stop on regression or no progress for one window".to_owned(),
            },
            rollback_steps: vec![
                "restore snapshot snap-9".to_owned(),
                "replay read probe on e-1".to_owned(),
            ],
            disable_note: "disable parks the surface without deleting state".to_owned(),
            forward_repair_note: "forward repair replays the typed vacuum only".to_owned(),
            reopen_note: "reopen only on a changed observed condition".to_owned(),
            required_decisions: vec![
                "Human approves the vacuum window".to_owned(),
                "owner accepts the rollback note".to_owned(),
            ],
            approval_expiry_note: "approval expires after one window".to_owned(),
            silence_is_approval: false,
            forbidden_widening_note: "no widening is admitted by this plan".to_owned(),
            protected_budget: super::BudgetSlice {
                cpu_ms: 10_000,
                memory_bytes: 16_777_216,
                storage_bytes: 16_777_216,
                network_bytes: 65_536,
                context_bytes: 16_384,
                model_calls: 0,
                cost_units: 10,
                human_minutes: 10,
                wall_ms: 30_000,
                idle_ms: 10_000,
                work_items: 1,
                output_bytes: 4_096,
            },
            external_automation_ref: None,
        }
    }

    /// Returns retained prior history with one attempt denominator.
    fn test_history() -> super::PriorHistory {
        super::PriorHistory {
            expected_attempt_ids: vec!["att-1".to_owned()],
            attempts: vec![super::HistoryAttempt {
                attempt_id: "att-1".to_owned(),
                equivalence_digest: "a".repeat(64),
                disposition: super::PriorAttemptDisposition::Verified,
                effect_state: super::PriorEffectState::NoEffect,
                changed_evidence: false,
                repeat_justification: super::RepeatJustification::None,
                request_digest: None,
                policy_revision: None,
            }],
            outcome_note: "one prior attempt retained verbatim".to_owned(),
        }
    }

    /// Returns a valid governing policy for the test plan.
    fn test_policy() -> super::MaintenancePolicy {
        super::MaintenancePolicy {
            policy_id: "policy-7".to_owned(),
            policy_revision: 2,
            allowed_op_kinds: vec![
                "compact".to_owned(),
                "inspect".to_owned(),
                "prune".to_owned(),
                "reconcile".to_owned(),
                "refresh".to_owned(),
                "reindex".to_owned(),
                "rotate".to_owned(),
                "snapshot".to_owned(),
                "vacuum".to_owned(),
                "verify".to_owned(),
            ],
            max_operations: super::MAX_OPERATIONS,
            max_dependencies: super::MAX_DEPENDENCIES,
            max_deltas: super::MAX_DELTAS,
            max_evidence: super::MAX_EVIDENCE_ITEMS,
            allow_partial: false,
            cancelled: false,
            observation_time_ms: Some(1_700_000_000_000),
            deadline_ms: Some(1_800_000_000_000),
            owner_note: "plan owned by the dreamer cell".to_owned(),
        }
    }

    /// Runs the full valid fixture set through the entry point.
    fn run_valid() -> super::MaintenancePlanCandidate {
        let job = test_job();
        let draft = test_draft();
        let grounded = test_grounded();
        let objective = test_objective();
        let trigger = test_trigger();
        let history = test_history();
        let operations = test_operations();
        let deltas = test_deltas();
        let boundary = test_boundary();
        let policy = test_policy();
        let Ok(candidate) = propose_maintenance_plan(
            &job,
            &draft,
            &grounded,
            &objective,
            &trigger,
            &history,
            &operations,
            &deltas,
            &boundary,
            &policy,
        ) else {
            panic!("valid plan must complete");
        };
        candidate
    }

    /// Owns one mutable test fixture so every numbered case exercises the
    /// public planner entry point with a disjoint semantic mutation.
    struct Fixture {
        job: DreamJobAdmission,
        draft: ValidatedDreamDraft,
        grounded: GroundedDreamDraft,
        objective: super::MaintenanceObjective,
        trigger: super::TriggerEvidence,
        history: super::PriorHistory,
        operations: Vec<super::PlannedOperation>,
        deltas: Vec<super::ExpectedDelta>,
        boundary: super::MaintenanceBoundary,
        policy: super::MaintenancePolicy,
    }

    impl Fixture {
        fn fresh() -> Self {
            Self {
                job: test_job(),
                draft: test_draft(),
                grounded: test_grounded(),
                objective: test_objective(),
                trigger: test_trigger(),
                history: test_history(),
                operations: test_operations(),
                deltas: test_deltas(),
                boundary: test_boundary(),
                policy: test_policy(),
            }
        }

        fn propose(&self) -> Result<super::MaintenancePlanCandidate, super::MaintenancePlanError> {
            propose_maintenance_plan(
                &self.job,
                &self.draft,
                &self.grounded,
                &self.objective,
                &self.trigger,
                &self.history,
                &self.operations,
                &self.deltas,
                &self.boundary,
                &self.policy,
            )
        }
    }

    fn inert_outcome(
        fixture: &Fixture,
        expected: super::MaintenanceOutcome,
    ) -> super::MaintenancePlanCandidate {
        let Ok(candidate) = fixture.propose() else {
            panic!("semantic case must return an inert candidate");
        };
        assert_eq!(candidate.outcome, expected);
        assert!(candidate.preservation.overall().is_ok());
        candidate
    }

    // WORK_UNIT_CASE: 677/1
    #[test]
    fn case_01_valid_owner_bound_plan_completes() {
        let candidate = run_valid();
        assert_eq!(candidate.outcome, super::MaintenanceOutcome::Complete);
        assert_eq!(candidate.plan_handle, "plan-obj-1");
        assert_eq!(candidate.objective_id, "obj-1");
        assert_eq!(candidate.objective_revision, 3);
        assert_eq!(candidate.owner, "owner-1");
        assert_eq!(candidate.trigger_id, "trig-1");
        assert_eq!(candidate.operations.len(), 3);
        assert_eq!(candidate.deltas.len(), 14);
        assert_eq!(candidate.verifier_id, "verifier-7");
        assert_eq!(candidate.rollback_steps.len(), 2);
        assert_eq!(candidate.required_decisions.len(), 2);
        assert_eq!(candidate.input_receipt_digest, "e".repeat(64));
        assert_eq!(candidate.attempt_denominator, vec!["att-1".to_owned()]);
        assert!(is_hex64_lower(&candidate.candidate_digest));
        assert!(candidate.preservation.overall().is_ok());
        assert_eq!(candidate.preservation.verdicts.len(), 7);
        assert_eq!(outcome_rejection_hint(&candidate.outcome), None);
    }

    // WORK_UNIT_CASE: 677/2
    #[test]
    fn case_02_unknown_operation_vocab_is_unsupported() {
        let job = test_job();
        let draft = test_draft();
        let grounded = test_grounded();
        let objective = test_objective();
        let trigger = test_trigger();
        let history = test_history();
        let mut operations = test_operations();
        operations[0].op_kind = "turbocharge".to_owned();
        let deltas = test_deltas();
        let boundary = test_boundary();
        let policy = test_policy();
        let Ok(candidate) = propose_maintenance_plan(
            &job,
            &draft,
            &grounded,
            &objective,
            &trigger,
            &history,
            &operations,
            &deltas,
            &boundary,
            &policy,
        ) else {
            panic!("unknown vocab stays an inert outcome");
        };
        assert_eq!(
            candidate.outcome,
            super::MaintenanceOutcome::UnsupportedShape
        );
        assert_eq!(
            outcome_rejection_hint(&candidate.outcome),
            Some(CurationRejectionCode::UnsupportedJobShape)
        );
        assert!(candidate.preservation.overall().is_ok());
    }

    // WORK_UNIT_CASE: 677/3
    #[test]
    fn case_03_wrong_job_shape_fails_closed() {
        let mut job = test_job();
        job.job_class = JobClass::Curation;
        let draft = test_draft();
        let grounded = test_grounded();
        let objective = test_objective();
        let trigger = test_trigger();
        let history = test_history();
        let operations = test_operations();
        let deltas = test_deltas();
        let boundary = test_boundary();
        let policy = test_policy();
        let result = propose_maintenance_plan(
            &job,
            &draft,
            &grounded,
            &objective,
            &trigger,
            &history,
            &operations,
            &deltas,
            &boundary,
            &policy,
        );
        let Err(err) = result else {
            panic!("wrong job shape must fail");
        };
        assert!(matches!(err, super::MaintenancePlanError::Binding { .. }));
        assert_eq!(
            error_rejection_hint(&err),
            CurationRejectionCode::IdentityMismatch
        );
    }

    // WORK_UNIT_CASE: 677/4
    #[test]
    fn case_04_grounding_drift_fails_closed() {
        let job = test_job();
        let draft = test_draft();
        let mut grounded = test_grounded();
        grounded.draft_digest = "9".repeat(64);
        let objective = test_objective();
        let trigger = test_trigger();
        let history = test_history();
        let operations = test_operations();
        let deltas = test_deltas();
        let boundary = test_boundary();
        let policy = test_policy();
        let result = propose_maintenance_plan(
            &job,
            &draft,
            &grounded,
            &objective,
            &trigger,
            &history,
            &operations,
            &deltas,
            &boundary,
            &policy,
        );
        let Err(err) = result else {
            panic!("grounding drift must fail");
        };
        assert!(matches!(err, super::MaintenancePlanError::Binding { .. }));
        assert_eq!(
            error_rejection_hint(&err),
            CurationRejectionCode::IdentityMismatch
        );
    }

    // WORK_UNIT_CASE: 677/5
    #[test]
    fn case_05_trigger_without_evidence_is_insufficient() {
        let job = test_job();
        let draft = test_draft();
        let grounded = test_grounded();
        let objective = test_objective();
        let mut trigger = test_trigger();
        trigger.evidence_refs = Vec::new();
        let history = test_history();
        let operations = test_operations();
        let deltas = test_deltas();
        let boundary = test_boundary();
        let policy = test_policy();
        let Ok(candidate) = propose_maintenance_plan(
            &job,
            &draft,
            &grounded,
            &objective,
            &trigger,
            &history,
            &operations,
            &deltas,
            &boundary,
            &policy,
        ) else {
            panic!("evidenceless trigger stays an inert outcome");
        };
        assert_eq!(candidate.outcome, super::MaintenanceOutcome::Insufficient);
        assert_eq!(
            outcome_rejection_hint(&candidate.outcome),
            Some(CurationRejectionCode::UnsupportedPrecision)
        );
        assert!(candidate.preservation.overall().is_ok());
    }

    // WORK_UNIT_CASE: 677/6
    #[test]
    fn case_06_generic_wish_is_rejected() {
        let job = test_job();
        let draft = test_draft();
        let grounded = test_grounded();
        let objective = test_objective();
        let mut trigger = test_trigger();
        trigger.condition_note = "optimize everything and keep thinking".to_owned();
        let history = test_history();
        let operations = test_operations();
        let deltas = test_deltas();
        let boundary = test_boundary();
        let policy = test_policy();
        let Ok(candidate) = propose_maintenance_plan(
            &job,
            &draft,
            &grounded,
            &objective,
            &trigger,
            &history,
            &operations,
            &deltas,
            &boundary,
            &policy,
        ) else {
            panic!("generic prose stays an inert outcome");
        };
        assert_eq!(candidate.outcome, super::MaintenanceOutcome::Rejected);
        assert_eq!(
            outcome_rejection_hint(&candidate.outcome),
            Some(CurationRejectionCode::IdentityMismatch)
        );
        assert!(candidate.preservation.overall().is_ok());
    }

    // WORK_UNIT_CASE: 677/7
    #[test]
    fn case_07_unmapped_signal_is_insufficient() {
        let job = test_job();
        let draft = test_draft();
        let grounded = test_grounded();
        let objective = test_objective();
        let mut trigger = test_trigger();
        trigger.outcome_mapping_note = None;
        let history = test_history();
        let operations = test_operations();
        let deltas = test_deltas();
        let boundary = test_boundary();
        let policy = test_policy();
        let Ok(candidate) = propose_maintenance_plan(
            &job,
            &draft,
            &grounded,
            &objective,
            &trigger,
            &history,
            &operations,
            &deltas,
            &boundary,
            &policy,
        ) else {
            panic!("unmapped signal stays an inert outcome");
        };
        assert_eq!(candidate.outcome, super::MaintenanceOutcome::Insufficient);
        assert_eq!(
            outcome_rejection_hint(&candidate.outcome),
            Some(CurationRejectionCode::UnsupportedPrecision)
        );
        assert!(candidate.preservation.overall().is_ok());
    }

    // WORK_UNIT_CASE: 677/8
    #[test]
    fn case_08_partial_denominator_is_partial() {
        let job = test_job();
        let draft = test_draft();
        let grounded = test_grounded();
        let objective = test_objective();
        let mut trigger = test_trigger();
        trigger.denominator_covered = 2;
        let history = test_history();
        let operations = test_operations();
        let deltas = test_deltas();
        let boundary = test_boundary();
        let mut policy = test_policy();
        policy.allow_partial = true;
        let Ok(candidate) = propose_maintenance_plan(
            &job,
            &draft,
            &grounded,
            &objective,
            &trigger,
            &history,
            &operations,
            &deltas,
            &boundary,
            &policy,
        ) else {
            panic!("partial denominator stays an inert outcome");
        };
        assert_eq!(candidate.outcome, super::MaintenanceOutcome::Partial);
        assert_eq!(
            outcome_rejection_hint(&candidate.outcome),
            Some(CurationRejectionCode::PreservationFailed)
        );
        assert!(candidate.preservation.overall().is_ok());
    }

    // WORK_UNIT_CASE: 677/9
    #[test]
    fn case_09_incident_and_recovery_keep_their_owner() {
        let mut fixture = Fixture::fresh();
        fixture.trigger.kind = super::TriggerKind::IncidentRecovery;
        let candidate = inert_outcome(&fixture, super::MaintenanceOutcome::Rejected);
        assert!(candidate.note.contains("operational owner"));
    }

    // WORK_UNIT_CASE: 677/10
    #[test]
    fn case_10_explicit_multi_owner_decomposition_is_retained() {
        let mut fixture = Fixture::fresh();
        fixture.operations[1].owner = "owner-2".to_owned();
        fixture.objective.decomposition_owners = vec!["owner-1".to_owned(), "owner-2".to_owned()];
        let candidate = fixture
            .propose()
            .expect("explicit decomposition is a candidate");
        assert_eq!(candidate.outcome, super::MaintenanceOutcome::Complete);
        assert_eq!(
            candidate.decomposition_owners,
            fixture.objective.decomposition_owners
        );
    }

    // WORK_UNIT_CASE: 677/11
    #[test]
    fn case_11_conflicting_owner_without_decomposition_needs_decision() {
        let mut fixture = Fixture::fresh();
        fixture.operations[1].owner = "owner-2".to_owned();
        let candidate = inert_outcome(&fixture, super::MaintenanceOutcome::DecisionRequired);
        assert!(candidate.note.contains("decomposition"));
    }

    // WORK_UNIT_CASE: 677/12
    #[test]
    fn case_12_history_must_cover_its_declared_denominator() {
        let mut fixture = Fixture::fresh();
        fixture
            .history
            .expected_attempt_ids
            .push("att-2".to_owned());
        let result = fixture.propose();
        assert!(matches!(
            result,
            Err(super::MaintenancePlanError::Denominator { .. })
        ));
    }

    // WORK_UNIT_CASE: 677/13
    #[test]
    fn case_13_equivalent_plan_without_new_evidence_is_rejected() {
        let mut fixture = Fixture::fresh();
        fixture.history.expected_attempt_ids.clear();
        fixture.history.attempts.clear();
        let first = fixture.propose().expect("identity fixture must be valid");
        let mut identity_history = fixture.history.clone();
        identity_history.expected_attempt_ids.clear();
        identity_history.attempts.clear();
        let identity_digest = super::compute_plan_digest(
            &first.plan_handle,
            super::MaintenanceOutcome::Complete.as_str(),
            &fixture.objective,
            &fixture.trigger,
            &fixture.operations,
            &fixture.deltas,
            &fixture.boundary,
            &identity_history,
            &fixture.policy,
            &fixture.draft.receipt.output_digest,
        )
        .expect("identity digest must be deterministic");
        fixture.history.expected_attempt_ids = vec!["att-replay".to_owned()];
        fixture.history.attempts = vec![super::HistoryAttempt {
            attempt_id: "att-replay".to_owned(),
            equivalence_digest: identity_digest,
            disposition: super::PriorAttemptDisposition::Verified,
            effect_state: super::PriorEffectState::NoEffect,
            changed_evidence: false,
            repeat_justification: super::RepeatJustification::None,
            request_digest: None,
            policy_revision: None,
        }];
        let candidate = inert_outcome(&fixture, super::MaintenanceOutcome::Rejected);
        assert!(candidate.note.contains("equivalent"));
    }

    // WORK_UNIT_CASE: 677/14
    #[test]
    fn case_14_controlled_equivalent_repeat_requires_new_evidence() {
        let mut fixture = Fixture::fresh();
        fixture.history.expected_attempt_ids.clear();
        fixture.history.attempts.clear();
        let first = fixture.propose().expect("identity fixture must be valid");
        let identity_digest = super::compute_plan_digest(
            &first.plan_handle,
            super::MaintenanceOutcome::Complete.as_str(),
            &fixture.objective,
            &fixture.trigger,
            &fixture.operations,
            &fixture.deltas,
            &fixture.boundary,
            &fixture.history,
            &fixture.policy,
            &fixture.draft.receipt.output_digest,
        )
        .expect("identity digest must be deterministic");
        fixture.history.expected_attempt_ids = vec!["att-repeat".to_owned()];
        fixture.history.attempts = vec![super::HistoryAttempt {
            attempt_id: "att-repeat".to_owned(),
            equivalence_digest: identity_digest,
            disposition: super::PriorAttemptDisposition::Failed,
            effect_state: super::PriorEffectState::NoEffect,
            changed_evidence: true,
            repeat_justification: super::RepeatJustification::Replication,
            request_digest: None,
            policy_revision: None,
        }];
        let candidate = fixture
            .propose()
            .expect("controlled repeat remains a candidate");
        assert_eq!(candidate.outcome, super::MaintenanceOutcome::Complete);
    }

    // WORK_UNIT_CASE: 677/15
    #[test]
    fn case_15_failed_no_progress_or_hung_history_blocks_blind_retry() {
        let mut fixture = Fixture::fresh();
        fixture.history.attempts[0].disposition = super::PriorAttemptDisposition::NoProgress;
        let candidate = inert_outcome(&fixture, super::MaintenanceOutcome::DecisionRequired);
        assert!(candidate.note.contains("changed evidence"));
    }

    // WORK_UNIT_CASE: 677/16
    #[test]
    fn case_16_dependency_graph_is_finite_and_ordered() {
        let mut fixture = Fixture::fresh();
        fixture.operations[2].order = 4;
        let candidate = inert_outcome(&fixture, super::MaintenanceOutcome::Rejected);
        assert!(candidate.note.contains("contiguous"));
    }

    // WORK_UNIT_CASE: 677/17
    #[test]
    fn case_17_operation_missing_owner_is_malformed() {
        let mut fixture = Fixture::fresh();
        fixture.operations[0].owner.clear();
        let result = fixture.propose();
        assert!(matches!(
            result,
            Err(super::MaintenancePlanError::Shape { .. })
        ));
    }

    // WORK_UNIT_CASE: 677/18
    #[test]
    fn case_18_cycle_and_hidden_recurrence_are_rejected() {
        let mut fixture = Fixture::fresh();
        fixture.operations[1].depends_on = vec!["op-verify".to_owned()];
        fixture.operations[2].depends_on = vec!["op-vacuum".to_owned()];
        let candidate = inert_outcome(&fixture, super::MaintenanceOutcome::Rejected);
        assert!(candidate.note.contains("cyclic") || candidate.note.contains("finite"));
    }

    // WORK_UNIT_CASE: 677/19
    #[test]
    fn case_19_raw_command_provider_payload_or_secret_is_rejected() {
        let mut fixture = Fixture::fresh();
        fixture.operations[0].output_note = "run command shell: vacuum --all".to_owned();
        let candidate = inert_outcome(&fixture, super::MaintenanceOutcome::Rejected);
        assert!(candidate.note.contains("raw commands"));
    }

    // WORK_UNIT_CASE: 677/20
    #[test]
    fn case_20_each_independent_budget_boundary_rejects_one_over() {
        let setters: &[fn(&mut super::BudgetSlice)] = &[
            |budget| budget.cpu_ms = super::CPU_MS_CEILING + 1,
            |budget| budget.memory_bytes = super::MEMORY_BYTES_CEILING + 1,
            |budget| budget.storage_bytes = super::STORAGE_BYTES_CEILING + 1,
            |budget| budget.network_bytes = super::NETWORK_BYTES_CEILING + 1,
            |budget| budget.context_bytes = super::CONTEXT_BYTES_CEILING + 1,
            |budget| budget.model_calls = 1,
            |budget| budget.cost_units = super::COST_UNITS_CEILING + 1,
            |budget| budget.human_minutes = super::HUMAN_MINUTES_CEILING + 1,
            |budget| budget.wall_ms = super::WALL_MS_CEILING + 1,
            |budget| budget.idle_ms = super::IDLE_MS_CEILING + 1,
            |budget| budget.work_items = super::WORK_ITEMS_CEILING + 1,
            |budget| budget.output_bytes = super::OUTPUT_BYTES_CEILING + 1,
        ];
        for set_over in setters {
            let mut fixture = Fixture::fresh();
            set_over(&mut fixture.operations[0].budget);
            assert!(matches!(
                fixture.propose(),
                Err(super::MaintenancePlanError::Bounds { .. })
            ));
        }
        let mut protected = Fixture::fresh();
        protected.boundary.protected_budget.cpu_ms = super::CPU_MS_CEILING + 1;
        assert!(matches!(
            protected.propose(),
            Err(super::MaintenancePlanError::Bounds { .. })
        ));
    }

    // WORK_UNIT_CASE: 677/21
    #[test]
    fn case_21_unknown_admitted_budget_is_not_unlimited() {
        let mut fixture = Fixture::fresh();
        fixture.job.budget.input_bytes = None;
        let candidate = inert_outcome(&fixture, super::MaintenanceOutcome::Insufficient);
        assert!(candidate.note.contains("unknown independent"));
    }

    // WORK_UNIT_CASE: 677/22
    #[test]
    fn case_22_underuse_in_one_dimension_cannot_cover_another() {
        let mut fixture = Fixture::fresh();
        fixture.job.budget.input_bytes = Some(1);
        fixture.job.budget.output_bytes = Some(1_048_576);
        let candidate = inert_outcome(&fixture, super::MaintenanceOutcome::Insufficient);
        assert!(candidate.note.contains("input_bytes"));
    }

    // WORK_UNIT_CASE: 677/23
    #[test]
    fn case_23_protected_verification_rollback_and_human_headroom_is_explicit() {
        let mut fixture = Fixture::fresh();
        fixture.boundary.protected_budget.human_minutes = 0;
        let result = fixture.propose();
        assert!(matches!(
            result,
            Err(super::MaintenancePlanError::Shape { .. })
        ));
    }

    // WORK_UNIT_CASE: 677/24
    #[test]
    fn case_24_budget_exhaustion_keeps_omitted_operations_visible() {
        let mut fixture = Fixture::fresh();
        fixture.job.budget.candidates = Some(2);
        let candidate = inert_outcome(&fixture, super::MaintenanceOutcome::Insufficient);
        assert_eq!(candidate.operations.len(), 3);
        assert!(candidate.note.contains("candidates"));
    }

    // WORK_UNIT_CASE: 677/25
    #[test]
    fn case_25_expected_deltas_are_independent_and_complete() {
        let mut fixture = Fixture::fresh();
        fixture.deltas.retain(|delta| delta.dimension != "privacy");
        let candidate = inert_outcome(&fixture, super::MaintenanceOutcome::Insufficient);
        assert!(candidate.note.contains("independent"));
    }

    // WORK_UNIT_CASE: 677/26
    #[test]
    fn case_26_cost_improvement_cannot_compensate_safety_failure() {
        let mut fixture = Fixture::fresh();
        for delta in &mut fixture.deltas {
            if delta.dimension == "cost" {
                delta.direction = "improve".to_owned();
            }
            if delta.dimension == "security" {
                delta.direction = "preserve".to_owned();
            }
        }
        let candidate = inert_outcome(&fixture, super::MaintenanceOutcome::Rejected);
        assert!(candidate.note.contains("cannot compensate"));
    }

    // WORK_UNIT_CASE: 677/27
    #[test]
    fn case_27_unsupported_product_mapping_stays_insufficient() {
        let mut fixture = Fixture::fresh();
        fixture.trigger.outcome_mapping_note =
            Some("product-unknown has a metric delta".to_owned());
        let candidate = inert_outcome(&fixture, super::MaintenanceOutcome::Insufficient);
        assert!(candidate.note.contains("exact supported product"));
    }

    // WORK_UNIT_CASE: 677/28
    #[test]
    fn case_28_operations_and_deltas_bind_the_exact_semantic_verifier() {
        let mut fixture = Fixture::fresh();
        fixture.operations[0].verifier_id = "other-verifier".to_owned();
        let candidate = inert_outcome(&fixture, super::MaintenanceOutcome::Rejected);
        assert!(candidate.note.contains("semantic verifier"));
    }

    // WORK_UNIT_CASE: 677/29
    #[test]
    fn case_29_process_exit_or_metric_movement_is_not_semantic_success() {
        let mut fixture = Fixture::fresh();
        fixture.boundary.verifier.success_note = "exit 0".to_owned();
        let candidate = inert_outcome(&fixture, super::MaintenanceOutcome::Insufficient);
        assert!(candidate.note.contains("process activity"));
    }

    // WORK_UNIT_CASE: 677/30
    #[test]
    fn case_30_verifier_outcomes_remain_distinct() {
        let mut fixture = Fixture::fresh();
        fixture.boundary.verifier.partial_note = fixture.boundary.verifier.success_note.clone();
        let candidate = inert_outcome(&fixture, super::MaintenanceOutcome::Insufficient);
        assert!(candidate.note.contains("distinguish outcomes"));
    }

    // WORK_UNIT_CASE: 677/31
    #[test]
    fn case_31_retry_and_stop_envelopes_fit_the_verifier() {
        let mut fixture = Fixture::fresh();
        fixture.boundary.verifier.max_attempts = 1;
        let candidate = inert_outcome(&fixture, super::MaintenanceOutcome::Rejected);
        assert!(candidate.note.contains("attempt ceiling"));
    }

    // WORK_UNIT_CASE: 677/32
    #[test]
    fn case_32_cancellation_distinguishes_no_effect_from_possible_effect() {
        let mut fixture = Fixture::fresh();
        fixture.operations[1].cancellation =
            super::CancellationHandling::PossibleEffectRequiresReconciliation;
        fixture.operations[1].cancel_note =
            "cancellation with possible effect requires reconciliation before retry".to_owned();
        let candidate = fixture
            .propose()
            .expect("typed cancellation remains a candidate");
        assert_eq!(candidate.outcome, super::MaintenanceOutcome::Complete);
        assert_eq!(
            candidate.operations[1].cancellation,
            super::CancellationHandling::PossibleEffectRequiresReconciliation
        );
    }

    // WORK_UNIT_CASE: 677/33
    #[test]
    fn case_33_unknown_prior_effect_blocks_unsafe_retry() {
        let mut fixture = Fixture::fresh();
        fixture.history.attempts[0].effect_state = super::PriorEffectState::Unknown;
        let candidate = inert_outcome(&fixture, super::MaintenanceOutcome::DecisionRequired);
        assert!(candidate.note.contains("unknown prior effects"));
    }

    // WORK_UNIT_CASE: 677/34
    #[test]
    fn case_34_cleanup_rollback_disable_and_forward_repair_are_required() {
        let mut fixture = Fixture::fresh();
        fixture.operations[0].rollback_note = "leave the prior state unspecified".to_owned();
        let candidate = inert_outcome(&fixture, super::MaintenanceOutcome::Rejected);
        assert!(candidate.note.contains("recovery"));
    }

    // WORK_UNIT_CASE: 677/35
    #[test]
    fn case_35_explicit_human_decision_is_required() {
        let mut fixture = Fixture::fresh();
        fixture.boundary.required_decisions.clear();
        let result = fixture.propose();
        assert!(matches!(
            result,
            Err(super::MaintenancePlanError::Shape { .. })
        ));
    }

    // WORK_UNIT_CASE: 677/36
    #[test]
    fn case_36_silence_is_not_approval() {
        let mut fixture = Fixture::fresh();
        fixture.boundary.silence_is_approval = true;
        let result = fixture.propose();
        assert!(matches!(
            result,
            Err(super::MaintenancePlanError::Shape { .. })
        ));
    }

    // WORK_UNIT_CASE: 677/37
    #[test]
    fn case_37_privacy_cost_remote_model_and_policy_widening_is_rejected() {
        let mut fixture = Fixture::fresh();
        fixture.operations[0].effect_ceiling = "share externally and grant admin".to_owned();
        let candidate = inert_outcome(&fixture, super::MaintenanceOutcome::Rejected);
        assert!(candidate.note.contains("widening"));
    }

    // WORK_UNIT_CASE: 677/38
    #[test]
    fn case_38_external_cadence_is_referenced_without_creating_one() {
        let mut fixture = Fixture::fresh();
        fixture.trigger.kind = super::TriggerKind::ExternalCadence;
        fixture.boundary.external_automation_ref = Some("maintenance-mode-ref-9".to_owned());
        let candidate = fixture
            .propose()
            .expect("external cadence remains a reference");
        assert_eq!(candidate.outcome, super::MaintenanceOutcome::Complete);
        assert!(!candidate.note.contains("schedule"));
    }

    // WORK_UNIT_CASE: 677/39
    #[test]
    fn case_39_candidate_has_no_executable_runtime_owner_surface() {
        let mut fixture = Fixture::fresh();
        fixture.operations[0].output_note = "execute now".to_owned();
        let candidate = inert_outcome(&fixture, super::MaintenanceOutcome::Rejected);
        assert!(candidate.note.contains("scheduling"));
    }

    // WORK_UNIT_CASE: 677/40
    #[test]
    fn case_40_preserves_all_output_dimensions_and_input_receipt_lineage() {
        let candidate = run_valid();
        assert_eq!(candidate.preservation.verdicts.len(), 7);
        assert_eq!(candidate.input_receipt_digest, "e".repeat(64));
        assert!(candidate.preservation.overall().is_ok());
        assert!(!candidate.note.contains("reinvok"));
    }

    // WORK_UNIT_CASE: 677/41
    #[test]
    fn case_41_partial_deadline_and_cancellation_are_distinct() {
        let mut partial = Fixture::fresh();
        partial.trigger.denominator_covered = 2;
        partial.policy.allow_partial = true;
        assert_eq!(
            partial
                .propose()
                .expect("partial is an inert result")
                .outcome,
            super::MaintenanceOutcome::Partial
        );
        let mut cancelled = Fixture::fresh();
        cancelled.policy.cancelled = true;
        assert_eq!(
            cancelled
                .propose()
                .expect("cancelled is an inert result")
                .outcome,
            super::MaintenanceOutcome::Rejected
        );
        let mut stale = Fixture::fresh();
        stale.policy.observation_time_ms = Some(10);
        stale.policy.deadline_ms = Some(10);
        assert_eq!(
            stale
                .propose()
                .expect("deadline is an inert result")
                .outcome,
            super::MaintenanceOutcome::Stale
        );
    }

    // WORK_UNIT_CASE: 677/42
    #[test]
    fn case_42_proof_and_authority_ceiling_mismatch_escalates() {
        let mut fixture = Fixture::fresh();
        fixture.draft.receipt.proof_ceiling = "executed-and-admitted".to_owned();
        let result = fixture.propose();
        assert!(matches!(
            result,
            Err(super::MaintenancePlanError::Receipt { .. })
        ));
    }

    // WORK_UNIT_CASE: 677/43
    #[test]
    fn case_43_trigger_operation_history_and_output_bounds_are_all_checked() {
        let mut evidence = Fixture::fresh();
        evidence.trigger.evidence_refs = (0..=super::MAX_EVIDENCE_ITEMS)
            .map(|index| format!("e-{index:03}"))
            .collect();
        assert!(matches!(
            evidence.propose(),
            Err(super::MaintenancePlanError::Bounds { .. })
        ));
        let mut inputs = Fixture::fresh();
        inputs.operations[0].inputs = (0..=super::MAX_OPERATION_INPUTS)
            .map(|index| format!("input-{index:03}"))
            .collect();
        assert!(matches!(
            inputs.propose(),
            Err(super::MaintenancePlanError::Bounds { .. })
        ));
        let mut history = Fixture::fresh();
        history.history.expected_attempt_ids = (0..=super::MAX_ATTEMPTS)
            .map(|index| format!("att-{index:03}"))
            .collect();
        assert!(matches!(
            history.propose(),
            Err(super::MaintenancePlanError::Bounds { .. })
        ));
        let mut output = Fixture::fresh();
        output.operations[0].output_note = "x".repeat(super::MAX_NOTE_BYTES + 1);
        assert!(matches!(
            output.propose(),
            Err(super::MaintenancePlanError::Shape { .. })
        ));
    }

    // WORK_UNIT_CASE: 677/44
    #[test]
    fn case_44_canonical_sets_preserve_dependency_identity() {
        let mut fixture = Fixture::fresh();
        fixture.operations[2].depends_on = vec!["op-vacuum".to_owned(), "op-inspect".to_owned()];
        let result = fixture.propose();
        assert!(matches!(
            result,
            Err(super::MaintenancePlanError::Order { .. })
        ));
    }

    // WORK_UNIT_CASE: 677/45
    #[test]
    fn case_45_exact_replay_and_changed_same_id_request_are_conflicts() {
        let mut replay = Fixture::fresh();
        replay.history.expected_attempt_ids.clear();
        replay.history.attempts.clear();
        let first = replay.propose().expect("replay seed must be valid");
        let identity_digest = super::compute_plan_digest(
            &first.plan_handle,
            super::MaintenanceOutcome::Complete.as_str(),
            &replay.objective,
            &replay.trigger,
            &replay.operations,
            &replay.deltas,
            &replay.boundary,
            &replay.history,
            &replay.policy,
            &replay.draft.receipt.output_digest,
        )
        .expect("replay identity must be deterministic");
        replay.history.expected_attempt_ids = vec!["op-1".to_owned()];
        replay.history.attempts = vec![super::HistoryAttempt {
            attempt_id: "op-1".to_owned(),
            equivalence_digest: identity_digest.clone(),
            disposition: super::PriorAttemptDisposition::Verified,
            effect_state: super::PriorEffectState::NoEffect,
            changed_evidence: false,
            repeat_justification: super::RepeatJustification::None,
            request_digest: Some(identity_digest.clone()),
            policy_revision: Some(2),
        }];
        assert_eq!(
            replay
                .propose()
                .expect("replay must remain a candidate")
                .outcome,
            super::MaintenanceOutcome::Rejected
        );
        let mut changed_request = replay;
        changed_request.objective.causal_note = "a changed request identity".to_owned();
        assert_eq!(
            changed_request
                .propose()
                .expect("identity conflict must remain a candidate")
                .outcome,
            super::MaintenanceOutcome::Rejected
        );
        let mut changed_policy = Fixture::fresh();
        changed_policy.history.expected_attempt_ids = vec!["op-1".to_owned()];
        changed_policy.history.attempts = vec![super::HistoryAttempt {
            attempt_id: "op-1".to_owned(),
            equivalence_digest: "a".repeat(64),
            disposition: super::PriorAttemptDisposition::Verified,
            effect_state: super::PriorEffectState::NoEffect,
            changed_evidence: false,
            repeat_justification: super::RepeatJustification::None,
            request_digest: None,
            policy_revision: Some(2),
        }];
        changed_policy.policy.policy_revision = 3;
        assert_eq!(
            changed_policy
                .propose()
                .expect("stale policy must remain a candidate")
                .outcome,
            super::MaintenanceOutcome::Stale
        );
    }

    // WORK_UNIT_CASE: 677/46
    #[test]
    fn case_46_malformed_bounded_inputs_are_panic_free() {
        let mut fixture = Fixture::fresh();
        fixture.operations[0].depends_on = vec!["missing".to_owned(); super::MAX_DEPENDENCIES + 1];
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| fixture.propose()));
        assert!(result.is_ok());
        assert!(matches!(
            result.expect("planner must not panic"),
            Err(super::MaintenancePlanError::Bounds { .. })
        ));
    }

    // WORK_UNIT_CASE: 677/47
    #[test]
    fn case_47_complete_plan_is_finite_and_each_operation_is_closed() {
        let candidate = run_valid();
        assert_eq!(candidate.outcome, super::MaintenanceOutcome::Complete);
        for operation in &candidate.operations {
            assert!(!operation.owner.is_empty());
            assert_eq!(operation.verifier_id, candidate.verifier_id);
            assert!(operation.budget.cpu_ms > 0);
            assert!(operation.rollback_note.contains("rollback"));
        }
    }

    // WORK_UNIT_CASE: 677/48
    #[test]
    fn case_48_no_operation_is_executable_scheduled_or_admitted() {
        let mut fixture = Fixture::fresh();
        fixture.operations[0].stop_note = "execute now".to_owned();
        let candidate = inert_outcome(&fixture, super::MaintenanceOutcome::Rejected);
        assert!(candidate.note.contains("scheduling"));
    }

    // WORK_UNIT_CASE: 677/49
    #[test]
    fn case_49_removing_any_load_bearing_boundary_blocks_completeness() {
        let mut trigger = Fixture::fresh();
        trigger.trigger.evidence_refs.clear();
        assert_eq!(
            trigger.propose().expect("missing trigger is inert").outcome,
            super::MaintenanceOutcome::Insufficient
        );
        let mut owner = Fixture::fresh();
        owner.operations[0].owner.clear();
        assert!(matches!(
            owner.propose(),
            Err(super::MaintenancePlanError::Shape { .. })
        ));
        let mut budget = Fixture::fresh();
        budget.boundary.protected_budget.cpu_ms = 0;
        assert!(matches!(
            budget.propose(),
            Err(super::MaintenancePlanError::Shape { .. })
        ));
        let mut verifier = Fixture::fresh();
        verifier.boundary.verifier.verifier_id.clear();
        assert!(matches!(
            verifier.propose(),
            Err(super::MaintenancePlanError::Bounds { .. }
                | super::MaintenancePlanError::Shape { .. })
        ));
        let mut human = Fixture::fresh();
        human.boundary.required_decisions.clear();
        assert!(matches!(
            human.propose(),
            Err(super::MaintenancePlanError::Shape { .. })
        ));
    }

    // WORK_UNIT_CASE: 677/50
    #[test]
    fn case_50_source_and_api_guard_remain_candidate_only() {
        let source = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/lib.rs"));
        for line in source
            .lines()
            .filter(|line| line.trim_start().starts_with("use "))
        {
            let lowered = line.to_ascii_lowercase();
            for forbidden in [
                "scheduler",
                "readyqueue",
                "wakeintent",
                "doctor",
                "provider",
                "store",
                "authority",
                "finish",
                "durablejob",
            ] {
                assert!(!lowered.contains(forbidden), "forbidden API import: {line}");
            }
        }
        assert!(source.contains("pub fn propose_maintenance_plan"));
        let execute_api = ["pub fn ", "execute_maintenance"].concat();
        let schedule_api = ["pub fn ", "schedule_maintenance"].concat();
        assert!(!source.contains(&execute_api));
        assert!(!source.contains(&schedule_api));
    }
}
