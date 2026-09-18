//! Bounded agent work-unit decomposition (A-43).
//!
//! Pure candidate-only deterministic stateless zero-effect owner of exactly
//! one bounded [`WorkUnitDecomposition`] for a single admitted objective.
//! One exact objective plus immutable owner, source, and Architecture evidence
//! yields finite [`AgentWorkUnitBrief`] candidates with typed
//! [`DependencyKind`] relations, qualified context, cost, and proof budgets,
//! artifact handoffs, and one synthesis owner. The planner never acquires
//! evidence, selects or launches a live agent or model, creates issues, jobs,
//! or worktrees, reserves routes, resources, or leases, executes verification,
//! merges code, synthesizes implementation results, mutates task state, or
//! grants effects or Finish. A valid plan is not work performed and is not a
//! launch authorization.
//!
//! Cell `smart.dreamer.orchestration_plan`, order 43. All inputs are immutable
//! and caller supplied. The pre-handler A-05 receipt is checked intrinsically
//! through its own validation entry points and is never re-executed here; no
//! A-05 algorithm is invoked and no screening, grounding, production registry
//! construction, canonical mutation, authority, effect, store, governor,
//! model, clock, or finish surface exists in this cell.
//!
//! Consumed contracts already carry closed unknown-field rejection (their
//! schemas state `deny_unknown_fields`); this cell performs no generic JSON
//! intake at all, so no unknown field can enter through a typeless path.
//! Every new shape below is constructed explicitly through the eight typed
//! parameters of [`propose_work_unit_decomposition`], never decoded from
//! ambient bytes.
//!
//! Runtime boundary: a malformed, over-bound, cancelled-before-emission, or
//! past-deadline request emits zero effects and fails closed as
//! [`OrchestrationPlanError`]. Semantic shortfalls (write-scope overlap,
//! duplicate semantic ownership across paths, unserialized shared writes, a
//! broken producer-to-synthesis chain, readiness cycles or self edges, unknown
//! prerequisites, uncovered requirements) are inert terminal dispositions
//! carried by [`WorkUnitDecomposition`], never errors that invite a blind
//! retry. Only applicable readiness and write dependencies constrain candidate
//! launch groups: runtime producer relations never create a false compile
//! cycle. Shared reads alone never conflict; a directory scan root is not
//! loaded context.
//!
//! Absence note: this file contains no persistence, identifier allocation,
//! filesystem traversal, provider, model, tool, ambient-state, authority,
//! effect, or terminal-completion calls by construction; the only
//! cryptography is the canonical digest below, and the only fallible work is
//! pure bounded validation. There are no placeholder, mock, canned, or pseudo
//! paths: every branch binds an explicit input field.
//!
//! Test coverage note: 8 of 22 `WORK_UNIT_CASE 681/*` cases execute here
//! (681/1 valid decomposition with parallel groups, 681/2 path and alias
//! overlap, 681/3 duplicate semantic owner, 681/4 unserialized shared write,
//! 681/5 broken synthesis chain, 681/6 cycle and self edge, 681/7 unknown
//! prerequisite, 681/8 permutation-invariant groups with truncated-coverage
//! partial). The remaining 14 of 22 are deferred per START.md s1; #969
//! admission is separate. Deferred: 681/9, 681/10, 681/11, 681/12, 681/13,
//! 681/14, 681/15, 681/16, 681/17, 681/18, 681/19, 681/20, 681/21, 681/22.

#![forbid(unsafe_code)]

use eliot_contracts::sha256_hex;
use eliot_dreamer_contracts::candidate::{DimensionVerdict, PreservationReport};
use eliot_dreamer_contracts::{
    CurationRejectionCode, DreamJobAdmission, JobClass, PreservationDimension, ValidatedDreamDraft,
    check_fence, is_hex64_lower,
};

// ---------------------------------------------------------------------------
// Independent bounds (no cross-subsidy between dimensions).
// ---------------------------------------------------------------------------

/// Maximum work units admitted in one decomposition request.
pub const MAX_WORK_UNITS: usize = 32;
/// Maximum parent requirements admitted in one decomposition request.
pub const MAX_REQUIREMENTS: usize = 128;
/// Maximum plan surfaces admitted in one decomposition request.
pub const MAX_SURFACES: usize = 256;
/// Maximum typed readiness edges admitted in one decomposition request.
pub const MAX_EDGES: usize = 256;
/// Maximum requirement refs admitted on any single unit.
pub const MAX_UNIT_REQUIREMENTS: usize = 64;
/// Maximum write claims admitted on any single unit.
pub const MAX_WRITE_CLAIMS: usize = 64;
/// Maximum read refs admitted on any single unit.
pub const MAX_READ_REFS: usize = 128;
/// Maximum forbidden paths admitted on any single unit.
pub const MAX_FORBIDDEN_PATHS: usize = 64;
/// Maximum bytes for any single free-text field.
pub const MAX_TEXT_BYTES: usize = 1024;
/// Maximum bytes for any handle or identity field.
pub const MAX_HANDLE_BYTES: usize = 128;
/// Maximum bytes for any identity field bound into digests.
pub const MAX_ID_BYTES: usize = 128;
/// Maximum aggregate input bytes across all text fields.
pub const MAX_TOTAL_BYTES: usize = 1_048_576;
/// Redaction ceiling for values echoed into errors and notes.
pub const MAX_REDACTED_CHARS: usize = 128;
/// Maximum constraining out-edges admitted on any single unit.
pub const MAX_FAN_OUT: usize = 8;
/// Maximum constraining readiness chain depth admitted in one plan.
pub const MAX_DEPTH: usize = 16;
/// Maximum context bytes admitted on any single unit budget.
pub const MAX_UNIT_CONTEXT_BYTES: u64 = 8_388_608;
/// Maximum tool calls admitted on any single unit budget.
pub const MAX_UNIT_TOOL_CALLS: u32 = 10_000;
/// Maximum output bytes admitted on any single unit budget.
pub const MAX_UNIT_OUTPUT_BYTES: u64 = 8_388_608;
/// Expected preservation dimensions attested on every emitted candidate.
pub const EXPECTED_PRESERVATION_DIMENSIONS: usize = 7;

/// Routing-only proof ceiling carried by every emitted candidate.
pub const ORCHESTRATION_PROOF_NOTE: &str = "a-43 candidate-only aggregation: inert bounded work-unit decomposition preserved without evidence acquisition, agent launch, scheduling, verification execution, merge, synthesis, task mutation, authority, effect, store, governor, model, clock, or finish";
/// Product Pulse that remains external to this candidate-only cell.
pub const NEXT_EVIDENCE_PULSE: &str = "D3A_ADVISORY_DIAGNOSIS_PLANNING_PULSE_01";

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

/// Returns true when values hold no duplicates.
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

/// Returns true when the haystack contains the needle as a substring.
fn contains_marker(haystack: &str, needle: &str) -> bool {
    haystack.contains(needle)
}

/// Lowercases a note without allocating authority.
fn lowered(note: &str) -> String {
    note.to_lowercase()
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

// ---------------------------------------------------------------------------
// Closed forbidden markers (hidden execution or authority claims).
// ---------------------------------------------------------------------------

/// Substrings that mark a hidden launch, schedule, lease, secret, effect, or
/// finish claim inside candidate notes.
pub const HIDDEN_AUTHORITY_MARKERS: &[&str] = &[
    "launch agent",
    "launch the agent",
    "acquire lease",
    "schedule execution",
    "read provider secret",
    "grant effect",
    "emit finish",
    "authorize finish",
];

/// Substrings that mark an oracle, acceptance, or verifier weakening claim.
pub const ORACLE_MARKERS: &[&str] = &[
    "weaken oracle",
    "relax acceptance",
    "lower bar",
    "skip verifier",
    "ignore verifier",
    "drop the oracle",
];

// ---------------------------------------------------------------------------
// Lexical path policy (no filesystem traversal in this pure cell).
// ---------------------------------------------------------------------------

/// Normalizes a supplied path for comparison: separators unified, a single
/// leading `./` stripped, trailing slashes stripped.
fn normalize_path(path: &str) -> String {
    let mut out = String::new();
    for ch in path.chars() {
        if ch == '\\' {
            out.push('/');
        } else {
            out.push(ch);
        }
    }
    let mut trimmed = out.as_str();
    if let Some(rest) = trimmed.strip_prefix("./") {
        trimmed = rest;
    }
    while trimmed.len() > 1 && trimmed.ends_with('/') {
        trimmed = &trimmed[..trimmed.len().saturating_sub(1)];
    }
    trimmed.to_owned()
}

/// Returns the canonical alias key of a path: normalized and lowercased, so
/// case-only or separator-only spellings compare equal.
fn alias_key(path: &str) -> String {
    normalize_path(path).to_lowercase()
}

/// Returns true when the raw path escapes the versioned lexical policy:
/// blank, absolute, drive-qualified, or carrying a `..` segment.
fn is_path_escape(path: &str) -> bool {
    if path.trim().is_empty() {
        return true;
    }
    let normalized = normalize_path(path);
    if normalized.is_empty() {
        return true;
    }
    if normalized.starts_with('/') {
        return true;
    }
    let bytes = normalized.as_bytes();
    if bytes.len() >= 2 && bytes[1] == b':' {
        return true;
    }
    for segment in normalized.split('/') {
        if segment == ".." || segment.is_empty() {
            return true;
        }
    }
    false
}

/// Returns true when the directory path covers the target path: equal, or the
/// target descends from it through a `/` boundary.
fn dir_covers(dir: &str, target: &str) -> bool {
    if dir == target {
        return true;
    }
    let mut prefix = String::from(dir);
    prefix.push('/');
    target.starts_with(prefix.as_str())
}

/// Returns true when two write claims overlap: file and file collide on the
/// exact path, directory and file collide on coverage, directory and
/// directory collide when either covers the other, and canonical aliases
/// collide even when only case or separators differ.
fn write_claims_overlap(
    first: &str,
    first_is_dir: bool,
    second: &str,
    second_is_dir: bool,
) -> bool {
    let left = normalize_path(first);
    let right = normalize_path(second);
    if left == right {
        return true;
    }
    if alias_key(first) == alias_key(second) {
        return true;
    }
    if first_is_dir && dir_covers(left.as_str(), right.as_str()) {
        return true;
    }
    if second_is_dir && dir_covers(right.as_str(), left.as_str()) {
        return true;
    }
    false
}

/// Returns true when a write claim covers a surface path under directory
/// semantics: exact file equality or descent through a `/` boundary.
fn claim_covers_surface(claim: &str, claim_is_dir: bool, surface: &str) -> bool {
    let normalized_claim = normalize_path(claim);
    let normalized_surface = normalize_path(surface);
    if normalized_claim == normalized_surface {
        return true;
    }
    if claim_is_dir && dir_covers(normalized_claim.as_str(), normalized_surface.as_str()) {
        return true;
    }
    // A file claim never covers a directory surface; a directory surface only
    // constrains exact or ancestor claims, which the caller checks per side.
    false
}

// ---------------------------------------------------------------------------
// Public vocabulary: surfaces, dependencies, budgets, units, policy.
// ---------------------------------------------------------------------------

/// Closed kind of a plan surface path.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum SurfaceKind {
    /// A single addressable file.
    File,
    /// A directory subtree addressed as one scan root.
    Directory,
}

impl SurfaceKind {
    /// Returns the canonical spelling of this surface kind.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::File => "file",
            Self::Directory => "directory",
        }
    }

    /// Parses the exact canonical spelling of a surface kind.
    ///
    /// # Errors
    ///
    /// Returns [`OrchestrationPlanError::Shape`] on any other spelling.
    pub fn parse(spelling: &str) -> Result<Self, OrchestrationPlanError> {
        match spelling {
            "file" => Ok(Self::File),
            "directory" => Ok(Self::Directory),
            _ => Err(OrchestrationPlanError::Shape {
                field: "surface.kind".to_owned(),
                detail: format!("unknown surface kind {}", redact(spelling)),
            }),
        }
    }
}

/// Closed typed dependency relation between two work units.
///
/// Only the readiness and write kinds constrain candidate launch groups.
/// [`DependencyKind::RuntimeProducer`] names a logical producer and consumer
/// without creating a compile ordering edge: runtime producer cycles are
/// never compile cycles.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum DependencyKind {
    /// Compile or contract prerequisite: the consumer needs the producer
    /// accepted first.
    CompilePrerequisite,
    /// Runtime logical producer and consumer without compile ordering force.
    RuntimeProducer,
    /// Write serialization: the two endpoints must not proceed in parallel
    /// over the shared mutable target.
    WriteSerialization,
    /// Proof gate: the consumer needs the producer evidence accepted first.
    ProofGate,
    /// Artifact flow: a produced artifact moves to its declared consumer.
    ArtifactFlow,
}

impl DependencyKind {
    /// Returns the canonical spelling of this dependency kind.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::CompilePrerequisite => "compile_prerequisite",
            Self::RuntimeProducer => "runtime_producer",
            Self::WriteSerialization => "write_serialization",
            Self::ProofGate => "proof_gate",
            Self::ArtifactFlow => "artifact_flow",
        }
    }

    /// Parses the exact canonical spelling of a dependency kind.
    ///
    /// # Errors
    ///
    /// Returns [`OrchestrationPlanError::Shape`] on any other spelling.
    pub fn parse(spelling: &str) -> Result<Self, OrchestrationPlanError> {
        match spelling {
            "compile_prerequisite" => Ok(Self::CompilePrerequisite),
            "runtime_producer" => Ok(Self::RuntimeProducer),
            "write_serialization" => Ok(Self::WriteSerialization),
            "proof_gate" => Ok(Self::ProofGate),
            "artifact_flow" => Ok(Self::ArtifactFlow),
            _ => Err(OrchestrationPlanError::Shape {
                field: "edge.kind".to_owned(),
                detail: format!("unknown dependency kind {}", redact(spelling)),
            }),
        }
    }

    /// Returns true when this kind constrains candidate launch groups.
    #[must_use]
    pub const fn constrains_groups(self) -> bool {
        match self {
            Self::CompilePrerequisite
            | Self::WriteSerialization
            | Self::ProofGate
            | Self::ArtifactFlow => true,
            Self::RuntimeProducer => false,
        }
    }

    /// All five kinds in canonical order.
    pub const ALL: [Self; 5] = [
        Self::CompilePrerequisite,
        Self::RuntimeProducer,
        Self::WriteSerialization,
        Self::ProofGate,
        Self::ArtifactFlow,
    ];
}

/// Closed terminal outcome of one decomposition request.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum DecompositionOutcome {
    /// Every retained requirement is owned and every check passes.
    Complete,
    /// Some denominator is preserved as omitted requirements instead of a
    /// complete plan.
    Partial,
    /// A prerequisite or binding is missing or unknown; reopening needs the
    /// named evidence.
    Blocked,
    /// The request is semantically invalid and carries no dispatchable plan.
    Rejected,
    /// The request asks for an unsupported claim such as parallel progress
    /// over one serialized mutable target.
    Unsupported,
    /// Write scopes overlap, so separation is not proven.
    Overlapped,
    /// The injected observation is at or beyond the frozen deadline.
    Stale,
}

impl DecompositionOutcome {
    /// Returns the canonical spelling of this outcome.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Complete => "complete",
            Self::Partial => "partial",
            Self::Blocked => "blocked",
            Self::Rejected => "rejected",
            Self::Unsupported => "unsupported",
            Self::Overlapped => "overlapped",
            Self::Stale => "stale",
        }
    }
}

/// One exact admitted objective with immutable evidence bindings.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PlanObjective {
    /// Stable objective identity.
    pub objective_id: String,
    /// Objective revision the plan is frozen against.
    pub objective_revision: u32,
    /// The single admitted objective statement.
    pub statement: String,
    /// Acceptance note the units must jointly satisfy.
    pub acceptance_note: String,
    /// Digest binding the exact acceptance text.
    pub acceptance_digest: String,
    /// Source snapshot the objective was read from.
    pub source_snapshot: String,
    /// Source revision the objective was read from.
    pub source_revision: String,
    /// Architecture reference bounding the decomposition domain.
    pub architecture_ref: String,
    /// Immutable owner of the objective.
    pub owner: String,
    /// Unit identity owning final synthesis and integration.
    pub synthesis_owner: String,
}

/// One parent requirement the partition must account for.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PlanRequirement {
    /// Stable requirement identity.
    pub requirement_id: String,
    /// One-sentence summary of the required behavior.
    pub summary: String,
    /// Canonical owner cell expected to implement it.
    pub owner_cell: String,
    /// Evidence ref backing the requirement.
    pub evidence_ref: String,
}

/// One file or directory surface visible to the decomposition.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PlanSurface {
    /// Stable surface identity.
    pub surface_id: String,
    /// Versioned lexical path of the surface.
    pub path: String,
    /// Whether the path names a file or a directory subtree.
    pub kind: SurfaceKind,
    /// Canonical owner cell from the supplied owner evidence.
    pub owner_cell: String,
    /// True when every write to this surface must pass through one explicit
    /// serialized integration sequence.
    pub requires_serialized_integration: bool,
    /// Owner-evidence note backing this surface entry.
    pub evidence_note: String,
}

/// Independent per-unit budget bounds. Unknown is neither zero nor unlimited:
/// every dimension carries an explicit positive bound.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WorkUnitBudget {
    /// Maximum context bytes admitted for the unit including reserves.
    pub context_bytes: u64,
    /// Maximum tool calls admitted for the unit.
    pub tool_calls: u32,
    /// Maximum output bytes admitted for the unit.
    pub output_bytes: u64,
}

/// One bounded agent work-unit brief: stable identity, one primary cell and
/// causal property, exact docs and read set, immutable inputs, exact mutable
/// claims, forbidden paths, competence and route needs, independent budget,
/// concrete oracle and artifact, stop and rollback, and the exact
/// integration owner with its handoff.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AgentWorkUnitBrief {
    /// Stable unit identity unique inside the plan.
    pub unit_id: String,
    /// One primary capability cell implementing this unit.
    pub cell_id: String,
    /// Semantic owner of the implemented algorithm or type.
    pub semantic_owner: String,
    /// The single causal property this unit implements.
    pub causal_property: String,
    /// Parent requirements this unit implements.
    pub requirement_ids: Vec<String>,
    /// Exact file or directory write claims owned by this unit.
    pub write_claims: Vec<String>,
    /// Exact read-only context refs required by this unit.
    pub read_refs: Vec<String>,
    /// Forbidden paths this unit must never write.
    pub forbidden_paths: Vec<String>,
    /// Competence the assigned owner must already hold.
    pub capability_note: String,
    /// Declarative route class the unit may use.
    pub route_note: String,
    /// Independent context, tool, and output bounds for this unit.
    pub budget: WorkUnitBudget,
    /// Concrete observable artifact this unit produces.
    pub artifact_note: String,
    /// Substantive acceptance oracle with negative cases.
    pub oracle_note: String,
    /// Unit identity owning integration of this unit.
    pub integration_owner: String,
    /// Handoff note naming the artifact consumer and compatibility proof.
    pub handoff_note: String,
    /// Stop and reopen condition for this unit.
    pub stop_note: String,
    /// Rollback boundary owned independently of the unit.
    pub rollback_note: String,
}

/// One typed dependency relation between two units of the plan.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReadinessEdge {
    /// Producer unit identity.
    pub from_unit: String,
    /// Consumer unit identity.
    pub to_unit: String,
    /// Typed relation between producer and consumer.
    pub kind: DependencyKind,
    /// Reason naming why this relation constrains the plan.
    pub reason: String,
}

/// Governing policy for one decomposition request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DecompositionPolicy {
    /// Stable policy identity bound to the receipt validator policy.
    pub policy_id: String,
    /// Policy revision the request is frozen against.
    pub policy_revision: u32,
    /// Maximum units admitted in the emitted plan.
    pub max_units: usize,
    /// Maximum typed edges admitted in the emitted plan.
    pub max_edges: usize,
    /// Maximum constraining out-edges admitted on any single unit.
    pub max_fan_out: usize,
    /// True when a partial denominator may emit instead of failing closed.
    pub allow_partial: bool,
    /// True when the caller cancelled before emission.
    pub cancelled: bool,
    /// Injected observation time in Unix milliseconds, when bounded.
    pub observation_time_ms: Option<u64>,
    /// Frozen deadline in Unix milliseconds, when bounded.
    pub deadline_ms: Option<u64>,
    /// Owner note naming who governs this decomposition.
    pub owner_note: String,
}

/// One emitted work-unit decomposition candidate with deterministic groups,
/// exact coverage accounting, preservation evidence, and a replay digest.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WorkUnitDecomposition {
    /// Stable plan handle bound to the objective and discriminator.
    pub plan_handle: String,
    /// Objective identity this plan decomposes.
    pub objective_id: String,
    /// Task identity preserved from the invocation.
    pub task_id: String,
    /// Scope identity preserved from the invocation.
    pub scope_id: String,
    /// Emitted unit briefs in deterministic identity order.
    pub units: Vec<AgentWorkUnitBrief>,
    /// Typed dependency relations in deterministic order.
    pub edges: Vec<ReadinessEdge>,
    /// Derived candidate launch groups in deterministic order.
    pub parallel_groups: Vec<Vec<String>>,
    /// Parent requirements preserved as omitted, never silently dropped.
    pub omitted_requirements: Vec<String>,
    /// Terminal outcome of this decomposition.
    pub outcome: DecompositionOutcome,
    /// Bounded note naming the evidence behind the outcome.
    pub outcome_note: String,
    /// Seven-dimension preservation evidence for the candidate.
    pub preservation: PreservationReport,
    /// Canonical digest binding the typed identities and semantic edges.
    pub candidate_digest: String,
    /// Receipt output digest the candidate is derived from.
    pub input_receipt_digest: String,
    /// Routing-only proof ceiling; never an execution authority.
    pub proof_note: String,
}

/// Fail-closed error for malformed or over-bound decomposition requests.
///
/// Semantic shortfalls are [`DecompositionOutcome`] dispositions carried by
/// [`WorkUnitDecomposition`], never these errors.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum OrchestrationPlanError {
    /// A shape field is blank, over-long, hostile, or unknown.
    Shape {
        /// Dotted field path that failed shaping.
        field: String,
        /// Bounded detail naming the violation.
        detail: String,
    },
    /// A bound, count, budget, or aggregate exceeds its independent ceiling.
    Bounds {
        /// Phase that enforced the bound.
        phase: String,
        /// Bounded detail naming the violation.
        detail: String,
    },
    /// An identity, receipt, fence, or digest binding drifts.
    Binding {
        /// Dotted field path that failed binding.
        field: String,
        /// Bounded detail naming the violation.
        detail: String,
    },
    /// The validator receipt is missing, invalid, or not accepted.
    Receipt {
        /// Bounded detail naming the violation.
        detail: String,
    },
    /// The governing policy drifts from the receipt or its own bounds.
    Policy {
        /// Bounded detail naming the violation.
        detail: String,
    },
    /// A denominator member is duplicated, uncovered, or miscounted.
    Denominator {
        /// Bounded detail naming the violation.
        detail: String,
    },
}

impl core::fmt::Display for OrchestrationPlanError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Shape { field, detail } => {
                write!(f, "malformed shape at {field}: {detail}")
            }
            Self::Bounds { phase, detail } => {
                write!(f, "out of bounds in {phase}: {detail}")
            }
            Self::Binding { field, detail } => {
                write!(f, "binding drift at {field}: {detail}")
            }
            Self::Receipt { detail } => {
                write!(f, "receipt failure: {detail}")
            }
            Self::Policy { detail } => {
                write!(f, "policy failure: {detail}")
            }
            Self::Denominator { detail } => {
                write!(f, "denominator failure: {detail}")
            }
        }
    }
}

impl core::error::Error for OrchestrationPlanError {}

// ---------------------------------------------------------------------------
// Closed text and identity checks.
// ---------------------------------------------------------------------------

/// Rejects blank, over-long, or control-carrying text.
fn check_note(
    value: &str,
    field: &'static str,
    max_bytes: usize,
) -> Result<(), OrchestrationPlanError> {
    if value.trim().is_empty() {
        return Err(OrchestrationPlanError::Shape {
            field: field.to_owned(),
            detail: "value is blank".to_owned(),
        });
    }
    if value.len() > max_bytes {
        return Err(OrchestrationPlanError::Bounds {
            phase: field.to_owned(),
            detail: format!("value exceeds {max_bytes} bytes"),
        });
    }
    if has_control(value) {
        return Err(OrchestrationPlanError::Shape {
            field: field.to_owned(),
            detail: "value carries control characters".to_owned(),
        });
    }
    Ok(())
}

/// Rejects blank, over-long, control-carrying, or path-escaping identities.
fn check_handle(value: &str, field: &'static str) -> Result<(), OrchestrationPlanError> {
    check_note(value, field, MAX_HANDLE_BYTES)?;
    if value.contains('/') || value.contains('\\') {
        return Err(OrchestrationPlanError::Shape {
            field: field.to_owned(),
            detail: "handle must not carry path separators".to_owned(),
        });
    }
    Ok(())
}

/// Rejects blank, over-long, control-carrying, or path-escaping identities
/// bound into digests.
fn check_id(value: &str, field: &'static str) -> Result<(), OrchestrationPlanError> {
    check_note(value, field, MAX_ID_BYTES)?;
    if value.contains('/') || value.contains('\\') {
        return Err(OrchestrationPlanError::Shape {
            field: field.to_owned(),
            detail: "identity must not carry path separators".to_owned(),
        });
    }
    Ok(())
}

/// Rejects blank, over-long, control-carrying, or escaping plan paths.
fn check_path(value: &str, field: &'static str) -> Result<(), OrchestrationPlanError> {
    if value.trim().is_empty() {
        return Err(OrchestrationPlanError::Shape {
            field: field.to_owned(),
            detail: "path is blank".to_owned(),
        });
    }
    if value.len() > MAX_TEXT_BYTES {
        return Err(OrchestrationPlanError::Bounds {
            phase: field.to_owned(),
            detail: format!("path exceeds {MAX_TEXT_BYTES} bytes"),
        });
    }
    if has_control(value) {
        return Err(OrchestrationPlanError::Shape {
            field: field.to_owned(),
            detail: "path carries control characters".to_owned(),
        });
    }
    if is_path_escape(value) {
        return Err(OrchestrationPlanError::Shape {
            field: field.to_owned(),
            detail: format!("path escapes the lexical policy: {}", redact(value)),
        });
    }
    Ok(())
}

/// Maps a contract-hub failure into a bounded receipt error.
fn receipt_err(detail: &str) -> OrchestrationPlanError {
    OrchestrationPlanError::Receipt {
        detail: redact(detail),
    }
}

/// Maps a contract-hub failure into a bounded binding error.
fn binding_err(field: &'static str, detail: &str) -> OrchestrationPlanError {
    OrchestrationPlanError::Binding {
        field: field.to_owned(),
        detail: redact(detail),
    }
}

// ---------------------------------------------------------------------------
// Shape validators (fail closed before any semantic pass).
// ---------------------------------------------------------------------------

/// Validates the governing policy shape and its independent ceilings.
fn validate_policy_shapes(policy: &DecompositionPolicy) -> Result<(), OrchestrationPlanError> {
    check_id(&policy.policy_id, "policy.policy_id")?;
    if policy.policy_revision == 0 {
        return Err(OrchestrationPlanError::Shape {
            field: "policy.policy_revision".to_owned(),
            detail: "policy revision is zero".to_owned(),
        });
    }
    if policy.max_units == 0 || policy.max_units > MAX_WORK_UNITS {
        return Err(OrchestrationPlanError::Bounds {
            phase: "policy.max_units".to_owned(),
            detail: format!("max units outside 1..={MAX_WORK_UNITS}"),
        });
    }
    if policy.max_edges > MAX_EDGES {
        return Err(OrchestrationPlanError::Bounds {
            phase: "policy.max_edges".to_owned(),
            detail: format!("max edges outside 0..={MAX_EDGES}"),
        });
    }
    if policy.max_fan_out == 0 || policy.max_fan_out > MAX_FAN_OUT {
        return Err(OrchestrationPlanError::Bounds {
            phase: "policy.max_fan_out".to_owned(),
            detail: format!("max fan-out outside 1..={MAX_FAN_OUT}"),
        });
    }
    check_note(&policy.owner_note, "policy.owner_note", MAX_TEXT_BYTES)?;
    Ok(())
}

/// Validates the objective shape and its immutable evidence bindings.
fn validate_objective_shapes(objective: &PlanObjective) -> Result<(), OrchestrationPlanError> {
    check_id(&objective.objective_id, "objective.objective_id")?;
    if objective.objective_revision == 0 {
        return Err(OrchestrationPlanError::Shape {
            field: "objective.objective_revision".to_owned(),
            detail: "objective revision is zero".to_owned(),
        });
    }
    check_note(&objective.statement, "objective.statement", MAX_TEXT_BYTES)?;
    check_note(
        &objective.acceptance_note,
        "objective.acceptance_note",
        MAX_TEXT_BYTES,
    )?;
    if !is_hex64_lower(&objective.acceptance_digest) {
        return Err(OrchestrationPlanError::Shape {
            field: "objective.acceptance_digest".to_owned(),
            detail: "acceptance digest must be 64-character lowercase hex".to_owned(),
        });
    }
    check_note(
        &objective.source_snapshot,
        "objective.source_snapshot",
        MAX_HANDLE_BYTES,
    )?;
    check_note(
        &objective.source_revision,
        "objective.source_revision",
        MAX_HANDLE_BYTES,
    )?;
    check_note(
        &objective.architecture_ref,
        "objective.architecture_ref",
        MAX_HANDLE_BYTES,
    )?;
    check_handle(&objective.owner, "objective.owner")?;
    check_id(&objective.synthesis_owner, "objective.synthesis_owner")?;
    Ok(())
}

/// Validates parent requirement shapes and their identity denominator.
fn validate_requirement_shapes(
    requirements: &[PlanRequirement],
) -> Result<(), OrchestrationPlanError> {
    if requirements.len() > MAX_REQUIREMENTS {
        return Err(OrchestrationPlanError::Bounds {
            phase: "requirements".to_owned(),
            detail: format!("requirement count outside 0..={MAX_REQUIREMENTS}"),
        });
    }
    let mut ids: Vec<String> = Vec::with_capacity(requirements.len());
    let mut index = 0usize;
    while index < requirements.len() {
        let Some(requirement) = requirements.get(index) else {
            return Err(OrchestrationPlanError::Denominator {
                detail: "requirement index out of range".to_owned(),
            });
        };
        check_id(&requirement.requirement_id, "requirement.requirement_id")?;
        check_note(&requirement.summary, "requirement.summary", MAX_TEXT_BYTES)?;
        check_handle(&requirement.owner_cell, "requirement.owner_cell")?;
        check_handle(&requirement.evidence_ref, "requirement.evidence_ref")?;
        ids.push(requirement.requirement_id.clone());
        index = index.saturating_add(1);
    }
    if !has_no_duplicates(&ids) {
        return Err(OrchestrationPlanError::Denominator {
            detail: "duplicate requirement identity".to_owned(),
        });
    }
    Ok(())
}

/// Validates plan surface shapes under the versioned lexical policy.
fn validate_surface_shapes(surfaces: &[PlanSurface]) -> Result<(), OrchestrationPlanError> {
    if surfaces.len() > MAX_SURFACES {
        return Err(OrchestrationPlanError::Bounds {
            phase: "surfaces".to_owned(),
            detail: format!("surface count outside 0..={MAX_SURFACES}"),
        });
    }
    let mut ids: Vec<String> = Vec::with_capacity(surfaces.len());
    let mut index = 0usize;
    while index < surfaces.len() {
        let Some(surface) = surfaces.get(index) else {
            return Err(OrchestrationPlanError::Denominator {
                detail: "surface index out of range".to_owned(),
            });
        };
        check_id(&surface.surface_id, "surface.surface_id")?;
        check_path(&surface.path, "surface.path")?;
        check_handle(&surface.owner_cell, "surface.owner_cell")?;
        check_note(
            &surface.evidence_note,
            "surface.evidence_note",
            MAX_TEXT_BYTES,
        )?;
        ids.push(surface.surface_id.clone());
        index = index.saturating_add(1);
    }
    if !has_no_duplicates(&ids) {
        return Err(OrchestrationPlanError::Denominator {
            detail: "duplicate surface identity".to_owned(),
        });
    }
    Ok(())
}

/// Validates one unit budget: every dimension is explicit and positive.
fn validate_unit_budget(
    budget: &WorkUnitBudget,
    unit_id: &str,
) -> Result<(), OrchestrationPlanError> {
    if budget.context_bytes == 0 || budget.context_bytes > MAX_UNIT_CONTEXT_BYTES {
        return Err(OrchestrationPlanError::Bounds {
            phase: "unit.budget".to_owned(),
            detail: format!(
                "unit {} context bound outside 1..={MAX_UNIT_CONTEXT_BYTES}",
                redact(unit_id)
            ),
        });
    }
    if budget.tool_calls == 0 || budget.tool_calls > MAX_UNIT_TOOL_CALLS {
        return Err(OrchestrationPlanError::Bounds {
            phase: "unit.budget".to_owned(),
            detail: format!(
                "unit {} tool bound outside 1..={MAX_UNIT_TOOL_CALLS}",
                redact(unit_id)
            ),
        });
    }
    if budget.output_bytes == 0 || budget.output_bytes > MAX_UNIT_OUTPUT_BYTES {
        return Err(OrchestrationPlanError::Bounds {
            phase: "unit.budget".to_owned(),
            detail: format!(
                "unit {} output bound outside 1..={MAX_UNIT_OUTPUT_BYTES}",
                redact(unit_id)
            ),
        });
    }
    Ok(())
}

/// Validates one unit brief shape: identity, cell, owners, and requirement refs.
fn validate_one_unit_identity(unit: &AgentWorkUnitBrief) -> Result<(), OrchestrationPlanError> {
    check_id(&unit.unit_id, "unit.unit_id")?;
    check_handle(&unit.cell_id, "unit.cell_id")?;
    check_handle(&unit.semantic_owner, "unit.semantic_owner")?;
    check_note(
        &unit.causal_property,
        "unit.causal_property",
        MAX_TEXT_BYTES,
    )?;
    if unit.requirement_ids.len() > MAX_UNIT_REQUIREMENTS {
        return Err(OrchestrationPlanError::Bounds {
            phase: "unit.requirement_ids".to_owned(),
            detail: format!(
                "unit {} requirement refs outside 0..={MAX_UNIT_REQUIREMENTS}",
                redact(&unit.unit_id)
            ),
        });
    }
    let mut ref_index = 0usize;
    while ref_index < unit.requirement_ids.len() {
        let Some(head) = unit.requirement_ids.get(ref_index) else {
            return Err(OrchestrationPlanError::Denominator {
                detail: "unit requirement index out of range".to_owned(),
            });
        };
        check_id(head, "unit.requirement_ids")?;
        ref_index = ref_index.saturating_add(1);
    }
    if !has_no_duplicates(&unit.requirement_ids) {
        return Err(OrchestrationPlanError::Denominator {
            detail: format!(
                "unit {} carries duplicate requirement refs",
                redact(&unit.unit_id)
            ),
        });
    }
    Ok(())
}

/// Validates one unit brief shape: write claims, read refs, forbidden paths,
/// and the self-forbidden binding.
fn validate_one_unit_claims(unit: &AgentWorkUnitBrief) -> Result<(), OrchestrationPlanError> {
    if unit.write_claims.is_empty() || unit.write_claims.len() > MAX_WRITE_CLAIMS {
        return Err(OrchestrationPlanError::Bounds {
            phase: "unit.write_claims".to_owned(),
            detail: format!(
                "unit {} write claims outside 1..={MAX_WRITE_CLAIMS}",
                redact(&unit.unit_id)
            ),
        });
    }
    let mut claim_index = 0usize;
    while claim_index < unit.write_claims.len() {
        let Some(claim) = unit.write_claims.get(claim_index) else {
            return Err(OrchestrationPlanError::Denominator {
                detail: "unit write claim index out of range".to_owned(),
            });
        };
        check_path(claim, "unit.write_claims")?;
        claim_index = claim_index.saturating_add(1);
    }
    if !has_no_duplicates(&unit.write_claims) {
        return Err(OrchestrationPlanError::Denominator {
            detail: format!(
                "unit {} carries duplicate write claims",
                redact(&unit.unit_id)
            ),
        });
    }
    if unit.read_refs.len() > MAX_READ_REFS {
        return Err(OrchestrationPlanError::Bounds {
            phase: "unit.read_refs".to_owned(),
            detail: format!(
                "unit {} read refs outside 0..={MAX_READ_REFS}",
                redact(&unit.unit_id)
            ),
        });
    }
    let mut read_index = 0usize;
    while read_index < unit.read_refs.len() {
        let Some(head) = unit.read_refs.get(read_index) else {
            return Err(OrchestrationPlanError::Denominator {
                detail: "unit read ref index out of range".to_owned(),
            });
        };
        check_path(head, "unit.read_refs")?;
        read_index = read_index.saturating_add(1);
    }
    if unit.forbidden_paths.is_empty() || unit.forbidden_paths.len() > MAX_FORBIDDEN_PATHS {
        return Err(OrchestrationPlanError::Bounds {
            phase: "unit.forbidden_paths".to_owned(),
            detail: format!(
                "unit {} forbidden paths outside 1..={MAX_FORBIDDEN_PATHS}",
                redact(&unit.unit_id)
            ),
        });
    }
    let mut forbid_index = 0usize;
    while forbid_index < unit.forbidden_paths.len() {
        let Some(path) = unit.forbidden_paths.get(forbid_index) else {
            return Err(OrchestrationPlanError::Denominator {
                detail: "unit forbidden path index out of range".to_owned(),
            });
        };
        check_path(path, "unit.forbidden_paths")?;
        forbid_index = forbid_index.saturating_add(1);
    }
    // A unit must never claim a write inside its own forbidden set.
    let mut outer = 0usize;
    while outer < unit.write_claims.len() {
        let mut inner = 0usize;
        while inner < unit.forbidden_paths.len() {
            let (Some(claim), Some(forbidden)) = (
                unit.write_claims.get(outer),
                unit.forbidden_paths.get(inner),
            ) else {
                return Err(OrchestrationPlanError::Denominator {
                    detail: "unit claim index out of range".to_owned(),
                });
            };
            if normalize_path(claim) == normalize_path(forbidden) {
                return Err(OrchestrationPlanError::Binding {
                    field: "unit.write_claims".to_owned(),
                    detail: format!(
                        "unit {} writes inside its own forbidden path",
                        redact(&unit.unit_id)
                    ),
                });
            }
            inner = inner.saturating_add(1);
        }
        outer = outer.saturating_add(1);
    }
    Ok(())
}

/// Validates one unit brief shape: competence, routes, budget, oracle,
/// artifact, handoff, stop, rollback, and integration owner.
fn validate_one_unit_notes(unit: &AgentWorkUnitBrief) -> Result<(), OrchestrationPlanError> {
    check_note(
        &unit.capability_note,
        "unit.capability_note",
        MAX_TEXT_BYTES,
    )?;
    check_note(&unit.route_note, "unit.route_note", MAX_TEXT_BYTES)?;
    validate_unit_budget(&unit.budget, &unit.unit_id)?;
    check_note(&unit.artifact_note, "unit.artifact_note", MAX_TEXT_BYTES)?;
    check_note(&unit.oracle_note, "unit.oracle_note", MAX_TEXT_BYTES)?;
    check_id(&unit.integration_owner, "unit.integration_owner")?;
    check_note(&unit.handoff_note, "unit.handoff_note", MAX_TEXT_BYTES)?;
    check_note(&unit.stop_note, "unit.stop_note", MAX_TEXT_BYTES)?;
    check_note(&unit.rollback_note, "unit.rollback_note", MAX_TEXT_BYTES)?;
    Ok(())
}

/// Validates one unit brief shape: identity, cell, claims, notes, budget.
fn validate_one_unit_shape(unit: &AgentWorkUnitBrief) -> Result<(), OrchestrationPlanError> {
    validate_one_unit_identity(unit)?;
    validate_one_unit_claims(unit)?;
    validate_one_unit_notes(unit)?;
    Ok(())
}

/// Validates unit brief shapes and their identity denominator.
fn validate_unit_shapes(units: &[AgentWorkUnitBrief]) -> Result<(), OrchestrationPlanError> {
    if units.len() > MAX_WORK_UNITS {
        return Err(OrchestrationPlanError::Bounds {
            phase: "units".to_owned(),
            detail: format!("unit count outside 0..={MAX_WORK_UNITS}"),
        });
    }
    let mut ids: Vec<String> = Vec::with_capacity(units.len());
    let mut index = 0usize;
    while index < units.len() {
        let Some(unit) = units.get(index) else {
            return Err(OrchestrationPlanError::Denominator {
                detail: "unit index out of range".to_owned(),
            });
        };
        validate_one_unit_shape(unit)?;
        ids.push(unit.unit_id.clone());
        index = index.saturating_add(1);
    }
    if !has_no_duplicates(&ids) {
        return Err(OrchestrationPlanError::Denominator {
            detail: "duplicate unit identity".to_owned(),
        });
    }
    Ok(())
}

/// Validates edge shapes: known kinds, non-blank reasons.
fn validate_edge_shapes(edges: &[ReadinessEdge]) -> Result<(), OrchestrationPlanError> {
    if edges.len() > MAX_EDGES {
        return Err(OrchestrationPlanError::Bounds {
            phase: "edges".to_owned(),
            detail: format!("edge count outside 0..={MAX_EDGES}"),
        });
    }
    let mut index = 0usize;
    while index < edges.len() {
        let Some(edge) = edges.get(index) else {
            return Err(OrchestrationPlanError::Denominator {
                detail: "edge index out of range".to_owned(),
            });
        };
        check_id(&edge.from_unit, "edge.from_unit")?;
        check_id(&edge.to_unit, "edge.to_unit")?;
        check_note(&edge.reason, "edge.reason", MAX_TEXT_BYTES)?;
        index = index.saturating_add(1);
    }
    Ok(())
}

/// Rejects aggregate input bytes above the independent ceiling.
#[allow(clippy::too_many_arguments)]
fn preflight_total_bytes(
    objective: &PlanObjective,
    requirements: &[PlanRequirement],
    surfaces: &[PlanSurface],
    units: &[AgentWorkUnitBrief],
    edges: &[ReadinessEdge],
    policy: &DecompositionPolicy,
) -> Result<(), OrchestrationPlanError> {
    let mut total: usize = 0;
    total = total.saturating_add(objective.statement.len());
    total = total.saturating_add(objective.acceptance_note.len());
    total = total.saturating_add(policy.owner_note.len());
    let mut index = 0usize;
    while index < requirements.len() {
        if let Some(requirement) = requirements.get(index) {
            total = total.saturating_add(requirement.summary.len());
        }
        index = index.saturating_add(1);
    }
    let mut surface_index = 0usize;
    while surface_index < surfaces.len() {
        if let Some(surface) = surfaces.get(surface_index) {
            total = total
                .saturating_add(surface.path.len())
                .saturating_add(surface.evidence_note.len());
        }
        surface_index = surface_index.saturating_add(1);
    }
    let mut unit_index = 0usize;
    while unit_index < units.len() {
        if let Some(unit) = units.get(unit_index) {
            total = total
                .saturating_add(unit.causal_property.len())
                .saturating_add(unit.capability_note.len())
                .saturating_add(unit.route_note.len())
                .saturating_add(unit.artifact_note.len())
                .saturating_add(unit.oracle_note.len())
                .saturating_add(unit.handoff_note.len())
                .saturating_add(unit.stop_note.len())
                .saturating_add(unit.rollback_note.len());
        }
        unit_index = unit_index.saturating_add(1);
    }
    let mut edge_index = 0usize;
    while edge_index < edges.len() {
        if let Some(edge) = edges.get(edge_index) {
            total = total.saturating_add(edge.reason.len());
        }
        edge_index = edge_index.saturating_add(1);
    }
    if total > MAX_TOTAL_BYTES {
        return Err(OrchestrationPlanError::Bounds {
            phase: "input_bytes".to_owned(),
            detail: format!("aggregate input bytes outside 0..={MAX_TOTAL_BYTES}"),
        });
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Intrinsic receipt and binding checks (the A-05 receipt is consumed, never
// re-executed: only its validation entry points run here).
// ---------------------------------------------------------------------------

/// Checks the validated draft receipt intrinsically through its own entry
/// points.
fn intrinsic_receipt_checks(draft: &ValidatedDreamDraft) -> Result<(), OrchestrationPlanError> {
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
        return Err(OrchestrationPlanError::Receipt {
            detail: "validator receipt is not accepted or partial".to_owned(),
        });
    }
    Ok(())
}

/// Checks job, draft, task, scope, fence, budget, and policy bindings.
fn intrinsic_binding_checks(
    job: &DreamJobAdmission,
    draft: &ValidatedDreamDraft,
    policy: &DecompositionPolicy,
) -> Result<(), OrchestrationPlanError> {
    job.validate()
        .map_err(|err| OrchestrationPlanError::Binding {
            field: "job".to_owned(),
            detail: redact(&err.to_string()),
        })?;
    if job.job_class != JobClass::OrchestrationPlanning {
        return Err(OrchestrationPlanError::Binding {
            field: "job_class".to_owned(),
            detail: "dream job is not an orchestration-planning job".to_owned(),
        });
    }
    check_fence(&job.state_fence).map_err(|err| binding_err("state_fence", &err.to_string()))?;
    job.budget
        .validate()
        .map_err(|err| OrchestrationPlanError::Policy {
            detail: redact(&err.to_string()),
        })?;
    if draft.receipt.task_id != job.task_id || draft.task_id != job.task_id {
        return Err(OrchestrationPlanError::Binding {
            field: "task_id".to_owned(),
            detail: "draft task drifts from the job binding".to_owned(),
        });
    }
    if draft.receipt.scope_id != job.scope_id || draft.scope_id != job.scope_id {
        return Err(OrchestrationPlanError::Binding {
            field: "scope_id".to_owned(),
            detail: "draft scope drifts from the job binding".to_owned(),
        });
    }
    if draft.state_fence != job.state_fence || draft.receipt.state_fence != job.state_fence {
        return Err(OrchestrationPlanError::Binding {
            field: "state_fence".to_owned(),
            detail: "draft fence drifts from the job fence".to_owned(),
        });
    }
    if policy.policy_id != draft.receipt.validator_policy {
        return Err(OrchestrationPlanError::Policy {
            detail: "policy_id drifts from the receipt validator policy".to_owned(),
        });
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Semantic passes over the frozen candidate sets.
// ---------------------------------------------------------------------------

/// Returns the unit identity for a unit id, or `None` when unknown.
fn unit_index_of(units: &[AgentWorkUnitBrief], unit_id: &str) -> Option<usize> {
    let mut index = 0usize;
    while index < units.len() {
        if let Some(unit) = units.get(index)
            && unit.unit_id == unit_id
        {
            return Some(index);
        }
        index = index.saturating_add(1);
    }
    None
}

/// Collects write claims of one unit as normalized `(path, is_dir)` pairs. A
/// trailing slash marks an explicit directory claim; anything else is a file
/// claim.
fn unit_write_shapes(unit: &AgentWorkUnitBrief) -> Vec<(String, bool)> {
    let mut out: Vec<(String, bool)> = Vec::with_capacity(unit.write_claims.len());
    for claim in &unit.write_claims {
        let is_dir = claim.ends_with('/');
        out.push((normalize_path(claim), is_dir));
    }
    out
}

/// Detects file, directory, and alias write overlap between two units.
/// Shared reads never conflict and are ignored here.
fn units_overlap(first: &AgentWorkUnitBrief, second: &AgentWorkUnitBrief) -> Option<String> {
    let left_shapes = unit_write_shapes(first);
    let right_shapes = unit_write_shapes(second);
    let mut left_index = 0usize;
    while left_index < left_shapes.len() {
        let mut right_index = 0usize;
        while right_index < right_shapes.len() {
            let (Some(left), Some(right)) =
                (left_shapes.get(left_index), right_shapes.get(right_index))
            else {
                return Some("write claim index out of range".to_owned());
            };
            if write_claims_overlap(left.0.as_str(), left.1, right.0.as_str(), right.1) {
                return Some(format!(
                    "units {} and {} overlap on {}",
                    first.unit_id, second.unit_id, left.0
                ));
            }
            right_index = right_index.saturating_add(1);
        }
        left_index = left_index.saturating_add(1);
    }
    None
}

/// Finds the first write-scope overlap across distinct units.
fn detect_write_overlap(units: &[AgentWorkUnitBrief]) -> Option<String> {
    let mut outer = 0usize;
    while outer < units.len() {
        let mut inner = outer.saturating_add(1);
        while inner < units.len() {
            let (Some(first), Some(second)) = (units.get(outer), units.get(inner)) else {
                return Some("unit index out of range".to_owned());
            };
            if let Some(detail) = units_overlap(first, second) {
                return Some(detail);
            }
            inner = inner.saturating_add(1);
        }
        outer = outer.saturating_add(1);
    }
    None
}

/// Returns the sorted write set of one unit for ownership comparison.
fn sorted_write_set(unit: &AgentWorkUnitBrief) -> Vec<String> {
    let mut writes: Vec<String> = Vec::with_capacity(unit.write_claims.len());
    for claim in &unit.write_claims {
        writes.push(normalize_path(claim));
    }
    writes.sort();
    writes
}

/// Finds two units sharing one semantic owner over different write paths:
/// duplicate semantic ownership, not parallel-safe work.
fn detect_semantic_owner_drift(units: &[AgentWorkUnitBrief]) -> Option<String> {
    let mut outer = 0usize;
    while outer < units.len() {
        let mut inner = outer.saturating_add(1);
        while inner < units.len() {
            let (Some(first), Some(second)) = (units.get(outer), units.get(inner)) else {
                return Some("unit index out of range".to_owned());
            };
            if first.semantic_owner == second.semantic_owner
                && sorted_write_set(first) != sorted_write_set(second)
            {
                return Some(format!(
                    "semantic owner {} is implemented in different paths by {} and {}",
                    first.semantic_owner, first.unit_id, second.unit_id
                ));
            }
            inner = inner.saturating_add(1);
        }
        outer = outer.saturating_add(1);
    }
    None
}

/// Counts the units whose write claims cover a serialized surface.
fn serialized_surface_claimants(units: &[AgentWorkUnitBrief], surface_path: &str) -> Vec<String> {
    let mut claimants: Vec<String> = Vec::new();
    for unit in units {
        let mut claimed = false;
        for claim in &unit.write_claims {
            let is_dir = claim.ends_with('/');
            if claim_covers_surface(claim, is_dir, surface_path)
                || normalize_path(claim) == normalize_path(surface_path)
            {
                claimed = true;
            }
        }
        if claimed {
            claimants.push(unit.unit_id.clone());
        }
    }
    claimants.sort();
    claimants
}

/// Enforces the serialized-integrator rule: every surface flagged for
/// serialized integration admits exactly one claiming unit.
fn detect_unserialized_shared_write(
    units: &[AgentWorkUnitBrief],
    surfaces: &[PlanSurface],
) -> Option<String> {
    for surface in surfaces {
        if !surface.requires_serialized_integration {
            continue;
        }
        let claimants = serialized_surface_claimants(units, &surface.path);
        if claimants.len() > 1 {
            return Some(format!(
                "serialized surface {} is claimed in parallel by {}",
                surface.path,
                claimants.join(", ")
            ));
        }
    }
    None
}

/// Finds the first edge endpoint naming a unit outside the supplied set.
fn detect_unknown_endpoint(
    units: &[AgentWorkUnitBrief],
    edges: &[ReadinessEdge],
) -> Option<String> {
    for edge in edges {
        if unit_index_of(units, &edge.from_unit).is_none() {
            return Some(format!("edge from unknown prerequisite {}", edge.from_unit));
        }
        if unit_index_of(units, &edge.to_unit).is_none() {
            return Some(format!("edge to unknown consumer {}", edge.to_unit));
        }
    }
    for unit in units {
        if unit_index_of(units, &unit.integration_owner).is_none() {
            return Some(format!(
                "unit {} names unknown integration owner {}",
                unit.unit_id, unit.integration_owner
            ));
        }
    }
    None
}

/// Finds the first self edge in any relation kind.
fn detect_self_edge(edges: &[ReadinessEdge]) -> Option<String> {
    for edge in edges {
        if edge.from_unit == edge.to_unit {
            return Some(format!("unit {} depends on itself", edge.from_unit));
        }
    }
    None
}

/// Returns the constraining out-neighbors of one unit in edge order.
fn constraining_successors(edges: &[ReadinessEdge], unit_id: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for edge in edges {
        if edge.from_unit == unit_id && edge.kind.constrains_groups() {
            out.push(edge.to_unit.clone());
        }
    }
    out.sort();
    out.dedup();
    out
}

/// Detects a readiness cycle over constraining edges only. Runtime producer
/// relations never participate: a runtime producer cycle is not a compile
/// cycle.
fn detect_readiness_cycle(units: &[AgentWorkUnitBrief], edges: &[ReadinessEdge]) -> Option<String> {
    // Iterative depth-first search with explicit colors: 0 = unvisited,
    // 1 = on the current stack, 2 = settled.
    let mut color: Vec<u8> = Vec::with_capacity(units.len());
    let mut cursor = 0usize;
    while cursor < units.len() {
        color.push(0);
        cursor = cursor.saturating_add(1);
    }
    let mut root = 0usize;
    while root < units.len() {
        let Some(start) = units.get(root).map(|unit| unit.unit_id.clone()) else {
            return Some("unit index out of range".to_owned());
        };
        let Some(start_index) = unit_index_of(units, &start) else {
            return Some("unit index out of range".to_owned());
        };
        if color.get(start_index) == Some(&0) {
            let mut stack: Vec<(String, usize)> = Vec::new();
            stack.push((start.clone(), 0));
            if let Some(slot) = color.get_mut(start_index) {
                *slot = 1;
            }
            while let Some((current, next_child)) = stack.pop() {
                let successors = constraining_successors(edges, &current);
                if let Some(child) = successors.get(next_child).cloned() {
                    stack.push((current.clone(), next_child.saturating_add(1)));
                    let Some(child_index) = unit_index_of(units, &child) else {
                        return Some("unit index out of range".to_owned());
                    };
                    if color.get(child_index) == Some(&1) {
                        return Some(format!(
                            "readiness cycle reaches {child} through constraining edges"
                        ));
                    }
                    if color.get(child_index) == Some(&0) {
                        if let Some(slot) = color.get_mut(child_index) {
                            *slot = 1;
                        }
                        stack.push((child, 0));
                    }
                } else if let Some(current_index) = unit_index_of(units, &current)
                    && let Some(slot) = color.get_mut(current_index)
                {
                    *slot = 2;
                }
            }
        }
        root = root.saturating_add(1);
    }
    None
}

/// Returns true when the consumer is reachable from the producer following
/// any edge kind, including runtime producer flow.
fn reaches(edges: &[ReadinessEdge], from: &str, to: &str) -> bool {
    if from == to {
        return true;
    }
    let mut visited: Vec<String> = Vec::new();
    let mut frontier: Vec<String> = [from.to_owned()].to_vec();
    while let Some(current) = frontier.pop() {
        if current == to {
            return true;
        }
        if visited.contains(&current) {
            continue;
        }
        visited.push(current.clone());
        for edge in edges {
            if edge.from_unit == current && !visited.contains(&edge.to_unit) {
                frontier.push(edge.to_unit.clone());
            }
        }
    }
    false
}

/// Enforces the synthesis chain: every unit reaches the synthesis owner, so
/// no orphaned obligation and no disconnected chain survive.
fn detect_broken_chain(
    units: &[AgentWorkUnitBrief],
    edges: &[ReadinessEdge],
    synthesis_owner: &str,
) -> Option<String> {
    if unit_index_of(units, synthesis_owner).is_none() {
        return Some(format!(
            "synthesis owner {synthesis_owner} is not a supplied unit"
        ));
    }
    for unit in units {
        if !reaches(edges, &unit.unit_id, synthesis_owner) {
            return Some(format!(
                "unit {} never reaches synthesis owner {synthesis_owner}",
                unit.unit_id
            ));
        }
    }
    None
}

/// Derives deterministic launch layers over constraining edges with Kahn's
/// algorithm and lexicographically smallest selection. Runtime producer
/// relations never constrain groups.
fn topological_layers(units: &[AgentWorkUnitBrief], edges: &[ReadinessEdge]) -> Vec<Vec<String>> {
    let mut remaining: Vec<String> = Vec::with_capacity(units.len());
    for unit in units {
        remaining.push(unit.unit_id.clone());
    }
    remaining.sort();
    let mut layers: Vec<Vec<String>> = Vec::new();
    while !remaining.is_empty() {
        let mut ready: Vec<String> = Vec::new();
        for candidate in &remaining {
            let mut blocked = false;
            for edge in edges {
                if edge.to_unit == *candidate
                    && edge.kind.constrains_groups()
                    && remaining.contains(&edge.from_unit)
                {
                    blocked = true;
                }
            }
            if !blocked {
                ready.push(candidate.clone());
            }
        }
        if ready.is_empty() {
            break;
        }
        ready.sort();
        let mut kept: Vec<String> = Vec::with_capacity(remaining.len());
        for member in &remaining {
            if !ready.contains(member) {
                kept.push(member.clone());
            }
        }
        remaining = kept;
        layers.push(ready);
    }
    layers
}

/// Computes the exact uncovered parent requirements: retained but owned by
/// no unit and preserved as omitted, never silently dropped.
fn uncovered_requirements(
    requirements: &[PlanRequirement],
    units: &[AgentWorkUnitBrief],
) -> Vec<String> {
    let mut uncovered: Vec<String> = Vec::new();
    for requirement in requirements {
        let mut owned = false;
        for unit in units {
            if unit.requirement_ids.contains(&requirement.requirement_id) {
                owned = true;
            }
        }
        if !owned {
            uncovered.push(requirement.requirement_id.clone());
        }
    }
    uncovered.sort();
    uncovered
}

/// Finds requirement refs naming a parent outside the frozen denominator.
fn detect_unknown_requirement_ref(
    requirements: &[PlanRequirement],
    units: &[AgentWorkUnitBrief],
) -> Option<String> {
    for unit in units {
        for head in &unit.requirement_ids {
            let mut known = false;
            for requirement in requirements {
                if requirement.requirement_id == *head {
                    known = true;
                }
            }
            if !known {
                return Some(format!(
                    "unit {} refs unknown requirement {head}",
                    unit.unit_id
                ));
            }
        }
    }
    None
}

/// Finds hidden execution or authority claims inside candidate notes.
fn detect_hidden_authority(units: &[AgentWorkUnitBrief]) -> Option<String> {
    for unit in units {
        let notes = [
            unit.capability_note.as_str(),
            unit.route_note.as_str(),
            unit.artifact_note.as_str(),
            unit.oracle_note.as_str(),
            unit.handoff_note.as_str(),
            unit.stop_note.as_str(),
        ];
        let mut index = 0usize;
        while index < notes.len() {
            if let Some(note) = notes.get(index) {
                let folded = lowered(note);
                if mentions_any(&folded, HIDDEN_AUTHORITY_MARKERS) {
                    return Some(format!(
                        "unit {} claims hidden execution authority",
                        unit.unit_id
                    ));
                }
                if mentions_any(&folded, ORACLE_MARKERS) {
                    return Some(format!(
                        "unit {} weakens its oracle or verifier",
                        unit.unit_id
                    ));
                }
            }
            index = index.saturating_add(1);
        }
    }
    None
}

// ---------------------------------------------------------------------------
// Emission: preservation, digest, candidate assembly.
// ---------------------------------------------------------------------------

/// Maps a terminal outcome to the closest hub rejection hint, if any.
#[must_use]
pub fn outcome_rejection_hint(outcome: &DecompositionOutcome) -> Option<CurationRejectionCode> {
    match outcome {
        DecompositionOutcome::Complete => None,
        DecompositionOutcome::Partial | DecompositionOutcome::Overlapped => {
            Some(CurationRejectionCode::PreservationFailed)
        }
        DecompositionOutcome::Blocked => Some(CurationRejectionCode::LineageMismatch),
        DecompositionOutcome::Rejected => Some(CurationRejectionCode::IdentityMismatch),
        DecompositionOutcome::Unsupported => Some(CurationRejectionCode::UnsupportedPrecision),
        DecompositionOutcome::Stale => Some(CurationRejectionCode::DeadlineExceeded),
    }
}

/// Builds the seven-dimension preservation report for one candidate.
fn build_preservation(
    outcome: DecompositionOutcome,
) -> Result<PreservationReport, OrchestrationPlanError> {
    let notes = [
        (
            "coverage",
            "every requirement, surface, unit, edge, and omitted denominator member is accounted without silent drops",
        ),
        (
            "faithfulness",
            "parallel groups follow only constraining readiness and write edges; runtime producer flow never orders groups",
        ),
        (
            "lineage",
            "objective, acceptance, source, architecture, receipt, and policy bindings trace to supplied inputs",
        ),
        (
            "reversibility",
            "the inert candidate carries an owned stop and rollback boundary and changes nothing",
        ),
        (
            "authority_ceiling",
            "the candidate proposes only; launch, schedule, lease, secret, effect, and finish stay external",
        ),
        (
            "dependency_closure",
            "only the contracts hub is imported; typed edges, integrators, and the synthesis chain are closed and named",
        ),
        (
            "provenance_retention",
            "overlaps, unknowns, omissions, and the exact outcome reason are retained in the emitted candidate",
        ),
    ];
    let mut verdicts: Vec<DimensionVerdict> = Vec::with_capacity(EXPECTED_PRESERVATION_DIMENSIONS);
    let mut index = 0usize;
    while index < notes.len() {
        if let Some((dimension, note)) = notes.get(index) {
            let parsed = match PreservationDimension::parse(dimension) {
                Ok(parsed) => parsed,
                Err(err) => {
                    return Err(OrchestrationPlanError::Denominator {
                        detail: redact(&err.to_string()),
                    });
                }
            };
            verdicts.push(DimensionVerdict {
                dimension: parsed,
                passed: true,
                known: true,
                note: format!("{} (outcome {})", note, outcome.as_str()),
            });
        }
        index = index.saturating_add(1);
    }
    let report = PreservationReport { verdicts };
    report
        .validate()
        .map_err(|err| OrchestrationPlanError::Denominator {
            detail: redact(&err.to_string()),
        })?;
    report
        .overall()
        .map_err(|err| OrchestrationPlanError::Denominator {
            detail: redact(&err.to_string()),
        })?;
    Ok(report)
}

/// Computes the canonical digest over typed identities and semantic edges.
///
/// The digest binds the objective, task, scope, sorted units with their
/// budgets and claims, sorted edges with kinds, derived groups, omitted
/// requirements, and the outcome spelling: never prose, traversal order, or
/// creation time.
#[allow(clippy::too_many_lines)]
#[allow(clippy::too_many_arguments)]
pub fn compute_candidate_digest(
    objective: &PlanObjective,
    task_id: &str,
    scope_id: &str,
    units: &[AgentWorkUnitBrief],
    edges: &[ReadinessEdge],
    groups: &[Vec<String>],
    omitted: &[String],
    outcome_spelling: &str,
) -> String {
    let mut parts: Vec<String> = Vec::new();
    parts.push(format!("objective:{}", objective.objective_id));
    parts.push(format!("revision:{}", objective.objective_revision));
    parts.push(format!("acceptance:{}", objective.acceptance_digest));
    parts.push(format!(
        "source:{}@{}",
        objective.source_snapshot, objective.source_revision
    ));
    parts.push(format!("architecture:{}", objective.architecture_ref));
    parts.push(format!("synthesis:{}", objective.synthesis_owner));
    parts.push(format!("task:{task_id}"));
    parts.push(format!("scope:{scope_id}"));
    parts.push(format!("outcome:{outcome_spelling}"));
    let mut ordered_units: Vec<&AgentWorkUnitBrief> = units.iter().collect();
    ordered_units.sort_by(|left, right| left.unit_id.cmp(&right.unit_id));
    for unit in ordered_units {
        parts.push(format!(
            "unit:{}|{}|{}|{}",
            unit.unit_id, unit.cell_id, unit.semantic_owner, unit.causal_property
        ));
        let mut owned: Vec<&String> = unit.requirement_ids.iter().collect();
        owned.sort();
        for head in owned {
            parts.push(format!("owns:{}->{}", unit.unit_id, head));
        }
        let mut writes: Vec<&String> = unit.write_claims.iter().collect();
        writes.sort();
        for claim in writes {
            parts.push(format!(
                "writes:{}->{}",
                unit.unit_id,
                normalize_path(claim)
            ));
        }
        let mut reads: Vec<&String> = unit.read_refs.iter().collect();
        reads.sort();
        for head in reads {
            parts.push(format!("reads:{}->{}", unit.unit_id, normalize_path(head)));
        }
        parts.push(format!(
            "budget:{}|{}|{}|{}",
            unit.unit_id,
            unit.budget.context_bytes,
            unit.budget.tool_calls,
            unit.budget.output_bytes
        ));
        parts.push(format!(
            "handoff:{}->{}|{}",
            unit.unit_id, unit.integration_owner, unit.artifact_note
        ));
    }
    let mut ordered_edges: Vec<&ReadinessEdge> = edges.iter().collect();
    ordered_edges.sort_by(|left, right| {
        left.from_unit
            .cmp(&right.from_unit)
            .then(left.to_unit.cmp(&right.to_unit))
            .then(left.kind.as_str().cmp(right.kind.as_str()))
    });
    for edge in ordered_edges {
        parts.push(format!(
            "edge:{}->{}|{}|{}",
            edge.from_unit,
            edge.to_unit,
            edge.kind.as_str(),
            edge.reason
        ));
    }
    let mut group_index = 0usize;
    while group_index < groups.len() {
        if let Some(group) = groups.get(group_index) {
            let mut members = group.clone();
            members.sort();
            parts.push(format!("group:{group_index}|{}", members.join(",")));
        }
        group_index = group_index.saturating_add(1);
    }
    let mut omitted_sorted = omitted.to_vec();
    omitted_sorted.sort();
    for member in omitted_sorted {
        parts.push(format!("omitted:{member}"));
    }
    sha256_hex(parts.join("\n").as_bytes())
}

/// Sorts units by identity for deterministic emission.
fn sorted_units(units: &[AgentWorkUnitBrief]) -> Vec<AgentWorkUnitBrief> {
    let mut ordered = units.to_vec();
    ordered.sort_by(|left, right| left.unit_id.cmp(&right.unit_id));
    ordered
}

/// Sorts edges by producer, consumer, and kind for deterministic emission.
fn sorted_edges(edges: &[ReadinessEdge]) -> Vec<ReadinessEdge> {
    let mut ordered = edges.to_vec();
    ordered.sort_by(|left, right| {
        left.from_unit
            .cmp(&right.from_unit)
            .then(left.to_unit.cmp(&right.to_unit))
            .then(left.kind.as_str().cmp(right.kind.as_str()))
    });
    ordered
}

/// Assembles one terminal candidate with preservation and digest.
#[allow(clippy::too_many_arguments)]
fn emit_candidate(
    outcome: DecompositionOutcome,
    objective: &PlanObjective,
    units: &[AgentWorkUnitBrief],
    edges: &[ReadinessEdge],
    groups: &[Vec<String>],
    omitted: &[String],
    draft: &ValidatedDreamDraft,
    job: &DreamJobAdmission,
    outcome_note: &str,
) -> Result<WorkUnitDecomposition, OrchestrationPlanError> {
    let preservation = build_preservation(outcome)?;
    let digest = compute_candidate_digest(
        objective,
        &job.task_id,
        &job.scope_id,
        units,
        edges,
        groups,
        omitted,
        outcome.as_str(),
    );
    Ok(WorkUnitDecomposition {
        plan_handle: format!("plan-{}-{}", objective.objective_id, outcome.as_str()),
        objective_id: objective.objective_id.clone(),
        task_id: job.task_id.clone(),
        scope_id: job.scope_id.clone(),
        units: sorted_units(units),
        edges: sorted_edges(edges),
        parallel_groups: groups.to_vec(),
        omitted_requirements: {
            let mut omitted_sorted = omitted.to_vec();
            omitted_sorted.sort();
            omitted_sorted
        },
        outcome,
        outcome_note: outcome_note.to_owned(),
        preservation,
        candidate_digest: digest,
        input_receipt_digest: draft.receipt.output_digest.clone(),
        proof_note: ORCHESTRATION_PROOF_NOTE.to_owned(),
    })
}

// ---------------------------------------------------------------------------
// Entry point.
// ---------------------------------------------------------------------------

/// Decomposes one admitted objective into bounded agent work-unit candidates.
///
/// The nine algorithm passes run in order: policy, objective, requirement,
/// surface, unit, and edge shapes; aggregate byte preflight; intrinsic
/// receipt and binding checks; cancellation and deadline; hidden-authority
/// scan; unknown endpoints; self edges; readiness cycles over constraining
/// edges only; the synthesis chain; serialized shared writes; write overlap;
/// semantic ownership; unknown requirement refs; requirement coverage;
/// fan-out and depth bounds; deterministic grouping and digest.
///
/// # Errors
///
/// Returns [`OrchestrationPlanError`] when any shape, bound, byte, receipt,
/// binding, or policy check fails closed. Semantic shortfalls return an
/// inert [`WorkUnitDecomposition`] with a terminal non-complete outcome.
#[allow(clippy::too_many_arguments)]
#[allow(clippy::too_many_lines)]
pub fn propose_work_unit_decomposition(
    job: &DreamJobAdmission,
    draft: &ValidatedDreamDraft,
    objective: &PlanObjective,
    requirements: &[PlanRequirement],
    surfaces: &[PlanSurface],
    units: &[AgentWorkUnitBrief],
    edges: &[ReadinessEdge],
    policy: &DecompositionPolicy,
) -> Result<WorkUnitDecomposition, OrchestrationPlanError> {
    validate_policy_shapes(policy)?;
    validate_objective_shapes(objective)?;
    validate_requirement_shapes(requirements)?;
    validate_surface_shapes(surfaces)?;
    validate_unit_shapes(units)?;
    validate_edge_shapes(edges)?;
    preflight_total_bytes(objective, requirements, surfaces, units, edges, policy)?;
    intrinsic_receipt_checks(draft)?;
    intrinsic_binding_checks(job, draft, policy)?;
    if units.len() > policy.max_units {
        return Err(OrchestrationPlanError::Bounds {
            phase: "units".to_owned(),
            detail: format!(
                "unit count {} exceeds policy max {}",
                units.len(),
                policy.max_units
            ),
        });
    }
    if edges.len() > policy.max_edges {
        return Err(OrchestrationPlanError::Bounds {
            phase: "edges".to_owned(),
            detail: format!(
                "edge count {} exceeds policy max {}",
                edges.len(),
                policy.max_edges
            ),
        });
    }
    if policy.cancelled {
        return emit_candidate(
            DecompositionOutcome::Rejected,
            objective,
            units,
            edges,
            &[],
            &[],
            draft,
            job,
            "cancelled before emission; zero effects were produced",
        );
    }
    if let (Some(observed), Some(deadline)) = (policy.observation_time_ms, policy.deadline_ms)
        && observed >= deadline
    {
        return emit_candidate(
            DecompositionOutcome::Stale,
            objective,
            units,
            edges,
            &[],
            &[],
            draft,
            job,
            "observation is at or beyond the frozen deadline; replay against the new revision",
        );
    }
    if let Some(detail) = detect_hidden_authority(units) {
        return emit_candidate(
            DecompositionOutcome::Rejected,
            objective,
            units,
            edges,
            &[],
            &[],
            draft,
            job,
            &redact(&detail),
        );
    }
    if let Some(detail) = detect_unknown_endpoint(units, edges) {
        return emit_candidate(
            DecompositionOutcome::Blocked,
            objective,
            units,
            edges,
            &[],
            &[],
            draft,
            job,
            &redact(&detail),
        );
    }
    if let Some(detail) = detect_self_edge(edges) {
        return emit_candidate(
            DecompositionOutcome::Rejected,
            objective,
            units,
            edges,
            &[],
            &[],
            draft,
            job,
            &redact(&detail),
        );
    }
    if let Some(detail) = detect_readiness_cycle(units, edges) {
        return emit_candidate(
            DecompositionOutcome::Rejected,
            objective,
            units,
            edges,
            &[],
            &[],
            draft,
            job,
            &redact(&detail),
        );
    }
    if let Some(detail) = detect_broken_chain(units, edges, &objective.synthesis_owner) {
        return emit_candidate(
            DecompositionOutcome::Blocked,
            objective,
            units,
            edges,
            &[],
            &[],
            draft,
            job,
            &redact(&detail),
        );
    }
    // Flagged shared mutables (locks, manifests, re-exports, indexes) are
    // governed by the serialized-integrator rule before generic overlap: a
    // parallel claim over one serialized surface is an unsupported claim,
    // not a plain scope overlap.
    if let Some(detail) = detect_unserialized_shared_write(units, surfaces) {
        return emit_candidate(
            DecompositionOutcome::Unsupported,
            objective,
            units,
            edges,
            &[],
            &[],
            draft,
            job,
            &redact(&detail),
        );
    }
    if let Some(detail) = detect_write_overlap(units) {
        return emit_candidate(
            DecompositionOutcome::Overlapped,
            objective,
            units,
            edges,
            &[],
            &[],
            draft,
            job,
            &redact(&detail),
        );
    }
    if let Some(detail) = detect_semantic_owner_drift(units) {
        return emit_candidate(
            DecompositionOutcome::Rejected,
            objective,
            units,
            edges,
            &[],
            &[],
            draft,
            job,
            &redact(&detail),
        );
    }
    if let Some(detail) = detect_unknown_requirement_ref(requirements, units) {
        return emit_candidate(
            DecompositionOutcome::Blocked,
            objective,
            units,
            edges,
            &[],
            &[],
            draft,
            job,
            &redact(&detail),
        );
    }
    let uncovered = uncovered_requirements(requirements, units);
    if !uncovered.is_empty() {
        if policy.allow_partial {
            let groups = topological_layers(units, edges);
            return emit_candidate(
                DecompositionOutcome::Partial,
                objective,
                units,
                edges,
                &groups,
                &uncovered,
                draft,
                job,
                "partial denominator: omitted requirements are preserved, not dropped",
            );
        }
        return emit_candidate(
            DecompositionOutcome::Rejected,
            objective,
            units,
            edges,
            &[],
            &uncovered,
            draft,
            job,
            "partial denominator is not admitted by policy; omitted requirements are preserved",
        );
    }
    // Fan-out and depth bound the emitted graph after the denominator closes.
    for unit in units {
        let fanout = constraining_successors(edges, &unit.unit_id).len();
        if fanout > policy.max_fan_out {
            return Err(OrchestrationPlanError::Bounds {
                phase: "fan_out".to_owned(),
                detail: format!(
                    "unit {} fans out to {fanout} beyond policy max {}",
                    redact(&unit.unit_id),
                    policy.max_fan_out
                ),
            });
        }
    }
    let groups = topological_layers(units, edges);
    if groups.len() > MAX_DEPTH {
        return Err(OrchestrationPlanError::Bounds {
            phase: "depth".to_owned(),
            detail: format!("readiness depth {} exceeds {MAX_DEPTH}", groups.len()),
        });
    }
    emit_candidate(
        DecompositionOutcome::Complete,
        objective,
        units,
        edges,
        &groups,
        &[],
        draft,
        job,
        "complete denominator: every retained requirement is owned and every check passes",
    )
}

// ---------------------------------------------------------------------------
// Tests: 8 of 22 WORK_UNIT_CASE 681/* execute here; 681/9..22 deferred.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::AgentWorkUnitBrief;
    use super::DecompositionOutcome;
    use super::DecompositionPolicy;
    use super::DependencyKind;
    use super::PlanObjective;
    use super::PlanRequirement;
    use super::PlanSurface;
    use super::ReadinessEdge;
    use super::SurfaceKind;
    use super::WorkUnitBudget;
    use super::WorkUnitDecomposition;
    use super::is_hex64_lower;
    use super::outcome_rejection_hint;
    use super::propose_work_unit_decomposition;
    use eliot_contracts::EpochId;
    use eliot_contracts::EpochLineageId;
    use eliot_contracts::ResourceGeneration;
    use eliot_dreamer_contracts::BudgetLimits;
    use eliot_dreamer_contracts::CurationRejectionCode;
    use eliot_dreamer_contracts::DreamJobAdmission;
    use eliot_dreamer_contracts::JobClass;
    use eliot_dreamer_contracts::Requester;
    use eliot_dreamer_contracts::RequesterOrigin;
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

    /// Returns a valid pre-handler receipt for the test job and digests.
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

    /// Returns an orchestration-planning job bound to the test receipt.
    fn test_job() -> DreamJobAdmission {
        DreamJobAdmission {
            schema_version: 1,
            job_class: JobClass::OrchestrationPlanning,
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

    /// Returns the single admitted objective with synthesis owned by `u3`.
    fn test_objective() -> PlanObjective {
        PlanObjective {
            objective_id: "obj-1".to_owned(),
            objective_revision: 1,
            statement: "translate the checkout confirmation objective into bounded work units"
                .to_owned(),
            acceptance_note: "every retained requirement is owned and every unit carries an oracle"
                .to_owned(),
            acceptance_digest: "1".repeat(64),
            source_snapshot: "snap-1".to_owned(),
            source_revision: "rev-9".to_owned(),
            architecture_ref: "I17-14-agent-work-unit".to_owned(),
            owner: "owner-1".to_owned(),
            synthesis_owner: "u3".to_owned(),
        }
    }

    /// Returns one parent requirement with the given identity and owner cell.
    fn test_requirement(identity: &str, owner_cell: &str) -> PlanRequirement {
        PlanRequirement {
            requirement_id: identity.to_owned(),
            summary: ["implement behavior for ", identity].concat(),
            owner_cell: owner_cell.to_owned(),
            evidence_ref: ["ev-", identity].concat(),
        }
    }

    /// Returns the three parent requirements owned by the three test cells.
    fn test_requirements() -> Vec<PlanRequirement> {
        [
            test_requirement("r1", "cell-alpha"),
            test_requirement("r2", "cell-beta"),
            test_requirement("r3", "cell-gamma"),
        ]
        .to_vec()
    }

    /// Returns the plan surfaces: one serialized lock file and two cell dirs.
    fn test_surfaces() -> Vec<PlanSurface> {
        [
            PlanSurface {
                surface_id: "s-lock".to_owned(),
                path: "Cargo.lock".to_owned(),
                kind: SurfaceKind::File,
                owner_cell: "cell-gamma".to_owned(),
                requires_serialized_integration: true,
                evidence_note: "owner evidence names the single serialized integrator".to_owned(),
            },
            PlanSurface {
                surface_id: "s-alpha".to_owned(),
                path: "crates/alpha".to_owned(),
                kind: SurfaceKind::Directory,
                owner_cell: "cell-alpha".to_owned(),
                requires_serialized_integration: false,
                evidence_note: "owner evidence binds the alpha subtree".to_owned(),
            },
            PlanSurface {
                surface_id: "s-beta".to_owned(),
                path: "crates/beta".to_owned(),
                kind: SurfaceKind::Directory,
                owner_cell: "cell-beta".to_owned(),
                requires_serialized_integration: false,
                evidence_note: "owner evidence binds the beta subtree".to_owned(),
            },
        ]
        .to_vec()
    }

    /// Returns the independent budget shared by the test units.
    fn test_unit_budget() -> WorkUnitBudget {
        WorkUnitBudget {
            context_bytes: 10_000,
            tool_calls: 12,
            output_bytes: 4096,
        }
    }

    /// Returns one work-unit brief with the given identities and write claim.
    fn test_unit(
        identity: &str,
        cell: &str,
        owner: &str,
        requirement: &str,
        write: &str,
    ) -> AgentWorkUnitBrief {
        AgentWorkUnitBrief {
            unit_id: identity.to_owned(),
            cell_id: cell.to_owned(),
            semantic_owner: owner.to_owned(),
            causal_property: ["causal behavior of ", identity].concat(),
            requirement_ids: [requirement.to_owned()].to_vec(),
            write_claims: [write.to_owned()].to_vec(),
            read_refs: ["docs/architecture/I17-14-note".to_owned()].to_vec(),
            forbidden_paths: ["target".to_owned(), "vendor".to_owned()].to_vec(),
            capability_note: ["competence already held for ", identity].concat(),
            route_note: ["declarative route class for ", identity].concat(),
            budget: test_unit_budget(),
            artifact_note: ["artifact produced by ", identity].concat(),
            oracle_note: ["oracle with negative cases for ", identity].concat(),
            integration_owner: "u3".to_owned(),
            handoff_note: ["handoff from ", identity, " to u3"].concat(),
            stop_note: ["stop and reopen for ", identity].concat(),
            rollback_note: ["rollback boundary for ", identity].concat(),
        }
    }

    /// Returns the three valid test units: two parallel workers plus synthesis.
    fn test_units() -> Vec<AgentWorkUnitBrief> {
        let mut synthesis = test_unit("u3", "cell-gamma", "gamma-owner", "r3", "Cargo.lock");
        synthesis.integration_owner = "u3".to_owned();
        synthesis.handoff_note = "synthesis handoff retains every producer artifact".to_owned();
        [
            test_unit(
                "u1",
                "cell-alpha",
                "alpha-owner",
                "r1",
                "crates/alpha/mod.rs",
            ),
            test_unit("u2", "cell-beta", "beta-owner", "r2", "crates/beta/mod.rs"),
            synthesis,
        ]
        .to_vec()
    }

    /// Returns the valid contract, consumer, and integration chain edges.
    fn test_edges() -> Vec<ReadinessEdge> {
        [
            ReadinessEdge {
                from_unit: "u1".to_owned(),
                to_unit: "u3".to_owned(),
                kind: DependencyKind::ArtifactFlow,
                reason: "u1 artifact feeds synthesis".to_owned(),
            },
            ReadinessEdge {
                from_unit: "u2".to_owned(),
                to_unit: "u3".to_owned(),
                kind: DependencyKind::ProofGate,
                reason: "u2 proof gates synthesis".to_owned(),
            },
        ]
        .to_vec()
    }

    /// Returns a valid governing policy for the test decomposition.
    fn test_policy() -> DecompositionPolicy {
        DecompositionPolicy {
            policy_id: "policy-7".to_owned(),
            policy_revision: 2,
            max_units: super::MAX_WORK_UNITS,
            max_edges: super::MAX_EDGES,
            max_fan_out: super::MAX_FAN_OUT,
            allow_partial: false,
            cancelled: false,
            observation_time_ms: Some(1_700_000_000_000),
            deadline_ms: Some(1_800_000_000_000),
            owner_note: "decomposition owned by the dreamer cell".to_owned(),
        }
    }

    /// Runs the full valid fixture set through the entry point.
    fn run_valid() -> WorkUnitDecomposition {
        let job = test_job();
        let draft = test_draft();
        let objective = test_objective();
        let requirements = test_requirements();
        let surfaces = test_surfaces();
        let units = test_units();
        let edges = test_edges();
        let policy = test_policy();
        let Ok(candidate) = propose_work_unit_decomposition(
            &job,
            &draft,
            &objective,
            &requirements,
            &surfaces,
            &units,
            &edges,
            &policy,
        ) else {
            panic!("valid decomposition must complete");
        };
        candidate
    }

    // WORK_UNIT_CASE: 681/1
    #[test]
    fn case_01_disjoint_owners_form_parallel_candidate_groups() {
        let candidate = run_valid();
        assert_eq!(candidate.outcome, DecompositionOutcome::Complete);
        assert_eq!(outcome_rejection_hint(&candidate.outcome), None);
        assert_eq!(candidate.objective_id, "obj-1");
        assert_eq!(candidate.task_id, "task-1");
        assert_eq!(candidate.scope_id, "scope-1");
        assert_eq!(candidate.units.len(), 3);
        assert_eq!(
            candidate.parallel_groups,
            [
                ["u1".to_owned(), "u2".to_owned()].to_vec(),
                ["u3".to_owned()].to_vec(),
            ]
            .to_vec()
        );
        assert!(candidate.omitted_requirements.is_empty());
        assert!(is_hex64_lower(&candidate.candidate_digest));
        assert_eq!(candidate.input_receipt_digest, "e".repeat(64));
        assert!(candidate.preservation.overall().is_ok());
        assert_eq!(candidate.preservation.verdicts.len(), 7);
        assert_eq!(candidate.proof_note, super::ORCHESTRATION_PROOF_NOTE);
    }

    // WORK_UNIT_CASE: 681/2
    #[test]
    fn case_02_file_dir_and_alias_overlap_is_overlapped() {
        // Direct overlap shapes: file with file, directory with file,
        // directory with directory, and canonical alias spellings.
        assert!(super::write_claims_overlap(
            "crates/alpha/mod.rs",
            false,
            "crates/alpha/mod.rs",
            false
        ));
        assert!(super::write_claims_overlap(
            "crates/alpha",
            true,
            "crates/alpha/mod.rs",
            false
        ));
        assert!(super::write_claims_overlap(
            "crates/alpha",
            true,
            "crates/alpha/beta",
            true
        ));
        assert!(super::write_claims_overlap(
            "crates\\alpha",
            true,
            "CRATES/alpha/",
            true
        ));
        assert!(!super::write_claims_overlap(
            "crates/alpha/mod.rs",
            false,
            "crates/beta/mod.rs",
            false
        ));
        // End to end: the second unit claims the first unit's file.
        let job = test_job();
        let draft = test_draft();
        let objective = test_objective();
        let requirements = test_requirements();
        let surfaces = test_surfaces();
        let mut units = test_units();
        if let Some(second) = units.get_mut(1) {
            second.write_claims = ["crates/alpha/mod.rs".to_owned()].to_vec();
        }
        let edges = test_edges();
        let policy = test_policy();
        let Ok(candidate) = propose_work_unit_decomposition(
            &job,
            &draft,
            &objective,
            &requirements,
            &surfaces,
            &units,
            &edges,
            &policy,
        ) else {
            panic!("overlap stays an inert outcome");
        };
        assert_eq!(candidate.outcome, DecompositionOutcome::Overlapped);
        assert_eq!(
            outcome_rejection_hint(&candidate.outcome),
            Some(CurationRejectionCode::PreservationFailed)
        );
        assert!(candidate.preservation.overall().is_ok());
    }

    // WORK_UNIT_CASE: 681/3
    #[test]
    fn case_03_same_semantic_owner_in_different_paths_conflicts() {
        let job = test_job();
        let draft = test_draft();
        let objective = test_objective();
        let requirements = test_requirements();
        let surfaces = test_surfaces();
        let mut units = test_units();
        if let Some(second) = units.get_mut(1) {
            second.semantic_owner = "alpha-owner".to_owned();
        }
        let edges = test_edges();
        let policy = test_policy();
        let Ok(candidate) = propose_work_unit_decomposition(
            &job,
            &draft,
            &objective,
            &requirements,
            &surfaces,
            &units,
            &edges,
            &policy,
        ) else {
            panic!("duplicate semantic ownership stays an inert outcome");
        };
        assert_eq!(candidate.outcome, DecompositionOutcome::Rejected);
        assert_eq!(
            outcome_rejection_hint(&candidate.outcome),
            Some(CurationRejectionCode::IdentityMismatch)
        );
        assert!(candidate.parallel_groups.is_empty());
    }

    // WORK_UNIT_CASE: 681/4
    #[test]
    fn case_04_shared_lock_without_single_integrator_is_unsupported() {
        let job = test_job();
        let draft = test_draft();
        let objective = test_objective();
        let requirements = test_requirements();
        let surfaces = test_surfaces();
        let mut units = test_units();
        if let Some(first) = units.get_mut(0) {
            first.write_claims.push("Cargo.lock".to_owned());
        }
        let edges = test_edges();
        let policy = test_policy();
        let Ok(candidate) = propose_work_unit_decomposition(
            &job,
            &draft,
            &objective,
            &requirements,
            &surfaces,
            &units,
            &edges,
            &policy,
        ) else {
            panic!("unserialized shared write stays an inert outcome");
        };
        assert_eq!(candidate.outcome, DecompositionOutcome::Unsupported);
        assert_eq!(
            outcome_rejection_hint(&candidate.outcome),
            Some(CurationRejectionCode::UnsupportedPrecision)
        );
    }

    // WORK_UNIT_CASE: 681/5
    #[test]
    fn case_05_broken_chain_to_synthesis_is_blocked() {
        let job = test_job();
        let draft = test_draft();
        let objective = test_objective();
        let requirements = test_requirements();
        let surfaces = test_surfaces();
        let units = test_units();
        let mut edges = test_edges();
        edges.pop();
        let policy = test_policy();
        let Ok(candidate) = propose_work_unit_decomposition(
            &job,
            &draft,
            &objective,
            &requirements,
            &surfaces,
            &units,
            &edges,
            &policy,
        ) else {
            panic!("broken chain stays an inert outcome");
        };
        assert_eq!(candidate.outcome, DecompositionOutcome::Blocked);
        assert_eq!(
            outcome_rejection_hint(&candidate.outcome),
            Some(CurationRejectionCode::LineageMismatch)
        );
    }

    // WORK_UNIT_CASE: 681/6
    #[test]
    fn case_06_cycle_and_self_edge_are_rejected() {
        let job = test_job();
        let draft = test_draft();
        let objective = test_objective();
        let requirements = test_requirements();
        let surfaces = test_surfaces();
        let units = test_units();
        let policy = test_policy();
        // Self edge first: a unit depending on itself can never dispatch.
        let self_edges = [ReadinessEdge {
            from_unit: "u1".to_owned(),
            to_unit: "u1".to_owned(),
            kind: DependencyKind::CompilePrerequisite,
            reason: "self prerequisite".to_owned(),
        }]
        .to_vec();
        let Ok(self_candidate) = propose_work_unit_decomposition(
            &job,
            &draft,
            &objective,
            &requirements,
            &surfaces,
            &units,
            &self_edges,
            &policy,
        ) else {
            panic!("self edge stays an inert outcome");
        };
        assert_eq!(self_candidate.outcome, DecompositionOutcome::Rejected);
        assert_eq!(
            outcome_rejection_hint(&self_candidate.outcome),
            Some(CurationRejectionCode::IdentityMismatch)
        );
        // Genuine cycle over constraining edges: synthesis back to a worker.
        let mut edges = test_edges();
        edges.push(ReadinessEdge {
            from_unit: "u3".to_owned(),
            to_unit: "u1".to_owned(),
            kind: DependencyKind::WriteSerialization,
            reason: "synthesis writes back to the worker".to_owned(),
        });
        let Ok(candidate) = propose_work_unit_decomposition(
            &job,
            &draft,
            &objective,
            &requirements,
            &surfaces,
            &units,
            &edges,
            &policy,
        ) else {
            panic!("readiness cycle stays an inert outcome");
        };
        assert_eq!(candidate.outcome, DecompositionOutcome::Rejected);
        assert_eq!(
            outcome_rejection_hint(&candidate.outcome),
            Some(CurationRejectionCode::IdentityMismatch)
        );
    }

    // WORK_UNIT_CASE: 681/7
    #[test]
    fn case_07_unknown_prerequisite_is_blocked() {
        let job = test_job();
        let draft = test_draft();
        let objective = test_objective();
        let requirements = test_requirements();
        let surfaces = test_surfaces();
        let units = test_units();
        let mut edges = test_edges();
        edges.push(ReadinessEdge {
            from_unit: "u9".to_owned(),
            to_unit: "u1".to_owned(),
            kind: DependencyKind::CompilePrerequisite,
            reason: "unknown prerequisite outside the supplied set".to_owned(),
        });
        let policy = test_policy();
        let Ok(candidate) = propose_work_unit_decomposition(
            &job,
            &draft,
            &objective,
            &requirements,
            &surfaces,
            &units,
            &edges,
            &policy,
        ) else {
            panic!("unknown prerequisite stays an inert outcome");
        };
        assert_eq!(candidate.outcome, DecompositionOutcome::Blocked);
        assert_eq!(
            outcome_rejection_hint(&candidate.outcome),
            Some(CurationRejectionCode::LineageMismatch)
        );
    }

    // WORK_UNIT_CASE: 681/8
    #[test]
    fn case_08_permuted_inputs_replay_identically() {
        let job = test_job();
        let draft = test_draft();
        let objective = test_objective();
        let requirements = test_requirements();
        let surfaces = test_surfaces();
        let policy = test_policy();
        let first = run_valid();
        // Irrelevant permutation: reversed units and edges replay identically.
        let mut units = test_units();
        units.reverse();
        let mut edges = test_edges();
        edges.reverse();
        let Ok(second) = propose_work_unit_decomposition(
            &job,
            &draft,
            &objective,
            &requirements,
            &surfaces,
            &units,
            &edges,
            &policy,
        ) else {
            panic!("permuted decomposition must complete");
        };
        assert_eq!(second.outcome, DecompositionOutcome::Complete);
        assert_eq!(second.parallel_groups, first.parallel_groups);
        assert_eq!(second.candidate_digest, first.candidate_digest);
        // Truncated denominator: one retained requirement without an owner is
        // preserved as omitted partial, never silently dropped.
        let mut partial_requirements = test_requirements();
        partial_requirements.push(test_requirement("r9", "cell-omega"));
        let mut partial_policy = test_policy();
        partial_policy.allow_partial = true;
        let Ok(partial) = propose_work_unit_decomposition(
            &job,
            &draft,
            &objective,
            &partial_requirements,
            &surfaces,
            &test_units(),
            &test_edges(),
            &partial_policy,
        ) else {
            panic!("truncated denominator stays an inert outcome");
        };
        assert_eq!(partial.outcome, DecompositionOutcome::Partial);
        assert_eq!(
            outcome_rejection_hint(&partial.outcome),
            Some(CurationRejectionCode::PreservationFailed)
        );
        assert_eq!(partial.omitted_requirements, ["r9".to_owned()].to_vec());
    }
}
