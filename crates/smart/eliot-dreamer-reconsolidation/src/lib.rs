//! Forward-only derived-memory reconsolidation candidate (A-28).
//!
//! Pure candidate-only owner of one forward derived-memory child revision
//! after exact externally observed reactivation plus genuinely new material
//! evidence. The handler proposes; it never persists, allocates revisions,
//! mutates relations or axes, calls providers or stores, or exercises
//! authority, effects, or finish semantics.
//!
//! Cell `smart.dreamer.reconsolidation`, order 28. Inputs are immutable and
//! caller-supplied; every clock observation, policy binding, and receipt is
//! explicit. The A-05 receipt is checked intrinsically via its own
//! validation entry point and is never re-executed here.

#![forbid(unsafe_code)]

use eliot_dreamer_candidate_validation::RejectionCode;
use eliot_dreamer_contracts::{
    CurationKind, PreservationReport, TargetDenominator, ValidationReceipt,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Independent bounds (no cross-subsidy between dimensions).
// ---------------------------------------------------------------------------

/// Maximum parent propositions admitted in one request.
pub const MAX_PARENT_PROPOSITIONS: usize = 64;
/// Maximum new evidence items admitted in one request.
pub const MAX_NEW_ITEMS: usize = 64;
/// Maximum affected dependents admitted in one request.
pub const MAX_DEPENDENTS: usize = 64;
/// Maximum predecessor revisions admitted in one parent chain.
pub const MAX_PREDECESSORS: usize = 32;
/// Maximum baseline handles or lineages admitted in one request.
pub const MAX_BASELINE_REFS: usize = 256;
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

fn is_hex64_lower(value: &str) -> bool {
    if value.len() != 64 {
        return false;
    }
    value
        .bytes()
        .all(|b| b.is_ascii_hexdigit() && !(b.is_ascii_uppercase()))
}

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

fn normalize_statement(value: &str) -> String {
    let mut out = String::new();
    let mut pending_space = false;
    for word in value.split_whitespace() {
        if pending_space {
            out.push(' ');
        }
        for ch in word.chars() {
            for lower in ch.to_lowercase() {
                out.push(lower);
            }
        }
        pending_space = true;
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

fn digits_of(value: &str) -> Vec<char> {
    value.chars().filter(char::is_ascii_digit).collect()
}

fn has_absolute_claim(value: &str) -> bool {
    let lowered = value.to_lowercase();
    lowered.contains("always")
        || lowered.contains("never")
        || lowered.contains("proven")
        || lowered.contains("guaranteed")
        || lowered.contains("certain")
        || lowered.contains("100%")
}

fn mentions_majority_resolution(rationale: &str) -> bool {
    let lowered = rationale.to_lowercase();
    lowered.contains("majority")
        || lowered.contains("vote")
        || lowered.contains("consensus resolves")
}

// ---------------------------------------------------------------------------
// Public vocabulary.
// ---------------------------------------------------------------------------

/// Allowed target classes. Only derived memory may be reconsolidated.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
pub enum TargetKind {
    /// Derived memory subject to forward revision.
    DerivedMemory,
    /// Raw episode history; never rewritten here.
    RawEpisode,
    /// Raw artifact payload; never rewritten here.
    RawArtifact,
}

/// How the reactivation was observed. Only exact external observation qualifies.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
pub enum ReactivationObservationKind {
    /// Externally observed access with a qualifying policy receipt.
    ExternalObservation,
    /// Bare availability signal without observation content.
    Availability,
    /// Index or membership signal without observation content.
    IndexMembership,
    /// Model mention without external observation.
    ModelMention,
    /// Partial observation with unknown coverage.
    PartialObservation,
}

/// Source class of one new evidence item. Only external observation counts.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
pub enum EvidenceSourceKind {
    /// Externally observed outcome or evidence.
    ExternalObservation,
    /// Model-generated mention without external grounding.
    ModelMention,
    /// Retrieval duplicate of already-admitted material.
    RetrievalDuplicate,
    /// Availability or index signal without content.
    AvailabilitySignal,
}

/// Disposition of one parent proposition in the proposed child view.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
pub enum PropositionDisposition {
    /// Kept byte-exact in the child view.
    Retained,
    /// Scope narrowed with evidence-backed bounds.
    Narrowed,
    /// Qualified with additional conditions.
    Qualified,
    /// Contradicted; both sides retained with new evidence.
    Contradicted,
    /// Withdrawn from the child view only; parent history preserved.
    Withdrawn,
    /// Left unresolved; load-bearing unresolved blocks completeness.
    Unresolved,
}

/// Disposition of one affected dependent under the proposed child.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
pub enum DependentDisposition {
    /// Kept as-is; child does not affect it.
    Retain,
    /// Unaffected with supporting evidence cited.
    UnaffectedWithEvidence,
    /// Must be revalidated against the child.
    Revalidate,
    /// Must be rebuilt against the child.
    Rebuild,
    /// Invalidated by the child with reason preserved.
    Invalidate,
    /// Retargeted to the child revision.
    Retarget,
    /// Reconciled against both parent and child.
    Reconcile,
    /// Cannot be disposed; blocks completeness.
    Blocked,
}

/// Current derived parent with its predecessor chain and frontier identity.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ParentRevision {
    /// Derived parent handle.
    pub handle: String,
    /// Current parent revision identity.
    pub revision: String,
    /// Predecessor chain, oldest first, without duplicates.
    pub predecessor_chain: Vec<String>,
    /// Frontier revision the writer observed; must equal `revision`.
    pub frontier_revision: String,
    /// Target class; only derived memory is admitted.
    pub target_kind: TargetKind,
    /// True when the parent was picked by wall-clock recency; always rejected.
    pub selected_by_timestamp: bool,
}

/// One parent proposition in the accepted baseline.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ParentProposition {
    /// Stable proposition identity.
    pub id: String,
    /// Accepted statement text.
    pub statement: String,
    /// Baseline support handle backing the proposition.
    pub support_handle: String,
    /// Lineage the proposition was admitted under.
    pub lineage: String,
    /// True when downstream reasoning loads on this proposition.
    pub is_load_bearing: bool,
}

/// Proposed delta for one parent proposition.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PropositionDelta {
    /// Parent proposition identity this delta accounts for.
    pub proposition_id: String,
    /// Exactly one disposition for the parent proposition.
    pub disposition: PropositionDisposition,
    /// Revised statement when the disposition changes wording.
    pub revised_statement: Option<String>,
    /// Bounded rationale naming the triggering evidence.
    pub rationale: String,
    /// Evidence handles backing the delta.
    pub evidence_refs: Vec<String>,
}

/// One candidate new evidence item claimed as genuinely new.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct NewEvidenceItem {
    /// New evidence handle.
    pub handle: String,
    /// Digest of the canonical evidence bytes (64 lowercase hex).
    pub digest: String,
    /// Lineage the item arrives under.
    pub lineage: String,
    /// Evidence statement or outcome text.
    pub statement: String,
    /// Source class; only external observation can be material.
    pub source_kind: EvidenceSourceKind,
    /// Explicit observation time; unknown time is never filled in.
    pub observed_at_ms: Option<u64>,
}

/// Policy-qualified externally observed reactivation at an exact checkpoint.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ReactivationEvidence {
    /// Checkpoint revision that was reactivated; must equal the parent revision.
    pub checkpoint: String,
    /// Policy that qualifies the observation.
    pub policy_id: String,
    /// External handle that was observed (retrieval, probe, outcome).
    pub external_handle: String,
    /// How the reactivation was observed.
    pub observation_kind: ReactivationObservationKind,
    /// True only for a complete observation at the exact checkpoint.
    pub exact_match: bool,
    /// Explicit observation time; unknown time is never filled in.
    pub observed_at_ms: Option<u64>,
}

/// One affected dependent requiring an exact disposition.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DependentRecord {
    /// Dependent handle.
    pub handle: String,
    /// True when the dependent is required for completeness.
    pub required: bool,
    /// Dependent kind label (index, summary, retrieval, probe).
    pub kind: String,
}

/// Proposed disposition for one affected dependent.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DependentOutcome {
    /// Dependent handle this outcome disposes.
    pub handle: String,
    /// Exactly one disposition for the dependent.
    pub disposition: DependentDisposition,
    /// Bounded note naming the evidence or blocker.
    pub note: String,
}

/// Independent owner references preserved unchanged by content revision.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AxisOwnerRefs {
    /// Owner of the support axis.
    pub support_owner: String,
    /// Owner of the assertability axis.
    pub assertability_owner: String,
    /// Owner of the accessibility axis.
    pub accessibility_owner: String,
    /// Owner of the influence axis.
    pub influence_owner: String,
    /// Owner of the lifecycle axis.
    pub lifecycle_owner: String,
    /// Owner of the privacy axis.
    pub privacy_owner: String,
    /// Owner of the retention axis.
    pub retention_owner: String,
    /// Owner of the source-assurance axis.
    pub source_assurance_owner: String,
}

/// External child-allocation request. Requests only; issues nothing.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ChildAllocationRequest {
    /// Parent handle the child would revise.
    pub parent_handle: String,
    /// Parent revision the child would extend.
    pub parent_revision: String,
    /// Proposed child handle; never an allocated revision.
    pub proposed_child_handle: String,
    /// Verifier that would check the child on admission.
    pub verifier: String,
    /// Inverse note describing how to set the child aside.
    pub inverse_note: String,
    /// Forward-correction note describing the next repair on error.
    pub forward_correction: String,
    /// Explicit expiry; unknown expiry is never filled in.
    pub expiry_ms: Option<u64>,
    /// Reopen condition naming the frontier change that reopens review.
    pub reopen_condition: String,
    /// Always true: this value requests, it does not issue.
    pub request_only: bool,
    /// Always false: this cell allocates no revision.
    pub allocates_revision: bool,
}

/// Terminal outcome of one reconsolidation proposal.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
pub enum ReconsolidationOutcome {
    /// Complete candidate with an external allocation request.
    Complete,
    /// Partial candidate; non-load-bearing gaps remain with conditions.
    Partial,
    /// Reactivation is real but no material new item survives filtering.
    NoMaterialNewEvidence,
    /// The delta admits no safe revision from the supplied evidence.
    NoSafeRevision,
    /// Observation is partial or unknown; the cell abstains.
    Abstention,
    /// Parent frontier or checkpoint moved; the request is stale.
    Stale,
    /// Required accounting, dependent, preservation, or denominator is blocked.
    Blocked,
    /// The request is not a reconsolidation of derived memory.
    Rejected,
}

/// Complete result envelope: outcome plus the optional external request.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ReconsolidationResult {
    /// Terminal outcome for this request.
    pub outcome: ReconsolidationOutcome,
    /// External allocation request for complete and partial outcomes.
    pub child: Option<ChildAllocationRequest>,
    /// Number of parent propositions accounted.
    pub accounted_parents: u32,
    /// Number of genuinely new items admitted.
    pub admitted_new: u32,
    /// Bounded machine-readable note.
    pub note: String,
}

/// Typed fail-closed error. Malformed input only; semantic shortfalls are outcomes.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
pub enum ReconsolidationError {
    /// A bound or shape check failed in the named phase.
    Bounds { phase: String, detail: String },
    /// Deterministic ordering was violated in the named phase.
    Order { phase: String, detail: String },
    /// A proposition delta is malformed.
    Proposition { id: String, detail: String },
    /// A source or evidence handle is malformed.
    Source { handle: String, detail: String },
    /// A dependent record is malformed.
    Dependent { handle: String, detail: String },
    /// Generic malformed input in the named phase.
    Malformed { phase: String, detail: String },
    /// The bundled A-05 receipt is intrinsically invalid.
    Receipt { detail: String },
    /// The preservation report shape is invalid.
    Preservation { detail: String },
    /// The new-member denominator shape is invalid.
    Denominator { detail: String },
}

impl core::fmt::Display for ReconsolidationError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Bounds { phase, detail } => {
                write!(f, "bounds[{phase}]: {detail}")
            }
            Self::Order { phase, detail } => {
                write!(f, "order[{phase}]: {detail}")
            }
            Self::Proposition { id, detail } => {
                write!(f, "proposition[{id}]: {detail}")
            }
            Self::Source { handle, detail } => {
                write!(f, "source[{handle}]: {detail}")
            }
            Self::Dependent { handle, detail } => {
                write!(f, "dependent[{handle}]: {detail}")
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

impl core::error::Error for ReconsolidationError {}

/// Full immutable input for one reconsolidation proposal.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ReconsolidationRequest {
    /// Curation kind; must be reconsolidation.
    pub curation_kind: CurationKind,
    /// Current derived parent.
    pub parent: ParentRevision,
    /// Accepted parent propositions (sorted by id, unique).
    pub parent_propositions: Vec<ParentProposition>,
    /// One delta per parent proposition (sorted by proposition id).
    pub deltas: Vec<PropositionDelta>,
    /// Candidate new evidence items (sorted by handle, unique).
    pub new_items: Vec<NewEvidenceItem>,
    /// Baseline handles the parent already covers (sorted, unique).
    pub parent_baseline_handles: Vec<String>,
    /// Baseline lineages the parent already covers (sorted, unique).
    pub parent_baseline_lineages: Vec<String>,
    /// Exact externally observed reactivation.
    pub reactivation: ReactivationEvidence,
    /// Affected dependents (sorted by handle, unique).
    pub dependents: Vec<DependentRecord>,
    /// One outcome per affected dependent (sorted by handle).
    pub dependent_outcomes: Vec<DependentOutcome>,
    /// Owner references preserved unchanged.
    pub axis_owners: AxisOwnerRefs,
    /// Seven-dimension preservation report from the caller.
    pub preservation: PreservationReport,
    /// A-05 receipt checked intrinsically, never re-executed.
    pub receipt: ValidationReceipt,
    /// New-member denominator covering exactly the admitted additions.
    pub new_member_denominator: TargetDenominator,
    /// Proposed child handle; must differ from the parent handle.
    pub proposed_child_handle: String,
    /// Verifier named in the allocation request.
    pub child_verifier: String,
    /// Inverse note named in the allocation request.
    pub child_inverse_note: String,
    /// Forward-correction note named in the allocation request.
    pub child_forward_correction: String,
    /// Explicit expiry for the request.
    pub child_expiry_ms: Option<u64>,
    /// Reopen condition for the request.
    pub child_reopen_condition: String,
    /// Expected policy identity; reactivation and receipt must bind to it.
    pub policy_id: String,
}

// ---------------------------------------------------------------------------
// Validation phases (all pure, all bounded, none panicking).
// ---------------------------------------------------------------------------

fn check_bounded_text(value: &str, field: &str, max: usize) -> Result<(), ReconsolidationError> {
    if value.trim().is_empty() {
        return Err(ReconsolidationError::Bounds {
            phase: field.to_owned(),
            detail: "blank text is not admitted".to_owned(),
        });
    }
    if has_control(value) {
        return Err(ReconsolidationError::Malformed {
            phase: field.to_owned(),
            detail: "control characters are not admitted".to_owned(),
        });
    }
    if value.len() > max {
        return Err(ReconsolidationError::Bounds {
            phase: field.to_owned(),
            detail: "text exceeds its byte bound".to_owned(),
        });
    }
    Ok(())
}

fn check_handle(value: &str, field: &str) -> Result<(), ReconsolidationError> {
    check_bounded_text(value, field, MAX_HANDLE_BYTES)
}

fn total_bytes(request: &ReconsolidationRequest) -> usize {
    let mut total = 0usize;
    let mut add = |n: usize| {
        total = total.saturating_add(n);
    };
    add(request.parent.handle.len());
    add(request.parent.revision.len());
    add(request.parent.frontier_revision.len());
    for h in &request.parent.predecessor_chain {
        add(h.len());
    }
    for p in &request.parent_propositions {
        add(p.id.len());
        add(p.statement.len());
        add(p.support_handle.len());
        add(p.lineage.len());
    }
    for d in &request.deltas {
        add(d.proposition_id.len());
        add(d.rationale.len());
        if let Some(revised) = d.revised_statement.as_ref() {
            add(revised.len());
        }
        for r in &d.evidence_refs {
            add(r.len());
        }
    }
    for n in &request.new_items {
        add(n.handle.len());
        add(n.digest.len());
        add(n.lineage.len());
        add(n.statement.len());
    }
    for h in &request.parent_baseline_handles {
        add(h.len());
    }
    for l in &request.parent_baseline_lineages {
        add(l.len());
    }
    add(request.reactivation.checkpoint.len());
    add(request.reactivation.policy_id.len());
    add(request.reactivation.external_handle.len());
    for d in &request.dependents {
        add(d.handle.len());
        add(d.kind.len());
    }
    for o in &request.dependent_outcomes {
        add(o.handle.len());
        add(o.note.len());
    }
    add(request.proposed_child_handle.len());
    add(request.child_verifier.len());
    add(request.child_inverse_note.len());
    add(request.child_forward_correction.len());
    add(request.child_reopen_condition.len());
    add(request.policy_id.len());
    total
}

fn preflight_bounds(request: &ReconsolidationRequest) -> Result<(), ReconsolidationError> {
    let bound = |phase: &str, got: usize, max: usize| -> Result<(), ReconsolidationError> {
        if got > max {
            return Err(ReconsolidationError::Bounds {
                phase: phase.to_owned(),
                detail: "cardinality exceeds its independent bound".to_owned(),
            });
        }
        Ok(())
    };
    bound(
        "propositions",
        request.parent_propositions.len(),
        MAX_PARENT_PROPOSITIONS,
    )?;
    bound("deltas", request.deltas.len(), MAX_PARENT_PROPOSITIONS)?;
    bound("sources", request.new_items.len(), MAX_NEW_ITEMS)?;
    bound("dependents", request.dependents.len(), MAX_DEPENDENTS)?;
    bound(
        "dependent_outcomes",
        request.dependent_outcomes.len(),
        MAX_DEPENDENTS,
    )?;
    bound(
        "revisions",
        request.parent.predecessor_chain.len(),
        MAX_PREDECESSORS,
    )?;
    bound(
        "baseline_handles",
        request.parent_baseline_handles.len(),
        MAX_BASELINE_REFS,
    )?;
    bound(
        "baseline_lineages",
        request.parent_baseline_lineages.len(),
        MAX_BASELINE_REFS,
    )?;
    if request.parent_propositions.is_empty() {
        return Err(ReconsolidationError::Bounds {
            phase: "propositions".to_owned(),
            detail: "at least one parent proposition is required".to_owned(),
        });
    }
    if total_bytes(request) > MAX_TOTAL_BYTES {
        return Err(ReconsolidationError::Bounds {
            phase: "bytes".to_owned(),
            detail: "aggregate input exceeds its byte bound".to_owned(),
        });
    }
    Ok(())
}

#[allow(clippy::too_many_lines)]
fn validate_shapes(request: &ReconsolidationRequest) -> Result<(), ReconsolidationError> {
    check_handle(&request.parent.handle, "parent.handle")?;
    check_bounded_text(
        &request.parent.revision,
        "parent.revision",
        MAX_HANDLE_BYTES,
    )?;
    check_bounded_text(
        &request.parent.frontier_revision,
        "parent.frontier",
        MAX_HANDLE_BYTES,
    )?;
    for rev in &request.parent.predecessor_chain {
        check_bounded_text(rev, "parent.predecessor", MAX_HANDLE_BYTES)?;
    }
    {
        let mut seen: Vec<&String> = Vec::new();
        for rev in &request.parent.predecessor_chain {
            if seen.contains(&rev) {
                return Err(ReconsolidationError::Order {
                    phase: "parent.predecessor".to_owned(),
                    detail: "duplicate predecessor revision".to_owned(),
                });
            }
            seen.push(rev);
        }
    }
    check_handle(&request.proposed_child_handle, "child.handle")?;
    check_bounded_text(&request.child_verifier, "child.verifier", MAX_TEXT_BYTES)?;
    check_bounded_text(&request.child_inverse_note, "child.inverse", MAX_TEXT_BYTES)?;
    check_bounded_text(
        &request.child_forward_correction,
        "child.forward_correction",
        MAX_TEXT_BYTES,
    )?;
    check_bounded_text(
        &request.child_reopen_condition,
        "child.reopen",
        MAX_TEXT_BYTES,
    )?;
    check_bounded_text(&request.policy_id, "policy", MAX_HANDLE_BYTES)?;
    check_bounded_text(
        &request.reactivation.checkpoint,
        "reactivation.checkpoint",
        MAX_HANDLE_BYTES,
    )?;
    check_bounded_text(
        &request.reactivation.policy_id,
        "reactivation.policy",
        MAX_HANDLE_BYTES,
    )?;
    check_handle(
        &request.reactivation.external_handle,
        "reactivation.external",
    )?;

    let mut ids: Vec<String> = Vec::new();
    for p in &request.parent_propositions {
        check_bounded_text(&p.id, "proposition.id", MAX_HANDLE_BYTES)?;
        check_bounded_text(&p.statement, "proposition.statement", MAX_TEXT_BYTES)?;
        check_handle(&p.support_handle, "proposition.support")?;
        check_bounded_text(&p.lineage, "proposition.lineage", MAX_HANDLE_BYTES)?;
        ids.push(p.id.clone());
    }
    if !is_sorted_unique(&ids) {
        return Err(ReconsolidationError::Order {
            phase: "propositions".to_owned(),
            detail: "proposition ids must be sorted and unique".to_owned(),
        });
    }
    let mut delta_ids: Vec<String> = Vec::new();
    for d in &request.deltas {
        check_bounded_text(&d.proposition_id, "delta.proposition", MAX_HANDLE_BYTES)?;
        check_bounded_text(&d.rationale, "delta.rationale", MAX_TEXT_BYTES)?;
        if let Some(revised) = d.revised_statement.as_ref() {
            check_bounded_text(revised, "delta.revised", MAX_TEXT_BYTES)?;
        }
        for r in &d.evidence_refs {
            check_handle(r, "delta.evidence")?;
        }
        delta_ids.push(d.proposition_id.clone());
    }
    if !is_sorted_unique(&delta_ids) {
        return Err(ReconsolidationError::Order {
            phase: "deltas".to_owned(),
            detail: "delta proposition ids must be sorted and unique".to_owned(),
        });
    }
    let mut item_handles: Vec<String> = Vec::new();
    for n in &request.new_items {
        check_handle(&n.handle, "source.handle")?;
        if !is_hex64_lower(&n.digest) {
            return Err(ReconsolidationError::Source {
                handle: redact(&n.handle),
                detail: "digest must be 64 lowercase hex".to_owned(),
            });
        }
        check_bounded_text(&n.lineage, "source.lineage", MAX_HANDLE_BYTES)?;
        check_bounded_text(&n.statement, "source.statement", MAX_TEXT_BYTES)?;
        item_handles.push(n.handle.clone());
    }
    if !is_sorted_unique(&item_handles) {
        return Err(ReconsolidationError::Order {
            phase: "sources".to_owned(),
            detail: "new handles must be sorted and unique".to_owned(),
        });
    }
    for h in &request.parent_baseline_handles {
        check_handle(h, "baseline.handle")?;
    }
    if !is_sorted_unique(&request.parent_baseline_handles) {
        return Err(ReconsolidationError::Order {
            phase: "baseline_handles".to_owned(),
            detail: "baseline handles must be sorted and unique".to_owned(),
        });
    }
    for l in &request.parent_baseline_lineages {
        check_bounded_text(l, "baseline.lineage", MAX_HANDLE_BYTES)?;
    }
    if !is_sorted_unique(&request.parent_baseline_lineages) {
        return Err(ReconsolidationError::Order {
            phase: "baseline_lineages".to_owned(),
            detail: "baseline lineages must be sorted and unique".to_owned(),
        });
    }
    let mut dep_handles: Vec<String> = Vec::new();
    for d in &request.dependents {
        check_handle(&d.handle, "dependent.handle")?;
        check_bounded_text(&d.kind, "dependent.kind", MAX_HANDLE_BYTES)?;
        dep_handles.push(d.handle.clone());
    }
    if !is_sorted_unique(&dep_handles) {
        return Err(ReconsolidationError::Order {
            phase: "dependents".to_owned(),
            detail: "dependent handles must be sorted and unique".to_owned(),
        });
    }
    let mut outcome_handles: Vec<String> = Vec::new();
    for o in &request.dependent_outcomes {
        check_handle(&o.handle, "dependent_outcome.handle")?;
        check_bounded_text(&o.note, "dependent_outcome.note", MAX_TEXT_BYTES)?;
        outcome_handles.push(o.handle.clone());
    }
    if !is_sorted_unique(&outcome_handles) {
        return Err(ReconsolidationError::Order {
            phase: "dependent_outcomes".to_owned(),
            detail: "dependent outcomes must be sorted and unique".to_owned(),
        });
    }
    let owners = [
        ("support", &request.axis_owners.support_owner),
        ("assertability", &request.axis_owners.assertability_owner),
        ("accessibility", &request.axis_owners.accessibility_owner),
        ("influence", &request.axis_owners.influence_owner),
        ("lifecycle", &request.axis_owners.lifecycle_owner),
        ("privacy", &request.axis_owners.privacy_owner),
        ("retention", &request.axis_owners.retention_owner),
        (
            "source_assurance",
            &request.axis_owners.source_assurance_owner,
        ),
    ];
    for (axis, owner) in owners {
        if owner.trim().is_empty() || has_control(owner) || owner.len() > MAX_HANDLE_BYTES {
            return Err(ReconsolidationError::Malformed {
                phase: "axis_owners".to_owned(),
                detail: "owner for axis is not a bounded handle".to_owned() + axis,
            });
        }
    }
    Ok(())
}

fn find_proposition<'a>(
    propositions: &'a [ParentProposition],
    id: &str,
) -> Option<&'a ParentProposition> {
    propositions.iter().find(|p| p.id == id)
}

fn ok_result(
    outcome: ReconsolidationOutcome,
    child: Option<ChildAllocationRequest>,
    accounted: usize,
    admitted: usize,
    note: &str,
) -> Result<ReconsolidationResult, ReconsolidationError> {
    let accounted_parents = u32::try_from(accounted).map_err(|_| ReconsolidationError::Bounds {
        phase: "propositions".to_owned(),
        detail: "proposition count does not fit the result envelope".to_owned(),
    })?;
    let admitted_new = u32::try_from(admitted).map_err(|_| ReconsolidationError::Bounds {
        phase: "sources".to_owned(),
        detail: "admitted count does not fit the result envelope".to_owned(),
    })?;
    Ok(ReconsolidationResult {
        outcome,
        child,
        accounted_parents,
        admitted_new,
        note: redact(note),
    })
}

fn build_child(request: &ReconsolidationRequest) -> ChildAllocationRequest {
    ChildAllocationRequest {
        parent_handle: request.parent.handle.clone(),
        parent_revision: request.parent.revision.clone(),
        proposed_child_handle: request.proposed_child_handle.clone(),
        verifier: request.child_verifier.clone(),
        inverse_note: request.child_inverse_note.clone(),
        forward_correction: request.child_forward_correction.clone(),
        expiry_ms: request.child_expiry_ms,
        reopen_condition: request.child_reopen_condition.clone(),
        request_only: true,
        allocates_revision: false,
    }
}

// ---------------------------------------------------------------------------
// Public entry point.
// ---------------------------------------------------------------------------

/// Proposes one forward reconsolidation candidate from immutable inputs.
///
/// The function is pure and synchronous: it reads only `request`, allocates
/// no revision, persists nothing, and fills no unknown time from any clock.
/// Semantic shortfalls become [`ReconsolidationOutcome`] values inside
/// [`Ok`]; only malformed or out-of-bound input becomes [`Err`].
///
/// # Errors
///
/// Returns [`ReconsolidationError`] when any bound, shape, ordering, receipt,
/// preservation, or denominator check fails closed.
#[allow(clippy::too_many_lines)]
pub fn propose_reconsolidation(
    request: &ReconsolidationRequest,
) -> Result<ReconsolidationResult, ReconsolidationError> {
    preflight_bounds(request)?;
    validate_shapes(request)?;

    request
        .receipt
        .validate()
        .map_err(|err| ReconsolidationError::Receipt {
            detail: redact(&err.to_string()),
        })?;
    if request.receipt.terminal_disposition != "accepted"
        && request.receipt.terminal_disposition != "partial"
    {
        return ok_result(
            ReconsolidationOutcome::Rejected,
            None,
            request.parent_propositions.len(),
            0,
            "a-05 receipt is not accepted or partial",
        );
    }
    if request.receipt.validator_policy != request.policy_id {
        return ok_result(
            ReconsolidationOutcome::Abstention,
            None,
            request.parent_propositions.len(),
            0,
            "receipt policy does not bind the expected policy",
        );
    }

    if request.curation_kind != CurationKind::Reconsolidation {
        return ok_result(
            ReconsolidationOutcome::Rejected,
            None,
            request.parent_propositions.len(),
            0,
            "curation kind is not reconsolidation",
        );
    }

    if request.parent.target_kind != TargetKind::DerivedMemory {
        return ok_result(
            ReconsolidationOutcome::Rejected,
            None,
            request.parent_propositions.len(),
            0,
            "raw episodes and artifacts are never reconsolidated",
        );
    }
    if request.parent.selected_by_timestamp {
        return ok_result(
            ReconsolidationOutcome::Rejected,
            None,
            request.parent_propositions.len(),
            0,
            "timestamp-selected latest is not an exact parent",
        );
    }
    if request.parent.handle == request.proposed_child_handle {
        return ok_result(
            ReconsolidationOutcome::Rejected,
            None,
            request.parent_propositions.len(),
            0,
            "self-parenting child handle is not admitted",
        );
    }
    if contains_handle(&request.parent.predecessor_chain, &request.parent.handle)
        || contains_handle(
            &request.parent.predecessor_chain,
            &request.proposed_child_handle,
        )
    {
        return ok_result(
            ReconsolidationOutcome::Rejected,
            None,
            request.parent_propositions.len(),
            0,
            "parent chain mints or repeats the child identity",
        );
    }
    if request.parent.frontier_revision != request.parent.revision {
        return ok_result(
            ReconsolidationOutcome::Stale,
            None,
            request.parent_propositions.len(),
            0,
            "parent frontier does not equal the current revision",
        );
    }
    if request.reactivation.checkpoint != request.parent.revision {
        return ok_result(
            ReconsolidationOutcome::Stale,
            None,
            request.parent_propositions.len(),
            0,
            "reactivation checkpoint does not match the parent revision",
        );
    }
    if request.reactivation.policy_id != request.policy_id {
        return ok_result(
            ReconsolidationOutcome::Abstention,
            None,
            request.parent_propositions.len(),
            0,
            "reactivation policy is not the expected policy",
        );
    }
    if request.reactivation.observation_kind != ReactivationObservationKind::ExternalObservation
        || !request.reactivation.exact_match
    {
        return ok_result(
            ReconsolidationOutcome::Abstention,
            None,
            request.parent_propositions.len(),
            0,
            "availability, index, model mention, or partial observation never qualifies",
        );
    }

    let parent_statements: Vec<String> = request
        .parent_propositions
        .iter()
        .map(|p| normalize_statement(&p.statement))
        .collect();
    let mut genuine: Vec<&NewEvidenceItem> = Vec::new();
    let mut unknown_temporal = 0usize;
    for item in &request.new_items {
        if item.source_kind != EvidenceSourceKind::ExternalObservation {
            continue;
        }
        if contains_handle(&request.parent_baseline_handles, &item.handle) {
            continue;
        }
        if contains_handle(&request.parent_baseline_lineages, &item.lineage) {
            continue;
        }
        let normalized = normalize_statement(&item.statement);
        if parent_statements.contains(&normalized) {
            continue;
        }
        if item.observed_at_ms.is_none() {
            unknown_temporal = unknown_temporal.saturating_add(1);
            continue;
        }
        genuine.push(item);
    }
    if genuine.is_empty() {
        if unknown_temporal > 0 {
            return ok_result(
                ReconsolidationOutcome::Abstention,
                None,
                request.parent_propositions.len(),
                0,
                "temporal order is unknown and no wall-clock fill is admitted",
            );
        }
        return ok_result(
            ReconsolidationOutcome::NoMaterialNewEvidence,
            None,
            request.parent_propositions.len(),
            0,
            "no material new item survives genuine-new filtering",
        );
    }

    if request.deltas.len() != request.parent_propositions.len() {
        return ok_result(
            ReconsolidationOutcome::Blocked,
            None,
            request.parent_propositions.len(),
            genuine.len(),
            "every parent proposition needs exactly one delta",
        );
    }
    for delta in &request.deltas {
        let Some(parent) = find_proposition(&request.parent_propositions, &delta.proposition_id)
        else {
            return ok_result(
                ReconsolidationOutcome::Blocked,
                None,
                request.parent_propositions.len(),
                genuine.len(),
                "delta names an unknown parent proposition",
            );
        };
        match delta.disposition {
            PropositionDisposition::Retained => {
                if let Some(revised) = delta.revised_statement.as_ref() {
                    if normalize_statement(revised) != normalize_statement(&parent.statement) {
                        return ok_result(
                            ReconsolidationOutcome::NoSafeRevision,
                            None,
                            request.parent_propositions.len(),
                            genuine.len(),
                            "retained must stay byte-exact in meaning",
                        );
                    }
                    return ok_result(
                        ReconsolidationOutcome::NoSafeRevision,
                        None,
                        request.parent_propositions.len(),
                        genuine.len(),
                        "retained carries no revised wording",
                    );
                }
                if !delta.evidence_refs.is_empty() {
                    let _ = &genuine;
                }
            }
            PropositionDisposition::Narrowed
            | PropositionDisposition::Qualified
            | PropositionDisposition::Contradicted => {
                let Some(revised) = delta.revised_statement.as_ref() else {
                    return Err(ReconsolidationError::Proposition {
                        id: redact(&delta.proposition_id),
                        detail: "changed disposition needs revised wording".to_owned(),
                    });
                };
                if revised.trim().is_empty() {
                    return Err(ReconsolidationError::Proposition {
                        id: redact(&delta.proposition_id),
                        detail: "revised wording is blank".to_owned(),
                    });
                }
                if delta.evidence_refs.is_empty() {
                    return ok_result(
                        ReconsolidationOutcome::NoSafeRevision,
                        None,
                        request.parent_propositions.len(),
                        genuine.len(),
                        "free-text replacement without evidence is not a revision",
                    );
                }
                if normalize_statement(revised) == normalize_statement(&parent.statement) {
                    return ok_result(
                        ReconsolidationOutcome::NoSafeRevision,
                        None,
                        request.parent_propositions.len(),
                        genuine.len(),
                        "cosmetic-only change is not a revision",
                    );
                }
                if mentions_majority_resolution(&delta.rationale) {
                    return ok_result(
                        ReconsolidationOutcome::NoSafeRevision,
                        None,
                        request.parent_propositions.len(),
                        genuine.len(),
                        "majority resolution never settles a contradiction",
                    );
                }
                let parent_digits = digits_of(&parent.statement);
                let revised_digits = digits_of(revised);
                let mut introduces_precision = false;
                for digit in &revised_digits {
                    if !parent_digits.contains(digit)
                        && !genuine.iter().any(|g| g.statement.contains(*digit))
                    {
                        introduces_precision = true;
                        break;
                    }
                }
                if introduces_precision || has_absolute_claim(revised) {
                    let mut supported = false;
                    for item in &genuine {
                        if item.statement.contains(revised.as_str())
                            || revised.contains(item.statement.as_str())
                        {
                            supported = true;
                            break;
                        }
                    }
                    if !supported {
                        return ok_result(
                            ReconsolidationOutcome::NoSafeRevision,
                            None,
                            request.parent_propositions.len(),
                            genuine.len(),
                            "unsupported precision or strength inflation is rejected",
                        );
                    }
                }
                if delta.disposition == PropositionDisposition::Contradicted
                    && delta.evidence_refs.is_empty()
                {
                    return ok_result(
                        ReconsolidationOutcome::NoSafeRevision,
                        None,
                        request.parent_propositions.len(),
                        genuine.len(),
                        "contradictions retain both sides with evidence",
                    );
                }
            }
            PropositionDisposition::Withdrawn => {
                if delta.revised_statement.is_some() {
                    return ok_result(
                        ReconsolidationOutcome::NoSafeRevision,
                        None,
                        request.parent_propositions.len(),
                        genuine.len(),
                        "withdrawal removes only from the child view",
                    );
                }
            }
            PropositionDisposition::Unresolved => {
                if delta.revised_statement.is_some() {
                    return ok_result(
                        ReconsolidationOutcome::NoSafeRevision,
                        None,
                        request.parent_propositions.len(),
                        genuine.len(),
                        "unresolved carries no revised wording",
                    );
                }
            }
        }
        for handle in &delta.evidence_refs {
            let known_new = genuine.iter().any(|g| &g.handle == handle);
            let known_base = contains_handle(&request.parent_baseline_handles, handle);
            let known_external = &request.reactivation.external_handle == handle;
            if !known_new && !known_base && !known_external {
                return Err(ReconsolidationError::Source {
                    handle: redact(handle),
                    detail: "delta evidence is outside parent, new, and reactivation handles"
                        .to_owned(),
                });
            }
        }
    }

    request
        .preservation
        .validate()
        .map_err(|err| ReconsolidationError::Preservation {
            detail: redact(&err.to_string()),
        })?;
    if request.preservation.overall().is_err() {
        return ok_result(
            ReconsolidationOutcome::Blocked,
            None,
            request.parent_propositions.len(),
            genuine.len(),
            "preservation is judged per dimension with no averaging",
        );
    }

    request
        .new_member_denominator
        .validate()
        .map_err(|err| ReconsolidationError::Denominator {
            detail: redact(&err.to_string()),
        })?;
    for item in &genuine {
        if !request
            .new_member_denominator
            .members
            .contains(&item.handle)
        {
            return ok_result(
                ReconsolidationOutcome::Blocked,
                None,
                request.parent_propositions.len(),
                genuine.len(),
                "admitted additions must sit in the separate new-member denominator",
            );
        }
    }
    for handle in &request.parent_baseline_handles {
        if request.new_member_denominator.members.contains(handle) {
            return ok_result(
                ReconsolidationOutcome::Blocked,
                None,
                request.parent_propositions.len(),
                genuine.len(),
                "parent members never share the new-member denominator",
            );
        }
    }

    if request.dependent_outcomes.len() != request.dependents.len() {
        return ok_result(
            ReconsolidationOutcome::Blocked,
            None,
            request.parent_propositions.len(),
            genuine.len(),
            "every affected dependent needs exactly one disposition",
        );
    }
    for dependent in &request.dependents {
        let Some(outcome) = request
            .dependent_outcomes
            .iter()
            .find(|o| o.handle == dependent.handle)
        else {
            if dependent.required {
                return ok_result(
                    ReconsolidationOutcome::Blocked,
                    None,
                    request.parent_propositions.len(),
                    genuine.len(),
                    "missing required dependent blocks completeness",
                );
            }
            continue;
        };
        if outcome.disposition == DependentDisposition::Blocked {
            return ok_result(
                ReconsolidationOutcome::Blocked,
                None,
                request.parent_propositions.len(),
                genuine.len(),
                "blocked dependent blocks completeness",
            );
        }
    }

    let mut has_unresolved = false;
    let mut has_load_bearing_unresolved = false;
    for delta in &request.deltas {
        if delta.disposition == PropositionDisposition::Unresolved {
            has_unresolved = true;
            if let Some(parent) =
                find_proposition(&request.parent_propositions, &delta.proposition_id)
                && parent.is_load_bearing
            {
                has_load_bearing_unresolved = true;
                break;
            }
        }
    }
    if has_load_bearing_unresolved {
        return ok_result(
            ReconsolidationOutcome::Blocked,
            None,
            request.parent_propositions.len(),
            genuine.len(),
            "load-bearing unresolved blocks completeness",
        );
    }
    if has_unresolved {
        return ok_result(
            ReconsolidationOutcome::Partial,
            Some(build_child(request)),
            request.parent_propositions.len(),
            genuine.len(),
            "non-load-bearing unresolved yields a partial candidate",
        );
    }

    ok_result(
        ReconsolidationOutcome::Complete,
        Some(build_child(request)),
        request.parent_propositions.len(),
        genuine.len(),
        "forward child revision proposed as an external request",
    )
}

/// Maps a terminal outcome to the closest A-05 hint without re-running validation.
///
/// Returns `None` for [`ReconsolidationOutcome::Complete`]; every other
/// outcome maps to the rejection class a downstream gate would most likely
/// record. The mapping is diagnostic only and never executes validation.
#[must_use]
pub fn outcome_rejection_hint(outcome: &ReconsolidationOutcome) -> Option<RejectionCode> {
    match outcome {
        ReconsolidationOutcome::Complete => None,
        ReconsolidationOutcome::Partial | ReconsolidationOutcome::Blocked => {
            Some(RejectionCode::PreservationFailed)
        }
        ReconsolidationOutcome::NoMaterialNewEvidence | ReconsolidationOutcome::Abstention => {
            Some(RejectionCode::LineageMismatch)
        }
        ReconsolidationOutcome::NoSafeRevision => Some(RejectionCode::UnsupportedPrecision),
        ReconsolidationOutcome::Stale | ReconsolidationOutcome::Rejected => {
            Some(RejectionCode::IdentityMismatch)
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use eliot_contracts::{AuthorityEpoch, ResourceGeneration, StateFence};
    use eliot_dreamer_contracts::candidate::{DimensionVerdict, PreservationDimension};
    use eliot_dreamer_contracts::{AtomicityMode, PreservationReport};

    fn test_fence() -> StateFence {
        StateFence::new(AuthorityEpoch::genesis(), ResourceGeneration::genesis())
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

    fn test_owners() -> AxisOwnerRefs {
        AxisOwnerRefs {
            support_owner: "owner-support".to_owned(),
            assertability_owner: "owner-assert".to_owned(),
            accessibility_owner: "owner-access".to_owned(),
            influence_owner: "owner-influence".to_owned(),
            lifecycle_owner: "owner-lifecycle".to_owned(),
            privacy_owner: "owner-privacy".to_owned(),
            retention_owner: "owner-retention".to_owned(),
            source_assurance_owner: "owner-assurance".to_owned(),
        }
    }

    fn valid_request() -> ReconsolidationRequest {
        ReconsolidationRequest {
            curation_kind: CurationKind::Reconsolidation,
            parent: ParentRevision {
                handle: "derived-1".to_owned(),
                revision: "rev-2".to_owned(),
                predecessor_chain: vec!["rev-1".to_owned()],
                frontier_revision: "rev-2".to_owned(),
                target_kind: TargetKind::DerivedMemory,
                selected_by_timestamp: false,
            },
            parent_propositions: vec![
                ParentProposition {
                    id: "p1".to_owned(),
                    statement: "Caching helps warm keys.".to_owned(),
                    support_handle: "src-a".to_owned(),
                    lineage: "lineage-a".to_owned(),
                    is_load_bearing: false,
                },
                ParentProposition {
                    id: "p2".to_owned(),
                    statement: "Cold starts stay slow.".to_owned(),
                    support_handle: "src-b".to_owned(),
                    lineage: "lineage-b".to_owned(),
                    is_load_bearing: false,
                },
            ],
            deltas: vec![
                PropositionDelta {
                    proposition_id: "p1".to_owned(),
                    disposition: PropositionDisposition::Retained,
                    revised_statement: None,
                    rationale: "no new evidence touches p1".to_owned(),
                    evidence_refs: vec![],
                },
                PropositionDelta {
                    proposition_id: "p2".to_owned(),
                    disposition: PropositionDisposition::Qualified,
                    revised_statement: Some(
                        "Cold starts stay slow except after the observed warm-up.".to_owned(),
                    ),
                    rationale: "obs-1 shows warm-up shortens cold starts".to_owned(),
                    evidence_refs: vec!["obs-1".to_owned()],
                },
            ],
            new_items: vec![NewEvidenceItem {
                handle: "obs-1".to_owned(),
                digest: "1".repeat(64),
                lineage: "lineage-new-1".to_owned(),
                statement: "Warm-up run 7 shortened the next cold start.".to_owned(),
                source_kind: EvidenceSourceKind::ExternalObservation,
                observed_at_ms: Some(1_700_000_000_000),
            }],
            parent_baseline_handles: vec!["src-a".to_owned(), "src-b".to_owned()],
            parent_baseline_lineages: vec!["lineage-a".to_owned(), "lineage-b".to_owned()],
            reactivation: ReactivationEvidence {
                checkpoint: "rev-2".to_owned(),
                policy_id: "policy-7".to_owned(),
                external_handle: "obs-ext-1".to_owned(),
                observation_kind: ReactivationObservationKind::ExternalObservation,
                exact_match: true,
                observed_at_ms: Some(1_700_000_000_001),
            },
            dependents: vec![DependentRecord {
                handle: "dep-1".to_owned(),
                required: true,
                kind: "summary".to_owned(),
            }],
            dependent_outcomes: vec![DependentOutcome {
                handle: "dep-1".to_owned(),
                disposition: DependentDisposition::Revalidate,
                note: "revalidate summary against the qualified child".to_owned(),
            }],
            axis_owners: test_owners(),
            preservation: test_preservation(),
            receipt: test_receipt(),
            new_member_denominator: TargetDenominator {
                mode: AtomicityMode::PerMember,
                members: vec!["obs-1".to_owned()],
                expected_total: 1,
            },
            proposed_child_handle: "derived-1-rev-3".to_owned(),
            child_verifier: "verifier-7".to_owned(),
            child_inverse_note: "set aside derived-1-rev-3 to restore rev-2".to_owned(),
            child_forward_correction: "re-qualify p2 on the next warm-up outcome".to_owned(),
            child_expiry_ms: Some(1_800_000_000_000),
            child_reopen_condition: "reopen when rev-2 frontier advances".to_owned(),
            policy_id: "policy-7".to_owned(),
        }
    }

    // WORK_UNIT_CASE: 667/1
    #[test]
    fn case_01_valid_derived_completes_with_allocation_request() {
        let request = valid_request();
        let result = propose_reconsolidation(&request).expect("valid request is well-formed");
        assert_eq!(result.outcome, ReconsolidationOutcome::Complete);
        assert_eq!(result.accounted_parents, 2);
        assert_eq!(result.admitted_new, 1);
        let child = result.child.expect("complete carries a child request");
        assert_eq!(child.parent_handle, "derived-1");
        assert_eq!(child.parent_revision, "rev-2");
        assert_eq!(child.proposed_child_handle, "derived-1-rev-3");
        assert!(child.request_only);
        assert!(!child.allocates_revision);
        assert_eq!(outcome_rejection_hint(&result.outcome), None);
    }

    // WORK_UNIT_CASE: 667/4
    #[test]
    fn case_04_stale_frontier_blocks_single_parent_identity() {
        let mut request = valid_request();
        request.parent.frontier_revision = "rev-1".to_owned();
        let result = propose_reconsolidation(&request).expect("stale is an outcome, not malformed");
        assert_eq!(result.outcome, ReconsolidationOutcome::Stale);
        assert!(result.child.is_none());
        let mut request = valid_request();
        request.parent.predecessor_chain = vec!["rev-1".to_owned(), "rev-1".to_owned()];
        assert!(propose_reconsolidation(&request).is_err());
    }

    // WORK_UNIT_CASE: 667/9
    #[test]
    fn case_09_unqualified_reactivation_abstains() {
        let mut request = valid_request();
        request.reactivation.observation_kind = ReactivationObservationKind::Availability;
        let result =
            propose_reconsolidation(&request).expect("availability shortfall is an outcome");
        assert_eq!(result.outcome, ReconsolidationOutcome::Abstention);
        assert!(result.child.is_none());
        let mut partial = valid_request();
        partial.reactivation.observation_kind = ReactivationObservationKind::PartialObservation;
        partial.reactivation.exact_match = true;
        let result =
            propose_reconsolidation(&partial).expect("partial observation abstains as unknown");
        assert_eq!(result.outcome, ReconsolidationOutcome::Abstention);
    }

    // WORK_UNIT_CASE: 667/15
    #[test]
    fn case_15_reactivation_without_new_evidence_yields_no_candidate() {
        let mut request = valid_request();
        request.new_items = Vec::new();
        request.new_member_denominator = TargetDenominator {
            mode: AtomicityMode::PerMember,
            members: Vec::new(),
            expected_total: 0,
        };
        let result = propose_reconsolidation(&request).expect("empty new evidence is an outcome");
        assert_eq!(
            result.outcome,
            ReconsolidationOutcome::NoMaterialNewEvidence
        );
        assert!(result.child.is_none());
        let mut restated = valid_request();
        restated.new_items[0].statement = "Caching helps warm keys.".to_owned();
        let result =
            propose_reconsolidation(&restated).expect("restatement is filtered as not new");
        assert_eq!(
            result.outcome,
            ReconsolidationOutcome::NoMaterialNewEvidence
        );
    }

    // WORK_UNIT_CASE: 667/36
    #[test]
    fn case_36_child_is_request_not_issued_revision() {
        let request = valid_request();
        let frozen = request.clone();
        let result = propose_reconsolidation(&request).expect("valid request completes");
        assert_eq!(request, frozen, "pure handler never mutates its inputs");
        let child = result.child.expect("complete carries a child request");
        assert!(child.request_only);
        assert!(!child.allocates_revision);
        assert_ne!(child.proposed_child_handle, child.parent_revision);
        assert!(!child.verifier.trim().is_empty());
        assert!(!child.inverse_note.trim().is_empty());
        assert!(!child.forward_correction.trim().is_empty());
        assert!(!child.reopen_condition.trim().is_empty());
    }
}
