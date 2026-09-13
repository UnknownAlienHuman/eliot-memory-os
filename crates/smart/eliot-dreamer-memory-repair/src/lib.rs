//! Bounded typed memory-defect repair candidate (A-30).
//!
//! Pure candidate-only owner of exactly one typed non-identity-surgery
//! defect: missing provenance, contaminated influence, false relation, stale
//! derived view, or representation gap. The handler proposes one bounded
//! owner-directed repair, verification, or inverse candidate; it never
//! persists, allocates identities, rewrites sources, mutates relations,
//! views, or axes, traverses graphs, runs books, calls providers, models,
//! tools, or ambient state, and never exercises authority, effects, or
//! terminal completion semantics.
//!
//! Cell `smart.dreamer.memory_repair`, order 30. Inputs are immutable and
//! caller-supplied; every clock observation, policy binding, digest, and
//! receipt is explicit. The A-05 receipt is checked intrinsically via its own
//! validation entry point and is never re-executed here.
//!
//! Absence note: this file contains no persistence, identifier allocation,
//! graph traversal, run-book execution, provider, model, tool, ambient-state,
//! authority, effect, or terminal-completion calls by construction; the only
//! cryptography is the canonical digest below, and the only fallible work is
//! pure bounded validation. There are no placeholder, mock, canned, or
//! pseudo paths: every branch binds an explicit input field.
//!
//! Test coverage note: 6 of 66 `WORK_UNIT_CASE 671/*` cases execute here
//! (671/1 valid missing-provenance, 671/16 complete contamination closure,
//! 671/24 invalidate false relation, 671/33 stale view preserve, 671/40
//! representation one identity, 671/57 determinism). The remaining 60 of 66
//! are deferred per START.md s1/s22.1; #966 admission is separate.
//! Deferred: 671/2, 671/3, 671/4, 671/5, 671/6, 671/7, 671/8, 671/9, 671/10,
//! 671/11, 671/12, 671/13, 671/14, 671/15, 671/17, 671/18, 671/19, 671/20,
//! 671/21, 671/22, 671/23, 671/25, 671/26, 671/27, 671/28, 671/29, 671/30,
//! 671/31, 671/32, 671/34, 671/35, 671/36, 671/37, 671/38, 671/39, 671/41,
//! 671/42, 671/43, 671/44, 671/45, 671/46, 671/47, 671/48, 671/49, 671/50,
//! 671/51, 671/52, 671/53, 671/54, 671/55, 671/56, 671/58, 671/59, 671/60,
//! 671/61, 671/62, 671/63, 671/64, 671/65, 671/66.

#![forbid(unsafe_code)]

use eliot_contracts::{StateFence, canonical_json_bytes, sha256_hex};
use eliot_dreamer_candidate_validation::RejectionCode;
use eliot_dreamer_contracts::{
    CurationKind, GroundedDreamDraft, PreservationReport, TargetDenominator, ValidatedCurationItem,
    ValidationReceipt, is_hex64_lower,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Independent bounds (no cross-subsidy between dimensions).
// ---------------------------------------------------------------------------

/// Maximum affected members admitted in one request.
pub const MAX_AFFECTED: usize = 64;
/// Maximum evidence items admitted in any single evidence list.
pub const MAX_EVIDENCE_ITEMS: usize = 64;
/// Maximum closure dependent refs admitted in one request.
pub const MAX_CLOSURE_REFS: usize = 256;
/// Maximum protection entries admitted in one request.
pub const MAX_PROTECTIONS: usize = 32;
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

fn check_handle(value: &str, field: &str) -> Result<(), RepairError> {
    if value.is_empty() || value.len() > MAX_HANDLE_BYTES {
        return Err(RepairError::Bounds {
            phase: field.to_owned(),
            detail: "handle is blank or exceeds the handle ceiling".to_owned(),
        });
    }
    if has_control(value) {
        return Err(RepairError::Bounds {
            phase: field.to_owned(),
            detail: "handle carries control characters".to_owned(),
        });
    }
    Ok(())
}

fn check_text(value: &str, field: &str) -> Result<(), RepairError> {
    if value.trim().is_empty() || value.len() > MAX_TEXT_BYTES {
        return Err(RepairError::Bounds {
            phase: field.to_owned(),
            detail: "text is blank or exceeds the text ceiling".to_owned(),
        });
    }
    if has_control(value) {
        return Err(RepairError::Bounds {
            phase: field.to_owned(),
            detail: "text carries control characters".to_owned(),
        });
    }
    Ok(())
}

fn check_digest(value: &str, field: &str) -> Result<(), RepairError> {
    if !is_hex64_lower(value) {
        return Err(RepairError::Bounds {
            phase: field.to_owned(),
            detail: "digest is not 64 lowercase hex".to_owned(),
        });
    }
    Ok(())
}

fn mentions_similarity_as_proof(note: &str) -> bool {
    let lowered = note.to_lowercase();
    lowered.contains("similar")
        || lowered.contains("looks like")
        || lowered.contains("confidence proves")
        || lowered.contains("model says the author")
}

fn claims_chronology_is_causality(note: &str) -> bool {
    let lowered = note.to_lowercase();
    (lowered.contains("before") || lowered.contains("earlier") || lowered.contains("preceded"))
        && (lowered.contains("therefore causes")
            || lowered.contains("hence causes")
            || lowered.contains("proves caus")
            || lowered.contains("is the cause"))
}

fn claims_timestamp_is_currentness(note: &str) -> bool {
    let lowered = note.to_lowercase();
    (lowered.contains("newest")
        || lowered.contains("latest timestamp")
        || lowered.contains("most recent"))
        && (lowered.contains("therefore current")
            || lowered.contains("hence current")
            || lowered.contains("proves current")
            || lowered.contains("is current"))
}

// ---------------------------------------------------------------------------
// Closed repair spellings carried by the A-03 repair payload.
// ---------------------------------------------------------------------------

/// Accepted `repair` spellings for the missing-provenance family.
pub const PROVENANCE_REPAIRS: &[&str] = &["provenance-link", "provenance-quarantine"];
/// Accepted `repair` spellings for the contaminated-influence family.
pub const CONTAMINATION_REPAIRS: &[&str] = &[
    "contamination-quarantine",
    "influence-revoke-request",
    "influence-restrict-request",
    "influence-revalidate-request",
];
/// Accepted `repair` spellings for the false-relation family.
pub const RELATION_REPAIRS: &[&str] = &[
    "relation-invalidate",
    "relation-reclassify",
    "relation-replace",
    "relation-quarantine",
];
/// Accepted `repair` spellings for the stale-derived-view family.
pub const STALE_VIEW_REPAIRS: &[&str] = &["view-invalidate", "view-rebuild", "view-revalidate"];
/// Accepted `repair` spellings for the representation-gap family.
pub const REPRESENTATION_REPAIRS: &[&str] = &[
    "representation-add",
    "representation-repair",
    "representation-remove",
];
/// `repair` spellings owned by A-27 merge/split identity work (#665).
pub const IDENTITY_SURGERY_REPAIRS: &[&str] = &[
    "merge",
    "split",
    "merge-identities",
    "split-identity",
    "false-merge",
    "merge-split",
];
/// `repair` spellings owned by A-28 derived-content reconsolidation (#667).
pub const RECONSOLIDATION_REPAIRS: &[&str] = &[
    "reconsolidate",
    "reconsolidation",
    "forward-revision",
    "content-revision",
];
/// `repair` spellings owned by A-29 pure axis tuning (#669).
pub const AXIS_TUNING_REPAIRS: &[&str] = &[
    "axis-tune",
    "accessibility-tune",
    "influence-tune",
    "axis-adjust",
];

// ---------------------------------------------------------------------------
// Public vocabulary.
// ---------------------------------------------------------------------------

/// The exactly-one defect family this candidate repairs.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
pub enum RepairDefectKind {
    /// An exact lineage edge or field is missing.
    MissingProvenance,
    /// A derived influence is tainted and needs closure-bound handling.
    ContaminatedInfluence,
    /// A registry relation is false and needs typed correction.
    FalseRelation,
    /// A derived view is stale and needs owner-directed rebuild.
    StaleDerivedView,
    /// A canonical identity lacks an adequate representation.
    RepresentationGap,
}

/// Closed inert operation proposed to the owning handler.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
pub enum RepairOperationKind {
    /// Link one authoritative source to the missing edge.
    ProvenanceLink,
    /// Hold members for owner revalidation without changing them.
    QuarantineForRevalidation,
    /// Invalidate one exact relation revision.
    RelationInvalidate,
    /// Reclassify one exact relation under a grounded type.
    RelationReclassify,
    /// Replace one exact relation with an independently grounded one.
    RelationReplace,
    /// Invalidate consumers of a stale view.
    ViewInvalidate,
    /// Rebuild a view from a complete source frontier.
    ViewRebuild,
    /// Revalidate consumers against a rebuilt view.
    ViewRevalidateConsumers,
    /// Add a representation for one canonical identity.
    RepresentationAdd,
    /// Repair a representation without touching canonical content.
    RepresentationRepair,
    /// Remove a duplicate or harmful representation.
    RepresentationRemove,
    /// Route members to owner-directed review with no state change.
    OwnerDirectedReview,
}

/// Exactly-one disposition per affected member.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
pub enum MemberDispositionKind {
    /// Member is unchanged; evidence names why it is unaffected.
    UnchangedWithEvidence,
    /// Member gains one authoritative provenance link.
    ProvenanceLink,
    /// Member is held for owner revalidation.
    QuarantineRevalidate,
    /// Member relation binding changes by typed correction.
    RelationChange,
    /// Member view is rebuilt from a complete frontier.
    Rebuild,
    /// Member representation changes without content rewrite.
    RepresentationChange,
    /// Member is visible to its owner only pending review.
    OwnerOnlyVisibility,
    /// Member is unavailable or unknown and blocks completeness.
    BlockedUnavailableUnknown,
}

/// Closed subject classes. Raw history is never rewritten here.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
pub enum SubjectKind {
    /// Held semantic memory subject to typed repair.
    SemanticMemory,
    /// Derived view subject to invalidate or rebuild.
    DerivedView,
    /// Relation record subject to typed correction.
    RelationRecord,
    /// Representation record subject to add, repair, or removal.
    RepresentationRecord,
    /// Influence record subject to closure-bound handling.
    InfluenceRecord,
    /// Raw episode history; preserved verbatim, never repaired here.
    RawEpisode,
}

/// Closed authority classes for a provenance link. Similarity is never one.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
pub enum SourceAuthorityKind {
    /// An authoritative recorded transition.
    AuthoritativeTransition,
    /// An authoritative held artifact.
    AuthoritativeArtifact,
    /// An authoritative validation receipt.
    AuthoritativeReceipt,
    /// An authoritative admitted source.
    AuthoritativeSource,
}

/// Terminal outcome of one repair request. Fail-closed ordering applies.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
pub enum RepairOutcome {
    /// One complete candidate with full accounting and proof.
    Complete,
    /// A candidate with named partial coverage; completeness is blocked.
    Partial,
    /// The handler abstains; members route to quarantine or revalidation.
    Abstention,
    /// No safe repair exists under the given evidence and ceilings.
    NoSafeRepair,
    /// Inputs moved under the request; replay against the new revision.
    Stale,
    /// A mandatory closure, member, or evidence block is unavailable.
    Blocked,
    /// Owner review is required before any completion claim.
    Review,
    /// The request is rejected with a boundary handoff.
    Rejected,
}

/// Typed fail-closed error. Malformed input only; semantic shortfalls are outcomes.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
pub enum RepairError {
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
    /// A member, closure, or evidence record is malformed.
    Member {
        /// Member or record handle (redacted).
        handle: String,
        /// Bounded detail.
        detail: String,
    },
    /// An intrinsic receipt, item, or draft check failed.
    Receipt {
        /// Bounded detail.
        detail: String,
    },
}

// ---------------------------------------------------------------------------
// Owner, trajectory, threat, and projection records.
// ---------------------------------------------------------------------------

/// Owner references for every independent memory axis.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AxisOwnerRefs {
    /// Owner of the existence and lifecycle axis.
    pub existence_owner: String,
    /// Owner of the support and assertability axis.
    pub support_owner: String,
    /// Owner of the accessibility axis.
    pub accessibility_owner: String,
    /// Owner of the influence axis.
    pub influence_owner: String,
    /// Owner of the privacy and retention axis.
    pub privacy_owner: String,
    /// Owner of the erasure axis.
    pub erasure_owner: String,
    /// Owner of the source-assurance axis.
    pub assurance_owner: String,
}

/// Trajectory occurrence, recurrence, and extinction evidence.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TrajectoryEvidence {
    /// Exact failure trigger the defect was observed under.
    pub failure_trigger: String,
    /// Occurrence count observed in the trajectory window.
    pub occurrences: u32,
    /// Recurrence count across windows.
    pub recurrences: u32,
    /// False-positive observations retained as counterevidence.
    pub false_positive_refs: Vec<String>,
    /// Rival explanations retained without suppression.
    pub rival_refs: Vec<String>,
    /// Unknown trajectory branches that remain open.
    pub unknown_refs: Vec<String>,
    /// Reopen condition naming what revives review.
    pub reopen_condition: String,
    /// Extinction evidence ref when the failure no longer fires, if any.
    pub extinction_evidence_ref: Option<String>,
    /// External run-book reference (read-only; never executed here).
    pub runbook_ref: Option<String>,
}

/// Threat lineage bound to the defect without executing any handling.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ThreatEvidence {
    /// Threat lineage identifiers in sorted unique order.
    pub threat_lineage_refs: Vec<String>,
    /// Revocation lineage identifiers in sorted unique order.
    pub revocation_refs: Vec<String>,
    /// Taint lineage identifiers in sorted unique order.
    pub taint_refs: Vec<String>,
    /// Review owner that owns threat qualification.
    pub review_owner: String,
}

/// Exact current projection of the defective subject and its axes.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CurrentMemoryProjection {
    /// Subject handle under repair.
    pub subject_handle: String,
    /// Closed subject class.
    pub subject_kind: SubjectKind,
    /// Current subject revision the candidate binds.
    pub subject_revision: String,
    /// Canonical digest of the current subject bytes (64 lowercase hex).
    pub subject_digest: String,
    /// Scope the subject is projected under.
    pub scope_id: String,
    /// Task the subject is projected under.
    pub task_id: String,
    /// Policy the subject is projected under.
    pub policy_id: String,
    /// State fence of the projection.
    pub state_fence: StateFence,
    /// Owner references for every independent axis.
    pub owners: AxisOwnerRefs,
    /// Current revision held per axis, one entry per axis name.
    pub axis_revisions: Vec<String>,
    /// Trajectory evidence bound to the defect.
    pub trajectory: TrajectoryEvidence,
    /// Threat evidence bound to the defect.
    pub threat: ThreatEvidence,
    /// Protection reasons that must keep holding.
    pub protection_refs: Vec<String>,
    /// Negative-memory triggers retained until qualified extinction.
    pub negative_memory_refs: Vec<String>,
    /// Counterevidence and minority material retained verbatim.
    pub counterevidence_refs: Vec<String>,
}

// ---------------------------------------------------------------------------
// Per-kind repair specifications.
// ---------------------------------------------------------------------------

/// One authoritative link admissible as missing-provenance fill.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AuthoritativeSourceLink {
    /// Source handle the link points at.
    pub source_handle: String,
    /// Closed authority class of the source.
    pub authority: SourceAuthorityKind,
    /// Exact source revision the link binds.
    pub source_revision: String,
    /// Canonical digest of the source bytes (64 lowercase hex).
    pub source_digest: String,
    /// Scope the source admits.
    pub scope_id: String,
    /// Privacy note bounding the link.
    pub privacy_note: String,
    /// Fence note binding the link.
    pub fence_note: String,
    /// Why this source exactly matches the missing edge.
    pub match_note: String,
}

/// Missing-provenance repair specification.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ProvenanceRepairSpec {
    /// Exact missing edge or field identity.
    pub missing_edge: String,
    /// Complete expected lineage denominator (sorted, unique).
    pub expected_lineage: Vec<String>,
    /// Expected denominator total; member count must equal it.
    pub expected_total: u32,
    /// The one authoritative link, when established.
    pub authoritative_source: Option<AuthoritativeSourceLink>,
    /// Conflicting lineage refs preserved without deletion.
    pub conflicting_lineage_refs: Vec<String>,
    /// Affected derivative refs preserved without silent change.
    pub affected_derivative_refs: Vec<String>,
    /// True when the only support is content similarity or confidence.
    pub similarity_only: bool,
    /// True when the source owner conflicts with another claimant.
    pub owner_conflict: bool,
    /// Verifier that checks the proposed link.
    pub verifier: String,
}

/// Complete public closure over every affected branch for contamination.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ContaminationClosure {
    /// Closure identity.
    pub closure_id: String,
    /// Every affected dependent in sorted unique order.
    pub dependent_refs: Vec<String>,
    /// Expected dependent total; member count must equal it when complete.
    pub expected_dependents_total: u32,
    /// True only when the closure covers every affected branch.
    pub complete: bool,
    /// True when the closure revision is stale.
    pub stale: bool,
    /// Unknown gaps that remain open.
    pub unknown_gaps: Vec<String>,
    /// Review owner of the closure.
    pub review_owner: String,
    /// Renewal owner for reopening.
    pub renewal_owner: String,
    /// Verifier that checks quarantine and renewal.
    pub verifier: String,
    /// Policy the closure is bound under.
    pub policy_id: String,
    /// Scope the closure covers.
    pub scope_id: String,
    /// Closure revision.
    pub closure_revision: String,
    /// State fence of the closure.
    pub state_fence: StateFence,
}

/// Closed inert action for a contaminated influence.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
pub enum ContaminationAction {
    /// Hold dependents for owner revalidation.
    QuarantineDependents,
    /// Request revocation of one dependent by its owner.
    RevokeDependent,
    /// Request narrowing of the influence scope.
    RestrictScope,
    /// Request revalidation against new owner-admitted evidence.
    RevalidateWithNewEvidence,
}

/// Contaminated-influence repair specification.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ContaminationRepairSpec {
    /// Tainted subject handle.
    pub subject_handle: String,
    /// Taint source handle.
    pub source_handle: String,
    /// Derived influence under suspicion.
    pub derived_influence_note: String,
    /// Current policy and graph note.
    pub current_graph_note: String,
    /// Exact taint lineage refs (sorted, unique).
    pub taint_lineage_refs: Vec<String>,
    /// Exact revocation lineage refs (sorted, unique).
    pub revocation_refs: Vec<String>,
    /// Proposed inert action; execution stays with the owner.
    pub action: ContaminationAction,
    /// Complete public closure over every affected branch.
    pub closure: ContaminationClosure,
    /// Note proving other axes and raw history stay unchanged.
    pub other_axes_preserved_note: String,
    /// Inverse and reconciliation note restoring the before state.
    pub inverse_note: String,
    /// True when retrieval or model agreement is offered as cleansing.
    pub agreement_offered_as_cleansing: bool,
}

/// Closed proposal for a false relation.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
pub enum FalseRelationProposal {
    /// Invalidate the exact relation revision.
    Invalidate,
    /// Reclassify under a new independently grounded type.
    Reclassify {
        /// Proposed relation type.
        new_type: String,
    },
    /// Replace with an independently grounded relation.
    Replace {
        /// Replacement grounding reference.
        replacement_ref: String,
    },
    /// Hold the relation for owner reverification.
    QuarantineReverify,
}

/// False-relation repair specification.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FalseRelationSpec {
    /// Exact relation identity.
    pub relation_id: String,
    /// Current relation type.
    pub relation_type: String,
    /// Current relation revision.
    pub relation_revision: String,
    /// Registry owner of the relation.
    pub registry_owner: String,
    /// First endpoint handle.
    pub endpoint_a: String,
    /// First endpoint revision.
    pub endpoint_a_revision: String,
    /// Second endpoint handle.
    pub endpoint_b: String,
    /// Second endpoint revision.
    pub endpoint_b_revision: String,
    /// Scope the relation claims.
    pub scope_id: String,
    /// Fence note binding the relation.
    pub fence_note: String,
    /// Original source and support refs (sorted, unique).
    pub original_source_refs: Vec<String>,
    /// Contradictory or changed-condition evidence refs (sorted, unique).
    pub contradictory_evidence_refs: Vec<String>,
    /// Full dependent and use denominator (sorted, unique).
    pub dependent_refs: Vec<String>,
    /// Expected dependent total; member count must equal it when complete.
    pub expected_dependents_total: u32,
    /// True when chronology or correlation is offered as causality.
    pub chronology_offered_as_causality: bool,
    /// Proposed typed correction.
    pub proposal: FalseRelationProposal,
    /// Old-to-new mapping note preserved for audit.
    pub mapping_note: String,
    /// Verifier that checks the correction.
    pub verifier: String,
    /// Inverse and forward-correction note.
    pub inverse_note: String,
}

/// Stale-derived-view repair specification.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct StaleViewSpec {
    /// View handle.
    pub view_handle: String,
    /// View schema identity.
    pub view_schema: String,
    /// Stale view revision preserved for audit.
    pub view_revision: String,
    /// Canonical digest of the stale view bytes (64 lowercase hex).
    pub view_digest: String,
    /// Original source recipe identity.
    pub source_recipe: String,
    /// Complete source frontier (sorted, unique).
    pub source_frontier: Vec<String>,
    /// Expected frontier total; member count must equal it when complete.
    pub expected_frontier_total: u32,
    /// Owner-issued invalidation evidence ref.
    pub invalidation_ref: String,
    /// Owner that owns the rebuild.
    pub rebuild_owner: String,
    /// Input contract the rebuild follows.
    pub rebuild_contract_ref: String,
    /// True only when old bytes and history stay addressable.
    pub old_bytes_preserved: bool,
    /// True when a bare timestamp is offered as currentness proof.
    pub timestamp_offered_as_currentness: bool,
    /// Affected consumer, cue, index, and decision refs (sorted, unique).
    pub consumer_refs: Vec<String>,
    /// Verifier that checks the rebuilt view.
    pub verifier: String,
    /// Inverse and forward-correction note.
    pub inverse_note: String,
}

/// Closed proposal for a representation gap.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
pub enum RepresentationProposal {
    /// Add a representation for the canonical identity.
    Add,
    /// Repair a representation without touching canonical content.
    Repair,
    /// Remove a duplicate or harmful representation.
    Remove,
}

/// Representation-gap repair specification.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RepresentationSpec {
    /// The one existing canonical semantic identity.
    pub canonical_identity: String,
    /// Canonical revision the representation binds.
    pub canonical_revision: String,
    /// Canonical source reference.
    pub canonical_source_ref: String,
    /// Canonical digest of the source bytes (64 lowercase hex).
    pub canonical_digest: String,
    /// Exact missing or inadequate representation.
    pub missing_representation_note: String,
    /// Consumer need the representation serves.
    pub consumer_need_note: String,
    /// Accepted representation schema or format.
    pub representation_schema: String,
    /// Accepted representation recipe or measurement.
    pub representation_recipe: String,
    /// Source coverage refs (sorted, unique).
    pub source_coverage_refs: Vec<String>,
    /// Omission note; lossy summaries must declare exact omissions.
    pub omission_note: String,
    /// True only when the representation is exactly reversible.
    pub reversible: bool,
    /// Addressability note binding the representation to its source.
    pub addressability_note: String,
    /// Proposed inert change.
    pub proposal: RepresentationProposal,
    /// True when the request would create a second truth or support owner.
    pub second_truth: bool,
    /// True when the request widens support, accessibility, influence,
    /// disclosure, privacy, or effect ceilings implicitly.
    pub widens_ceilings: bool,
    /// Complete affected consumer, index, and context refs (sorted, unique).
    pub consumer_refs: Vec<String>,
    /// Verifier that checks the representation.
    pub verifier: String,
    /// Inverse and removal note.
    pub inverse_note: String,
}

// ---------------------------------------------------------------------------
// Member accounting, policy, request, and candidate.
// ---------------------------------------------------------------------------

/// One affected source, member, or dependent under repair.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AffectedMember {
    /// Member handle.
    pub handle: String,
    /// Owner that owns the member.
    pub owner: String,
    /// True when the member is required for a complete candidate.
    pub required: bool,
    /// True when the member state is unavailable or unknown.
    pub unknown: bool,
}

/// One owner-specific disposition for exactly one affected member.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MemberDisposition {
    /// Member handle this disposition accounts for.
    pub handle: String,
    /// Closed disposition kind.
    pub disposition: MemberDispositionKind,
    /// Exact old state identity.
    pub old_identity: String,
    /// Proposed state identity.
    pub proposed_identity: String,
    /// Owner that owns the member.
    pub owner: String,
    /// Reason binding the disposition to evidence.
    pub reason: String,
    /// Evidence reference supporting the disposition.
    pub evidence_ref: String,
    /// Scope the disposition applies under.
    pub scope_id: String,
    /// Fence note binding the disposition.
    pub fence_note: String,
    /// Verifier that checks the disposition.
    pub verifier: String,
    /// Inverse restoring the old state.
    pub inverse_note: String,
    /// Proof note naming the executed check.
    pub proof_note: String,
}

/// One typed inert operation proposed to an external owner.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TypedRepairOperation {
    /// Closed operation kind.
    pub operation: RepairOperationKind,
    /// External owner that must execute or decline the operation.
    pub owner: String,
    /// Verifier that checks the operation outcome.
    pub verifier: String,
    /// Inverse restoring the before state.
    pub inverse_note: String,
    /// Explicit expiry of the operation in milliseconds, if any.
    pub expiry_ms: Option<u64>,
    /// Scope the operation applies under.
    pub scope_id: String,
}

/// Closed policy governing one repair request.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RepairPolicy {
    /// Governing policy identity; must equal the receipt validator policy.
    pub policy_id: String,
    /// Subject the policy governs.
    pub target_subject: String,
    /// Verifier identity for the expected observable.
    pub verifier: String,
    /// Observation window the observable is checked in.
    pub observation_window_note: String,
    /// Inverse restoring the before state.
    pub inverse_note: String,
    /// Explicit expiry of the proposal in milliseconds, if any.
    pub expiry_ms: Option<u64>,
    /// Renewal condition naming what reopens review.
    pub renewal_condition: String,
    /// Support ceiling the repair must not widen.
    pub support_ceiling: String,
    /// Privacy ceiling the repair must not widen.
    pub privacy_ceiling: String,
    /// Influence ceiling the repair must not widen.
    pub influence_ceiling: String,
    /// Maximum affected members admitted.
    pub max_affected: usize,
    /// Maximum evidence items admitted per list.
    pub max_evidence_items: usize,
    /// True when the caller cancelled this request.
    pub cancelled: bool,
    /// Explicit observation time in milliseconds, if any.
    pub observation_time_ms: Option<u64>,
    /// Frozen deadline in milliseconds, if any.
    pub deadline_ms: Option<u64>,
}

/// Complete repair request binding the six canonical families:
///
/// validated curation item, frozen bundle, grounded draft, current memory and
/// trajectory projection, affected dependency projection, and policy.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MemoryRepairRequest {
    /// Validated A-03 curation item; kind must be repair.
    pub item: ValidatedCurationItem,
    /// Grounded draft the item digest binds.
    pub grounded: GroundedDreamDraft,
    /// Frozen bundle digest; must equal the receipt bundle digest.
    pub frozen_bundle_digest: String,
    /// Frozen manifest digest; must equal the receipt manifest digest.
    pub frozen_manifest_digest: String,
    /// Explicitly selected defect family; exactly one spec must match it.
    pub defect_kind: RepairDefectKind,
    /// Exact current projection of the subject, trajectory, and threat.
    pub projection: CurrentMemoryProjection,
    /// Missing-provenance spec; present only for that family.
    pub provenance: Option<ProvenanceRepairSpec>,
    /// Contaminated-influence spec; present only for that family.
    pub contamination: Option<ContaminationRepairSpec>,
    /// False-relation spec; present only for that family.
    pub relation: Option<FalseRelationSpec>,
    /// Stale-view spec; present only for that family.
    pub stale_view: Option<StaleViewSpec>,
    /// Representation spec; present only for that family.
    pub representation: Option<RepresentationSpec>,
    /// Affected members (sorted by handle, unique).
    pub affected: Vec<AffectedMember>,
    /// One disposition per affected member (sorted by handle).
    pub dispositions: Vec<MemberDisposition>,
    /// Seven-dimension preservation report from the caller.
    pub preservation: PreservationReport,
    /// A-05 receipt checked intrinsically, never re-executed.
    pub receipt: ValidationReceipt,
    /// Denominator covering exactly the affected handles.
    pub closure_denominator: TargetDenominator,
    /// Closed policy governing the repair.
    pub policy: RepairPolicy,
}

/// Complete proposal envelope: outcome plus bindings, never an applied receipt.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MemoryRepairCandidate {
    /// Terminal outcome for this request.
    pub outcome: RepairOutcome,
    /// The single defect family this candidate repairs.
    pub defect_kind: RepairDefectKind,
    /// Subject handle under repair.
    pub subject_handle: String,
    /// Subject revision the candidate binds.
    pub subject_revision: String,
    /// Typed inert operations proposed to external owners.
    pub operations: Vec<TypedRepairOperation>,
    /// One disposition per affected member, in handle order.
    pub dispositions: Vec<MemberDisposition>,
    /// Intended hypothesis the repair tests.
    pub hypothesis: String,
    /// Expected observable proving the repair took effect.
    pub expected_observable: String,
    /// Verifier that checks the observable.
    pub verifier: String,
    /// Observation window the observable is checked in.
    pub window_note: String,
    /// Exact inverse restoring the before state.
    pub inverse_note: String,
    /// Forward correction applied when the before state is unreachable.
    pub forward_correction_note: String,
    /// Explicit expiry of the proposal in milliseconds, if any.
    pub expiry_ms: Option<u64>,
    /// Renewal condition naming what reopens review.
    pub renewal_condition: String,
    /// Reopen condition naming what revives review.
    pub reopen_note: String,
    /// How unknown outcomes are handled without silent completion.
    pub unknown_handling_note: String,
    /// Seven-dimension accounting note.
    pub dimensions_note: String,
    /// Deterministic digest binding the proposal inputs.
    pub candidate_digest: String,
    /// Bounded machine-readable note.
    pub note: String,
}

// ---------------------------------------------------------------------------
// Preflight bounds (shape only; semantic shortfalls stay outcomes).
// ---------------------------------------------------------------------------

fn count_text_bytes(values: &[&str]) -> usize {
    let mut total = 0usize;
    for value in values {
        total = total.saturating_add(value.len());
    }
    total
}

fn bound_list_length(phase: &str, got: usize, max: usize) -> Result<(), RepairError> {
    if got > max {
        return Err(RepairError::Bounds {
            phase: phase.to_owned(),
            detail: "list exceeds its independent ceiling".to_owned(),
        });
    }
    Ok(())
}

fn preflight_spec_bounds(request: &MemoryRepairRequest) -> Result<(), RepairError> {
    let evidence_ceiling = request.policy.max_evidence_items.min(MAX_EVIDENCE_ITEMS);
    if let Some(spec) = &request.provenance {
        bound_list_length(
            "provenance-lineage",
            spec.expected_lineage.len(),
            MAX_CLOSURE_REFS,
        )?;
        bound_list_length(
            "provenance-conflicts",
            spec.conflicting_lineage_refs
                .len()
                .saturating_add(spec.affected_derivative_refs.len()),
            evidence_ceiling,
        )?;
    }
    if let Some(spec) = &request.contamination {
        bound_list_length(
            "contamination-closure",
            spec.closure.dependent_refs.len(),
            MAX_CLOSURE_REFS,
        )?;
        bound_list_length(
            "contamination-gaps",
            spec.closure.unknown_gaps.len(),
            evidence_ceiling,
        )?;
        bound_list_length(
            "contamination-lineage",
            spec.taint_lineage_refs
                .len()
                .saturating_add(spec.revocation_refs.len()),
            evidence_ceiling,
        )?;
    }
    if let Some(spec) = &request.relation {
        bound_list_length(
            "relation-evidence",
            spec.original_source_refs
                .len()
                .saturating_add(spec.contradictory_evidence_refs.len()),
            evidence_ceiling,
        )?;
        bound_list_length(
            "relation-dependents",
            spec.dependent_refs.len(),
            MAX_CLOSURE_REFS,
        )?;
    }
    if let Some(spec) = &request.stale_view {
        bound_list_length(
            "stale-frontier",
            spec.source_frontier.len(),
            MAX_CLOSURE_REFS,
        )?;
        bound_list_length(
            "stale-consumers",
            spec.consumer_refs.len(),
            MAX_CLOSURE_REFS,
        )?;
    }
    if let Some(spec) = &request.representation {
        bound_list_length(
            "representation-coverage",
            spec.source_coverage_refs.len(),
            MAX_CLOSURE_REFS,
        )?;
        bound_list_length(
            "representation-consumers",
            spec.consumer_refs.len(),
            MAX_CLOSURE_REFS,
        )?;
    }
    Ok(())
}

fn preflight_text_and_order(request: &MemoryRepairRequest) -> Result<(), RepairError> {
    let mut total = 0usize;
    total = total.saturating_add(count_text_bytes(&[
        &request.projection.subject_handle,
        &request.projection.subject_revision,
        &request.projection.scope_id,
        &request.projection.task_id,
        &request.projection.policy_id,
        &request.policy.policy_id,
        &request.policy.target_subject,
        &request.policy.verifier,
    ]));
    for member in &request.affected {
        total = total.saturating_add(count_text_bytes(&[&member.handle, &member.owner]));
    }
    for disposition in &request.dispositions {
        total = total.saturating_add(count_text_bytes(&[
            &disposition.handle,
            &disposition.old_identity,
            &disposition.proposed_identity,
            &disposition.owner,
            &disposition.reason,
            &disposition.evidence_ref,
            &disposition.verifier,
            &disposition.inverse_note,
            &disposition.proof_note,
        ]));
    }
    if total > MAX_TOTAL_BYTES {
        return Err(RepairError::Bounds {
            phase: "total-bytes".to_owned(),
            detail: "aggregate input exceeds the total byte ceiling".to_owned(),
        });
    }
    let affected_handles: Vec<String> = request.affected.iter().map(|m| m.handle.clone()).collect();
    if !is_sorted_unique(&affected_handles) {
        return Err(RepairError::Order {
            phase: "affected".to_owned(),
            detail: "affected handles must be sorted and unique".to_owned(),
        });
    }
    let disposition_handles: Vec<String> = request
        .dispositions
        .iter()
        .map(|d| d.handle.clone())
        .collect();
    if !is_sorted_unique(&disposition_handles) {
        return Err(RepairError::Order {
            phase: "dispositions".to_owned(),
            detail: "disposition handles must be sorted and unique".to_owned(),
        });
    }
    Ok(())
}

fn preflight_bounds(request: &MemoryRepairRequest) -> Result<(), RepairError> {
    bound_list_length(
        "affected",
        request.affected.len(),
        request.policy.max_affected.min(MAX_AFFECTED),
    )?;
    bound_list_length(
        "dispositions",
        request.dispositions.len(),
        request.policy.max_affected.min(MAX_AFFECTED),
    )?;
    bound_list_length(
        "closure-denominator",
        request.closure_denominator.members.len(),
        MAX_CLOSURE_REFS,
    )?;
    bound_list_length(
        "protection",
        request.projection.protection_refs.len(),
        MAX_PROTECTIONS,
    )?;
    let evidence_ceiling = request.policy.max_evidence_items.min(MAX_EVIDENCE_ITEMS);
    bound_list_length(
        "trajectory",
        request
            .projection
            .trajectory
            .false_positive_refs
            .len()
            .saturating_add(request.projection.trajectory.rival_refs.len())
            .saturating_add(request.projection.trajectory.unknown_refs.len()),
        evidence_ceiling,
    )?;
    bound_list_length(
        "threat",
        request
            .projection
            .threat
            .threat_lineage_refs
            .len()
            .saturating_add(request.projection.threat.revocation_refs.len())
            .saturating_add(request.projection.threat.taint_refs.len()),
        evidence_ceiling,
    )?;
    preflight_spec_bounds(request)?;
    preflight_text_and_order(request)?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Shape validation (malformed input only).
// ---------------------------------------------------------------------------

fn validate_owner_refs(owners: &AxisOwnerRefs) -> Result<(), RepairError> {
    check_text(&owners.existence_owner, "owners.existence")?;
    check_text(&owners.support_owner, "owners.support")?;
    check_text(&owners.accessibility_owner, "owners.accessibility")?;
    check_text(&owners.influence_owner, "owners.influence")?;
    check_text(&owners.privacy_owner, "owners.privacy")?;
    check_text(&owners.erasure_owner, "owners.erasure")?;
    check_text(&owners.assurance_owner, "owners.assurance")?;
    Ok(())
}

fn validate_sorted_refs(values: &[String], field: &str) -> Result<(), RepairError> {
    for value in values {
        check_handle(value, field)?;
    }
    if !is_sorted_unique(values) {
        return Err(RepairError::Order {
            phase: field.to_owned(),
            detail: "refs must be sorted and unique".to_owned(),
        });
    }
    Ok(())
}

fn validate_shapes(request: &MemoryRepairRequest) -> Result<(), RepairError> {
    check_handle(&request.projection.subject_handle, "projection.subject")?;
    check_text(&request.projection.subject_revision, "projection.revision")?;
    check_digest(&request.projection.subject_digest, "projection.digest")?;
    check_handle(&request.projection.scope_id, "projection.scope")?;
    check_handle(&request.projection.task_id, "projection.task")?;
    check_handle(&request.projection.policy_id, "projection.policy")?;
    check_digest(&request.frozen_bundle_digest, "frozen-bundle")?;
    check_digest(&request.frozen_manifest_digest, "frozen-manifest")?;
    validate_owner_refs(&request.projection.owners)?;
    if request.projection.axis_revisions.len() != 7 {
        return Err(RepairError::Bounds {
            phase: "projection.axes".to_owned(),
            detail: "exactly seven independent axis revisions are required".to_owned(),
        });
    }
    for revision in &request.projection.axis_revisions {
        check_text(revision, "projection.axis-revision")?;
    }
    let trajectory = &request.projection.trajectory;
    check_text(&trajectory.failure_trigger, "trajectory.trigger")?;
    check_text(&trajectory.reopen_condition, "trajectory.reopen")?;
    validate_sorted_refs(
        &trajectory.false_positive_refs,
        "trajectory.false-positives",
    )?;
    validate_sorted_refs(&trajectory.rival_refs, "trajectory.rivals")?;
    validate_sorted_refs(&trajectory.unknown_refs, "trajectory.unknowns")?;
    let threat = &request.projection.threat;
    validate_sorted_refs(&threat.threat_lineage_refs, "threat.lineage")?;
    validate_sorted_refs(&threat.revocation_refs, "threat.revocation")?;
    validate_sorted_refs(&threat.taint_refs, "threat.taint")?;
    check_text(&threat.review_owner, "threat.review-owner")?;
    validate_sorted_refs(
        &request.projection.protection_refs,
        "projection.protections",
    )?;
    validate_sorted_refs(
        &request.projection.negative_memory_refs,
        "projection.negative-memory",
    )?;
    validate_sorted_refs(
        &request.projection.counterevidence_refs,
        "projection.counterevidence",
    )?;
    for member in &request.affected {
        check_handle(&member.handle, "affected.handle")?;
        check_text(&member.owner, "affected.owner")?;
    }
    for disposition in &request.dispositions {
        check_handle(&disposition.handle, "disposition.handle")?;
        check_text(&disposition.old_identity, "disposition.old")?;
        check_text(&disposition.proposed_identity, "disposition.proposed")?;
        check_text(&disposition.owner, "disposition.owner")?;
        check_text(&disposition.reason, "disposition.reason")?;
        check_handle(&disposition.evidence_ref, "disposition.evidence")?;
        check_handle(&disposition.scope_id, "disposition.scope")?;
        check_text(&disposition.fence_note, "disposition.fence")?;
        check_text(&disposition.verifier, "disposition.verifier")?;
        check_text(&disposition.inverse_note, "disposition.inverse")?;
        check_text(&disposition.proof_note, "disposition.proof")?;
    }
    check_handle(&request.policy.policy_id, "policy.id")?;
    check_handle(&request.policy.target_subject, "policy.target")?;
    check_text(&request.policy.verifier, "policy.verifier")?;
    check_text(&request.policy.observation_window_note, "policy.window")?;
    check_text(&request.policy.inverse_note, "policy.inverse")?;
    check_text(&request.policy.renewal_condition, "policy.renewal")?;
    check_text(&request.policy.support_ceiling, "policy.support-ceiling")?;
    check_text(&request.policy.privacy_ceiling, "policy.privacy-ceiling")?;
    check_text(
        &request.policy.influence_ceiling,
        "policy.influence-ceiling",
    )?;
    request
        .closure_denominator
        .validate()
        .map_err(|err| RepairError::Bounds {
            phase: "closure-denominator".to_owned(),
            detail: redact(&err.to_string()),
        })?;
    request.preservation.validate().map_err(|err| {
        // Shape only here: a failed or unknown dimension is a semantic
        // shortfall judged at emission, not a malformed request.
        let detail = err.to_string();
        if detail.contains("expected 7")
            || detail.contains("duplicate")
            || detail.contains("missing")
            || detail.contains("blank")
            || detail.contains("exceeds")
        {
            RepairError::Bounds {
                phase: "preservation".to_owned(),
                detail: redact(&detail),
            }
        } else {
            // Defer dimension verdicts to the outcome stage by accepting
            // the shape; the overall check below re-derives the verdict.
            RepairError::Bounds {
                phase: "preservation-deferred".to_owned(),
                detail: redact(&detail),
            }
        }
    })?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Intrinsic checks, boundary routing, and exactly-one-kind selection.
// ---------------------------------------------------------------------------

fn unchanged_candidate(
    request: &MemoryRepairRequest,
    outcome: RepairOutcome,
    note: &str,
) -> Result<MemoryRepairCandidate, RepairError> {
    let dispositions = request.dispositions.clone();
    let digest_inputs = CandidateDigestInputs {
        request,
        operations: &[],
        subject_handle: &request.projection.subject_handle,
        subject_revision: &request.projection.subject_revision,
        hypothesis: note,
        verifier: &request.policy.verifier,
        inverse_note: &request.policy.inverse_note,
        expiry_ms: request.policy.expiry_ms,
    };
    let digest = candidate_digest(&digest_inputs)?;
    Ok(MemoryRepairCandidate {
        outcome,
        defect_kind: request.defect_kind,
        subject_handle: request.projection.subject_handle.clone(),
        subject_revision: request.projection.subject_revision.clone(),
        operations: Vec::new(),
        dispositions,
        hypothesis: "no repair is proposed under the observed shortfall".to_owned(),
        expected_observable: "subject and members remain exactly as projected".to_owned(),
        verifier: request.policy.verifier.clone(),
        window_note: request.policy.observation_window_note.clone(),
        inverse_note: request.policy.inverse_note.clone(),
        forward_correction_note: "no forward correction applies without a proposal".to_owned(),
        expiry_ms: request.policy.expiry_ms,
        renewal_condition: request.policy.renewal_condition.clone(),
        reopen_note: request.projection.trajectory.reopen_condition.clone(),
        unknown_handling_note: "unknowns stay open and block completeness".to_owned(),
        dimensions_note: "seven dimensions judged independently with no averaging".to_owned(),
        candidate_digest: digest,
        note: note.chars().take(MAX_TEXT_BYTES).collect(),
    })
}

fn repair_spelling_family(spelling: &str) -> Option<RepairDefectKind> {
    if PROVENANCE_REPAIRS.contains(&spelling) {
        Some(RepairDefectKind::MissingProvenance)
    } else if CONTAMINATION_REPAIRS.contains(&spelling) {
        Some(RepairDefectKind::ContaminatedInfluence)
    } else if RELATION_REPAIRS.contains(&spelling) {
        Some(RepairDefectKind::FalseRelation)
    } else if STALE_VIEW_REPAIRS.contains(&spelling) {
        Some(RepairDefectKind::StaleDerivedView)
    } else if REPRESENTATION_REPAIRS.contains(&spelling) {
        Some(RepairDefectKind::RepresentationGap)
    } else {
        None
    }
}

fn intrinsic_receipt_binding(
    request: &MemoryRepairRequest,
) -> Result<Option<MemoryRepairCandidate>, RepairError> {
    request
        .receipt
        .validate()
        .map_err(|err| RepairError::Receipt {
            detail: redact(&err.to_string()),
        })?;
    request
        .item
        .validate()
        .map_err(|err| RepairError::Receipt {
            detail: redact(&err.to_string()),
        })?;
    request
        .grounded
        .validate()
        .map_err(|err| RepairError::Receipt {
            detail: redact(&err.to_string()),
        })?;
    if request.receipt.terminal_disposition != "accepted"
        && request.receipt.terminal_disposition != "partial"
    {
        return Ok(Some(unchanged_candidate(
            request,
            RepairOutcome::Rejected,
            "a-05 receipt is not accepted or partial",
        )?));
    }
    if request.receipt.validator_policy != request.policy.policy_id {
        return Ok(Some(unchanged_candidate(
            request,
            RepairOutcome::Abstention,
            "receipt policy does not bind the governing policy",
        )?));
    }
    if request.item.payload.kind() != CurationKind::Repair {
        return Ok(Some(unchanged_candidate(
            request,
            RepairOutcome::Rejected,
            "curation item is not the repair kind",
        )?));
    }
    Ok(None)
}

fn intrinsic_subject_binding(
    request: &MemoryRepairRequest,
    payload_target: &str,
) -> Result<Option<MemoryRepairCandidate>, RepairError> {
    if payload_target != request.projection.subject_handle {
        return Ok(Some(unchanged_candidate(
            request,
            RepairOutcome::Rejected,
            "curation subject does not bind the projected subject",
        )?));
    }
    if payload_target != request.policy.target_subject {
        return Ok(Some(unchanged_candidate(
            request,
            RepairOutcome::Rejected,
            "curation subject does not bind the policy target",
        )?));
    }
    if request.frozen_bundle_digest != request.receipt.bundle_digest
        || request.frozen_manifest_digest != request.receipt.manifest_digest
    {
        return Ok(Some(unchanged_candidate(
            request,
            RepairOutcome::Stale,
            "frozen bundle no longer matches the receipt bundle",
        )?));
    }
    if request.item.task_id != request.projection.task_id
        || request.item.scope_id != request.projection.scope_id
    {
        return Ok(Some(unchanged_candidate(
            request,
            RepairOutcome::Stale,
            "curation task or scope moved from the projection",
        )?));
    }
    if request.projection.policy_id != request.policy.policy_id {
        return Ok(Some(unchanged_candidate(
            request,
            RepairOutcome::Stale,
            "projection policy moved from the governing policy",
        )?));
    }
    if request.policy.cancelled {
        return Ok(Some(unchanged_candidate(
            request,
            RepairOutcome::Rejected,
            "caller cancelled this repair request",
        )?));
    }
    if let (Some(observed), Some(deadline)) = (
        request.policy.observation_time_ms,
        request.policy.deadline_ms,
    ) && observed >= deadline
    {
        return Ok(Some(unchanged_candidate(
            request,
            RepairOutcome::Stale,
            "observation is at or beyond the frozen deadline",
        )?));
    }
    if request.projection.subject_kind == SubjectKind::RawEpisode {
        return Ok(Some(unchanged_candidate(
            request,
            RepairOutcome::Rejected,
            "raw episode history is preserved verbatim and never repaired here",
        )?));
    }
    Ok(None)
}

fn intrinsic_routing(
    request: &MemoryRepairRequest,
    payload_repair: &str,
) -> Result<Option<MemoryRepairCandidate>, RepairError> {
    // Closed-spelling boundary routing before any kind work.
    if IDENTITY_SURGERY_REPAIRS.contains(&payload_repair) {
        return Ok(Some(unchanged_candidate(
            request,
            RepairOutcome::Rejected,
            "merge or split identity repair routes to a-27 (#665)",
        )?));
    }
    if RECONSOLIDATION_REPAIRS.contains(&payload_repair) {
        return Ok(Some(unchanged_candidate(
            request,
            RepairOutcome::Rejected,
            "derived-content reconsolidation routes to a-28 (#667)",
        )?));
    }
    if AXIS_TUNING_REPAIRS.contains(&payload_repair) {
        return Ok(Some(unchanged_candidate(
            request,
            RepairOutcome::Rejected,
            "pure axis tuning routes to a-29 (#669)",
        )?));
    }
    let Some(spelling_family) = repair_spelling_family(payload_repair) else {
        return Ok(Some(unchanged_candidate(
            request,
            RepairOutcome::Rejected,
            "repair spelling is not one of the five closed families",
        )?));
    };
    if spelling_family != request.defect_kind {
        return Ok(Some(unchanged_candidate(
            request,
            RepairOutcome::Rejected,
            "repair spelling family does not match the selected defect kind",
        )?));
    }
    // Exactly one spec must be present and it must match the selection.
    let present = u8::from(request.provenance.is_some())
        + u8::from(request.contamination.is_some())
        + u8::from(request.relation.is_some())
        + u8::from(request.stale_view.is_some())
        + u8::from(request.representation.is_some());
    if present == 0 {
        return Ok(Some(unchanged_candidate(
            request,
            RepairOutcome::Rejected,
            "no defect specification matches the selected kind",
        )?));
    }
    if present > 1 {
        return Ok(Some(unchanged_candidate(
            request,
            RepairOutcome::Rejected,
            "compound defects need decomposition, not a compound patch",
        )?));
    }
    let matches_selection = match request.defect_kind {
        RepairDefectKind::MissingProvenance => request.provenance.is_some(),
        RepairDefectKind::ContaminatedInfluence => request.contamination.is_some(),
        RepairDefectKind::FalseRelation => request.relation.is_some(),
        RepairDefectKind::StaleDerivedView => request.stale_view.is_some(),
        RepairDefectKind::RepresentationGap => request.representation.is_some(),
    };
    if !matches_selection {
        return Ok(Some(unchanged_candidate(
            request,
            RepairOutcome::Rejected,
            "defect specification does not match the selected kind",
        )?));
    }
    Ok(None)
}

fn intrinsic_checks(
    request: &MemoryRepairRequest,
) -> Result<Option<MemoryRepairCandidate>, RepairError> {
    if let Some(early) = intrinsic_receipt_binding(request)? {
        return Ok(Some(early));
    }
    let (payload_target, payload_repair) =
        if let eliot_dreamer_contracts::curation::CurationPayload::Repair(payload) =
            &request.item.payload
        {
            (payload.target.clone(), payload.repair.clone())
        } else {
            return Ok(Some(unchanged_candidate(
                request,
                RepairOutcome::Rejected,
                "curation payload does not carry a repair target",
            )?));
        };
    if let Some(early) = intrinsic_subject_binding(request, &payload_target)? {
        return Ok(Some(early));
    }
    // Closed-spelling boundary routing before any kind work.
    if let Some(early) = intrinsic_routing(request, &payload_repair)? {
        return Ok(Some(early));
    }
    Ok(None)
}

// ---------------------------------------------------------------------------
// Per-kind contracts.
// ---------------------------------------------------------------------------

enum KindVerdict {
    Complete {
        operations: Vec<TypedRepairOperation>,
        hypothesis: String,
        observable: String,
        note: String,
    },
    Partial {
        operations: Vec<TypedRepairOperation>,
        hypothesis: String,
        observable: String,
        note: String,
    },
    Outcome {
        outcome: RepairOutcome,
        note: String,
    },
}

fn operation(
    operation: RepairOperationKind,
    owner: &str,
    verifier: &str,
    inverse_note: &str,
    expiry_ms: Option<u64>,
    scope_id: &str,
) -> TypedRepairOperation {
    TypedRepairOperation {
        operation,
        owner: owner.to_owned(),
        verifier: verifier.to_owned(),
        inverse_note: inverse_note.to_owned(),
        expiry_ms,
        scope_id: scope_id.to_owned(),
    }
}

fn evaluate_provenance(
    request: &MemoryRepairRequest,
    spec: &ProvenanceRepairSpec,
) -> Result<KindVerdict, RepairError> {
    check_handle(&spec.missing_edge, "provenance.missing-edge")?;
    check_text(&spec.verifier, "provenance.verifier")?;
    validate_sorted_refs(&spec.expected_lineage, "provenance.lineage")?;
    validate_sorted_refs(&spec.conflicting_lineage_refs, "provenance.conflicts")?;
    validate_sorted_refs(&spec.affected_derivative_refs, "provenance.derivatives")?;
    if spec.expected_lineage.is_empty() {
        return Ok(KindVerdict::Outcome {
            outcome: RepairOutcome::Blocked,
            note: "expected lineage denominator is empty".to_owned(),
        });
    }
    if spec.expected_lineage.len() != spec.expected_total as usize {
        return Ok(KindVerdict::Outcome {
            outcome: RepairOutcome::Partial,
            note: "expected lineage denominator is partial; completeness is blocked".to_owned(),
        });
    }
    if spec.similarity_only {
        return Ok(KindVerdict::Outcome {
            outcome: RepairOutcome::Rejected,
            note: "author, time, and operation are never inferred from similarity".to_owned(),
        });
    }
    if mentions_similarity_as_proof(&spec.verifier) {
        return Ok(KindVerdict::Outcome {
            outcome: RepairOutcome::Rejected,
            note: "similarity or confidence is not an authoritative source".to_owned(),
        });
    }
    if spec.owner_conflict {
        return Ok(KindVerdict::Outcome {
            outcome: RepairOutcome::Review,
            note: "conflicting source owners require owner review".to_owned(),
        });
    }
    let Some(link) = &spec.authoritative_source else {
        return Ok(KindVerdict::Outcome {
            outcome: RepairOutcome::Abstention,
            note: "unestablished source routes to quarantine and revalidation, not invention"
                .to_owned(),
        });
    };
    check_handle(&link.source_handle, "provenance.source")?;
    check_text(&link.source_revision, "provenance.source-revision")?;
    check_digest(&link.source_digest, "provenance.source-digest")?;
    check_handle(&link.scope_id, "provenance.source-scope")?;
    check_text(&link.privacy_note, "provenance.privacy")?;
    check_text(&link.fence_note, "provenance.fence")?;
    check_text(&link.match_note, "provenance.match")?;
    if mentions_similarity_as_proof(&link.match_note) {
        return Ok(KindVerdict::Outcome {
            outcome: RepairOutcome::Rejected,
            note: "content equality alone never establishes the missing edge".to_owned(),
        });
    }
    if link.scope_id != request.projection.scope_id {
        return Ok(KindVerdict::Outcome {
            outcome: RepairOutcome::Blocked,
            note: "source scope does not admit the subject scope".to_owned(),
        });
    }
    let scope = request.projection.scope_id.clone();
    Ok(KindVerdict::Complete {
        operations: vec![operation(
            RepairOperationKind::ProvenanceLink,
            &request.projection.owners.assurance_owner,
            &spec.verifier,
            &request.policy.inverse_note,
            request.policy.expiry_ms,
            &scope,
        )],
        hypothesis: "the missing edge is exactly the authoritative link".to_owned(),
        observable: "the missing edge resolves to the named source revision".to_owned(),
        note: "provenance link from one authoritative matching source; raw history unchanged"
            .to_owned(),
    })
}

fn evaluate_contamination(
    request: &MemoryRepairRequest,
    spec: &ContaminationRepairSpec,
) -> Result<KindVerdict, RepairError> {
    check_handle(&spec.subject_handle, "contamination.subject")?;
    check_handle(&spec.source_handle, "contamination.source")?;
    check_text(&spec.derived_influence_note, "contamination.influence")?;
    check_text(&spec.current_graph_note, "contamination.graph")?;
    check_text(
        &spec.other_axes_preserved_note,
        "contamination.axes-preserved",
    )?;
    check_text(&spec.inverse_note, "contamination.inverse")?;
    validate_sorted_refs(&spec.taint_lineage_refs, "contamination.taint")?;
    validate_sorted_refs(&spec.revocation_refs, "contamination.revocation")?;
    let closure = &spec.closure;
    check_handle(&closure.closure_id, "closure.id")?;
    validate_sorted_refs(&closure.dependent_refs, "closure.dependents")?;
    validate_sorted_refs(&closure.unknown_gaps, "closure.gaps")?;
    check_text(&closure.review_owner, "closure.review-owner")?;
    check_text(&closure.renewal_owner, "closure.renewal-owner")?;
    check_text(&closure.verifier, "closure.verifier")?;
    check_text(&closure.closure_revision, "closure.revision")?;
    if spec.subject_handle != request.projection.subject_handle {
        return Ok(KindVerdict::Outcome {
            outcome: RepairOutcome::Rejected,
            note: "contamination subject does not bind the projected subject".to_owned(),
        });
    }
    if closure.policy_id != request.policy.policy_id
        || closure.scope_id != request.projection.scope_id
    {
        return Ok(KindVerdict::Outcome {
            outcome: RepairOutcome::Stale,
            note: "closure policy or scope moved from the governing request".to_owned(),
        });
    }
    if spec.agreement_offered_as_cleansing {
        return Ok(KindVerdict::Outcome {
            outcome: RepairOutcome::Rejected,
            note: "retrieval or model agreement never cleanses taint".to_owned(),
        });
    }
    if !closure.complete || closure.stale || !closure.unknown_gaps.is_empty() {
        return Ok(KindVerdict::Outcome {
            outcome: RepairOutcome::Blocked,
            note: "partial, stale, or unknown closure blocks a complete candidate".to_owned(),
        });
    }
    if closure.dependent_refs.len() != closure.expected_dependents_total as usize {
        return Ok(KindVerdict::Outcome {
            outcome: RepairOutcome::Partial,
            note: "closure dependent denominator is partial; completeness is blocked".to_owned(),
        });
    }
    let inert = match spec.action {
        ContaminationAction::QuarantineDependents => RepairOperationKind::QuarantineForRevalidation,
        ContaminationAction::RevokeDependent | ContaminationAction::RestrictScope => {
            RepairOperationKind::OwnerDirectedReview
        }
        ContaminationAction::RevalidateWithNewEvidence => {
            RepairOperationKind::QuarantineForRevalidation
        }
    };
    let scope = request.projection.scope_id.clone();
    Ok(KindVerdict::Complete {
        operations: vec![operation(
            inert,
            &closure.review_owner,
            &closure.verifier,
            &spec.inverse_note,
            request.policy.expiry_ms,
            &scope,
        )],
        hypothesis: "holding the closed dependents removes the tainted influence".to_owned(),
        observable: "every closed dependent is held or renewed by its owner".to_owned(),
        note: "complete closure over every affected branch; record kept, no silent axis change"
            .to_owned(),
    })
}

fn false_relation_partial_denominator(
    request: &MemoryRepairRequest,
    spec: &FalseRelationSpec,
) -> KindVerdict {
    let scope = request.projection.scope_id.clone();
    let partial_op = match &spec.proposal {
        FalseRelationProposal::Invalidate => Some(RepairOperationKind::RelationInvalidate),
        FalseRelationProposal::QuarantineReverify => {
            Some(RepairOperationKind::QuarantineForRevalidation)
        }
        FalseRelationProposal::Reclassify { .. } | FalseRelationProposal::Replace { .. } => None,
    };
    if let Some(kind) = partial_op {
        // Invalidate and quarantine stay safe under partial dependent
        // coverage; reclassify and replace need the full denominator.
        return KindVerdict::Partial {
            operations: vec![operation(
                kind,
                &spec.registry_owner,
                &spec.verifier,
                &spec.inverse_note,
                request.policy.expiry_ms,
                &scope,
            )],
            hypothesis: "holding the exact relation revision limits the false binding".to_owned(),
            observable: "the exact relation revision no longer guides covered dependents"
                .to_owned(),
            note: "dependent denominator is partial; completeness is blocked".to_owned(),
        };
    }
    KindVerdict::Outcome {
        outcome: RepairOutcome::Partial,
        note: "dependent denominator is partial; completeness is blocked".to_owned(),
    }
}

fn evaluate_false_relation(
    request: &MemoryRepairRequest,
    spec: &FalseRelationSpec,
) -> Result<KindVerdict, RepairError> {
    check_handle(&spec.relation_id, "relation.id")?;
    check_text(&spec.relation_type, "relation.type")?;
    check_text(&spec.relation_revision, "relation.revision")?;
    check_text(&spec.registry_owner, "relation.registry-owner")?;
    check_handle(&spec.endpoint_a, "relation.endpoint-a")?;
    check_text(&spec.endpoint_a_revision, "relation.endpoint-a-revision")?;
    check_handle(&spec.endpoint_b, "relation.endpoint-b")?;
    check_text(&spec.endpoint_b_revision, "relation.endpoint-b-revision")?;
    check_handle(&spec.scope_id, "relation.scope")?;
    check_text(&spec.fence_note, "relation.fence")?;
    check_text(&spec.mapping_note, "relation.mapping")?;
    check_text(&spec.verifier, "relation.verifier")?;
    check_text(&spec.inverse_note, "relation.inverse")?;
    validate_sorted_refs(&spec.original_source_refs, "relation.sources")?;
    validate_sorted_refs(
        &spec.contradictory_evidence_refs,
        "relation.counterevidence",
    )?;
    validate_sorted_refs(&spec.dependent_refs, "relation.dependents")?;
    if spec.endpoint_a.is_empty() || spec.endpoint_b.is_empty() {
        return Ok(KindVerdict::Outcome {
            outcome: RepairOutcome::Blocked,
            note: "unknown endpoints yield partial or blocked, never completion".to_owned(),
        });
    }
    if spec.chronology_offered_as_causality || claims_chronology_is_causality(&spec.mapping_note) {
        return Ok(KindVerdict::Outcome {
            outcome: RepairOutcome::Rejected,
            note: "chronology, correlation, and proximity are not causality".to_owned(),
        });
    }
    if spec.original_source_refs.is_empty() || spec.contradictory_evidence_refs.is_empty() {
        return Ok(KindVerdict::Outcome {
            outcome: RepairOutcome::Partial,
            note: "source or counterevidence denominator is partial".to_owned(),
        });
    }
    if spec.dependent_refs.len() != spec.expected_dependents_total as usize {
        return Ok(false_relation_partial_denominator(request, spec));
    }
    let kind = match &spec.proposal {
        FalseRelationProposal::Invalidate => RepairOperationKind::RelationInvalidate,
        FalseRelationProposal::Reclassify { new_type } => {
            check_text(new_type, "relation.new-type")?;
            RepairOperationKind::RelationReclassify
        }
        FalseRelationProposal::Replace { replacement_ref } => {
            check_handle(replacement_ref, "relation.replacement")?;
            if !contains_handle(&spec.original_source_refs, replacement_ref)
                && !contains_handle(&spec.contradictory_evidence_refs, replacement_ref)
            {
                return Ok(KindVerdict::Outcome {
                    outcome: RepairOutcome::Blocked,
                    note: "replacement lacks independent grounding in the bound evidence"
                        .to_owned(),
                });
            }
            RepairOperationKind::RelationReplace
        }
        FalseRelationProposal::QuarantineReverify => RepairOperationKind::QuarantineForRevalidation,
    };
    let scope = request.projection.scope_id.clone();
    Ok(KindVerdict::Complete {
        operations: vec![operation(
            kind,
            &spec.registry_owner,
            &spec.verifier,
            &spec.inverse_note,
            request.policy.expiry_ms,
            &scope,
        )],
        hypothesis: "the typed correction removes the false binding".to_owned(),
        observable: "the exact relation revision no longer guides dependents".to_owned(),
        note: "old and new mapping preserved with verifier and inverse; no registry write"
            .to_owned(),
    })
}

fn evaluate_stale_view(
    request: &MemoryRepairRequest,
    spec: &StaleViewSpec,
) -> Result<KindVerdict, RepairError> {
    check_handle(&spec.view_handle, "stale.view")?;
    check_text(&spec.view_schema, "stale.schema")?;
    check_text(&spec.view_revision, "stale.revision")?;
    check_digest(&spec.view_digest, "stale.digest")?;
    check_text(&spec.source_recipe, "stale.recipe")?;
    validate_sorted_refs(&spec.source_frontier, "stale.frontier")?;
    check_handle(&spec.invalidation_ref, "stale.invalidation")?;
    check_text(&spec.rebuild_owner, "stale.rebuild-owner")?;
    check_text(&spec.rebuild_contract_ref, "stale.rebuild-contract")?;
    check_text(&spec.verifier, "stale.verifier")?;
    check_text(&spec.inverse_note, "stale.inverse")?;
    validate_sorted_refs(&spec.consumer_refs, "stale.consumers")?;
    if spec.view_handle != request.projection.subject_handle {
        return Ok(KindVerdict::Outcome {
            outcome: RepairOutcome::Rejected,
            note: "stale view does not bind the projected subject".to_owned(),
        });
    }
    if !spec.old_bytes_preserved {
        return Ok(KindVerdict::Outcome {
            outcome: RepairOutcome::Rejected,
            note: "old bytes and history must stay addressable".to_owned(),
        });
    }
    if spec.timestamp_offered_as_currentness
        || claims_timestamp_is_currentness(&spec.invalidation_ref)
    {
        return Ok(KindVerdict::Outcome {
            outcome: RepairOutcome::Rejected,
            note: "a bare timestamp never proves currentness".to_owned(),
        });
    }
    if spec.source_frontier.len() != spec.expected_frontier_total as usize {
        // Invalidation stays safe under a partial frontier; rebuild and
        // consumer revalidation need the complete denominator.
        let scope = request.projection.scope_id.clone();
        return Ok(KindVerdict::Partial {
            operations: vec![operation(
                RepairOperationKind::ViewInvalidate,
                &spec.rebuild_owner,
                &spec.verifier,
                &spec.inverse_note,
                request.policy.expiry_ms,
                &scope,
            )],
            hypothesis: "holding consumers on the preserved old revision limits staleness spread"
                .to_owned(),
            observable: "consumers stay invalidated against the preserved old bytes".to_owned(),
            note: "source frontier is partial; a complete rebuild is blocked".to_owned(),
        });
    }
    if spec.consumer_refs.is_empty() {
        return Ok(KindVerdict::Outcome {
            outcome: RepairOutcome::Partial,
            note: "consumer plan is empty; rebuild direction is unknown".to_owned(),
        });
    }
    let scope = request.projection.scope_id.clone();
    Ok(KindVerdict::Complete {
        operations: vec![
            operation(
                RepairOperationKind::ViewInvalidate,
                &spec.rebuild_owner,
                &spec.verifier,
                &spec.inverse_note,
                request.policy.expiry_ms,
                &scope,
            ),
            operation(
                RepairOperationKind::ViewRebuild,
                &spec.rebuild_owner,
                &spec.verifier,
                &spec.inverse_note,
                request.policy.expiry_ms,
                &scope,
            ),
            operation(
                RepairOperationKind::ViewRevalidateConsumers,
                &spec.rebuild_owner,
                &spec.verifier,
                &spec.inverse_note,
                request.policy.expiry_ms,
                &scope,
            ),
        ],
        hypothesis: "rebuilding from the complete frontier refreshes consumers".to_owned(),
        observable: "consumers bind the rebuilt revision or stay invalidated".to_owned(),
        note: "old view preserved and addressable; source records unchanged; no current projection is published"
            .to_owned(),
    })
}

fn evaluate_representation(
    request: &MemoryRepairRequest,
    spec: &RepresentationSpec,
) -> Result<KindVerdict, RepairError> {
    check_handle(&spec.canonical_identity, "representation.identity")?;
    check_text(&spec.canonical_revision, "representation.revision")?;
    check_handle(&spec.canonical_source_ref, "representation.source")?;
    check_digest(&spec.canonical_digest, "representation.digest")?;
    check_text(&spec.missing_representation_note, "representation.missing")?;
    check_text(&spec.consumer_need_note, "representation.need")?;
    check_text(&spec.representation_schema, "representation.schema")?;
    check_text(&spec.representation_recipe, "representation.recipe")?;
    check_text(&spec.omission_note, "representation.omissions")?;
    check_text(&spec.addressability_note, "representation.addressability")?;
    check_text(&spec.verifier, "representation.verifier")?;
    check_text(&spec.inverse_note, "representation.inverse")?;
    validate_sorted_refs(&spec.source_coverage_refs, "representation.coverage")?;
    validate_sorted_refs(&spec.consumer_refs, "representation.consumers")?;
    if spec.canonical_identity != request.projection.subject_handle {
        return Ok(KindVerdict::Outcome {
            outcome: RepairOutcome::Rejected,
            note: "representation must bind one existing canonical identity".to_owned(),
        });
    }
    if spec.second_truth {
        return Ok(KindVerdict::Outcome {
            outcome: RepairOutcome::Rejected,
            note: "a second truth or support owner is never proposed".to_owned(),
        });
    }
    if spec.widens_ceilings {
        return Ok(KindVerdict::Outcome {
            outcome: RepairOutcome::Rejected,
            note: "representation availability never widens ceilings implicitly".to_owned(),
        });
    }
    if !spec.reversible {
        return Ok(KindVerdict::Outcome {
            outcome: RepairOutcome::Blocked,
            note: "an irreversible representation blocks a complete candidate".to_owned(),
        });
    }
    if spec.source_coverage_refs.is_empty() {
        return Ok(KindVerdict::Outcome {
            outcome: RepairOutcome::Abstention,
            note: "absent source routes to provenance or unsupported, not invention".to_owned(),
        });
    }
    if spec.consumer_refs.is_empty() {
        return Ok(KindVerdict::Outcome {
            outcome: RepairOutcome::Partial,
            note: "consumer denominator is partial; completeness is blocked".to_owned(),
        });
    }
    let kind = match spec.proposal {
        RepresentationProposal::Add => RepairOperationKind::RepresentationAdd,
        RepresentationProposal::Repair => RepairOperationKind::RepresentationRepair,
        RepresentationProposal::Remove => RepairOperationKind::RepresentationRemove,
    };
    let scope = request.projection.scope_id.clone();
    Ok(KindVerdict::Complete {
        operations: vec![operation(
            kind,
            &request.projection.owners.support_owner,
            &spec.verifier,
            &spec.inverse_note,
            request.policy.expiry_ms,
            &scope,
        )],
        hypothesis:
            "the new representation serves the consumer need losslessly or with declared omissions"
                .to_owned(),
        observable: "consumers resolve the canonical identity through the admitted schema"
            .to_owned(),
        note: "canonical content unchanged; source, omission, and reversal retained".to_owned(),
    })
}

// ---------------------------------------------------------------------------
// Member accounting, preservation, digest, and emission.
// ---------------------------------------------------------------------------

fn check_member_accounting(request: &MemoryRepairRequest) -> Option<KindVerdict> {
    let affected_handles: Vec<String> = request.affected.iter().map(|m| m.handle.clone()).collect();
    let disposition_handles: Vec<String> = request
        .dispositions
        .iter()
        .map(|d| d.handle.clone())
        .collect();
    if !sorted_set_eq(&affected_handles, &disposition_handles) {
        return Some(KindVerdict::Outcome {
            outcome: RepairOutcome::Partial,
            note: "every affected member needs exactly one disposition and vice versa".to_owned(),
        });
    }
    let mut denominator = request.closure_denominator.members.clone();
    denominator.sort();
    if !sorted_set_eq(&affected_handles, &denominator) {
        return Some(KindVerdict::Outcome {
            outcome: RepairOutcome::Partial,
            note: "affected denominator does not cover exactly the affected members".to_owned(),
        });
    }
    for member in &request.affected {
        if member.unknown {
            let held = request.dispositions.iter().any(|d| {
                d.handle == member.handle
                    && d.disposition == MemberDispositionKind::BlockedUnavailableUnknown
            });
            if !held {
                return Some(KindVerdict::Outcome {
                    outcome: RepairOutcome::Blocked,
                    note: "unknown members must be held as blocked, never unaffected".to_owned(),
                });
            }
        }
    }
    for disposition in &request.dispositions {
        let Some(member) = request
            .affected
            .iter()
            .find(|m| m.handle == disposition.handle)
        else {
            return Some(KindVerdict::Outcome {
                outcome: RepairOutcome::Partial,
                note: "a disposition names a member outside the affected set".to_owned(),
            });
        };
        if disposition.owner != member.owner {
            return Some(KindVerdict::Outcome {
                outcome: RepairOutcome::Rejected,
                note: "a disposition owner does not bind the member owner".to_owned(),
            });
        }
        if disposition.scope_id != request.projection.scope_id {
            return Some(KindVerdict::Outcome {
                outcome: RepairOutcome::Stale,
                note: "a disposition scope moved from the projection scope".to_owned(),
            });
        }
    }
    let any_blocked = request
        .dispositions
        .iter()
        .any(|d| d.disposition == MemberDispositionKind::BlockedUnavailableUnknown);
    if any_blocked {
        return Some(KindVerdict::Outcome {
            outcome: RepairOutcome::Blocked,
            note: "a blocked member holds the candidate below complete".to_owned(),
        });
    }
    None
}

#[derive(Serialize)]
struct DigestView<'a> {
    subject_handle: &'a str,
    subject_revision: &'a str,
    subject_digest: &'a str,
    scope_id: &'a str,
    task_id: &'a str,
    policy_id: &'a str,
    defect_kind: &'a str,
    repair_spelling: &'a str,
    operation_kinds: Vec<&'a str>,
    disposition_handles: Vec<&'a str>,
    hypothesis: &'a str,
    observable: &'a str,
    verifier: &'a str,
    inverse_note: &'a str,
    expiry_ms: Option<u64>,
}

fn defect_kind_spelling(kind: RepairDefectKind) -> &'static str {
    match kind {
        RepairDefectKind::MissingProvenance => "missing_provenance",
        RepairDefectKind::ContaminatedInfluence => "contaminated_influence",
        RepairDefectKind::FalseRelation => "false_relation",
        RepairDefectKind::StaleDerivedView => "stale_derived_view",
        RepairDefectKind::RepresentationGap => "representation_gap",
    }
}

fn operation_spelling(operation: RepairOperationKind) -> &'static str {
    match operation {
        RepairOperationKind::ProvenanceLink => "provenance_link",
        RepairOperationKind::QuarantineForRevalidation => "quarantine_for_revalidation",
        RepairOperationKind::RelationInvalidate => "relation_invalidate",
        RepairOperationKind::RelationReclassify => "relation_reclassify",
        RepairOperationKind::RelationReplace => "relation_replace",
        RepairOperationKind::ViewInvalidate => "view_invalidate",
        RepairOperationKind::ViewRebuild => "view_rebuild",
        RepairOperationKind::ViewRevalidateConsumers => "view_revalidate_consumers",
        RepairOperationKind::RepresentationAdd => "representation_add",
        RepairOperationKind::RepresentationRepair => "representation_repair",
        RepairOperationKind::RepresentationRemove => "representation_remove",
        RepairOperationKind::OwnerDirectedReview => "owner_directed_review",
    }
}

struct CandidateDigestInputs<'a> {
    request: &'a MemoryRepairRequest,
    operations: &'a [TypedRepairOperation],
    subject_handle: &'a str,
    subject_revision: &'a str,
    hypothesis: &'a str,
    verifier: &'a str,
    inverse_note: &'a str,
    expiry_ms: Option<u64>,
}

fn candidate_digest(inputs: &CandidateDigestInputs<'_>) -> Result<String, RepairError> {
    let request = inputs.request;
    let repair_spelling =
        if let eliot_dreamer_contracts::curation::CurationPayload::Repair(payload) =
            &request.item.payload
        {
            payload.repair.as_str()
        } else {
            ""
        };
    let mut operation_kinds: Vec<&str> = inputs
        .operations
        .iter()
        .map(|o| operation_spelling(o.operation))
        .collect();
    operation_kinds.sort_unstable();
    let mut disposition_handles: Vec<&str> = request
        .dispositions
        .iter()
        .map(|d| d.handle.as_str())
        .collect();
    disposition_handles.sort_unstable();
    let view = DigestView {
        subject_handle: inputs.subject_handle,
        subject_revision: inputs.subject_revision,
        subject_digest: request.projection.subject_digest.as_str(),
        scope_id: request.projection.scope_id.as_str(),
        task_id: request.projection.task_id.as_str(),
        policy_id: request.policy.policy_id.as_str(),
        defect_kind: defect_kind_spelling(request.defect_kind),
        repair_spelling,
        operation_kinds,
        disposition_handles,
        hypothesis: inputs.hypothesis,
        observable: inputs.verifier,
        verifier: inputs.verifier,
        inverse_note: inputs.inverse_note,
        expiry_ms: inputs.expiry_ms,
    };
    canonical_json_bytes(&view)
        .map(|bytes| sha256_hex(&bytes))
        .map_err(|_| RepairError::Bounds {
            phase: "digest".to_owned(),
            detail: "proposal inputs cannot be canonically serialized".to_owned(),
        })
}

fn select_kind_verdict(request: &MemoryRepairRequest) -> Result<KindVerdict, RepairError> {
    match request.defect_kind {
        RepairDefectKind::MissingProvenance => {
            let Some(spec) = &request.provenance else {
                return Ok(KindVerdict::Outcome {
                    outcome: RepairOutcome::Rejected,
                    note: "provenance spec is absent".to_owned(),
                });
            };
            evaluate_provenance(request, spec)
        }
        RepairDefectKind::ContaminatedInfluence => {
            let Some(spec) = &request.contamination else {
                return Ok(KindVerdict::Outcome {
                    outcome: RepairOutcome::Rejected,
                    note: "contamination spec is absent".to_owned(),
                });
            };
            evaluate_contamination(request, spec)
        }
        RepairDefectKind::FalseRelation => {
            let Some(spec) = &request.relation else {
                return Ok(KindVerdict::Outcome {
                    outcome: RepairOutcome::Rejected,
                    note: "relation spec is absent".to_owned(),
                });
            };
            evaluate_false_relation(request, spec)
        }
        RepairDefectKind::StaleDerivedView => {
            let Some(spec) = &request.stale_view else {
                return Ok(KindVerdict::Outcome {
                    outcome: RepairOutcome::Rejected,
                    note: "stale view spec is absent".to_owned(),
                });
            };
            evaluate_stale_view(request, spec)
        }
        RepairDefectKind::RepresentationGap => {
            let Some(spec) = &request.representation else {
                return Ok(KindVerdict::Outcome {
                    outcome: RepairOutcome::Rejected,
                    note: "representation spec is absent".to_owned(),
                });
            };
            evaluate_representation(request, spec)
        }
    }
}

fn emit_repair_candidate(
    request: &MemoryRepairRequest,
    kind_verdict: KindVerdict,
) -> Result<MemoryRepairCandidate, RepairError> {
    let (mut outcome, operations, hypothesis, observable, mut note) = match kind_verdict {
        KindVerdict::Complete {
            operations,
            hypothesis,
            observable,
            note,
        } => (
            RepairOutcome::Complete,
            operations,
            hypothesis,
            observable,
            note,
        ),
        KindVerdict::Partial {
            operations,
            hypothesis,
            observable,
            note,
        } => (
            RepairOutcome::Partial,
            operations,
            hypothesis,
            observable,
            note,
        ),
        KindVerdict::Outcome { outcome, note } => {
            return unchanged_candidate(request, outcome, &note);
        }
    };
    if let Some(KindVerdict::Outcome { outcome, note }) = check_member_accounting(request) {
        return unchanged_candidate(request, outcome, &note);
    }
    // A failed or unknown preservation dimension blocks completeness without
    // invoking any further validation: the candidate drops to partial.
    if outcome == RepairOutcome::Complete && request.preservation.overall().is_err() {
        outcome = RepairOutcome::Partial;
        "a preservation dimension failed or is unknown; completeness is blocked"
            .clone_into(&mut note);
    }
    let digest_inputs = CandidateDigestInputs {
        request,
        operations: &operations,
        subject_handle: &request.projection.subject_handle,
        subject_revision: &request.projection.subject_revision,
        hypothesis: &hypothesis,
        verifier: &request.policy.verifier,
        inverse_note: &request.policy.inverse_note,
        expiry_ms: request.policy.expiry_ms,
    };
    let digest = candidate_digest(&digest_inputs)?;
    Ok(MemoryRepairCandidate {
        outcome,
        defect_kind: request.defect_kind,
        subject_handle: request.projection.subject_handle.clone(),
        subject_revision: request.projection.subject_revision.clone(),
        operations,
        dispositions: request.dispositions.clone(),
        hypothesis,
        expected_observable: observable,
        verifier: request.policy.verifier.clone(),
        window_note: request.policy.observation_window_note.clone(),
        inverse_note: request.policy.inverse_note.clone(),
        forward_correction_note:
            "when the before state is unreachable the owner re-derives from the bound frontier"
                .to_owned(),
        expiry_ms: request.policy.expiry_ms,
        renewal_condition: request.policy.renewal_condition.clone(),
        reopen_note: request.projection.trajectory.reopen_condition.clone(),
        unknown_handling_note: "unknown outcomes stay open and block completeness".to_owned(),
        dimensions_note: "seven dimensions judged independently with no averaging".to_owned(),
        candidate_digest: digest,
        note,
    })
}

/// Proposes one bounded typed repair candidate for one closed defect.
///
/// The request binds the six canonical families: validated curation item,
/// frozen bundle digests, grounded draft, current memory and trajectory
/// projection, affected dependency projection (affected members, one
/// disposition each, and the closure denominator), and policy. The A-05
/// receipt is checked intrinsically and never re-executed. Returned
/// candidates are inert: every operation names the external owner that must
/// execute or decline it.
pub fn propose_memory_repair(
    request: &MemoryRepairRequest,
) -> Result<MemoryRepairCandidate, RepairError> {
    preflight_bounds(request)?;
    if let Err(failure) = validate_shapes(request) {
        // Preservation dimension shortfalls are semantic, not malformed:
        // only the deferred marker reroutes here, and the emission stage
        // re-derives the exact verdict through `overall`.
        let deferred = matches!(&failure, RepairError::Bounds { phase, .. } if phase == "preservation-deferred");
        if !deferred {
            return Err(failure);
        }
    }
    if let Some(early) = intrinsic_checks(request)? {
        return Ok(early);
    }
    let kind_verdict = select_kind_verdict(request)?;
    emit_repair_candidate(request, kind_verdict)
}

/// Maps a terminal outcome to the closest A-05 rejection hint, if any.
#[must_use]
pub fn outcome_rejection_hint(outcome: &RepairOutcome) -> Option<RejectionCode> {
    match outcome {
        RepairOutcome::Complete => None,
        RepairOutcome::Partial | RepairOutcome::Blocked | RepairOutcome::Review => {
            Some(RejectionCode::PreservationFailed)
        }
        RepairOutcome::Abstention | RepairOutcome::NoSafeRepair => {
            Some(RejectionCode::LineageMismatch)
        }
        RepairOutcome::Stale | RepairOutcome::Rejected => Some(RejectionCode::IdentityMismatch),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use eliot_contracts::{AuthorityEpoch, ResourceGeneration};
    use eliot_dreamer_contracts::candidate::{DimensionVerdict, PreservationDimension};
    use eliot_dreamer_contracts::curation::{RepairPayload, TargetEvidence};
    use eliot_dreamer_contracts::{
        AtomicityMode, ClaimResidue, Requester, RequesterOrigin, SupportState, kind_family,
    };

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

    fn test_grounded() -> GroundedDreamDraft {
        GroundedDreamDraft {
            schema_version: 1,
            job_id: "job-1".to_owned(),
            draft_digest: "a".repeat(64),
            residues: vec![ClaimResidue {
                claim: "the lineage edge is missing".to_owned(),
                state: SupportState::Supported,
                detail: "obs-1 shows the gap".to_owned(),
            }],
            coverage_note: "one claim accounted".to_owned(),
        }
    }

    fn test_item(spelling: &str) -> ValidatedCurationItem {
        let payload = eliot_dreamer_contracts::CurationPayload::Repair(RepairPayload {
            target: "mem-1".to_owned(),
            repair: spelling.to_owned(),
            target_evidence: TargetEvidence {
                targets: vec!["mem-1".to_owned()],
                evidence_refs: vec!["e-1".to_owned()],
            },
        });
        ValidatedCurationItem {
            receipt: test_receipt(),
            kind_spelling: "repair".to_owned(),
            family_spelling: kind_family(CurationKind::Repair).to_owned(),
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
            erasure_owner: "owner-erasure".to_owned(),
            assurance_owner: "owner-assurance".to_owned(),
        }
    }

    fn test_projection() -> CurrentMemoryProjection {
        CurrentMemoryProjection {
            subject_handle: "mem-1".to_owned(),
            subject_kind: SubjectKind::SemanticMemory,
            subject_revision: "rev-2".to_owned(),
            subject_digest: "9".repeat(64),
            scope_id: "scope-1".to_owned(),
            task_id: "task-1".to_owned(),
            policy_id: "policy-7".to_owned(),
            state_fence: test_fence(),
            owners: test_owners(),
            axis_revisions: vec![
                "existence@rev-2".to_owned(),
                "support@rev-2".to_owned(),
                "accessibility@rev-2".to_owned(),
                "influence@rev-2".to_owned(),
                "privacy@rev-2".to_owned(),
                "erasure@rev-2".to_owned(),
                "assurance@rev-2".to_owned(),
            ],
            trajectory: TrajectoryEvidence {
                failure_trigger: "obs-1 shows the missing edge".to_owned(),
                occurrences: 3,
                recurrences: 1,
                false_positive_refs: vec!["fp-1".to_owned()],
                rival_refs: vec!["rival-1".to_owned()],
                unknown_refs: vec!["unknown-1".to_owned()],
                reopen_condition: "reopen when obs-2 fires".to_owned(),
                extinction_evidence_ref: None,
                runbook_ref: Some("runbook-3".to_owned()),
            },
            threat: ThreatEvidence {
                threat_lineage_refs: vec!["threat-1".to_owned()],
                revocation_refs: vec!["revoke-1".to_owned()],
                taint_refs: vec!["taint-1".to_owned()],
                review_owner: "owner-review".to_owned(),
            },
            protection_refs: vec!["prot-1".to_owned()],
            negative_memory_refs: vec!["m-1".to_owned()],
            counterevidence_refs: vec!["m-1".to_owned()],
        }
    }

    fn test_policy() -> RepairPolicy {
        RepairPolicy {
            policy_id: "policy-7".to_owned(),
            target_subject: "mem-1".to_owned(),
            verifier: "verifier-7".to_owned(),
            observation_window_note: "window w-10".to_owned(),
            inverse_note: "restore rev-2 bindings".to_owned(),
            expiry_ms: Some(1_800_000_000_000),
            renewal_condition: "reopen when scope-1 frontier advances".to_owned(),
            support_ceiling: "no wider support".to_owned(),
            privacy_ceiling: "no wider audience".to_owned(),
            influence_ceiling: "no new decisions".to_owned(),
            max_affected: 64,
            max_evidence_items: 64,
            cancelled: false,
            observation_time_ms: Some(1_700_000_000_000),
            deadline_ms: Some(1_800_000_000_000),
        }
    }

    fn test_affected() -> Vec<AffectedMember> {
        vec![AffectedMember {
            handle: "dep-1".to_owned(),
            owner: "owner-assurance".to_owned(),
            required: true,
            unknown: false,
        }]
    }

    fn test_disposition(kind: MemberDispositionKind) -> Vec<MemberDisposition> {
        vec![MemberDisposition {
            handle: "dep-1".to_owned(),
            disposition: kind,
            old_identity: "dep-1@rev-2".to_owned(),
            proposed_identity: "dep-1@rev-3".to_owned(),
            owner: "owner-assurance".to_owned(),
            reason: "revalidate the derivative against the repaired edge".to_owned(),
            evidence_ref: "e-1".to_owned(),
            scope_id: "scope-1".to_owned(),
            fence_note: "fence f-1".to_owned(),
            verifier: "verifier-7".to_owned(),
            inverse_note: "restore dep-1@rev-2".to_owned(),
            proof_note: "executed check c-1".to_owned(),
        }]
    }

    fn test_denominator() -> TargetDenominator {
        TargetDenominator {
            mode: AtomicityMode::PerMember,
            members: vec!["dep-1".to_owned()],
            expected_total: 1,
        }
    }

    fn provenance_spec() -> ProvenanceRepairSpec {
        ProvenanceRepairSpec {
            missing_edge: "edge mem-1.author".to_owned(),
            expected_lineage: vec!["src-1".to_owned()],
            expected_total: 1,
            authoritative_source: Some(AuthoritativeSourceLink {
                source_handle: "src-1".to_owned(),
                authority: SourceAuthorityKind::AuthoritativeReceipt,
                source_revision: "rev-4".to_owned(),
                source_digest: "7".repeat(64),
                scope_id: "scope-1".to_owned(),
                privacy_note: "reviewers only".to_owned(),
                fence_note: "fence f-1".to_owned(),
                match_note: "receipt r-9 records exactly edge mem-1.author at rev-4".to_owned(),
            }),
            conflicting_lineage_refs: vec!["src-2".to_owned()],
            affected_derivative_refs: vec!["dep-1".to_owned()],
            similarity_only: false,
            owner_conflict: false,
            verifier: "verifier-7".to_owned(),
        }
    }

    fn contamination_spec() -> ContaminationRepairSpec {
        ContaminationRepairSpec {
            subject_handle: "mem-1".to_owned(),
            source_handle: "src-taint".to_owned(),
            derived_influence_note: "ranking cue c-2 derives from src-taint".to_owned(),
            current_graph_note: "graph g-1 at rev-2".to_owned(),
            taint_lineage_refs: vec!["taint-1".to_owned()],
            revocation_refs: vec!["revoke-1".to_owned()],
            action: ContaminationAction::QuarantineDependents,
            closure: ContaminationClosure {
                closure_id: "closure-1".to_owned(),
                dependent_refs: vec!["dep-1".to_owned()],
                expected_dependents_total: 1,
                complete: true,
                stale: false,
                unknown_gaps: Vec::new(),
                review_owner: "owner-review".to_owned(),
                renewal_owner: "owner-renew".to_owned(),
                verifier: "verifier-7".to_owned(),
                policy_id: "policy-7".to_owned(),
                scope_id: "scope-1".to_owned(),
                closure_revision: "rev-2".to_owned(),
                state_fence: test_fence(),
            },
            other_axes_preserved_note: "support, privacy, and assurance untouched".to_owned(),
            inverse_note: "release dep-1 back to rev-2 influence".to_owned(),
            agreement_offered_as_cleansing: false,
        }
    }

    fn relation_spec() -> FalseRelationSpec {
        FalseRelationSpec {
            relation_id: "rel-1".to_owned(),
            relation_type: "supports".to_owned(),
            relation_revision: "rev-2".to_owned(),
            registry_owner: "owner-registry".to_owned(),
            endpoint_a: "mem-1".to_owned(),
            endpoint_a_revision: "rev-2".to_owned(),
            endpoint_b: "mem-2".to_owned(),
            endpoint_b_revision: "rev-5".to_owned(),
            scope_id: "scope-1".to_owned(),
            fence_note: "fence f-1".to_owned(),
            original_source_refs: vec!["e-1".to_owned()],
            contradictory_evidence_refs: vec!["e-9".to_owned()],
            dependent_refs: vec!["dep-1".to_owned()],
            expected_dependents_total: 1,
            chronology_offered_as_causality: false,
            proposal: FalseRelationProposal::Invalidate,
            mapping_note: "rel-1 rev-2 maps to no relation after e-9".to_owned(),
            verifier: "verifier-7".to_owned(),
            inverse_note: "restore rel-1 rev-2".to_owned(),
        }
    }

    fn stale_view_spec() -> StaleViewSpec {
        StaleViewSpec {
            view_handle: "mem-1".to_owned(),
            view_schema: "schema-v3".to_owned(),
            view_revision: "rev-2".to_owned(),
            view_digest: "8".repeat(64),
            source_recipe: "recipe-4".to_owned(),
            source_frontier: vec!["src-1".to_owned()],
            expected_frontier_total: 1,
            invalidation_ref: "inv-1".to_owned(),
            rebuild_owner: "owner-view".to_owned(),
            rebuild_contract_ref: "contract-view-2".to_owned(),
            old_bytes_preserved: true,
            timestamp_offered_as_currentness: false,
            consumer_refs: vec!["dep-1".to_owned()],
            verifier: "verifier-7".to_owned(),
            inverse_note: "serve rev-2 bytes again".to_owned(),
        }
    }

    fn representation_spec() -> RepresentationSpec {
        RepresentationSpec {
            canonical_identity: "mem-1".to_owned(),
            canonical_revision: "rev-2".to_owned(),
            canonical_source_ref: "src-1".to_owned(),
            canonical_digest: "6".repeat(64),
            missing_representation_note: "no caption exists for reviewers".to_owned(),
            consumer_need_note: "reviewers need a short caption".to_owned(),
            representation_schema: "caption-v1".to_owned(),
            representation_recipe: "recipe-caption-2".to_owned(),
            source_coverage_refs: vec!["src-1".to_owned()],
            omission_note: "caption omits examples e-x and e-y".to_owned(),
            reversible: true,
            addressability_note: "caption points at src-1 bytes 0..64".to_owned(),
            proposal: RepresentationProposal::Add,
            second_truth: false,
            widens_ceilings: false,
            consumer_refs: vec!["dep-1".to_owned()],
            verifier: "verifier-7".to_owned(),
            inverse_note: "drop the caption".to_owned(),
        }
    }

    fn base_request(spelling: &str, kind: RepairDefectKind) -> MemoryRepairRequest {
        let receipt = test_receipt();
        MemoryRepairRequest {
            item: test_item(spelling),
            grounded: test_grounded(),
            frozen_bundle_digest: receipt.bundle_digest.clone(),
            frozen_manifest_digest: receipt.manifest_digest.clone(),
            defect_kind: kind,
            projection: test_projection(),
            provenance: None,
            contamination: None,
            relation: None,
            stale_view: None,
            representation: None,
            affected: test_affected(),
            dispositions: test_disposition(MemberDispositionKind::QuarantineRevalidate),
            preservation: test_preservation(),
            receipt,
            closure_denominator: test_denominator(),
            policy: test_policy(),
        }
    }

    // WORK_UNIT_CASE: 671/1
    #[test]
    fn case_01_valid_missing_provenance_links_authoritative_source() {
        let mut request = base_request("provenance-link", RepairDefectKind::MissingProvenance);
        request.provenance = Some(provenance_spec());
        request.dispositions = test_disposition(MemberDispositionKind::ProvenanceLink);
        let candidate = match propose_memory_repair(&request) {
            Ok(candidate) => candidate,
            Err(err) => panic!("valid provenance request: {err:?}"),
        };
        assert_eq!(candidate.outcome, RepairOutcome::Complete);
        assert_eq!(candidate.defect_kind, RepairDefectKind::MissingProvenance);
        assert_eq!(candidate.subject_handle, "mem-1");
        assert_eq!(candidate.operations.len(), 1);
        assert_eq!(
            candidate.operations[0].operation,
            RepairOperationKind::ProvenanceLink
        );
        assert_eq!(candidate.operations[0].owner, "owner-assurance");
        assert!(is_hex64_lower(&candidate.candidate_digest));
        assert_eq!(outcome_rejection_hint(&candidate.outcome), None);
    }

    // WORK_UNIT_CASE: 671/16
    #[test]
    fn case_16_complete_contamination_closure_holds_dependents() {
        let mut request = base_request(
            "contamination-quarantine",
            RepairDefectKind::ContaminatedInfluence,
        );
        request.contamination = Some(contamination_spec());
        let candidate = match propose_memory_repair(&request) {
            Ok(candidate) => candidate,
            Err(err) => panic!("valid contamination request: {err:?}"),
        };
        assert_eq!(candidate.outcome, RepairOutcome::Complete);
        assert_eq!(
            candidate.defect_kind,
            RepairDefectKind::ContaminatedInfluence
        );
        assert_eq!(candidate.operations.len(), 1);
        assert_eq!(
            candidate.operations[0].operation,
            RepairOperationKind::QuarantineForRevalidation
        );
        assert_eq!(candidate.operations[0].owner, "owner-review");
        assert!(is_hex64_lower(&candidate.candidate_digest));
        assert_eq!(candidate.dispositions.len(), 1);
    }

    // WORK_UNIT_CASE: 671/24
    #[test]
    fn case_24_invalidate_exact_false_relation_revision() {
        let mut request = base_request("relation-invalidate", RepairDefectKind::FalseRelation);
        request.relation = Some(relation_spec());
        request.dispositions = test_disposition(MemberDispositionKind::RelationChange);
        let candidate = match propose_memory_repair(&request) {
            Ok(candidate) => candidate,
            Err(err) => panic!("valid relation request: {err:?}"),
        };
        assert_eq!(candidate.outcome, RepairOutcome::Complete);
        assert_eq!(candidate.defect_kind, RepairDefectKind::FalseRelation);
        assert_eq!(candidate.operations.len(), 1);
        assert_eq!(
            candidate.operations[0].operation,
            RepairOperationKind::RelationInvalidate
        );
        assert_eq!(candidate.operations[0].owner, "owner-registry");
        assert!(is_hex64_lower(&candidate.candidate_digest));
    }

    // WORK_UNIT_CASE: 671/33
    #[test]
    fn case_33_stale_view_preserves_old_bytes_and_rebuilds() {
        let mut request = base_request("view-rebuild", RepairDefectKind::StaleDerivedView);
        request.stale_view = Some(stale_view_spec());
        request.dispositions = test_disposition(MemberDispositionKind::Rebuild);
        let candidate = match propose_memory_repair(&request) {
            Ok(candidate) => candidate,
            Err(err) => panic!("valid stale view request: {err:?}"),
        };
        assert_eq!(candidate.outcome, RepairOutcome::Complete);
        assert_eq!(candidate.defect_kind, RepairDefectKind::StaleDerivedView);
        assert_eq!(candidate.operations.len(), 3);
        assert_eq!(
            candidate.operations[1].operation,
            RepairOperationKind::ViewRebuild
        );
        assert_eq!(candidate.operations[1].owner, "owner-view");
        assert!(is_hex64_lower(&candidate.candidate_digest));
    }

    // WORK_UNIT_CASE: 671/40
    #[test]
    fn case_40_representation_binds_one_canonical_identity() {
        let mut request = base_request("representation-add", RepairDefectKind::RepresentationGap);
        request.representation = Some(representation_spec());
        request.dispositions = test_disposition(MemberDispositionKind::RepresentationChange);
        let candidate = match propose_memory_repair(&request) {
            Ok(candidate) => candidate,
            Err(err) => panic!("valid representation request: {err:?}"),
        };
        assert_eq!(candidate.outcome, RepairOutcome::Complete);
        assert_eq!(candidate.defect_kind, RepairDefectKind::RepresentationGap);
        assert_eq!(candidate.operations.len(), 1);
        assert_eq!(
            candidate.operations[0].operation,
            RepairOperationKind::RepresentationAdd
        );
        assert!(is_hex64_lower(&candidate.candidate_digest));
    }

    // WORK_UNIT_CASE: 671/57
    #[test]
    fn case_57_exact_replay_is_deterministic_and_revision_change_conflicts() {
        let mut request = base_request("provenance-link", RepairDefectKind::MissingProvenance);
        request.provenance = Some(provenance_spec());
        request.dispositions = test_disposition(MemberDispositionKind::ProvenanceLink);
        let first = match propose_memory_repair(&request) {
            Ok(candidate) => candidate,
            Err(err) => panic!("first replay: {err:?}"),
        };
        let second = match propose_memory_repair(&request) {
            Ok(candidate) => candidate,
            Err(err) => panic!("second replay: {err:?}"),
        };
        assert_eq!(first.outcome, RepairOutcome::Complete);
        assert_eq!(first.candidate_digest, second.candidate_digest);
        let mut moved = request.clone();
        moved.projection.subject_revision = "rev-3".to_owned();
        let rebound = match propose_memory_repair(&moved) {
            Ok(candidate) => candidate,
            Err(err) => panic!("moved revision: {err:?}"),
        };
        assert_eq!(rebound.outcome, RepairOutcome::Complete);
        assert_ne!(first.candidate_digest, rebound.candidate_digest);
    }
}
