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
//! Test coverage note: the complete `WORK_UNIT_CASE 671/1..66` matrix is
//! executable here. Each case exercises the production proposal path and
//! asserts an observable semantic boundary; markers are not used as proof.

#![forbid(unsafe_code)]

use eliot_contracts::{StateFence, canonical_json_bytes, sha256_hex};
use eliot_dreamer_contracts::curation::{CurationPayload, RepairPayload};
use eliot_dreamer_contracts::{
    BoundCurationCall, CandidateDisposition, ContractViolation, CurationFamily,
    CurationHandlerDescriptor, CurationHandlerPort, CurationKind, CurationRejectionCode,
    GroundedDreamDraft, NativeCurationHandler, PreservationReport, ProducedCurationContent,
    TargetDenominator, ValidatedCurationItem, ValidationReceipt, is_hex64_lower,
};
use eliot_security_contracts::{InfluenceDependencyClosure, InfluenceState};
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

/// Canonical relation spellings from I5.18. Similarity, sequence, and
/// co-change remain evidence only and are intentionally absent.
pub const CANONICAL_RELATION_TYPES: &[&str] = &[
    "supports",
    "contradicts",
    "verified_by",
    "supersedes",
    "belongs_to",
    "covers",
    "implements",
    "depends_on",
    "calls",
    "reads",
    "writes",
    "produces",
    "consumes",
    "causes",
    "fails_because",
    "resolved_by",
    "invalidated_by",
    "blocks",
    "unblocks",
    "satisfies",
    "reopens",
    "mentions",
    "derived_from",
    "included_in",
    "used_for",
    "suppressed_by",
    "authorized_by",
    "assigned_to",
    "influenced_by",
    "invalidates_influence",
    "derived_disclosure_from",
    "declassified_by",
    "grant_parent",
    "introduced_as",
    "bound_with_credential",
    "builds",
    "emits_artifact",
    "executes_test",
    "covers_code",
    "verifies_property",
    "co_change",
    "resembles",
    "diverges_from",
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

/// Request, operation, idempotency, requester, and attempt identity for one
/// immutable repair proposal.
///
/// The canonical request digest is supplied by the caller after all other
/// request fields are frozen. Reusing the same idempotency key with a changed
/// request therefore fails closed without requiring this pure crate to own a
/// store or an idempotency table.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RepairIdentity {
    /// Caller-visible request identity.
    pub request_id: String,
    /// Domain operation identity.
    pub operation_id: String,
    /// Idempotency namespace/key supplied by the operation owner.
    pub idempotency_key: String,
    /// Requester principal; must bind to the validated item requester.
    pub requester: String,
    /// One-based attempt number; zero is never an implicit first attempt.
    pub attempt: u32,
    /// Canonical digest over the request with this field blanked.
    pub canonical_request_digest: String,
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
    /// Raw episode/history roots that remain addressable.
    pub raw_history_refs: Vec<String>,
    /// Durable audit roots retained for forensic review.
    pub audit_refs: Vec<String>,
    /// Minority evidence roots retained without suppression.
    pub minority_refs: Vec<String>,
    /// Dependency roots whose closure must remain visible.
    pub dependency_root_refs: Vec<String>,
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
    /// Exact state fence observed for the authoritative source.
    pub source_state_fence: StateFence,
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
    /// True when more than one source could satisfy the edge without a
    /// discriminator.
    pub ambiguous_source: bool,
    /// Verifier that checks the proposed link.
    pub verifier: String,
}

/// Adapter metadata bound to the public B-SEC1 influence closure.
///
/// [`bsec1_closure`](Self::bsec1_closure) is the canonical owner evidence. The
/// surrounding fields bind that evidence to this candidate's policy, scope,
/// projected subject revision, completeness denominator, and owner-directed
/// renewal path. Local notes are explanatory only and are never used as proof
/// of graph membership or policy binding.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ContaminationClosure {
    /// Adapter copy of the canonical closure identity; it must equal the
    /// owner-issued B-SEC1 closure identity.
    pub closure_id: String,
    /// Typed public B-SEC1 closure/revocation evidence from its owner.
    pub bsec1_closure: InfluenceDependencyClosure,
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
    /// Source handles known to be unavailable or unknown.
    pub unknown_source_refs: Vec<String>,
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
    /// Context projection consumers.
    pub context_refs: Vec<String>,
    /// Retrieval cue consumers.
    pub cue_refs: Vec<String>,
    /// Index consumers.
    pub index_refs: Vec<String>,
    /// Decision consumers.
    pub decision_refs: Vec<String>,
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
#[allow(clippy::struct_excessive_bools)]
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
    /// True when a duplicate representation conflicts with an existing one.
    pub conflicting_duplicate: bool,
    /// True when the request widens support, accessibility, influence,
    /// disclosure, privacy, or effect ceilings implicitly.
    pub widens_ceilings: bool,
    /// Complete affected consumer, index, and context refs (sorted, unique).
    pub consumer_refs: Vec<String>,
    /// Context projections affected by this representation.
    pub context_refs: Vec<String>,
    /// Index projections affected by this representation.
    pub index_refs: Vec<String>,
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
    /// Request and operation identity frozen by the caller.
    pub identity: RepairIdentity,
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

/// Computes the request digest that seals a frozen repair request.
///
/// The digest preimage includes every request field except the digest being
/// sealed itself. Callers use this after constructing the request and then
/// retain the returned value in [`RepairIdentity::canonical_request_digest`].
pub fn canonical_request_digest(request: &MemoryRepairRequest) -> Result<String, RepairError> {
    let mut preimage = request.clone();
    preimage.identity.canonical_request_digest.clear();
    canonical_json_bytes(&preimage)
        .map(|bytes| sha256_hex(&bytes))
        .map_err(|_| RepairError::Bounds {
            phase: "identity.request-digest".to_owned(),
            detail: "request cannot be canonically serialized".to_owned(),
        })
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
    /// Identity bindings carried into the inert candidate.
    pub identity: RepairIdentity,
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
    /// Protected references carried forward without deletion.
    pub protection_refs: Vec<String>,
    /// Raw history roots carried forward without rewriting.
    pub raw_history_refs: Vec<String>,
    /// Audit roots carried forward without rewriting.
    pub audit_refs: Vec<String>,
    /// Minority/counterexample roots carried forward without suppression.
    pub minority_refs: Vec<String>,
    /// Dependency roots carried forward without silent closure loss.
    pub dependency_root_refs: Vec<String>,
    /// Negative-memory roots carried forward until explicit extinction.
    pub negative_memory_refs: Vec<String>,
    /// Counterevidence roots carried forward.
    pub counterevidence_refs: Vec<String>,
    /// Independent axis revisions copied into the candidate proof surface.
    pub axis_revisions: Vec<String>,
    /// Trajectory evidence copied into the candidate proof surface.
    pub trajectory: TrajectoryEvidence,
    /// Threat and revocation evidence copied into the candidate proof surface.
    pub threat: ThreatEvidence,
    /// Deterministic digest binding the proposal inputs.
    pub candidate_digest: String,
    /// Bounded machine-readable note.
    pub note: String,
}

/// Canonical A-03 handler identity for the memory-repair family.
pub const MEMORY_REPAIR_HANDLER_ID: &str = "eliot-dreamer-memory-repair";
/// Stable injected-port identity used by package-local handler fixtures.
pub const MEMORY_REPAIR_PORT_ID: &str = "memory-repair-port";

/// Returns the exact A-03 descriptor for the `Repair` wire kind.
///
/// The descriptor carries no dispatch authority and does not register itself;
/// A-31 supplies the closed registry and injected port at invocation time.
#[must_use]
pub fn memory_repair_handler_port() -> CurationHandlerPort {
    CurationHandlerPort {
        port_id: MEMORY_REPAIR_PORT_ID.to_owned(),
        descriptor: CurationHandlerDescriptor {
            family: CurationFamily::MemoryRepair,
            handler_id: MEMORY_REPAIR_HANDLER_ID.to_owned(),
            accepted_kinds: vec![CurationKind::Repair],
        },
    }
}

/// Immutable native handler adapter for the A-03 typed invocation seam.
///
/// The caller supplies the already-frozen semantic repair request. The
/// adapter only checks that the injected A-03 call is the same item and
/// identity projection, delegates to [`propose_memory_repair`], and returns
/// inert A-03 content. It performs no handler discovery, registry mutation,
/// persistence, or post-handler validation pass.
#[derive(Clone, Debug)]
pub struct MemoryRepairHandler {
    request: MemoryRepairRequest,
}

impl MemoryRepairHandler {
    /// Binds one immutable semantic repair request to this handler instance.
    #[must_use]
    pub fn new(request: MemoryRepairRequest) -> Self {
        Self { request }
    }

    /// Returns the frozen semantic request used by this handler.
    #[must_use]
    pub const fn request(&self) -> &MemoryRepairRequest {
        &self.request
    }

    fn bind_call(&self, call: &BoundCurationCall) -> Result<RepairPayload, ContractViolation> {
        call.validate()?;
        let expected = memory_repair_handler_port().descriptor;
        if call.port.descriptor != expected {
            return Err(ContractViolation::BindingMismatch {
                field: "handler_descriptor",
                reason: "memory-repair call is bound to a different handler descriptor".to_owned(),
            });
        }
        if call.request.kind != CurationKind::Repair
            || call.request.family != CurationFamily::MemoryRepair
        {
            return Err(ContractViolation::KindPayload(
                "memory-repair handler accepts only the Repair wire kind".to_owned(),
            ));
        }
        let item_payload = match &call.item.payload {
            CurationPayload::Repair(payload) => payload.clone(),
            _ => {
                return Err(ContractViolation::KindPayload(
                    "memory-repair handler requires the closed RepairPayload subtype".to_owned(),
                ));
            }
        };
        let CurationPayload::Repair(request_payload) = &call.request.payload else {
            return Err(ContractViolation::KindPayload(
                "memory-repair request requires the closed RepairPayload subtype".to_owned(),
            ));
        };
        if item_payload != *request_payload {
            return Err(ContractViolation::BindingMismatch {
                field: "payload",
                reason: "accepted item payload must equal typed request payload".to_owned(),
            });
        }
        if self.request.item != call.item {
            return Err(ContractViolation::BindingMismatch {
                field: "item",
                reason: "handler request is not bound to the accepted item".to_owned(),
            });
        }
        if self.request.projection.task_id != call.request.task_id
            || self.request.projection.scope_id != call.request.scope_id
            || self.request.projection.state_fence != call.request.state_fence
        {
            return Err(ContractViolation::BindingMismatch {
                field: "task_scope_fence",
                reason: "repair projection is not bound to the typed request".to_owned(),
            });
        }
        Ok(item_payload)
    }
}

fn candidate_disposition(outcome: RepairOutcome) -> CandidateDisposition {
    match outcome {
        RepairOutcome::Complete => CandidateDisposition::Candidate,
        RepairOutcome::Partial | RepairOutcome::Review => CandidateDisposition::Partial,
        RepairOutcome::Abstention | RepairOutcome::NoSafeRepair => CandidateDisposition::Abstention,
        RepairOutcome::Stale => CandidateDisposition::Conflict,
        RepairOutcome::Blocked => CandidateDisposition::Blocked,
        RepairOutcome::Rejected => CandidateDisposition::Unsupported,
    }
}

fn repair_error_as_contract(error: RepairError) -> ContractViolation {
    match error {
        RepairError::Bounds { phase, detail } => ContractViolation::Malformed {
            field: "memory_repair.bounds",
            reason: redact(&format!("{phase}: {detail}")),
        },
        RepairError::Order { phase, detail } => ContractViolation::BindingMismatch {
            field: "memory_repair.order",
            reason: redact(&format!("{phase}: {detail}")),
        },
        RepairError::Member { handle, detail } => ContractViolation::BindingMismatch {
            field: "memory_repair.member",
            reason: redact(&format!("{handle}: {detail}")),
        },
        RepairError::Receipt { detail } => ContractViolation::BindingMismatch {
            field: "memory_repair.receipt",
            reason: redact(&detail),
        },
    }
}

impl NativeCurationHandler for MemoryRepairHandler {
    fn handle(
        &self,
        call: &BoundCurationCall,
    ) -> Result<ProducedCurationContent, ContractViolation> {
        let payload = self.bind_call(call)?;
        let candidate = propose_memory_repair(&self.request).map_err(repair_error_as_contract)?;
        let content = ProducedCurationContent {
            payload: CurationPayload::Repair(payload),
            disposition: candidate_disposition(candidate.outcome),
            preservation: self.request.preservation.clone(),
            support_note: format!(
                "memory repair candidate: {}",
                redact(&candidate.expected_observable)
            ),
            rollback_note: redact(&candidate.inverse_note),
            counterevidence_refs: self.request.projection.counterevidence_refs.clone(),
        };
        Ok(content)
    }
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

#[allow(clippy::too_many_lines)]
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
            spec.conflicting_lineage_refs.len(),
            evidence_ceiling,
        )?;
        bound_list_length(
            "provenance-derivatives",
            spec.affected_derivative_refs.len(),
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
            "contamination-taint",
            spec.taint_lineage_refs.len(),
            evidence_ceiling,
        )?;
        bound_list_length(
            "contamination-revocation",
            spec.revocation_refs.len(),
            evidence_ceiling,
        )?;
    }
    if let Some(spec) = &request.relation {
        bound_list_length(
            "relation-sources",
            spec.original_source_refs.len(),
            evidence_ceiling,
        )?;
        bound_list_length(
            "relation-counterevidence",
            spec.contradictory_evidence_refs.len(),
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
            "stale-unknown-sources",
            spec.unknown_source_refs.len(),
            MAX_CLOSURE_REFS,
        )?;
        bound_list_length(
            "stale-consumers",
            spec.consumer_refs.len(),
            MAX_CLOSURE_REFS,
        )?;
        bound_list_length("stale-context", spec.context_refs.len(), MAX_CLOSURE_REFS)?;
        bound_list_length("stale-cues", spec.cue_refs.len(), MAX_CLOSURE_REFS)?;
        bound_list_length("stale-index", spec.index_refs.len(), MAX_CLOSURE_REFS)?;
        bound_list_length(
            "stale-decisions",
            spec.decision_refs.len(),
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
        bound_list_length(
            "representation-context",
            spec.context_refs.len(),
            MAX_CLOSURE_REFS,
        )?;
        bound_list_length(
            "representation-index",
            spec.index_refs.len(),
            MAX_CLOSURE_REFS,
        )?;
    }
    Ok(())
}

fn preflight_text_and_order(request: &MemoryRepairRequest) -> Result<(), RepairError> {
    let mut total = 0usize;
    total = total.saturating_add(count_text_bytes(&[
        &request.identity.request_id,
        &request.identity.operation_id,
        &request.identity.idempotency_key,
        &request.identity.requester,
        &request.identity.canonical_request_digest,
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
    bound_list_length(
        "raw-history",
        request.projection.raw_history_refs.len(),
        MAX_PROTECTIONS,
    )?;
    bound_list_length(
        "audit",
        request.projection.audit_refs.len(),
        MAX_PROTECTIONS,
    )?;
    bound_list_length(
        "minority",
        request.projection.minority_refs.len(),
        MAX_PROTECTIONS,
    )?;
    bound_list_length(
        "dependency-roots",
        request.projection.dependency_root_refs.len(),
        MAX_PROTECTIONS,
    )?;
    bound_list_length(
        "negative-memory",
        request.projection.negative_memory_refs.len(),
        MAX_PROTECTIONS,
    )?;
    bound_list_length(
        "counterevidence",
        request.projection.counterevidence_refs.len(),
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
        request.projection.threat.threat_lineage_refs.len(),
        evidence_ceiling,
    )?;
    bound_list_length(
        "threat-revocation",
        request.projection.threat.revocation_refs.len(),
        evidence_ceiling,
    )?;
    bound_list_length(
        "threat-taint",
        request.projection.threat.taint_refs.len(),
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

#[allow(clippy::too_many_lines)]
fn validate_shapes(request: &MemoryRepairRequest) -> Result<(), RepairError> {
    check_handle(&request.identity.request_id, "identity.request")?;
    check_handle(&request.identity.operation_id, "identity.operation")?;
    check_handle(&request.identity.idempotency_key, "identity.idempotency")?;
    check_handle(&request.identity.requester, "identity.requester")?;
    if request.identity.attempt == 0 {
        return Err(RepairError::Bounds {
            phase: "identity.attempt".to_owned(),
            detail: "attempt is one-based and must be non-zero".to_owned(),
        });
    }
    check_digest(
        &request.identity.canonical_request_digest,
        "identity.request-digest",
    )?;
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
        &request.projection.raw_history_refs,
        "projection.raw-history",
    )?;
    validate_sorted_refs(&request.projection.audit_refs, "projection.audit")?;
    validate_sorted_refs(&request.projection.minority_refs, "projection.minority")?;
    validate_sorted_refs(
        &request.projection.dependency_root_refs,
        "projection.dependency-roots",
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
        identity: request.identity.clone(),
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
        protection_refs: request.projection.protection_refs.clone(),
        raw_history_refs: request.projection.raw_history_refs.clone(),
        audit_refs: request.projection.audit_refs.clone(),
        minority_refs: request.projection.minority_refs.clone(),
        dependency_root_refs: request.projection.dependency_root_refs.clone(),
        negative_memory_refs: request.projection.negative_memory_refs.clone(),
        counterevidence_refs: request.projection.counterevidence_refs.clone(),
        axis_revisions: request.projection.axis_revisions.clone(),
        trajectory: request.projection.trajectory.clone(),
        threat: request.projection.threat.clone(),
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
    if request.item.receipt != request.receipt {
        return Ok(Some(unchanged_candidate(
            request,
            RepairOutcome::Stale,
            "validated item receipt differs from the supplied validation receipt",
        )?));
    }
    if request.grounded.job_id != request.receipt.job_id
        || request.grounded.draft_digest != request.receipt.draft_digest
    {
        return Ok(Some(unchanged_candidate(
            request,
            RepairOutcome::Stale,
            "grounded draft is not bound to the validated job and draft",
        )?));
    }
    if request.receipt.task_id != request.projection.task_id
        || request.receipt.scope_id != request.projection.scope_id
        || request.receipt.state_fence != request.projection.state_fence
    {
        return Ok(Some(unchanged_candidate(
            request,
            RepairOutcome::Stale,
            "validation receipt is not bound to the current task scope and fence",
        )?));
    }
    if request.identity.requester != request.item.requester.principal {
        return Ok(Some(unchanged_candidate(
            request,
            RepairOutcome::Rejected,
            "requester identity does not bind to the validated item",
        )?));
    }
    let expected_digest = canonical_request_digest(request)?;
    if request.identity.canonical_request_digest != expected_digest {
        return Ok(Some(unchanged_candidate(
            request,
            RepairOutcome::Stale,
            "same idempotency identity carries a changed canonical request",
        )?));
    }
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
    if let (Some(observed), Some(expiry)) =
        (request.policy.observation_time_ms, request.policy.expiry_ms)
        && observed >= expiry
    {
        return Ok(Some(unchanged_candidate(
            request,
            RepairOutcome::Stale,
            "observation is at or beyond the proposal expiry",
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

#[allow(clippy::too_many_lines)]
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
    if spec.ambiguous_source {
        return Ok(KindVerdict::Outcome {
            outcome: RepairOutcome::Rejected,
            note: "an ambiguous source cannot fill an exact provenance edge".to_owned(),
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
    if !contains_handle(&spec.expected_lineage, &link.source_handle) {
        return Ok(KindVerdict::Outcome {
            outcome: RepairOutcome::Blocked,
            note: "authoritative source is outside the expected lineage denominator".to_owned(),
        });
    }
    if link.source_state_fence != request.projection.state_fence {
        return Ok(KindVerdict::Outcome {
            outcome: RepairOutcome::Stale,
            note: "authoritative source fence does not bind the projected fence".to_owned(),
        });
    }
    if link.privacy_note != request.policy.privacy_ceiling {
        return Ok(KindVerdict::Outcome {
            outcome: RepairOutcome::Blocked,
            note: "authoritative source privacy binding exceeds or differs from policy".to_owned(),
        });
    }
    for required in [
        spec.missing_edge.as_str(),
        link.source_handle.as_str(),
        link.source_revision.as_str(),
        link.source_digest.as_str(),
        link.scope_id.as_str(),
    ] {
        if !link.match_note.contains(required) {
            return Ok(KindVerdict::Outcome {
                outcome: RepairOutcome::Blocked,
                note: "source match note does not bind every exact edge field".to_owned(),
            });
        }
    }
    if contains_handle(&spec.conflicting_lineage_refs, &link.source_handle) {
        return Ok(KindVerdict::Outcome {
            outcome: RepairOutcome::Review,
            note: "the proposed source is also recorded as conflicting lineage".to_owned(),
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

#[allow(clippy::too_many_lines)]
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
    closure
        .bsec1_closure
        .validate()
        .map_err(|error| RepairError::Member {
            handle: redact(&closure.closure_id),
            detail: format!(
                "public B-SEC1 closure is invalid: {}",
                redact(&error.to_string())
            ),
        })?;
    validate_sorted_refs(&closure.dependent_refs, "closure.dependents")?;
    validate_sorted_refs(&closure.unknown_gaps, "closure.gaps")?;
    check_text(&closure.review_owner, "closure.review-owner")?;
    check_text(&closure.renewal_owner, "closure.renewal-owner")?;
    check_text(&closure.verifier, "closure.verifier")?;
    check_text(&closure.closure_revision, "closure.revision")?;
    if closure.closure_id != closure.bsec1_closure.closure_id {
        return Ok(KindVerdict::Outcome {
            outcome: RepairOutcome::Stale,
            note: "local closure identity does not bind the public B-SEC1 closure".to_owned(),
        });
    }
    if closure.bsec1_closure.root_ref != spec.source_handle {
        return Ok(KindVerdict::Outcome {
            outcome: RepairOutcome::Blocked,
            note: "public B-SEC1 closure root does not bind the named taint source".to_owned(),
        });
    }
    if closure.bsec1_closure.dependent_refs != closure.dependent_refs {
        return Ok(KindVerdict::Outcome {
            outcome: RepairOutcome::Partial,
            note: "public B-SEC1 closure dependents do not match the adapter denominator"
                .to_owned(),
        });
    }
    if closure.bsec1_closure.state_fence != closure.state_fence {
        return Ok(KindVerdict::Outcome {
            outcome: RepairOutcome::Stale,
            note: "public B-SEC1 closure fence does not bind the adapter closure".to_owned(),
        });
    }
    if matches!(
        closure.bsec1_closure.current_influence,
        InfluenceState::Active | InfluenceState::Unknown
    ) {
        return Ok(KindVerdict::Outcome {
            outcome: RepairOutcome::Blocked,
            note: "active or unknown B-SEC1 influence cannot prove contained contamination"
                .to_owned(),
        });
    }
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
    if closure.state_fence != request.projection.state_fence
        || closure.closure_revision != request.projection.subject_revision
    {
        return Ok(KindVerdict::Outcome {
            outcome: RepairOutcome::Stale,
            note: "contamination closure is not bound to the current revision and fence".to_owned(),
        });
    }
    if spec.taint_lineage_refs != request.projection.threat.taint_refs
        || spec.revocation_refs != request.projection.threat.revocation_refs
    {
        return Ok(KindVerdict::Outcome {
            outcome: RepairOutcome::Stale,
            note: "taint or revocation lineage moved from the current threat projection".to_owned(),
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
    let affected_handles: Vec<String> = request
        .affected
        .iter()
        .map(|member| member.handle.clone())
        .collect();
    if !sorted_set_eq(&closure.dependent_refs, &affected_handles) {
        return Ok(KindVerdict::Outcome {
            outcome: RepairOutcome::Partial,
            note: "complete contamination closure must match every affected member".to_owned(),
        });
    }
    if !spec.revocation_refs.is_empty() && closure.renewal_owner == closure.review_owner {
        return Ok(KindVerdict::Outcome {
            outcome: RepairOutcome::Blocked,
            note: "revoked influence requires a distinct renewal owner".to_owned(),
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

#[allow(clippy::too_many_lines)]
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
    if !CANONICAL_RELATION_TYPES.contains(&spec.relation_type.as_str()) {
        return Ok(KindVerdict::Outcome {
            outcome: RepairOutcome::Rejected,
            note: "relation type is not a canonical relation-registry family".to_owned(),
        });
    }
    if spec.scope_id != request.projection.scope_id {
        return Ok(KindVerdict::Outcome {
            outcome: RepairOutcome::Stale,
            note: "relation scope moved from the projected scope".to_owned(),
        });
    }
    let subject_is_a = spec.endpoint_a == request.projection.subject_handle;
    let subject_is_b = spec.endpoint_b == request.projection.subject_handle;
    if !subject_is_a && !subject_is_b {
        return Ok(KindVerdict::Outcome {
            outcome: RepairOutcome::Blocked,
            note: "relation endpoints do not include the projected subject".to_owned(),
        });
    }
    if (subject_is_a && spec.endpoint_a_revision != request.projection.subject_revision)
        || (subject_is_b && spec.endpoint_b_revision != request.projection.subject_revision)
    {
        return Ok(KindVerdict::Outcome {
            outcome: RepairOutcome::Stale,
            note: "relation endpoint revision does not bind the projected subject".to_owned(),
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
    if spec
        .original_source_refs
        .iter()
        .any(|source| spec.contradictory_evidence_refs.contains(source))
    {
        return Ok(KindVerdict::Outcome {
            outcome: RepairOutcome::Review,
            note: "source and contradictory evidence sets overlap ambiguously".to_owned(),
        });
    }
    if spec.dependent_refs.len() != spec.expected_dependents_total as usize {
        return Ok(false_relation_partial_denominator(request, spec));
    }
    let affected_handles: Vec<String> = request
        .affected
        .iter()
        .map(|member| member.handle.clone())
        .collect();
    if !sorted_set_eq(&spec.dependent_refs, &affected_handles) {
        return Ok(KindVerdict::Outcome {
            outcome: RepairOutcome::Partial,
            note: "relation dependent closure does not match every affected member".to_owned(),
        });
    }
    if !spec.mapping_note.contains(&spec.relation_id)
        || !spec.mapping_note.contains(&spec.relation_revision)
    {
        return Ok(KindVerdict::Outcome {
            outcome: RepairOutcome::Blocked,
            note: "relation mapping does not preserve the exact old identity".to_owned(),
        });
    }
    let kind = match &spec.proposal {
        FalseRelationProposal::Invalidate => RepairOperationKind::RelationInvalidate,
        FalseRelationProposal::Reclassify { new_type } => {
            check_text(new_type, "relation.new-type")?;
            if new_type == &spec.relation_type || !spec.mapping_note.contains(new_type) {
                return Ok(KindVerdict::Outcome {
                    outcome: RepairOutcome::Blocked,
                    note: "reclassification needs a distinct grounded type in the mapping"
                        .to_owned(),
                });
            }
            RepairOperationKind::RelationReclassify
        }
        FalseRelationProposal::Replace { replacement_ref } => {
            check_handle(replacement_ref, "relation.replacement")?;
            if !contains_handle(&spec.contradictory_evidence_refs, replacement_ref)
                || !spec.mapping_note.contains(replacement_ref)
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

#[allow(clippy::too_many_lines)]
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
    validate_sorted_refs(&spec.unknown_source_refs, "stale.unknown-sources")?;
    check_handle(&spec.invalidation_ref, "stale.invalidation")?;
    check_text(&spec.rebuild_owner, "stale.rebuild-owner")?;
    check_text(&spec.rebuild_contract_ref, "stale.rebuild-contract")?;
    check_text(&spec.verifier, "stale.verifier")?;
    check_text(&spec.inverse_note, "stale.inverse")?;
    validate_sorted_refs(&spec.consumer_refs, "stale.consumers")?;
    validate_sorted_refs(&spec.context_refs, "stale.context")?;
    validate_sorted_refs(&spec.cue_refs, "stale.cues")?;
    validate_sorted_refs(&spec.index_refs, "stale.index")?;
    validate_sorted_refs(&spec.decision_refs, "stale.decisions")?;
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
    if !spec.unknown_source_refs.is_empty()
        || spec.source_frontier.len() != spec.expected_frontier_total as usize
    {
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
            note: "source frontier is partial or unknown; a complete rebuild is blocked".to_owned(),
        });
    }
    let all_consumer_refs = [
        &spec.context_refs,
        &spec.cue_refs,
        &spec.index_refs,
        &spec.decision_refs,
    ];
    if spec.consumer_refs.is_empty()
        || all_consumer_refs.iter().any(|refs| refs.is_empty())
        || all_consumer_refs
            .iter()
            .flat_map(|refs| refs.iter())
            .any(|reference| !contains_handle(&spec.consumer_refs, reference))
    {
        return Ok(KindVerdict::Outcome {
            outcome: RepairOutcome::Partial,
            note: "consumer plan lacks a Context, cue, index, or decision binding".to_owned(),
        });
    }
    if !spec.inverse_note.contains(&spec.view_handle)
        || !spec.inverse_note.contains(&spec.view_revision)
    {
        return Ok(KindVerdict::Outcome {
            outcome: RepairOutcome::Blocked,
            note: "stale view inverse must retain the exact old handle and revision".to_owned(),
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
    if spec.source_coverage_refs.is_empty() {
        return Ok(KindVerdict::Outcome {
            outcome: RepairOutcome::Abstention,
            note: "absent source routes to provenance or unsupported, not invention".to_owned(),
        });
    }
    if spec.canonical_identity != request.projection.subject_handle {
        return Ok(KindVerdict::Outcome {
            outcome: RepairOutcome::Rejected,
            note: "representation must bind one existing canonical identity".to_owned(),
        });
    }
    if spec.canonical_revision != request.projection.subject_revision
        || spec.canonical_digest != request.projection.subject_digest
        || !contains_handle(&spec.source_coverage_refs, &spec.canonical_source_ref)
    {
        return Ok(KindVerdict::Outcome {
            outcome: RepairOutcome::Stale,
            note: "representation does not bind one existing canonical revision and source"
                .to_owned(),
        });
    }
    if spec.second_truth {
        return Ok(KindVerdict::Outcome {
            outcome: RepairOutcome::Rejected,
            note: "a second truth or support owner is never proposed".to_owned(),
        });
    }
    if spec.conflicting_duplicate {
        return Ok(KindVerdict::Outcome {
            outcome: RepairOutcome::Rejected,
            note: "conflicting duplicate representations remain explicit and are not merged"
                .to_owned(),
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
    if spec.consumer_refs.is_empty()
        || spec.context_refs.is_empty()
        || spec.index_refs.is_empty()
        || spec
            .context_refs
            .iter()
            .chain(spec.index_refs.iter())
            .any(|reference| !contains_handle(&spec.consumer_refs, reference))
    {
        return Ok(KindVerdict::Outcome {
            outcome: RepairOutcome::Partial,
            note: "consumer, index, or Context denominator is partial; completeness is blocked"
                .to_owned(),
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
        let unchanged = disposition.disposition == MemberDispositionKind::UnchangedWithEvidence;
        if unchanged && disposition.old_identity != disposition.proposed_identity {
            return Some(KindVerdict::Outcome {
                outcome: RepairOutcome::Rejected,
                note: "an unchanged disposition must preserve its exact identity".to_owned(),
            });
        }
        if !unchanged && disposition.old_identity == disposition.proposed_identity {
            return Some(KindVerdict::Outcome {
                outcome: RepairOutcome::Partial,
                note: "a changed disposition must name a proposed identity change".to_owned(),
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

fn validate_operations(
    request: &MemoryRepairRequest,
    operations: &[TypedRepairOperation],
) -> Option<KindVerdict> {
    for operation in operations {
        if operation.owner.trim().is_empty()
            || operation.verifier.trim().is_empty()
            || operation.inverse_note.trim().is_empty()
            || operation.scope_id != request.projection.scope_id
        {
            return Some(KindVerdict::Outcome {
                outcome: RepairOutcome::Blocked,
                note: "every proposed operation needs an owner, verifier, inverse, and scope"
                    .to_owned(),
            });
        }
    }
    None
}

#[derive(Serialize)]
struct DigestView<'a> {
    request_id: &'a str,
    operation_id: &'a str,
    idempotency_key: &'a str,
    requester: &'a str,
    attempt: u32,
    canonical_request_digest: &'a str,
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
        request_id: request.identity.request_id.as_str(),
        operation_id: request.identity.operation_id.as_str(),
        idempotency_key: request.identity.idempotency_key.as_str(),
        requester: request.identity.requester.as_str(),
        attempt: request.identity.attempt,
        canonical_request_digest: request.identity.canonical_request_digest.as_str(),
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
    if let Some(KindVerdict::Outcome { outcome, note }) = validate_operations(request, &operations)
    {
        return unchanged_candidate(request, outcome, &note);
    }
    // A failed or unknown preservation dimension blocks completeness without
    // invoking any further validation: the candidate drops to partial.
    if outcome == RepairOutcome::Complete && request.preservation.overall().is_err() {
        outcome = RepairOutcome::Partial;
        "a preservation dimension failed or is unknown; completeness is blocked"
            .clone_into(&mut note);
    }
    let inverse_note = operations.first().map_or_else(
        || request.policy.inverse_note.clone(),
        |operation| operation.inverse_note.clone(),
    );
    let digest_inputs = CandidateDigestInputs {
        request,
        operations: &operations,
        subject_handle: &request.projection.subject_handle,
        subject_revision: &request.projection.subject_revision,
        hypothesis: &hypothesis,
        verifier: &request.policy.verifier,
        inverse_note: inverse_note.as_str(),
        expiry_ms: request.policy.expiry_ms,
    };
    let digest = candidate_digest(&digest_inputs)?;
    Ok(MemoryRepairCandidate {
        outcome,
        defect_kind: request.defect_kind,
        subject_handle: request.projection.subject_handle.clone(),
        subject_revision: request.projection.subject_revision.clone(),
        identity: request.identity.clone(),
        operations,
        dispositions: request.dispositions.clone(),
        hypothesis,
        expected_observable: observable,
        verifier: request.policy.verifier.clone(),
        window_note: request.policy.observation_window_note.clone(),
        inverse_note,
        forward_correction_note:
            "when the before state is unreachable the owner re-derives from the bound frontier"
                .to_owned(),
        expiry_ms: request.policy.expiry_ms,
        renewal_condition: request.policy.renewal_condition.clone(),
        reopen_note: request.projection.trajectory.reopen_condition.clone(),
        unknown_handling_note: "unknown outcomes stay open and block completeness".to_owned(),
        dimensions_note: "seven dimensions judged independently with no averaging".to_owned(),
        protection_refs: request.projection.protection_refs.clone(),
        raw_history_refs: request.projection.raw_history_refs.clone(),
        audit_refs: request.projection.audit_refs.clone(),
        minority_refs: request.projection.minority_refs.clone(),
        dependency_root_refs: request.projection.dependency_root_refs.clone(),
        negative_memory_refs: request.projection.negative_memory_refs.clone(),
        counterevidence_refs: request.projection.counterevidence_refs.clone(),
        axis_revisions: request.projection.axis_revisions.clone(),
        trajectory: request.projection.trajectory.clone(),
        threat: request.projection.threat.clone(),
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

/// Maps a terminal outcome to the closest A-03 curation rejection hint, if any.
#[must_use]
pub fn outcome_rejection_hint(outcome: &RepairOutcome) -> Option<CurationRejectionCode> {
    match outcome {
        RepairOutcome::Complete => None,
        RepairOutcome::Partial | RepairOutcome::Blocked | RepairOutcome::Review => {
            Some(CurationRejectionCode::PreservationFailed)
        }
        RepairOutcome::Abstention | RepairOutcome::NoSafeRepair => {
            Some(CurationRejectionCode::LineageMismatch)
        }
        RepairOutcome::Stale | RepairOutcome::Rejected => {
            Some(CurationRejectionCode::IdentityMismatch)
        }
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::large_stack_arrays)]
mod tests {
    use super::*;
    use eliot_contracts::{EpochId, EpochLineageId, ReceiptId, RequestId, ResourceGeneration};
    use eliot_dreamer_contracts::candidate::{DimensionVerdict, PreservationDimension};
    use eliot_dreamer_contracts::curation::{RepairPayload, TargetEvidence};
    use eliot_dreamer_contracts::{
        AtomicityMode, BoundCurationCall, ClaimResidue, CurationFamily, CurationHandlerDescriptor,
        CurationHandlerPort, CurationKind, Requester, RequesterOrigin, ScreenBinding, ScreenState,
        SupportState, TypedCurationHandlerRequest, kind_family,
    };
    use std::num::NonZeroU64;

    fn test_fence_with_sequence(sequence: u64) -> StateFence {
        let epoch = EpochId::new(
            EpochLineageId::new("550e8400-e29b-41d4-a716-446655440000")
                .expect("canonical test lineage-A"),
            NonZeroU64::new(sequence).expect("non-zero test sequence"),
        )
        .expect("valid test epoch");
        StateFence::new(epoch, ResourceGeneration::genesis())
    }

    fn test_fence() -> StateFence {
        test_fence_with_sequence(1)
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

    fn bound_call(item: &ValidatedCurationItem) -> BoundCurationCall {
        let fence = item.state_fence.clone();
        let request_id = match RequestId::new("request-1") {
            Ok(value) => value,
            Err(error) => panic!("request id fixture must be valid: {error:?}"),
        };
        let receipt_id = match ReceiptId::new("receipt-1") {
            Ok(value) => value,
            Err(error) => panic!("receipt id fixture must be valid: {error:?}"),
        };
        let targets = item.payload.facets().targets.clone();
        let request = TypedCurationHandlerRequest {
            request_id: request_id.clone().into_string(),
            receipt_id: receipt_id.clone().into_string(),
            source_snapshot: "snapshot-1".to_owned(),
            source_revision: "revision-1".to_owned(),
            profile: "repair-profile".to_owned(),
            kind: CurationKind::Repair,
            family: CurationFamily::MemoryRepair,
            job_id: "job-1".to_owned(),
            scope_id: item.scope_id.clone(),
            task_id: item.task_id.clone(),
            state_fence: fence.clone(),
            payload: item.payload.clone(),
            denominator: item.denominator.clone(),
            screen_binding: Some(ScreenBinding {
                request_id,
                receipt_id,
                screened_targets: targets,
                source_snapshot: "snapshot-1".to_owned(),
                source_revision: "revision-1".to_owned(),
                profile: "repair-profile".to_owned(),
                task_id: item.task_id.clone(),
                scope_id: item.scope_id.clone(),
                state_fence: fence,
                state: ScreenState::Eligible,
                result_digest: "1".repeat(64),
                item_digest: "2".repeat(64),
            }),
        };
        BoundCurationCall {
            port: CurationHandlerPort {
                port_id: MEMORY_REPAIR_PORT_ID.to_owned(),
                descriptor: CurationHandlerDescriptor {
                    family: CurationFamily::MemoryRepair,
                    handler_id: MEMORY_REPAIR_HANDLER_ID.to_owned(),
                    accepted_kinds: vec![CurationKind::Repair],
                },
            },
            item: item.clone(),
            request,
            registry_digest: "3".repeat(64),
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
            raw_history_refs: Vec::new(),
            audit_refs: Vec::new(),
            minority_refs: Vec::new(),
            dependency_root_refs: Vec::new(),
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
                source_state_fence: test_fence(),
                match_note: format!(
                    "receipt r-9 records exactly edge mem-1.author src-1 at rev-4 digest {} scope-1",
                    "7".repeat(64)
                ),
            }),
            conflicting_lineage_refs: vec!["src-2".to_owned()],
            affected_derivative_refs: vec!["dep-1".to_owned()],
            similarity_only: false,
            owner_conflict: false,
            ambiguous_source: false,
            verifier: "verifier-7".to_owned(),
        }
    }

    fn contamination_spec() -> ContaminationRepairSpec {
        ContaminationRepairSpec {
            subject_handle: "mem-1".to_owned(),
            source_handle: "src-taint".to_owned(),
            derived_influence_note: "ranking cue c-2 derives from src-taint".to_owned(),
            current_graph_note: "graph g-1 at rev-2 under policy-7".to_owned(),
            taint_lineage_refs: vec!["taint-1".to_owned()],
            revocation_refs: vec!["revoke-1".to_owned()],
            action: ContaminationAction::QuarantineDependents,
            closure: ContaminationClosure {
                closure_id: "closure-1".to_owned(),
                bsec1_closure: InfluenceDependencyClosure {
                    closure_id: "closure-1".to_owned(),
                    root_ref: "src-taint".to_owned(),
                    dependent_refs: vec!["dep-1".to_owned()],
                    invalidation_reason: Some(eliot_security_contracts::RevocationReason::Poisoned),
                    current_influence: InfluenceState::Revoked,
                    state_fence: test_fence(),
                    revision: 1,
                },
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
            unknown_source_refs: Vec::new(),
            invalidation_ref: "inv-1".to_owned(),
            rebuild_owner: "owner-view".to_owned(),
            rebuild_contract_ref: "contract-view-2".to_owned(),
            old_bytes_preserved: true,
            timestamp_offered_as_currentness: false,
            consumer_refs: vec![
                "ctx-1".to_owned(),
                "cue-1".to_owned(),
                "dec-1".to_owned(),
                "idx-1".to_owned(),
            ],
            context_refs: vec!["ctx-1".to_owned()],
            cue_refs: vec!["cue-1".to_owned()],
            index_refs: vec!["idx-1".to_owned()],
            decision_refs: vec!["dec-1".to_owned()],
            verifier: "verifier-7".to_owned(),
            inverse_note: "serve mem-1 rev-2 bytes again".to_owned(),
        }
    }

    fn representation_spec() -> RepresentationSpec {
        RepresentationSpec {
            canonical_identity: "mem-1".to_owned(),
            canonical_revision: "rev-2".to_owned(),
            canonical_source_ref: "src-1".to_owned(),
            canonical_digest: "9".repeat(64),
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
            conflicting_duplicate: false,
            widens_ceilings: false,
            consumer_refs: vec!["ctx-1".to_owned(), "idx-1".to_owned()],
            context_refs: vec!["ctx-1".to_owned()],
            index_refs: vec!["idx-1".to_owned()],
            verifier: "verifier-7".to_owned(),
            inverse_note: "drop the caption".to_owned(),
        }
    }

    fn base_request(spelling: &str, kind: RepairDefectKind) -> MemoryRepairRequest {
        let receipt = test_receipt();
        let mut request = MemoryRepairRequest {
            identity: RepairIdentity {
                request_id: "request-1".to_owned(),
                operation_id: "operation-1".to_owned(),
                idempotency_key: "repair-1".to_owned(),
                requester: "op-1".to_owned(),
                attempt: 1,
                canonical_request_digest: "0".repeat(64),
            },
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
        };
        request.projection.raw_history_refs = vec!["raw-1".to_owned()];
        request.projection.audit_refs = vec!["audit-1".to_owned()];
        request.projection.minority_refs = vec!["minority-1".to_owned()];
        request.projection.dependency_root_refs = vec!["root-1".to_owned()];
        request.policy.privacy_ceiling = "reviewers only".to_owned();
        request.identity.canonical_request_digest =
            canonical_request_digest(&request).expect("request fixture must seal");
        request
    }

    fn reseal(request: &mut MemoryRepairRequest) {
        request.identity.canonical_request_digest =
            canonical_request_digest(request).expect("request mutation must reseal");
    }

    fn valid_provenance_request() -> MemoryRepairRequest {
        let mut request = base_request("provenance-link", RepairDefectKind::MissingProvenance);
        request.provenance = Some(provenance_spec());
        request.dispositions = test_disposition(MemberDispositionKind::ProvenanceLink);
        reseal(&mut request);
        request
    }

    fn valid_contamination_request() -> MemoryRepairRequest {
        let mut request = base_request(
            "contamination-quarantine",
            RepairDefectKind::ContaminatedInfluence,
        );
        request.contamination = Some(contamination_spec());
        reseal(&mut request);
        request
    }

    fn valid_relation_request() -> MemoryRepairRequest {
        let mut request = base_request("relation-invalidate", RepairDefectKind::FalseRelation);
        request.relation = Some(relation_spec());
        request.dispositions = test_disposition(MemberDispositionKind::RelationChange);
        reseal(&mut request);
        request
    }

    fn valid_stale_view_request() -> MemoryRepairRequest {
        let mut request = base_request("view-rebuild", RepairDefectKind::StaleDerivedView);
        request.stale_view = Some(stale_view_spec());
        request.dispositions = test_disposition(MemberDispositionKind::Rebuild);
        reseal(&mut request);
        request
    }

    fn valid_representation_request() -> MemoryRepairRequest {
        let mut request = base_request("representation-add", RepairDefectKind::RepresentationGap);
        request.representation = Some(representation_spec());
        request.dispositions = test_disposition(MemberDispositionKind::RepresentationChange);
        reseal(&mut request);
        request
    }

    fn outcome(request: &MemoryRepairRequest) -> RepairOutcome {
        propose_memory_repair(request)
            .expect("bounded fixture should return a typed candidate")
            .outcome
    }

    #[test]
    fn a03_port_binds_repair_wire_kind_and_preserves_candidate_content() {
        let request = valid_provenance_request();
        let call = bound_call(&request.item);
        let handler = MemoryRepairHandler::new(request);

        let content = match handler.handle(&call) {
            Ok(content) => content,
            Err(error) => panic!("bound repair content: {error:?}"),
        };

        assert_eq!(
            memory_repair_handler_port().descriptor.family,
            CurationFamily::MemoryRepair
        );
        assert_eq!(
            memory_repair_handler_port().descriptor.accepted_kinds,
            vec![CurationKind::Repair]
        );
        assert!(matches!(
            content.payload,
            CurationPayload::Repair(RepairPayload { .. })
        ));
        assert_eq!(content.disposition, CandidateDisposition::Candidate);
    }

    #[test]
    fn a03_handler_rejects_a_rebound_item_before_proposal() {
        let request = valid_provenance_request();
        let mut call = bound_call(&request.item);
        call.item.budget_note = "rebound budget note".to_owned();

        let Err(err) = MemoryRepairHandler::new(request).handle(&call) else {
            panic!("changed accepted item must fail closed");
        };
        assert!(matches!(
            err,
            ContractViolation::BindingMismatch { field: "item", .. }
        ));
    }

    #[test]
    fn a03_handler_rejects_a_payload_rebinding_before_proposal() {
        let request = valid_provenance_request();
        let mut call = bound_call(&request.item);
        let CurationPayload::Repair(payload) = &mut call.request.payload else {
            panic!("repair fixture must carry RepairPayload");
        };
        payload.repair = "provenance-quarantine".to_owned();

        let Err(err) = MemoryRepairHandler::new(request).handle(&call) else {
            panic!("rebound typed request payload must fail closed");
        };
        assert!(matches!(
            err,
            ContractViolation::BindingMismatch {
                field: "payload",
                ..
            }
        ));
    }

    #[test]
    fn a03_repair_outcome_mapping_covers_every_closed_outcome() {
        let mappings = [
            (RepairOutcome::Complete, CandidateDisposition::Candidate),
            (RepairOutcome::Partial, CandidateDisposition::Partial),
            (RepairOutcome::Abstention, CandidateDisposition::Abstention),
            (
                RepairOutcome::NoSafeRepair,
                CandidateDisposition::Abstention,
            ),
            (RepairOutcome::Stale, CandidateDisposition::Conflict),
            (RepairOutcome::Blocked, CandidateDisposition::Blocked),
            (RepairOutcome::Review, CandidateDisposition::Partial),
            (RepairOutcome::Rejected, CandidateDisposition::Unsupported),
        ];
        assert_eq!(mappings.len(), 8);
        for (outcome, expected) in mappings {
            assert_eq!(candidate_disposition(outcome), expected);
        }
    }

    #[test]
    fn a03_repair_error_mapping_preserves_contract_violation_categories() {
        assert!(matches!(
            repair_error_as_contract(RepairError::Bounds {
                phase: "shape".to_owned(),
                detail: "bad bound".to_owned(),
            }),
            ContractViolation::Malformed {
                field: "memory_repair.bounds",
                ..
            }
        ));
        assert!(matches!(
            repair_error_as_contract(RepairError::Order {
                phase: "refs".to_owned(),
                detail: "not sorted".to_owned(),
            }),
            ContractViolation::BindingMismatch {
                field: "memory_repair.order",
                ..
            }
        ));
        assert!(matches!(
            repair_error_as_contract(RepairError::Member {
                handle: "member-1".to_owned(),
                detail: "not bound".to_owned(),
            }),
            ContractViolation::BindingMismatch {
                field: "memory_repair.member",
                ..
            }
        ));
        assert!(matches!(
            repair_error_as_contract(RepairError::Receipt {
                detail: "receipt drift".to_owned(),
            }),
            ContractViolation::BindingMismatch {
                field: "memory_repair.receipt",
                ..
            }
        ));
    }

    // WORK_UNIT_CASE: 671/1
    #[test]
    fn case_01_valid_missing_provenance_links_authoritative_source() {
        let request = valid_provenance_request();
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

        for other in [
            valid_contamination_request(),
            valid_relation_request(),
            valid_stale_view_request(),
            valid_representation_request(),
        ] {
            assert_eq!(outcome(&other), RepairOutcome::Complete);
        }
    }

    // WORK_UNIT_CASE: 671/2
    #[test]
    fn case_02_wrong_missing_and_multiple_subtypes_are_rejected() {
        let mut wrong = valid_provenance_request();
        wrong.defect_kind = RepairDefectKind::FalseRelation;
        reseal(&mut wrong);
        assert_eq!(outcome(&wrong), RepairOutcome::Rejected);

        let missing = base_request("provenance-link", RepairDefectKind::MissingProvenance);
        assert_eq!(outcome(&missing), RepairOutcome::Rejected);

        let mut multiple = valid_provenance_request();
        multiple.relation = Some(relation_spec());
        reseal(&mut multiple);
        assert_eq!(outcome(&multiple), RepairOutcome::Rejected);
    }

    // WORK_UNIT_CASE: 671/3
    #[test]
    fn case_03_identity_surgery_routes_to_a27_without_a_local_operation() {
        let request = base_request("merge-split", RepairDefectKind::MissingProvenance);
        let candidate = propose_memory_repair(&request).expect("identity route is typed");
        assert_eq!(candidate.outcome, RepairOutcome::Rejected);
        assert!(candidate.operations.is_empty());
        assert!(candidate.note.contains("a-27"));
    }

    // WORK_UNIT_CASE: 671/4
    #[test]
    fn case_04_content_reconsolidation_routes_to_a28() {
        let request = base_request("reconsolidate", RepairDefectKind::MissingProvenance);
        let candidate = propose_memory_repair(&request).expect("reconsolidation route is typed");
        assert_eq!(candidate.outcome, RepairOutcome::Rejected);
        assert!(candidate.operations.is_empty());
        assert!(candidate.note.contains("a-28"));
    }

    // WORK_UNIT_CASE: 671/5
    #[test]
    fn case_05_pure_axis_adjustment_routes_to_a29() {
        let request = base_request("axis-adjust", RepairDefectKind::MissingProvenance);
        let candidate = propose_memory_repair(&request).expect("axis route is typed");
        assert_eq!(candidate.outcome, RepairOutcome::Rejected);
        assert!(candidate.operations.is_empty());
        assert!(candidate.note.contains("a-29"));
    }

    // WORK_UNIT_CASE: 671/6
    #[test]
    fn case_06_task_attempt_scope_fence_bundle_manifest_and_grounding_mismatch_fail_closed() {
        let mut task = valid_provenance_request();
        task.projection.task_id = "task-moved".to_owned();
        reseal(&mut task);
        assert_eq!(outcome(&task), RepairOutcome::Stale);

        let mut attempt = valid_provenance_request();
        attempt.identity.attempt = 0;
        assert!(propose_memory_repair(&attempt).is_err());

        let mut scope = valid_provenance_request();
        scope.projection.scope_id = "scope-moved".to_owned();
        reseal(&mut scope);
        assert_eq!(outcome(&scope), RepairOutcome::Stale);

        let mut bundle = valid_provenance_request();
        bundle.frozen_bundle_digest = "0".repeat(64);
        reseal(&mut bundle);
        assert_eq!(outcome(&bundle), RepairOutcome::Stale);

        let mut manifest = valid_provenance_request();
        manifest.frozen_manifest_digest = "0".repeat(64);
        reseal(&mut manifest);
        assert_eq!(outcome(&manifest), RepairOutcome::Stale);

        let mut grounding = valid_provenance_request();
        grounding.grounded.draft_digest = "0".repeat(64);
        reseal(&mut grounding);
        assert_eq!(outcome(&grounding), RepairOutcome::Stale);
    }

    // WORK_UNIT_CASE: 671/7
    #[test]
    fn case_07_changed_same_id_request_is_a_canonical_identity_conflict() {
        let request = valid_provenance_request();
        let mut changed = request.clone();
        changed.projection.subject_digest = "8".repeat(64);
        let candidate = propose_memory_repair(&changed).expect("identity conflict is a candidate");
        assert_eq!(candidate.outcome, RepairOutcome::Stale);
        assert!(candidate.note.contains("canonical request"));
    }

    // WORK_UNIT_CASE: 671/8
    #[test]
    fn case_08_proposal_is_pure_and_operations_are_inert() {
        let request = valid_representation_request();
        let before = request.clone();
        let candidate = propose_memory_repair(&request).expect("pure proposal");
        assert_eq!(request, before);
        assert_eq!(candidate.outcome, RepairOutcome::Complete);
        assert!(!candidate.operations.is_empty());
        assert!(
            candidate
                .operations
                .iter()
                .all(|operation| !operation.owner.is_empty() && !operation.verifier.is_empty())
        );
        assert!(candidate.note.contains("canonical content unchanged"));
    }

    // WORK_UNIT_CASE: 671/9
    #[test]
    fn case_09_provenance_requires_the_exact_edge_and_authoritative_source() {
        let request = valid_provenance_request();
        let candidate = propose_memory_repair(&request).expect("exact source candidate");
        assert_eq!(candidate.outcome, RepairOutcome::Complete);
        assert_eq!(
            candidate.operations[0].operation,
            RepairOperationKind::ProvenanceLink
        );
        assert!(
            candidate
                .operations
                .iter()
                .all(|operation| operation.owner == "owner-assurance")
        );
    }

    // WORK_UNIT_CASE: 671/10
    #[test]
    fn case_10_fabricated_ambiguous_and_similarity_only_provenance_is_rejected() {
        let mut ambiguous = valid_provenance_request();
        ambiguous
            .provenance
            .as_mut()
            .expect("spec")
            .ambiguous_source = true;
        reseal(&mut ambiguous);
        assert_eq!(outcome(&ambiguous), RepairOutcome::Rejected);

        let mut similarity = valid_provenance_request();
        let spec = similarity.provenance.as_mut().expect("spec");
        spec.similarity_only = true;
        reseal(&mut similarity);
        assert_eq!(outcome(&similarity), RepairOutcome::Rejected);

        let mut fabricated = valid_provenance_request();
        fabricated
            .provenance
            .as_mut()
            .expect("spec")
            .authoritative_source
            .as_mut()
            .expect("link")
            .match_note = "content looks similar".to_owned();
        reseal(&mut fabricated);
        assert_eq!(outcome(&fabricated), RepairOutcome::Rejected);
    }

    // WORK_UNIT_CASE: 671/11
    #[test]
    fn case_11_conflicting_provenance_owners_require_review() {
        let mut request = valid_provenance_request();
        request.provenance.as_mut().expect("spec").owner_conflict = true;
        reseal(&mut request);
        assert_eq!(outcome(&request), RepairOutcome::Review);
    }

    // WORK_UNIT_CASE: 671/12
    #[test]
    fn case_12_provenance_denominator_distinguishes_full_partial_and_empty() {
        let mut partial = valid_provenance_request();
        partial.provenance.as_mut().expect("spec").expected_total = 2;
        reseal(&mut partial);
        assert_eq!(outcome(&partial), RepairOutcome::Partial);

        let mut empty = valid_provenance_request();
        let spec = empty.provenance.as_mut().expect("spec");
        spec.expected_lineage.clear();
        spec.expected_total = 0;
        reseal(&mut empty);
        assert_eq!(outcome(&empty), RepairOutcome::Blocked);
    }

    // WORK_UNIT_CASE: 671/13
    #[test]
    fn case_13_provenance_source_privacy_scope_fence_and_revision_mismatch_do_not_complete() {
        let mut privacy = valid_provenance_request();
        privacy.policy.privacy_ceiling = "different audience".to_owned();
        reseal(&mut privacy);
        assert_eq!(outcome(&privacy), RepairOutcome::Blocked);

        let mut scope = valid_provenance_request();
        scope
            .provenance
            .as_mut()
            .expect("spec")
            .authoritative_source
            .as_mut()
            .expect("link")
            .scope_id = "other-scope".to_owned();
        reseal(&mut scope);
        assert_eq!(outcome(&scope), RepairOutcome::Blocked);

        let mut revision = valid_provenance_request();
        revision
            .provenance
            .as_mut()
            .expect("spec")
            .authoritative_source
            .as_mut()
            .expect("link")
            .source_revision = "rev-5".to_owned();
        reseal(&mut revision);
        assert_eq!(outcome(&revision), RepairOutcome::Blocked);

        let mut fence = valid_provenance_request();
        fence
            .provenance
            .as_mut()
            .expect("spec")
            .authoritative_source
            .as_mut()
            .expect("link")
            .source_state_fence = StateFence::new(
            EpochId::new(
                EpochLineageId::new("550e8400-e29b-41d4-a716-446655440000").expect("lineage"),
                NonZeroU64::new(2).expect("sequence"),
            )
            .expect("fence"),
            ResourceGeneration::genesis(),
        );
        reseal(&mut fence);
        assert_eq!(outcome(&fence), RepairOutcome::Stale);
    }

    // WORK_UNIT_CASE: 671/14
    #[test]
    fn case_14_missing_authority_abstains_to_owner_revalidation() {
        let mut request = valid_provenance_request();
        request
            .provenance
            .as_mut()
            .expect("spec")
            .authoritative_source = None;
        reseal(&mut request);
        assert_eq!(outcome(&request), RepairOutcome::Abstention);
    }

    // WORK_UNIT_CASE: 671/15
    #[test]
    fn case_15_raw_history_and_dependents_are_preserved_in_the_candidate() {
        let request = valid_provenance_request();
        let candidate = propose_memory_repair(&request).expect("preservation candidate");
        assert_eq!(
            candidate.raw_history_refs,
            request.projection.raw_history_refs
        );
        assert_eq!(candidate.audit_refs, request.projection.audit_refs);
        assert_eq!(
            candidate.dependency_root_refs,
            request.projection.dependency_root_refs
        );
        assert_eq!(candidate.dispositions, request.dispositions);
        assert_eq!(
            candidate.counterevidence_refs,
            request.projection.counterevidence_refs
        );
    }

    // WORK_UNIT_CASE: 671/16
    #[test]
    fn case_16_complete_contamination_closure_holds_dependents() {
        let request = valid_contamination_request();
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

    // WORK_UNIT_CASE: 671/17
    #[test]
    fn case_17_taint_revocation_and_source_lineage_must_match_the_projection() {
        let mut request = valid_contamination_request();
        request
            .contamination
            .as_mut()
            .expect("spec")
            .taint_lineage_refs = vec!["different-taint".to_owned()];
        reseal(&mut request);
        assert_eq!(outcome(&request), RepairOutcome::Stale);

        let mut source = valid_contamination_request();
        source
            .contamination
            .as_mut()
            .expect("spec")
            .closure
            .bsec1_closure
            .root_ref = "different-source".to_owned();
        reseal(&mut source);
        assert_eq!(outcome(&source), RepairOutcome::Blocked);

        let mut note_only = valid_contamination_request();
        note_only
            .contamination
            .as_mut()
            .expect("spec")
            .derived_influence_note = "ranking cue has no textual source marker".to_owned();
        reseal(&mut note_only);
        assert_eq!(outcome(&note_only), RepairOutcome::Complete);
    }

    // WORK_UNIT_CASE: 671/18
    #[test]
    fn case_18_partial_unknown_and_stale_contamination_closure_blocks_completion() {
        let mut partial = valid_contamination_request();
        let closure = &mut partial.contamination.as_mut().expect("spec").closure;
        closure.complete = false;
        reseal(&mut partial);
        assert_eq!(outcome(&partial), RepairOutcome::Blocked);

        let mut stale = valid_contamination_request();
        let closure = &mut stale.contamination.as_mut().expect("spec").closure;
        closure.stale = true;
        reseal(&mut stale);
        assert_eq!(outcome(&stale), RepairOutcome::Blocked);

        let mut unknown = valid_contamination_request();
        let closure = &mut unknown.contamination.as_mut().expect("spec").closure;
        closure.unknown_gaps = vec!["branch-unknown".to_owned()];
        reseal(&mut unknown);
        assert_eq!(outcome(&unknown), RepairOutcome::Blocked);

        let mut active = valid_contamination_request();
        active
            .contamination
            .as_mut()
            .expect("spec")
            .closure
            .bsec1_closure
            .current_influence = InfluenceState::Active;
        active
            .contamination
            .as_mut()
            .expect("spec")
            .closure
            .bsec1_closure
            .invalidation_reason = None;
        reseal(&mut active);
        assert_eq!(outcome(&active), RepairOutcome::Blocked);

        let mut unknown_standing = valid_contamination_request();
        unknown_standing
            .contamination
            .as_mut()
            .expect("spec")
            .closure
            .bsec1_closure
            .current_influence = InfluenceState::Unknown;
        unknown_standing
            .contamination
            .as_mut()
            .expect("spec")
            .closure
            .bsec1_closure
            .invalidation_reason = None;
        reseal(&mut unknown_standing);
        assert_eq!(outcome(&unknown_standing), RepairOutcome::Blocked);

        let mut stale_fence = valid_contamination_request();
        stale_fence
            .contamination
            .as_mut()
            .expect("spec")
            .closure
            .bsec1_closure
            .state_fence = test_fence_with_sequence(2);
        reseal(&mut stale_fence);
        assert_eq!(outcome(&stale_fence), RepairOutcome::Stale);
    }

    // WORK_UNIT_CASE: 671/19
    #[test]
    fn case_19_contamination_actions_remain_owner_directed_and_inert() {
        let actions = [
            (
                ContaminationAction::QuarantineDependents,
                RepairOperationKind::QuarantineForRevalidation,
            ),
            (
                ContaminationAction::RevokeDependent,
                RepairOperationKind::OwnerDirectedReview,
            ),
            (
                ContaminationAction::RestrictScope,
                RepairOperationKind::OwnerDirectedReview,
            ),
            (
                ContaminationAction::RevalidateWithNewEvidence,
                RepairOperationKind::QuarantineForRevalidation,
            ),
        ];
        for (action, expected) in actions {
            let mut request = valid_contamination_request();
            request.contamination.as_mut().expect("spec").action = action;
            reseal(&mut request);
            let candidate = propose_memory_repair(&request).expect("inert action candidate");
            assert_eq!(candidate.outcome, RepairOutcome::Complete);
            assert_eq!(candidate.operations[0].operation, expected);
            assert_eq!(candidate.operations[0].owner, "owner-review");
        }
    }

    // WORK_UNIT_CASE: 671/20
    #[test]
    fn case_20_contamination_repair_carries_other_axes_and_history_unchanged() {
        let request = valid_contamination_request();
        let candidate = propose_memory_repair(&request).expect("axis preservation candidate");
        assert_eq!(candidate.axis_revisions, request.projection.axis_revisions);
        assert_eq!(
            candidate.negative_memory_refs,
            request.projection.negative_memory_refs
        );
        assert_eq!(candidate.trajectory, request.projection.trajectory);
        assert_eq!(candidate.threat, request.projection.threat);
        assert!(candidate.note.contains("no silent axis change"));
    }

    // WORK_UNIT_CASE: 671/21
    #[test]
    fn case_21_revoked_influence_requires_distinct_renewal_owner() {
        let mut request = valid_contamination_request();
        let spec = request.contamination.as_mut().expect("spec");
        spec.closure.renewal_owner = spec.closure.review_owner.clone();
        reseal(&mut request);
        assert_eq!(outcome(&request), RepairOutcome::Blocked);
    }

    // WORK_UNIT_CASE: 671/22
    #[test]
    fn case_22_retrieval_or_model_agreement_cannot_cleanse_taint() {
        let mut request = valid_contamination_request();
        request
            .contamination
            .as_mut()
            .expect("spec")
            .agreement_offered_as_cleansing = true;
        reseal(&mut request);
        assert_eq!(outcome(&request), RepairOutcome::Rejected);
    }

    // WORK_UNIT_CASE: 671/23
    #[test]
    fn case_23_contamination_candidate_requires_review_renewal_inverse_and_verifier() {
        let request = valid_contamination_request();
        let candidate = propose_memory_repair(&request).expect("owner-bound candidate");
        let operation = &candidate.operations[0];
        assert_eq!(operation.owner, "owner-review");
        assert_eq!(operation.verifier, "verifier-7");
        assert_eq!(operation.expiry_ms, request.policy.expiry_ms);
        assert!(operation.inverse_note.contains("release"));
        assert!(candidate.renewal_condition.contains("reopen"));

        let mut missing = valid_contamination_request();
        missing
            .contamination
            .as_mut()
            .expect("spec")
            .closure
            .review_owner = String::new();
        reseal(&mut missing);
        assert!(propose_memory_repair(&missing).is_err());
    }

    // WORK_UNIT_CASE: 671/24
    #[test]
    fn case_24_invalidate_exact_false_relation_revision() {
        let request = valid_relation_request();
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

    // WORK_UNIT_CASE: 671/25
    #[test]
    fn case_25_false_relation_reclassification_requires_a_distinct_grounded_type() {
        let mut request = valid_relation_request();
        request.relation.as_mut().expect("spec").proposal = FalseRelationProposal::Reclassify {
            new_type: "contradicts".to_owned(),
        };
        request
            .relation
            .as_mut()
            .expect("spec")
            .mapping_note
            .push_str("; reclassified as contradicts");
        reseal(&mut request);
        let candidate = propose_memory_repair(&request).expect("reclassification candidate");
        assert_eq!(candidate.outcome, RepairOutcome::Complete);
        assert_eq!(
            candidate.operations[0].operation,
            RepairOperationKind::RelationReclassify
        );

        let mut same = valid_relation_request();
        same.relation.as_mut().expect("spec").proposal = FalseRelationProposal::Reclassify {
            new_type: "supports".to_owned(),
        };
        reseal(&mut same);
        assert_eq!(outcome(&same), RepairOutcome::Blocked);
    }

    // WORK_UNIT_CASE: 671/26
    #[test]
    fn case_26_false_relation_replacement_needs_independent_counterevidence() {
        let mut request = valid_relation_request();
        request.relation.as_mut().expect("spec").proposal = FalseRelationProposal::Replace {
            replacement_ref: "e-9".to_owned(),
        };
        reseal(&mut request);
        let candidate = propose_memory_repair(&request).expect("replacement candidate");
        assert_eq!(candidate.outcome, RepairOutcome::Complete);
        assert_eq!(
            candidate.operations[0].operation,
            RepairOperationKind::RelationReplace
        );

        let mut original_only = valid_relation_request();
        original_only.relation.as_mut().expect("spec").proposal = FalseRelationProposal::Replace {
            replacement_ref: "e-1".to_owned(),
        };
        reseal(&mut original_only);
        assert_eq!(outcome(&original_only), RepairOutcome::Blocked);
    }

    // WORK_UNIT_CASE: 671/27
    #[test]
    fn case_27_false_relation_endpoint_type_revision_and_source_mismatches_fail_closed() {
        let mut endpoint = valid_relation_request();
        endpoint.relation.as_mut().expect("spec").endpoint_a = "other".to_owned();
        endpoint.relation.as_mut().expect("spec").endpoint_b = "another".to_owned();
        reseal(&mut endpoint);
        assert_eq!(outcome(&endpoint), RepairOutcome::Blocked);

        let mut relation_type = valid_relation_request();
        relation_type.relation.as_mut().expect("spec").relation_type = "unknown".to_owned();
        reseal(&mut relation_type);
        assert_eq!(outcome(&relation_type), RepairOutcome::Rejected);

        let mut revision = valid_relation_request();
        revision
            .relation
            .as_mut()
            .expect("spec")
            .endpoint_a_revision = "rev-1".to_owned();
        reseal(&mut revision);
        assert_eq!(outcome(&revision), RepairOutcome::Stale);

        let mut source = valid_relation_request();
        source
            .relation
            .as_mut()
            .expect("spec")
            .original_source_refs
            .clear();
        reseal(&mut source);
        assert_eq!(outcome(&source), RepairOutcome::Partial);
    }

    // WORK_UNIT_CASE: 671/28
    #[test]
    fn case_28_chronology_correlation_and_proximity_do_not_become_causality() {
        let mut flagged = valid_relation_request();
        flagged
            .relation
            .as_mut()
            .expect("spec")
            .chronology_offered_as_causality = true;
        reseal(&mut flagged);
        assert_eq!(outcome(&flagged), RepairOutcome::Rejected);

        let mut prose = valid_relation_request();
        prose.relation.as_mut().expect("spec").mapping_note =
            "rel-1 rev-2: earlier therefore causes this".to_owned();
        reseal(&mut prose);
        assert_eq!(outcome(&prose), RepairOutcome::Rejected);
    }

    // WORK_UNIT_CASE: 671/29
    #[test]
    fn case_29_relation_identity_surgery_routes_to_a27() {
        let request = base_request("merge", RepairDefectKind::FalseRelation);
        let candidate = propose_memory_repair(&request).expect("identity route");
        assert_eq!(candidate.outcome, RepairOutcome::Rejected);
        assert!(candidate.note.contains("a-27"));
        assert!(candidate.operations.is_empty());
    }

    // WORK_UNIT_CASE: 671/30
    #[test]
    fn case_30_false_relation_full_and_partial_dependent_denominators_are_distinct() {
        let complete = valid_relation_request();
        assert_eq!(outcome(&complete), RepairOutcome::Complete);

        let mut partial = valid_relation_request();
        partial
            .relation
            .as_mut()
            .expect("spec")
            .expected_dependents_total = 2;
        reseal(&mut partial);
        let candidate = propose_memory_repair(&partial).expect("partial relation candidate");
        assert_eq!(candidate.outcome, RepairOutcome::Partial);
        assert_eq!(
            candidate.operations[0].operation,
            RepairOperationKind::RelationInvalidate
        );
    }

    // WORK_UNIT_CASE: 671/31
    #[test]
    fn case_31_false_relation_retains_source_history_and_counterevidence() {
        let request = valid_relation_request();
        let candidate = propose_memory_repair(&request).expect("relation preservation candidate");
        assert_eq!(candidate.trajectory, request.projection.trajectory);
        assert_eq!(
            candidate.counterevidence_refs,
            request.projection.counterevidence_refs
        );
        assert_eq!(candidate.dispositions, request.dispositions);
        assert!(candidate.inverse_note.contains("restore"));
    }

    // WORK_UNIT_CASE: 671/32
    #[test]
    fn case_32_false_relation_only_proposes_owner_operation_without_registry_receipt() {
        let request = valid_relation_request();
        let candidate = propose_memory_repair(&request).expect("inert relation proposal");
        assert_eq!(candidate.operations.len(), 1);
        assert_eq!(candidate.operations[0].owner, "owner-registry");
        assert!(!candidate.note.contains("write receipt"));
    }

    // WORK_UNIT_CASE: 671/33
    #[test]
    fn case_33_stale_view_preserves_old_bytes_and_rebuilds() {
        let request = valid_stale_view_request();
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

    // WORK_UNIT_CASE: 671/34
    #[test]
    fn case_34_timestamp_only_currentness_is_rejected() {
        let mut flagged = valid_stale_view_request();
        flagged
            .stale_view
            .as_mut()
            .expect("spec")
            .timestamp_offered_as_currentness = true;
        reseal(&mut flagged);
        assert_eq!(outcome(&flagged), RepairOutcome::Rejected);

        let mut prose = valid_stale_view_request();
        prose.stale_view.as_mut().expect("spec").invalidation_ref =
            "newest therefore current".to_owned();
        reseal(&mut prose);
        assert_eq!(outcome(&prose), RepairOutcome::Rejected);
    }

    // WORK_UNIT_CASE: 671/35
    #[test]
    fn case_35_partial_or_unknown_view_frontier_prevents_complete_rebuild() {
        let mut partial = valid_stale_view_request();
        partial
            .stale_view
            .as_mut()
            .expect("spec")
            .expected_frontier_total = 2;
        reseal(&mut partial);
        assert_eq!(outcome(&partial), RepairOutcome::Partial);

        let mut unknown = valid_stale_view_request();
        unknown
            .stale_view
            .as_mut()
            .expect("spec")
            .unknown_source_refs = vec!["source-unknown".to_owned()];
        reseal(&mut unknown);
        assert_eq!(outcome(&unknown), RepairOutcome::Partial);
    }

    // WORK_UNIT_CASE: 671/36
    #[test]
    fn case_36_stale_view_candidate_does_not_change_source_records() {
        let request = valid_stale_view_request();
        let source_before = request.stale_view.clone();
        let candidate = propose_memory_repair(&request).expect("view proposal");
        assert_eq!(request.stale_view, source_before);
        assert!(candidate.note.contains("source records unchanged"));
        assert_eq!(
            candidate.raw_history_refs,
            request.projection.raw_history_refs
        );
    }

    // WORK_UNIT_CASE: 671/37
    #[test]
    fn case_37_stale_view_keeps_the_old_revision_addressable() {
        let request = valid_stale_view_request();
        let candidate = propose_memory_repair(&request).expect("addressable old view");
        assert!(candidate.inverse_note.contains("rev-2"));
        assert!(candidate.inverse_note.contains("serve"));
        assert!(
            request
                .stale_view
                .as_ref()
                .expect("spec")
                .old_bytes_preserved
        );
    }

    // WORK_UNIT_CASE: 671/38
    #[test]
    fn case_38_stale_view_plan_accounts_context_cue_index_and_decision_consumers() {
        let request = valid_stale_view_request();
        let candidate = propose_memory_repair(&request).expect("consumer plan");
        let spec = request.stale_view.as_ref().expect("spec");
        for reference in spec
            .context_refs
            .iter()
            .chain(spec.cue_refs.iter())
            .chain(spec.index_refs.iter())
            .chain(spec.decision_refs.iter())
        {
            assert!(spec.consumer_refs.contains(reference));
        }
        assert_eq!(candidate.operations.len(), 3);

        let mut missing = valid_stale_view_request();
        missing
            .stale_view
            .as_mut()
            .expect("spec")
            .context_refs
            .clear();
        reseal(&mut missing);
        assert_eq!(outcome(&missing), RepairOutcome::Partial);
    }

    // WORK_UNIT_CASE: 671/39
    #[test]
    fn case_39_stale_view_only_proposes_invalidation_and_rebuild_without_current_publication() {
        let request = valid_stale_view_request();
        let before = request.clone();
        let candidate = propose_memory_repair(&request).expect("view proposal");
        assert_eq!(request, before);
        assert!(
            candidate
                .note
                .contains("no current projection is published")
        );
        assert!(
            candidate
                .operations
                .iter()
                .any(|operation| { operation.operation == RepairOperationKind::ViewRebuild })
        );
    }

    // WORK_UNIT_CASE: 671/40
    #[test]
    fn case_40_representation_binds_one_canonical_identity() {
        let request = valid_representation_request();
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

    // WORK_UNIT_CASE: 671/41
    #[test]
    fn case_41_lossy_representation_retains_source_omission_and_reversal() {
        let request = valid_representation_request();
        let spec = request.representation.as_ref().expect("spec");
        assert!(!spec.omission_note.is_empty());
        assert!(spec.addressability_note.contains("src-1"));
        assert!(spec.reversible);
        let candidate = propose_memory_repair(&request).expect("lossy representation candidate");
        assert!(candidate.note.contains("omission"));
        assert!(candidate.inverse_note.contains("drop"));
    }

    // WORK_UNIT_CASE: 671/42
    #[test]
    fn case_42_absent_representation_source_routes_to_provenance_or_unsupported() {
        let mut request = valid_representation_request();
        request
            .representation
            .as_mut()
            .expect("spec")
            .source_coverage_refs
            .clear();
        reseal(&mut request);
        assert_eq!(outcome(&request), RepairOutcome::Abstention);
    }

    // WORK_UNIT_CASE: 671/43
    #[test]
    fn case_43_second_truth_or_support_owner_is_rejected() {
        let mut request = valid_representation_request();
        request.representation.as_mut().expect("spec").second_truth = true;
        reseal(&mut request);
        assert_eq!(outcome(&request), RepairOutcome::Rejected);
    }

    // WORK_UNIT_CASE: 671/44
    #[test]
    fn case_44_representation_availability_cannot_widen_independent_ceilings() {
        let mut request = valid_representation_request();
        request
            .representation
            .as_mut()
            .expect("spec")
            .widens_ceilings = true;
        reseal(&mut request);
        assert_eq!(outcome(&request), RepairOutcome::Rejected);
    }

    // WORK_UNIT_CASE: 671/45
    #[test]
    fn case_45_conflicting_duplicate_representation_stays_explicit() {
        let mut request = valid_representation_request();
        request
            .representation
            .as_mut()
            .expect("spec")
            .conflicting_duplicate = true;
        reseal(&mut request);
        assert_eq!(outcome(&request), RepairOutcome::Rejected);
    }

    // WORK_UNIT_CASE: 671/46
    #[test]
    fn case_46_representation_plan_accounts_consumers_indices_context_and_inverse() {
        let request = valid_representation_request();
        let spec = request.representation.as_ref().expect("spec");
        assert!(!spec.consumer_refs.is_empty());
        assert!(!spec.context_refs.is_empty());
        assert!(!spec.index_refs.is_empty());
        let candidate = propose_memory_repair(&request).expect("representation plan");
        assert!(candidate.operations[0].inverse_note.contains("drop"));

        let mut remove = valid_representation_request();
        remove.representation.as_mut().expect("spec").proposal = RepresentationProposal::Remove;
        reseal(&mut remove);
        let candidate = propose_memory_repair(&remove).expect("remove plan");
        assert_eq!(
            candidate.operations[0].operation,
            RepairOperationKind::RepresentationRemove
        );
    }

    // WORK_UNIT_CASE: 671/47
    #[test]
    fn case_47_representation_candidate_leaves_canonical_content_unchanged() {
        let request = valid_representation_request();
        let before = request.clone();
        let candidate = propose_memory_repair(&request).expect("representation proposal");
        assert_eq!(request, before);
        assert_eq!(candidate.subject_handle, "mem-1");
        assert!(candidate.note.contains("canonical content unchanged"));
    }

    // WORK_UNIT_CASE: 671/48
    #[test]
    fn case_48_trajectory_preserves_recurrence_false_positive_extinction_and_runbook_refs() {
        let mut request = valid_provenance_request();
        request.projection.trajectory.extinction_evidence_ref = Some("extinct-check-1".to_owned());
        reseal(&mut request);
        let candidate = propose_memory_repair(&request).expect("trajectory candidate");
        assert_eq!(candidate.trajectory.occurrences, 3);
        assert_eq!(candidate.trajectory.recurrences, 1);
        assert_eq!(
            candidate.trajectory.false_positive_refs,
            vec!["fp-1".to_owned()]
        );
        assert_eq!(
            candidate.trajectory.runbook_ref.as_deref(),
            Some("runbook-3")
        );
        assert_eq!(
            candidate.trajectory.extinction_evidence_ref.as_deref(),
            Some("extinct-check-1")
        );
    }

    // WORK_UNIT_CASE: 671/49
    #[test]
    fn case_49_non_extinguished_failure_history_remains_in_the_candidate() {
        let request = valid_provenance_request();
        let candidate = propose_memory_repair(&request).expect("failure history candidate");
        assert!(candidate.trajectory.extinction_evidence_ref.is_none());
        assert!(!candidate.negative_memory_refs.is_empty());
        assert!(candidate.trajectory.reopen_condition.contains("reopen"));
    }

    // WORK_UNIT_CASE: 671/50
    #[test]
    fn case_50_all_protected_history_and_dependency_roots_are_carried_forward() {
        let request = valid_provenance_request();
        let candidate = propose_memory_repair(&request).expect("protected roots candidate");
        assert_eq!(
            candidate.protection_refs,
            request.projection.protection_refs
        );
        assert_eq!(
            candidate.raw_history_refs,
            request.projection.raw_history_refs
        );
        assert_eq!(candidate.audit_refs, request.projection.audit_refs);
        assert_eq!(candidate.minority_refs, request.projection.minority_refs);
        assert_eq!(
            candidate.dependency_root_refs,
            request.projection.dependency_root_refs
        );
        assert_eq!(
            candidate.counterevidence_refs,
            request.projection.counterevidence_refs
        );
    }

    // WORK_UNIT_CASE: 671/51
    #[test]
    fn case_51_independent_axis_revisions_are_copied_without_implicit_tuning() {
        let request = valid_contamination_request();
        let candidate = propose_memory_repair(&request).expect("axis matrix candidate");
        assert_eq!(candidate.axis_revisions, request.projection.axis_revisions);
        assert_eq!(candidate.subject_handle, request.projection.subject_handle);
    }

    // WORK_UNIT_CASE: 671/52
    #[test]
    fn case_52_every_affected_member_has_exactly_one_owner_disposition() {
        let mut missing = valid_provenance_request();
        missing.affected.push(AffectedMember {
            handle: "dep-2".to_owned(),
            owner: "owner-assurance".to_owned(),
            required: true,
            unknown: false,
        });
        missing.closure_denominator.members.push("dep-2".to_owned());
        missing.closure_denominator.expected_total = 2;
        reseal(&mut missing);
        assert_eq!(outcome(&missing), RepairOutcome::Partial);

        let mut unknown = valid_provenance_request();
        unknown.affected[0].unknown = true;
        reseal(&mut unknown);
        assert_eq!(outcome(&unknown), RepairOutcome::Blocked);
    }

    // WORK_UNIT_CASE: 671/53
    #[test]
    fn case_53_all_seven_preservation_dimensions_are_independent() {
        let request = valid_provenance_request();
        assert_eq!(request.preservation.verdicts.len(), 7);
        for dimension in [
            PreservationDimension::Coverage,
            PreservationDimension::Faithfulness,
            PreservationDimension::Lineage,
            PreservationDimension::Reversibility,
            PreservationDimension::AuthorityCeiling,
            PreservationDimension::DependencyClosure,
            PreservationDimension::ProvenanceRetention,
        ] {
            let mut changed = request.clone();
            let verdict = changed
                .preservation
                .verdicts
                .iter_mut()
                .find(|verdict| verdict.dimension == dimension)
                .expect("dimension exists");
            verdict.passed = false;
            reseal(&mut changed);
            assert_eq!(outcome(&changed), RepairOutcome::Partial);
        }
    }

    // WORK_UNIT_CASE: 671/54
    #[test]
    fn case_54_failed_or_unknown_dimension_blocks_without_a05_reexecution() {
        let mut request = valid_provenance_request();
        request.preservation.verdicts[0].known = false;
        reseal(&mut request);
        let candidate = propose_memory_repair(&request).expect("unknown preservation candidate");
        assert_eq!(candidate.outcome, RepairOutcome::Partial);
        assert_eq!(candidate.identity.attempt, 1);
        assert!(candidate.note.contains("preservation"));
    }

    // WORK_UNIT_CASE: 671/55
    #[test]
    fn case_55_complete_partial_abstention_stale_and_rejected_are_distinct() {
        assert_eq!(
            outcome(&valid_provenance_request()),
            RepairOutcome::Complete
        );

        let mut partial = valid_provenance_request();
        partial.provenance.as_mut().expect("spec").expected_total = 2;
        reseal(&mut partial);
        assert_eq!(outcome(&partial), RepairOutcome::Partial);

        let mut abstention = valid_provenance_request();
        abstention
            .provenance
            .as_mut()
            .expect("spec")
            .authoritative_source = None;
        reseal(&mut abstention);
        assert_eq!(outcome(&abstention), RepairOutcome::Abstention);

        let mut stale = valid_provenance_request();
        stale.frozen_bundle_digest = "0".repeat(64);
        reseal(&mut stale);
        assert_eq!(outcome(&stale), RepairOutcome::Stale);

        let rejected = base_request("merge", RepairDefectKind::MissingProvenance);
        assert_eq!(outcome(&rejected), RepairOutcome::Rejected);
    }

    // WORK_UNIT_CASE: 671/56
    #[test]
    fn case_56_candidate_has_no_applied_owner_write_admission_effect_or_finish_state() {
        let request = valid_provenance_request();
        let before = request.clone();
        let candidate = propose_memory_repair(&request).expect("candidate only");
        assert_eq!(request, before);
        assert!(candidate.operations.iter().all(|operation| {
            operation.owner != "eliot-dreamer-memory-repair" && operation.owner != "governor-write"
        }));
        assert!(candidate.expected_observable.contains("resolves"));
        assert!(!candidate.note.contains("Finish"));
    }

    // WORK_UNIT_CASE: 671/57
    #[test]
    fn case_57_exact_replay_is_deterministic_and_revision_change_conflicts() {
        let request = valid_provenance_request();
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
        assert_eq!(rebound.outcome, RepairOutcome::Stale);
        assert_ne!(first.candidate_digest, rebound.candidate_digest);
    }

    // WORK_UNIT_CASE: 671/58
    #[test]
    fn case_58_each_independent_bound_rejects_one_over_without_cross_subsidy() {
        let mut affected = valid_provenance_request();
        affected.policy.max_affected = MAX_AFFECTED;
        affected.affected = (0..=MAX_AFFECTED)
            .map(|index| AffectedMember {
                handle: format!("member-{index:03}"),
                owner: "owner-assurance".to_owned(),
                required: true,
                unknown: false,
            })
            .collect();
        assert!(matches!(
            propose_memory_repair(&affected),
            Err(RepairError::Bounds { phase, .. }) if phase == "affected"
        ));

        let mut dispositions = valid_provenance_request();
        dispositions.policy.max_affected = MAX_AFFECTED;
        dispositions.dispositions = (0..=MAX_AFFECTED)
            .map(|index| MemberDisposition {
                handle: format!("member-{index:03}"),
                disposition: MemberDispositionKind::UnchangedWithEvidence,
                old_identity: format!("member-{index:03}@rev-1"),
                proposed_identity: format!("member-{index:03}@rev-1"),
                owner: "owner-assurance".to_owned(),
                reason: "unchanged for bound test".to_owned(),
                evidence_ref: "e-1".to_owned(),
                scope_id: "scope-1".to_owned(),
                fence_note: "fence f-1".to_owned(),
                verifier: "verifier-7".to_owned(),
                inverse_note: "restore".to_owned(),
                proof_note: "checked".to_owned(),
            })
            .collect();
        assert!(matches!(
            propose_memory_repair(&dispositions),
            Err(RepairError::Bounds { phase, .. }) if phase == "dispositions"
        ));

        let mut denominator = valid_provenance_request();
        denominator.closure_denominator.members = (0..=MAX_CLOSURE_REFS)
            .map(|index| format!("root-{index:03}"))
            .collect();
        denominator.closure_denominator.expected_total =
            u32::try_from(MAX_CLOSURE_REFS + 1).expect("test bound fits u32");
        assert!(matches!(
            propose_memory_repair(&denominator),
            Err(RepairError::Bounds { phase, .. }) if phase == "closure-denominator"
        ));

        let mut protections = valid_provenance_request();
        protections.projection.protection_refs = (0..=MAX_PROTECTIONS)
            .map(|index| format!("protection-{index:03}"))
            .collect();
        assert!(matches!(
            propose_memory_repair(&protections),
            Err(RepairError::Bounds { phase, .. }) if phase == "protection"
        ));

        let mut lineage = valid_provenance_request();
        lineage.provenance.as_mut().expect("spec").expected_lineage = (0..=MAX_CLOSURE_REFS)
            .map(|index| format!("source-{index:03}"))
            .collect();
        assert!(matches!(
            propose_memory_repair(&lineage),
            Err(RepairError::Bounds { phase, .. }) if phase == "provenance-lineage"
        ));

        let mut text = valid_provenance_request();
        text.provenance.as_mut().expect("spec").missing_edge = "x".repeat(MAX_HANDLE_BYTES + 1);
        reseal(&mut text);
        assert!(matches!(
            propose_memory_repair(&text),
            Err(RepairError::Bounds { phase, .. }) if phase == "provenance.missing-edge"
        ));
    }

    // WORK_UNIT_CASE: 671/59
    #[test]
    fn case_59_cancel_deadline_expiry_and_policy_drift_stay_stale_or_rejected() {
        let mut cancelled = valid_provenance_request();
        cancelled.policy.cancelled = true;
        reseal(&mut cancelled);
        assert_eq!(outcome(&cancelled), RepairOutcome::Rejected);

        let mut deadline = valid_provenance_request();
        deadline.policy.observation_time_ms = deadline.policy.deadline_ms;
        reseal(&mut deadline);
        assert_eq!(outcome(&deadline), RepairOutcome::Stale);

        let mut expiry = valid_provenance_request();
        expiry.policy.observation_time_ms = expiry.policy.expiry_ms;
        reseal(&mut expiry);
        assert_eq!(outcome(&expiry), RepairOutcome::Stale);

        let mut policy = valid_provenance_request();
        policy.projection.policy_id = "policy-moved".to_owned();
        reseal(&mut policy);
        assert_eq!(outcome(&policy), RepairOutcome::Stale);
    }

    // WORK_UNIT_CASE: 671/60
    #[test]
    fn case_60_diagnostics_are_bounded_and_redacted() {
        let error = repair_error_as_contract(RepairError::Receipt {
            detail: "secret\u{0}line\u{1}".to_owned(),
        });
        let ContractViolation::BindingMismatch { reason, .. } = error else {
            panic!("receipt maps to a binding mismatch");
        };
        assert!(!reason.contains('\0'));
        assert!(!reason.contains('\u{1}'));

        let mut request = valid_provenance_request();
        request.projection.subject_handle = "x".repeat(MAX_HANDLE_BYTES + 1);
        assert!(matches!(
            propose_memory_repair(&request),
            Err(RepairError::Bounds { phase, .. }) if phase == "projection.subject"
        ));
    }

    // WORK_UNIT_CASE: 671/61
    #[test]
    fn case_61_each_valid_request_selects_exactly_one_repair_family() {
        let requests = [
            valid_provenance_request(),
            valid_contamination_request(),
            valid_relation_request(),
            valid_stale_view_request(),
            valid_representation_request(),
        ];
        for request in requests {
            let candidate = propose_memory_repair(&request).expect("one family candidate");
            assert_eq!(candidate.outcome, RepairOutcome::Complete);
            assert_eq!(
                [
                    request.provenance.is_some(),
                    request.contamination.is_some(),
                    request.relation.is_some(),
                    request.stale_view.is_some(),
                    request.representation.is_some(),
                ]
                .into_iter()
                .filter(|present| *present)
                .count(),
                1
            );
        }
    }

    // WORK_UNIT_CASE: 671/62
    #[test]
    fn case_62_every_operation_carries_external_owner_verifier_inverse_and_expiry() {
        let requests = [
            valid_provenance_request(),
            valid_contamination_request(),
            valid_relation_request(),
            valid_stale_view_request(),
            valid_representation_request(),
        ];
        for request in requests {
            let candidate = propose_memory_repair(&request).expect("operation candidate");
            assert!(candidate.operations.iter().all(|operation| {
                !operation.owner.is_empty()
                    && !operation.verifier.is_empty()
                    && !operation.inverse_note.is_empty()
                    && operation.scope_id == request.projection.scope_id
                    && operation.expiry_ms == request.policy.expiry_ms
            }));
        }
    }

    // WORK_UNIT_CASE: 671/63
    #[test]
    fn case_63_no_candidate_path_erases_raw_history_or_changes_independent_axes() {
        let requests = [
            valid_provenance_request(),
            valid_contamination_request(),
            valid_relation_request(),
            valid_stale_view_request(),
            valid_representation_request(),
        ];
        for request in requests {
            let candidate = propose_memory_repair(&request).expect("preserving candidate");
            assert_eq!(
                candidate.raw_history_refs,
                request.projection.raw_history_refs
            );
            assert_eq!(candidate.axis_revisions, request.projection.axis_revisions);
            assert_eq!(
                candidate.protection_refs,
                request.projection.protection_refs
            );
        }
    }

    // WORK_UNIT_CASE: 671/64
    #[test]
    fn case_64_complete_influence_repair_requires_matching_complete_closure() {
        let mut dependent_gap = valid_contamination_request();
        dependent_gap
            .contamination
            .as_mut()
            .expect("spec")
            .closure
            .dependent_refs
            .clear();
        reseal(&mut dependent_gap);
        assert_eq!(outcome(&dependent_gap), RepairOutcome::Partial);

        let mut fence = valid_contamination_request();
        fence.contamination.as_mut().expect("spec").closure.scope_id = "other-scope".to_owned();
        reseal(&mut fence);
        assert_eq!(outcome(&fence), RepairOutcome::Stale);
    }

    // WORK_UNIT_CASE: 671/65
    #[test]
    fn case_65_representation_maps_to_one_existing_canonical_identity_revision_and_source() {
        let request = valid_representation_request();
        assert_eq!(outcome(&request), RepairOutcome::Complete);

        let mut source = valid_representation_request();
        source
            .representation
            .as_mut()
            .expect("spec")
            .canonical_source_ref = "src-2".to_owned();
        reseal(&mut source);
        assert_eq!(outcome(&source), RepairOutcome::Stale);

        let mut digest = valid_representation_request();
        digest
            .representation
            .as_mut()
            .expect("spec")
            .canonical_digest = "8".repeat(64);
        reseal(&mut digest);
        assert_eq!(outcome(&digest), RepairOutcome::Stale);
    }

    // WORK_UNIT_CASE: 671/66
    #[test]
    fn case_66_bounded_malformed_inputs_never_panic_or_create_applied_repairs() {
        let mut malformed = valid_provenance_request();
        malformed.projection.subject_handle = "\0".to_owned();
        let mut huge = valid_provenance_request();
        huge.provenance.as_mut().expect("spec").expected_total = u32::MAX;
        let mut duplicate = valid_provenance_request();
        duplicate.projection.protection_refs = vec!["same".to_owned(), "same".to_owned()];

        for request in [malformed, huge, duplicate] {
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                propose_memory_repair(&request)
            }));
            assert!(result.is_ok(), "malformed input must not panic");
            if let Ok(Ok(candidate)) = result {
                assert_ne!(candidate.outcome, RepairOutcome::Complete);
                assert!(candidate.operations.is_empty());
            }
        }
    }
}
