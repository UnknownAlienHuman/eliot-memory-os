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

use eliot_contracts::{StateFence, canonical_json_bytes, sha256_hex};
use eliot_dreamer_contracts::curation::{CurationPayload, ReconsolidationPayload};
use eliot_dreamer_contracts::{
    BoundCurationCall, CandidateDisposition, ContractViolation, CurationFamily,
    CurationHandlerDescriptor, CurationHandlerPort, CurationKind, CurationRejectionCode,
    GroundedDreamDraft, NativeCurationHandler, PreservationReport, ProducedCurationContent,
    Requester, TargetDenominator, ValidatedCurationItem, ValidationReceipt,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Independent bounds (no cross-subsidy between dimensions).
// ---------------------------------------------------------------------------

/// Maximum parent propositions admitted in one request.
pub const MAX_PARENT_PROPOSITIONS: usize = 64;
/// Maximum semantic field paths carried by one request.
pub const MAX_FIELDS: usize = 128;
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
/// Maximum output bytes for one inert child-allocation request.
pub const MAX_OUTPUT_BYTES: usize = 256 * 1024;
/// Maximum independent STU usage admitted by this leaf.
pub const MAX_STU: u64 = 65_536;
/// Maximum bounded work units admitted by this leaf.
pub const MAX_WORK_UNITS: u64 = 65_536;
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

fn contains_baseline_pair(
    handles: &[String],
    lineages: &[String],
    support_handle: &str,
    lineage: &str,
) -> bool {
    handles
        .iter()
        .zip(lineages)
        .any(|(baseline_handle, baseline_lineage)| {
            baseline_handle == support_handle && baseline_lineage == lineage
        })
}

fn baseline_index(
    handles: &[String],
    lineages: &[String],
    handle: &str,
    lineage: &str,
) -> Option<usize> {
    handles
        .iter()
        .zip(lineages)
        .position(|(baseline_handle, baseline_lineage)| {
            baseline_handle == handle && baseline_lineage == lineage
        })
}

#[allow(clippy::too_many_arguments)]
fn contains_baseline_record(
    handles: &[String],
    lineages: &[String],
    revisions: &[String],
    digests: &[String],
    handle: &str,
    lineage: &str,
    revision: &str,
    digest: &str,
) -> bool {
    handles
        .iter()
        .zip(lineages)
        .zip(revisions)
        .zip(digests)
        .any(
            |(((baseline_handle, baseline_lineage), baseline_revision), baseline_digest)| {
                baseline_handle == handle
                    && baseline_lineage == lineage
                    && baseline_revision == revision
                    && baseline_digest == digest
            },
        )
}

fn same_sorted_set(left: &[String], right: &[String]) -> bool {
    let mut left = left.to_vec();
    let mut right = right.to_vec();
    left.sort();
    right.sort();
    left == right
}

fn has_repeated_handle(values: &[String]) -> bool {
    values
        .iter()
        .enumerate()
        .any(|(index, value)| values[..index].iter().any(|previous| previous == value))
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

/// Observable reactivation checkpoint.  A later checkpoint includes the
/// evidence of the earlier stages, but a delivery or acknowledgement alone is
/// never promoted to public use.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
pub enum ReactivationStage {
    /// A record was available to a route, without proof it was retrieved.
    Availability,
    /// The exact record was retrieved.
    Retrieval,
    /// The record was expanded into an observed context.
    Expansion,
    /// The context was delivered to an external consumer.
    Delivery,
    /// The consumer acknowledged the delivered context.
    Acknowledgement,
    /// A governed public use or verifier-relevant action was observed.
    QualifyingPublicUse,
}

/// Whether a new item has an independent observation owner and source.
///
/// A caller may report a shared or unknown source, but this leaf can admit
/// only an explicitly independent observation as material new evidence.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
pub enum EvidenceIndependence {
    Independent,
    SharedSource,
    DerivedFromParent,
    Unknown,
}

impl ReactivationStage {
    const fn rank(self) -> u8 {
        match self {
            Self::Availability => 0,
            Self::Retrieval => 1,
            Self::Expansion => 2,
            Self::Delivery => 3,
            Self::Acknowledgement => 4,
            Self::QualifyingPublicUse => 5,
        }
    }
}

/// Operation/request identity supplied by the A-03 envelope and the
/// reactivation owner.  The digest binds the fields that affect replay and
/// scope; a caller may not silently change one field under an existing ID.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RequestIdentity {
    /// Stable request identity.
    pub request_id: String,
    /// Canonical operation identity.
    pub operation_id: String,
    /// Idempotency namespace/key for this candidate request.
    pub idempotency_key: String,
    /// Authenticated requester carried from intake.
    pub requester: Requester,
    /// Task and attempt that own the proposal.
    pub task_id: String,
    /// Exact Dreamer attempt identity.
    pub attempt_id: String,
    /// Expected external observation actor and route bindings.
    pub actor: String,
    pub route: String,
    pub context_id: String,
    pub session_id: String,
    pub query: String,
    pub recipe: String,
    pub snapshot: String,
    /// Governing scope.
    pub scope_id: String,
    /// State fence captured before observation.
    pub state_fence: StateFence,
    /// Digest of the canonical fields above, supplied by the caller.
    pub canonical_request_digest: String,
}

impl RequestIdentity {
    fn computed_digest(&self) -> Result<String, ReconsolidationError> {
        #[derive(Serialize)]
        struct Preimage<'a> {
            request_id: &'a str,
            operation_id: &'a str,
            idempotency_key: &'a str,
            requester: &'a Requester,
            task_id: &'a str,
            attempt_id: &'a str,
            actor: &'a str,
            route: &'a str,
            context_id: &'a str,
            session_id: &'a str,
            query: &'a str,
            recipe: &'a str,
            snapshot: &'a str,
            scope_id: &'a str,
            state_fence: &'a StateFence,
        }
        let preimage = Preimage {
            request_id: &self.request_id,
            operation_id: &self.operation_id,
            idempotency_key: &self.idempotency_key,
            requester: &self.requester,
            task_id: &self.task_id,
            attempt_id: &self.attempt_id,
            actor: &self.actor,
            route: &self.route,
            context_id: &self.context_id,
            session_id: &self.session_id,
            query: &self.query,
            recipe: &self.recipe,
            snapshot: &self.snapshot,
            scope_id: &self.scope_id,
            state_fence: &self.state_fence,
        };
        let bytes =
            canonical_json_bytes(&preimage).map_err(|err| ReconsolidationError::Malformed {
                phase: "request_identity".to_owned(),
                detail: redact(&err.to_string()),
            })?;
        Ok(sha256_hex(&bytes))
    }
}

/// Exact externally observable identity bound to the reactivation receipt.
/// Every field is explicit so missing instrumentation remains unknown.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ReactivationBinding {
    /// Operation that owned the observation.
    pub operation_id: String,
    /// Owner-issued receipt for the observation.
    pub owner_receipt: String,
    /// Record handle and revision actually observed.
    pub record_handle: String,
    pub record_revision: String,
    /// Task and attempt that produced the observation.
    pub task_id: String,
    pub attempt_id: String,
    /// External actor, route, context and session identities.
    pub actor: String,
    pub route: String,
    pub context_id: String,
    pub session_id: String,
    /// Query, recipe and source snapshot identities.
    pub query: String,
    pub recipe: String,
    pub snapshot: String,
    /// Fence and complete observation denominator.
    pub state_fence: StateFence,
    pub observation_denominator: TargetDenominator,
}

/// Policy independently bounds the reconsolidation proposal and declares the
/// minimum reactivation checkpoint.  These are ceilings only; this crate never
/// widens an axis or executes a policy transition.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ReconsolidationPolicy {
    /// Governing policy identity; must bind the receipt and reactivation.
    pub policy_id: String,
    /// Minimum observable checkpoint accepted for reactivation.
    pub minimum_reactivation_stage: ReactivationStage,
    /// Whether a non-load-bearing unresolved residue may be returned.
    pub allow_partial: bool,
    /// Independent cardinality and output ceilings.
    pub max_parent_propositions: usize,
    pub max_fields: usize,
    pub max_new_items: usize,
    pub max_dependents: usize,
    pub max_predecessors: usize,
    pub max_baseline_refs: usize,
    pub max_total_bytes: usize,
    pub max_output_bytes: usize,
    pub max_work_units: u64,
    pub max_stu: u64,
    /// Explicit caller-supplied STU usage; never inferred from wall-clock or bytes.
    pub observed_stu: u64,
    /// Ceilings carried by the candidate and preserved verbatim.
    pub source_assurance_ceiling: String,
    pub authority_ceiling: String,
    pub privacy_ceiling: String,
    pub influence_ceiling: String,
    pub proof_ceiling: String,
    /// Cancellation and frozen timing state.
    pub cancelled: bool,
    pub observation_time_ms: Option<u64>,
    pub deadline_ms: Option<u64>,
}

/// One new proposition is accounted separately from the parent proposition
/// denominator.  It cannot be smuggled into a parent delta.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AddedProposition {
    pub id: String,
    pub statement: String,
    pub lineage: String,
    pub evidence_refs: Vec<String>,
}

/// A child proposition carried in the inert allocation request.  It is a
/// projection for admission checks, never a canonical revision.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ChildProposition {
    pub id: String,
    pub statement: String,
    pub lineage: String,
    pub support_handle: String,
    /// Supporting source revision retained with the child projection.
    pub support_revision: String,
    /// Supporting source digest retained with the child projection.
    pub support_digest: String,
    pub evidence_refs: Vec<String>,
    pub parent_proposition_id: Option<String>,
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

/// Whether an external dependent effect has an observable terminal state.
///
/// An unknown effect is never treated as a failed write or as a safe rollback
/// opportunity. This leaf can only propose before effects are attempted.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
pub enum EffectObservation {
    /// No dependent or external effect has been attempted.
    NotAttempted,
    /// An effect was observed as applied; this candidate cannot disposition it.
    Applied,
    /// The effect outcome is unknown and requires reconciliation before retry.
    Unknown,
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
    /// Parent schema identity, frozen with the current projection.
    pub schema: String,
    /// Current parent revision identity.
    pub revision: String,
    /// Canonical digest of the exact current parent projection.
    pub digest: String,
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
    /// Canonical revision of the supporting source record.
    pub support_revision: String,
    /// Canonical digest of the supporting source record.
    pub support_digest: String,
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
    /// Owner of the observed source record.
    pub owner: String,
    /// Frozen source manifest that produced the observation.
    pub source_manifest_digest: String,
    /// Source revision that produced the evidence bytes.
    pub source_revision: String,
    /// Scope in which the evidence was observed.
    pub scope: String,
    /// Authority ceiling under which the source was observed.
    pub authority: String,
    /// Privacy ceiling under which the source was observed.
    pub privacy: String,
    /// Independence classification; shared or unknown material is not new.
    pub independence: EvidenceIndependence,
    /// Sorted parent/addition/dependent identities covered by this item.
    pub coverage: Vec<String>,
    /// Source-assurance reference, bounded by the request policy.
    pub assurance: String,
    /// Evidence statement or outcome text.
    pub statement: String,
    /// Source class; only external observation can be material.
    pub source_kind: EvidenceSourceKind,
    /// Explicit observation time; unknown time is never filled in.
    pub observed_at_ms: Option<u64>,
    /// Source freshness cursor; it must bind exactly to `observed_at_ms`.
    pub freshness_ms: Option<u64>,
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
    /// Strongest independently observed checkpoint.
    pub stage: ReactivationStage,
    /// True only for a complete observation at the exact checkpoint.
    pub exact_match: bool,
    /// Explicit observation time; unknown time is never filled in.
    pub observed_at_ms: Option<u64>,
    /// Exact operation/record/route/fence binding for the observation.
    pub binding: ReactivationBinding,
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
    /// Exact old dependent identity before the candidate.
    pub old_identity: String,
    /// Immutable source identity used by the dependent.
    pub source_identity: String,
    /// Owner responsible for the dependent.
    pub owner: String,
    /// Verifier assigned to the dependent's candidate disposition.
    pub verifier: String,
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
    /// Exact old dependent identity being disposed.
    pub old_identity: String,
    /// Immutable source identity used by the dependent.
    pub source_identity: String,
    /// Exact proposed child identity being considered.
    pub new_candidate_identity: String,
    /// Owner responsible for the dependent disposition.
    pub owner: String,
    /// Verifier that will check the dependent against the candidate.
    pub verifier: String,
    /// Inverse action that can set the dependent aside before effects.
    pub inverse_note: String,
    /// Forward correction required if the later write or verification fails.
    pub forward_correction: String,
    /// Observed effect state; unknown/applied states cannot be retried blindly.
    pub effect_status: EffectObservation,
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

/// Source contract bindings retained with the inert child request.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PreservedSourceBinding {
    pub handle: String,
    pub manifest_digest: String,
    pub scope: String,
    pub authority: String,
    pub privacy: String,
    pub freshness_ms: Option<u64>,
}

#[derive(Serialize)]
struct ChildDigestPreimage<'a> {
    identity_digest: &'a str,
    parent_handle: &'a str,
    parent_schema: &'a str,
    parent_revision: &'a str,
    parent_digest: &'a str,
    propositions: &'a [ChildProposition],
    preserved_revision_history: &'a [String],
    preserved_source_refs: &'a [String],
    preserved_source_identities: &'a [String],
    preserved_source_bindings: &'a [PreservedSourceBinding],
    field_paths: &'a [String],
    axis_owners: &'a AxisOwnerRefs,
    source_assurance_ceiling: &'a str,
    authority_ceiling: &'a str,
    privacy_ceiling: &'a str,
    influence_ceiling: &'a str,
    proof_ceiling: &'a str,
}

/// External child-allocation request. Requests only; issues nothing.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ChildAllocationRequest {
    /// Parent handle the child would revise.
    pub parent_handle: String,
    /// Parent schema identity retained in the allocation request.
    pub parent_schema: String,
    /// Parent revision the child would extend.
    pub parent_revision: String,
    /// Parent projection digest retained in the allocation request.
    pub parent_digest: String,
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
    /// Child proposition projection used by the external owner for admission.
    pub propositions: Vec<ChildProposition>,
    /// Immutable parent/prior revision handles retained for reopening.
    pub preserved_revision_history: Vec<String>,
    /// Raw/source/evidence handles retained without rewriting or deletion.
    pub preserved_source_refs: Vec<String>,
    /// Canonical source identities retained without rewriting or deletion.
    pub preserved_source_identities: Vec<String>,
    /// Manifest/scope/authority/privacy/freshness bindings retained verbatim.
    pub preserved_source_bindings: Vec<PreservedSourceBinding>,
    /// Exact semantic field paths covered by the candidate.
    pub field_paths: Vec<String>,
    /// Independent axis owners copied verbatim from the request.
    pub axis_owners: AxisOwnerRefs,
    /// Support/authority/privacy/influence/proof ceilings copied verbatim.
    pub source_assurance_ceiling: String,
    pub authority_ceiling: String,
    pub privacy_ceiling: String,
    pub influence_ceiling: String,
    pub proof_ceiling: String,
    /// Digest binding request identity and the exact candidate projection.
    pub request_digest: String,
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
            Self::Proposition { id, detail } => {
                write!(f, "proposition[{}]: {}", redact(id), redact(detail))
            }
            Self::Source { handle, detail } => {
                write!(f, "source[{}]: {}", redact(handle), redact(detail))
            }
            Self::Dependent { handle, detail } => {
                write!(f, "dependent[{}]: {}", redact(handle), redact(detail))
            }
            Self::Malformed { phase, detail } => {
                write!(f, "malformed[{}]: {}", redact(phase), redact(detail))
            }
            Self::Bounds { phase, detail } => {
                write!(f, "bounds[{}]: {}", redact(phase), redact(detail))
            }
            Self::Order { phase, detail } => {
                write!(f, "order[{}]: {}", redact(phase), redact(detail))
            }
            Self::Receipt { detail } => write!(f, "receipt: {}", redact(detail)),
            Self::Preservation { detail } => write!(f, "preservation: {}", redact(detail)),
            Self::Denominator { detail } => write!(f, "denominator: {}", redact(detail)),
        }
    }
}

impl core::error::Error for ReconsolidationError {}

/// Full immutable input for one reconsolidation proposal.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ReconsolidationRequest {
    /// Validator-bound A-03 item; its receipt is the authoritative accepted
    /// envelope for this pure handler.
    pub item: ValidatedCurationItem,
    /// Grounded draft whose residues remain addressable through the proposal.
    pub grounded: GroundedDreamDraft,
    /// Frozen bundle and manifest identities supplied by the caller.
    pub frozen_bundle_digest: String,
    pub frozen_manifest_digest: String,
    /// Request/operation/idempotency identity used for replay binding.
    pub identity: RequestIdentity,
    /// Curation kind; must be reconsolidation.
    pub curation_kind: CurationKind,
    /// Current derived parent.
    pub parent: ParentRevision,
    /// Accepted parent propositions (sorted by id, unique).
    pub parent_propositions: Vec<ParentProposition>,
    /// One delta per parent proposition (sorted by proposition id).
    pub deltas: Vec<PropositionDelta>,
    /// Exact semantic field paths covered by the candidate, sorted and unique.
    pub field_paths: Vec<String>,
    /// Candidate new evidence items (sorted by handle, unique).
    pub new_items: Vec<NewEvidenceItem>,
    /// New propositions are accounted independently from parent deltas.
    pub added_propositions: Vec<AddedProposition>,
    /// Denominator covering exactly `added_propositions`.
    pub added_member_denominator: TargetDenominator,
    /// Baseline handles the parent already covers (sorted, unique), positionally
    /// paired with [`Self::parent_baseline_lineages`].
    pub parent_baseline_handles: Vec<String>,
    /// Baseline lineages the parent already covers (sorted, unique), positionally
    /// paired with [`Self::parent_baseline_handles`].
    pub parent_baseline_lineages: Vec<String>,
    /// Canonical source revisions paired with the baseline handles/lineages.
    pub parent_baseline_revisions: Vec<String>,
    /// Canonical source digests paired with the baseline handles/lineages.
    pub parent_baseline_digests: Vec<String>,
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
    /// Independent policy, bounds, cancellation and ceiling binding.
    pub policy: ReconsolidationPolicy,
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

fn check_digest(value: &str, field: &str) -> Result<(), ReconsolidationError> {
    if !is_hex64_lower(value) {
        return Err(ReconsolidationError::Malformed {
            phase: field.to_owned(),
            detail: "digest must be 64 lowercase hex".to_owned(),
        });
    }
    Ok(())
}

fn check_state_fence(value: &StateFence, field: &str) -> Result<(), ReconsolidationError> {
    value
        .validate()
        .map_err(|err| ReconsolidationError::Malformed {
            phase: field.to_owned(),
            detail: redact(&err.to_string()),
        })
}

fn validate_policy_shape(request: &ReconsolidationRequest) -> Result<(), ReconsolidationError> {
    check_handle(&request.policy_id, "policy")?;
    check_handle(&request.policy.policy_id, "policy.id")?;
    if request.policy.policy_id != request.policy_id {
        return Err(ReconsolidationError::Malformed {
            phase: "policy".to_owned(),
            detail: "request and policy identities differ".to_owned(),
        });
    }
    for (field, value) in [
        (
            "policy.source_assurance_ceiling",
            &request.policy.source_assurance_ceiling,
        ),
        (
            "policy.authority_ceiling",
            &request.policy.authority_ceiling,
        ),
        ("policy.privacy_ceiling", &request.policy.privacy_ceiling),
        (
            "policy.influence_ceiling",
            &request.policy.influence_ceiling,
        ),
        ("policy.proof_ceiling", &request.policy.proof_ceiling),
    ] {
        check_bounded_text(value, field, MAX_TEXT_BYTES)?;
    }
    for (field, value) in [
        (
            "policy.max_parent_propositions",
            request.policy.max_parent_propositions,
        ),
        ("policy.max_fields", request.policy.max_fields),
        ("policy.max_new_items", request.policy.max_new_items),
        ("policy.max_dependents", request.policy.max_dependents),
        ("policy.max_predecessors", request.policy.max_predecessors),
        ("policy.max_baseline_refs", request.policy.max_baseline_refs),
        ("policy.max_total_bytes", request.policy.max_total_bytes),
        ("policy.max_output_bytes", request.policy.max_output_bytes),
    ] {
        if value == 0 {
            return Err(ReconsolidationError::Bounds {
                phase: field.to_owned(),
                detail: "policy ceiling must be positive".to_owned(),
            });
        }
    }
    if request.policy.max_work_units == 0 {
        return Err(ReconsolidationError::Bounds {
            phase: "policy.max_work_units".to_owned(),
            detail: "policy work ceiling must be positive".to_owned(),
        });
    }
    if request.policy.max_stu == 0 {
        return Err(ReconsolidationError::Bounds {
            phase: "policy.max_stu".to_owned(),
            detail: "policy STU ceiling must be positive".to_owned(),
        });
    }
    Ok(())
}

fn validate_identity_shape(identity: &RequestIdentity) -> Result<(), ReconsolidationError> {
    for (field, value) in [
        ("identity.request_id", &identity.request_id),
        ("identity.operation_id", &identity.operation_id),
        ("identity.idempotency_key", &identity.idempotency_key),
        ("identity.task_id", &identity.task_id),
        ("identity.attempt_id", &identity.attempt_id),
        ("identity.actor", &identity.actor),
        ("identity.route", &identity.route),
        ("identity.context_id", &identity.context_id),
        ("identity.session_id", &identity.session_id),
        ("identity.query", &identity.query),
        ("identity.recipe", &identity.recipe),
        ("identity.snapshot", &identity.snapshot),
        ("identity.scope_id", &identity.scope_id),
    ] {
        check_handle(value, field)?;
    }
    identity
        .requester
        .validate()
        .map_err(|err| ReconsolidationError::Malformed {
            phase: "identity.requester".to_owned(),
            detail: redact(&err.to_string()),
        })?;
    check_digest(
        &identity.canonical_request_digest,
        "identity.canonical_request_digest",
    )?;
    check_state_fence(&identity.state_fence, "identity.state_fence")
}

fn validate_reactivation_binding(
    reactivation: &ReactivationEvidence,
) -> Result<(), ReconsolidationError> {
    let binding = &reactivation.binding;
    for (field, value) in [
        ("reactivation.operation", &binding.operation_id),
        ("reactivation.owner_receipt", &binding.owner_receipt),
        ("reactivation.record_handle", &binding.record_handle),
        ("reactivation.record_revision", &binding.record_revision),
        ("reactivation.task", &binding.task_id),
        ("reactivation.attempt", &binding.attempt_id),
        ("reactivation.actor", &binding.actor),
        ("reactivation.route", &binding.route),
        ("reactivation.context", &binding.context_id),
        ("reactivation.session", &binding.session_id),
        ("reactivation.query", &binding.query),
        ("reactivation.recipe", &binding.recipe),
        ("reactivation.snapshot", &binding.snapshot),
    ] {
        check_bounded_text(value, field, MAX_HANDLE_BYTES)?;
    }
    check_state_fence(&binding.state_fence, "reactivation.state_fence")?;
    binding
        .observation_denominator
        .validate()
        .map_err(|err| ReconsolidationError::Denominator {
            detail: redact(&err.to_string()),
        })
}

#[allow(clippy::too_many_lines)]
fn total_bytes(request: &ReconsolidationRequest) -> usize {
    let mut total = 0usize;
    let mut add = |n: usize| {
        total = total.saturating_add(n);
    };
    add(request.frozen_bundle_digest.len());
    add(request.frozen_manifest_digest.len());
    for value in [
        &request.identity.request_id,
        &request.identity.operation_id,
        &request.identity.idempotency_key,
        &request.identity.task_id,
        &request.identity.attempt_id,
        &request.identity.actor,
        &request.identity.route,
        &request.identity.context_id,
        &request.identity.session_id,
        &request.identity.query,
        &request.identity.recipe,
        &request.identity.snapshot,
        &request.identity.scope_id,
        &request.identity.canonical_request_digest,
        &request.identity.requester.principal,
    ] {
        add(value.len());
    }
    if let Some(session) = request.identity.requester.session.as_ref() {
        add(session.len());
    }
    add(request.parent.handle.len());
    add(request.parent.schema.len());
    add(request.parent.revision.len());
    add(request.parent.digest.len());
    add(request.parent.frontier_revision.len());
    for h in &request.parent.predecessor_chain {
        add(h.len());
    }
    for p in &request.parent_propositions {
        add(p.id.len());
        add(p.statement.len());
        add(p.support_handle.len());
        add(p.support_revision.len());
        add(p.support_digest.len());
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
        add(n.owner.len());
        add(n.source_manifest_digest.len());
        add(n.source_revision.len());
        add(n.scope.len());
        add(n.authority.len());
        add(n.privacy.len());
        add(n.assurance.len());
        add(n.statement.len());
        for coverage in &n.coverage {
            add(coverage.len());
        }
    }
    for field_path in &request.field_paths {
        add(field_path.len());
    }
    for proposition in &request.added_propositions {
        add(proposition.id.len());
        add(proposition.statement.len());
        add(proposition.lineage.len());
        for handle in &proposition.evidence_refs {
            add(handle.len());
        }
    }
    for handle in &request.added_member_denominator.members {
        add(handle.len());
    }
    for h in &request.parent_baseline_handles {
        add(h.len());
    }
    for l in &request.parent_baseline_lineages {
        add(l.len());
    }
    for revision in &request.parent_baseline_revisions {
        add(revision.len());
    }
    for digest in &request.parent_baseline_digests {
        add(digest.len());
    }
    add(request.reactivation.checkpoint.len());
    add(request.reactivation.policy_id.len());
    add(request.reactivation.external_handle.len());
    for value in [
        &request.reactivation.binding.operation_id,
        &request.reactivation.binding.owner_receipt,
        &request.reactivation.binding.record_handle,
        &request.reactivation.binding.record_revision,
        &request.reactivation.binding.task_id,
        &request.reactivation.binding.attempt_id,
        &request.reactivation.binding.actor,
        &request.reactivation.binding.route,
        &request.reactivation.binding.context_id,
        &request.reactivation.binding.session_id,
        &request.reactivation.binding.query,
        &request.reactivation.binding.recipe,
        &request.reactivation.binding.snapshot,
    ] {
        add(value.len());
    }
    for d in &request.dependents {
        add(d.handle.len());
        add(d.kind.len());
        add(d.old_identity.len());
        add(d.source_identity.len());
        add(d.owner.len());
        add(d.verifier.len());
    }
    for o in &request.dependent_outcomes {
        add(o.handle.len());
        add(o.note.len());
        add(o.old_identity.len());
        add(o.source_identity.len());
        add(o.new_candidate_identity.len());
        add(o.owner.len());
        add(o.verifier.len());
        add(o.inverse_note.len());
        add(o.forward_correction.len());
    }
    add(request.proposed_child_handle.len());
    add(request.child_verifier.len());
    add(request.child_inverse_note.len());
    add(request.child_forward_correction.len());
    add(request.child_reopen_condition.len());
    add(request.policy_id.len());
    add(request.policy.policy_id.len());
    for value in [
        &request.policy.source_assurance_ceiling,
        &request.policy.authority_ceiling,
        &request.policy.privacy_ceiling,
        &request.policy.influence_ceiling,
        &request.policy.proof_ceiling,
    ] {
        add(value.len());
    }
    total
}

#[allow(clippy::too_many_lines)]
fn preflight_bounds(request: &ReconsolidationRequest) -> Result<(), ReconsolidationError> {
    validate_policy_shape(request)?;
    validate_identity_shape(&request.identity)?;
    check_digest(&request.frozen_bundle_digest, "frozen_bundle_digest")?;
    check_digest(&request.frozen_manifest_digest, "frozen_manifest_digest")?;
    let max_parent = request
        .policy
        .max_parent_propositions
        .min(MAX_PARENT_PROPOSITIONS);
    let max_fields = request.policy.max_fields.min(MAX_FIELDS);
    let max_new = request.policy.max_new_items.min(MAX_NEW_ITEMS);
    let max_dependents = request.policy.max_dependents.min(MAX_DEPENDENTS);
    let max_predecessors = request.policy.max_predecessors.min(MAX_PREDECESSORS);
    let max_baselines = request.policy.max_baseline_refs.min(MAX_BASELINE_REFS);
    let max_output_bytes = request.policy.max_output_bytes.min(MAX_OUTPUT_BYTES);
    let max_work_units = request.policy.max_work_units.min(MAX_WORK_UNITS);
    let max_stu = request.policy.max_stu.min(MAX_STU);
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
        max_parent,
    )?;
    bound("deltas", request.deltas.len(), max_parent)?;
    bound("fields", request.field_paths.len(), max_fields)?;
    bound("sources", request.new_items.len(), max_new)?;
    bound(
        "added_propositions",
        request.added_propositions.len(),
        max_new,
    )?;
    bound("dependents", request.dependents.len(), max_dependents)?;
    bound(
        "dependent_outcomes",
        request.dependent_outcomes.len(),
        max_dependents,
    )?;
    bound(
        "revisions",
        request.parent.predecessor_chain.len(),
        max_predecessors,
    )?;
    bound(
        "baseline_handles",
        request.parent_baseline_handles.len(),
        max_baselines,
    )?;
    bound(
        "baseline_lineages",
        request.parent_baseline_lineages.len(),
        max_baselines,
    )?;
    bound(
        "baseline_revisions",
        request.parent_baseline_revisions.len(),
        max_baselines,
    )?;
    bound(
        "baseline_digests",
        request.parent_baseline_digests.len(),
        max_baselines,
    )?;
    if request.parent_propositions.is_empty() {
        return Err(ReconsolidationError::Bounds {
            phase: "propositions".to_owned(),
            detail: "at least one parent proposition is required".to_owned(),
        });
    }
    if total_bytes(request) > request.policy.max_total_bytes.min(MAX_TOTAL_BYTES) {
        return Err(ReconsolidationError::Bounds {
            phase: "bytes".to_owned(),
            detail: "aggregate input exceeds its byte bound".to_owned(),
        });
    }
    let work = request
        .parent_propositions
        .len()
        .saturating_add(request.new_items.len())
        .saturating_add(request.added_propositions.len())
        .saturating_add(request.dependents.len())
        .saturating_add(request.field_paths.len());
    if u64::try_from(work).map_or(u64::MAX, |value| value) > max_work_units {
        return Err(ReconsolidationError::Bounds {
            phase: "work".to_owned(),
            detail: "bounded work ceiling exceeded".to_owned(),
        });
    }
    if request.policy.observed_stu > max_stu {
        return Err(ReconsolidationError::Bounds {
            phase: "stu".to_owned(),
            detail: "STU usage exceeds its independent policy ceiling".to_owned(),
        });
    }
    if max_output_bytes == 0 {
        return Err(ReconsolidationError::Bounds {
            phase: "output".to_owned(),
            detail: "output ceiling must be positive".to_owned(),
        });
    }
    Ok(())
}

#[allow(clippy::too_many_lines)]
fn validate_shapes(request: &ReconsolidationRequest) -> Result<(), ReconsolidationError> {
    request
        .item
        .validate()
        .map_err(|err| ReconsolidationError::Receipt {
            detail: redact(&err.to_string()),
        })?;
    request
        .grounded
        .validate()
        .map_err(|err| ReconsolidationError::Receipt {
            detail: redact(&err.to_string()),
        })?;
    validate_reactivation_binding(&request.reactivation)?;
    check_handle(&request.parent.handle, "parent.handle")?;
    check_bounded_text(&request.parent.schema, "parent.schema", MAX_HANDLE_BYTES)?;
    check_bounded_text(
        &request.parent.revision,
        "parent.revision",
        MAX_HANDLE_BYTES,
    )?;
    check_digest(&request.parent.digest, "parent.digest")?;
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
        check_bounded_text(
            &p.support_revision,
            "proposition.support_revision",
            MAX_HANDLE_BYTES,
        )?;
        check_digest(&p.support_digest, "proposition.support_digest")?;
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
    let mut item_digests: Vec<String> = Vec::new();
    for n in &request.new_items {
        check_handle(&n.handle, "source.handle")?;
        if !is_hex64_lower(&n.digest) {
            return Err(ReconsolidationError::Source {
                handle: redact(&n.handle),
                detail: "digest must be 64 lowercase hex".to_owned(),
            });
        }
        check_bounded_text(&n.lineage, "source.lineage", MAX_HANDLE_BYTES)?;
        check_handle(&n.owner, "source.owner")?;
        check_digest(&n.source_manifest_digest, "source.manifest_digest")?;
        check_bounded_text(&n.source_revision, "source.revision", MAX_HANDLE_BYTES)?;
        check_handle(&n.scope, "source.scope")?;
        check_handle(&n.authority, "source.authority")?;
        check_handle(&n.privacy, "source.privacy")?;
        check_bounded_text(&n.assurance, "source.assurance", MAX_TEXT_BYTES)?;
        if n.coverage.is_empty() {
            return Err(ReconsolidationError::Source {
                handle: redact(&n.handle),
                detail: "material evidence needs explicit coverage identities".to_owned(),
            });
        }
        if n.coverage.len() > MAX_PARENT_PROPOSITIONS + MAX_DEPENDENTS {
            return Err(ReconsolidationError::Bounds {
                phase: "source.coverage".to_owned(),
                detail: "evidence coverage exceeds its independent bound".to_owned(),
            });
        }
        for coverage in &n.coverage {
            check_handle(coverage, "source.coverage")?;
        }
        if !is_sorted_unique(&n.coverage) {
            return Err(ReconsolidationError::Order {
                phase: "source.coverage".to_owned(),
                detail: "evidence coverage must be sorted and unique".to_owned(),
            });
        }
        check_bounded_text(&n.statement, "source.statement", MAX_TEXT_BYTES)?;
        item_handles.push(n.handle.clone());
        if item_digests.contains(&n.digest) {
            return Err(ReconsolidationError::Source {
                handle: redact(&n.handle),
                detail: "duplicate evidence digest is not a new identity".to_owned(),
            });
        }
        item_digests.push(n.digest.clone());
    }
    if !is_sorted_unique(&item_handles) {
        return Err(ReconsolidationError::Order {
            phase: "sources".to_owned(),
            detail: "new handles must be sorted and unique".to_owned(),
        });
    }
    for field_path in &request.field_paths {
        check_bounded_text(field_path, "field.path", MAX_HANDLE_BYTES)?;
    }
    if !is_sorted_unique(&request.field_paths) {
        return Err(ReconsolidationError::Order {
            phase: "fields".to_owned(),
            detail: "field paths must be sorted and unique".to_owned(),
        });
    }
    for proposition in &request.added_propositions {
        check_bounded_text(&proposition.id, "added.id", MAX_HANDLE_BYTES)?;
        check_bounded_text(&proposition.statement, "added.statement", MAX_TEXT_BYTES)?;
        check_bounded_text(&proposition.lineage, "added.lineage", MAX_HANDLE_BYTES)?;
        for evidence_ref in &proposition.evidence_refs {
            check_handle(evidence_ref, "added.evidence")?;
        }
    }
    let added_ids: Vec<String> = request
        .added_propositions
        .iter()
        .map(|proposition| proposition.id.clone())
        .collect();
    if !is_sorted_unique(&added_ids) {
        return Err(ReconsolidationError::Order {
            phase: "added_propositions".to_owned(),
            detail: "added proposition ids must be sorted and unique".to_owned(),
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
    for revision in &request.parent_baseline_revisions {
        check_bounded_text(revision, "baseline.revision", MAX_HANDLE_BYTES)?;
    }
    for digest in &request.parent_baseline_digests {
        check_digest(digest, "baseline.digest")?;
    }
    request.added_member_denominator.validate().map_err(|err| {
        ReconsolidationError::Denominator {
            detail: redact(&err.to_string()),
        }
    })?;
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
        check_handle(&d.old_identity, "dependent.old_identity")?;
        check_handle(&d.source_identity, "dependent.source_identity")?;
        check_handle(&d.owner, "dependent.owner")?;
        check_handle(&d.verifier, "dependent.verifier")?;
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
        check_handle(&o.old_identity, "dependent_outcome.old_identity")?;
        check_handle(&o.source_identity, "dependent_outcome.source_identity")?;
        check_handle(
            &o.new_candidate_identity,
            "dependent_outcome.new_candidate_identity",
        )?;
        check_handle(&o.owner, "dependent_outcome.owner")?;
        check_handle(&o.verifier, "dependent_outcome.verifier")?;
        check_bounded_text(&o.inverse_note, "dependent_outcome.inverse", MAX_TEXT_BYTES)?;
        check_bounded_text(
            &o.forward_correction,
            "dependent_outcome.forward_correction",
            MAX_TEXT_BYTES,
        )?;
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

fn build_child_propositions(request: &ReconsolidationRequest) -> Vec<ChildProposition> {
    let mut propositions = Vec::new();
    for parent in &request.parent_propositions {
        let Some(delta) = request
            .deltas
            .iter()
            .find(|delta| delta.proposition_id == parent.id)
        else {
            continue;
        };
        if delta.disposition == PropositionDisposition::Withdrawn {
            continue;
        }
        propositions.push(ChildProposition {
            id: parent.id.clone(),
            statement: delta
                .revised_statement
                .clone()
                .unwrap_or_else(|| parent.statement.clone()),
            lineage: parent.lineage.clone(),
            support_handle: parent.support_handle.clone(),
            support_revision: parent.support_revision.clone(),
            support_digest: parent.support_digest.clone(),
            evidence_refs: delta.evidence_refs.clone(),
            parent_proposition_id: Some(parent.id.clone()),
        });
    }
    propositions.extend(request.added_propositions.iter().map(|added| {
        let evidence = added
            .evidence_refs
            .first()
            .and_then(|handle| request.new_items.iter().find(|item| &item.handle == handle));
        ChildProposition {
            id: added.id.clone(),
            statement: added.statement.clone(),
            lineage: added.lineage.clone(),
            support_handle: added
                .evidence_refs
                .first()
                .cloned()
                .unwrap_or_else(|| "unresolved-support".to_owned()),
            support_revision: evidence.map_or_else(
                || "unresolved-source-revision".to_owned(),
                |item| item.source_revision.clone(),
            ),
            support_digest: evidence.map_or_else(|| "0".repeat(64), |item| item.digest.clone()),
            evidence_refs: added.evidence_refs.clone(),
            parent_proposition_id: None,
        }
    }));
    propositions
}

fn build_child(
    request: &ReconsolidationRequest,
) -> Result<ChildAllocationRequest, ReconsolidationError> {
    let propositions = build_child_propositions(request);
    let mut preserved_revision_history = request.parent.predecessor_chain.clone();
    preserved_revision_history.push(request.parent.revision.clone());
    let mut preserved_source_refs = request.parent_baseline_handles.clone();
    preserved_source_refs.extend(request.new_items.iter().map(|item| item.handle.clone()));
    preserved_source_refs.push(request.reactivation.binding.owner_receipt.clone());
    preserved_source_refs.sort();
    preserved_source_refs.dedup();
    let mut preserved_source_identities: Vec<String> = request
        .parent_baseline_handles
        .iter()
        .zip(&request.parent_baseline_lineages)
        .zip(&request.parent_baseline_revisions)
        .zip(&request.parent_baseline_digests)
        .map(|(((handle, lineage), revision), digest)| {
            format!("{handle}|{lineage}|{revision}|{digest}")
        })
        .collect();
    preserved_source_identities.extend(request.new_items.iter().map(|item| {
        format!(
            "{}|{}|{}|{}",
            item.handle, item.lineage, item.source_revision, item.digest
        )
    }));
    preserved_source_identities.push(format!(
        "{}|{}",
        request.reactivation.binding.owner_receipt, request.reactivation.checkpoint
    ));
    preserved_source_identities.sort();
    preserved_source_identities.dedup();
    let preserved_source_bindings: Vec<PreservedSourceBinding> = request
        .new_items
        .iter()
        .map(|item| PreservedSourceBinding {
            handle: item.handle.clone(),
            manifest_digest: item.source_manifest_digest.clone(),
            scope: item.scope.clone(),
            authority: item.authority.clone(),
            privacy: item.privacy.clone(),
            freshness_ms: item.freshness_ms,
        })
        .collect();
    let preimage = ChildDigestPreimage {
        identity_digest: &request.identity.canonical_request_digest,
        parent_handle: &request.parent.handle,
        parent_schema: &request.parent.schema,
        parent_revision: &request.parent.revision,
        parent_digest: &request.parent.digest,
        propositions: &propositions,
        preserved_revision_history: &preserved_revision_history,
        preserved_source_refs: &preserved_source_refs,
        preserved_source_identities: &preserved_source_identities,
        preserved_source_bindings: &preserved_source_bindings,
        field_paths: &request.field_paths,
        axis_owners: &request.axis_owners,
        source_assurance_ceiling: &request.policy.source_assurance_ceiling,
        authority_ceiling: &request.policy.authority_ceiling,
        privacy_ceiling: &request.policy.privacy_ceiling,
        influence_ceiling: &request.policy.influence_ceiling,
        proof_ceiling: &request.policy.proof_ceiling,
    };
    let request_digest = canonical_json_bytes(&preimage)
        .map(|bytes| sha256_hex(&bytes))
        .map_err(|err| ReconsolidationError::Malformed {
            phase: "child_digest".to_owned(),
            detail: redact(&err.to_string()),
        })?;
    Ok(ChildAllocationRequest {
        parent_handle: request.parent.handle.clone(),
        parent_schema: request.parent.schema.clone(),
        parent_revision: request.parent.revision.clone(),
        parent_digest: request.parent.digest.clone(),
        proposed_child_handle: request.proposed_child_handle.clone(),
        verifier: request.child_verifier.clone(),
        inverse_note: request.child_inverse_note.clone(),
        forward_correction: request.child_forward_correction.clone(),
        expiry_ms: request.child_expiry_ms,
        reopen_condition: request.child_reopen_condition.clone(),
        propositions,
        preserved_revision_history,
        preserved_source_refs,
        preserved_source_identities,
        preserved_source_bindings,
        field_paths: request.field_paths.clone(),
        axis_owners: request.axis_owners.clone(),
        source_assurance_ceiling: request.policy.source_assurance_ceiling.clone(),
        authority_ceiling: request.policy.authority_ceiling.clone(),
        privacy_ceiling: request.policy.privacy_ceiling.clone(),
        influence_ceiling: request.policy.influence_ceiling.clone(),
        proof_ceiling: request.policy.proof_ceiling.clone(),
        request_digest,
        request_only: true,
        allocates_revision: false,
    })
}

#[allow(clippy::too_many_lines)]
fn child_projection_issue(
    request: &ReconsolidationRequest,
    child: &ChildAllocationRequest,
    genuine: &[&NewEvidenceItem],
) -> Option<&'static str> {
    if !child.request_only || child.allocates_revision {
        return Some("child projection is not an inert allocation request");
    }
    if child.parent_handle != request.parent.handle
        || child.parent_schema != request.parent.schema
        || child.parent_revision != request.parent.revision
        || child.parent_digest != request.parent.digest
        || child.verifier != request.child_verifier
        || child.reopen_condition != request.child_reopen_condition
    {
        return Some("child projection lost its parent or admission verifier binding");
    }
    if child.field_paths != request.field_paths {
        return Some("child projection lost the exact semantic field paths");
    }
    if child.axis_owners != request.axis_owners
        || child.source_assurance_ceiling != request.policy.source_assurance_ceiling
        || child.authority_ceiling != request.policy.authority_ceiling
        || child.privacy_ceiling != request.policy.privacy_ceiling
        || child.influence_ceiling != request.policy.influence_ceiling
        || child.proof_ceiling != request.policy.proof_ceiling
    {
        return Some("child projection changed an independent owner or proof ceiling");
    }
    if !request
        .parent
        .predecessor_chain
        .iter()
        .all(|revision| child.preserved_revision_history.contains(revision))
        || !child
            .preserved_revision_history
            .contains(&request.parent.revision)
    {
        return Some("child projection lost parent or prior revision history");
    }
    if !request
        .parent_baseline_handles
        .iter()
        .all(|handle| child.preserved_source_refs.contains(handle))
        || !genuine
            .iter()
            .all(|item| child.preserved_source_refs.contains(&item.handle))
        || !child
            .preserved_source_refs
            .contains(&request.reactivation.external_handle)
    {
        return Some("child projection lost a raw, source, or reactivation handle");
    }
    let expected_source_identities: Vec<String> = request
        .parent_baseline_handles
        .iter()
        .zip(&request.parent_baseline_lineages)
        .zip(&request.parent_baseline_revisions)
        .zip(&request.parent_baseline_digests)
        .map(|(((handle, lineage), revision), digest)| {
            format!("{handle}|{lineage}|{revision}|{digest}")
        })
        .collect();
    if !expected_source_identities
        .iter()
        .all(|identity| child.preserved_source_identities.contains(identity))
        || !genuine.iter().all(|item| {
            child.preserved_source_identities.contains(&format!(
                "{}|{}|{}|{}",
                item.handle, item.lineage, item.source_revision, item.digest
            ))
        })
    {
        return Some("child projection lost a canonical source identity");
    }
    let expected_source_bindings: Vec<PreservedSourceBinding> = request
        .new_items
        .iter()
        .map(|item| PreservedSourceBinding {
            handle: item.handle.clone(),
            manifest_digest: item.source_manifest_digest.clone(),
            scope: item.scope.clone(),
            authority: item.authority.clone(),
            privacy: item.privacy.clone(),
            freshness_ms: item.freshness_ms,
        })
        .collect();
    if child.preserved_source_bindings != expected_source_bindings {
        return Some("child projection lost a source manifest or freshness binding");
    }
    let mut ids = Vec::new();
    for proposition in &child.propositions {
        if ids.contains(&proposition.id) {
            return Some("child proposition identities are not one-to-one");
        }
        ids.push(proposition.id.clone());
        if proposition.parent_proposition_id.is_none()
            && !request
                .added_propositions
                .iter()
                .any(|added| added.id == proposition.id)
        {
            return Some("child contains an unaccounted proposition");
        }
    }
    for parent in &request.parent_propositions {
        let Some(delta) = request
            .deltas
            .iter()
            .find(|delta| delta.proposition_id == parent.id)
        else {
            return Some("parent proposition has no delta");
        };
        let child_proposition = child.propositions.iter().find(|p| p.id == parent.id);
        match delta.disposition {
            PropositionDisposition::Withdrawn => {
                if child_proposition.is_some() {
                    return Some("withdrawn proposition remains in the child view");
                }
            }
            PropositionDisposition::Retained | PropositionDisposition::Unresolved => {
                let Some(child_proposition) = child_proposition else {
                    return Some("retained or unresolved parent proposition was lost");
                };
                if child_proposition.statement != parent.statement
                    || child_proposition.support_handle != parent.support_handle
                    || child_proposition.support_revision != parent.support_revision
                    || child_proposition.support_digest != parent.support_digest
                    || child_proposition.lineage != parent.lineage
                {
                    return Some("retained parent proposition changed in the child projection");
                }
            }
            PropositionDisposition::Narrowed
            | PropositionDisposition::Qualified
            | PropositionDisposition::Contradicted => {
                let Some(child_proposition) = child_proposition else {
                    return Some("changed parent proposition was lost from the child projection");
                };
                if child_proposition.statement != delta.revised_statement.as_deref().unwrap_or("")
                    || child_proposition.support_handle != parent.support_handle
                    || child_proposition.support_revision != parent.support_revision
                    || child_proposition.support_digest != parent.support_digest
                    || child_proposition.lineage != parent.lineage
                    || !child_proposition
                        .evidence_refs
                        .iter()
                        .all(|handle| genuine.iter().any(|item| &item.handle == handle))
                {
                    return Some("changed child proposition lacks exact parent or new evidence");
                }
            }
        }
    }
    for added in &request.added_propositions {
        let Some(child_proposition) = child.propositions.iter().find(|p| p.id == added.id) else {
            return Some("added proposition was lost from the child projection");
        };
        if child_proposition.statement != added.statement
            || child_proposition.lineage != added.lineage
            || child_proposition.evidence_refs != added.evidence_refs
            || !added.evidence_refs.iter().any(|handle| {
                request.new_items.iter().any(|item| {
                    &item.handle == handle
                        && child_proposition.support_revision == item.source_revision
                        && child_proposition.support_digest == item.digest
                })
            })
        {
            return Some("added proposition changed without its manifest evidence");
        }
    }
    None
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
    let dependent_handles: Vec<String> = request
        .dependents
        .iter()
        .map(|dependent| dependent.handle.clone())
        .collect();
    let outcome_handles: Vec<String> = request
        .dependent_outcomes
        .iter()
        .map(|outcome| outcome.handle.clone())
        .collect();
    if has_repeated_handle(&dependent_handles) || has_repeated_handle(&outcome_handles) {
        return ok_result(
            ReconsolidationOutcome::Blocked,
            None,
            request.parent_propositions.len(),
            0,
            "dependent coverage requires one-to-one handles",
        );
    }
    validate_shapes(request)?;

    if request.item.receipt != request.receipt {
        return ok_result(
            ReconsolidationOutcome::Blocked,
            None,
            request.parent_propositions.len(),
            0,
            "same receipt identity carries changed content",
        );
    }
    if request.identity.computed_digest()? != request.identity.canonical_request_digest {
        return ok_result(
            ReconsolidationOutcome::Blocked,
            None,
            request.parent_propositions.len(),
            0,
            "request identity digest conflicts with its canonical fields",
        );
    }
    if request.identity.task_id != request.receipt.task_id
        || request.identity.scope_id != request.receipt.scope_id
        || request.identity.state_fence != request.receipt.state_fence
        || request.identity.requester != request.item.requester
    {
        return ok_result(
            ReconsolidationOutcome::Stale,
            None,
            request.parent_propositions.len(),
            0,
            "request task, scope, fence, or requester moved from the accepted envelope",
        );
    }
    if request.frozen_bundle_digest != request.receipt.bundle_digest
        || request.frozen_manifest_digest != request.receipt.manifest_digest
        || request.grounded.job_id != request.receipt.job_id
        || request.grounded.draft_digest != request.receipt.draft_digest
    {
        return ok_result(
            ReconsolidationOutcome::Stale,
            None,
            request.parent_propositions.len(),
            0,
            "frozen bundle, manifest, or grounded draft moved from the accepted receipt",
        );
    }
    let binding = &request.reactivation.binding;
    if binding.operation_id != request.identity.operation_id
        || binding.record_handle != request.parent.handle
        || binding.record_revision != request.parent.revision
        || binding.task_id != request.identity.task_id
        || binding.attempt_id != request.identity.attempt_id
        || binding.actor != request.identity.actor
        || binding.route != request.identity.route
        || binding.context_id != request.identity.context_id
        || binding.session_id != request.identity.session_id
        || binding.query != request.identity.query
        || binding.recipe != request.identity.recipe
        || binding.snapshot != request.identity.snapshot
        || binding.state_fence != request.identity.state_fence
        || binding.owner_receipt != request.reactivation.external_handle
    {
        return ok_result(
            ReconsolidationOutcome::Stale,
            None,
            request.parent_propositions.len(),
            0,
            "reactivation record, attempt, route, or fence does not bind the request",
        );
    }
    if !contains_handle(
        &binding.observation_denominator.members,
        &binding.record_handle,
    ) {
        return ok_result(
            ReconsolidationOutcome::Abstention,
            None,
            request.parent_propositions.len(),
            0,
            "reactivation denominator does not cover the observed record",
        );
    }
    if request.policy.cancelled {
        return ok_result(
            ReconsolidationOutcome::Rejected,
            None,
            request.parent_propositions.len(),
            0,
            "caller cancelled the reconsolidation request",
        );
    }
    if let Some(deadline) = request.policy.deadline_ms {
        let Some(observed) = request.policy.observation_time_ms else {
            return ok_result(
                ReconsolidationOutcome::Stale,
                None,
                request.parent_propositions.len(),
                0,
                "frozen policy deadline cannot be evaluated without an observation time",
            );
        };
        if observed >= deadline {
            return ok_result(
                ReconsolidationOutcome::Stale,
                None,
                request.parent_propositions.len(),
                0,
                "frozen policy deadline has elapsed",
            );
        }
    }

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
    let CurationPayload::Reconsolidation(item_payload) = &request.item.payload else {
        return ok_result(
            ReconsolidationOutcome::Rejected,
            None,
            request.parent_propositions.len(),
            0,
            "accepted curation item is not a reconsolidation payload",
        );
    };
    if item_payload.target != request.parent.handle {
        return ok_result(
            ReconsolidationOutcome::Stale,
            None,
            request.parent_propositions.len(),
            0,
            "accepted curation target does not bind the current parent",
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
        || contains_handle(&request.parent.predecessor_chain, &request.parent.revision)
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
    if request.reactivation.stage.rank() < request.policy.minimum_reactivation_stage.rank() {
        return ok_result(
            ReconsolidationOutcome::Abstention,
            None,
            request.parent_propositions.len(),
            0,
            "reactivation checkpoint is below the policy-qualified stage",
        );
    }
    let Some(reactivation_at) = request.reactivation.observed_at_ms else {
        return ok_result(
            ReconsolidationOutcome::Abstention,
            None,
            request.parent_propositions.len(),
            0,
            "reactivation order is unknown and no wall-clock fill is admitted",
        );
    };

    if request.parent_baseline_handles.len() != request.parent_baseline_lineages.len()
        || request.parent_baseline_handles.len() != request.parent_baseline_revisions.len()
        || request.parent_baseline_handles.len() != request.parent_baseline_digests.len()
    {
        return ok_result(
            ReconsolidationOutcome::Blocked,
            None,
            request.parent_propositions.len(),
            0,
            "parent baseline handles, lineages, revisions, and digests are not aligned",
        );
    }
    for proposition in &request.parent_propositions {
        if !contains_baseline_record(
            &request.parent_baseline_handles,
            &request.parent_baseline_lineages,
            &request.parent_baseline_revisions,
            &request.parent_baseline_digests,
            &proposition.support_handle,
            &proposition.lineage,
            &proposition.support_revision,
            &proposition.support_digest,
        ) {
            return ok_result(
                ReconsolidationOutcome::Blocked,
                None,
                request.parent_propositions.len(),
                0,
                "parent proposition support and lineage are outside its declared baseline",
            );
        }
    }

    let parent_statements: Vec<String> = request
        .parent_propositions
        .iter()
        .map(|p| normalize_statement(&p.statement))
        .collect();
    let mut genuine: Vec<&NewEvidenceItem> = Vec::new();
    let mut unknown_temporal = 0usize;
    let mut unknown_independence = 0usize;
    let mut stale_temporal = 0usize;
    let mut baseline_identity_conflict = false;
    let mut source_contract_conflict = false;
    let parent_lineages: Vec<&str> = request
        .parent_propositions
        .iter()
        .map(|proposition| proposition.lineage.as_str())
        .collect();
    for item in &request.new_items {
        if item.source_kind != EvidenceSourceKind::ExternalObservation {
            continue;
        }
        if item.scope != request.identity.scope_id
            || item.assurance != request.policy.source_assurance_ceiling
            || item.source_manifest_digest != request.frozen_manifest_digest
            || item.authority != request.policy.authority_ceiling
            || item.privacy != request.policy.privacy_ceiling
            || item.freshness_ms != item.observed_at_ms
        {
            source_contract_conflict = true;
            continue;
        }
        if item.independence != EvidenceIndependence::Independent {
            unknown_independence = unknown_independence.saturating_add(1);
            continue;
        }
        if contains_handle(&request.parent_baseline_handles, &item.handle)
            && let Some(index) = baseline_index(
                &request.parent_baseline_handles,
                &request.parent_baseline_lineages,
                &item.handle,
                &item.lineage,
            )
            && request.parent_baseline_revisions[index] == item.source_revision
            && request.parent_baseline_digests[index] == item.digest
        {
            continue;
        }
        if contains_handle(&request.parent_baseline_handles, &item.handle) {
            if contains_baseline_pair(
                &request.parent_baseline_handles,
                &request.parent_baseline_lineages,
                &item.handle,
                &item.lineage,
            ) {
                // Same handle and lineage with a changed revision or bytes is
                // an identity conflict, never a silently new observation.
                baseline_identity_conflict = true;
                continue;
            }
            // The baseline has no authority to silently reinterpret an
            // existing source handle under another lineage/revision.
            baseline_identity_conflict = true;
            continue;
        }
        if request
            .parent_baseline_digests
            .iter()
            .any(|digest| digest == &item.digest)
        {
            continue;
        }
        if parent_lineages.contains(&item.lineage.as_str())
            || request.parent_baseline_lineages.contains(&item.lineage)
            || genuine
                .iter()
                .any(|existing| existing.lineage == item.lineage)
        {
            continue;
        }
        let normalized = normalize_statement(&item.statement);
        if parent_statements.contains(&normalized) {
            continue;
        }
        let Some(observed_at) = item.observed_at_ms else {
            unknown_temporal = unknown_temporal.saturating_add(1);
            continue;
        };
        if observed_at <= reactivation_at {
            stale_temporal = stale_temporal.saturating_add(1);
            continue;
        }
        // Lineage groups provenance; the handle and canonical digest identify the item.
        genuine.push(item);
    }
    // Unknown temporal order abstains first; stale material then outranks every other result.
    if source_contract_conflict {
        return ok_result(
            ReconsolidationOutcome::Blocked,
            None,
            request.parent_propositions.len(),
            0,
            "new evidence source manifest, scope, authority, privacy, or freshness does not bind",
        );
    }
    if unknown_temporal > 0 {
        return ok_result(
            ReconsolidationOutcome::Abstention,
            None,
            request.parent_propositions.len(),
            0,
            "temporal order is unknown and no wall-clock fill is admitted",
        );
    }
    if stale_temporal > 0 {
        return ok_result(
            ReconsolidationOutcome::Stale,
            None,
            request.parent_propositions.len(),
            0,
            "new evidence does not follow the exact reactivation checkpoint",
        );
    }
    if unknown_independence > 0 {
        return ok_result(
            ReconsolidationOutcome::Abstention,
            None,
            request.parent_propositions.len(),
            0,
            "new evidence independence is unknown or shared",
        );
    }
    if baseline_identity_conflict {
        return ok_result(
            ReconsolidationOutcome::Blocked,
            None,
            request.parent_propositions.len(),
            0,
            "same baseline source identity changed without a paired revision digest",
        );
    }
    if genuine.is_empty() {
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
                if !delta
                    .evidence_refs
                    .iter()
                    .any(|handle| genuine.iter().any(|item| &item.handle == handle))
                {
                    return ok_result(
                        ReconsolidationOutcome::NoSafeRevision,
                        None,
                        request.parent_propositions.len(),
                        genuine.len(),
                        "changed propositions require genuinely new evidence",
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
                if !delta
                    .evidence_refs
                    .iter()
                    .any(|handle| genuine.iter().any(|item| &item.handle == handle))
                {
                    return ok_result(
                        ReconsolidationOutcome::NoSafeRevision,
                        None,
                        request.parent_propositions.len(),
                        genuine.len(),
                        "withdrawal requires genuinely new evidence",
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
    let genuine_handles: Vec<String> = genuine.iter().map(|item| item.handle.clone()).collect();
    let genuine_count = u32::try_from(genuine.len()).map_err(|_| ReconsolidationError::Bounds {
        phase: "new_members".to_owned(),
        detail: "admitted additions do not fit the result envelope".to_owned(),
    })?;
    if !same_sorted_set(&request.new_member_denominator.members, &genuine_handles)
        || request.new_member_denominator.expected_total != genuine_count
    {
        return ok_result(
            ReconsolidationOutcome::Blocked,
            None,
            request.parent_propositions.len(),
            genuine.len(),
            "new-member denominator must exactly cover admitted additions",
        );
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

    let added_ids: Vec<String> = request
        .added_propositions
        .iter()
        .map(|proposition| proposition.id.clone())
        .collect();
    let parent_ids: Vec<String> = request
        .parent_propositions
        .iter()
        .map(|proposition| proposition.id.clone())
        .collect();
    if added_ids.iter().any(|id| parent_ids.contains(id)) {
        return ok_result(
            ReconsolidationOutcome::Blocked,
            None,
            request.parent_propositions.len(),
            genuine.len(),
            "added propositions cannot reuse a parent proposition identity",
        );
    }
    if !same_sorted_set(&request.added_member_denominator.members, &added_ids)
        || request.added_member_denominator.expected_total
            != u32::try_from(added_ids.len()).map_err(|_| ReconsolidationError::Bounds {
                phase: "added_members".to_owned(),
                detail: "added proposition count does not fit the denominator".to_owned(),
            })?
    {
        return ok_result(
            ReconsolidationOutcome::Blocked,
            None,
            request.parent_propositions.len(),
            genuine.len(),
            "added proposition denominator must exactly cover additions",
        );
    }
    for added in &request.added_propositions {
        if added.evidence_refs.is_empty()
            || !added
                .evidence_refs
                .iter()
                .all(|handle| genuine.iter().any(|item| &item.handle == handle))
        {
            return ok_result(
                ReconsolidationOutcome::NoSafeRevision,
                None,
                request.parent_propositions.len(),
                genuine.len(),
                "added propositions require genuinely new evidence",
            );
        }
    }

    let parent_ids: Vec<String> = request
        .parent_propositions
        .iter()
        .map(|proposition| proposition.id.clone())
        .collect();
    let added_ids: Vec<String> = request
        .added_propositions
        .iter()
        .map(|proposition| proposition.id.clone())
        .collect();
    let dependent_ids: Vec<String> = request
        .dependents
        .iter()
        .map(|dependent| dependent.handle.clone())
        .collect();
    for item in &genuine {
        if !item.coverage.iter().any(|identity| {
            parent_ids.contains(identity)
                || added_ids.contains(identity)
                || dependent_ids.contains(identity)
        }) {
            return ok_result(
                ReconsolidationOutcome::NoSafeRevision,
                None,
                request.parent_propositions.len(),
                genuine.len(),
                "new evidence coverage is outside the parent, addition, and dependent closure",
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
    if has_repeated_handle(&dependent_handles)
        || has_repeated_handle(&outcome_handles)
        || !same_sorted_set(&dependent_handles, &outcome_handles)
    {
        return ok_result(
            ReconsolidationOutcome::Blocked,
            None,
            request.parent_propositions.len(),
            genuine.len(),
            "dependent outcomes must exactly cover affected dependents",
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
        if outcome.old_identity != dependent.old_identity
            || outcome.source_identity != dependent.source_identity
            || outcome.owner != dependent.owner
            || outcome.verifier != dependent.verifier
            || outcome.new_candidate_identity != request.proposed_child_handle
        {
            return ok_result(
                ReconsolidationOutcome::Blocked,
                None,
                request.parent_propositions.len(),
                genuine.len(),
                "dependent disposition identities or owner do not bind the proposed child",
            );
        }
        match outcome.effect_status {
            EffectObservation::NotAttempted => {}
            EffectObservation::Applied => {
                return ok_result(
                    ReconsolidationOutcome::Blocked,
                    None,
                    request.parent_propositions.len(),
                    genuine.len(),
                    "an applied dependent effect is outside this candidate-only leaf",
                );
            }
            EffectObservation::Unknown => {
                return ok_result(
                    ReconsolidationOutcome::Blocked,
                    None,
                    request.parent_propositions.len(),
                    genuine.len(),
                    "unknown external effect blocks blind rollback or retry",
                );
            }
        }
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
    let child = build_child(request)?;
    if let Some(note) = child_projection_issue(request, &child, &genuine) {
        return ok_result(
            ReconsolidationOutcome::Blocked,
            None,
            request.parent_propositions.len(),
            genuine.len(),
            note,
        );
    }
    let child_bytes =
        canonical_json_bytes(&child).map_err(|err| ReconsolidationError::Malformed {
            phase: "child_output".to_owned(),
            detail: redact(&err.to_string()),
        })?;
    if child_bytes.len() > request.policy.max_output_bytes.min(MAX_OUTPUT_BYTES) {
        return ok_result(
            ReconsolidationOutcome::Blocked,
            None,
            request.parent_propositions.len(),
            genuine.len(),
            "child allocation request exceeds the policy output ceiling",
        );
    }
    if has_unresolved {
        if !request.policy.allow_partial {
            return ok_result(
                ReconsolidationOutcome::Blocked,
                None,
                request.parent_propositions.len(),
                genuine.len(),
                "policy does not allow a partial unresolved candidate",
            );
        }
        return ok_result(
            ReconsolidationOutcome::Partial,
            Some(child),
            request.parent_propositions.len(),
            genuine.len(),
            "non-load-bearing unresolved yields a partial candidate",
        );
    }

    ok_result(
        ReconsolidationOutcome::Complete,
        Some(child),
        request.parent_propositions.len(),
        genuine.len(),
        "forward child revision proposed as an external request",
    )
}

/// Maps a terminal outcome to the closest A-03 hub hint without re-running validation.
///
/// Returns `None` for [`ReconsolidationOutcome::Complete`]; every other
/// outcome maps to the rejection class a downstream gate would most likely
/// record. The mapping is diagnostic only and never executes validation.
#[must_use]
pub fn outcome_rejection_hint(outcome: &ReconsolidationOutcome) -> Option<CurationRejectionCode> {
    match outcome {
        ReconsolidationOutcome::Complete => None,
        ReconsolidationOutcome::Partial | ReconsolidationOutcome::Blocked => {
            Some(CurationRejectionCode::PreservationFailed)
        }
        ReconsolidationOutcome::NoMaterialNewEvidence | ReconsolidationOutcome::Abstention => {
            Some(CurationRejectionCode::LineageMismatch)
        }
        ReconsolidationOutcome::NoSafeRevision => Some(CurationRejectionCode::UnsupportedPrecision),
        ReconsolidationOutcome::Stale | ReconsolidationOutcome::Rejected => {
            Some(CurationRejectionCode::IdentityMismatch)
        }
    }
}

/// Canonical A-03 handler identity for the Reconsolidation family.
pub const RECONSOLIDATION_HANDLER_ID: &str = "eliot-dreamer-reconsolidation";
/// Stable injected-port identity used by package-local handler fixtures.
pub const RECONSOLIDATION_PORT_ID: &str = "reconsolidation-port";

/// Returns the exact A-03 descriptor for the `Reconsolidation` wire kind.
/// Registration and dispatch remain owned by the curation integrator.
#[must_use]
pub fn reconsolidation_handler_port() -> CurationHandlerPort {
    CurationHandlerPort {
        port_id: RECONSOLIDATION_PORT_ID.to_owned(),
        descriptor: CurationHandlerDescriptor {
            family: CurationFamily::Reconsolidation,
            handler_id: RECONSOLIDATION_HANDLER_ID.to_owned(),
            accepted_kinds: vec![CurationKind::Reconsolidation],
        },
    }
}

/// Immutable adapter for the A-03 injected native-handler seam.  It binds a
/// frozen leaf request to the accepted item and returns only inert candidate
/// content; it does not discover, register, persist, allocate, or postflight.
#[derive(Clone, Debug)]
pub struct ReconsolidationHandler {
    request: ReconsolidationRequest,
}

impl ReconsolidationHandler {
    /// Binds one immutable semantic request to this handler instance.
    #[must_use]
    pub fn new(request: ReconsolidationRequest) -> Self {
        Self { request }
    }

    /// Returns the frozen request used by this adapter.
    #[must_use]
    pub const fn request(&self) -> &ReconsolidationRequest {
        &self.request
    }

    fn bind_call(
        &self,
        call: &BoundCurationCall,
    ) -> Result<ReconsolidationPayload, ContractViolation> {
        call.validate()?;
        if call.port.descriptor != reconsolidation_handler_port().descriptor {
            return Err(ContractViolation::BindingMismatch {
                field: "handler_descriptor",
                reason: "reconsolidation call is bound to a different handler descriptor"
                    .to_owned(),
            });
        }
        if call.request.kind != CurationKind::Reconsolidation
            || call.request.family != CurationFamily::Reconsolidation
        {
            return Err(ContractViolation::KindPayload(
                "reconsolidation handler accepts only the Reconsolidation wire kind".to_owned(),
            ));
        }
        let item_payload = match &call.item.payload {
            CurationPayload::Reconsolidation(payload) => payload.clone(),
            _ => {
                return Err(ContractViolation::KindPayload(
                    "reconsolidation handler requires the closed ReconsolidationPayload subtype"
                        .to_owned(),
                ));
            }
        };
        let CurationPayload::Reconsolidation(request_payload) = &call.request.payload else {
            return Err(ContractViolation::KindPayload(
                "typed request does not carry the ReconsolidationPayload subtype".to_owned(),
            ));
        };
        if item_payload != *request_payload {
            return Err(ContractViolation::BindingMismatch {
                field: "payload",
                reason: "accepted item payload must equal the typed request payload".to_owned(),
            });
        }
        if self.request.item != call.item {
            return Err(ContractViolation::BindingMismatch {
                field: "item",
                reason: "reconsolidation request is not bound to the accepted item".to_owned(),
            });
        }
        if self.request.parent.handle != item_payload.target {
            return Err(ContractViolation::BindingMismatch {
                field: "parent.target",
                reason: "accepted reconsolidation target is not the current parent".to_owned(),
            });
        }
        if self.request.identity.task_id != call.request.task_id
            || self.request.identity.scope_id != call.request.scope_id
            || self.request.identity.state_fence != call.request.state_fence
        {
            return Err(ContractViolation::BindingMismatch {
                field: "task_scope_fence",
                reason: "reconsolidation identity is not bound to the typed request".to_owned(),
            });
        }
        Ok(item_payload)
    }
}

fn reconsolidation_candidate_disposition(outcome: ReconsolidationOutcome) -> CandidateDisposition {
    match outcome {
        ReconsolidationOutcome::Complete => CandidateDisposition::Candidate,
        ReconsolidationOutcome::Partial => CandidateDisposition::Partial,
        ReconsolidationOutcome::Abstention
        | ReconsolidationOutcome::NoMaterialNewEvidence
        | ReconsolidationOutcome::NoSafeRevision => CandidateDisposition::Abstention,
        ReconsolidationOutcome::Stale => CandidateDisposition::Conflict,
        ReconsolidationOutcome::Blocked => CandidateDisposition::Blocked,
        ReconsolidationOutcome::Rejected => CandidateDisposition::Unsupported,
    }
}

fn reconsolidation_error_as_contract(error: ReconsolidationError) -> ContractViolation {
    match error {
        ReconsolidationError::Bounds { phase, detail }
        | ReconsolidationError::Malformed { phase, detail }
        | ReconsolidationError::Order { phase, detail } => ContractViolation::BindingMismatch {
            field: "reconsolidation.input",
            reason: redact(&format!("{phase}: {detail}")),
        },
        ReconsolidationError::Proposition { id, detail } => ContractViolation::BindingMismatch {
            field: "reconsolidation.proposition",
            reason: redact(&format!("{id}: {detail}")),
        },
        ReconsolidationError::Source { handle, detail } => ContractViolation::BindingMismatch {
            field: "reconsolidation.source",
            reason: redact(&format!("{handle}: {detail}")),
        },
        ReconsolidationError::Dependent { handle, detail } => ContractViolation::BindingMismatch {
            field: "reconsolidation.dependent",
            reason: redact(&format!("{handle}: {detail}")),
        },
        ReconsolidationError::Receipt { detail }
        | ReconsolidationError::Preservation { detail }
        | ReconsolidationError::Denominator { detail } => ContractViolation::BindingMismatch {
            field: "reconsolidation.receipt",
            reason: redact(&detail),
        },
    }
}

impl NativeCurationHandler for ReconsolidationHandler {
    fn handle(
        &self,
        call: &BoundCurationCall,
    ) -> Result<ProducedCurationContent, ContractViolation> {
        let payload = self.bind_call(call)?;
        let candidate =
            propose_reconsolidation(&self.request).map_err(reconsolidation_error_as_contract)?;
        let rollback_note = candidate
            .child
            .as_ref()
            .map_or("no child allocation request was formed", |child| {
                child.inverse_note.as_str()
            });
        Ok(ProducedCurationContent {
            payload: CurationPayload::Reconsolidation(payload),
            disposition: reconsolidation_candidate_disposition(candidate.outcome),
            preservation: self.request.preservation.clone(),
            support_note: format!("reconsolidation candidate: {}", redact(&candidate.note)),
            rollback_note: redact(rollback_note),
            counterevidence_refs: Vec::new(),
        })
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use eliot_contracts::{
        EpochId, EpochLineageId, ReceiptId, RequestId, ResourceGeneration, StateFence,
    };
    use eliot_dreamer_contracts::candidate::{DimensionVerdict, PreservationDimension};
    use eliot_dreamer_contracts::curation::{ReconsolidationPayload, TargetEvidence};
    use eliot_dreamer_contracts::{
        AtomicityMode, BoundCurationCall, CandidateDisposition, ClaimResidue, CurationFamily,
        PreservationReport, Requester, RequesterOrigin, ScreenBinding, ScreenState, SupportState,
        TypedCurationHandlerRequest,
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

    fn test_policy() -> ReconsolidationPolicy {
        ReconsolidationPolicy {
            policy_id: "policy-7".to_owned(),
            minimum_reactivation_stage: ReactivationStage::QualifyingPublicUse,
            allow_partial: true,
            max_parent_propositions: MAX_PARENT_PROPOSITIONS,
            max_fields: MAX_FIELDS,
            max_new_items: MAX_NEW_ITEMS,
            max_dependents: MAX_DEPENDENTS,
            max_predecessors: MAX_PREDECESSORS,
            max_baseline_refs: MAX_BASELINE_REFS,
            max_total_bytes: MAX_TOTAL_BYTES,
            max_output_bytes: MAX_OUTPUT_BYTES,
            max_work_units: 1_000,
            max_stu: MAX_STU,
            observed_stu: 0,
            source_assurance_ceiling: "assurance-7".to_owned(),
            authority_ceiling: "candidate-only".to_owned(),
            privacy_ceiling: "scope-7".to_owned(),
            influence_ceiling: "derived-local".to_owned(),
            proof_ceiling: "candidate-only".to_owned(),
            cancelled: false,
            observation_time_ms: Some(1_700_000_000_001),
            deadline_ms: Some(1_800_000_000_000),
        }
    }

    fn test_identity() -> RequestIdentity {
        let mut identity = RequestIdentity {
            request_id: "request-1".to_owned(),
            operation_id: "operation-1".to_owned(),
            idempotency_key: "idempotency-1".to_owned(),
            requester: Requester {
                origin: RequesterOrigin::AdmittedAgent,
                principal: "agent-1".to_owned(),
                session: Some("session-1".to_owned()),
            },
            task_id: "task-1".to_owned(),
            attempt_id: "attempt-1".to_owned(),
            actor: "actor-1".to_owned(),
            route: "route-1".to_owned(),
            context_id: "context-1".to_owned(),
            session_id: "session-1".to_owned(),
            query: "query-1".to_owned(),
            recipe: "recipe-1".to_owned(),
            snapshot: "snapshot-1".to_owned(),
            scope_id: "scope-1".to_owned(),
            state_fence: test_fence(),
            canonical_request_digest: "0".repeat(64),
        };
        identity.canonical_request_digest = identity
            .computed_digest()
            .expect("test request identity canonicalizes");
        identity
    }

    fn test_reactivation_binding() -> ReactivationBinding {
        ReactivationBinding {
            operation_id: "operation-1".to_owned(),
            owner_receipt: "obs-ext-1".to_owned(),
            record_handle: "derived-1".to_owned(),
            record_revision: "rev-2".to_owned(),
            task_id: "task-1".to_owned(),
            attempt_id: "attempt-1".to_owned(),
            actor: "actor-1".to_owned(),
            route: "route-1".to_owned(),
            context_id: "context-1".to_owned(),
            session_id: "session-1".to_owned(),
            query: "query-1".to_owned(),
            recipe: "recipe-1".to_owned(),
            snapshot: "snapshot-1".to_owned(),
            state_fence: test_fence(),
            observation_denominator: TargetDenominator {
                mode: AtomicityMode::AllOrNothing,
                members: vec!["derived-1".to_owned()],
                expected_total: 1,
            },
        }
    }

    fn test_item(receipt: &ValidationReceipt) -> ValidatedCurationItem {
        ValidatedCurationItem {
            receipt: receipt.clone(),
            kind_spelling: "reconsolidation".to_owned(),
            family_spelling: "reconsolidation".to_owned(),
            payload: CurationPayload::Reconsolidation(ReconsolidationPayload {
                target: "derived-1".to_owned(),
                update: "qualified-derived-memory".to_owned(),
                target_evidence: TargetEvidence {
                    targets: vec!["derived-1".to_owned()],
                    evidence_refs: vec!["obs-1".to_owned()],
                },
            }),
            denominator: TargetDenominator {
                mode: AtomicityMode::AllOrNothing,
                members: vec!["derived-1".to_owned()],
                expected_total: 1,
            },
            source_digest: "d".repeat(64),
            task_id: "task-1".to_owned(),
            scope_id: "scope-1".to_owned(),
            state_fence: test_fence(),
            job_digest: "0".repeat(64),
            requester: Requester {
                origin: RequesterOrigin::AdmittedAgent,
                principal: "agent-1".to_owned(),
                session: Some("session-1".to_owned()),
            },
            budget_note: "bounded candidate budget".to_owned(),
        }
    }

    fn test_grounded(receipt: &ValidationReceipt) -> GroundedDreamDraft {
        GroundedDreamDraft {
            schema_version: 1,
            job_id: receipt.job_id.clone(),
            draft_digest: receipt.draft_digest.clone(),
            residues: vec![ClaimResidue {
                claim: "reconsolidation candidate".to_owned(),
                state: SupportState::Supported,
                detail: "the accepted draft is covered by the frozen evidence bundle".to_owned(),
            }],
            coverage_note: "all candidate claims remain addressable".to_owned(),
        }
    }

    fn test_evidence_defaults() -> NewEvidenceItem {
        NewEvidenceItem {
            handle: "evidence-default".to_owned(),
            digest: "0".repeat(64),
            lineage: "lineage-default".to_owned(),
            owner: "owner-observation".to_owned(),
            source_manifest_digest: "c".repeat(64),
            source_revision: "source-rev-1".to_owned(),
            scope: "scope-1".to_owned(),
            authority: "candidate-only".to_owned(),
            privacy: "scope-7".to_owned(),
            independence: EvidenceIndependence::Independent,
            coverage: vec!["p2".to_owned()],
            assurance: "assurance-7".to_owned(),
            statement: "default evidence".to_owned(),
            source_kind: EvidenceSourceKind::ExternalObservation,
            observed_at_ms: Some(1_700_000_000_002),
            freshness_ms: Some(1_700_000_000_002),
        }
    }

    fn test_dependent_record_defaults() -> DependentRecord {
        DependentRecord {
            handle: "dependent-default".to_owned(),
            required: true,
            kind: "summary".to_owned(),
            old_identity: "dependent-old".to_owned(),
            source_identity: "dependent-source".to_owned(),
            owner: "dependent-owner".to_owned(),
            verifier: "dependent-verifier".to_owned(),
        }
    }

    fn test_dependent_outcome_defaults() -> DependentOutcome {
        DependentOutcome {
            handle: "dependent-default".to_owned(),
            disposition: DependentDisposition::Retain,
            note: "dependent remains addressable".to_owned(),
            old_identity: "dependent-old".to_owned(),
            source_identity: "dependent-source".to_owned(),
            new_candidate_identity: "derived-1-rev-3".to_owned(),
            owner: "dependent-owner".to_owned(),
            verifier: "dependent-verifier".to_owned(),
            inverse_note: "set dependent aside before external effects".to_owned(),
            forward_correction: "reconcile dependent forward if verification fails".to_owned(),
            effect_status: EffectObservation::NotAttempted,
        }
    }

    #[allow(clippy::too_many_lines)]
    fn valid_request() -> ReconsolidationRequest {
        let receipt = test_receipt();
        ReconsolidationRequest {
            item: test_item(&receipt),
            grounded: test_grounded(&receipt),
            frozen_bundle_digest: receipt.bundle_digest.clone(),
            frozen_manifest_digest: receipt.manifest_digest.clone(),
            identity: test_identity(),
            curation_kind: CurationKind::Reconsolidation,
            parent: ParentRevision {
                handle: "derived-1".to_owned(),
                schema: "derived-memory/v1".to_owned(),
                revision: "rev-2".to_owned(),
                digest: "9".repeat(64),
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
                    support_revision: "src-a-rev-1".to_owned(),
                    support_digest: "a".repeat(64),
                    lineage: "lineage-a".to_owned(),
                    is_load_bearing: false,
                },
                ParentProposition {
                    id: "p2".to_owned(),
                    statement: "Cold starts stay slow.".to_owned(),
                    support_handle: "src-b".to_owned(),
                    support_revision: "src-b-rev-1".to_owned(),
                    support_digest: "b".repeat(64),
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
            field_paths: vec!["p2.statement".to_owned()],
            new_items: vec![NewEvidenceItem {
                handle: "obs-1".to_owned(),
                digest: "1".repeat(64),
                lineage: "lineage-new-1".to_owned(),
                owner: "owner-observation".to_owned(),
                source_manifest_digest: "c".repeat(64),
                source_revision: "obs-rev-1".to_owned(),
                scope: "scope-1".to_owned(),
                authority: "candidate-only".to_owned(),
                privacy: "scope-7".to_owned(),
                independence: EvidenceIndependence::Independent,
                coverage: vec!["p2".to_owned()],
                assurance: "assurance-7".to_owned(),
                statement: "Warm-up run 7 shortened the next cold start.".to_owned(),
                source_kind: EvidenceSourceKind::ExternalObservation,
                observed_at_ms: Some(1_700_000_000_002),
                freshness_ms: Some(1_700_000_000_002),
            }],
            added_propositions: Vec::new(),
            added_member_denominator: TargetDenominator {
                mode: AtomicityMode::PerMember,
                members: Vec::new(),
                expected_total: 0,
            },
            parent_baseline_handles: vec!["src-a".to_owned(), "src-b".to_owned()],
            parent_baseline_lineages: vec!["lineage-a".to_owned(), "lineage-b".to_owned()],
            parent_baseline_revisions: vec!["src-a-rev-1".to_owned(), "src-b-rev-1".to_owned()],
            parent_baseline_digests: vec!["a".repeat(64), "b".repeat(64)],
            reactivation: ReactivationEvidence {
                checkpoint: "rev-2".to_owned(),
                policy_id: "policy-7".to_owned(),
                external_handle: "obs-ext-1".to_owned(),
                observation_kind: ReactivationObservationKind::ExternalObservation,
                stage: ReactivationStage::QualifyingPublicUse,
                exact_match: true,
                observed_at_ms: Some(1_700_000_000_001),
                binding: test_reactivation_binding(),
            },
            dependents: vec![DependentRecord {
                handle: "dep-1".to_owned(),
                required: true,
                kind: "summary".to_owned(),
                old_identity: "dependent-old".to_owned(),
                source_identity: "dependent-source".to_owned(),
                owner: "dependent-owner".to_owned(),
                verifier: "dependent-verifier".to_owned(),
            }],
            dependent_outcomes: vec![DependentOutcome {
                handle: "dep-1".to_owned(),
                disposition: DependentDisposition::Revalidate,
                note: "revalidate summary against the qualified child".to_owned(),
                old_identity: "dependent-old".to_owned(),
                source_identity: "dependent-source".to_owned(),
                new_candidate_identity: "derived-1-rev-3".to_owned(),
                owner: "dependent-owner".to_owned(),
                verifier: "dependent-verifier".to_owned(),
                inverse_note: "set summary aside before external effects".to_owned(),
                forward_correction: "reconcile summary forward if verification fails".to_owned(),
                effect_status: EffectObservation::NotAttempted,
            }],
            axis_owners: test_owners(),
            preservation: test_preservation(),
            receipt,
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
            policy: test_policy(),
        }
    }

    fn test_bound_call(request: &ReconsolidationRequest) -> BoundCurationCall {
        let screen = ScreenBinding {
            request_id: RequestId::new(&request.identity.request_id).expect("request id"),
            receipt_id: ReceiptId::new("receipt-1").expect("receipt id"),
            screened_targets: vec![request.parent.handle.clone()],
            source_snapshot: request.identity.snapshot.clone(),
            source_revision: request.parent.revision.clone(),
            profile: "profile-1".to_owned(),
            task_id: request.identity.task_id.clone(),
            scope_id: request.identity.scope_id.clone(),
            state_fence: request.identity.state_fence.clone(),
            state: ScreenState::Eligible,
            result_digest: "a".repeat(64),
            item_digest: "b".repeat(64),
        };
        BoundCurationCall {
            port: reconsolidation_handler_port(),
            item: request.item.clone(),
            request: TypedCurationHandlerRequest {
                request_id: request.identity.request_id.clone(),
                receipt_id: "receipt-1".to_owned(),
                source_snapshot: request.identity.snapshot.clone(),
                source_revision: request.parent.revision.clone(),
                profile: "profile-1".to_owned(),
                kind: CurationKind::Reconsolidation,
                family: CurationFamily::Reconsolidation,
                job_id: request.receipt.job_id.clone(),
                scope_id: request.identity.scope_id.clone(),
                task_id: request.identity.task_id.clone(),
                state_fence: request.identity.state_fence.clone(),
                payload: request.item.payload.clone(),
                denominator: request.item.denominator.clone(),
                screen_binding: Some(screen),
            },
            registry_digest: "c".repeat(64),
        }
    }

    fn refresh_identity(request: &mut ReconsolidationRequest) {
        request.identity.canonical_request_digest = request
            .identity
            .computed_digest()
            .expect("test identity digest refreshes");
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

    // WORK_UNIT_CASE: 667/2
    #[test]
    fn case_02_wrong_subtype_or_raw_target_is_rejected() {
        let mut request = valid_request();
        request.curation_kind = CurationKind::Episode;
        let result = propose_reconsolidation(&request).expect("wrong subtype is semantic");
        assert_eq!(result.outcome, ReconsolidationOutcome::Rejected);
        assert!(result.child.is_none());

        for target_kind in [TargetKind::RawEpisode, TargetKind::RawArtifact] {
            let mut request = valid_request();
            request.parent.target_kind = target_kind;
            let result = propose_reconsolidation(&request).expect("raw target is semantic");
            assert_eq!(result.outcome, ReconsolidationOutcome::Rejected);
            assert!(result.child.is_none());
        }
    }

    // WORK_UNIT_CASE: 667/3
    #[test]
    fn case_03_structure_and_repair_routes_are_rejected() {
        for curation_kind in [
            CurationKind::Merge,
            CurationKind::Split,
            CurationKind::Repair,
        ] {
            let mut request = valid_request();
            request.curation_kind = curation_kind;
            let result = propose_reconsolidation(&request).expect("sibling route is semantic");
            assert_eq!(result.outcome, ReconsolidationOutcome::Rejected);
            assert!(result.child.is_none());
        }
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

    // WORK_UNIT_CASE: 667/5
    #[test]
    fn case_05_parent_identity_rejects_self_parent_forks_and_mixed_revisions() {
        let mut self_parent = valid_request();
        self_parent.proposed_child_handle = self_parent.parent.handle.clone();
        let result = propose_reconsolidation(&self_parent).expect("self-parenting is semantic");
        assert_eq!(result.outcome, ReconsolidationOutcome::Rejected);

        for repeated in [
            "derived-1".to_owned(),
            "rev-2".to_owned(),
            "derived-1-rev-3".to_owned(),
        ] {
            let mut fork = valid_request();
            fork.parent.predecessor_chain.push(repeated);
            let result = propose_reconsolidation(&fork).expect("fork identity is semantic");
            assert_eq!(result.outcome, ReconsolidationOutcome::Rejected);
        }

        let mut mixed_frontier = valid_request();
        mixed_frontier.parent.frontier_revision = "rev-1".to_owned();
        let result = propose_reconsolidation(&mixed_frontier)
            .expect("mixed frontier is a stale semantic outcome");
        assert_eq!(result.outcome, ReconsolidationOutcome::Stale);

        let mut mixed_reactivation = valid_request();
        mixed_reactivation.reactivation.checkpoint = "rev-1".to_owned();
        let result = propose_reconsolidation(&mixed_reactivation)
            .expect("mixed reactivation revision is a stale semantic outcome");
        assert_eq!(result.outcome, ReconsolidationOutcome::Stale);
    }

    // WORK_UNIT_CASE: 667/8
    #[test]
    fn case_08_proposal_is_pure_and_does_not_mutate_or_issue() {
        let request = valid_request();
        let frozen = request.clone();
        let first = propose_reconsolidation(&request).expect("pure proposal succeeds");
        let second = propose_reconsolidation(&request).expect("repeat proposal succeeds");

        assert_eq!(request, frozen);
        assert_eq!(first, second);
        let child = first.child.expect("complete result has a request");
        assert!(child.request_only);
        assert!(!child.allocates_revision);
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

    // WORK_UNIT_CASE: 667/10
    #[test]
    fn case_10_availability_and_index_membership_are_insufficient() {
        for observation_kind in [
            ReactivationObservationKind::Availability,
            ReactivationObservationKind::IndexMembership,
        ] {
            let mut request = valid_request();
            request.reactivation.observation_kind = observation_kind;
            let result = propose_reconsolidation(&request)
                .expect("availability and index membership are semantic shortfalls");
            assert_eq!(result.outcome, ReconsolidationOutcome::Abstention);
            assert!(result.child.is_none());
        }
    }

    // WORK_UNIT_CASE: 667/14
    #[test]
    fn case_14_partial_observation_denominator_is_unknown() {
        let mut request = valid_request();
        request.reactivation.observation_kind = ReactivationObservationKind::PartialObservation;
        request.reactivation.exact_match = false;
        let result = propose_reconsolidation(&request).expect("partial observation is an outcome");
        assert_eq!(result.outcome, ReconsolidationOutcome::Abstention);
        assert!(result.child.is_none());
        assert!(result.note.contains("partial observation"));
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

    // WORK_UNIT_CASE: 667/16
    #[test]
    fn case_16_material_evidence_must_follow_reactivation() {
        let mut request = valid_request();
        request.new_items[0].observed_at_ms = Some(1_700_000_000_000);
        request.new_items[0].freshness_ms = Some(1_700_000_000_000);
        let result = propose_reconsolidation(&request).expect("stale ordering is semantic");
        assert_eq!(result.outcome, ReconsolidationOutcome::Stale);
        assert!(result.child.is_none());
    }

    // WORK_UNIT_CASE: 667/17
    #[test]
    fn case_17_duplicate_restatement_shared_lineage_and_model_only_are_not_new() {
        let mut duplicate = valid_request();
        duplicate.new_items.push(NewEvidenceItem {
            handle: "obs-2".to_owned(),
            digest: duplicate.new_items[0].digest.clone(),
            lineage: "lineage-new-2".to_owned(),
            statement: "A distinct handle repeats the same bytes.".to_owned(),
            source_kind: EvidenceSourceKind::ExternalObservation,
            observed_at_ms: Some(1_700_000_000_003),
            freshness_ms: Some(1_700_000_000_003),
            ..test_evidence_defaults()
        });
        duplicate
            .new_items
            .sort_by(|left, right| left.handle.cmp(&right.handle));
        let error = propose_reconsolidation(&duplicate).expect_err("same digest is not new");
        assert!(matches!(error, ReconsolidationError::Source { .. }));

        let mut restated = valid_request();
        restated.new_items[0].handle = "obs-restated".to_owned();
        restated.new_items[0].digest = "2".repeat(64);
        restated.new_items[0].lineage = "lineage-restated".to_owned();
        restated.new_items[0].statement = "Cold starts stay slow.".to_owned();
        restated.new_member_denominator.members = vec!["obs-restated".to_owned()];
        let result =
            propose_reconsolidation(&restated).expect("restatement is a semantic shortfall");
        assert_eq!(
            result.outcome,
            ReconsolidationOutcome::NoMaterialNewEvidence
        );
        assert!(result.child.is_none());

        let mut shared_lineage = valid_request();
        shared_lineage.new_items[0].lineage = "lineage-b".to_owned();
        let result = propose_reconsolidation(&shared_lineage)
            .expect("shared parent lineage is not independent new material");
        assert_eq!(
            result.outcome,
            ReconsolidationOutcome::NoMaterialNewEvidence
        );
        assert!(result.child.is_none());

        let mut model_only = valid_request();
        model_only.new_items[0].source_kind = EvidenceSourceKind::ModelMention;
        let result = propose_reconsolidation(&model_only)
            .expect("model-only mention cannot be material external evidence");
        assert_eq!(
            result.outcome,
            ReconsolidationOutcome::NoMaterialNewEvidence
        );
        assert!(result.child.is_none());
    }

    // WORK_UNIT_CASE: 667/18
    #[test]
    fn case_18_source_manifest_scope_authority_privacy_and_freshness_must_bind() {
        let mut manifest = valid_request();
        manifest.new_items[0].source_manifest_digest = "d".repeat(64);

        let mut scope = valid_request();
        scope.new_items[0].scope = "scope-other".to_owned();

        let mut authority = valid_request();
        authority.new_items[0].authority = "authority-other".to_owned();

        let mut privacy = valid_request();
        privacy.new_items[0].privacy = "privacy-other".to_owned();

        let mut freshness = valid_request();
        freshness.new_items[0].freshness_ms = Some(1_700_000_000_003);

        for (label, request) in vec![
            ("manifest", manifest),
            ("scope", scope),
            ("authority", authority),
            ("privacy", privacy),
            ("freshness", freshness),
        ]
        .into_boxed_slice()
        {
            let result = propose_reconsolidation(&request)
                .expect("source contract violations are bounded semantic blocks");
            assert_eq!(result.outcome, ReconsolidationOutcome::Blocked, "{label}");
            assert!(result.child.is_none(), "{label} must not produce a child");
        }
    }

    // WORK_UNIT_CASE: 667/19
    #[test]
    fn case_19_retained_proposition_is_byte_exact_in_the_child() {
        let request = valid_request();
        let parent = request
            .parent_propositions
            .iter()
            .find(|proposition| proposition.id == "p1")
            .expect("fixture has the retained proposition");
        let result = propose_reconsolidation(&request).expect("valid request succeeds");
        let child = result
            .child
            .expect("complete result carries a child projection");
        let retained = child
            .propositions
            .iter()
            .find(|proposition| proposition.id == parent.id)
            .expect("retained proposition remains in the child");

        assert_eq!(retained.statement, parent.statement);
        assert_eq!(retained.support_handle, parent.support_handle);
        assert_eq!(retained.support_revision, parent.support_revision);
        assert_eq!(retained.support_digest, parent.support_digest);
        assert_eq!(retained.lineage, parent.lineage);
        assert_eq!(retained.evidence_refs, Vec::<String>::new());
        assert_eq!(
            retained.parent_proposition_id.as_deref(),
            Some(parent.id.as_str())
        );
    }

    #[test]
    fn supplemental_distinct_evidence_under_a_fresh_lineage_is_admitted() {
        let mut request = valid_request();
        request.new_items.push(NewEvidenceItem {
            handle: "obs-2".to_owned(),
            digest: "2".repeat(64),
            lineage: "lineage-new-2".to_owned(),
            statement: "Warm-up run 8 shortened another cold start.".to_owned(),
            source_kind: EvidenceSourceKind::ExternalObservation,
            observed_at_ms: Some(1_700_000_000_003),
            freshness_ms: Some(1_700_000_000_003),
            ..test_evidence_defaults()
        });
        request
            .new_items
            .sort_by(|left, right| left.handle.cmp(&right.handle));
        request.new_member_denominator.members = vec!["obs-1".to_owned(), "obs-2".to_owned()];
        request.new_member_denominator.expected_total = 2;
        let result = propose_reconsolidation(&request).expect("distinct evidence is material");
        assert_eq!(result.outcome, ReconsolidationOutcome::Complete);
        assert_eq!(result.admitted_new, 2);

        let mut changed_baseline = valid_request();
        changed_baseline.new_items[0].handle = "src-a".to_owned();
        changed_baseline.new_items[0].lineage = "lineage-a".to_owned();
        changed_baseline.new_items[0].source_revision = "src-a-rev-2".to_owned();
        changed_baseline.new_items[0].digest = "c".repeat(64);
        let result = propose_reconsolidation(&changed_baseline)
            .expect("changed baseline bytes are a semantic identity conflict");
        assert_eq!(result.outcome, ReconsolidationOutcome::Blocked);

        let mut wrong_scope = valid_request();
        wrong_scope.new_items[0].scope = "scope-other".to_owned();
        let result = propose_reconsolidation(&wrong_scope)
            .expect("evidence outside the request scope is rejected semantically");
        assert_eq!(result.outcome, ReconsolidationOutcome::Blocked);
    }

    #[test]
    fn supplemental_stale_material_precedes_surviving_material() {
        let mut request = valid_request();
        request.new_items.push(NewEvidenceItem {
            handle: "obs-0".to_owned(),
            digest: "0".repeat(64),
            lineage: "lineage-new-0".to_owned(),
            statement: "Stale warm-up observation.".to_owned(),
            source_kind: EvidenceSourceKind::ExternalObservation,
            observed_at_ms: Some(1_700_000_000_001),
            freshness_ms: Some(1_700_000_000_001),
            ..test_evidence_defaults()
        });
        request
            .new_items
            .sort_by(|left, right| left.handle.cmp(&right.handle));
        let result = propose_reconsolidation(&request).expect("stale order is semantic");
        assert_eq!(result.outcome, ReconsolidationOutcome::Stale);
        assert!(result.child.is_none());
    }

    #[test]
    fn supplemental_unknown_temporal_precedes_stale_material() {
        let mut request = valid_request();
        request.new_items.extend([
            NewEvidenceItem {
                handle: "obs-0".to_owned(),
                digest: "0".repeat(64),
                lineage: "lineage-new-0".to_owned(),
                statement: "Stale warm-up observation.".to_owned(),
                source_kind: EvidenceSourceKind::ExternalObservation,
                observed_at_ms: Some(1_700_000_000_001),
                freshness_ms: Some(1_700_000_000_001),
                ..test_evidence_defaults()
            },
            NewEvidenceItem {
                handle: "obs-2".to_owned(),
                digest: "2".repeat(64),
                lineage: "lineage-new-2".to_owned(),
                statement: "Unknown-time warm-up observation.".to_owned(),
                source_kind: EvidenceSourceKind::ExternalObservation,
                observed_at_ms: None,
                freshness_ms: None,
                ..test_evidence_defaults()
            },
        ]);
        request
            .new_items
            .sort_by(|left, right| left.handle.cmp(&right.handle));
        let result = propose_reconsolidation(&request).expect("unknown order abstains");
        assert_eq!(result.outcome, ReconsolidationOutcome::Abstention);
        assert!(result.child.is_none());
    }

    // WORK_UNIT_CASE: 667/20
    #[test]
    fn case_20_new_member_denominator_is_exact() {
        let mut request = valid_request();
        request
            .new_member_denominator
            .members
            .push("extra".to_owned());
        request.new_member_denominator.expected_total = 2;
        let result = propose_reconsolidation(&request).expect("denominator mismatch is semantic");
        assert_eq!(result.outcome, ReconsolidationOutcome::Blocked);
        assert!(result.child.is_none());
    }

    // WORK_UNIT_CASE: 667/21
    #[test]
    fn case_21_narrowed_and_qualified_propositions_use_new_evidence() {
        for (disposition, revised_statement) in [
            (
                PropositionDisposition::Narrowed,
                "Cold starts stay slow when no warm-up was observed.",
            ),
            (
                PropositionDisposition::Qualified,
                "Cold starts stay slow except after the observed warm-up.",
            ),
        ] {
            let mut request = valid_request();
            request.deltas[1].disposition = disposition;
            request.deltas[1].revised_statement = Some(revised_statement.to_owned());
            request.deltas[1].evidence_refs = vec!["obs-1".to_owned()];

            let result = propose_reconsolidation(&request)
                .expect("narrowed and qualified deltas are well-formed");
            assert_eq!(result.outcome, ReconsolidationOutcome::Complete);
            assert_eq!(result.accounted_parents, 2);
            assert_eq!(result.admitted_new, 1);
        }
    }

    // WORK_UNIT_CASE: 667/22
    #[test]
    fn case_22_contradiction_requires_new_evidence_reference() {
        let mut request = valid_request();
        request.deltas[1].disposition = PropositionDisposition::Contradicted;
        request.deltas[1].evidence_refs = vec!["src-b".to_owned()];
        let result =
            propose_reconsolidation(&request).expect("unsupported contradiction is semantic");
        assert_eq!(result.outcome, ReconsolidationOutcome::NoSafeRevision);
        assert!(result.child.is_none());
    }

    // WORK_UNIT_CASE: 667/23
    #[test]
    fn case_23_withdrawal_requires_new_evidence_reference() {
        let mut request = valid_request();
        request.deltas[1].disposition = PropositionDisposition::Withdrawn;
        request.deltas[1].revised_statement = None;
        request.deltas[1].evidence_refs.clear();
        let result = propose_reconsolidation(&request).expect("unsupported withdrawal is semantic");
        assert_eq!(result.outcome, ReconsolidationOutcome::NoSafeRevision);
        assert!(result.child.is_none());
    }

    // WORK_UNIT_CASE: 667/24
    #[test]
    fn case_24_load_bearing_unresolved_material_blocks() {
        let mut request = valid_request();
        request.parent_propositions[1].is_load_bearing = true;
        request.deltas[1].disposition = PropositionDisposition::Unresolved;
        request.deltas[1].revised_statement = None;
        let result = propose_reconsolidation(&request).expect("unresolved is semantic");
        assert_eq!(result.outcome, ReconsolidationOutcome::Blocked);
        assert!(result.child.is_none());
    }

    // WORK_UNIT_CASE: 667/25
    #[test]
    fn case_25_unsupported_precision_or_grade_escalation_is_rejected() {
        for revised_statement in [
            "Cold starts stay slow within 250 ms.",
            "Cold starts are always slow except after the observed warm-up.",
        ] {
            let mut request = valid_request();
            request.deltas[1].revised_statement = Some(revised_statement.to_owned());
            let result = propose_reconsolidation(&request)
                .expect("unsupported precision and strength are semantic outcomes");
            assert_eq!(result.outcome, ReconsolidationOutcome::NoSafeRevision);
            assert!(result.child.is_none());
            assert!(result.note.contains("unsupported precision"));
        }
    }

    // WORK_UNIT_CASE: 667/26
    #[test]
    fn case_26_every_parent_proposition_is_accounted_once() {
        let mut request = valid_request();
        request.parent_propositions.push(ParentProposition {
            id: "p3".to_owned(),
            statement: "Warm keys remain addressable.".to_owned(),
            support_handle: "src-c".to_owned(),
            support_revision: "src-c-rev-1".to_owned(),
            support_digest: "c".repeat(64),
            lineage: "lineage-c".to_owned(),
            is_load_bearing: false,
        });
        request.parent_baseline_handles.push("src-c".to_owned());
        request
            .parent_baseline_lineages
            .push("lineage-c".to_owned());
        request
            .parent_baseline_revisions
            .push("src-c-rev-1".to_owned());
        request.parent_baseline_digests.push("c".repeat(64));

        let result = propose_reconsolidation(&request).expect("missing accounting is semantic");
        assert_eq!(result.outcome, ReconsolidationOutcome::Blocked);
        assert!(result.child.is_none());
        assert!(result.note.contains("every parent proposition"));
    }

    // WORK_UNIT_CASE: 667/27
    #[test]
    fn case_27_missing_duplicate_or_unmapped_proposition_is_rejected() {
        let mut missing = valid_request();
        missing.deltas.pop();
        let result = propose_reconsolidation(&missing).expect("missing delta is semantic");
        assert_eq!(result.outcome, ReconsolidationOutcome::Blocked);
        assert!(result.child.is_none());

        let mut duplicate = valid_request();
        duplicate.deltas[1].proposition_id = "p1".to_owned();
        let error = propose_reconsolidation(&duplicate).expect_err("duplicate delta is malformed");
        assert!(matches!(error, ReconsolidationError::Order { phase, .. } if phase == "deltas"));

        let mut unmapped = valid_request();
        unmapped.deltas[1].proposition_id = "p3".to_owned();
        let result = propose_reconsolidation(&unmapped).expect("unmapped delta is semantic");
        assert_eq!(result.outcome, ReconsolidationOutcome::Blocked);
        assert!(result.child.is_none());
        assert!(result.note.contains("unknown parent proposition"));
    }

    // WORK_UNIT_CASE: 667/28
    #[test]
    fn case_28_cosmetic_or_reordered_only_delta_is_rejected() {
        let mut cosmetic = valid_request();
        cosmetic.deltas[1].revised_statement = Some("  cold STARTS stay slow.  ".to_owned());
        let result = propose_reconsolidation(&cosmetic)
            .expect("cosmetic wording changes are semantic outcomes");
        assert_eq!(result.outcome, ReconsolidationOutcome::NoSafeRevision);
        assert!(result.child.is_none());
        assert!(result.note.contains("cosmetic-only"));

        let mut reordered = valid_request();
        reordered.deltas.reverse();
        let error = propose_reconsolidation(&reordered).expect_err("delta order is deterministic");
        assert!(matches!(error, ReconsolidationError::Order { phase, .. } if phase == "deltas"));
    }

    // WORK_UNIT_CASE: 667/29
    #[test]
    fn case_29_independent_memory_axis_owners_are_preserved() {
        let mut request = valid_request();
        let frozen_owners = request.axis_owners.clone();
        let frozen_preservation = request.preservation.clone();
        request.deltas[1].rationale =
            "new evidence changes content only; every independent axis remains caller-owned"
                .to_owned();

        let result = propose_reconsolidation(&request).expect("axis-preserving candidate succeeds");

        assert_eq!(result.outcome, ReconsolidationOutcome::Complete);
        assert_eq!(request.axis_owners, frozen_owners);
        assert_eq!(request.preservation, frozen_preservation);
        let child = result.child.expect("complete result carries a request");
        assert!(child.request_only);
        assert!(!child.allocates_revision);
    }

    // WORK_UNIT_CASE: 667/30
    #[test]
    fn case_30_contradiction_preserves_old_support_without_axis_demotion() {
        let mut request = valid_request();
        let frozen_parent = request.parent_propositions.clone();
        let frozen_owners = request.axis_owners.clone();
        request.deltas[1].disposition = PropositionDisposition::Contradicted;
        request.deltas[1].revised_statement =
            Some("Cold starts can be fast after the observed warm-up.".to_owned());
        request.deltas[1].rationale =
            "obs-1 is a counterexample; retain the prior proposition and support".to_owned();
        request.deltas[1].evidence_refs = vec!["obs-1".to_owned()];

        let result = propose_reconsolidation(&request).expect("supported contradiction is safe");

        assert_eq!(result.outcome, ReconsolidationOutcome::Complete);
        assert_eq!(request.parent_propositions, frozen_parent);
        assert_eq!(request.axis_owners, frozen_owners);
        assert_eq!(request.parent_propositions[1].support_handle, "src-b");
        assert_eq!(request.new_items[0].handle, "obs-1");
    }

    // WORK_UNIT_CASE: 667/31
    #[test]
    fn case_31_low_use_does_not_reduce_support_or_trigger_revision() {
        let mut request = valid_request();
        let frozen_support = request.parent_propositions[1].support_handle.clone();
        let frozen_support_owner = request.axis_owners.support_owner.clone();
        request.deltas[1].rationale =
            "low use is an ecology observation, not evidence to reduce support".to_owned();
        request.dependent_outcomes[0].note =
            "low retrieval use leaves the supported proposition unchanged".to_owned();

        let result = propose_reconsolidation(&request).expect("low-use candidate remains bounded");

        assert_eq!(result.outcome, ReconsolidationOutcome::Complete);
        assert_eq!(
            request.parent_propositions[1].support_handle,
            frozen_support
        );
        assert_eq!(request.axis_owners.support_owner, frozen_support_owner);
        assert_eq!(result.admitted_new, 1);
    }

    // WORK_UNIT_CASE: 667/32
    #[test]
    fn case_32_new_support_cannot_widen_influence() {
        let mut request = valid_request();
        let frozen_influence_owner = request.axis_owners.influence_owner.clone();
        request.deltas[1].rationale =
            "obs-1 adds local support without widening the influence owner or scope".to_owned();

        let result = propose_reconsolidation(&request).expect("support-bounded candidate succeeds");

        assert_eq!(result.outcome, ReconsolidationOutcome::Complete);
        assert_eq!(request.axis_owners.influence_owner, frozen_influence_owner);
        let child = result.child.expect("complete result carries a request");
        assert_eq!(child.parent_handle, "derived-1");
        assert_eq!(child.parent_revision, "rev-2");
    }

    // WORK_UNIT_CASE: 667/33
    #[test]
    fn case_33_raw_evidence_identity_and_parent_bytes_remain_unchanged() {
        let request = valid_request();
        let frozen = request.clone();

        let result =
            propose_reconsolidation(&request).expect("candidate preserves source identity");

        assert_eq!(result.outcome, ReconsolidationOutcome::Complete);
        assert_eq!(request.parent, frozen.parent);
        assert_eq!(request.parent_propositions, frozen.parent_propositions);
        assert_eq!(request.new_items, frozen.new_items);
        assert_eq!(request.new_items[0].digest, "1".repeat(64));
    }

    // WORK_UNIT_CASE: 667/34
    #[test]
    fn case_34_parent_history_and_change_reason_remain_addressable() {
        let mut request = valid_request();
        request.deltas[1].rationale =
            "change reason: observed warm-up outcome qualified the parent claim".to_owned();
        let frozen_parent = request.parent.clone();
        let frozen_reason = request.deltas[1].rationale.clone();

        let result =
            propose_reconsolidation(&request).expect("history-addressable candidate succeeds");
        let child = result.child.expect("complete result carries a request");

        assert_eq!(result.outcome, ReconsolidationOutcome::Complete);
        assert_eq!(child.parent_handle, frozen_parent.handle);
        assert_eq!(child.parent_revision, frozen_parent.revision);
        assert_eq!(
            request.parent.predecessor_chain,
            frozen_parent.predecessor_chain
        );
        assert_eq!(request.deltas[1].rationale, frozen_reason);
        assert_ne!(child.proposed_child_handle, child.parent_revision);
    }

    // WORK_UNIT_CASE: 667/35
    #[test]
    fn case_35_counterexample_minority_conflict_and_provenance_are_retained() {
        let mut request = valid_request();
        request.new_items[0].lineage = "minority-lineage-1".to_owned();
        request.new_items[0].statement =
            "Counterexample: one warm-up run shortened the next cold start.".to_owned();
        request.deltas[1].rationale =
            "preserve the minority counterexample and conflict provenance from obs-1".to_owned();
        let frozen_parent = request.parent_propositions[1].clone();
        let frozen_evidence = request.new_items[0].clone();

        let result =
            propose_reconsolidation(&request).expect("provenance-preserving candidate succeeds");

        assert_eq!(result.outcome, ReconsolidationOutcome::Complete);
        assert_eq!(request.parent_propositions[1], frozen_parent);
        assert_eq!(request.new_items[0], frozen_evidence);
        assert_eq!(request.new_items[0].lineage, "minority-lineage-1");
        assert!(request.deltas[1].rationale.contains("counterexample"));
        assert!(request.deltas[1].rationale.contains("provenance"));
    }

    // WORK_UNIT_CASE: 667/37
    #[allow(clippy::too_many_lines)]
    #[test]
    fn case_37_every_affected_dependent_has_an_exact_disposition() {
        let mut request = valid_request();
        request.dependents = vec![
            DependentRecord {
                handle: "dep-01".to_owned(),
                required: true,
                kind: "relation".to_owned(),
                ..test_dependent_record_defaults()
            },
            DependentRecord {
                handle: "dep-02".to_owned(),
                required: true,
                kind: "view".to_owned(),
                ..test_dependent_record_defaults()
            },
            DependentRecord {
                handle: "dep-03".to_owned(),
                required: true,
                kind: "procedure".to_owned(),
                ..test_dependent_record_defaults()
            },
            DependentRecord {
                handle: "dep-04".to_owned(),
                required: true,
                kind: "cue".to_owned(),
                ..test_dependent_record_defaults()
            },
            DependentRecord {
                handle: "dep-05".to_owned(),
                required: true,
                kind: "index".to_owned(),
                ..test_dependent_record_defaults()
            },
            DependentRecord {
                handle: "dep-06".to_owned(),
                required: true,
                kind: "decision".to_owned(),
                ..test_dependent_record_defaults()
            },
            DependentRecord {
                handle: "dep-07".to_owned(),
                required: true,
                kind: "claim".to_owned(),
                ..test_dependent_record_defaults()
            },
            DependentRecord {
                handle: "dep-08".to_owned(),
                required: true,
                kind: "axis".to_owned(),
                ..test_dependent_record_defaults()
            },
            DependentRecord {
                handle: "dep-09".to_owned(),
                required: true,
                kind: "negative-memory".to_owned(),
                ..test_dependent_record_defaults()
            },
        ];
        request.dependent_outcomes = vec![
            DependentOutcome {
                handle: "dep-01".to_owned(),
                disposition: DependentDisposition::Retain,
                note: "relation remains valid under the proposed child".to_owned(),
                ..test_dependent_outcome_defaults()
            },
            DependentOutcome {
                handle: "dep-02".to_owned(),
                disposition: DependentDisposition::UnaffectedWithEvidence,
                note: "view remains unaffected with evidence".to_owned(),
                ..test_dependent_outcome_defaults()
            },
            DependentOutcome {
                handle: "dep-03".to_owned(),
                disposition: DependentDisposition::Revalidate,
                note: "procedure requires child validation".to_owned(),
                ..test_dependent_outcome_defaults()
            },
            DependentOutcome {
                handle: "dep-04".to_owned(),
                disposition: DependentDisposition::Rebuild,
                note: "cue is rebuilt from the proposed child".to_owned(),
                ..test_dependent_outcome_defaults()
            },
            DependentOutcome {
                handle: "dep-05".to_owned(),
                disposition: DependentDisposition::Invalidate,
                note: "index entry is invalidated pending rebuild".to_owned(),
                ..test_dependent_outcome_defaults()
            },
            DependentOutcome {
                handle: "dep-06".to_owned(),
                disposition: DependentDisposition::Retarget,
                note: "decision points at the proposed child".to_owned(),
                ..test_dependent_outcome_defaults()
            },
            DependentOutcome {
                handle: "dep-07".to_owned(),
                disposition: DependentDisposition::Reconcile,
                note: "claim reconciles parent and child evidence".to_owned(),
                ..test_dependent_outcome_defaults()
            },
            DependentOutcome {
                handle: "dep-08".to_owned(),
                disposition: DependentDisposition::Retain,
                note: "axis owner remains caller-owned".to_owned(),
                ..test_dependent_outcome_defaults()
            },
            DependentOutcome {
                handle: "dep-09".to_owned(),
                disposition: DependentDisposition::UnaffectedWithEvidence,
                note: "negative memory remains addressable".to_owned(),
                ..test_dependent_outcome_defaults()
            },
        ];

        let expected_categories = [
            ("relation", DependentDisposition::Retain),
            ("view", DependentDisposition::UnaffectedWithEvidence),
            ("procedure", DependentDisposition::Revalidate),
            ("cue", DependentDisposition::Rebuild),
            ("index", DependentDisposition::Invalidate),
            ("decision", DependentDisposition::Retarget),
            ("claim", DependentDisposition::Reconcile),
            ("axis", DependentDisposition::Retain),
            (
                "negative-memory",
                DependentDisposition::UnaffectedWithEvidence,
            ),
        ];
        assert_eq!(request.dependents.len(), expected_categories.len());
        for (kind, expected_disposition) in expected_categories {
            let dependent = request
                .dependents
                .iter()
                .find(|dependent| dependent.kind == kind)
                .expect("every required dependent category is represented");
            assert!(dependent.required, "{kind} is required for completeness");
            let outcome = request
                .dependent_outcomes
                .iter()
                .find(|outcome| outcome.handle == dependent.handle)
                .expect("every required dependent category has one outcome");
            assert_eq!(outcome.disposition, expected_disposition, "{kind}");
            assert_eq!(outcome.old_identity, dependent.old_identity, "{kind}");
            assert_eq!(outcome.source_identity, dependent.source_identity, "{kind}");
            assert_eq!(outcome.owner, dependent.owner, "{kind}");
            assert_eq!(outcome.verifier, dependent.verifier, "{kind}");
            assert_eq!(
                outcome.new_candidate_identity, request.proposed_child_handle,
                "{kind}"
            );
        }
        let frozen = request.clone();

        let result = propose_reconsolidation(&request).expect("complete dependency closure passes");

        assert_eq!(result.outcome, ReconsolidationOutcome::Complete);
        assert_eq!(result.accounted_parents, 2);
        assert_eq!(result.admitted_new, 1);
        assert_eq!(request, frozen);
    }

    // WORK_UNIT_CASE: 667/38
    #[test]
    fn case_38_missing_or_unknown_dependent_blocks_completeness() {
        let mut missing = valid_request();
        missing.dependents.push(DependentRecord {
            handle: "dep-2".to_owned(),
            required: true,
            kind: "view".to_owned(),
            ..test_dependent_record_defaults()
        });
        let result = propose_reconsolidation(&missing).expect("missing outcome is semantic");
        assert_eq!(result.outcome, ReconsolidationOutcome::Blocked);
        assert!(result.child.is_none());

        let mut unknown = valid_request();
        unknown.dependents.push(DependentRecord {
            handle: "dep-2".to_owned(),
            required: false,
            kind: "view".to_owned(),
            ..test_dependent_record_defaults()
        });
        unknown.dependent_outcomes.push(DependentOutcome {
            handle: "dep-3".to_owned(),
            disposition: DependentDisposition::Retain,
            note: "not an affected dependent".to_owned(),
            ..test_dependent_outcome_defaults()
        });
        let result = propose_reconsolidation(&unknown).expect("unknown outcome is semantic");
        assert_eq!(result.outcome, ReconsolidationOutcome::Blocked);
        assert!(result.child.is_none());
        assert!(result.note.contains("exactly cover"));
    }

    #[test]
    fn duplicate_dependent_handle_is_blocked() {
        let mut request = valid_request();
        request.dependents.push(DependentRecord {
            handle: "dep-1".to_owned(),
            required: false,
            kind: "secondary-summary".to_owned(),
            ..test_dependent_record_defaults()
        });
        request.dependent_outcomes.push(DependentOutcome {
            handle: "dep-1".to_owned(),
            disposition: DependentDisposition::Retain,
            note: "second disposition must not be reused".to_owned(),
            ..test_dependent_outcome_defaults()
        });

        let result = propose_reconsolidation(&request).expect("duplicate dependent is semantic");
        assert_eq!(result.outcome, ReconsolidationOutcome::Blocked);
        assert!(result.child.is_none());
    }

    #[test]
    fn duplicate_outcome_handle_is_blocked() {
        let mut request = valid_request();
        request.dependents.push(DependentRecord {
            handle: "dep-1".to_owned(),
            required: true,
            kind: "secondary-summary".to_owned(),
            ..test_dependent_record_defaults()
        });
        request.dependent_outcomes.push(DependentOutcome {
            handle: "dep-1".to_owned(),
            disposition: DependentDisposition::Blocked,
            note: "second disposition must not be silently usable".to_owned(),
            ..test_dependent_outcome_defaults()
        });

        let result = propose_reconsolidation(&request).expect("duplicate outcome is semantic");
        assert_eq!(result.outcome, ReconsolidationOutcome::Blocked);
        assert!(result.child.is_none());
    }

    // WORK_UNIT_CASE: 667/40
    #[test]
    fn case_40_inverse_path_is_ready_before_external_effects() {
        let mut request = valid_request();
        request.child_inverse_note =
            "set aside derived-1-rev-3 before external effects and restore derived-1 rev-2"
                .to_owned();
        let frozen = request.clone();

        let result = propose_reconsolidation(&request).expect("inverse path is eligible");
        let child = result
            .child
            .expect("complete result carries an allocation request");

        assert_eq!(result.outcome, ReconsolidationOutcome::Complete);
        assert_eq!(child.parent_handle, request.parent.handle);
        assert_eq!(child.parent_revision, request.parent.revision);
        assert_eq!(child.inverse_note, request.child_inverse_note);
        assert!(child.request_only);
        assert!(!child.allocates_revision);
        assert_eq!(request, frozen);
    }

    // WORK_UNIT_CASE: 667/41
    #[test]
    fn case_41_forward_correction_is_bound_to_the_proposed_child() {
        let mut request = valid_request();
        request.child_forward_correction =
            "if the later write is rejected, issue a forward correction for derived-1-rev-3"
                .to_owned();

        let result = propose_reconsolidation(&request).expect("forward correction is carried");
        let child = result
            .child
            .expect("complete result carries an allocation request");

        assert_eq!(result.outcome, ReconsolidationOutcome::Complete);
        assert_eq!(child.proposed_child_handle, request.proposed_child_handle);
        assert_eq!(child.forward_correction, request.child_forward_correction);
        assert_eq!(child.expiry_ms, request.child_expiry_ms);
        assert_eq!(child.reopen_condition, request.child_reopen_condition);
        assert!(child.request_only);
        assert!(!child.allocates_revision);
    }

    // WORK_UNIT_CASE: 667/39
    #[test]
    fn case_39_unaffected_dependent_keeps_an_explicit_note() {
        let mut request = valid_request();
        request.dependent_outcomes[0].disposition = DependentDisposition::UnaffectedWithEvidence;
        request.dependent_outcomes[0].note =
            "new evidence leaves this summary unaffected".to_owned();
        let result = propose_reconsolidation(&request).expect("explicit dependent note is valid");
        assert_eq!(result.outcome, ReconsolidationOutcome::Complete);
    }

    // WORK_UNIT_CASE: 667/42
    #[test]
    fn case_42_unknown_effect_blocks_blind_rollback_or_retry() {
        let mut request = valid_request();
        request.dependent_outcomes[0].effect_status = EffectObservation::Unknown;
        let result =
            propose_reconsolidation(&request).expect("unknown effects are semantic blocks");
        assert_eq!(result.outcome, ReconsolidationOutcome::Blocked);
        assert!(result.child.is_none());
        assert!(result.note.contains("unknown external effect"));
    }

    // WORK_UNIT_CASE: 667/43
    #[test]
    fn case_43_missing_parent_verifier_or_reopen_is_rejected() {
        let mut missing_parent = valid_request();
        missing_parent.parent.handle.clear();
        let error = propose_reconsolidation(&missing_parent)
            .expect_err("a missing parent handle cannot produce a candidate");
        assert!(matches!(
            error,
            ReconsolidationError::Bounds { phase, .. } if phase == "parent.handle"
        ));

        let mut missing_verifier = valid_request();
        missing_verifier.child_verifier.clear();
        let error = propose_reconsolidation(&missing_verifier)
            .expect_err("a missing child verifier cannot produce a candidate");
        assert!(matches!(
            error,
            ReconsolidationError::Bounds { phase, .. } if phase == "child.verifier"
        ));

        let mut missing_reopen = valid_request();
        missing_reopen.child_reopen_condition.clear();
        let error = propose_reconsolidation(&missing_reopen)
            .expect_err("a missing reopen condition cannot produce a candidate");
        assert!(matches!(
            error,
            ReconsolidationError::Bounds { phase, .. } if phase == "child.reopen"
        ));
    }

    // WORK_UNIT_CASE: 667/44
    #[test]
    fn case_44_candidate_has_no_applied_dependent_or_write_receipt() {
        let request = valid_request();
        let frozen = request.clone();

        let result = propose_reconsolidation(&request).expect("candidate remains pure");
        let child = result
            .child
            .expect("complete result carries an allocation request");

        assert_eq!(result.outcome, ReconsolidationOutcome::Complete);
        assert_eq!(request, frozen);
        assert_eq!(request.dependent_outcomes, frozen.dependent_outcomes);
        assert!(child.request_only);
        assert!(!child.allocates_revision);

        let handler = ReconsolidationHandler::new(request.clone());
        let produced = handler
            .handle(&test_bound_call(&request))
            .expect("A-03 native handler invocation returns inert content");
        assert_eq!(produced.disposition, CandidateDisposition::Candidate);
        assert_eq!(produced.payload, request.item.payload);
        assert!(produced.support_note.contains("forward child revision"));
        assert_eq!(produced.rollback_note, request.child_inverse_note);
    }

    // WORK_UNIT_CASE: 667/45
    #[test]
    fn case_45_all_seven_preservation_dimensions_pass() {
        let request = valid_request();
        let expected = [
            PreservationDimension::Coverage,
            PreservationDimension::Faithfulness,
            PreservationDimension::Lineage,
            PreservationDimension::Reversibility,
            PreservationDimension::AuthorityCeiling,
            PreservationDimension::DependencyClosure,
            PreservationDimension::ProvenanceRetention,
        ];

        assert_eq!(request.preservation.verdicts.len(), expected.len());
        for dimension in expected {
            let verdict = request
                .preservation
                .verdicts
                .iter()
                .find(|verdict| verdict.dimension == dimension)
                .expect("each preservation dimension is represented");
            assert!(verdict.passed && verdict.known);
        }
        assert!(request.preservation.overall().is_ok());
        assert_eq!(
            propose_reconsolidation(&request)
                .expect("all preservation dimensions pass")
                .outcome,
            ReconsolidationOutcome::Complete
        );
    }

    // WORK_UNIT_CASE: 667/46
    #[test]
    fn case_46_failed_or_unknown_dimension_blocks_without_postflight() {
        let request = valid_request();
        let frozen_receipt = request.receipt.clone();

        for index in 0..request.preservation.verdicts.len() {
            let mut failed = request.clone();
            failed.preservation.verdicts[index].passed = false;
            let result = propose_reconsolidation(&failed).expect("failed dimension is semantic");
            assert_eq!(result.outcome, ReconsolidationOutcome::Blocked);
            assert!(result.child.is_none());
            assert_eq!(result.admitted_new, 1);
            assert_eq!(failed.receipt, frozen_receipt);

            let mut unknown = request.clone();
            unknown.preservation.verdicts[index].known = false;
            let result = propose_reconsolidation(&unknown).expect("unknown dimension is semantic");
            assert_eq!(result.outcome, ReconsolidationOutcome::Blocked);
            assert!(result.child.is_none());
            assert_eq!(result.admitted_new, 1);
            assert_eq!(unknown.receipt, frozen_receipt);
        }
    }

    // WORK_UNIT_CASE: 667/47
    #[test]
    fn case_47_terminal_outcomes_remain_distinct() {
        let complete = propose_reconsolidation(&valid_request())
            .expect("valid request is complete")
            .outcome;

        let mut partial_request = valid_request();
        partial_request.deltas[0].disposition = PropositionDisposition::Unresolved;
        let partial = propose_reconsolidation(&partial_request)
            .expect("non-load-bearing unresolved material is partial")
            .outcome;

        let mut abstention_request = valid_request();
        abstention_request.reactivation.observation_kind =
            ReactivationObservationKind::Availability;
        let abstention = propose_reconsolidation(&abstention_request)
            .expect("availability is abstention")
            .outcome;

        let mut stale_request = valid_request();
        stale_request.new_items[0].observed_at_ms = Some(1_700_000_000_001);
        stale_request.new_items[0].freshness_ms = Some(1_700_000_000_001);
        let stale = propose_reconsolidation(&stale_request)
            .expect("pre-reactivation evidence is stale")
            .outcome;

        let mut rejected_request = valid_request();
        rejected_request.curation_kind = CurationKind::Episode;
        let rejected = propose_reconsolidation(&rejected_request)
            .expect("wrong curation kind is rejected")
            .outcome;

        let outcomes = [complete, partial, abstention, stale, rejected];
        for (index, outcome) in outcomes.iter().enumerate() {
            assert!(
                !outcomes[..index].contains(outcome),
                "terminal outcome {outcome:?} must remain distinct"
            );
        }
        assert_eq!(complete, ReconsolidationOutcome::Complete);
        assert_eq!(partial, ReconsolidationOutcome::Partial);
        assert_eq!(abstention, ReconsolidationOutcome::Abstention);
        assert_eq!(stale, ReconsolidationOutcome::Stale);
        assert_eq!(rejected, ReconsolidationOutcome::Rejected);
    }

    // WORK_UNIT_CASE: 667/48
    #[test]
    fn case_48_set_order_keeps_candidate_and_receipt_deterministic() {
        let mut canonical = valid_request();
        canonical.new_items.push(NewEvidenceItem {
            handle: "obs-2".to_owned(),
            digest: "2".repeat(64),
            lineage: "lineage-new-2".to_owned(),
            statement: "Warm-up run 8 shortened the next cold start further.".to_owned(),
            source_kind: EvidenceSourceKind::ExternalObservation,
            observed_at_ms: Some(1_700_000_000_003),
            freshness_ms: Some(1_700_000_000_003),
            ..test_evidence_defaults()
        });
        canonical.new_member_denominator.members = vec!["obs-1".to_owned(), "obs-2".to_owned()];
        canonical.new_member_denominator.expected_total = 2;

        let mut reordered = canonical.clone();
        reordered.new_member_denominator.members.reverse();
        reordered.preservation.verdicts.reverse();

        let canonical_result =
            propose_reconsolidation(&canonical).expect("canonical set order succeeds");
        let reordered_result =
            propose_reconsolidation(&reordered).expect("equivalent set order succeeds");

        assert_eq!(canonical_result, reordered_result);
        assert_eq!(canonical.receipt, reordered.receipt);
        assert_eq!(canonical_result.outcome, ReconsolidationOutcome::Complete);
    }

    // WORK_UNIT_CASE: 667/49
    #[test]
    fn case_49_every_independent_bound_rejects_one_over() {
        let assert_bound_error = |request: ReconsolidationRequest, phase: &str| {
            let error = propose_reconsolidation(&request)
                .expect_err("one-over input must fail at its independent bound");
            assert!(
                matches!(error, ReconsolidationError::Bounds { phase: ref actual, .. } if actual == phase),
                "expected {phase} bound error, got {error:?}"
            );
        };

        let mut propositions = valid_request();
        propositions.policy.max_parent_propositions = 1;
        assert_bound_error(propositions, "propositions");

        let mut fields = valid_request();
        fields.field_paths.push("p1.statement".to_owned());
        fields.field_paths.sort();
        fields.policy.max_fields = 1;
        assert_bound_error(fields, "fields");

        let mut sources = valid_request();
        sources.new_items.push(NewEvidenceItem {
            handle: "obs-2".to_owned(),
            digest: "2".repeat(64),
            lineage: "lineage-new-2".to_owned(),
            source_revision: "obs-rev-2".to_owned(),
            statement: "A second independent warm-up observation.".to_owned(),
            observed_at_ms: Some(1_700_000_000_003),
            freshness_ms: Some(1_700_000_000_003),
            ..test_evidence_defaults()
        });
        sources
            .new_items
            .sort_by(|left, right| left.handle.cmp(&right.handle));
        sources.new_member_denominator.members = vec!["obs-1".to_owned(), "obs-2".to_owned()];
        sources.new_member_denominator.expected_total = 2;
        sources.policy.max_new_items = 1;
        assert_bound_error(sources, "sources");

        let mut revisions = valid_request();
        revisions.parent.predecessor_chain = vec!["rev-0".to_owned(), "rev-1".to_owned()];
        revisions.policy.max_predecessors = 1;
        assert_bound_error(revisions, "revisions");

        let mut dependents = valid_request();
        dependents.dependents.push(DependentRecord {
            handle: "dep-2".to_owned(),
            ..test_dependent_record_defaults()
        });
        dependents.policy.max_dependents = 1;
        assert_bound_error(dependents, "dependents");

        let mut bytes = valid_request();
        let baseline_bytes = total_bytes(&bytes);
        bytes.policy.max_total_bytes = baseline_bytes;
        bytes.child_forward_correction.push('x');
        assert_bound_error(bytes, "bytes");

        let mut stu = valid_request();
        stu.policy.max_stu = 1;
        stu.policy.observed_stu = 2;
        assert_bound_error(stu, "stu");

        let mut output = valid_request();
        let child = build_child(&output).expect("valid request has a bounded child projection");
        let child_bytes = canonical_json_bytes(&child).expect("child projection is serializable");
        assert!(child_bytes.len() > 1);
        output.policy.max_output_bytes = child_bytes.len() - 1;
        let result = propose_reconsolidation(&output).expect("output overflow is semantic");
        assert_eq!(result.outcome, ReconsolidationOutcome::Blocked);
        assert!(result.child.is_none());

        let mut work = valid_request();
        let work_units = (work.parent_propositions.len()
            + work.new_items.len()
            + work.added_propositions.len()
            + work.dependents.len()
            + work.field_paths.len()) as u64;
        work.policy.max_work_units = work_units - 1;
        assert_bound_error(work, "work");
    }

    #[test]
    fn parent_baseline_cross_product_mismatch_is_blocked() {
        let mut request = valid_request();
        request.parent_propositions[0].lineage = "lineage-b".to_owned();
        request.parent_propositions[1].lineage = "lineage-a".to_owned();

        let result = propose_reconsolidation(&request).expect("cross-pair mismatch is semantic");
        assert_eq!(result.outcome, ReconsolidationOutcome::Blocked);
        assert!(result.child.is_none());
    }

    #[test]
    fn parent_baseline_aligned_pair_passes() {
        let result = propose_reconsolidation(&valid_request()).expect("aligned pairs are valid");
        assert_eq!(result.outcome, ReconsolidationOutcome::Complete);
        assert!(result.child.is_some());
    }

    // WORK_UNIT_CASE: 667/6
    #[test]
    fn case_06_request_scope_bundle_manifest_and_grounding_bindings_are_checked() {
        let mut task = valid_request();
        task.identity.task_id = "task-moved".to_owned();
        refresh_identity(&mut task);
        assert_eq!(
            propose_reconsolidation(&task)
                .expect("task drift is a semantic stale result")
                .outcome,
            ReconsolidationOutcome::Stale
        );

        let mut manifest = valid_request();
        manifest.frozen_manifest_digest = "0".repeat(64);
        assert_eq!(
            propose_reconsolidation(&manifest)
                .expect("manifest drift is a semantic stale result")
                .outcome,
            ReconsolidationOutcome::Stale
        );

        let mut grounding = valid_request();
        grounding.grounded.job_id = "job-moved".to_owned();
        assert_eq!(
            propose_reconsolidation(&grounding)
                .expect("grounding drift is a semantic stale result")
                .outcome,
            ReconsolidationOutcome::Stale
        );
    }

    // WORK_UNIT_CASE: 667/7
    #[test]
    fn case_07_changed_same_identity_is_blocked_without_replay_authority() {
        let mut changed_idempotency = valid_request();
        changed_idempotency.identity.idempotency_key = "idempotency-reused-differently".to_owned();
        let result = propose_reconsolidation(&changed_idempotency)
            .expect("changed same-id request is a semantic identity conflict");
        assert_eq!(result.outcome, ReconsolidationOutcome::Blocked);
        assert!(result.child.is_none());

        let mut changed_receipt = valid_request();
        changed_receipt.item.receipt.output_digest = "9".repeat(64);
        let result = propose_reconsolidation(&changed_receipt)
            .expect("changed accepted receipt is a semantic identity conflict");
        assert_eq!(result.outcome, ReconsolidationOutcome::Blocked);
        assert!(result.child.is_none());
    }

    // WORK_UNIT_CASE: 667/11
    #[test]
    fn case_11_retrieval_is_insufficient_when_policy_requires_expansion() {
        let mut request = valid_request();
        request.policy.minimum_reactivation_stage = ReactivationStage::Expansion;
        request.reactivation.stage = ReactivationStage::Retrieval;
        let result = propose_reconsolidation(&request)
            .expect("insufficient retrieval is an abstention, not a revision");
        assert_eq!(result.outcome, ReconsolidationOutcome::Abstention);
        assert!(result.child.is_none());
    }

    // WORK_UNIT_CASE: 667/12
    #[test]
    fn case_12_delivery_acknowledgement_and_self_report_do_not_qualify_by_themselves() {
        for stage in [
            ReactivationStage::Delivery,
            ReactivationStage::Acknowledgement,
        ] {
            let mut request = valid_request();
            request.reactivation.stage = stage;
            let result = propose_reconsolidation(&request)
                .expect("delivery and acknowledgement are below public-use policy");
            assert_eq!(result.outcome, ReconsolidationOutcome::Abstention);
            assert!(result.child.is_none());
        }

        let mut self_report = valid_request();
        self_report.reactivation.observation_kind = ReactivationObservationKind::ModelMention;
        let result = propose_reconsolidation(&self_report)
            .expect("model self-report cannot qualify external reactivation");
        assert_eq!(result.outcome, ReconsolidationOutcome::Abstention);
        assert!(result.child.is_none());
    }

    // WORK_UNIT_CASE: 667/13
    #[test]
    fn case_13_wrong_record_revision_attempt_route_context_or_fence_is_stale() {
        let mut requests = Vec::new();
        let mut record = valid_request();
        record.reactivation.binding.record_handle = "other-derived".to_owned();
        requests.push(record);
        let mut revision = valid_request();
        revision.reactivation.binding.record_revision = "rev-1".to_owned();
        requests.push(revision);
        let mut attempt = valid_request();
        attempt.reactivation.binding.attempt_id = "attempt-other".to_owned();
        requests.push(attempt);
        let mut route = valid_request();
        route.reactivation.binding.route = "route-other".to_owned();
        requests.push(route);
        let mut context = valid_request();
        context.reactivation.binding.context_id = "context-other".to_owned();
        requests.push(context);
        let mut fence = valid_request();
        fence.reactivation.binding.state_fence = StateFence::new(
            EpochId::new(
                EpochLineageId::new("550e8400-e29b-41d4-a716-446655440001")
                    .expect("alternate test lineage"),
                NonZeroU64::new(1).expect("alternate test sequence"),
            )
            .expect("alternate test epoch"),
            ResourceGeneration::new(2).expect("alternate resource generation"),
        );
        requests.push(fence);

        for request in requests {
            let result = propose_reconsolidation(&request).expect("binding drift is semantic");
            assert_eq!(result.outcome, ReconsolidationOutcome::Stale);
            assert!(result.child.is_none());
        }
    }

    // WORK_UNIT_CASE: 667/50
    #[test]
    fn case_50_cancellation_and_frozen_deadline_are_distinct_policy_outcomes() {
        let mut cancelled = valid_request();
        cancelled.policy.cancelled = true;
        let result = propose_reconsolidation(&cancelled).expect("cancellation is semantic");
        assert_eq!(result.outcome, ReconsolidationOutcome::Rejected);
        assert!(result.child.is_none());

        let mut expired = valid_request();
        expired.policy.observation_time_ms = expired.policy.deadline_ms;
        let result = propose_reconsolidation(&expired).expect("deadline drift is semantic");
        assert_eq!(result.outcome, ReconsolidationOutcome::Stale);
        assert!(result.child.is_none());

        let mut missing_observation = valid_request();
        missing_observation.policy.observation_time_ms = None;
        let result = propose_reconsolidation(&missing_observation)
            .expect("deadline without a frozen observation time is stale");
        assert_eq!(result.outcome, ReconsolidationOutcome::Stale);
        assert!(result.child.is_none());

        let mut before_deadline = valid_request();
        before_deadline.policy.observation_time_ms = Some(
            before_deadline
                .policy
                .deadline_ms
                .expect("fixture has a frozen deadline")
                - 1,
        );
        let result = propose_reconsolidation(&before_deadline)
            .expect("an observation immediately before the deadline remains eligible");
        assert_eq!(result.outcome, ReconsolidationOutcome::Complete);
        assert!(result.child.is_some());
    }

    // WORK_UNIT_CASE: 667/51
    #[test]
    fn case_51_diagnostics_redact_control_and_oversize_identity_values() {
        let long = "secret".repeat(80);
        let rendered = ReconsolidationError::Dependent {
            handle: format!("{long}\u{0000}tail"),
            detail: format!("{long}\u{0001}tail"),
        }
        .to_string();
        assert!(!rendered.contains('\u{0000}'));
        assert!(!rendered.contains('\u{0001}'));
        assert!(rendered.contains("..."));
        assert!(rendered.len() < 400);
    }

    // WORK_UNIT_CASE: 667/52
    #[test]
    fn case_52_child_propositions_retain_or_bind_every_changed_statement() {
        let result = propose_reconsolidation(&valid_request()).expect("child projection succeeds");
        let child = result
            .child
            .expect("complete result has a child projection");
        let p1 = child
            .propositions
            .iter()
            .find(|proposition| proposition.id == "p1")
            .expect("retained parent proposition remains");
        assert_eq!(p1.statement, "Caching helps warm keys.");
        let p2 = child
            .propositions
            .iter()
            .find(|proposition| proposition.id == "p2")
            .expect("qualified parent proposition remains");
        assert_eq!(
            p2.statement,
            "Cold starts stay slow except after the observed warm-up."
        );
        assert_eq!(p2.support_revision, "src-b-rev-1");
        assert_eq!(p2.support_digest, "b".repeat(64));
        assert_eq!(p2.evidence_refs, vec!["obs-1".to_owned()]);
    }

    // WORK_UNIT_CASE: 667/53
    #[test]
    fn case_53_parent_delta_denominator_is_exactly_one_to_one() {
        let mut request = valid_request();
        request.deltas[0].proposition_id = "p2".to_owned();
        let error =
            propose_reconsolidation(&request).expect_err("duplicate parent delta is malformed");
        assert!(matches!(error, ReconsolidationError::Order { phase, .. } if phase == "deltas"));
    }

    // WORK_UNIT_CASE: 667/54
    #[test]
    fn case_54_child_preserves_revision_and_source_history_handles() {
        let request = valid_request();
        let result =
            propose_reconsolidation(&request).expect("history-preserving candidate succeeds");
        let child = result
            .child
            .expect("complete result carries history handles");
        assert_eq!(
            child.preserved_revision_history,
            vec!["rev-1".to_owned(), "rev-2".to_owned()]
        );
        for handle in ["src-a", "src-b", "obs-1", "obs-ext-1"] {
            assert!(child.preserved_source_refs.contains(&handle.to_owned()));
        }
        assert_eq!(request.parent.revision, "rev-2");
        assert_eq!(child.parent_schema, "derived-memory/v1");
        assert_eq!(child.parent_digest, "9".repeat(64));
        assert_eq!(request.new_items[0].digest, "1".repeat(64));
        assert!(
            child
                .preserved_source_identities
                .contains(&format!("src-b|lineage-b|src-b-rev-1|{}", "b".repeat(64)))
        );
        assert!(
            child
                .preserved_source_identities
                .contains(&format!("obs-1|lineage-new-1|obs-rev-1|{}", "1".repeat(64)))
        );
    }

    // WORK_UNIT_CASE: 667/55
    #[test]
    fn case_55_complete_result_accounts_each_required_dependent_once() {
        let mut request = valid_request();
        request.dependents.push(DependentRecord {
            handle: "dep-2".to_owned(),
            required: true,
            kind: "procedure".to_owned(),
            ..test_dependent_record_defaults()
        });
        request.dependent_outcomes.push(DependentOutcome {
            handle: "dep-2".to_owned(),
            disposition: DependentDisposition::Revalidate,
            note: "procedure is revalidated against the child".to_owned(),
            ..test_dependent_outcome_defaults()
        });
        request.dependents.sort_by(|a, b| a.handle.cmp(&b.handle));
        request
            .dependent_outcomes
            .sort_by(|a, b| a.handle.cmp(&b.handle));
        let result = propose_reconsolidation(&request).expect("dependent closure is complete");
        assert_eq!(result.outcome, ReconsolidationOutcome::Complete);
        assert_eq!(request.dependents.len(), request.dependent_outcomes.len());

        let mut missing = valid_request();
        missing.dependent_outcomes[0].handle = "dep-other".to_owned();
        let result = propose_reconsolidation(&missing).expect("missing dependent is semantic");
        assert_eq!(result.outcome, ReconsolidationOutcome::Blocked);

        let mut wrong_binding = valid_request();
        wrong_binding.dependent_outcomes[0].verifier = "other-verifier".to_owned();
        let result = propose_reconsolidation(&wrong_binding)
            .expect("dependent verifier metadata is part of the semantic closure");
        assert_eq!(result.outcome, ReconsolidationOutcome::Blocked);
    }

    // WORK_UNIT_CASE: 667/56
    #[test]
    fn case_56_child_preserves_all_axis_owners_and_proof_ceilings() {
        let request = valid_request();
        let result =
            propose_reconsolidation(&request).expect("ceiling-preserving candidate succeeds");
        let child = result.child.expect("complete result has a child request");
        assert_eq!(child.axis_owners, request.axis_owners);
        assert_eq!(child.source_assurance_ceiling, "assurance-7");
        assert_eq!(child.authority_ceiling, "candidate-only");
        assert_eq!(child.privacy_ceiling, "scope-7");
        assert_eq!(child.influence_ceiling, "derived-local");
        assert_eq!(child.proof_ceiling, "candidate-only");
        assert!(request.preservation.overall().is_ok());
    }

    // WORK_UNIT_CASE: 667/57
    #[test]
    fn case_57_bounded_malformed_input_never_panics_or_forms_authority() {
        let mut request = valid_request();
        request.new_items[0].statement = "x".repeat(MAX_TEXT_BYTES + 1);
        let frozen = request.clone();
        let result = std::panic::catch_unwind(|| propose_reconsolidation(&request));
        assert!(result.is_ok(), "bounded malformed input must not panic");
        assert!(result.expect("catch_unwind returned").is_err());
        assert_eq!(request, frozen);
    }
}
