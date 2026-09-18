//! Typed inputs of the candidate mapper.
//!
//! The canonical signature from issue #604 is
//! `construct_context_candidates(request, recipe, task_frame,
//! attention_and_conflicts, epistemic_position, cue_activation_result,
//! negative_memory, evidence, affordances, policy)`. The seven provider roles
//! stay statically identifiable: three cross as opaque versioned projections
//! (Governor-owned schemas are absent on current main and are never invented
//! here), four bind their exact owner contracts.
//!
//! Issue #43 designs the eighth provider slot (applicable memory) at this
//! input boundary without changing the mapped denominator yet: [`MemoryInput`]
//! carries the evaluated `ApplicableMemorySet` shape structurally (binding,
//! slot state, applicable/excluded handles, advisory cue hits,
//! denominator/truncation flags) because the typed
//! `eliot-memory-projection-contracts` dependency can only land with
//! workspace admission (registry flip deferred). The mapper still enforces
//! the seven-slot denominator; [`eight_slots`] and
//! [`check_denominator_is_seven_or_eight`] name the migration target the
//! mapper adopts after #41 merges. No eighth provider, unknown field, or
//! unknown variant is absorbed silently anywhere.
//!
//! Every record uses `deny_unknown_fields`: an unknown current field or an
//! unknown variant is rejected at the boundary, never absorbed.

use eliot_context_contracts::{
    AtomAvailability, AuthorityClass, ContextBinding, ContextError, ContextRecipe, MeasurementRef,
    PrivacyClass, ProofBinding, ProviderId, ProviderRole, SemanticRole, SourceSnapshot,
};
use eliot_contracts::{ArtifactId, ContractVersion, RequestId, StateFence, TaskId};
use eliot_cue_contracts::{ActivationResult, Completeness};
use eliot_epistemic_contracts::{ConflictSet, CurrentEpistemicPosition, SourceAssurance};
use eliot_evidence::{Assertability, EpistemicStatus, EvidenceEnvelope};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// Hard ceiling on members carried by one projection, independent of policy.
///
/// Policy bounds are always tighter in practice; this ceiling only keeps a
/// malformed input bounded before policy evaluation.
pub const MAX_PROJECTION_MEMBERS: usize = 4_096;
/// Hard ceiling on dependency handles carried by one member.
pub const MAX_MEMBER_DEPENDENCIES: usize = 256;
/// Hard ceiling on whole content bytes carried by one member (1 MiB, matching
/// the atom representation boundary).
pub const MAX_MEMBER_BYTES: usize = 1_048_576;
/// Hard ceiling on frontier/resume handles carried by one projection.
pub const MAX_FRONTIER_HANDLES: usize = 256;

fn check_text(value: &str, field: &'static str) -> Result<(), ContextError> {
    if value.trim().is_empty() || value.chars().any(char::is_control) {
        return Err(ContextError::InvalidField(field));
    }
    Ok(())
}

fn check_content(value: &str) -> Result<(), ContextError> {
    if value.trim().is_empty()
        || value
            .chars()
            .any(|c| c.is_control() && !matches!(c, '\n' | '\r' | '\t'))
        || value.len() > MAX_MEMBER_BYTES
    {
        return Err(ContextError::InvalidField("member.content"));
    }
    Ok(())
}

/// Caller request binding: task, attempt, scope, fence, decision, operation,
/// plus the request and idempotency identities.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CandidateRequest {
    /// Shared task/scope/fence/decision identity every projection must match.
    pub binding: ContextBinding,
    /// Stable caller request identity.
    pub request_id: RequestId,
    /// Caller idempotency key for this compilation.
    pub idempotency_key: String,
}

impl CandidateRequest {
    /// Validate identity bindings without acquiring anything.
    pub fn validate(&self) -> Result<(), ContextError> {
        self.binding.validate()?;
        check_text(&self.idempotency_key, "request.idempotency_key")?;
        Ok(())
    }
}

/// Independent capacity bounds for one candidate compilation.
///
/// Every bound is enforced independently; hitting any bound omits further
/// material with an exact recoverable handle (never silent loss), except
/// `max_omissions`, `max_output_bytes` and `max_work`, whose exhaustion fails
/// closed because the gap itself could no longer be represented.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CandidateBounds {
    /// Maximum members accepted per provider projection.
    pub max_members_per_provider: usize,
    /// Maximum candidate atoms emitted in total.
    pub max_candidates: usize,
    /// Maximum dependency handles per atom.
    pub max_dependencies_per_atom: usize,
    /// Maximum whole content bytes per atom.
    pub max_atom_bytes: usize,
    /// Maximum total content bytes across emitted atoms.
    pub max_total_bytes: u64,
    /// Maximum omission records (gap representation capacity).
    pub max_omissions: usize,
    /// Maximum canonical output bytes of the emitted set envelope.
    pub max_output_bytes: u64,
    /// Maximum internal work units (members processed plus dependencies
    /// resolved).
    pub max_work: u64,
}

impl CandidateBounds {
    /// A generous deterministic default used by tests and callers without a
    /// tighter route profile. Real routes supply their measured profile.
    #[must_use]
    pub const fn generous() -> Self {
        Self {
            max_members_per_provider: 64,
            max_candidates: 64,
            max_dependencies_per_atom: 16,
            max_atom_bytes: 65_536,
            max_total_bytes: 1_048_576,
            max_omissions: 64,
            max_output_bytes: 8_388_608,
            max_work: 100_000,
        }
    }
}

/// Candidate-stage policy: bounds, the expected measurement serializer and
/// cancellation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CandidatePolicy {
    /// Independent capacity bounds.
    pub bounds: CandidateBounds,
    /// Serializer identity every supplied measurement must carry.
    ///
    /// A measurement from another serializer is foreign and is rejected; the
    /// candidate stage owns no serializer registry beyond this declaration.
    pub serializer: String,
    /// Caller cancellation observation. A cancelled call fails with a typed
    /// error instead of returning a silent empty set.
    pub cancelled: bool,
}

impl CandidatePolicy {
    /// Validate policy shape without acquiring anything.
    pub fn validate(&self) -> Result<(), ContextError> {
        check_text(&self.serializer, "policy.serializer")?;
        if self.cancelled {
            return Err(ContextError::InvalidField("policy.cancelled"));
        }
        Ok(())
    }
}

/// Owner/schema/source identity of one opaque Governor-owned projection.
///
/// Only envelope metadata travels here: owner label, owner schema version,
/// source revision and the snapshot digest. No Governor inner field is
/// interpreted.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ProjectionSchema {
    /// Source owner label of the projection.
    pub owner: ProviderId,
    /// Owner schema version the snapshot was captured under.
    pub schema_version: ContractVersion,
    /// Source revision of the snapshot.
    pub source_revision: String,
    /// Content digest of the complete source snapshot.
    pub snapshot_digest: String,
}

impl ProjectionSchema {
    /// Validate envelope metadata shape.
    pub fn validate(&self) -> Result<(), ContextError> {
        check_text(&self.source_revision, "projection.source_revision")?;
        if self.snapshot_digest.len() != 64
            || !self
                .snapshot_digest
                .bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
        {
            return Err(ContextError::InvalidDigest("projection.snapshot_digest"));
        }
        Ok(())
    }
}

/// Completeness state of one supplied projection.
///
/// Every variant except `Complete` and `KnownEmpty` degrades the slot
/// disposition explicitly; a missing required projection stays
/// missing/partial in the output, never filler.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "state", deny_unknown_fields)]
pub enum ProjectionState {
    /// Complete authoritative projection; members follow.
    #[serde(rename = "COMPLETE")]
    Complete,
    /// Authoritative empty: the denominator slot stays, zero members follow.
    #[serde(rename = "KNOWN_EMPTY")]
    KnownEmpty,
    /// Truncated authoritative projection with an explicit reason.
    #[serde(rename = "PARTIAL")]
    Partial {
        /// Stable bounded reason class.
        reason: String,
    },
    /// Snapshot older than the request fence, with an explicit reason.
    #[serde(rename = "STALE")]
    Stale {
        /// Stable bounded reason class.
        reason: String,
    },
    /// Source projection could not be read, with an explicit reason.
    #[serde(rename = "UNAVAILABLE")]
    Unavailable {
        /// Stable bounded reason class.
        reason: String,
    },
    /// Policy or safety condition blocked evaluation, with a reason.
    #[serde(rename = "BLOCKED")]
    Blocked {
        /// Stable bounded reason class.
        reason: String,
    },
    /// Evaluation could not classify the source, with a reason.
    #[serde(rename = "UNKNOWN")]
    Unknown {
        /// Stable bounded reason class.
        reason: String,
    },
    /// Required projection not supplied at all.
    #[serde(rename = "MISSING")]
    Missing,
}

impl ProjectionState {
    /// Validate reason text where the variant carries one.
    pub fn validate(&self) -> Result<(), ContextError> {
        match self {
            Self::Complete | Self::KnownEmpty | Self::Missing => Ok(()),
            Self::Partial { reason }
            | Self::Stale { reason }
            | Self::Unavailable { reason }
            | Self::Blocked { reason }
            | Self::Unknown { reason } => check_text(reason, "projection.reason"),
        }
    }

    /// Base availability contributed by the projection state alone.
    #[must_use]
    pub const fn availability(&self) -> AtomAvailability {
        match self {
            Self::Complete => AtomAvailability::PresentCurrent,
            Self::KnownEmpty => AtomAvailability::KnownEmpty,
            Self::Partial { .. } => AtomAvailability::Partial,
            Self::Stale { .. } => AtomAvailability::Stale,
            Self::Unavailable { .. } => AtomAvailability::Unavailable,
            Self::Blocked { .. } => AtomAvailability::Blocked,
            Self::Unknown { .. } => AtomAvailability::Unknown,
            Self::Missing => AtomAvailability::Missing,
        }
    }

    /// Whether the projection may carry member payloads.
    ///
    /// `Missing`, `Blocked`, `Unavailable`, `Unknown` and `KnownEmpty`
    /// projections carry zero members; members under any of those states are
    /// contradictory input and are rejected. `Complete`, `Partial` and
    /// `Stale` may carry members, degraded truthfully.
    #[must_use]
    pub const fn allows_members(&self) -> bool {
        match self {
            Self::Complete | Self::Partial { .. } | Self::Stale { .. } => true,
            Self::KnownEmpty
            | Self::Unavailable { .. }
            | Self::Blocked { .. }
            | Self::Unknown { .. }
            | Self::Missing => false,
        }
    }
}

/// One whole supplied member of an opaque projection.
///
/// Content is the complete unit bytes: never split, summarized, truncated or
/// rewritten. The mapper binds `measurement.digest` and
/// `source.content_sha256` to the exact content bytes, so any truncation or
/// rewrite fails closed instead of emitting a fluent fragment.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OpaqueMember {
    /// Stable member identity within the supplying provider.
    pub member_id: ArtifactId,
    /// Closed member kind (see the versioned kind map).
    pub kind: String,
    /// Complete unit bytes.
    pub content: String,
    /// Immutable source snapshot lineage; `content_sha256` must be the exact
    /// SHA-256 of `content`.
    pub source: SourceSnapshot,
    /// Exact supplied measurement; `digest` must be the exact SHA-256 of
    /// `content` and `serializer` must equal the policy serializer.
    pub measurement: MeasurementRef,
    /// Interpretation dependency member identities, resolved inside the
    /// emitted set.
    pub dependencies: Vec<ArtifactId>,
    /// Protection ceiling. Required kinds must set this to true; a provider
    /// cannot downgrade required/protected material.
    pub protected: bool,
    /// Privacy ceiling travelling with the unit.
    pub privacy: PrivacyClass,
    /// Authority ceiling travelling with the unit. Affordance members must
    /// stay at `None` or `Informational`: capability is not permission,
    /// admission or an effect lease.
    pub authority: AuthorityClass,
    /// Source epistemic status; the mapper may cap it but never promotes it.
    pub status: EpistemicStatus,
    /// Source assertability; the mapper may cap it but never promotes it.
    pub assertability: Assertability,
    /// Evidence/proof ceiling reference.
    pub proof: ProofBinding,
}

impl OpaqueMember {
    /// Validate member shape (kind mapping and cross-field bindings are
    /// checked by the mapper, which sees the slot and policy).
    pub fn validate(&self) -> Result<(), ContextError> {
        check_text(&self.kind, "member.kind")?;
        check_content(&self.content)?;
        self.source.validate()?;
        self.measurement.validate()?;
        if self.dependencies.len() > MAX_MEMBER_DEPENDENCIES {
            return Err(ContextError::Bounds {
                field: "member.dependencies",
            });
        }
        let mut seen = std::collections::BTreeSet::new();
        for dependency in &self.dependencies {
            if !seen.insert(dependency.clone()) {
                return Err(ContextError::Duplicate("member.dependencies"));
            }
        }
        Ok(())
    }
}

/// One opaque Governor-owned provider projection: Task Frame, negative
/// memory or affordance.
///
/// The envelope carries binding, schema metadata, completeness state, whole
/// members and resume handles. Inner Governor fields are never modelled.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OpaqueProjection {
    /// Owner/schema/source envelope of the snapshot.
    pub schema: ProjectionSchema,
    /// Task binding; must equal the request task.
    pub task_id: TaskId,
    /// Scope binding; must equal the request scope.
    pub scope_id: eliot_receipts::WorkScopeId,
    /// Fence binding; must equal the request fence.
    pub state_fence: StateFence,
    /// Completeness state of the projection.
    pub state: ProjectionState,
    /// Whole members (only for states that allow members).
    pub members: Vec<OpaqueMember>,
    /// Resume handles for truncated volume.
    pub frontier: Vec<String>,
}

impl OpaqueProjection {
    /// Validate envelope shape and member shapes.
    pub fn validate(&self) -> Result<(), ContextError> {
        self.schema.validate()?;
        self.state.validate()?;
        self.state_fence
            .validate()
            .map_err(|_| ContextError::InvalidFence)?;
        if self.members.len() > MAX_PROJECTION_MEMBERS {
            return Err(ContextError::Bounds {
                field: "projection.members",
            });
        }
        if !self.state.allows_members() && !self.members.is_empty() {
            return Err(ContextError::InvalidField("projection.members"));
        }
        for member in &self.members {
            member.validate()?;
        }
        if self.frontier.len() > MAX_FRONTIER_HANDLES {
            return Err(ContextError::Bounds {
                field: "projection.frontier",
            });
        }
        for handle in &self.frontier {
            check_text(handle, "projection.frontier")?;
        }
        Ok(())
    }
}

/// Supplied measurement aligned to one derived member identity.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MemberMeasurement {
    /// Derived member identity (see the `*_member_id` helpers).
    pub member_id: ArtifactId,
    /// Exact supplied measurement for that member.
    pub measurement: MeasurementRef,
}

/// Critical Attention projection plus its conflict sets.
///
/// Every attention member and every conflict position maps to one whole atom;
/// sticky material, objections, minorities and dissent all survive with no
/// winner selected. Measurements arrive aligned by member identity: the
/// attention identity for members, `conflict_member_id` for positions.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AttentionInput {
    /// Immutable attention projection owned by `eliot-context-contracts`.
    pub projection: eliot_context_contracts::CriticalAttentionProjection,
    /// Immutable conflict sets owned by `eliot-epistemic-contracts`.
    pub conflicts: Vec<ConflictSet>,
    /// Supplied measurements keyed by derived member identity.
    pub measurements: Vec<MemberMeasurement>,
}

/// Current Epistemic Position projection.
///
/// The admitted read view is preserved whole: canonical support, partial,
/// conflict, unknown, stale and absence evidence plus denominator and causal
/// ceilings travel in the exact source bytes. The view is never resolved,
/// reconstructed or truth-promoted here; in particular a `Verified` source
/// status is capped at the candidate-stage ceiling, never asserted.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EpistemicInput {
    /// Immutable admitted read view owned by `eliot-epistemic-contracts`.
    pub position: CurrentEpistemicPosition,
    /// Supplied measurement for the single derived member.
    pub measurements: Vec<MemberMeasurement>,
}

/// Explicit cue activation result projection.
///
/// The result is read, never produced: direct and derived activations keep
/// their explicit path, source, snapshot, profile, fence, truncation,
/// frontier and score ceiling. No traversal runs here, so paths may name
/// edges that resolve nowhere in this crate. Relevance never becomes
/// support, admission or a hard block.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CueInput {
    /// Immutable activation result owned by `eliot-cue-contracts`.
    pub result: ActivationResult,
    /// Supplied measurements keyed by derived member identity.
    pub measurements: Vec<MemberMeasurement>,
}

/// Evidence and source-assurance projection.
///
/// Envelopes (dimensions, provenance, coverage, counterevidence, unknowns)
/// and assurances (source binding with integrity digest) each map to one
/// whole atom. Instruction-like payload bytes travel as `payloads` members
/// under the evidence slot and stay data: they never change the provider or
/// semantic role and grant nothing (I15.6).
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EvidenceInput {
    /// Immutable evidence envelopes owned by `eliot-evidence`.
    pub envelopes: Vec<EvidenceEnvelope>,
    /// Immutable source assurances owned by `eliot-epistemic-contracts`.
    pub assurances: Vec<SourceAssurance>,
    /// Whole evidence payload bytes, including instruction-like data that
    /// stays data.
    pub payloads: Vec<OpaqueMember>,
    /// Supplied measurements keyed by derived member identity (envelopes
    /// and assurances; payloads carry their own).
    pub measurements: Vec<MemberMeasurement>,
}

/// Returns the cue completeness of a result for slot-state derivation.
#[must_use]
pub fn cue_availability(result: &ActivationResult) -> AtomAvailability {
    match &result.completeness {
        Completeness::Complete => AtomAvailability::PresentCurrent,
        Completeness::Truncated { .. } | Completeness::Partial { .. } => AtomAvailability::Partial,
        Completeness::Blocked { .. } => AtomAvailability::Blocked,
        Completeness::Unavailable { .. } | Completeness::SourceUnavailable { .. } => {
            AtomAvailability::Unavailable
        }
        // A readable snapshot with no direct hit is a known-empty answer,
        // not an unreadable source. A result with this completeness carries
        // no activations by owner validation. Any other (including future)
        // completeness variant is an explicit unknown, never current.
        Completeness::NoDirectMatch { .. } => AtomAvailability::KnownEmpty,
        Completeness::Stale { .. } => AtomAvailability::Stale,
        _ => AtomAvailability::Unknown,
    }
}

/// Re-exported for documentation parity: the issue's stale spelling
/// `CueActivationResult` always means [`ActivationResult`].
pub use eliot_cue_contracts::ActivationResult as CueActivationResult;

/// Validate that a recipe denominator is exactly the seven-slot vocabulary.
///
/// Order-insensitive; an eighth slot, a missing slot or a swapped role is a
/// denominator mismatch, never silent absorption.
pub fn check_denominator_is_seven(recipe: &ContextRecipe) -> Result<(), ContextError> {
    let mut expected = crate::seven_slots()?;
    let mut actual = recipe.denominator.requested.clone();
    expected.sort();
    actual.sort();
    if expected != actual {
        return Err(ContextError::DenominatorMismatch);
    }
    Ok(())
}

/// Provider identity of the eighth applicable-memory slot (issue #43).
///
/// The constant lives here rather than in [`crate::vocabulary`] because that
/// module owns the closed seven-slot map held by #41; vocabulary adoption of
/// the eighth slot moves there when the mapper adopts the eight-slot
/// denominator after #41 merges.
pub const MEMORY_PROVIDER: &str = "eliot.memory-applicability.v1";

/// Hard ceiling on advisory cue-hit handles carried by one memory input.
///
/// This mirrors the evaluator advisory bound structurally; the typed import
/// lands with workspace admission.
pub const MAX_MEMORY_CUE_HITS: usize = 512;

/// One excluded applicable-memory handle with its substantive reason.
///
/// The reason travels as a bounded reason class (never a cue-hit flag):
/// the typed `ExclusionReason` enum lives in
/// `eliot-memory-projection-contracts` and is imported directly once that
/// crate is workspace-admitted. A cue hit on an excluded handle is recorded
/// on `cue_hit` and never promotes the handle into `applicable`.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MemoryExclusion {
    /// Exact canonical handle of the excluded record.
    pub handle: ArtifactId,
    /// Stable bounded exclusion reason class.
    pub reason: String,
    /// Whether advisory cue-hit evidence named this record.
    pub cue_hit: bool,
}

impl MemoryExclusion {
    /// Validate the exclusion shape.
    pub fn validate(&self) -> Result<(), ContextError> {
        check_text(&self.reason, "memory.exclusion.reason")
    }
}

/// Eighth-slot input: the evaluated applicable-memory set in structural form.
///
/// The binding reuses the exact shared task/scope/fence identity every other
/// slot binds; `state` reuses the slot-state vocabulary so the memory slot
/// degrades exactly like the opaque Governor projections (missing/partial
/// stays visible, never filler). `applicable` names records the evaluator
/// admitted; `excluded` names records it refused with exact reason classes.
/// `cue_hits` is advisory evidence only.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MemoryInput {
    /// Shared task/scope/fence/decision identity; must equal the request task.
    pub binding: ContextBinding,
    /// Completeness state of the memory slot projection.
    pub state: ProjectionState,
    /// Applicable record handles admitted by the evaluator.
    pub applicable: Vec<ArtifactId>,
    /// Excluded record handles with exact reason classes.
    pub excluded: Vec<MemoryExclusion>,
    /// Advisory cue-hit handles; flags only, never proof.
    pub cue_hits: Vec<ArtifactId>,
    /// Whether the evaluated set carried a known denominator. An unknown
    /// denominator with applicable members is contradictory input (the
    /// evaluator fails closed on unknown denominators) and is rejected.
    pub denominator_known: bool,
    /// Whether the evaluated set was truncated; travels explicitly.
    pub truncated: bool,
}

impl MemoryInput {
    /// Validate the memory slot shape: binding, slot-state/member coherence,
    /// handle uniqueness across applicable/excluded/cue lists, and the
    /// unknown-denominator closure rule.
    pub fn validate(&self) -> Result<(), ContextError> {
        self.binding.validate()?;
        self.state.validate()?;
        if self.applicable.len() > MAX_PROJECTION_MEMBERS {
            return Err(ContextError::Bounds {
                field: "memory.applicable",
            });
        }
        if !self.state.allows_members() && !self.applicable.is_empty() {
            return Err(ContextError::InvalidField("memory.applicable"));
        }
        if !self.denominator_known && !self.applicable.is_empty() {
            return Err(ContextError::InvalidField("memory.applicable"));
        }
        let mut seen = std::collections::BTreeSet::new();
        for handle in &self.applicable {
            if !seen.insert(handle.clone()) {
                return Err(ContextError::Duplicate("memory.applicable"));
            }
        }
        for exclusion in &self.excluded {
            exclusion.validate()?;
            if !seen.insert(exclusion.handle.clone()) {
                return Err(ContextError::Duplicate("memory.handles"));
            }
        }
        if self.cue_hits.len() > MAX_MEMORY_CUE_HITS {
            return Err(ContextError::Bounds {
                field: "memory.cue_hits",
            });
        }
        let mut seen_hits = std::collections::BTreeSet::new();
        for handle in &self.cue_hits {
            if !seen_hits.insert(handle.clone()) {
                return Err(ContextError::Duplicate("memory.cue_hits"));
            }
        }
        Ok(())
    }
}

/// Returns the slot availability of a memory input for disposition derivation.
///
/// Availability reflects the slot projection state only, exactly like
/// [`cue_availability`]: it never promotes an excluded record and never
/// demotes an applicable one on cue evidence.
#[must_use]
pub fn memory_availability(input: &MemoryInput) -> AtomAvailability {
    input.state.availability()
}

/// Return the eight requested provider/role slots in canonical order.
///
/// The seven canonical slots keep their order and roles; the memory slot
/// joins last with the `Evidence` semantic role under its distinct provider
/// identity. The shared role is provisional: mapper adoption after #41
/// decides whether memory atoms merge into evidence emission or form their
/// own emission, but the denominator slot identity is stable now.
pub fn eight_slots() -> Result<Vec<ProviderRole>, ContextError> {
    let mut slots = crate::seven_slots()?;
    slots.push(ProviderRole {
        provider: ProviderId::new(MEMORY_PROVIDER)
            .map_err(|_| ContextError::InvalidField("memory.provider"))?,
        role: SemanticRole::Evidence,
    });
    Ok(slots)
}

/// Validate that a recipe denominator is exactly the seven- or eight-slot
/// vocabulary.
///
/// Order-insensitive. A seven-slot recipe stays valid with the memory slot
/// explicitly missing; an eight-slot recipe must name the exact memory
/// slot. Anything else is a denominator mismatch, never silent absorption.
pub fn check_denominator_is_seven_or_eight(recipe: &ContextRecipe) -> Result<(), ContextError> {
    let mut seven = crate::seven_slots()?;
    let mut eight = eight_slots()?;
    let mut actual = recipe.denominator.requested.clone();
    seven.sort();
    eight.sort();
    actual.sort();
    if actual == seven || actual == eight {
        Ok(())
    } else {
        Err(ContextError::DenominatorMismatch)
    }
}
