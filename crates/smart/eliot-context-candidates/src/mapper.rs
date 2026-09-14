//! Pure deterministic mapper from seven provider projections to whole atoms.
//!
//! [`construct_context_candidates`] is the canonical typed equivalent of the
//! issue #604 signature. It acquires nothing, queries no provider or Store,
//! runs no activation, ranking, admission, assembly, rendering, delivery,
//! authority, effect or Finish step. It validates, freezes and maps each
//! supplied member to one whole atom (or one exact disposition) under the
//! closed versioned kind map, deduplicates only exact identity, reserves
//! representation capacity for recipe-required roles before optional volume,
//! enforces every independent bound, and emits one disposition per
//! role/member/candidate plus exact omissions, frontier and digest.
//!
//! Availability doctrine: each slot rolls up to the worst-case state of its
//! projection, members and bound pressure, and every emitted atom of the
//! slot carries that slot state (the admission equality rule). Finer member
//! truth survives in the exact content bytes, the candidate status and the
//! per-member disposition, never silently.

use std::collections::{BTreeMap, BTreeSet};

use eliot_context_contracts::{
    AtomAvailability, ContextBinding, ContextCandidate, ContextCandidateSet, ContextError,
    ContextRecipe, DecisionRevision, ExpansionHandle, MeasurementRef, OmissionReason,
    OmissionRecord, ProviderDisposition, ProviderRole, ProviderRoleDenominator, SemanticRole,
};
use eliot_contracts::{ArtifactId, StateFence, TaskRevision, canonical_json_bytes, sha256_hex};
use eliot_evidence::{Assertability, EpistemicStatus};
use eliot_receipts::ProofCeiling;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::derive::{
    NormalizedMember, derive_attention, derive_cue, derive_epistemic, derive_evidence,
};
use crate::inputs::{
    AttentionInput, CandidatePolicy, CandidateRequest, CueInput, EpistemicInput, EvidenceInput,
    OpaqueMember, OpaqueProjection, check_denominator_is_seven, cue_availability,
};
use crate::vocabulary::{
    KIND_MAP_VERSION, KindRule, PROVIDER_AFFORDANCE, PROVIDER_ATTENTION, PROVIDER_CUE,
    PROVIDER_EPISTEMIC, PROVIDER_EVIDENCE, PROVIDER_NEGATIVE_MEMORY, PROVIDER_TASK_FRAME,
    kind_rule, role_rank, seven_slots,
};

/// Rank slot availability worst-case first for the rollup.
///
/// `Missing` dominates everything; `PresentCurrent` dominates nothing. The
/// order keeps every non-success state distinct instead of collapsing them.
const fn availability_rank(state: AtomAvailability) -> u8 {
    match state {
        AtomAvailability::PresentCurrent => 0,
        AtomAvailability::KnownEmpty => 1,
        AtomAvailability::Unknown => 2,
        AtomAvailability::Partial | AtomAvailability::Omitted => 3,
        AtomAvailability::Stale => 4,
        AtomAvailability::Unavailable | AtomAvailability::Exhausted => 5,
        AtomAvailability::Blocked => 6,
        AtomAvailability::Missing => 7,
    }
}

/// Worst-case rollup of two availability states.
const fn worst_state(first: AtomAvailability, second: AtomAvailability) -> AtomAvailability {
    if availability_rank(first) >= availability_rank(second) {
        first
    } else {
        second
    }
}

/// Per-provider-slot disposition: exactly one per requested slot.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RoleDisposition {
    /// Exact requested slot.
    pub slot: ProviderRole,
    /// Rolled-up slot state.
    pub state: AtomAvailability,
    /// Whether the recipe requires this role for the Safety Floor.
    pub required: bool,
    /// Emitted candidate atoms for this slot.
    pub emitted: usize,
    /// Members omitted under an explicit bound with records.
    pub omitted: usize,
}

/// Outcome of one supplied member: exactly one per member.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "outcome", deny_unknown_fields)]
pub enum MemberOutcome {
    /// Emitted as the named candidate atom.
    #[serde(rename = "EMITTED")]
    Emitted {
        /// Emitted candidate atom identity.
        atom_id: ArtifactId,
    },
    /// Exact cross-slot duplicate coalesced into the named atom; every
    /// source lineage is retained instead of dropped.
    #[serde(rename = "COALESCED")]
    Coalesced {
        /// Surviving candidate atom identity.
        into_atom_id: ArtifactId,
        /// Retained source snapshot of the coalesced member.
        retained_source: Box<eliot_context_contracts::SourceSnapshot>,
    },
    /// Omitted under an explicit bound with a recoverable record.
    #[serde(rename = "OMITTED")]
    Omitted {
        /// Bound reason; always capacity-family for emission pressure.
        reason: OmissionReason,
    },
}

/// Per-member disposition: exactly one per supplied member.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MemberDisposition {
    /// Supplied member identity.
    pub identity: ArtifactId,
    /// Supplying slot.
    pub slot: ProviderRole,
    /// Closed member kind.
    pub kind: String,
    /// Member truthful state before the slot rollup.
    pub truthful: AtomAvailability,
    /// Exact outcome.
    pub outcome: MemberOutcome,
}

/// Frontier record: exact resume handles where permitted.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FrontierRecord {
    /// Owning slot.
    pub slot: ProviderRole,
    /// Resume edge/handle texts in deterministic order.
    pub edges: Vec<String>,
    /// Bound or reason class that stopped the work, if any.
    pub bound: Option<String>,
    /// Snapshot fence a stale result was built at, if any.
    pub fence: Option<StateFence>,
}

/// Maximum bytes of one frontier edge or bound text, matching the cue
/// supplier text boundary so valid supplier reasons stay representable.
pub const MAX_FRONTIER_TEXT_BYTES: usize = 8_192;

impl FrontierRecord {
    /// Validate handle bounds and non-emptiness.
    pub fn validate(&self) -> Result<(), ContextError> {
        self.slot.validate()?;
        if self.edges.len() > crate::inputs::MAX_FRONTIER_HANDLES {
            return Err(ContextError::Bounds {
                field: "frontier.edges",
            });
        }
        for edge in &self.edges {
            if edge.trim().is_empty()
                || edge.len() > MAX_FRONTIER_TEXT_BYTES
                || edge.chars().any(char::is_control)
            {
                return Err(ContextError::InvalidField("frontier.edges"));
            }
        }
        if let Some(bound) = &self.bound
            && (bound.trim().is_empty()
                || bound.len() > MAX_FRONTIER_TEXT_BYTES
                || bound.chars().any(char::is_control))
        {
            return Err(ContextError::InvalidField("frontier.bound"));
        }
        if let Some(fence) = &self.fence {
            fence.validate().map_err(|_| ContextError::InvalidFence)?;
        }
        if self.edges.is_empty() && self.bound.is_none() {
            return Err(ContextError::InvalidField("frontier.record"));
        }
        Ok(())
    }
}

/// Complete output of one candidate compilation: the bounded candidate set
/// proposed to A-17a admission plus exact dispositions, omissions, frontier
/// and proof.
///
/// This proposes material only. It admits, ranks, assembles, renders,
/// delivers, authorizes or finishes nothing.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ContextCandidateSetResult {
    /// Bounded whole-atom candidate set for admission.
    pub set: ContextCandidateSet,
    /// One disposition per requested provider slot, in denominator order.
    pub roles: Vec<RoleDisposition>,
    /// One disposition per supplied member, in supply order.
    pub members: Vec<MemberDisposition>,
    /// Omission records with recoverable handles, in emission order.
    pub omissions: Vec<OmissionRecord>,
    /// Resume frontier records, in slot order.
    pub frontier: Vec<FrontierRecord>,
    /// Whether every required role is completely represented. When false,
    /// consumers must not treat the required floor as complete.
    pub complete_floor: bool,
    /// Candidate-only proof ceiling: `CandidateArtifact` when the floor is
    /// complete, lowered to `Observation` otherwise.
    pub proof_ceiling: ProofCeiling,
    /// Digest over the ordered envelope (binding, candidates, denominator,
    /// dispositions, omissions, frontier, floor flag).
    pub digest: String,
}

impl ContextCandidateSetResult {
    /// Validate internal disposition coverage without re-running the mapper.
    pub fn validate(&self) -> Result<(), ContextError> {
        if self.roles.len() != 7 {
            return Err(ContextError::DenominatorMismatch);
        }
        self.set.validate_for_admission()?;
        if !self.set.candidates.is_empty() {
            self.set.validate()?;
        }
        let mut atoms = BTreeSet::new();
        for candidate in &self.set.candidates {
            if !atoms.insert(candidate.atom_id.clone()) {
                return Err(ContextError::Duplicate("result.atoms"));
            }
        }
        let mut emitted_atoms = BTreeSet::new();
        for member in &self.members {
            match &member.outcome {
                MemberOutcome::Emitted { atom_id } => {
                    if !atoms.contains(atom_id) || !emitted_atoms.insert(atom_id.clone()) {
                        return Err(ContextError::DenominatorMismatch);
                    }
                }
                MemberOutcome::Coalesced { into_atom_id, .. } => {
                    if !atoms.contains(into_atom_id) {
                        return Err(ContextError::DenominatorMismatch);
                    }
                }
                MemberOutcome::Omitted { .. } => {}
            }
        }
        if emitted_atoms != atoms {
            return Err(ContextError::DenominatorMismatch);
        }
        for omission in &self.omissions {
            omission.validate(&self.set.binding)?;
        }
        for record in &self.frontier {
            record.validate()?;
        }
        Ok(())
    }
}

/// One normalized member plus its slot assignment and closed rule.
struct WorkMember {
    /// Index into the slot table.
    slot_index: usize,
    /// Supply order for deterministic emission.
    order: usize,
    /// Normalized whole member.
    member: NormalizedMember,
    /// Closed kind rule.
    rule: KindRule,
    /// Whether the slot role is recipe-required.
    required: bool,
    /// Resolved candidate-stage status.
    status: EpistemicStatus,
    /// Resolved candidate-stage assertability.
    assertability: Assertability,
    /// Member truthful state before slot rollup.
    truthful: AtomAvailability,
}

/// Strength order for the assertability ceiling: weaker wins.
const fn assertability_strength(value: Assertability) -> u8 {
    match value {
        Assertability::AbstainOrFence => 0,
        Assertability::NonAssertableUnverified => 1,
        Assertability::Assertable => 2,
    }
}

/// Resolve emitted ceilings under the closed rule.
///
/// Sources cannot self-certify standing or widen scope: authority above the
/// rule is rejected, `Assertable` is capped to the rule ceiling, and statuses
/// downgrade (stale, contested, rejected, unknown) are preserved while any
/// other source status takes the rule assignment. Nothing is promoted.
fn resolve_ceilings(
    member: &NormalizedMember,
    rule: KindRule,
) -> Result<(EpistemicStatus, Assertability, AtomAvailability), ContextError> {
    if rule.required_protected && !member.protected {
        return Err(ContextError::InvalidField("member.protected"));
    }
    if member.authority > rule.authority {
        return Err(ContextError::InvalidField("member.authority"));
    }
    let status = match member.status {
        EpistemicStatus::Stale
        | EpistemicStatus::Superseded
        | EpistemicStatus::Contested
        | EpistemicStatus::Rejected
        | EpistemicStatus::Unknown => member.status,
        EpistemicStatus::Observed | EpistemicStatus::Supported | EpistemicStatus::Verified => {
            rule.status
        }
    };
    let assertability = if assertability_strength(member.assertability)
        <= assertability_strength(rule.assertability)
    {
        member.assertability
    } else {
        rule.assertability
    };
    // Member truth rolls stale/unknown overrides and source downgrades into
    // the projection base without ever promoting toward current.
    let mut truthful = member.truthful_state;
    if rule.stale_override || matches!(status, EpistemicStatus::Stale | EpistemicStatus::Superseded)
    {
        truthful = worst_state(truthful, AtomAvailability::Stale);
    }
    if rule.unknown_override || status == EpistemicStatus::Unknown {
        truthful = worst_state(truthful, AtomAvailability::Unknown);
    }
    Ok((status, assertability, truthful))
}

/// Normalize one opaque member under its slot rule and projection base.
fn normalize_opaque(
    member: &OpaqueMember,
    provider_label: &'static str,
    base: AtomAvailability,
    serializer: &str,
) -> Result<(NormalizedMember, KindRule), ContextError> {
    let rule = kind_rule(provider_label, member.kind.as_str())
        .ok_or(ContextError::InvalidField("member.kind"))?;
    if member.measurement.serializer != serializer {
        return Err(ContextError::InvalidField("member.measurement.serializer"));
    }
    let content_sha = sha256_hex(member.content.as_bytes());
    if member.source.content_sha256 != content_sha {
        return Err(ContextError::IdentityConflict);
    }
    if member.measurement.digest != content_sha {
        return Err(ContextError::IdentityConflict);
    }
    let normalized = NormalizedMember {
        member_id: member.member_id.clone(),
        kind: member.kind.clone(),
        content: member.content.clone(),
        content_sha,
        source: member.source.clone(),
        measurement: member.measurement.clone(),
        dependencies: member.dependencies.clone(),
        protected: member.protected,
        privacy: member.privacy,
        authority: member.authority,
        status: member.status,
        assertability: member.assertability,
        proof: member.proof.clone(),
        truthful_state: base,
    };
    Ok((normalized, rule))
}

/// Check the request, recipe and policy envelope and return slots plus the
/// mandatory role set.
fn check_envelope(
    request: &CandidateRequest,
    recipe: &ContextRecipe,
    policy: &CandidatePolicy,
) -> Result<(Vec<ProviderRole>, BTreeSet<SemanticRole>), ContextError> {
    request.validate()?;
    policy.validate()?;
    recipe.validate()?;
    check_denominator_is_seven(recipe)?;
    if recipe.binding != request.binding {
        return Err(ContextError::InvalidFence);
    }
    let slots = seven_slots()?;
    let mut mandatory = BTreeSet::new();
    for rule in &recipe.role_policies {
        if rule.required {
            mandatory.insert(rule.role);
        }
    }
    Ok((slots, mandatory))
}

/// Binding all projections must share with the request.
fn check_projection_binding(
    binding: &ContextBinding,
    task: &eliot_contracts::TaskId,
    scope: &eliot_receipts::WorkScopeId,
    fence: &StateFence,
) -> Result<(), ContextError> {
    if task != &binding.task_id || scope != &binding.scope_id || fence != &binding.state_fence {
        return Err(ContextError::InvalidFence);
    }
    Ok(())
}

/// Collect normalized members for one opaque projection.
#[allow(clippy::too_many_arguments)]
fn collect_opaque(
    projection: &OpaqueProjection,
    provider_label: &'static str,
    slot: &ProviderRole,
    binding: &ContextBinding,
    serializer: &str,
    out: &mut Vec<(NormalizedMember, KindRule)>,
    frontier_edges: &mut Vec<String>,
) -> Result<AtomAvailability, ContextError> {
    projection.validate()?;
    check_projection_binding(
        binding,
        &projection.task_id,
        &projection.scope_id,
        &projection.state_fence,
    )?;
    let base = projection.state.availability();
    for member in &projection.members {
        let (normalized, rule) = normalize_opaque(member, provider_label, base, serializer)?;
        if rule.role != slot.role {
            return Err(ContextError::DenominatorMismatch);
        }
        out.push((normalized, rule));
    }
    frontier_edges.extend(projection.frontier.iter().cloned());
    Ok(base)
}

/// Collect normalized members for the attention projection.
fn collect_attention(
    input: Option<&AttentionInput>,
    slot: &ProviderRole,
    binding: &ContextBinding,
    out: &mut Vec<(NormalizedMember, KindRule)>,
    frontier_edges: &mut Vec<String>,
) -> Result<AtomAvailability, ContextError> {
    let Some(input) = input else {
        return Ok(AtomAvailability::Missing);
    };
    check_projection_binding(
        binding,
        &input.projection.task_id,
        &input.projection.scope_id,
        &input.projection.state_fence,
    )?;
    for conflict in &input.conflicts {
        if let Some(task) = &conflict.task_id
            && task != &binding.task_id
        {
            return Err(ContextError::InvalidFence);
        }
    }
    let derived = derive_attention(input, &slot.provider, AtomAvailability::PresentCurrent)?;
    for member in &derived {
        let rule = kind_rule(PROVIDER_ATTENTION, member.kind.as_str())
            .ok_or(ContextError::InvalidField("attention.kind"))?;
        out.push((member.clone(), rule));
    }
    frontier_edges.extend(input.projection.missing_coverage.iter().cloned());
    Ok(AtomAvailability::PresentCurrent)
}

/// Collect the epistemic member, checking the admission fence.
fn collect_epistemic(
    input: Option<&EpistemicInput>,
    slot: &ProviderRole,
    binding: &ContextBinding,
    out: &mut Vec<(NormalizedMember, KindRule)>,
) -> Result<AtomAvailability, ContextError> {
    let Some(input) = input else {
        return Ok(AtomAvailability::Missing);
    };
    if input.position.admission.fence != binding.state_fence {
        return Err(ContextError::InvalidFence);
    }
    let derived = derive_epistemic(input, &slot.provider, AtomAvailability::PresentCurrent)?;
    for member in &derived {
        let rule = kind_rule(PROVIDER_EPISTEMIC, member.kind.as_str())
            .ok_or(ContextError::InvalidField("epistemic.kind"))?;
        out.push((member.clone(), rule));
    }
    Ok(AtomAvailability::PresentCurrent)
}

/// Collect cue members plus the completeness frontier.
fn collect_cue(
    input: Option<&CueInput>,
    slot: &ProviderRole,
    binding: &ContextBinding,
    out: &mut Vec<(NormalizedMember, KindRule)>,
    frontier: &mut Vec<FrontierRecord>,
) -> Result<AtomAvailability, ContextError> {
    let Some(input) = input else {
        return Ok(AtomAvailability::Missing);
    };
    if input.result.state_fence != binding.state_fence {
        return Err(ContextError::InvalidFence);
    }
    let base = if input.result.cancelled {
        // A cancelled run is retained as an explicit unknown, never as
        // current material and never silently dropped.
        AtomAvailability::Unknown
    } else {
        cue_availability(&input.result)
    };
    let derived = derive_cue(input, &slot.provider, base)?;
    for member in &derived {
        let rule = kind_rule(PROVIDER_CUE, member.kind.as_str())
            .ok_or(ContextError::InvalidField("cue.kind"))?;
        out.push((member.clone(), rule));
    }
    push_cue_frontier(input, slot, frontier)?;
    Ok(base)
}

/// Preserve the cue completeness frontier explicitly.
fn push_cue_frontier(
    input: &CueInput,
    slot: &ProviderRole,
    frontier: &mut Vec<FrontierRecord>,
) -> Result<(), ContextError> {
    use eliot_cue_contracts::Completeness as Done;
    let record = match &input.result.completeness {
        Done::Complete | Done::NoDirectMatch { .. } => None,
        Done::Truncated {
            frontier,
            bound_hit,
        } => Some(FrontierRecord {
            slot: slot.clone(),
            edges: frontier
                .iter()
                .map(|edge| edge.as_str().to_owned())
                .collect(),
            bound: Some(format!("cue-truncated-{bound_hit:?}")),
            fence: None,
        }),
        Done::Partial { frontier } => Some(FrontierRecord {
            slot: slot.clone(),
            edges: frontier
                .iter()
                .map(|edge| edge.as_str().to_owned())
                .collect(),
            bound: Some("cue-partial".to_owned()),
            fence: None,
        }),
        Done::Blocked { reason } => Some(FrontierRecord {
            slot: slot.clone(),
            edges: Vec::new(),
            bound: Some(format!("cue-blocked:{reason}")),
            fence: None,
        }),
        Done::Unavailable { reason } => Some(FrontierRecord {
            slot: slot.clone(),
            edges: Vec::new(),
            bound: Some(format!("cue-unavailable:{reason}")),
            fence: None,
        }),
        Done::Unknown { reason } => Some(FrontierRecord {
            slot: slot.clone(),
            edges: Vec::new(),
            bound: Some(format!("cue-unknown:{reason}")),
            fence: None,
        }),
        Done::SourceUnavailable { reason } => Some(FrontierRecord {
            slot: slot.clone(),
            edges: Vec::new(),
            bound: Some(format!("cue-source-unavailable:{reason}")),
            fence: None,
        }),
        Done::Stale { snapshot_fence } => Some(FrontierRecord {
            slot: slot.clone(),
            edges: Vec::new(),
            bound: Some("cue-stale".to_owned()),
            fence: Some(snapshot_fence.clone()),
        }),
        // Future completeness variants stay explicit unknowns, never
        // current material and never silent.
        _ => Some(FrontierRecord {
            slot: slot.clone(),
            edges: Vec::new(),
            bound: Some("cue-unclassified".to_owned()),
            fence: None,
        }),
    };
    if let Some(record) = record {
        record.validate()?;
        frontier.push(record);
    }
    Ok(())
}

/// Collect evidence members, checking every envelope fence.
fn collect_evidence(
    input: Option<&EvidenceInput>,
    slot: &ProviderRole,
    binding: &ContextBinding,
    out: &mut Vec<(NormalizedMember, KindRule)>,
) -> Result<AtomAvailability, ContextError> {
    let Some(input) = input else {
        return Ok(AtomAvailability::Missing);
    };
    for envelope in &input.envelopes {
        if envelope.state_fence != binding.state_fence {
            return Err(ContextError::InvalidFence);
        }
    }
    let derived = derive_evidence(input, &slot.provider, AtomAvailability::PresentCurrent)?;
    for member in &derived {
        let rule = kind_rule(PROVIDER_EVIDENCE, member.kind.as_str())
            .ok_or(ContextError::InvalidField("evidence.kind"))?;
        if rule.role != slot.role {
            return Err(ContextError::DenominatorMismatch);
        }
        out.push((member.clone(), rule));
    }
    Ok(AtomAvailability::PresentCurrent)
}

/// Work accounting guard: every member processed and every dependency
/// resolved consumes one unit.
struct WorkLedger {
    used: u64,
    limit: u64,
}

impl WorkLedger {
    const fn new(limit: u64) -> Self {
        Self { used: 0, limit }
    }

    fn spend(&mut self, units: u64) -> Result<(), ContextError> {
        self.used = self.used.checked_add(units).ok_or(ContextError::Overflow)?;
        if self.used > self.limit {
            return Err(ContextError::Bounds {
                field: "policy.max_work",
            });
        }
        Ok(())
    }
}

/// Canonical typed equivalent of
/// `construct_context_candidates(request, recipe, task_frame,
/// attention_and_conflicts, epistemic_position, cue_activation_result,
/// negative_memory, evidence, affordances, policy)`.
///
/// Ten explicit parameters keep all seven roles statically identifiable: no
/// dynamic provider map, no `OtherProvider`, no untyped value crosses this
/// boundary.
///
/// The mapper is pure and deterministic: same inputs always yield the same
/// ordered set, dispositions, omissions, frontier and digest.
#[allow(clippy::too_many_arguments)]
pub fn construct_context_candidates(
    request: &CandidateRequest,
    recipe: &ContextRecipe,
    task_frame: &OpaqueProjection,
    attention_and_conflicts: Option<&AttentionInput>,
    epistemic_position: Option<&EpistemicInput>,
    cue_activation_result: Option<&CueInput>,
    negative_memory: &OpaqueProjection,
    evidence: Option<&EvidenceInput>,
    affordances: &OpaqueProjection,
    policy: &CandidatePolicy,
) -> Result<ContextCandidateSetResult, ContextError> {
    let (slots, mandatory) = check_envelope(request, recipe, policy)?;
    let binding = &request.binding;
    let serializer = policy.serializer.as_str();
    // Slot tables in denominator order: task, attention, epistemic, cue,
    // negative, evidence, affordance.
    let mut per_slot: Vec<Vec<(NormalizedMember, KindRule)>> = Vec::with_capacity(7);
    for _ in 0..7 {
        per_slot.push(Vec::new());
    }
    let mut bases = [AtomAvailability::PresentCurrent; 7];
    let mut edge_tables: Vec<Vec<String>> = Vec::with_capacity(7);
    for _ in 0..7 {
        edge_tables.push(Vec::new());
    }
    let mut frontier = Vec::new();
    bases[0] = collect_opaque(
        task_frame,
        PROVIDER_TASK_FRAME,
        &slots[0],
        binding,
        serializer,
        &mut per_slot[0],
        &mut edge_tables[0],
    )?;
    bases[1] = collect_attention(
        attention_and_conflicts,
        &slots[1],
        binding,
        &mut per_slot[1],
        &mut edge_tables[1],
    )?;
    bases[2] = collect_epistemic(epistemic_position, &slots[2], binding, &mut per_slot[2])?;
    bases[3] = collect_cue(
        cue_activation_result,
        &slots[3],
        binding,
        &mut per_slot[3],
        &mut frontier,
    )?;
    bases[4] = collect_opaque(
        negative_memory,
        PROVIDER_NEGATIVE_MEMORY,
        &slots[4],
        binding,
        serializer,
        &mut per_slot[4],
        &mut edge_tables[4],
    )?;
    bases[5] = collect_evidence(evidence, &slots[5], binding, &mut per_slot[5])?;
    bases[6] = collect_opaque(
        affordances,
        PROVIDER_AFFORDANCE,
        &slots[6],
        binding,
        serializer,
        &mut per_slot[6],
        &mut edge_tables[6],
    )?;
    push_plain_frontiers(&slots, &edge_tables, &mut frontier)?;
    let unified = unify_members(&slots, &mandatory, per_slot, policy)?;
    let plan = plan_emission(&unified, policy)?;
    assemble_result(
        request, recipe, policy, &slots, &mandatory, bases, &unified, &plan, frontier,
    )
}

/// Frontier records for opaque and attention resume handles.
fn push_plain_frontiers(
    slots: &[ProviderRole],
    edge_tables: &[Vec<String>],
    frontier: &mut Vec<FrontierRecord>,
) -> Result<(), ContextError> {
    for (index, edges) in edge_tables.iter().enumerate() {
        if edges.is_empty() {
            continue;
        }
        let mut sorted = edges.clone();
        sorted.sort();
        sorted.dedup();
        let record = FrontierRecord {
            slot: slots[index].clone(),
            edges: sorted,
            bound: None,
            fence: None,
        };
        record.validate()?;
        frontier.push(record);
    }
    Ok(())
}

/// Merge per-slot members into one supply-ordered table, resolving
/// identities: exact resupply coalesces with retained lineage during
/// emission planning, while any same-ID divergence in payload, role,
/// ceiling, measurement or lineage is an identity conflict.
fn unify_members(
    slots: &[ProviderRole],
    mandatory: &BTreeSet<SemanticRole>,
    per_slot: Vec<Vec<(NormalizedMember, KindRule)>>,
    policy: &CandidatePolicy,
) -> Result<Vec<WorkMember>, ContextError> {
    let mut ledger = WorkLedger::new(policy.bounds.max_work);
    let mut unified: Vec<WorkMember> = Vec::new();
    // member_id -> positions, for cross-entry identity analysis: exact
    // resupply coalesces with retained lineage anywhere (same or cross
    // slot), while same-ID divergence is an identity conflict.
    let mut id_positions: BTreeMap<ArtifactId, Vec<usize>> = BTreeMap::new();
    let mut order = 0_usize;
    for (slot_index, members) in per_slot.into_iter().enumerate() {
        for (member, rule) in members {
            ledger.spend(1)?;
            check_member_bindings(&member, policy)?;
            let (status, assertability, truthful) = resolve_ceilings(&member, rule)?;
            let candidate = WorkMember {
                slot_index,
                order,
                member,
                rule,
                required: mandatory.contains(&slots[slot_index].role),
                status,
                assertability,
                truthful,
            };
            let position = unified.len();
            id_positions
                .entry(candidate.member.member_id.clone())
                .or_default()
                .push(position);
            unified.push(candidate);
            order = order.saturating_add(1);
        }
    }
    resolve_cross_slot_identities(&mut unified, &id_positions)?;
    // Unknown dependency targets are malformed input, never silent gaps.
    let known: BTreeSet<ArtifactId> = unified
        .iter()
        .map(|item| item.member.member_id.clone())
        .collect();
    for item in &unified {
        ledger.spend(
            u64::try_from(item.member.dependencies.len()).map_err(|_| ContextError::Overflow)?,
        )?;
        for dependency in &item.member.dependencies {
            if !known.contains(dependency) {
                return Err(ContextError::MissingField("member.dependencies"));
            }
        }
    }
    Ok(unified)
}

/// Enforce whole-lossless bindings: content, measurement and source digests
/// must agree exactly, and the serializer must be the policy serializer.
fn check_member_bindings(
    member: &NormalizedMember,
    policy: &CandidatePolicy,
) -> Result<(), ContextError> {
    let content_sha = sha256_hex(member.content.as_bytes());
    if content_sha != member.content_sha
        || member.source.content_sha256 != content_sha
        || member.measurement.digest != content_sha
    {
        return Err(ContextError::IdentityConflict);
    }
    if member.measurement.serializer != policy.serializer {
        return Err(ContextError::InvalidField("member.measurement.serializer"));
    }
    Ok(())
}

/// Resolve same-ID members: exact identity coalesces later, while any
/// divergence in payload, role, ceiling, measurement or lineage is an
/// identity conflict, never a merge.
fn resolve_cross_slot_identities(
    unified: &mut [WorkMember],
    id_positions: &BTreeMap<ArtifactId, Vec<usize>>,
) -> Result<(), ContextError> {
    for positions in id_positions.values() {
        if positions.len() < 2 {
            continue;
        }
        let first = &unified[positions[0]];
        for other in &positions[1..] {
            let candidate = &unified[*other];
            // Same-slot resupply was already rejected above; here any
            // divergence in payload, role, ceiling, measurement or lineage
            // is an identity conflict, while exact cross-slot identity
            // coalesces during emission planning.
            let identical = candidate.member == first.member
                && candidate.status == first.status
                && candidate.assertability == first.assertability;
            if !identical {
                return Err(ContextError::IdentityConflict);
            }
        }
    }
    Ok(())
}

/// Emission decision per unified member.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum EmitDecision {
    Emit,
    Coalesced,
    Omit,
}

/// Plan emission under reservation and bounds.
///
/// Required-role members fill first (representation fairness, not
/// admission), then optional volume with remaining capacity. Every bound hit
/// omits explicitly with a capacity reason; dependency targets omitted by
/// bounds cascade deterministically.
fn plan_emission(
    unified: &[WorkMember],
    policy: &CandidatePolicy,
) -> Result<Vec<EmitDecision>, ContextError> {
    let bounds = &policy.bounds;
    // Deterministic fill order: required class first, then slot order, then
    // supply order. Input order never decides survival (order invariance).
    let mut fill: Vec<usize> = (0..unified.len()).collect();
    fill.sort_by_key(|index| {
        let item = &unified[*index];
        (u8::from(!item.required), item.slot_index, item.order)
    });
    let mut decisions = vec![EmitDecision::Omit; unified.len()];
    // Coalesced entries point at their surviving twin (fill-order first).
    let mut twin: Vec<Option<usize>> = vec![None; unified.len()];
    let mut emitted_atoms: BTreeMap<ArtifactId, ArtifactId> = BTreeMap::new();
    let mut omitted_ids: BTreeSet<ArtifactId> = BTreeSet::new();
    let mut per_provider = [0_usize; 7];
    let mut total_bytes: u64 = 0;
    let mut emitted_count = 0_usize;
    // First pass: exact cross-slot duplicates coalesce into the first
    // twin in fill order; bounds apply to the surviving atoms.
    let mut first_seen: BTreeMap<ArtifactId, usize> = BTreeMap::new();
    for index in &fill {
        let item = &unified[*index];
        if let Some(first) = first_seen.get(&item.member.member_id) {
            let sibling = &unified[*first];
            if item.member == sibling.member
                && item.status == sibling.status
                && item.assertability == sibling.assertability
            {
                decisions[*index] = EmitDecision::Coalesced;
                twin[*index] = Some(*first);
                continue;
            }
            // Same-ID divergence was already rejected during unification.
        } else {
            first_seen.insert(item.member.member_id.clone(), *index);
        }
        decisions[*index] = EmitDecision::Emit;
    }
    // Second pass: bounds in fill order.
    for index in &fill {
        if decisions[*index] != EmitDecision::Emit {
            continue;
        }
        let item = &unified[*index];
        let bytes = u64::try_from(item.member.content.len()).map_err(|_| ContextError::Overflow)?;
        let over_provider = per_provider[item.slot_index] >= bounds.max_members_per_provider;
        let over_count = emitted_count >= bounds.max_candidates;
        let over_atom = item.member.content.len() > bounds.max_atom_bytes;
        let over_total = total_bytes
            .checked_add(bytes)
            .is_none_or(|next| next > bounds.max_total_bytes);
        let over_deps = item.member.dependencies.len() > bounds.max_dependencies_per_atom;
        if over_provider || over_count || over_atom || over_total || over_deps {
            decisions[*index] = EmitDecision::Omit;
            omitted_ids.insert(item.member.member_id.clone());
        } else {
            per_provider[item.slot_index] = per_provider[item.slot_index].saturating_add(1);
            total_bytes = total_bytes.saturating_add(bytes);
            emitted_count = emitted_count.saturating_add(1);
            emitted_atoms.insert(item.member.member_id.clone(), item.member.member_id.clone());
        }
    }
    // Fixpoint: members depending on omitted atoms omit as well, and twins
    // whose survivor was omitted omit instead of dangling.
    loop {
        let mut changed = false;
        for index in &fill {
            match decisions[*index] {
                EmitDecision::Omit => {}
                EmitDecision::Coalesced => {
                    let survivor = twin[*index].unwrap_or(*index);
                    if decisions[survivor] != EmitDecision::Emit {
                        decisions[*index] = EmitDecision::Omit;
                        omitted_ids.insert(unified[*index].member.member_id.clone());
                        changed = true;
                    }
                }
                EmitDecision::Emit => {
                    let item = &unified[*index];
                    if depends_on_omitted(item, &emitted_atoms, &omitted_ids) {
                        decisions[*index] = EmitDecision::Omit;
                        omitted_ids.insert(item.member.member_id.clone());
                        emitted_atoms.remove(&item.member.member_id);
                        per_provider[item.slot_index] =
                            per_provider[item.slot_index].saturating_sub(1);
                        let bytes = u64::try_from(item.member.content.len())
                            .map_err(|_| ContextError::Overflow)?;
                        total_bytes = total_bytes.saturating_sub(bytes);
                        emitted_count = emitted_count.saturating_sub(1);
                        changed = true;
                    }
                }
            }
        }
        if !changed {
            break;
        }
    }
    Ok(decisions)
}

/// Whether a member's dependencies resolve to omitted atoms.
///
/// Coalesced twins resolve through their surviving atom identity, which
/// equals the shared member identity by construction.
fn depends_on_omitted(
    item: &WorkMember,
    emitted_atoms: &BTreeMap<ArtifactId, ArtifactId>,
    omitted_ids: &BTreeSet<ArtifactId>,
) -> bool {
    for dependency in &item.member.dependencies {
        if omitted_ids.contains(dependency) {
            return true;
        }
        if let Some(target) = emitted_atoms.get(dependency)
            && omitted_ids.contains(target)
        {
            return true;
        }
    }
    false
}

/// Roll up slot states: worst of projection base, member truth and bound
/// pressure. Zero members under a current base is authoritative empty.
fn rollup_slot_states(
    bases: [AtomAvailability; 7],
    unified: &[WorkMember],
    plan: &[EmitDecision],
) -> [AtomAvailability; 7] {
    let mut states = bases;
    for (item, decision) in unified.iter().zip(plan.iter()) {
        match decision {
            EmitDecision::Emit | EmitDecision::Coalesced => {
                states[item.slot_index] = worst_state(states[item.slot_index], item.truthful);
            }
            EmitDecision::Omit => {
                states[item.slot_index] =
                    worst_state(states[item.slot_index], AtomAvailability::Partial);
            }
        }
    }
    for (index, state) in states.iter_mut().enumerate() {
        let has_members = unified
            .iter()
            .zip(plan.iter())
            .any(|(item, decision)| item.slot_index == index && *decision != EmitDecision::Omit);
        if !has_members && *state == AtomAvailability::PresentCurrent {
            *state = AtomAvailability::KnownEmpty;
        }
    }
    states
}

/// Check omission representation capacity and the task-bound fence needed
/// for reversible handles. Returns the fence revision when omissions exist.
fn check_omission_capacity(
    plan: &[EmitDecision],
    max_omissions: usize,
    task_revision: Option<TaskRevision>,
) -> Result<Option<TaskRevision>, ContextError> {
    let omission_count = plan
        .iter()
        .filter(|decision| **decision == EmitDecision::Omit)
        .count();
    if omission_count > max_omissions {
        return Err(ContextError::Bounds {
            field: "policy.max_omissions",
        });
    }
    if omission_count > 0 && task_revision.is_none() {
        return Err(ContextError::MissingField(
            "binding.state_fence.task_revision",
        ));
    }
    Ok(task_revision.filter(|_| omission_count > 0))
}

/// Emitted envelope pieces before ordering and proof.
struct Emission {
    candidates: Vec<ContextCandidate>,
    member_records: Vec<MemberDisposition>,
    omissions: Vec<OmissionRecord>,
    atom_of: BTreeMap<ArtifactId, ArtifactId>,
}

/// Run the emission plan into candidates, dispositions and omissions.
fn run_emission(
    request: &CandidateRequest,
    recipe: &ContextRecipe,
    slots: &[ProviderRole],
    states: [AtomAvailability; 7],
    unified: &[WorkMember],
    plan: &[EmitDecision],
    revision: Option<TaskRevision>,
) -> Result<Emission, ContextError> {
    let mut emission = Emission {
        candidates: Vec::new(),
        member_records: Vec::new(),
        omissions: Vec::new(),
        atom_of: BTreeMap::new(),
    };
    // Atom identities are stable member identities: an emitted member and
    // its coalesced twins share one atom identity by construction.
    for (item, decision) in unified.iter().zip(plan.iter()) {
        if *decision != EmitDecision::Omit {
            emission
                .atom_of
                .insert(item.member.member_id.clone(), item.member.member_id.clone());
        }
    }
    for (item, decision) in unified.iter().zip(plan.iter()) {
        emit_one(
            request,
            recipe,
            &slots[item.slot_index],
            states[item.slot_index],
            item,
            *decision,
            &mut emission,
            revision,
        )?;
    }
    Ok(emission)
}

/// Emit one member disposition triple into the running envelope.
#[allow(clippy::too_many_arguments)]
fn emit_one(
    request: &CandidateRequest,
    recipe: &ContextRecipe,
    slot: &ProviderRole,
    state: AtomAvailability,
    item: &WorkMember,
    decision: EmitDecision,
    emission: &mut Emission,
    revision: Option<TaskRevision>,
) -> Result<(), ContextError> {
    let record_base = || MemberDisposition {
        identity: item.member.member_id.clone(),
        slot: slot.clone(),
        kind: item.member.kind.clone(),
        truthful: item.truthful,
        outcome: MemberOutcome::Omitted {
            reason: OmissionReason::Capacity,
        },
    };
    match decision {
        EmitDecision::Emit => {
            let atom = build_atom(request, slot, state, item);
            atom.validate()?;
            emission
                .atom_of
                .insert(item.member.member_id.clone(), atom.atom_id.clone());
            emission.candidates.push(atom);
            let mut record = record_base();
            record.outcome = MemberOutcome::Emitted {
                atom_id: item.member.member_id.clone(),
            };
            emission.member_records.push(record);
        }
        EmitDecision::Coalesced => {
            let survivor = emission
                .atom_of
                .get(&item.member.member_id)
                .cloned()
                .ok_or(ContextError::DenominatorMismatch)?;
            let mut record = record_base();
            record.outcome = MemberOutcome::Coalesced {
                into_atom_id: survivor,
                retained_source: Box::new(item.member.source.clone()),
            };
            emission.member_records.push(record);
        }
        EmitDecision::Omit => {
            let revision = revision.ok_or(ContextError::MissingField(
                "binding.state_fence.task_revision",
            ))?;
            let omission = build_omission(request, recipe, slot, item, revision)?;
            omission.validate(&request.binding)?;
            emission.omissions.push(omission);
            emission.member_records.push(record_base());
        }
    }
    Ok(())
}

/// Resolve dependencies through surviving atoms, sorted for determinism.
/// Omitted targets are unreachable: the cascade already omitted dependents.
fn resolve_dependencies(
    candidates: &mut [ContextCandidate],
    atom_of: &BTreeMap<ArtifactId, ArtifactId>,
) -> Result<(), ContextError> {
    for candidate in candidates.iter_mut() {
        let mut resolved = BTreeSet::new();
        for dependency in candidate.dependencies.clone() {
            let target = atom_of
                .get(&dependency)
                .cloned()
                .ok_or(ContextError::DenominatorMismatch)?;
            resolved.insert(target);
        }
        candidate.dependencies = resolved.into_iter().collect();
        candidate.validate()?;
    }
    Ok(())
}

/// Canonical set order: required class, role rank, provider, atom.
fn sort_candidates(candidates: &mut [ContextCandidate], mandatory: &BTreeSet<SemanticRole>) {
    candidates.sort_by(|left, right| {
        let left_required = mandatory.contains(&left.provider_role.role);
        let right_required = mandatory.contains(&right.provider_role.role);
        (u8::from(!left_required), role_rank(left.provider_role.role))
            .cmp(&(
                u8::from(!right_required),
                role_rank(right.provider_role.role),
            ))
            .then_with(|| {
                left.provider_role
                    .provider
                    .as_str()
                    .cmp(right.provider_role.provider.as_str())
            })
            .then_with(|| left.atom_id.as_str().cmp(right.atom_id.as_str()))
    });
}

/// One disposition per requested slot with emission counts.
fn build_roles(
    slots: &[ProviderRole],
    states: [AtomAvailability; 7],
    member_records: &[MemberDisposition],
    mandatory: &BTreeSet<SemanticRole>,
) -> Vec<RoleDisposition> {
    slots
        .iter()
        .zip(states.iter())
        .map(|(slot, state)| {
            let emitted = member_records
                .iter()
                .filter(|record| {
                    record.slot == *slot && matches!(record.outcome, MemberOutcome::Emitted { .. })
                })
                .count();
            let omitted = member_records
                .iter()
                .filter(|record| {
                    record.slot == *slot && matches!(record.outcome, MemberOutcome::Omitted { .. })
                })
                .count();
            RoleDisposition {
                slot: slot.clone(),
                state: *state,
                required: mandatory.contains(&slot.role),
                emitted,
                omitted,
            }
        })
        .collect()
}

/// Required representation fairness: the floor is complete only when every
/// required slot is current and no required member was omitted or coalesced
/// away from its own atom.
fn floor_complete(
    roles: &[RoleDisposition],
    unified: &[WorkMember],
    plan: &[EmitDecision],
) -> bool {
    for role in roles {
        if role.required && (role.state != AtomAvailability::PresentCurrent || role.omitted > 0) {
            return false;
        }
    }
    for (item, decision) in unified.iter().zip(plan.iter()) {
        if item.required && *decision != EmitDecision::Emit {
            return false;
        }
    }
    true
}

/// Canonical envelope order for dispositions, omissions and frontier, so the
/// digest is invariant under input supply order.
fn sort_envelope(
    frontier: &mut [FrontierRecord],
    member_records: &mut [MemberDisposition],
    omissions: &mut [OmissionRecord],
) {
    frontier.sort_by(|left, right| {
        left.slot
            .provider
            .as_str()
            .cmp(right.slot.provider.as_str())
            .then_with(|| left.slot.role.cmp(&right.slot.role))
    });
    member_records.sort_by(|left, right| {
        left.slot
            .provider
            .as_str()
            .cmp(right.slot.provider.as_str())
            .then_with(|| left.slot.role.cmp(&right.slot.role))
            .then_with(|| left.identity.as_str().cmp(right.identity.as_str()))
    });
    omissions.sort_by(|left, right| {
        left.provider_role
            .provider
            .as_str()
            .cmp(right.provider_role.provider.as_str())
            .then_with(|| left.provider_role.role.cmp(&right.provider_role.role))
            .then_with(|| left.atom_id.as_str().cmp(right.atom_id.as_str()))
    });
}

/// Output ceiling fails closed: an over-budget envelope is an error, never
/// a silent cut.
fn check_output_bytes(
    result: &ContextCandidateSetResult,
    max_output_bytes: u64,
) -> Result<(), ContextError> {
    let output_bytes =
        canonical_json_bytes(result).map_err(|_| ContextError::InvalidField("result.output"))?;
    if u64::try_from(output_bytes.len()).map_err(|_| ContextError::Overflow)? > max_output_bytes {
        return Err(ContextError::Bounds {
            field: "policy.max_output_bytes",
        });
    }
    Ok(())
}

/// Assemble the result envelope from the emission plan.
#[allow(clippy::too_many_arguments)]
fn assemble_result(
    request: &CandidateRequest,
    recipe: &ContextRecipe,
    policy: &CandidatePolicy,
    slots: &[ProviderRole],
    mandatory: &BTreeSet<SemanticRole>,
    bases: [AtomAvailability; 7],
    unified: &[WorkMember],
    plan: &[EmitDecision],
    mut frontier: Vec<FrontierRecord>,
) -> Result<ContextCandidateSetResult, ContextError> {
    let bounds = &policy.bounds;
    let states = rollup_slot_states(bases, unified, plan);
    // Omission records need a task-bound fence for the reversible handle.
    let revision = check_omission_capacity(
        plan,
        bounds.max_omissions,
        request.binding.state_fence.task_revision,
    )?;
    let mut emission = run_emission(request, recipe, slots, states, unified, plan, revision)?;
    resolve_dependencies(&mut emission.candidates, &emission.atom_of)?;
    sort_candidates(&mut emission.candidates, mandatory);
    let denominator = ProviderRoleDenominator {
        requested: slots.to_vec(),
        dispositions: slots
            .iter()
            .zip(states.iter())
            .map(|(slot, state)| ProviderDisposition {
                slot: slot.clone(),
                state: *state,
                evidence: None,
            })
            .collect(),
    };
    let set = ContextCandidateSet {
        binding: request.binding.clone(),
        candidates: emission.candidates,
        denominator,
    };
    set.validate_for_admission()?;
    if !set.candidates.is_empty() {
        set.validate()?;
    }
    let roles = build_roles(slots, states, &emission.member_records, mandatory);
    // Required representation fairness: the floor is complete only when
    // every required slot is current and no required member was omitted.
    let complete_floor = floor_complete(&roles, unified, plan);
    let proof_ceiling = if complete_floor {
        ProofCeiling::CandidateArtifact
    } else {
        ProofCeiling::Observation
    };
    sort_envelope(
        &mut frontier,
        &mut emission.member_records,
        &mut emission.omissions,
    );
    let digest = result_digest(
        &set,
        &roles,
        &emission.member_records,
        &emission.omissions,
        &frontier,
    )?;
    let result = ContextCandidateSetResult {
        set,
        roles,
        members: emission.member_records,
        omissions: emission.omissions,
        frontier,
        complete_floor,
        proof_ceiling,
        digest,
    };
    result.validate()?;
    check_output_bytes(&result, bounds.max_output_bytes)?;
    Ok(result)
}

/// Build one whole candidate atom from an emitted member.
fn build_atom(
    request: &CandidateRequest,
    slot: &ProviderRole,
    state: AtomAvailability,
    item: &WorkMember,
) -> ContextCandidate {
    ContextCandidate {
        binding: request.binding.clone(),
        atom_id: item.member.member_id.clone(),
        provider_role: slot.clone(),
        source: item.member.source.clone(),
        representation: eliot_context_contracts::AtomRepresentation::Whole {
            content: item.member.content.clone(),
        },
        loss_policy: item.rule.loss_policy,
        availability: state,
        protected: item.member.protected,
        privacy: item.member.privacy,
        authority: item.member.authority,
        status: item.status,
        assertability: item.assertability,
        measurement: MeasurementRef {
            digest: item.member.content_sha.clone(),
            serializer: item.member.measurement.serializer.clone(),
        },
        dependencies: item.member.dependencies.clone(),
        proof: item.member.proof.clone(),
    }
}

/// Build the recoverable omission record for one bound-hit member.
fn build_omission(
    request: &CandidateRequest,
    recipe: &ContextRecipe,
    slot: &ProviderRole,
    item: &WorkMember,
    task_revision: eliot_contracts::TaskRevision,
) -> Result<OmissionRecord, ContextError> {
    let bytes = u64::try_from(item.member.content.len()).map_err(|_| ContextError::Overflow)?;
    let decision: DecisionRevision = recipe.decision.clone();
    let competing =
        "candidate-stage capacity bound (member, atom, dependency or total ceiling)".to_owned();
    let handle = ExpansionHandle {
        handle_id: ArtifactId::new(format!("expand-{}", item.member.member_id.as_str()))
            .map_err(|_| ContextError::InvalidField("omission.handle"))?,
        atom_id: item.member.member_id.clone(),
        source_id: item.member.source.snapshot_id.clone(),
        source_revision: item.member.source.revision.clone(),
        context: request.binding.clone(),
        decision: decision.clone(),
        policy: item.rule.loss_policy,
        provider_role: slot.clone(),
        handle_digest: item.member.content_sha.clone(),
        expires: None,
        invalidation: None,
    };
    let digest_shape = (
        KIND_MAP_VERSION,
        item.member.member_id.as_str(),
        slot.provider.as_str(),
        slot.role,
        bytes,
    );
    let digest_bytes =
        canonical_json_bytes(&digest_shape).map_err(|_| ContextError::InvalidField("omission"))?;
    Ok(OmissionRecord {
        atom_id: item.member.member_id.clone(),
        source_id: item.member.source.snapshot_id.clone(),
        provider_role: slot.clone(),
        decision,
        task_revision,
        reason: OmissionReason::Capacity,
        competing_constraint: competing,
        measured_cost: Some(bytes),
        allowed_representation: item.rule.loss_policy,
        expansion: Some(handle),
        non_recoverable_reason: None,
        authorization_requirement:
            "candidate-stage omission: resupply the owning provider snapshot".to_owned(),
        privacy_requirement: "omitted unit retains its source privacy ceiling on reopen".to_owned(),
        proof_requirement: "candidate-only proof; reopening revalidates lineage and measurement"
            .to_owned(),
        expires: None,
        invalidation: None,
        digest: sha256_hex(&digest_bytes),
    })
}

/// Digest over the ordered result envelope (kind-map version included).
fn result_digest(
    set: &ContextCandidateSet,
    roles: &[RoleDisposition],
    members: &[MemberDisposition],
    omissions: &[OmissionRecord],
    frontier: &[FrontierRecord],
) -> Result<String, ContextError> {
    #[derive(Serialize)]
    struct DigestShape<'a> {
        kind_map: u16,
        binding: &'a ContextBinding,
        candidates: &'a [ContextCandidate],
        denominator: &'a ProviderRoleDenominator,
        roles: &'a [RoleDisposition],
        members: &'a [MemberDisposition],
        omissions: &'a [OmissionRecord],
        frontier: &'a [FrontierRecord],
    }
    let shape = DigestShape {
        kind_map: KIND_MAP_VERSION,
        binding: &set.binding,
        candidates: &set.candidates,
        denominator: &set.denominator,
        roles,
        members,
        omissions,
        frontier,
    };
    let bytes =
        canonical_json_bytes(&shape).map_err(|_| ContextError::InvalidField("result.digest"))?;
    Ok(sha256_hex(&bytes))
}
