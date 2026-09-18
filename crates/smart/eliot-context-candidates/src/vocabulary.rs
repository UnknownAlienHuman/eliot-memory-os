//! Closed seven-role vocabulary and versioned member-kind map.
//!
//! Issue #604 (A-16a) maps exactly seven immutable provider projections to
//! whole [`ContextCandidate`](eliot_context_contracts::ContextCandidate)
//! atoms. The seven provider slots below are the entire denominator: no
//! eighth provider exists, and no dynamic string/provider map is accepted.
//!
//! Three of the seven providers (Task Frame, negative memory, affordance) have
//! no landed owner-neutral schema on current main (Governor-owned, CC-004 /
//! CC-008 open). They cross this boundary as opaque versioned role handles
//! ([`OpaqueProjection`](crate::OpaqueProjection)): whole content bytes plus
//! explicit lineage, measurement and ceilings. No Governor inner schema is
//! invented, forked or copied here; a required role whose projection is
//! missing stays an explicit missing/partial disposition, never filler.
//!
//! The four bound providers reuse their exact owner contracts without
//! redefinition:
//!
//! - Critical Attention / Conflict: `CriticalAttentionProjection` plus
//!   `ConflictSet`, both owned by `eliot-context-contracts` and
//!   `eliot-epistemic-contracts` respectively;
//! - Current Epistemic Position: `CurrentEpistemicPosition` owned by
//!   `eliot-epistemic-contracts` (never the legacy `eliot-epistemic`
//!   resolver, which is donor/migration material only);
//! - Cue activation: `ActivationResult` owned by `eliot-cue-contracts` (the
//!   stale issue spelling `CueActivationResult` means this exact type; the
//!   `eliot-cue-activation` algorithm crate is never imported or called);
//! - Evidence: `EvidenceEnvelope` owned by `eliot-evidence` plus
//!   `SourceAssurance` owned by `eliot-epistemic-contracts`.

use eliot_context_contracts::{
    AuthorityClass, ContextError, LossPolicy, ProviderId, ProviderRole, SemanticRole,
};
use eliot_contracts::ContractVersion;
use eliot_evidence::{Assertability, EpistemicStatus};

/// Version of the closed member-kind map in [`kind_rule`].
///
/// A change to any kind, role, policy or ceiling assignment bumps this
/// version; frozen bytes stay comparable across revisions.
pub const KIND_MAP_VERSION: u16 = 1;

/// Envelope version for this crate's opaque provider projections.
///
/// This versions only the local envelope shape. Owner revision text for
/// Governor-owned projections travels inside
/// [`ProjectionSchema`](crate::ProjectionSchema) and is never interpreted.
pub const CANDIDATE_SCHEMA_VERSION: ContractVersion = ContractVersion::new(1, 0, 0);

/// Opaque handle of the Governor-owned Task Frame projection.
pub const PROVIDER_TASK_FRAME: &str = "eliot.task-frame.v1";
/// Handle of the Critical Attention / Conflict projection.
pub const PROVIDER_ATTENTION: &str = "eliot.attention.v1";
/// Handle of the A-06e Current Epistemic Position projection.
pub const PROVIDER_EPISTEMIC: &str = "eliot.epistemic.v1";
/// Handle of the explicit A-10 cue activation result projection.
pub const PROVIDER_CUE: &str = "eliot.cue-activation.v1";
/// Opaque handle of the Governor-owned negative-memory projection.
pub const PROVIDER_NEGATIVE_MEMORY: &str = "eliot.negative-memory.v1";
/// Handle of the evidence / source-assurance projection.
pub const PROVIDER_EVIDENCE: &str = "eliot.evidence.v1";
/// Opaque handle of the Governor-owned affordance projection.
pub const PROVIDER_AFFORDANCE: &str = "eliot.affordance.v1";

/// One closed mapping entry: member kind to semantic role, loss policy and
/// candidate-stage ceilings.
///
/// `required_protected` marks Safety-Floor material: a member of such a kind
/// with `protected == false` is a provider downgrade attempt and is rejected.
/// `stale_override` marks kinds whose own lifecycle (expiry, reopen,
/// supersession) forces a `Stale` availability even under a current
/// projection. `unknown_override` marks explicit-unknown kinds.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct KindRule {
    /// Semantic role every member of this kind carries.
    pub role: SemanticRole,
    /// Explicit loss policy every atom of this kind carries.
    pub loss_policy: LossPolicy,
    /// Whether `protected` must be true.
    pub required_protected: bool,
    /// Candidate-stage epistemic status.
    pub status: EpistemicStatus,
    /// Candidate-stage assertability ceiling (never `Assertable`: the
    /// candidate stage proposes material, it never asserts truth).
    pub assertability: Assertability,
    /// Candidate-stage authority ceiling.
    pub authority: AuthorityClass,
    /// Whether members of this kind are `Stale` by their own lifecycle.
    pub stale_override: bool,
    /// Whether members of this kind are explicit unknowns.
    pub unknown_override: bool,
}

/// Return the exact seven requested provider/role slots in canonical order.
///
/// The order is the normative emission order: Task Frame objective first,
/// affordance volume last.
pub fn seven_slots() -> Result<Vec<ProviderRole>, ContextError> {
    let slots = [
        (PROVIDER_TASK_FRAME, SemanticRole::Goal),
        (PROVIDER_ATTENTION, SemanticRole::Conflict),
        (PROVIDER_EPISTEMIC, SemanticRole::Verifier),
        (PROVIDER_CUE, SemanticRole::Source),
        (PROVIDER_NEGATIVE_MEMORY, SemanticRole::Negative),
        (PROVIDER_EVIDENCE, SemanticRole::Evidence),
        (PROVIDER_AFFORDANCE, SemanticRole::Scope),
    ];
    let mut out = Vec::with_capacity(slots.len());
    for (provider, role) in slots {
        out.push(ProviderRole {
            provider: ProviderId::new(provider)
                .map_err(|_| ContextError::InvalidField("vocabulary.provider"))?,
            role,
        });
    }
    Ok(out)
}

/// Rank semantic roles for the canonical set order.
///
/// Required-before-optional is applied first by the caller; this rank orders
/// roles inside each class. The ranks are fixed by this vocabulary version.
#[must_use]
pub const fn role_rank(role: SemanticRole) -> u8 {
    match role {
        SemanticRole::Goal => 0,
        SemanticRole::Conflict => 1,
        SemanticRole::Verifier => 2,
        SemanticRole::Negative => 3,
        SemanticRole::Evidence => 4,
        SemanticRole::Source => 5,
        SemanticRole::Scope => 6,
        SemanticRole::Authority
        | SemanticRole::Acceptance
        | SemanticRole::Security
        | SemanticRole::Instruction
        | SemanticRole::Optional
        | SemanticRole::Constraint
        | SemanticRole::MaterialUnknown => 7,
    }
}

/// Task Frame kinds: objective, acceptance, constraints and boundaries.
fn task_frame_rule(kind: &str) -> Option<KindRule> {
    match kind {
        "objective" | "acceptance" | "constraint" | "boundary" => Some(KindRule {
            role: SemanticRole::Goal,
            loss_policy: LossPolicy::NonDroppable,
            required_protected: true,
            status: EpistemicStatus::Supported,
            assertability: Assertability::NonAssertableUnverified,
            authority: AuthorityClass::Governing,
            stale_override: false,
            unknown_override: false,
        }),
        _ => None,
    }
}

/// Attention kinds: sticky material, objections, minorities, dissent.
fn attention_rule(kind: &str) -> Option<KindRule> {
    match kind {
        "sticky" => Some(KindRule {
            role: SemanticRole::Conflict,
            loss_policy: LossPolicy::NonDroppable,
            required_protected: true,
            status: EpistemicStatus::Supported,
            assertability: Assertability::NonAssertableUnverified,
            authority: AuthorityClass::DecisionRelevant,
            stale_override: false,
            unknown_override: false,
        }),
        "objection" | "minority" | "dissent" => Some(KindRule {
            role: SemanticRole::Conflict,
            loss_policy: LossPolicy::NonDroppable,
            required_protected: true,
            status: EpistemicStatus::Contested,
            assertability: Assertability::NonAssertableUnverified,
            authority: AuthorityClass::DecisionRelevant,
            stale_override: false,
            unknown_override: false,
        }),
        _ => None,
    }
}

/// Epistemic kinds: support, conflict, unknowns, stale, absence, coverage.
fn epistemic_rule(kind: &str) -> Option<KindRule> {
    match kind {
        "support" | "partial" | "coverage" => Some(KindRule {
            role: SemanticRole::Verifier,
            loss_policy: LossPolicy::NonDroppable,
            required_protected: true,
            status: EpistemicStatus::Supported,
            assertability: Assertability::NonAssertableUnverified,
            authority: AuthorityClass::DecisionRelevant,
            stale_override: false,
            unknown_override: false,
        }),
        "conflict" => Some(KindRule {
            role: SemanticRole::Verifier,
            loss_policy: LossPolicy::NonDroppable,
            required_protected: true,
            status: EpistemicStatus::Contested,
            assertability: Assertability::NonAssertableUnverified,
            authority: AuthorityClass::DecisionRelevant,
            stale_override: false,
            unknown_override: false,
        }),
        "stale" => Some(KindRule {
            role: SemanticRole::Verifier,
            loss_policy: LossPolicy::NonDroppable,
            required_protected: true,
            status: EpistemicStatus::Stale,
            assertability: Assertability::AbstainOrFence,
            authority: AuthorityClass::DecisionRelevant,
            stale_override: true,
            unknown_override: false,
        }),
        "unknown" | "absence" => Some(KindRule {
            role: SemanticRole::Verifier,
            loss_policy: LossPolicy::NonDroppable,
            required_protected: true,
            status: EpistemicStatus::Unknown,
            assertability: Assertability::AbstainOrFence,
            authority: AuthorityClass::DecisionRelevant,
            stale_override: false,
            unknown_override: true,
        }),
        _ => None,
    }
}

/// Cue kinds: direct hits and relation-derived activations stay distinct.
fn cue_rule(kind: &str) -> Option<KindRule> {
    match kind {
        "direct" | "derived" => Some(KindRule {
            role: SemanticRole::Source,
            loss_policy: LossPolicy::Extractive,
            required_protected: false,
            status: EpistemicStatus::Observed,
            assertability: Assertability::NonAssertableUnverified,
            authority: AuthorityClass::Informational,
            stale_override: false,
            unknown_override: false,
        }),
        _ => None,
    }
}

/// Negative-memory core kinds: triggers, invariants, counterexamples.
fn negative_core_rule(kind: &str) -> Option<KindRule> {
    match kind {
        "trigger" | "invariant" | "counterexample" => Some(KindRule {
            role: SemanticRole::Negative,
            loss_policy: LossPolicy::NonDroppable,
            required_protected: true,
            status: EpistemicStatus::Supported,
            assertability: Assertability::NonAssertableUnverified,
            authority: AuthorityClass::DecisionRelevant,
            stale_override: false,
            unknown_override: false,
        }),
        "expiry" | "reopen" => Some(KindRule {
            role: SemanticRole::Negative,
            loss_policy: LossPolicy::NonDroppable,
            required_protected: true,
            status: EpistemicStatus::Stale,
            assertability: Assertability::AbstainOrFence,
            authority: AuthorityClass::DecisionRelevant,
            stale_override: true,
            unknown_override: false,
        }),
        _ => None,
    }
}

/// Negative-memory lifecycle kinds: expiry, reopen and advisory near-miss.
fn negative_memory_rule(kind: &str) -> Option<KindRule> {
    if let Some(rule) = negative_core_rule(kind) {
        return Some(rule);
    }
    // A semantic near-match is advisory data, never a hard block: it maps
    // to `Observed` under a current availability, exactly like any other
    // present member of this provider.
    match kind {
        "near-miss" => Some(KindRule {
            role: SemanticRole::Negative,
            loss_policy: LossPolicy::NonDroppable,
            required_protected: true,
            status: EpistemicStatus::Observed,
            assertability: Assertability::NonAssertableUnverified,
            authority: AuthorityClass::Informational,
            stale_override: false,
            unknown_override: false,
        }),
        _ => None,
    }
}

/// Evidence core kinds: provenance, assurance, coverage, counterevidence.
fn evidence_core_rule(kind: &str) -> Option<KindRule> {
    match kind {
        "provenance" | "assurance" | "coverage" => Some(KindRule {
            role: SemanticRole::Evidence,
            loss_policy: LossPolicy::NonDroppable,
            required_protected: true,
            status: EpistemicStatus::Supported,
            assertability: Assertability::NonAssertableUnverified,
            authority: AuthorityClass::Informational,
            stale_override: false,
            unknown_override: false,
        }),
        "counterevidence" => Some(KindRule {
            role: SemanticRole::Evidence,
            loss_policy: LossPolicy::NonDroppable,
            required_protected: true,
            status: EpistemicStatus::Contested,
            assertability: Assertability::NonAssertableUnverified,
            authority: AuthorityClass::Informational,
            stale_override: false,
            unknown_override: false,
        }),
        "unknown" => Some(KindRule {
            role: SemanticRole::Evidence,
            loss_policy: LossPolicy::NonDroppable,
            required_protected: true,
            status: EpistemicStatus::Unknown,
            assertability: Assertability::AbstainOrFence,
            authority: AuthorityClass::Informational,
            stale_override: false,
            unknown_override: true,
        }),
        _ => None,
    }
}

/// Evidence edge kinds: stale/rejected records and instruction-like data.
fn evidence_rule(kind: &str) -> Option<KindRule> {
    if let Some(rule) = evidence_core_rule(kind) {
        return Some(rule);
    }
    match kind {
        "stale-record" => Some(KindRule {
            role: SemanticRole::Evidence,
            loss_policy: LossPolicy::NonDroppable,
            required_protected: true,
            status: EpistemicStatus::Stale,
            assertability: Assertability::AbstainOrFence,
            authority: AuthorityClass::Informational,
            stale_override: true,
            unknown_override: false,
        }),
        "rejected-record" => Some(KindRule {
            role: SemanticRole::Evidence,
            loss_policy: LossPolicy::NonDroppable,
            required_protected: true,
            status: EpistemicStatus::Rejected,
            assertability: Assertability::NonAssertableUnverified,
            authority: AuthorityClass::Informational,
            stale_override: false,
            unknown_override: false,
        }),
        // Instruction-like evidence bytes stay data under the evidence slot:
        // the content never changes the provider or semantic role, grants no
        // authority and admits nothing (I15.6 instruction/data separation).
        "instruction-data" => Some(KindRule {
            role: SemanticRole::Evidence,
            loss_policy: LossPolicy::NonDroppable,
            required_protected: true,
            status: EpistemicStatus::Observed,
            assertability: Assertability::NonAssertableUnverified,
            authority: AuthorityClass::Informational,
            stale_override: false,
            unknown_override: false,
        }),
        _ => None,
    }
}

/// Affordance kinds: capability, availability, feasibility, limits.
fn affordance_rule(kind: &str) -> Option<KindRule> {
    match kind {
        "capability" | "availability" | "feasibility" | "limit" => Some(KindRule {
            role: SemanticRole::Scope,
            loss_policy: LossPolicy::Extractive,
            required_protected: false,
            status: EpistemicStatus::Observed,
            assertability: Assertability::NonAssertableUnverified,
            // Capability is not permission: callers may declare at most
            // `Informational`; `DecisionRelevant` or `Governing` is an
            // authority escalation and is rejected by the mapper.
            authority: AuthorityClass::Informational,
            stale_override: false,
            unknown_override: false,
        }),
        _ => None,
    }
}

/// Resolve a provider-scoped member kind to its closed mapping rule.
///
/// Returns `None` for unknown or ambiguous kinds; the mapper keeps those
/// invalid (rejects the call) instead of guessing a role, policy or ceiling.
/// No prose length, confidence, recency or preference signal is inspected:
/// routing is by the declared kind string only.
#[must_use]
pub fn kind_rule(provider: &str, kind: &str) -> Option<KindRule> {
    match provider {
        PROVIDER_TASK_FRAME => task_frame_rule(kind),
        PROVIDER_ATTENTION => attention_rule(kind),
        PROVIDER_EPISTEMIC => epistemic_rule(kind),
        PROVIDER_CUE => cue_rule(kind),
        PROVIDER_NEGATIVE_MEMORY => negative_memory_rule(kind),
        PROVIDER_EVIDENCE => evidence_rule(kind),
        PROVIDER_AFFORDANCE => affordance_rule(kind),
        _ => None,
    }
}
