//! Canonical closed retrieval-admission decision outcomes (I12.26).
//!
//! [`RetrievalAdmissionDecision`] is the typed `MemoryAdmissionDecision`
//! outcome set from I12.26 ("Memory admission and retrieval trace"): exactly
//! `include_exact`, `include_handle`, `include_with_warning`,
//! `require_revalidation`, `suppress`, and `quarantine`. It is a closed
//! operational result, never a confidence scalar, and it is derived by the
//! retrieval/admission owner from scope and State Fence, epistemic
//! status/freshness, source assurance, expected decision delta,
//! contradiction risk, cost, and repetition — never accepted from
//! bridge/model output.
//!
//! [`RetrievalStaleness`] is the I12.26 stale-projection trichotomy:
//! `STALE_PROJECTION`, `PACKET_REFRESH_REQUIRED`, or `PROBE_REQUIRED`. Before
//! exact cue firing, source/projection revisions and the State Fence are
//! compared; a mismatch never silently injects stale material. The live
//! admission entrypoint ([`crate::admit_context`]) enforces the fence arm of
//! this gate; floor/optional staleness keeps flowing through the existing
//! typed incomplete/omission paths, and the full classification is exposed
//! here for the runtime caller.
//!
//! [`MaterialRankTrace`] carries the per-material rank-trace linkage I12.26
//! requires for every material inclusion or suppression: the material
//! identity, the evaluated disposition and contract-determined outcome, the
//! freshness signal, the rule basis, the explicit suppression reason, the
//! dependency/invalidation set, the decision anchor, and a content-addressed
//! handle resolving to exactly the delivered record.
//!
//! Boundary note: `eliot_types::MemoryAdmissionDecision` (memory-influence
//! vocabulary: `IncludeVerified`, `IncludeSupported`, and related variants)
//! is a separate pre-existing projection contract with different semantics.
//! This type does not replace it, duplicate its variants, or convert into it
//! (no `From`/`Into` bridge); convergence of the two vocabularies is owned
//! separately with the cognition contract owner. Likewise,
//! `eliot_context_contracts::AdmissionDisposition` remains the per-candidate
//! membership disposition; [`RetrievalAdmissionDecision::from_membership`]
//! resolves only the exact-name counterparts and returns `None` where the
//! contract determines no outcome, rather than inventing a mapping.

#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};

use eliot_context_contracts::{
    AdmissionDisposition, AdmissionInput, AdmissionResult, AtomAvailability, ContextCandidate,
    ContextError, OmissionRecord,
};
use eliot_contracts::{ArtifactId, DecisionId, StateFence, fences_match_exact};
use serde::{Deserialize, Serialize};

/// Closed retrieval-admission outcome for one evaluated candidate.
///
/// Exactly the six I12.26 outcomes. Wire spelling is `SCREAMING_SNAKE_CASE`,
/// matching the existing closed outcome enums (`RecallDisposition`,
/// `AdmissionDisposition`).
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RetrievalAdmissionDecision {
    /// Admit the exact unit for direct use.
    IncludeExact,
    /// Admit a handle only; content loads through explicit expansion.
    IncludeHandle,
    /// Admit with an explicit warning attached (framing, staleness bound,
    /// or contradiction risk that stays below suppression).
    IncludeWithWarning,
    /// Withhold until the candidate is revalidated against current
    /// source/projection revisions and the State Fence.
    RequireRevalidation,
    /// Withhold under policy; suppression is explicit, never inferred.
    Suppress,
    /// Isolate as potentially harmful; never silently injectable.
    Quarantine,
}

impl RetrievalAdmissionDecision {
    /// Canonical wire value for this outcome.
    #[must_use]
    pub const fn as_wire_str(self) -> &'static str {
        match self {
            Self::IncludeExact => "INCLUDE_EXACT",
            Self::IncludeHandle => "INCLUDE_HANDLE",
            Self::IncludeWithWarning => "INCLUDE_WITH_WARNING",
            Self::RequireRevalidation => "REQUIRE_REVALIDATION",
            Self::Suppress => "SUPPRESS",
            Self::Quarantine => "QUARANTINE",
        }
    }

    /// The exact six canonical wire values, in I12.26 contract order.
    #[must_use]
    pub const fn canonical_set() -> [&'static str; 6] {
        [
            "INCLUDE_EXACT",
            "INCLUDE_HANDLE",
            "INCLUDE_WITH_WARNING",
            "REQUIRE_REVALIDATION",
            "SUPPRESS",
            "QUARANTINE",
        ]
    }

    /// Resolve an exact canonical wire value to its outcome.
    ///
    /// Only the six [`Self::canonical_set`] spellings resolve; anything else
    /// — including historical confidence labels — returns `None` rather than
    /// coercing to a nearby outcome.
    #[must_use]
    pub fn from_wire_str(value: &str) -> Option<Self> {
        match value {
            "INCLUDE_EXACT" => Some(Self::IncludeExact),
            "INCLUDE_HANDLE" => Some(Self::IncludeHandle),
            "INCLUDE_WITH_WARNING" => Some(Self::IncludeWithWarning),
            "REQUIRE_REVALIDATION" => Some(Self::RequireRevalidation),
            "SUPPRESS" => Some(Self::Suppress),
            "QUARANTINE" => Some(Self::Quarantine),
            _ => None,
        }
    }

    /// Resolve the contract-determined outcome for one membership disposition.
    ///
    /// Only exact-name counterparts resolve: `Include` without warning
    /// evidence is `include_exact`, `Include` with non-blank warning evidence
    /// is `include_with_warning`, and `HandleOnly`, `Revalidate`, `Suppress`,
    /// `Quarantine` resolve to their same-named outcomes. `Unavailable`,
    /// `Blocked`, and `OverBudget` have no I12.26 counterpart and yield
    /// `None`, as does `Include` with blank warning text: the contract
    /// determines no outcome there, and this function refuses to invent one.
    /// The runtime caller owns the total classification as a later slice.
    #[must_use]
    pub fn from_membership(
        disposition: AdmissionDisposition,
        warning: Option<&str>,
    ) -> Option<Self> {
        match disposition {
            AdmissionDisposition::Include => match warning {
                None => Some(Self::IncludeExact),
                Some(text) if text.trim().is_empty() => None,
                Some(_) => Some(Self::IncludeWithWarning),
            },
            AdmissionDisposition::HandleOnly => Some(Self::IncludeHandle),
            AdmissionDisposition::Revalidate => Some(Self::RequireRevalidation),
            AdmissionDisposition::Suppress => Some(Self::Suppress),
            AdmissionDisposition::Quarantine => Some(Self::Quarantine),
            AdmissionDisposition::Unavailable
            | AdmissionDisposition::Blocked
            | AdmissionDisposition::OverBudget => None,
        }
    }
}

/// Closed stale-projection outcome from the pre-admission fence comparison.
///
/// Exactly the I12.26 trichotomy yielded when source/projection revisions and
/// the State Fence disagree before exact cue firing. Wire spelling is
/// `SCREAMING_SNAKE_CASE`.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RetrievalStaleness {
    /// A mandatory (floor) candidate is stale: the projection cannot satisfy
    /// the Safety Floor and must not be cited as current.
    StaleProjection,
    /// The candidate closure was compiled under another fence: reopen the
    /// packet under the current fence instead of admitting across fences.
    PacketRefreshRequired,
    /// An optional candidate is stale: a targeted revalidation probe for that
    /// atom is required before it may be admitted.
    ProbeRequired,
}

impl RetrievalStaleness {
    /// Canonical wire value for this outcome.
    #[must_use]
    pub const fn as_wire_str(self) -> &'static str {
        match self {
            Self::StaleProjection => "STALE_PROJECTION",
            Self::PacketRefreshRequired => "PACKET_REFRESH_REQUIRED",
            Self::ProbeRequired => "PROBE_REQUIRED",
        }
    }

    /// The exact three canonical wire values, in I12.26 contract order.
    #[must_use]
    pub const fn canonical_set() -> [&'static str; 3] {
        [
            "STALE_PROJECTION",
            "PACKET_REFRESH_REQUIRED",
            "PROBE_REQUIRED",
        ]
    }

    /// Resolve an exact canonical wire value to its outcome.
    ///
    /// Only the three [`Self::canonical_set`] spellings resolve; anything
    /// else returns `None` rather than coercing to a nearby outcome.
    #[must_use]
    pub fn from_wire_str(value: &str) -> Option<Self> {
        match value {
            "STALE_PROJECTION" => Some(Self::StaleProjection),
            "PACKET_REFRESH_REQUIRED" => Some(Self::PacketRefreshRequired),
            "PROBE_REQUIRED" => Some(Self::ProbeRequired),
            _ => None,
        }
    }
}

/// Compare candidate fences and freshness against the request before firing.
///
/// Fence disagreement for any candidate yields
/// [`RetrievalStaleness::PacketRefreshRequired`]: the closure was compiled
/// under another fence. A stale mandatory (floor) candidate yields
/// [`RetrievalStaleness::StaleProjection`]; a stale optional candidate yields
/// [`RetrievalStaleness::ProbeRequired`]. The outcome is deterministic and
/// independent of candidate order. This check performs no selection, ranking,
/// or mutation; it only classifies the already-typed closure evidence.
pub fn check_retrieval_freshness(input: &AdmissionInput) -> Result<(), RetrievalStaleness> {
    for candidate in &input.candidates.candidates {
        if !fences_match_exact(
            &input.binding.state_fence,
            &candidate.binding.state_fence,
        ) {
            return Err(RetrievalStaleness::PacketRefreshRequired);
        }
    }
    let floor_ids: BTreeSet<&ArtifactId> = input
        .floor
        .floor
        .members
        .iter()
        .map(|member| &member.atom_id)
        .collect();
    let mut optional_stale = false;
    for candidate in &input.candidates.candidates {
        if candidate.availability == AtomAvailability::Stale {
            if floor_ids.contains(&candidate.atom_id) {
                return Err(RetrievalStaleness::StaleProjection);
            }
            optional_stale = true;
        }
    }
    if optional_stale {
        return Err(RetrievalStaleness::ProbeRequired);
    }
    Ok(())
}

/// Classify the freshness signal for one candidate.
///
/// Returns the fence arm first (closure compiled under another fence), then
/// the stale arms by floor membership, else `None`. Pure and total over the
/// already-typed candidate evidence.
fn material_staleness(
    request_fence: &StateFence,
    candidate: &ContextCandidate,
    floor_ids: &BTreeSet<ArtifactId>,
) -> Option<RetrievalStaleness> {
    if !fences_match_exact(request_fence, &candidate.binding.state_fence) {
        return Some(RetrievalStaleness::PacketRefreshRequired);
    }
    if candidate.availability == AtomAvailability::Stale {
        if floor_ids.contains(&candidate.atom_id) {
            return Some(RetrievalStaleness::StaleProjection);
        }
        return Some(RetrievalStaleness::ProbeRequired);
    }
    None
}

/// Per-material rank-trace linkage for one evaluated candidate.
///
/// This is the admission-side record of the I12.26 `FusedRankTrace`
/// requirement: every material inclusion or suppression resolves to a trace
/// carrying the material identity, the evaluated disposition with its
/// contract-determined outcome slot, the freshness signal, the rule basis,
/// the explicit suppression reason (never inferred), the
/// dependency/invalidation set, the decision anchor locating the material in
/// its packet compilation, and a content-addressed handle resolving to
/// exactly this record. Packet-offset binding inside the assembled view is
/// assembly-owned and remains a later slice.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MaterialRankTrace {
    /// Stable identity of the traced material.
    pub atom_id: ArtifactId,
    /// Evaluated membership disposition for this material.
    pub disposition: AdmissionDisposition,
    /// Contract-determined six-outcome slot; `None` where I12.26 determines
    /// no outcome (see [`RetrievalAdmissionDecision::from_membership`]).
    pub outcome: Option<RetrievalAdmissionDecision>,
    /// Freshness signal for this material, if any.
    pub staleness: Option<RetrievalStaleness>,
    /// Admission rule that evaluated this material (features/exact-relations
    /// basis reference).
    pub rule_evidence: ArtifactId,
    /// Owner-authored suppression text; `None` for admitted material and for
    /// incomplete outcomes that carry no omission record.
    pub suppression_reason: Option<String>,
    /// Interpretation dependency set from the evaluated candidate.
    pub dependencies: Vec<ArtifactId>,
    /// Invalidation handle from the omission record, if any.
    pub invalidation: Option<ArtifactId>,
    /// Decision anchor locating this material in its packet compilation.
    pub decision_id: DecisionId,
    /// Content-addressed handle (`material-trace:<sha256>`) resolving to
    /// exactly this record; swapping any bound fact invalidates the handle.
    pub trace_handle: String,
}

impl MaterialRankTrace {
    /// Validate that the handle resolves to exactly this record.
    ///
    /// Recomputes the content-addressed handle over the handle-cleared
    /// record; a swapped disposition, outcome, reason, dependency,
    /// invalidation, or anchor fails closed.
    pub fn validate(&self) -> Result<(), ContextError> {
        if self.trace_handle != material_trace_handle(self)? {
            return Err(ContextError::InvalidField("material_trace.handle"));
        }
        Ok(())
    }
}

/// Derive the deterministic delivery handle for one material trace.
///
/// The handle is content-addressed (`material-trace:<sha256>`) over the
/// canonical bytes of the handle-cleared record, so it resolves to exactly
/// the delivered selection evidence.
fn material_trace_handle(trace: &MaterialRankTrace) -> Result<String, ContextError> {
    let unsigned = MaterialRankTrace {
        trace_handle: String::new(),
        ..trace.clone()
    };
    Ok(format!(
        "material-trace:{}",
        eliot_context_contracts::canonical_digest(&unsigned)?
    ))
}

/// Join one admission input closure with its result into per-material traces.
///
/// Fails closed via [`AdmissionResult::validate_for`] when the evidence does
/// not conserve the input closure. Every input candidate yields exactly one
/// trace, ordered by atom identity; suppression reasons come only from the
/// owner-authored omission records, never inferred from absence.
pub fn trace_material(
    input: &AdmissionInput,
    result: &AdmissionResult,
) -> Result<Vec<MaterialRankTrace>, ContextError> {
    result.validate_for(input)?;
    let floor_ids: BTreeSet<ArtifactId> = input
        .floor
        .floor
        .members
        .iter()
        .map(|member| member.atom_id.clone())
        .collect();
    let omissions: BTreeMap<&ArtifactId, &OmissionRecord> = result
        .evidence
        .omissions
        .iter()
        .map(|omission| (&omission.atom_id, omission))
        .collect();
    let mut traces = Vec::with_capacity(input.candidates.candidates.len());
    for candidate in &input.candidates.candidates {
        let decision = result
            .evidence
            .decisions
            .iter()
            .find(|item| item.atom_id == candidate.atom_id)
            .ok_or(ContextError::DenominatorMismatch)?;
        let omission = omissions.get(&candidate.atom_id).copied();
        let mut trace = MaterialRankTrace {
            atom_id: candidate.atom_id.clone(),
            disposition: decision.disposition,
            outcome: RetrievalAdmissionDecision::from_membership(decision.disposition, None),
            staleness: material_staleness(
                &input.binding.state_fence,
                candidate,
                &floor_ids,
            ),
            rule_evidence: decision.rule_evidence.clone(),
            suppression_reason: omission.map(|item| item.competing_constraint.clone()),
            dependencies: candidate.dependencies.clone(),
            invalidation: omission.and_then(|item| item.invalidation.clone()),
            decision_id: input.binding.decision_id.clone(),
            trace_handle: String::new(),
        };
        trace.trace_handle = material_trace_handle(&trace)?;
        trace.validate()?;
        traces.push(trace);
    }
    traces.sort_by(|left, right| left.atom_id.cmp(&right.atom_id));
    Ok(traces)
}
