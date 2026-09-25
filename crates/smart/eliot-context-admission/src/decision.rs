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
//! membership disposition; [`classify_admission`] resolves the exact-name
//! counterparts into [`RetrievalAdmissionDecision`] and carries every other
//! case on the explicit typed unable-path with its owner evidence preserved,
//! rather than inventing a mapping the contract did not determine.

#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};

use eliot_context_contracts::{
    AdmissionDisposition, AdmissionInput, AdmissionResult, AdmissionRuleIdentity, AtomAvailability,
    ContextCandidate, ContextError, ContextOutcome, OmissionRecord,
};
use eliot_contracts::{ArtifactId, DecisionId, StateFence, fences_match_exact};
use eliot_evidence::{Assertability, EpistemicStatus};
use eliot_reactive_context_plan::RetrievalPlan;
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
}

/// Owner-backed evidence for classifying one evaluated candidate.
///
/// Every field comes from an owning record: the membership disposition from
/// the admission decision, the optional warning text from explicit caller
/// evidence, the rule identity from the admission rule owner, the
/// availability from the candidate's freshness owner, and the floor flag
/// from the Safety Floor owner.
///
/// Warning-text ownership (I12.26 `include_with_warning`: framing,
/// staleness bound, or contradiction risk staying below suppression) is
/// assigned, not invented here. The live channel is candidate-owned
/// epistemic evidence evaluated by [`derive_candidate_warnings`] under the
/// canonical [`ContextCandidate::validate`] coherence rule (see below);
/// lane producers (projection owners and successors) may additionally mint
/// [`SuppliedWarning`] records threaded through the warning-capable join.
/// Governor risk stays factual and separate: its atom-keyed attestation
/// never authorises warning text here, and no tier maps to any outcome.
/// [`classify_admission`] keeps the total unable-path for absent evidence;
/// no new outcome kind is created.
pub struct ClassificationEvidence<'a> {
    /// Evaluated membership disposition for the candidate.
    pub disposition: AdmissionDisposition,
    /// Explicit warning evidence for an admitted unit, if any.
    pub warning: Option<&'a str>,
    /// Admission rule that evaluated the candidate.
    pub rule: &'a AdmissionRuleIdentity,
    /// Freshness state of the evaluated candidate.
    pub availability: AtomAvailability,
    /// Whether the candidate is a mandatory floor member.
    pub floor_member: bool,
}

/// Total classification of one evaluated candidate.
///
/// Every membership disposition yields exactly one value: the five
/// contract-determined outcomes resolve to [`RetrievalAdmissionDecision`],
/// while `Unavailable`, `Blocked`, and `OverBudget` — which have no I12.26
/// counterpart — and blank warning text take the explicit typed unable-path.
/// The unable arm carries the exact evaluated disposition with the owner
/// evidence that was considered, so the runtime can route it without any
/// renamed quotient: nothing is coerced into `Suppress` or any other outcome
/// the contract did not determine.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "classification", deny_unknown_fields)]
pub enum ClassifiedAdmission {
    /// Contract-determined six-outcome slot.
    Decided(RetrievalAdmissionDecision),
    /// No I12.26 counterpart determined; exact evidence preserved verbatim.
    Undetermined {
        /// Evaluated membership disposition, unmapped and unrenamed.
        disposition: AdmissionDisposition,
        /// Freshness state that was considered.
        availability: AtomAvailability,
        /// Floor membership that was considered.
        floor_member: bool,
        /// Admission rule that evaluated the candidate.
        rule_id: ArtifactId,
    },
}

impl ClassifiedAdmission {
    /// The decided outcome, if the contract determined one.
    #[must_use]
    pub const fn decided(&self) -> Option<RetrievalAdmissionDecision> {
        match self {
            Self::Decided(outcome) => Some(*outcome),
            Self::Undetermined { .. } => None,
        }
    }
}

/// Classify one evaluated candidate over owner-backed evidence.
///
/// Total and deterministic: exact-name counterparts
/// (`Include` without warning evidence, `HandleOnly`, `Revalidate`,
/// `Suppress`, `Quarantine`) decide their same-named outcome, `Include` with
/// non-blank warning evidence decides `include_with_warning`, and every
/// other case — `Unavailable`, `Blocked`, `OverBudget`, blank warning text —
/// takes the typed unable-path with its evidence preserved. No arm invents a
/// quotient the contract did not determine.
#[must_use]
pub fn classify_admission(evidence: &ClassificationEvidence<'_>) -> ClassifiedAdmission {
    let undetermined = || ClassifiedAdmission::Undetermined {
        disposition: evidence.disposition,
        availability: evidence.availability,
        floor_member: evidence.floor_member,
        rule_id: evidence.rule.rule_id.clone(),
    };
    match evidence.disposition {
        AdmissionDisposition::Include => match evidence.warning {
            None => ClassifiedAdmission::Decided(RetrievalAdmissionDecision::IncludeExact),
            Some(text) if text.trim().is_empty() => undetermined(),
            Some(_) => ClassifiedAdmission::Decided(RetrievalAdmissionDecision::IncludeWithWarning),
        },
        AdmissionDisposition::HandleOnly => {
            ClassifiedAdmission::Decided(RetrievalAdmissionDecision::IncludeHandle)
        }
        AdmissionDisposition::Revalidate => {
            ClassifiedAdmission::Decided(RetrievalAdmissionDecision::RequireRevalidation)
        }
        AdmissionDisposition::Suppress => {
            ClassifiedAdmission::Decided(RetrievalAdmissionDecision::Suppress)
        }
        AdmissionDisposition::Quarantine => {
            ClassifiedAdmission::Decided(RetrievalAdmissionDecision::Quarantine)
        }
        AdmissionDisposition::Unavailable
        | AdmissionDisposition::Blocked
        | AdmissionDisposition::OverBudget => undetermined(),
    }
}

/// Maximum Unicode scalar values admitted in one warning text.
pub const MAX_WARNING_TEXT_CHARS: usize = 1024;

/// Owner-minted warning evidence for one evaluated candidate.
///
/// The text is authored by exactly one of the assigned warning owners
/// (Governor risk, conflict-analysis, or projection owners) and threaded
/// by the runtime join through [`trace_material_with_warnings`]; the
/// admission owner validates the shape (bounded non-blank text over a
/// referenced input candidate) and binds the text into the trace handle,
/// but never authors, interprets, or maps the content. A warning never
/// invents an outcome: admitted candidates carrying non-blank warning
/// evidence classify to `include_with_warning` through the unchanged
/// [`classify_admission`] arm, and every other disposition keeps its
/// contract-determined mapping.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SuppliedWarning {
    /// Stable identity of the warned material.
    pub atom_id: ArtifactId,
    /// Owner-authored warning text.
    pub text: String,
}

impl SuppliedWarning {
    /// Validate shape without interpreting content: the text is bounded
    /// non-blank UTF-8 without control characters. Content authority
    /// travels with the minting owner through the runtime join, never
    /// with this shape check.
    pub fn validate(&self) -> Result<(), ContextError> {
        validate_warning_text(&self.text)
    }
}

fn validate_warning_text(value: &str) -> Result<(), ContextError> {
    if value.trim().is_empty() || value.chars().any(char::is_control) {
        return Err(ContextError::InvalidField("admission.warning.text"));
    }
    if value.chars().count() > MAX_WARNING_TEXT_CHARS {
        return Err(ContextError::Bounds {
            field: "admission.warning.text",
        });
    }
    Ok(())
}

/// Derive owner warning evidence from one candidate's epistemic record.
///
/// ## Canonical grounding (exact, no quotient)
///
/// Governing fragment
/// `docs/architecture/I12-26-memory-admission-and-retrieval-trace.md:29-40`
/// requires the decision to evaluate epistemic status/freshness (`:33`)
/// and contradiction and framing risk (`:37`); `:42-51` closes the outcome
/// to the six kinds with `include_with_warning` (`:47`); `:71` forces the
/// pre-firing revision/fence compare. [`ContextCandidate::validate`]
/// (`crates/smart/eliot-context-contracts/src/atom.rs:570-624`) imposes
/// the coherence lattice this derivation reads, it invents nothing:
///
/// - `Observed`/`Unknown` or `Stale`/`Contested`/`Superseded`/`Rejected`
///   status can never pair with `Assertable`; `Verified` requires it.
/// - `PresentCurrent` availability can never pair with `Stale`/`Superseded`
///   status, so epistemic staleness on admitted material is owned by the
///   availability gate, never by this derivation.
///
/// Hence admitted material carrying `Contested` status is the I12.26
/// contradiction risk below suppression (the analysis preserves without
/// resolving; the decision admits with warning), and admitted material
/// whose assertability is not `Assertable` carries the validity-imposed
/// framing qualification (attributed or fenced, never asserted). Clean
/// pairs (`Supported`/`Verified` with `Assertable`) derive nothing. Each
/// signal is quoted by its canonical wire spelling in fixed order
/// (epistemic status, then assertability); the text is bounded short
/// literals, so it always satisfies [`SuppliedWarning::validate`].
/// Selection is untouched: degraded statuses that policy must suppress
/// stay a disposition/policy matter, never a warning invention here.
#[must_use]
pub fn derive_candidate_warnings(candidate: &ContextCandidate) -> Option<SuppliedWarning> {
    let mut signals = Vec::new();
    if candidate.status == EpistemicStatus::Contested {
        signals.push("epistemic:CONTESTED");
    }
    match candidate.assertability {
        Assertability::Assertable => {}
        Assertability::NonAssertableUnverified => {
            signals.push("assertability:NON_ASSERTABLE_UNVERIFIED");
        }
        Assertability::AbstainOrFence => {
            signals.push("assertability:ABSTAIN_OR_FENCE");
        }
    }
    if signals.is_empty() {
        return None;
    }
    Some(SuppliedWarning {
        atom_id: candidate.atom_id.clone(),
        text: signals.join("; "),
    })
}

/// Derive the warning set for one admission input closure.
///
/// Applies [`derive_candidate_warnings`] to every input candidate in
/// canonical atom-identity order. The runtime join threads the result
/// into [`trace_material_with_warnings`]; admitted candidates carrying
/// derived evidence classify to `include_with_warning` through the
/// unchanged [`classify_admission`] arm. Pure over the input: no I/O, no
/// selection, no mutation.
#[must_use]
pub fn derive_input_warnings(input: &AdmissionInput) -> Vec<SuppliedWarning> {
    let mut warnings: Vec<SuppliedWarning> = input
        .candidates
        .candidates
        .iter()
        .filter_map(derive_candidate_warnings)
        .collect();
    warnings.sort_by(|left, right| left.atom_id.cmp(&right.atom_id));
    warnings
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
        if !fences_match_exact(&input.binding.state_fence, &candidate.binding.state_fence) {
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

/// Compare candidate source revisions against plan expectations.
///
/// For every fence-matching candidate, the candidate's actual source
/// revision must resolve against a plan-supplied `expected_revision`:
/// fence-disagreeing candidates defer to the fence arm
/// (`PacketRefreshRequired`) and take no revision verdict here.
///
/// ## Owning record and namespace semantics
///
/// The actual comparand is the source owner's revision string on the
/// candidate; the expected comparand is the retrieval owner's
/// `expected_revision` on the matching plan fence entry, matched by exact
/// source-owner identity. Revision strings are an opaque source-owner
/// namespace — they are not task counters and never task-revision values;
/// no text-to-counter equivalence is assumed or constructed anywhere in
/// this comparison, only exact string equality within one source owner.
///
/// ## Fail-closed coverage
///
/// An unresolved compare rejects: a fence-matching candidate whose source
/// has no plan entry, or whose entry states no expectation, yields
/// [`RetrievalStaleness::StaleProjection`] when mandatory (floor) and
/// [`RetrievalStaleness::ProbeRequired`] when optional. Silence would admit
/// material the plan owner never bound. Floor verdicts report before
/// optional ones, so the outcome is deterministic and independent of
/// candidate order. This check performs no selection, ranking, or
/// mutation; the runtime join runs it beside plan validation before
/// admission firing.
pub fn check_plan_revisions(
    plan: &RetrievalPlan,
    input: &AdmissionInput,
) -> Result<(), RetrievalStaleness> {
    let floor_ids: BTreeSet<&ArtifactId> = input
        .floor
        .floor
        .members
        .iter()
        .map(|member| &member.atom_id)
        .collect();
    let mut optional_unresolved = false;
    for candidate in &input.candidates.candidates {
        // Fence disagreement is owned by the fence arm
        // (`check_retrieval_freshness` → `PacketRefreshRequired`):
        // revision expectations bind only under a matching fence, so a
        // cross-fence closure always routes to packet refresh rather than
        // to a stale/probe verdict here.
        if !fences_match_exact(&input.binding.state_fence, &candidate.binding.state_fence) {
            continue;
        }
        let resolved = plan
            .source_projection_fences
            .iter()
            .find(|entry| entry.source == candidate.source.source_id)
            .and_then(|entry| entry.expected_revision.as_deref())
            .is_some_and(|expected| candidate.source.revision == *expected);
        if !resolved {
            if floor_ids.contains(&candidate.atom_id) {
                return Err(RetrievalStaleness::StaleProjection);
            }
            optional_unresolved = true;
        }
    }
    if optional_unresolved {
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
    /// Total classification for this material: the contract-determined
    /// six-outcome slot, or the explicit typed unable-path with its owner
    /// evidence preserved verbatim.
    pub outcome: ClassifiedAdmission,
    /// Freshness signal for this material, if any.
    pub staleness: Option<RetrievalStaleness>,
    /// Admission rule that evaluated this material (features/exact-relations
    /// basis reference).
    pub rule_evidence: ArtifactId,
    /// Owner-authored suppression text; `None` for admitted material and for
    /// incomplete outcomes that carry no omission record.
    pub suppression_reason: Option<String>,
    /// Owner-minted warning text bound at the join; `None` when no warning
    /// was supplied for this material. Covered by `trace_handle`, so a
    /// swapped warning invalidates the handle exactly like any other fact.
    pub warning: Option<String>,
    /// Interpretation dependency set from the evaluated candidate.
    pub dependencies: Vec<ArtifactId>,
    /// Invalidation handle from the omission record, if any.
    pub invalidation: Option<ArtifactId>,
    /// Decision anchor locating this material in its packet compilation.
    pub decision_id: DecisionId,
    /// Owner-backed capacity signal: true when this material was admitted
    /// while the admission economy reported zero remaining headroom. Read
    /// directly from the admission economy receipt; it classifies nothing by
    /// itself and never remaps the outcome.
    pub capacity_constrained: bool,
    /// Content-addressed handle (`material-trace:<sha256>`) resolving to
    /// exactly this record; swapping any bound fact invalidates the handle.
    pub trace_handle: String,
}

impl MaterialRankTrace {
    /// Validate that the handle resolves to exactly this record.
    ///
    /// Recomputes the content-addressed handle over the handle-cleared
    /// record; a swapped disposition, outcome, reason, warning, dependency,
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
/// owner-authored omission records, never inferred from absence. No warning
/// evidence applies on this path; use [`trace_material_with_warnings`] to
/// bind owner-minted warnings.
pub fn trace_material(
    input: &AdmissionInput,
    result: &AdmissionResult,
) -> Result<Vec<MaterialRankTrace>, ContextError> {
    build_traces(input, result, &BTreeMap::new())
}

/// Join one admission input closure with its result and owner warnings.
///
/// Same conservation as [`trace_material`], plus one owner-minted
/// [`SuppliedWarning`] channel: every warning validates fail-closed, must
/// reference an input candidate, and must name each warned atom at most
/// once — an unknown atom is [`ContextError::DenominatorMismatch`], a
/// repeat is [`ContextError::Duplicate`]. Admitted candidates carrying
/// non-blank warning evidence classify to `include_with_warning` through
/// the unchanged [`classify_admission`] arm; the text is bound into the
/// trace handle verbatim.
pub fn trace_material_with_warnings(
    input: &AdmissionInput,
    result: &AdmissionResult,
    warnings: &[SuppliedWarning],
) -> Result<Vec<MaterialRankTrace>, ContextError> {
    let candidates: BTreeSet<&ArtifactId> = input
        .candidates
        .candidates
        .iter()
        .map(|candidate| &candidate.atom_id)
        .collect();
    let mut bound = BTreeMap::new();
    for warning in warnings {
        warning.validate()?;
        if !candidates.contains(&warning.atom_id) {
            return Err(ContextError::DenominatorMismatch);
        }
        if bound
            .insert(&warning.atom_id, warning.text.as_str())
            .is_some()
        {
            return Err(ContextError::Duplicate("admission.warning.atom_id"));
        }
    }
    build_traces(input, result, &bound)
}

fn build_traces(
    input: &AdmissionInput,
    result: &AdmissionResult,
    warnings: &BTreeMap<&ArtifactId, &str>,
) -> Result<Vec<MaterialRankTrace>, ContextError> {
    result.validate_for(input)?;
    let floor_ids: BTreeSet<ArtifactId> = input
        .floor
        .floor
        .members
        .iter()
        .map(|member| member.atom_id.clone())
        .collect();
    // Owner-backed capacity fact: the admitted economy reports zero remaining
    // headroom. Read once from the receipt that owns it; per-material use
    // below only records the signal, never reinterprets it.
    let headroom_exhausted = matches!(
        &result.outcome,
        ContextOutcome::Complete(set) if set.economy.allocations.remaining_headroom == 0
    );
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
        let warning = warnings.get(&candidate.atom_id).copied();
        let mut trace = MaterialRankTrace {
            atom_id: candidate.atom_id.clone(),
            disposition: decision.disposition,
            outcome: classify_admission(&ClassificationEvidence {
                disposition: decision.disposition,
                // Owner-minted warning evidence threaded by the runtime
                // join; `None` on the warning-free path classifies exactly
                // as before, never synthesized here.
                warning,
                rule: &input.rule,
                availability: candidate.availability,
                floor_member: floor_ids.contains(&candidate.atom_id),
            }),
            staleness: material_staleness(&input.binding.state_fence, candidate, &floor_ids),
            rule_evidence: decision.rule_evidence.clone(),
            suppression_reason: omission.map(|item| item.competing_constraint.clone()),
            warning: warning.map(str::to_owned),
            dependencies: candidate.dependencies.clone(),
            invalidation: omission.and_then(|item| item.invalidation.clone()),
            decision_id: input.binding.decision_id.clone(),
            capacity_constrained: headroom_exhausted
                && matches!(
                    decision.disposition,
                    AdmissionDisposition::Include | AdmissionDisposition::HandleOnly
                ),
            trace_handle: String::new(),
        };
        trace.trace_handle = material_trace_handle(&trace)?;
        trace.validate()?;
        traces.push(trace);
    }
    traces.sort_by(|left, right| left.atom_id.cmp(&right.atom_id));
    Ok(traces)
}
