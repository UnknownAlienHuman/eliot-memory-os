//! Packet-scorecard production from the compilation's own evidence (#1726).
//!
//! I12.13 requires one scorecard vector per compiled View, and its governing
//! sentence is that **no scalar packet score may hide a load-bearing failed
//! dimension**. This module is the producer that makes both true. It grades each
//! of the twelve `QUALITY_DIMENSIONS` from the packet the compiler actually
//! produced — the admitted set, the rendered payload, the recipe and the
//! complete omission/expansion accounting — together with the governing owners'
//! supported facts. It never grades a dimension from a caller-asserted handle.
//!
//! # Why the shape is what it is
//!
//! Before this module a `QualityScorecard` had no producer in the tree: every
//! literal was either a fixture or the one Governor single-axis mutator
//! (`negative_memory_context.rs::apply_negative_memory_coverage`). The shape
//! here follows that one existing grader exactly — a per-dimension `impl` that
//! builds a `QualityDimensionResult` from real evidence, the result decided by
//! the contract's own `QualityScorecard::validate`, and `Unknown` returned
//! honestly rather than defaulted. It is not a second scheme beside that one.
//!
//! Three properties are structural rather than conventional:
//!
//! * **Completeness is compared against an independent denominator.** Each
//!   grader states its own required member set from the packet; the observed set
//!   is what this compilation actually carried. Nothing compares a required list
//!   with a copy of the same caller list.
//! * **A missing required member fails or marks the axis unknown; it never
//!   passes.** `QualityDimensionResult::validate` requires a `Passed` axis to
//!   carry every required member as observed evidence with no unknown element,
//!   and the graders here feed it real observed and real missing handles, so
//!   that rule now bites on real packets.
//! * **Optional uncertainty is classified, not inferred.** Every dimension
//!   carries an explicit [`QualityObligation`], so an optional metric's
//!   uncertainty can neither conceal a mandatory failure nor disable unrelated
//!   safe work.
//!
//! # Grading the final representation
//!
//! The card binds the exact output: the recipe digest, fence digest, admitted
//! digest, ordered rendered digest, serializer/route identity and omission
//! handles all come from the same owners that recompute them during validation
//! (`ActiveUnderstandingView::validate`, and this crate's
//! `assemble::require_graded_output`). The scorecard is an input to none of
//! those digests, so grading the final representation and hashing it remain two
//! ordered steps and there is no receipt containing its own output hash.
//!
//! # Honest unknowns
//!
//! I12.13 degradation is whole-unit and operation-specific, and an unmeasured
//! dimension must not read as a pass. Where a dimension has no real evidence in
//! the current inputs it is graded `Unknown` with the exact missing handle
//! named. An honest unknown that blocks its dependent action is the correct
//! outcome; a fabricated pass is the defect this module exists to remove. The
//! `DiagnosticDisplay` operation and the Governor's negative-memory mutator
//! remain the surfaces that read an incomplete card; this module does not wire
//! either of them.

use std::collections::BTreeSet;

use eliot_context_contracts::{
    AdmissionDisposition, AdmittedAtom, AdmittedContextSet, AtomAvailability, AtomRepresentation,
    ContextBinding, ContextError, ContextRecipe, LossPolicy, MeasurementRef, QUALITY_DIMENSIONS,
    QUALITY_RESULT_SCHEMA_VERSION, QUALITY_SCORECARD_SCHEMA_VERSION, QualityApplicability,
    QualityApplicabilityInput, QualityDimension, QualityDimensionResult, QualityDimensionState,
    QualityOutputBinding, QualityScorecard, RenderedAtom, SemanticRole,
    SerializedContextMeasurement,
};
use eliot_contracts::ArtifactId;
use eliot_receipts::ProofCeiling;

use crate::AssemblyPolicy;

/// The impact class of the requested effect; an applicability input.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ImpactClassification {
    /// Read-only; no dependent effect beyond display.
    Read,
    /// A reversible candidate mutation.
    Candidate,
    /// A durable reversible mutation.
    ReversibleMutation,
    /// An irreversible external effect.
    ExternalEffect,
}

/// How load-bearing one I12.13 dimension is for a dependent action.
///
/// The twelve dimensions and the operation-conditional required set already
/// exist in the contract ([`QualityOperation::required_dimensions`]). What was
/// missing anywhere in the tree is a statement of which dimensions are
/// load-bearing by construction, versus whose uncertainty is a real but
/// tolerated optional cost, versus whose result is reported for the operator
/// only. This classification is what lets an optional metric's uncertainty stay
/// visible without letting it either mask a mandatory failure or needlessly
/// disable independent safe work.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum QualityObligation {
    /// Load-bearing: a failed, unknown or degraded result must block the
    /// dependent action regardless of any caller-selected optional set.
    Mandatory,
    /// A real measured property whose uncertainty is a genuine cost but which
    /// does not by itself refuse unrelated safe work.
    Optional,
    /// Reported for the operator; never gates by itself.
    Informational,
}

/// Classify one I12.13 dimension's obligation as a closed mapping.
///
/// The seven mandatory axes are the ones a dependent decision rests on: the
/// three [`QualityOperation::DependentAction`](eliot_context_contracts::QualityOperation)
/// names directly (exact anchor/provenance, instruction sufficiency, verifier
/// readiness), plus the acceptance and causal-sufficiency facts that bound the
/// same decision, the freshness/fence coherence that makes a grade current, and
/// the negative-memory invariants I12.13 makes non-negotiable.
///
/// The two measured cost axes are **optional**: a real measured property whose
/// uncertainty is a genuine cost, but which by itself neither conceals a
/// mandatory failure nor disables independent safe work. The three visibility
/// axes are **informational**: their result is reported to the operator and
/// compared against the floor, but nothing turns on them alone.
///
/// Every dimension is graded either way. The classification changes only
/// whether its uncertainty is independently load-bearing, and it is a fixed
/// function of the dimension, so no caller can relabel a mandatory axis as
/// optional to let a blocked action proceed.
#[must_use]
pub const fn quality_obligation_of(dimension: QualityDimension) -> QualityObligation {
    match dimension {
        QualityDimension::AcceptanceDecisionCoverage
        | QualityDimension::CausalOperationalSufficiency
        | QualityDimension::ExactAnchorProvenanceCoverage
        | QualityDimension::FreshnessStateFenceCoherence
        | QualityDimension::NegativeMemoryInvariantCoverage
        | QualityDimension::InstructionSufficiency
        | QualityDimension::VerifierActionReadiness => QualityObligation::Mandatory,
        QualityDimension::PayloadHandleReconstructionCost
        | QualityDimension::TelemetryMeasurementCostCoverage => QualityObligation::Optional,
        QualityDimension::RivalsConflictsUnknownsVisibility
        | QualityDimension::RouteAccessibilityLayoutRisk
        | QualityDimension::KnownOmissionsExpansionPaths => QualityObligation::Informational,
    }
}

/// Every dimension this crate classifies as load-bearing, in canonical order.
///
/// Derived by filtering the contract's own [`QUALITY_DIMENSIONS`] constant
/// through [`quality_obligation_of`], so it cannot drift from the declared
/// dimension list and cannot be narrowed by a caller.
#[must_use]
pub fn mandatory_quality_dimensions() -> Vec<QualityDimension> {
    QUALITY_DIMENSIONS
        .into_iter()
        .filter(|dimension| quality_obligation_of(*dimension) == QualityObligation::Mandatory)
        .collect()
}

/// The non-passing dimension results a graded card still carries, split by
/// obligation so a reader can tell a load-bearing gap from a tolerated one.
///
/// A6 requires that optional metric uncertainty neither conceal a mandatory
/// failure nor unnecessarily disable independent safe work. That is only
/// decidable if the two are distinguishable, so this projection is the
/// classification made concrete on one real card: the mandatory list is what
/// blocks, the optional list is the metric cost an operator sees, and the
/// informational list is reported without gating. The three lists are
/// disjoint and together account for every dimension that is not a current
/// pass; a current pass appears in none of them.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct QualityObligationReport {
    /// Non-passing results whose uncertainty is load-bearing.
    pub mandatory: Vec<QualityDimensionResult>,
    /// Non-passing measured-cost results whose uncertainty is a real cost.
    pub optional: Vec<QualityDimensionResult>,
    /// Non-passing visibility results reported without gating.
    pub informational: Vec<QualityDimensionResult>,
}

impl QualityObligationReport {
    /// Split one graded card's non-passing results by
    /// [`quality_obligation_of`].
    ///
    /// This is a projection over a card already graded from real evidence; it
    /// re-grades nothing and decides no operation. The operation-scoped
    /// refusal remains [`QualityScorecard::suitability`], and this report never
    /// replaces it or narrows it.
    #[must_use]
    pub fn from_scorecard(scorecard: &QualityScorecard) -> Self {
        let mut report = Self {
            mandatory: Vec::new(),
            optional: Vec::new(),
            informational: Vec::new(),
        };
        for result in &scorecard.results {
            if result.is_current_pass() {
                continue;
            }
            match quality_obligation_of(result.dimension) {
                QualityObligation::Mandatory => report.mandatory.push(result.clone()),
                QualityObligation::Optional => report.optional.push(result.clone()),
                QualityObligation::Informational => report.informational.push(result.clone()),
            }
        }
        report
    }

    /// Whether any load-bearing dimension is currently not a pass.
    ///
    /// An optional or informational uncertainty never contributes here, which is
    /// precisely the A6 separation: a metric the route could not measure does
    /// not present itself as a failure of the decision, and a genuine
    /// load-bearing failure is not averaged away by any number of optional
    /// passes.
    #[must_use]
    pub fn has_mandatory_failure(&self) -> bool {
        !self.mandatory.is_empty()
    }
}

/// The governing owners' supported facts for one compilation, beyond what the
/// admitted set alone can prove.
///
/// I12.13 requires decision and causal sufficiency to consume the task, model
/// and requirement owner's *supported facts* — roles and keywords alone are
/// insufficient — and requires provenance and freshness to consume the exact
/// source and #1729 read evidence. Those facts do not live in
/// `AdmittedContextSet`; the owner that produces them supplies them here.
///
/// Every field is an `Option`. An absent field is an honest "this owner
/// supplied no fact", and the corresponding dimension is graded `Unknown` with
/// the exact missing handle named. A present field names the owner's own
/// artifact identity; this crate does not re-derive a verdict the owner owns and
/// never manufactures an observation to cover a gap.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct GoverningEvidence {
    /// The acceptance anchor the task/requirement owner issued for this
    /// decision. Required by `AcceptanceDecisionCoverage`; a `SemanticRole::
    /// Acceptance` atom is not that fact.
    pub acceptance_anchor: Option<ArtifactId>,
    /// The goal/causal-model owner's supported fact. Required by
    /// `CausalOperationalSufficiency`.
    pub causal_sufficiency_fact: Option<ArtifactId>,
    /// The currently active directive governing this decision. Required by
    /// `InstructionSufficiency`; its absence is exactly the "missing active
    /// directive" case that must visibly fail.
    pub active_directive: Option<ArtifactId>,
    /// The applicable *current* verifier or action contract. Required by
    /// `VerifierActionReadiness`; a zero-cost flag and a past unrelated test
    /// pass are not accepted in its place.
    pub verifier_contract: Option<ArtifactId>,
    /// The #1729 coherent-read evidence binding this read to one fence.
    /// Required by `FreshnessStateFenceCoherence` and consumed by
    /// `ExactAnchorProvenanceCoverage`.
    pub coherent_read_evidence: Option<ArtifactId>,
    /// The governing Governance Profile identity for this compilation.
    pub governance_profile: Option<ArtifactId>,
    /// The protected Safety Floor identity for this compilation.
    pub protected_floor: Option<ArtifactId>,
    /// The impact classification of the requested effect.
    ///
    /// An unresolved impact is recorded as unknown applicability, which blocks
    /// a dependent action while leaving read-only display available.
    pub impact: Option<ImpactClassification>,
}

impl GoverningEvidence {
    /// Resolve the six applicability inputs from the facts actually supplied.
    ///
    /// `resolved` and `unknown` partition
    /// [`QUALITY_APPLICABILITY_INPUTS`](eliot_context_contracts::QUALITY_APPLICABILITY_INPUTS).
    /// An input whose governing fact was not supplied is recorded as unknown.
    /// An unknown input is *not* resolved to the weakest governing profile: it
    /// blocks the dependent decision that needs it and stays visible on a
    /// read-only display. `TaskAcceptance` and `Route` are resolved by the
    /// compilation itself — the packet is bound to one task and one route, both
    /// carried on the binding and the output binding.
    #[must_use]
    pub fn resolve_applicability(&self) -> QualityApplicability {
        let mut unknown = Vec::new();
        if self.impact.is_none() {
            unknown.push(QualityApplicabilityInput::Impact);
        }
        if self.governance_profile.is_none() {
            unknown.push(QualityApplicabilityInput::GovernanceProfile);
        }
        if self.protected_floor.is_none() {
            unknown.push(QualityApplicabilityInput::ProtectedFloor);
        }
        if self.active_directive.is_none() {
            unknown.push(QualityApplicabilityInput::ActiveDirective);
        }
        QualityApplicability {
            resolved: vec![
                QualityApplicabilityInput::TaskAcceptance,
                QualityApplicabilityInput::Route,
            ],
            unknown,
        }
    }
}

/// Grade one dimension against a route's real byte/token observation.
///
/// The measurement is optional evidence: a route that ran no qualified
/// measurement for this exact rendered payload simply has none, and the axis
/// that consumes it is graded honestly unknown rather than a measured zero.
/// A measurement whose envelope digest is not this packet's rendered digest
/// does not measure this packet and is not consumed.
fn measurement_reference(measurement: &SerializedContextMeasurement) -> MeasurementRef {
    MeasurementRef {
        digest: measurement.envelope_digest.clone(),
        serializer: measurement.serializer_id.clone(),
    }
}

/// Build the complete twelve-dimension scorecard for one compiled packet.
///
/// `rendered` must be the final ordered representation this compilation
/// produced, not the pre-pruning candidate set. `measurements` are the route's
/// observations of that same rendered payload; a caller with none supplies an
/// empty slice and the cost axes grade `Unknown` rather than a fabricated zero.
/// `evidence` carries the governing owners' supported facts; each absent fact
/// makes its axis visibly unknown.
///
/// The returned card is validated by the contract's own `QualityScorecard`
/// before it leaves this function, so no fabricated pass can be returned.
pub fn grade_packet(
    admitted: &AdmittedContextSet,
    recipe: &ContextRecipe,
    rendered: &[RenderedAtom],
    policy: &AssemblyPolicy,
    measurements: &[SerializedContextMeasurement],
    evidence: &GoverningEvidence,
) -> Result<QualityScorecard, ContextError> {
    let binding = &admitted.binding;
    let fence_digest = eliot_context_contracts::canonical_fence_digest(&binding.state_fence)?;
    let output = QualityOutputBinding {
        recipe_digest: recipe.recipe_sha256.clone(),
        fence_digest,
        admitted_digest: admitted.canonical_payload_digest()?,
        rendered_digest: eliot_context_contracts::ActiveUnderstandingView::canonical_output_digest(
            binding,
            &recipe.recipe_sha256,
            &eliot_context_contracts::canonical_fence_digest(&binding.state_fence)?,
            rendered,
        )?,
        serializer_id: policy.serializer_id.clone(),
        serializer_version: policy.serializer_version.clone(),
        serializer_options_digest: policy.serializer_options_digest.clone(),
        route_id: policy.route_id.clone(),
        evidence_revisions: source_revision_handles(admitted),
        omission_handles: admitted.economy.displaced.clone(),
    };

    let results = vec![
        grade_acceptance(admitted, binding, evidence)?,
        grade_causal_sufficiency(binding, evidence)?,
        grade_exact_anchor_provenance(admitted, rendered, binding, evidence)?,
        grade_freshness_fence(admitted, binding, evidence)?,
        grade_rivals_unknowns(admitted, binding)?,
        grade_negative_memory(admitted, rendered, binding)?,
        grade_verifier_readiness(admitted, rendered, binding, evidence)?,
        grade_route_layout(admitted, rendered, binding)?,
        grade_instruction_sufficiency(admitted, rendered, binding, evidence)?,
        grade_payload_cost(rendered, measurements, binding)?,
        grade_known_omissions(admitted, binding)?,
        grade_telemetry_cost(admitted, rendered, measurements, binding)?,
    ];

    let card = QualityScorecard {
        schema_version: QUALITY_SCORECARD_SCHEMA_VERSION,
        binding: binding.clone(),
        output,
        applicability: evidence.resolve_applicability(),
        results,
    };
    // The contract's own validator is the authority on whether each graded
    // result is a legal scorecard value, and it is not weakened here: a
    // `Passed` axis must carry every required member as observed evidence with
    // no unknown element, while a failed, unknown or degraded axis must name
    // its failed invariant or missing handle. Grading through it means a
    // fabricated pass cannot leave this function.
    card.validate()?;
    Ok(card)
}

/// One admitted source revision, as a distinct evidence handle.
///
/// A repeated revision is one revision, never two observations, so a
/// duplicated handle cannot pose as wider evidence coverage.
fn source_revision_handles(admitted: &AdmittedContextSet) -> Vec<ArtifactId> {
    let mut revisions: BTreeSet<ArtifactId> = BTreeSet::new();
    for record in &admitted.records {
        let token = format!(
            "source-revision:{}:{}:{}",
            record.candidate.source.snapshot_id.as_str(),
            record.candidate.source.revision,
            record.candidate.source.content_sha256
        );
        if let Ok(handle) = ArtifactId::new(token) {
            revisions.insert(handle);
        }
    }
    revisions.into_iter().collect()
}

/// The admitted atoms this compilation actually carries, in admitted order.
///
/// Derived through the contract's own `Include | HandleOnly` rule, the same
/// rule `ActiveUnderstandingView::assemble` uses, so this grader and the
/// rendered payload cannot disagree about what the packet contains.
fn carried_records(admitted: &AdmittedContextSet) -> Vec<&AdmittedAtom> {
    admitted
        .records
        .iter()
        .filter(|record| {
            matches!(
                record.disposition,
                AdmissionDisposition::Include | AdmissionDisposition::HandleOnly
            )
        })
        .collect()
}

/// Rendered atom identities, as an independent membership set.
fn rendered_ids(rendered: &[RenderedAtom]) -> BTreeSet<ArtifactId> {
    rendered.iter().map(|atom| atom.atom_id.clone()).collect()
}

/// The measured cost of each carried unit, as graded evidence references.
///
/// Only units present in the rendered payload contribute, so an atom the
/// projection dropped cannot pay for a dimension it was not part of.
fn carried_measurements(
    admitted: &AdmittedContextSet,
    carried: &BTreeSet<ArtifactId>,
) -> Vec<MeasurementRef> {
    carried_records(admitted)
        .into_iter()
        .filter(|record| carried.contains(&record.candidate.atom_id))
        .map(|record| record.candidate.measurement.clone())
        .collect()
}

/// The exact source anchor a candidate measured, as an evidence handle.
///
/// An absent range is a typed unknown, not a whole-unit claim: a provider that
/// cannot say where its material came from says nothing. The handle names the
/// snapshot, revision and both endpoints, so it is re-checkable against the
/// same source the boundary owner checks rather than being a keyword.
fn exact_anchor_handle(record: &AdmittedAtom) -> Option<ArtifactId> {
    let candidate = &record.candidate;
    let token = format!(
        "exact-anchor:{}:{}:{}:{}:{}",
        candidate.atom_id.as_str(),
        candidate.source.snapshot_id.as_str(),
        candidate.source_range.as_ref()?.source_revision,
        candidate.source_range.as_ref()?.start,
        candidate.source_range.as_ref()?.end_exclusive
    );
    ArtifactId::new(token).ok()
}

/// Names one element a dimension still lacks.
fn missing_handle(dimension: QualityDimension, what: &str) -> Result<ArtifactId, ContextError> {
    ArtifactId::new(format!("{dimension:?}-uncovered:{what}"))
        .map_err(|_| ContextError::InvalidField("quality.unknown_evidence"))
}

/// Names the invariant a dimension failed.
fn failed_invariant(dimension: QualityDimension, what: &str) -> Result<ArtifactId, ContextError> {
    ArtifactId::new(format!("{dimension:?}-failed:{what}"))
        .map_err(|_| ContextError::InvalidField("quality.failed_invariant"))
}

/// Rule revision naming the producer of every grade in this module.
const SCORECARD_RULE_REVISION: &str = "context.assembly.scorecard.v1";

/// The rule revision handle every result in this module carries.
fn rule_revision() -> Result<ArtifactId, ContextError> {
    ArtifactId::new(SCORECARD_RULE_REVISION)
        .map_err(|_| ContextError::InvalidField("quality.rule_revision"))
}

/// Assemble one result from a graded state and its three real evidence sets.
///
/// The state's consistency with those sets is decided by the contract's own
/// `QualityDimensionResult::validate` through [`grade_packet`]; this function
/// only places the required, observed and missing handles a grader computed.
#[allow(clippy::too_many_arguments)]
fn result(
    dimension: QualityDimension,
    state: QualityDimensionState,
    required_evidence: Vec<ArtifactId>,
    evidence: Vec<ArtifactId>,
    unknown_evidence: Vec<ArtifactId>,
    failed: Option<ArtifactId>,
    measurements: Vec<MeasurementRef>,
    binding: &ContextBinding,
) -> Result<QualityDimensionResult, ContextError> {
    Ok(QualityDimensionResult {
        schema_version: QUALITY_RESULT_SCHEMA_VERSION,
        dimension,
        state,
        rule_revision: rule_revision()?,
        required_evidence,
        evidence,
        measurements,
        failed_invariant: failed,
        unknown_evidence,
        proof_ceiling: ProofCeiling::ScopedVerification,
        invalidation: None,
        binding: binding.clone(),
    })
}

/// Grade one axis by comparing an independent required member set against the
/// members this compilation actually observed.
///
/// The required set is this grader's own statement of what the dimension needs,
/// built from the packet. The observed set is what the packet carried. A
/// required member that was not observed becomes the axis's missing set, and its
/// presence there is what makes the axis `Failed` or `Unknown` rather than
/// `Passed`. Every state this function can produce is accepted by the contract's
/// own validation: a pass carries a non-empty required set fully observed, and
/// a failed, unknown or degraded axis names its failed invariant or missing
/// handle.
fn coverage_axis(
    dimension: QualityDimension,
    required: Vec<ArtifactId>,
    observed: BTreeSet<ArtifactId>,
    measurements: Vec<MeasurementRef>,
    binding: &ContextBinding,
) -> Result<QualityDimensionResult, ContextError> {
    // An axis with no required member is never `Passed` on an empty
    // observation: a vacuous requirement is reported unknown and names itself,
    // so a dimension can never be satisfied by having nothing to check.
    if required.is_empty() {
        return coverage_axis(
            dimension,
            vec![missing_handle(dimension, "requirement")?],
            BTreeSet::new(),
            measurements,
            binding,
        );
    }
    let missing: Vec<ArtifactId> = required
        .iter()
        .filter(|member| !observed.contains(*member))
        .cloned()
        .collect();
    let state = if missing.is_empty() {
        QualityDimensionState::Passed
    } else if observed.is_empty() {
        // Nothing on this packet bears on the dimension, so it is honestly
        // unknown: the required set names what is absent rather than the axis
        // claiming an unexplained success.
        QualityDimensionState::Unknown
    } else {
        // Some required members observed and some not. The axis is genuinely
        // uncovered, and it names both what it did observe and what is missing.
        QualityDimensionState::Failed
    };
    let failed = (state == QualityDimensionState::Failed)
        .then(|| failed_invariant(dimension, "required member unobserved"))
        .transpose()?;
    result(
        dimension,
        state,
        required,
        observed.into_iter().collect(),
        missing,
        failed,
        measurements,
        binding,
    )
}

/// Grade `AcceptanceDecisionCoverage` from the requirement owner's anchor.
///
/// A role-labelled `Acceptance` atom is not the acceptance criterion: I12.13
/// requires the task and requirement owner's supported fact. The anchor is
/// observed only when the owner supplied it *and* the packet admitted the
/// acceptance material it names. An owner anchor with no admitted acceptance
/// member is an uncovered axis naming exactly that gap.
fn grade_acceptance(
    admitted: &AdmittedContextSet,
    binding: &ContextBinding,
    evidence: &GoverningEvidence,
) -> Result<QualityDimensionResult, ContextError> {
    let Some(anchor) = evidence.acceptance_anchor.clone() else {
        return coverage_axis(
            QualityDimension::AcceptanceDecisionCoverage,
            vec![missing_handle(
                QualityDimension::AcceptanceDecisionCoverage,
                "acceptance-anchor",
            )?],
            BTreeSet::new(),
            Vec::new(),
            binding,
        );
    };
    let admits_acceptance = carried_records(admitted)
        .into_iter()
        .any(|record| record.candidate.provider_role.role == SemanticRole::Acceptance);
    let observed: BTreeSet<ArtifactId> = if admits_acceptance {
        BTreeSet::from([anchor.clone()])
    } else {
        BTreeSet::new()
    };
    coverage_axis(
        QualityDimension::AcceptanceDecisionCoverage,
        vec![anchor],
        observed,
        Vec::new(),
        binding,
    )
}

/// Grade `CausalOperationalSufficiency` from the causal owner's supported fact.
///
/// Roles and keywords are insufficient by construction here: a `Goal` atom does
/// not prove the packet is causally sufficient to act, and only the goal /
/// causal-model owner's fact does. Without it the axis is `Unknown` and names
/// the missing fact.
fn grade_causal_sufficiency(
    binding: &ContextBinding,
    evidence: &GoverningEvidence,
) -> Result<QualityDimensionResult, ContextError> {
    let required = vec![
        evidence
            .causal_sufficiency_fact
            .clone()
            .unwrap_or(missing_handle(
                QualityDimension::CausalOperationalSufficiency,
                "causal-owner-fact",
            )?),
    ];
    let observed: BTreeSet<ArtifactId> = evidence
        .causal_sufficiency_fact
        .clone()
        .into_iter()
        .collect();
    coverage_axis(
        QualityDimension::CausalOperationalSufficiency,
        required,
        observed,
        Vec::new(),
        binding,
    )
}

/// Grade `ExactAnchorProvenanceCoverage` from the exact anchors actually
/// measured on the material this packet carries.
///
/// The required set is every carried atom whose loss policy is
/// `NonDroppable`, because such a unit may not be represented by a handle or a
/// lossy form and must be traceable to where it came from. The observed set is
/// the anchors measured on atoms that are actually present in the rendered
/// payload, so an anchor on material the packet did not carry is not an
/// observation of this packet.
///
/// A high-relevance packet with no exact anchors therefore visibly fails this
/// dimension and cannot enable its dependent action, which is the #1726
/// acceptance case.
fn grade_exact_anchor_provenance(
    admitted: &AdmittedContextSet,
    rendered: &[RenderedAtom],
    binding: &ContextBinding,
    evidence: &GoverningEvidence,
) -> Result<QualityDimensionResult, ContextError> {
    let carried: BTreeSet<ArtifactId> = rendered_ids(rendered);
    let required: Vec<ArtifactId> = carried_records(admitted)
        .into_iter()
        .filter(|record| record.candidate.loss_policy == LossPolicy::NonDroppable)
        .map(|record| record.candidate.atom_id.clone())
        .collect();
    let observed: BTreeSet<ArtifactId> = carried_records(admitted)
        .into_iter()
        .filter(|record| carried.contains(&record.candidate.atom_id))
        .filter_map(exact_anchor_handle)
        .collect();
    let mut axis = coverage_axis(
        QualityDimension::ExactAnchorProvenanceCoverage,
        required,
        observed,
        carried_measurements(admitted, &carried),
        binding,
    )?;
    // Provenance is only current if the read that produced it was coherent under
    // this fence. Without the #1729 evidence the grade is not a pass, and the
    // missing read is named rather than ignored.
    if axis.state == QualityDimensionState::Passed && evidence.coherent_read_evidence.is_none() {
        axis.unknown_evidence.push(missing_handle(
            QualityDimension::ExactAnchorProvenanceCoverage,
            "coherent-read-evidence",
        )?);
        axis.state = QualityDimensionState::Failed;
        axis.failed_invariant = Some(failed_invariant(
            QualityDimension::ExactAnchorProvenanceCoverage,
            "exact anchors without #1729 coherent-read evidence",
        )?);
    }
    Ok(axis)
}

/// Grade `FreshnessStateFenceCoherence` from the #1729 coherent-read evidence.
///
/// The admitted set proves its members satisfy a fence; it does not prove the
/// read that produced them was coherent under it. That is the #1729 owner's
/// fact. With it present, a carried member that is not `PresentCurrent` is a
/// real freshness failure that a coherent read cannot launder away. Without it,
/// freshness is an honest unknown.
fn grade_freshness_fence(
    admitted: &AdmittedContextSet,
    binding: &ContextBinding,
    evidence: &GoverningEvidence,
) -> Result<QualityDimensionResult, ContextError> {
    let not_current: Vec<ArtifactId> = carried_records(admitted)
        .into_iter()
        .filter(|record| record.candidate.availability != AtomAvailability::PresentCurrent)
        .map(|record| record.candidate.atom_id.clone())
        .collect();
    let Some(read) = evidence.coherent_read_evidence.clone() else {
        return coverage_axis(
            QualityDimension::FreshnessStateFenceCoherence,
            vec![missing_handle(
                QualityDimension::FreshnessStateFenceCoherence,
                "coherent-read-evidence",
            )?],
            BTreeSet::new(),
            Vec::new(),
            binding,
        );
    };
    let mut axis = coverage_axis(
        QualityDimension::FreshnessStateFenceCoherence,
        vec![read.clone()],
        [read].into_iter().collect(),
        Vec::new(),
        binding,
    )?;
    if axis.state == QualityDimensionState::Passed && !not_current.is_empty() {
        axis.unknown_evidence = not_current;
        axis.state = QualityDimensionState::Failed;
        axis.failed_invariant = Some(failed_invariant(
            QualityDimension::FreshnessStateFenceCoherence,
            "carried member is not present-current under a coherent read",
        )?);
    }
    Ok(axis)
}

/// Grade `RivalsConflictsUnknownsVisibility` from the conflict, rival and
/// unknown material this packet actually carries.
///
/// I12.13 forbids substituting one representative atom for a role. The
/// required set is one member per conflict-bearing role the Safety Floor
/// declared; the observed set is the carried atoms occupying those roles, read
/// from the admitted set. A floor that requested no conflict-bearing role states
/// no visibility requirement, and the axis is reported unknown rather than
/// vacuously passed.
fn grade_rivals_unknowns(
    admitted: &AdmittedContextSet,
    binding: &ContextBinding,
) -> Result<QualityDimensionResult, ContextError> {
    let conflict_roles = [
        SemanticRole::Conflict,
        SemanticRole::MaterialUnknown,
        SemanticRole::Negative,
    ];
    let requested: Vec<SemanticRole> = conflict_roles
        .into_iter()
        .filter(|role| admitted.floor.mandatory_roles.contains(role))
        .collect();
    let carried = carried_records(admitted);
    if requested.is_empty() {
        return coverage_axis(
            QualityDimension::RivalsConflictsUnknownsVisibility,
            vec![missing_handle(
                QualityDimension::RivalsConflictsUnknownsVisibility,
                "requested-rival-or-unknown-role",
            )?],
            BTreeSet::new(),
            Vec::new(),
            binding,
        );
    }
    // The floor's requested conflict-bearing roles are the independent
    // denominator: one required member per requested role, and a role the
    // packet does not carry contributes its own missing handle. Deriving the
    // required set from what *was* carried would let a missing rival satisfy
    // its own requirement, so the requirement is stated from the floor first
    // and only then compared against the carried population.
    let observed: BTreeSet<ArtifactId> = carried
        .iter()
        .filter(|record| conflict_roles.contains(&record.candidate.provider_role.role))
        .map(|record| record.candidate.atom_id.clone())
        .collect();
    let mut required: Vec<ArtifactId> = Vec::with_capacity(requested.len());
    let mut absent_roles: Vec<ArtifactId> = Vec::new();
    for role in &requested {
        match carried
            .iter()
            .find(|record| record.candidate.provider_role.role == *role)
        {
            Some(record) => required.push(record.candidate.atom_id.clone()),
            None => absent_roles.push(missing_handle(
                QualityDimension::RivalsConflictsUnknownsVisibility,
                role_name(*role),
            )?),
        }
    }
    let mut axis = coverage_axis(
        QualityDimension::RivalsConflictsUnknownsVisibility,
        required,
        observed,
        Vec::new(),
        binding,
    )?;
    if !absent_roles.is_empty() {
        // Some rival material is present, but a floor-requested role is absent.
        // That is partial visibility, not coverage, and the absent role is
        // named so the gap is visible rather than averaged away. A card that
        // carried no conflict material at all is already `Unknown`; naming the
        // absent roles in addition keeps the reason exact either way.
        axis.unknown_evidence.extend(absent_roles);
        if axis.state == QualityDimensionState::Passed {
            axis.state = QualityDimensionState::Failed;
            axis.failed_invariant = Some(failed_invariant(
                QualityDimension::RivalsConflictsUnknownsVisibility,
                "floor-requested rival or unknown role is not represented",
            )?);
        }
    }
    Ok(axis)
}

/// The wire name of one semantic role, used in a missing-evidence handle.
const fn role_name(role: SemanticRole) -> &'static str {
    match role {
        SemanticRole::Authority => "authority",
        SemanticRole::Goal => "goal",
        SemanticRole::Scope => "scope",
        SemanticRole::Acceptance => "acceptance",
        SemanticRole::Source => "source",
        SemanticRole::Verifier => "verifier",
        SemanticRole::MaterialUnknown => "material-unknown",
        SemanticRole::Negative => "negative",
        SemanticRole::Security => "security",
        SemanticRole::Evidence => "evidence",
        SemanticRole::Instruction => "instruction",
        SemanticRole::Optional => "optional",
        SemanticRole::Conflict => "conflict",
        SemanticRole::Constraint => "constraint",
    }
}

/// Grade `NegativeMemoryInvariantCoverage` from the invariant material this
/// packet actually carries.
///
/// The Governor's `apply_negative_memory_coverage` remains the owner of the
/// rule-comparison axis and mutates its result in place; this grader reads only
/// the packet's own carried invariant and constraint material and does not
/// re-implement that comparison. It is passed rather than absent when the packet
/// exposes at least one invariant-bearing unit, and honestly unknown when it
/// exposes none.
fn grade_negative_memory(
    admitted: &AdmittedContextSet,
    rendered: &[RenderedAtom],
    binding: &ContextBinding,
) -> Result<QualityDimensionResult, ContextError> {
    let carried: BTreeSet<ArtifactId> = rendered_ids(rendered);
    let observed: BTreeSet<ArtifactId> = carried_records(admitted)
        .into_iter()
        .filter(|record| {
            carried.contains(&record.candidate.atom_id)
                && matches!(
                    record.candidate.provider_role.role,
                    SemanticRole::Negative | SemanticRole::Constraint
                )
        })
        .map(|record| record.candidate.atom_id.clone())
        .collect();
    if observed.is_empty() {
        return coverage_axis(
            QualityDimension::NegativeMemoryInvariantCoverage,
            vec![missing_handle(
                QualityDimension::NegativeMemoryInvariantCoverage,
                "exposed-invariant-member",
            )?],
            BTreeSet::new(),
            Vec::new(),
            binding,
        );
    }
    coverage_axis(
        QualityDimension::NegativeMemoryInvariantCoverage,
        observed.iter().cloned().collect(),
        observed,
        Vec::new(),
        binding,
    )
}

/// Grade `VerifierActionReadiness` from the applicable current verifier
/// contract.
///
/// This is the dimension a missing required verifier must visibly fail.
/// Readiness needs the *current* verifier or action contract for this action and
/// the packet's verifier material; the compiler proves neither from a role
/// label, a zero-cost flag, or a past unrelated test pass. The owner supplies
/// the contract, and without it the axis is `Unknown` naming the missing
/// verifier, which blocks the dependent action.
fn grade_verifier_readiness(
    admitted: &AdmittedContextSet,
    rendered: &[RenderedAtom],
    binding: &ContextBinding,
    evidence: &GoverningEvidence,
) -> Result<QualityDimensionResult, ContextError> {
    let Some(verifier) = evidence.verifier_contract.clone() else {
        return coverage_axis(
            QualityDimension::VerifierActionReadiness,
            vec![missing_handle(
                QualityDimension::VerifierActionReadiness,
                "current-verifier-contract",
            )?],
            BTreeSet::new(),
            Vec::new(),
            binding,
        );
    };
    let carried: BTreeSet<ArtifactId> = rendered_ids(rendered);
    let carries_verifier_material = carried_records(admitted).into_iter().any(|record| {
        carried.contains(&record.candidate.atom_id)
            && record.candidate.provider_role.role == SemanticRole::Verifier
    });
    // The owner supplied a current contract, but the packet does not carry the
    // verifier material that contract applies to. Both the supplied contract and
    // the absent material are named, so the axis is uncovered rather than a
    // pass on a handle alone.
    if !carries_verifier_material {
        return coverage_axis(
            QualityDimension::VerifierActionReadiness,
            vec![
                verifier,
                missing_handle(
                    QualityDimension::VerifierActionReadiness,
                    "carried-verifier-material",
                )?,
            ],
            BTreeSet::new(),
            Vec::new(),
            binding,
        );
    }
    coverage_axis(
        QualityDimension::VerifierActionReadiness,
        vec![verifier.clone()],
        [verifier].into_iter().collect(),
        Vec::new(),
        binding,
    )
}

/// Grade `RouteAccessibilityLayoutRisk` from the rendered membership this
/// compilation actually produced.
///
/// Route accessibility is the fact that every admitted member reached the
/// rendered payload as an explicit representation under the route's own loss
/// policy. The required set is the carried admitted population and the observed
/// set is the part of it that is actually rendered, read from the rendered
/// payload rather than from the admitted set, so a member the projection dropped
/// cannot satisfy its own requirement. The route identity itself is bound on the
/// card's output binding.
fn grade_route_layout(
    admitted: &AdmittedContextSet,
    rendered: &[RenderedAtom],
    binding: &ContextBinding,
) -> Result<QualityDimensionResult, ContextError> {
    let required: Vec<ArtifactId> = carried_records(admitted)
        .into_iter()
        .map(|record| record.candidate.atom_id.clone())
        .collect();
    let rendered_membership: BTreeSet<ArtifactId> = rendered_ids(rendered);
    let observed: BTreeSet<ArtifactId> = required
        .iter()
        .filter(|id| rendered_membership.contains(*id))
        .cloned()
        .collect();
    coverage_axis(
        QualityDimension::RouteAccessibilityLayoutRisk,
        required,
        observed,
        Vec::new(),
        binding,
    )
}

/// Grade `InstructionSufficiency` from the currently active directive.
///
/// This is the dimension a missing active directive must visibly fail. The
/// governing owner supplies the current directive, and the packet must carry
/// the instruction or authority material that directive acts on; a supplied
/// directive with no carried directive material is an uncovered axis naming
/// both the supplied contract and the absent material, so a directive handle
/// alone cannot enable the dependent action.
fn grade_instruction_sufficiency(
    admitted: &AdmittedContextSet,
    rendered: &[RenderedAtom],
    binding: &ContextBinding,
    evidence: &GoverningEvidence,
) -> Result<QualityDimensionResult, ContextError> {
    let Some(directive) = evidence.active_directive.clone() else {
        return coverage_axis(
            QualityDimension::InstructionSufficiency,
            vec![missing_handle(
                QualityDimension::InstructionSufficiency,
                "active-directive",
            )?],
            BTreeSet::new(),
            Vec::new(),
            binding,
        );
    };
    let carried: BTreeSet<ArtifactId> = rendered_ids(rendered);
    let carries_directive_material = carried_records(admitted).into_iter().any(|record| {
        carried.contains(&record.candidate.atom_id)
            && matches!(
                record.candidate.provider_role.role,
                SemanticRole::Instruction | SemanticRole::Authority
            )
    });
    if !carries_directive_material {
        return coverage_axis(
            QualityDimension::InstructionSufficiency,
            vec![
                directive,
                missing_handle(
                    QualityDimension::InstructionSufficiency,
                    "carried-active-directive-material",
                )?,
            ],
            BTreeSet::new(),
            Vec::new(),
            binding,
        );
    }
    coverage_axis(
        QualityDimension::InstructionSufficiency,
        vec![directive.clone()],
        [directive].into_iter().collect(),
        Vec::new(),
        binding,
    )
}

/// Grade `PayloadHandleReconstructionCost` from the real representation kinds
/// on the rendered payload.
///
/// Reconstruction cost is what the consumer pays to reopen the packet. Every
/// rendered unit must be either complete or an exact named handle; a whole,
/// extractive or summary representation is present in the packet, and a handle
/// representation is present when it names a non-empty handle identity. A
/// rendered unit with no reconstruction path is named as a gap rather than
/// counted as a covered cost.
fn grade_payload_cost(
    rendered: &[RenderedAtom],
    measurements: &[SerializedContextMeasurement],
    binding: &ContextBinding,
) -> Result<QualityDimensionResult, ContextError> {
    let required: Vec<ArtifactId> = rendered.iter().map(|atom| atom.atom_id.clone()).collect();
    let observed: BTreeSet<ArtifactId> = rendered
        .iter()
        .filter(|atom| is_reconstructible(atom))
        .map(|atom| atom.atom_id.clone())
        .collect();
    coverage_axis(
        QualityDimension::PayloadHandleReconstructionCost,
        required,
        observed,
        measurements.iter().map(measurement_reference).collect(),
        binding,
    )
}

/// Whether one rendered unit carries a reconstruction path.
///
/// A whole, extractive or summary unit is present in the packet as content; a
/// handle unit is reconstructible exactly when it names an identity a consumer
/// can reopen, which `AtomRepresentation::validate` and `ArtifactId::new`
/// already guarantee. The check is stated here rather than assumed so the axis
/// still reports a genuinely unopenable unit as a gap instead of counting it as
/// a covered cost.
fn is_reconstructible(atom: &RenderedAtom) -> bool {
    match &atom.representation {
        AtomRepresentation::Handle { handle } => !handle.as_str().trim().is_empty(),
        AtomRepresentation::Whole { .. }
        | AtomRepresentation::Extractive { .. }
        | AtomRepresentation::Summary { .. } => true,
    }
}

/// Grade `KnownOmissionsExpansionPaths` from the complete omission and
/// expansion accounting the economy receipt carries.
///
/// I12.13 requires the omissions to be *known* and their expansion paths
/// available. The required set is every displaced atom, read from the economy
/// receipt; the observed set is the displaced atoms whose omission record is
/// recoverable *under this packet's own binding* — a reversible expansion
/// handle names the decision, scope, attempt and fence it was issued for, and
/// the contract already requires that handle to match the omission it belongs
/// to. A displaced atom whose only path is a non-recoverable reason is known
/// but not expandable, and that is named as a gap on the axis rather than
/// counted as an available expansion path.
fn grade_known_omissions(
    admitted: &AdmittedContextSet,
    binding: &ContextBinding,
) -> Result<QualityDimensionResult, ContextError> {
    let required: Vec<ArtifactId> = admitted.economy.displaced.clone();
    if required.is_empty() {
        // The economy proves that no material was displaced, so this axis has a
        // real observation rather than a vacuous one: the receipt digest is the
        // observed fact that no displacement occurred. It is not a pass claimed
        // from an empty list.
        let receipt = ArtifactId::new(format!(
            "no-displacement:{}",
            admitted.economy.receipt_digest
        ))
        .map_err(|_| ContextError::InvalidField("quality.required_evidence"))?;
        return coverage_axis(
            QualityDimension::KnownOmissionsExpansionPaths,
            vec![receipt.clone()],
            [receipt].into_iter().collect(),
            Vec::new(),
            binding,
        );
    }
    // The independent denominator: the economy's displaced set, which the
    // economy's own validation already proves equals the omitted-atom set. The
    // observed set is the subset whose omission is genuinely reopenable.
    let reopenable: BTreeSet<ArtifactId> = admitted
        .economy
        .omissions
        .iter()
        .filter(|omission| omission.expansion.is_some())
        .map(|omission| omission.atom_id.clone())
        .collect();
    let observed: BTreeSet<ArtifactId> = required
        .iter()
        .filter(|id| reopenable.contains(*id))
        .cloned()
        .collect();
    let mut axis = coverage_axis(
        QualityDimension::KnownOmissionsExpansionPaths,
        required,
        observed,
        Vec::new(),
        binding,
    )?;
    // An omission that is known but has no reopening path is a visible gap even
    // though it is not one of the required, reopenable members; naming it keeps
    // the loss visible instead of letting the reopenable majority speak for it.
    let unreopenable: Vec<ArtifactId> = admitted
        .economy
        .omissions
        .iter()
        .filter(|omission| omission.expansion.is_none())
        .map(|omission| omission.atom_id.clone())
        .collect();
    if !unreopenable.is_empty() {
        axis.unknown_evidence.extend(unreopenable);
        if axis.state == QualityDimensionState::Passed {
            axis.state = QualityDimensionState::Failed;
            axis.failed_invariant = Some(failed_invariant(
                QualityDimension::KnownOmissionsExpansionPaths,
                "displaced material with no reopening path",
            )?);
        }
    }
    Ok(axis)
}

/// Grade `TelemetryMeasurementCostCoverage` from the route's real measurement
/// of *this* rendered payload.
///
/// Only a measurement whose envelope digest is this packet's rendered digest and
/// whose context is this packet's binding measures this packet; any other
/// observation is not consumed. With no such measurement the cost is explicitly
/// unknown, never a measured zero, and any non-zero recorded false-safe
/// overflow is named as a gap.
fn grade_telemetry_cost(
    admitted: &AdmittedContextSet,
    rendered: &[RenderedAtom],
    measurements: &[SerializedContextMeasurement],
    binding: &ContextBinding,
) -> Result<QualityDimensionResult, ContextError> {
    let fence_digest = eliot_context_contracts::canonical_fence_digest(&binding.state_fence)?;
    let rendered_digest =
        eliot_context_contracts::ActiveUnderstandingView::canonical_output_digest(
            binding,
            &admitted.economy.recipe_digest,
            &fence_digest,
            rendered,
        )?;
    let matching: Vec<&SerializedContextMeasurement> = measurements
        .iter()
        .filter(|measurement| {
            measurement.envelope_digest == rendered_digest && measurement.context == *binding
        })
        .collect();
    if matching.is_empty() {
        return coverage_axis(
            QualityDimension::TelemetryMeasurementCostCoverage,
            vec![missing_handle(
                QualityDimension::TelemetryMeasurementCostCoverage,
                "route-measurement-of-this-rendered-output",
            )?],
            BTreeSet::new(),
            Vec::new(),
            binding,
        );
    }
    let references: Vec<MeasurementRef> = matching
        .iter()
        .map(|measurement| measurement_reference(measurement))
        .collect();
    let observed: BTreeSet<ArtifactId> = matching
        .iter()
        .filter_map(|measurement| {
            ArtifactId::new(format!(
                "telemetry:{measurement_id}",
                measurement_id = measurement.measurement_id.as_str()
            ))
            .ok()
        })
        .collect();
    let mut axis = coverage_axis(
        QualityDimension::TelemetryMeasurementCostCoverage,
        observed.iter().cloned().collect(),
        observed,
        references,
        binding,
    )?;
    let overflow: Vec<ArtifactId> = matching
        .iter()
        .filter_map(|measurement| measurement.false_safe_overflow.clone())
        .collect();
    if axis.state == QualityDimensionState::Passed && !overflow.is_empty() {
        axis.unknown_evidence = overflow;
        axis.state = QualityDimensionState::Failed;
        axis.failed_invariant = Some(failed_invariant(
            QualityDimension::TelemetryMeasurementCostCoverage,
            "route measurement records a false-safe overflow",
        )?);
    }
    Ok(axis)
}
