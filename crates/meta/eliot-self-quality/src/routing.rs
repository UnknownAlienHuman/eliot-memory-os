//! Deterministic routing of self-quality observations to inert owner handoffs.
//!
//! Routing is a pure precedence table over one observation's dimension,
//! status, counterevidence refs, and family name. It assigns an external
//! decision owner; it never plans, executes, or authorizes anything.
//!
//! # Precedence (first match wins)
//!
//! 1. Non-empty `counterevidence_refs` or family `MEMORY_CONFLICT` =>
//!    [`SelfQualityHandoffOwner::ConflictAnalysis673`].
//! 2. Dimension [`SelfQualityDimension::ReconciliationUnknownEffects`] or family
//!    `RECOVERY` / `ERASURE_INFLUENCE` =>
//!    [`SelfQualityHandoffOwner::IncidentRecovery`].
//! 3. Family `SECURITY_PRIVACY` => [`SelfQualityHandoffOwner::HumanPrivacy`].
//! 4. Family `HUMAN_ATTENTION` => [`SelfQualityHandoffOwner::HumanPolicy`].
//! 5. Family `COST_QUOTA` => [`SelfQualityHandoffOwner::HumanCostRisk`].
//! 6. Family `PRODUCT` => [`SelfQualityHandoffOwner::HumanObjective`].
//! 7. Family `PERFORMANCE_RESOURCES` / `MEMORY_PROVENANCE` =>
//!    [`SelfQualityHandoffOwner::MaintenancePlan677`].
//! 8. Family `RECOVERY_COMPATIBILITY` / `SOURCE_BUILD` =>
//!    [`SelfQualityHandoffOwner::ConfigurationAssistance679`].
//! 9. Dimension [`SelfQualityDimension::LearningQuality`] /
//!    [`SelfQualityDimension::ContextQuality`], or status
//!    [`DimensionStatus::Inconclusive`] =>
//!    [`SelfQualityHandoffOwner::Instrumentation`].
//! 10. Otherwise => [`SelfQualityHandoffOwner::DevelopmentDiagnosis675`].
//!
//! [`SelfQualityHandoffOwner::UnsupportedOwner`] is never returned, and
//! [`SelfQualityHandoffOwner::Instrumentation`] is returned only by rule 9.
//!
//! # Memory-provenance problem refs
//!
//! Memory-provenance findings routed to
//! [`SelfQualityHandoffOwner::MaintenancePlan677`] must carry a problem ref of
//! the form `memory-repair:<observation_ref>` (callers and fixture authors do
//! this when building handoffs by hand; [`crate::diagnose::diagnose_self_quality`]
//! does this automatically for `MEMORY_PROVENANCE` findings).

use eliot_conformance_contracts::{
    DimensionStatus, Priority, SELF_QUALITY_CONTRACT_VERSION, SelfQualityDimension,
    SelfQualityHandoff, SelfQualityHandoffOwner, SelfQualityObservation, validate_handoff,
};

use crate::error::SelfQualityError;

/// Route one observation to its inert handoff owner.
///
/// Pure and deterministic: inspects `observation.core()` (dimension, status,
/// counterevidence refs) and `observation.family_name()`, then applies the
/// precedence table documented above.
pub fn route_owner(observation: &SelfQualityObservation) -> SelfQualityHandoffOwner {
    let core = observation.core();
    let family = observation.family_name();
    if !core.counterevidence_refs.is_empty() || family == "MEMORY_CONFLICT" {
        return SelfQualityHandoffOwner::ConflictAnalysis673;
    }
    if core.dimension == SelfQualityDimension::ReconciliationUnknownEffects
        || family == "RECOVERY"
        || family == "ERASURE_INFLUENCE"
    {
        return SelfQualityHandoffOwner::IncidentRecovery;
    }
    if family == "SECURITY_PRIVACY" {
        return SelfQualityHandoffOwner::HumanPrivacy;
    }
    if family == "HUMAN_ATTENTION" {
        return SelfQualityHandoffOwner::HumanPolicy;
    }
    if family == "COST_QUOTA" {
        return SelfQualityHandoffOwner::HumanCostRisk;
    }
    if family == "PRODUCT" {
        return SelfQualityHandoffOwner::HumanObjective;
    }
    if family == "PERFORMANCE_RESOURCES" || family == "MEMORY_PROVENANCE" {
        return SelfQualityHandoffOwner::MaintenancePlan677;
    }
    if family == "RECOVERY_COMPATIBILITY" || family == "SOURCE_BUILD" {
        return SelfQualityHandoffOwner::ConfigurationAssistance679;
    }
    if core.dimension == SelfQualityDimension::LearningQuality
        || core.dimension == SelfQualityDimension::ContextQuality
        || core.status == DimensionStatus::Inconclusive
    {
        return SelfQualityHandoffOwner::Instrumentation;
    }
    SelfQualityHandoffOwner::DevelopmentDiagnosis675
}

/// Build one inert handoff to an external owner.
///
/// Clones every ref collection into sorted order, stamps
/// [`SELF_QUALITY_CONTRACT_VERSION`], and validates with the normative
/// [`validate_handoff`]. Empty symptom, problem, evidence, applicability, or
/// invalidation collections are rejected as contract errors; nothing is
/// defaulted or repaired. Pure: no clock, no I/O.
///
/// The `#[allow]` below exists only because the frozen four-test-agent API
/// fixes ten parameters on this constructor.
///
#[allow(clippy::too_many_arguments)]
pub fn make_handoff(
    handoff_ref: &str,
    owner: SelfQualityHandoffOwner,
    symptom_refs: &[String],
    problem_refs: &[String],
    evidence_refs: &[String],
    missing_evidence_refs: &[String],
    applicability_refs: &[String],
    priority: Priority,
    constraint_refs: &[String],
    invalidation_set: &[String],
) -> Result<SelfQualityHandoff, SelfQualityError> {
    fn ordered(values: &[String]) -> Vec<String> {
        let mut out = values.to_vec();
        out.sort();
        out
    }
    let handoff = SelfQualityHandoff {
        contract_version: SELF_QUALITY_CONTRACT_VERSION,
        handoff_ref: handoff_ref.to_owned(),
        owner,
        symptom_refs: ordered(symptom_refs),
        problem_refs: ordered(problem_refs),
        evidence_refs: ordered(evidence_refs),
        missing_evidence_refs: ordered(missing_evidence_refs),
        applicability_refs: ordered(applicability_refs),
        priority,
        constraint_refs: ordered(constraint_refs),
        invalidation_set: ordered(invalidation_set),
    };
    validate_handoff(&handoff).map_err(SelfQualityError::Contract)?;
    Ok(handoff)
}
