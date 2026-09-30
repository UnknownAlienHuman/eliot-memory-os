//! Validated admission-closure assembly.
//!
//! [`assemble_closure`] builds one complete [`AdmissionInput`] closure from
//! explicit, caller-owned parts and validates it fail-closed before it may
//! reach [`crate::admit_context`]. Part SELECTION policy (which recipe,
//! floor, priority, rule, and measurement owners apply to a decision)
//! belongs to the caller — M1/M2 coordinate it — this owner only assembles
//! the parts verbatim and enforces the closure contract. No defaults are
//! filled, no member is inferred, and no measurement is estimated here.

#![forbid(unsafe_code)]

use eliot_context_contracts::{
    AdmissionInput, AdmissionMeasurement, AdmissionRuleIdentity, ContextBinding,
    ContextCandidateSet, ContextError, ContextRecipe, ContextRecipePolicy,
    MeasurementCompositionProfile, PriorityPolicyIdentity, SafetyFloorIdentity,
    SuppliedOmissionBinding,
};
use eliot_contracts::ContractVersion;

/// Explicit caller-owned parts of one admission closure.
///
/// Shapes mirror [`AdmissionInput`] field for field: the assembler only
/// constructs and validates, never supplies policy.
pub struct ClosureParts {
    /// Contract version the closure is built against.
    pub schema_version: ContractVersion,
    /// Shared task/scope/fence identity every member must carry.
    pub binding: ContextBinding,
    /// Immutable context recipe with capacity and role policies.
    pub recipe: ContextRecipe,
    /// The approved policy revision this recipe instance was issued under.
    ///
    /// Carried verbatim or not at all: the assembler never resolves a catalogue,
    /// never selects a revision and never defaults a section budget. An
    /// `AdmissionInput` built without it carries no approved budget record,
    /// which is the truthful state rather than a synthesized one.
    pub approved_policy: Option<ContextRecipePolicy>,
    /// Candidate set with its provider denominator.
    pub candidates: ContextCandidateSet,
    /// Safety-floor identity with the mandatory floor.
    pub floor: SafetyFloorIdentity,
    /// Priority policy with one declaration per candidate.
    pub priority: PriorityPolicyIdentity,
    /// Admission rule identity with its policy revision.
    pub rule: AdmissionRuleIdentity,
    /// Measurement composition profile qualifying additive costs.
    pub measurement_profile: MeasurementCompositionProfile,
    /// Supplied omission bindings for omittable candidates.
    pub supplied_omissions: Vec<SuppliedOmissionBinding>,
    /// Exact measurements, one per candidate representation.
    pub measurements: Vec<AdmissionMeasurement>,
}

/// Assemble explicit parts into a validated admission closure.
///
/// Constructs the [`AdmissionInput`] verbatim and runs its complete
/// validation (identity, denominator, floor, measurement, priority, and
/// omission closures with fence agreement). Any incoherence fails closed
/// here with stage attribution at the supplier, before admission selection
/// ever fires.
pub fn assemble_closure(parts: ClosureParts) -> Result<AdmissionInput, ContextError> {
    let input = AdmissionInput {
        schema_version: parts.schema_version,
        binding: parts.binding,
        recipe: parts.recipe,
        approved_policy: parts.approved_policy,
        candidates: parts.candidates,
        learning_tickets: Vec::new(),
        floor: parts.floor,
        priority: parts.priority,
        rule: parts.rule,
        measurement_profile: parts.measurement_profile,
        supplied_omissions: parts.supplied_omissions,
        measurements: parts.measurements,
    };
    input.validate()?;
    Ok(input)
}
