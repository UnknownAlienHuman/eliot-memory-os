//! Exact typed precision checks used by the grounding binder.

use eliot_dreamer_contracts::grounding::canonical::CausalStatus;
use eliot_dreamer_contracts::grounding::{MaterialClaim, PrecisionPayload};

/// Checks the full typed precision payload, including all fields owned by its
/// precision class. Equality is deliberately exact: a narrowed range,
/// changed version, omitted rival, or altered attribution is not covered.
pub(crate) fn payload_matches(claim: &MaterialClaim, assertion: &PrecisionPayload) -> bool {
    claim.payload == *assertion
}

/// Performs class-specific checks which are not represented by equality alone.
pub(crate) fn class_is_groundable(claim: &MaterialClaim, manifest_has_denominator: bool) -> bool {
    match &claim.payload {
        PrecisionPayload::Causal { causal } => {
            matches!(
                causal.status,
                CausalStatus::Mechanism
                    | CausalStatus::InterventionSupported
                    | CausalStatus::AblationSupported
            ) && !causal.mechanism.trim().is_empty()
                && !causal.rivals.is_empty()
                && !causal.confounders.is_empty()
        }
        PrecisionPayload::AbsenceExhaustiveNegative { absence_proof, .. } => {
            absence_proof.is_some() && manifest_has_denominator
        }
        _ => true,
    }
}

/// Finds class-specific precision limitations without inventing a new status
/// vocabulary. These strings are bounded diagnostic details in the A03 record.
pub(crate) fn precision_findings(
    claim: &MaterialClaim,
    manifest_has_denominator: bool,
) -> impl Iterator<Item = &'static str> {
    let mut findings = Vec::new();
    match &claim.payload {
        PrecisionPayload::Causal { causal }
            if matches!(
                causal.status,
                CausalStatus::Mechanism
                    | CausalStatus::InterventionSupported
                    | CausalStatus::AblationSupported
            ) && (causal.rivals.is_empty() || causal.confounders.is_empty()) =>
        {
            findings.push("causal mechanism requires rivals and confounders");
        }
        PrecisionPayload::AbsenceExhaustiveNegative { absence_proof, .. } => {
            if absence_proof.is_none() {
                findings.push("absence requires canonical complete proof");
            }
            if !manifest_has_denominator {
                findings.push("absence denominator is absent from the manifest");
            }
        }
        _ => {}
    }
    findings.into_iter()
}
