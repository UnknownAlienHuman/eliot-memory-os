//! Shared immutable view of classification facts across admitted profiles.

use eliot_dreamer_contracts::{
    AdmittedTargetRef, ClassificationInput, FeatureObservation, NamedEvidence,
    OrientationClassificationProfile, PriorAssignmentRef, TaxonomyDenominator,
};

/// Fields consumed by the shared taxonomy/evidence selector.
///
/// Admission and publication remain profile-specific. This view only removes
/// the Curation-only envelope from the deterministic semantic scoring core.
pub(crate) struct ClassificationSemantics<'a> {
    pub target: &'a AdmittedTargetRef,
    pub evidence: &'a [NamedEvidence],
    pub features: &'a [FeatureObservation],
    pub taxonomy: &'a TaxonomyDenominator,
    pub prior_assignment: &'a Option<PriorAssignmentRef>,
}

impl<'a> ClassificationSemantics<'a> {
    pub fn from_curation(input: &'a ClassificationInput) -> Self {
        Self {
            target: &input.target,
            evidence: &input.evidence,
            features: &input.features,
            taxonomy: &input.taxonomy,
            prior_assignment: &input.prior_assignment,
        }
    }

    pub fn from_orientation(input: &'a OrientationClassificationProfile) -> Self {
        Self {
            target: &input.target,
            evidence: &input.evidence,
            features: &input.features,
            taxonomy: &input.taxonomy,
            prior_assignment: &input.prior_assignment,
        }
    }
}
