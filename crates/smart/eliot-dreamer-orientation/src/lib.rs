//! Basic problem-oriented `DreamPacket` projection.
//!
//! This crate is a pure candidate owner: it reads an A03 validated aggregate,
//! projects admitted material, and performs no acquisition, promotion, write,
//! authority, effect, self-query, clarification, or probe execution.

#![forbid(unsafe_code)]

pub mod input;
pub mod policy;
pub mod projection;
pub mod result;

pub use input::{
    AdmittedOrientationJob, CanonicalEvidenceHandle, CoverageCepMember, CoverageEvidenceMember,
    CurrentEpistemicPositionHandle, LocalOrientationFrame, OrientationCoverageDenominator,
    OrientationError, ValidatedOrientationCandidate,
};
pub use policy::OrientationPolicy;
pub use projection::{
    AnchoredEvidence, InertProbe, OrientationCoverage, OrientationInterpretation,
    OrientationPacketCandidate, OrientationProvenance, OrientationResidue, OrientationSection,
    OrientationSectionKind,
};
pub use result::{OrientationDisposition, OrientationResult};

/// Pure five-input Orientation projector.
pub fn project_orientation(
    admitted_orientation_job: &AdmittedOrientationJob,
    bounded_bundle: &eliot_dreamer_contracts::DreamInputBundle,
    validated_dream_draft: &ValidatedOrientationCandidate,
    current_epistemic_position_handles: &[CurrentEpistemicPositionHandle],
    orientation_policy: &OrientationPolicy,
) -> OrientationResult {
    projection::build_projection(
        admitted_orientation_job,
        validated_dream_draft,
        bounded_bundle,
        current_epistemic_position_handles,
        orientation_policy,
    )
}
