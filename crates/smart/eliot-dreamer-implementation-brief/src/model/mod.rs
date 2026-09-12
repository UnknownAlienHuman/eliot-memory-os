mod evidence;
mod input;
mod output;
mod source;

pub use evidence::{
    CurrentEvidenceTarget, EvidenceVerdict, ImplementationEvidence, ProofStage,
};
pub use input::{
    ImplementationBriefInput, ImplementationDenominator, ImplementationMechanism,
    ImplementationObligation,
};
pub use output::{
    EvidenceAxisSnapshot, ImplementationBriefDisposition, ImplementationBriefProjection,
    ImplementationGap, ImplementationGapClass, ImplementationOmission, MechanismAssessment,
    MechanismDisposition, ObligationAssessment,
};
pub use source::{
    ImplementationSourceSnapshot, ImplementationSourceStatus, ImplementationStatement,
    ImplementationStatementKind,
};

/// Current wire revision of the Implementation-brief package contracts.
pub const IMPLEMENTATION_BRIEF_SCHEMA_VERSION: u32 = 1;
/// Maximum proof claim of this pure package.
pub const IMPLEMENTATION_BRIEF_PROOF_CEILING: &str = "candidate-only";
