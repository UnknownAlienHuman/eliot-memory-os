//! Pure evidence-bound `ImplementationBrief` self-query projection.
//!
//! The package joins the existing A-03 [`eliot_dreamer_contracts::SelfQueryInput`]
//! closure with one externally accepted Implementation projection and the
//! owner-neutral I0.5 conformance axes. It preserves Architecture precedence,
//! accounts every expected mechanism/obligation/evidence identity, and emits
//! candidate-only output. It owns no source discovery, probe execution, Store,
//! policy mutation, authority, external effect, or Finish path.

#![forbid(unsafe_code)]

mod error;
mod model;
mod projection;
mod validation;

pub use error::ImplementationBriefError;
pub use model::{
    ArchitectureAlignment, CurrentEvidenceTarget, EvidenceAxisSnapshot, EvidenceVerdict,
    ImplementationBriefDisposition, ImplementationBriefInput, ImplementationBriefProjection,
    ImplementationDenominator, ImplementationEvidence, ImplementationGap,
    ImplementationGapClass, ImplementationMechanism, ImplementationObligation,
    ImplementationOmission, ImplementationSourceSnapshot, ImplementationSourceStatus,
    ImplementationStatement, ImplementationStatementKind, MechanismAssessment,
    MechanismDisposition, ObligationAssessment, ProofStage, StageAssessment,
    StageDisposition, IMPLEMENTATION_BRIEF_PROOF_CEILING, IMPLEMENTATION_BRIEF_SCHEMA_VERSION,
};
pub use projection::project_implementation_brief;
