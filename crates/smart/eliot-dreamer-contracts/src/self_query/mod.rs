//! Provider-neutral contracts for the `ArchitectureSelfQuery` output profiles.
//!
//! This namespace is the immutable handoff between A-03 and the two self-query
//! projection owners. It records source and anchor lineage, applicability and
//! dependency coverage, and the candidate-only result shape. It performs shape
//! and binding checks only; source acceptance, acquisition, parsing, model work,
//! conformance execution and canonical promotion remain with their owners.

#![forbid(unsafe_code)]

mod input;
mod result;
mod source;

pub use input::{
    AttemptBinding, SelfQueryInput, SelfQueryOutputProfile, SelfQueryPolicy, SelfQueryProfile,
};
pub use result::{
    ArchitectureBriefCandidate, ArchitectureBriefDisposition, ArchitectureBriefGap,
    ArchitectureBriefGapClass, ArchitectureBriefGapState, ArchitectureBriefOmission,
    ArchitectureBriefSection, ArchitectureBriefSectionKind, ArchitectureBriefStatement,
    SelfQueryContractError,
};
pub use source::{
    ArchitectureAnchor, ArchitectureAnchorClass, ArchitectureApplicability,
    ArchitectureApplicabilityBasis, ArchitectureApplicabilityState,
    ArchitectureDependencyDenominator, ArchitectureDependencyKind, ArchitectureDependencyMember,
    ArchitectureSourceSnapshot, ArchitectureSourceStatus, ArchitectureStatementModality,
    NormativePairBinding,
};
