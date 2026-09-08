//! Candidate-only post-admission classification contracts.
//!
//! This module composes exact caller-supplied admission, validation and screen
//! handles with an explicit taxonomy denominator. It does not authenticate
//! admission, select a taxonomy winner, mutate a canonical record, or execute
//! a classifier. The A-21 policy owns selection over this neutral closure.

#![forbid(unsafe_code)]

mod input;
mod result;
mod taxonomy;

pub use input::{
    AdmittedTargetRef, ClassificationInput, ExternalGradeRef, FeatureObservation, NamedEvidence,
    PriorAssignmentRef, classification_input_digest, preflight_classification_acceptance,
    seal_classification, validate_classification, validate_classification_acceptance,
};
pub use result::{
    ClassificationAssignmentSnapshot, ClassificationCandidate, ClassificationCandidateClosure,
    ClassificationRollback,
};
pub use taxonomy::{
    ClassificationCriterionRole, ClassificationPreservation, ClassificationPreservationDimension,
    ClassificationPreservationVerdict, ClassificationRecordFamily, CriterionApplicability,
    CriterionStatus, GroundedCriterion, TaxonomyAliasMapping, TaxonomyAlternative,
    TaxonomyCoverage, TaxonomyDenominator,
};
