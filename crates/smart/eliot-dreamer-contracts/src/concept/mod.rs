//! Typed, candidate-only Concept and Abstraction contracts.
//!
//! Concept and Abstraction are semantic modes of the single `Concept` curation
//! kind. This module owns structural joins and deterministic encoding only.

#![forbid(unsafe_code)]

mod input;
mod proposal;
mod result;

pub use input::{
    ConceptInput, ConceptSourceDenominator, ConceptSourceSet, concept_input_digest,
    validate_concept, validate_concept_acceptance,
};
pub use proposal::{
    ConceptApplicability, ConceptCase, ConceptCaseKind, ConceptCoverage, ConceptCriterion,
    ConceptCriterionRole, ConceptDependency, ConceptDiscriminator, ConceptEvidence, ConceptMode,
    ConceptNeighborhood, ConceptParameter, ConceptProposal, ConceptSnapshot, ConceptSourceRef,
    ConceptVerifierRef, concept_proposal_digest,
};
pub use result::{ConceptCandidate, ConceptDisposition, ConceptRollback, seal_concept};
