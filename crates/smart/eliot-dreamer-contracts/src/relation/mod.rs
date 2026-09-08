//! Candidate-only typed directed relation contracts.
//!
//! This module is the A03 structural owner for the relation family.  It
//! validates joins, identities, bounds and canonical encoding; it does not
//! select a relation, admit an endpoint, mutate a graph or execute policy.

#![forbid(unsafe_code)]

mod input;
mod registry;
mod result;

pub use input::{
    RelationAlternative, RelationDisclosureEvidence, RelationEndpoint, RelationEvidence,
    RelationEvidencePolarity, RelationInput, RelationNeighborhood, RelationPredicate,
    RelationSnapshot, RelationTemporalEvidence, RelationTimePoint, RelationVerifier,
    relation_input_digest, validate_relation,
};
pub use registry::{
    RELATION_FAMILIES, RelationDirection, RelationFamily, RelationFamilyRule,
    RelationRegistrySnapshot,
};
pub use result::{
    RelationCandidate, RelationCandidateClosure, RelationDisposition, RelationPreservation,
    RelationPreservationDimension, RelationPreservationVerdict, RelationRollback, seal_relation,
};
