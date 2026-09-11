//! Pure A-05 pre-handler validation of structured Dreamer drafts.
//!
//! This cell checks the exact A-03 job, bundle, model, grounded draft and
//! preservation contracts once before a semantic handler is called. It has no
//! model, handler, registry, runtime, storage, provider, or canonical-write
//! dependency. Rejected inputs remain inert and preserve their supplied
//! residues for diagnosis.

#![forbid(unsafe_code)]

mod bounds;
mod error;
mod input;
mod receipt;
mod structured;
mod validate;

pub use eliot_dreamer_contracts::ValidationPolicy;
pub use error::{
    CandidateRejectionReport, CandidateValidationOutcome, DreamDraftValidationError, RejectionCode,
    ValidatedCandidate,
};
pub use input::validate_grounded_dream_draft_at;
pub use structured::{
    StructuredCandidateRejectionReport, StructuredCandidateValidationOutcome,
    validate_grounding_candidate_at,
};
