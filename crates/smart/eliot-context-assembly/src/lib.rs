//! Deterministic projection of one admitted A-15 context set.
//!
//! This crate owns assembly only. It never retrieves, ranks, re-admits, edits,
//! or persists context. The returned [`ActiveUnderstandingView`] remains a
//! candidate projection whose measurement is supplied by the caller.

#![forbid(unsafe_code)]

mod assemble;
mod bounds;
mod error;
mod measurement;
mod render;

pub use assemble::{
    ASSEMBLY_ORDERING_REVISION, ActiveUnderstandingViewResult, AssemblyPolicy, assemble_active_view,
};
pub use error::AssemblyError;

pub use eliot_context_contracts::{
    ActiveUnderstandingView, AdmittedContextSet, ContextError, ContextOutcome, QualityScorecard,
    RenderedAtom, SelectionIntegrityProof, SerializedContextMeasurement,
};
