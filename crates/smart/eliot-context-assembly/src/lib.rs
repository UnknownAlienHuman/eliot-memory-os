//! Deterministic projection of one admitted A-15 context set.
//!
//! This crate owns assembly only. It never retrieves, ranks, re-admits, edits,
//! or persists context. The returned [`ActiveUnderstandingView`] remains a
//! candidate projection whose measurement is supplied by the caller.

#![forbid(unsafe_code)]

mod assemble;
mod bounds;
mod cite;
mod error;
#[cfg(not(target_arch = "wasm32"))]
mod learning_gate;
mod measurement;
mod readback;
mod render;

pub use assemble::{
    ASSEMBLY_ORDERING_REVISION, ActiveUnderstandingViewResult, AssemblyPolicy, assemble_active_view,
};
pub use cite::project_citation;
pub use error::AssemblyError;
#[cfg(not(target_arch = "wasm32"))]
pub use learning_gate::assemble_active_view_with_learning;
pub use readback::{ReopenedSource, gate_citation};

pub use eliot_context_contracts::{
    ActiveUnderstandingView, AdmittedContextSet, ContextError, ContextOutcome, IndexPreview,
    PreviewAuthority, ProjectedCitation, QualityScorecard, ReadbackRefusal, ReadbackRefusalKind,
    ReadbackRequest, RenderedAtom, SelectionIntegrityProof, SerializedContextMeasurement,
};
