//! Deterministic projection of one admitted A-15 context set.
//!
//! This crate owns assembly only. It never retrieves, ranks, re-admits, edits,
//! or persists context. The returned [`ActiveUnderstandingView`] remains a
//! candidate projection whose measurement is supplied by the caller, either
//! as an injected callback to [`assemble_active_view`] or, through
//! [`assemble_active_view_with_measurement`], as caller-owned parameters that
//! the sole #704 measurement owner measures the canonical bytes with.
//!
//! A `PrivacyClass` reaches this crate only on an ALREADY-ADMITTED atom: the non-`Public`
//! refusal is the admission path's
//! (`ContextCandidate::validate_public_privacy`, called from `AdmissionInput::validate`
//! in `eliot-context-contracts`), not a rule this crate re-implements. The wider A00.3
//! disclosure boundary is owned by `crates/governor/eliot-workscope`
//! (`PrivacyProfile::admits`, `WorkScopeError::PrivacyDenied`), and non-public delivery is
//! withheld as `DeliveryDisposition::WithheldPrivacy` by `eliot-reactive-context-plan`.

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
pub use measurement::assemble_active_view_with_measurement;
pub use readback::{ReopenedSource, gate_citation};

pub use eliot_context_contracts::{
    ActiveUnderstandingView, AdmittedContextSet, ContextError, ContextOutcome, IndexPreview,
    PreviewAuthority, ProjectedCitation, QualityScorecard, ReadbackRefusal, ReadbackRefusalKind,
    ReadbackRequest, RenderedAtom, SelectionIntegrityProof, SerializedContextMeasurement,
};
