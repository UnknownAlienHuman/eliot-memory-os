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
//!
//! Issue #1862 adds the campaign learning-state join this cell owns:
//! [`check_campaign_view_for_assembly`] refuses an immutable
//! `CampaignLearningStateView` whose State Fence, task/scope identity or
//! load-bearing Context recipe owner revision does not join the admitted set
//! about to be rendered. It re-derives that join from the admitted set's own
//! binding and inherits no other cell's verdict. The #40-frozen
//! `eliot_context::ContextCompiler` decides nothing on this route.

#![forbid(unsafe_code)]

mod assemble;
mod boundary;
mod bounds;
mod campaign_view;
mod cite;
#[cfg(not(target_arch = "wasm32"))]
mod learning_gate;
mod measurement;
mod readback;
mod render;

pub use assemble::{ASSEMBLY_ORDERING_REVISION, assemble_active_view};
pub use boundary::{
    BOUNDARY_ASSEMBLY_TRANSFORMER_ID, BOUNDARY_ASSEMBLY_TRANSFORMER_REVISION,
    assembly_boundary_limits, boundary_binding_digest, project_assembly_boundaries,
    read_back_boundaries, verify_boundary_binding,
};
pub use campaign_view::check_campaign_view_for_assembly;
pub use cite::project_citation;
#[cfg(not(target_arch = "wasm32"))]
pub use learning_gate::assemble_active_view_with_learning;
pub use measurement::assemble_active_view_with_measurement;
pub use readback::{ReopenedSource, gate_citation};

pub use eliot_context_contracts::{
    ActiveUnderstandingView, ActiveUnderstandingViewResult, AdmittedContextSet, AssemblyError,
    AssemblyPolicy, BoundaryMetadataSet, ContextError, ContextOutcome, IndexPreview,
    PreviewAuthority, ProjectedCitation, QualityScorecard, ReadbackRefusal, ReadbackRefusalKind,
    ReadbackRequest, RenderedAtom, SelectionIntegrityProof, SerializedContextMeasurement,
};
