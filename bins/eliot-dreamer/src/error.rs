#![forbid(unsafe_code)]

//! Typed Dreamer refusal errors (issue #702, Slice 1).
//!
//! Single owner of [`DreamerError`]: `lib.rs` re-exports the type, so the
//! public path `eliot_dreamer::DreamerError` is unchanged and no duplicate
//! error type exists. Slice 1 adds two typed refusals — an unadmitted
//! curation kind and a non-closed handler registry — so unknown or unowned
//! work fails closed before any leaf runs. Both map to the existing
//! request-rejected code, never to the Kernel-admission code.

use eliot_dreamer_contracts::{CurationKind, JobClass};
use thiserror::Error;

use crate::KERNEL_ADMISSION_REQUIRED;

#[derive(Debug, Error, PartialEq)]
pub enum DreamerError {
    #[error("invalid field: {0}")]
    InvalidField(&'static str),
    #[error("input limit exceeded: {0}")]
    LimitExceeded(&'static str),
    #[error("invalid admission: {0}")]
    InvalidAdmission(&'static str),
    #[error("job already exists: {0}")]
    DuplicateJob(String),
    #[error("unknown job: {0}")]
    UnknownJob(String),
    #[error("job is not cancellable: {0}")]
    NotCancellable(String),
    #[error("{KERNEL_ADMISSION_REQUIRED}: {0}")]
    KernelAdmissionRequired(String),
    #[error("unsupported Dreamer job class: {0:?}")]
    UnsupportedJobClass(JobClass),
    /// Slice-1 typed kind refusal: the kind has no covering descriptor in the
    /// validated registry, so it cannot be dispatched to any leaf.
    #[error("unsupported Dreamer curation kind: {0:?}")]
    UnsupportedCurationKind(CurationKind),
    /// Slice-1 typed registry refusal: the static handler registry failed its
    /// closed validation (construction, exact closure, kind coverage, or
    /// digest), so no admission may proceed to semantic work.
    #[error("curation handler registry is not closed: {0}")]
    RegistryNotClosed(String),
}

impl DreamerError {
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::KernelAdmissionRequired(_) => KERNEL_ADMISSION_REQUIRED,
            Self::InvalidField(_)
            | Self::LimitExceeded(_)
            | Self::InvalidAdmission(_)
            | Self::DuplicateJob(_)
            | Self::UnknownJob(_)
            | Self::NotCancellable(_)
            | Self::UnsupportedJobClass(_)
            | Self::UnsupportedCurationKind(_)
            | Self::RegistryNotClosed(_) => "DREAMER_REQUEST_REJECTED",
        }
    }
}
