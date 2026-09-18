//! Owner-neutral bounded canonical memory projection contracts (CC-008).
//!
//! This crate owns the versioned read shapes shared by the Governor
//! projection provider, the Smart applicability evaluator, and the context
//! candidate memory slot: [`MemoryProjectionRecord`], the fenced
//! [`MemoryProjectionBatch`], and the [`ApplicableMemorySet`] verdict.
//!
//! The crate owns no store, index, retrieval, ranking, or promotion
//! authority. It only describes the bounded evidence a projector promises
//! and the typed result of task-local applicability over that promise.

#![forbid(unsafe_code)]

mod batch;
mod error;
mod record;
mod set;

pub use batch::{
    CoverageOmission, DenominatorState, MAX_BATCH_FRONTIER, MAX_BATCH_OMISSIONS,
    MEMORY_PROJECTION_MAX_RECORDS, MemoryProjectionBatch, ProjectionCoverage,
};
pub use error::MemoryProjectionError;
pub use record::{
    CueTrigger, FreshnessState, MAX_APPLICABILITY_LIMITS, MAX_CUE_TRIGGERS, MAX_PRECONDITIONS,
    MAX_RECORD_ROLES, MAX_SCOPE_CHARS, MemoryFreshness, MemoryKind, MemoryProjectionRecord,
    MemoryRole, MemoryScopeBinding, NegativeTrigger, Precondition,
};
pub use set::{ApplicableMemory, ApplicableMemorySet, ExcludedMemory, ExclusionReason};

/// Stable wire name for this contract family.
pub const CONTRACT_NAME: &str = "eliot.foundation.memory-projection-contracts";
/// Current wire revision for this contract family.
pub const CONTRACT_VERSION: eliot_contracts::ContractVersion =
    eliot_contracts::ContractVersion::new(0, 1, 0);
