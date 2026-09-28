//! Owner-neutral bounded canonical memory projection contracts (CC-008).
//!
//! This cell owns the versioned read shapes shared by the Governor
//! projection provider, the Smart applicability evaluator, and the context
//! candidate memory slot: [`MemoryProjectionRecord`], the fenced
//! [`MemoryProjectionBatch`], and the [`ApplicableMemorySet`] verdict.
//! It also owns the caller selection schema closed under
//! CC-MEMORY-PROJECTION-SCHEMA: [`MemoryQueryIntent`],
//! [`MemorySelectionPolicy`], and the [`MemorySelectionTrace`] emitted by
//! [`select`], which narrows without verdicting.
//!
//! The cell owns no store, index, retrieval, ranking, or promotion
//! authority. It only describes the bounded evidence a projector promises
//! and the typed result of task-local applicability over that promise.

mod batch;
mod error;
mod record;
mod selection;
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
pub use selection::{
    MemoryQueryIntent, MemorySelectionPolicy, MemorySelectionTrace, SelectionCoverage,
    SelectionDisposition, SelectionEntry, SelectionError, select,
};
pub use set::{ApplicableMemory, ApplicableMemorySet, ExcludedMemory, ExclusionReason};

/// Stable wire name for this contract family.
pub const CONTRACT_NAME: &str = "eliot.foundation.memory-projection-contracts";
/// Current wire revision for this contract family.
///
/// # Compatibility decision
///
/// 0.1.0 -> 0.2.0 is a **minor** bump, and the component names in
/// [`ContractVersion`](eliot_contracts::ContractVersion) say why: minor is the
/// additive component. The single change is one new
/// [`ExclusionReason::InfluenceIneligible`] variant. No field is removed,
/// retyped, or given a new meaning, so every value written under 0.1.0 still
/// decodes unchanged under 0.2.0; the new reason is a strict superset.
///
/// The bump is still required rather than cosmetic, because
/// `ExclusionReason` is `#[serde(tag = "rule", deny_unknown_fields)]` and its
/// consumers match it exhaustively. A 0.1.0 reader meeting 0.2.0 data fails
/// closed on deserialization instead of misreading the new rule, and an
/// in-tree consumer with an outdated exhaustive match fails to compile. Both
/// are the intended divergence signal; the minor bump is what makes the
/// divergence *declared* rather than silent, and it names the change class
/// (I0.4 cross-module, shared contract) for the compatibility suite.
///
/// A `major` bump would be wrong: nothing 0.1.0 consumers rely on was
/// withdrawn, and it would overstate a superset change as a contract
/// replacement. A `patch` bump would be wrong: a patch is a
/// backwards-compatible correction to the existing shape, and a new variant is
/// a new member of a closed set.
///
/// Two records of the prior revision are deliberately left for their owners
/// rather than edited here: the byte-pinned static freeze
/// `crates/smart/cognitive-rev12-contract-schema-freeze.toml`, whose
/// `contract_version = "0.1.0"` row and `ExclusionReason` field list are a
/// frozen snapshot whose own `[readback].rule` makes a byte change a new freeze
/// candidate, and the generated serde boundary registry
/// `crates/foundation/eliot-contracts/tests/data/shipped_serde_boundaries.toml`,
/// which records `set.rs` span and file digests. Both are recorded handoffs to
/// the freeze and registry owners (CC-W2-FREEZE-REPIN; #929).
pub const CONTRACT_VERSION: eliot_contracts::ContractVersion =
    eliot_contracts::ContractVersion::new(0, 2, 0);
