//! Canonical observation models — passive data-model structs.
//!
//! Owns the passive public data-model structs `CanonicalToolObservation` and
//! `CanonicalClaimCard` extracted verbatim from
//! `crates/eliot-store/src/canonical_store.rs`: `CanonicalToolObservation` and
//! `CanonicalClaimCard` with exact fields, derives, `serde` shape, and `pub`
//! visibility. No canonical write, authority, or transport semantics live here.
//!
//! Architecture: P.6 canonical Store — observation/claim-card projection
//! boundary; A13.2 Kernel failure domains — canonical state isolation; parent
//! `canonical_store` retains the store, receipt, and transport boundary.
//! Implementation: I16.1 Four surfaces — Reports/durable-audit projections
//! generated from canonical state; I2.2, I2.23 — extracted observation-model
//! module owns only its passive data-model cell; parent remains the sole
//! write/receipt authority. Mechanical split from
//! `crates/eliot-store/src/canonical_store.rs` — behavior preserved.
//! Forbidden: passive data-model only, no cognitive/record/secret/capacity/
//! recall/L2/replay, no provider/handshake/migration/atomic-write, no
//! Dreamer/Luna/frozen/integrated scopes, no canonical write ownership or
//! broad re-exports — no new dependencies.

use eliot_types::{
    ClaimId, EpistemicStatus, LifecycleStatus, MemoryRevision, ProjectId, ProjectSequence,
    TaintClass, TaskId, Visibility, WriteId,
};
use serde_json::Value;

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
pub struct CanonicalToolObservation {
    pub observation_id: String,
    pub project_id: ProjectId,
    pub task_id: Option<TaskId>,
    pub scope: String,
    pub authority: String,
    pub tool_name: String,
    pub observation: String,
    pub payload: Value,
    pub memory_revision: MemoryRevision,
    pub project_sequence: ProjectSequence,
    pub write_id: WriteId,
}

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
pub struct CanonicalClaimCard {
    pub claim_id: ClaimId,
    pub project_id: ProjectId,
    pub task_id: Option<TaskId>,
    pub scope: String,
    pub status: EpistemicStatus,
    pub lifecycle_status: LifecycleStatus,
    pub visibility: Visibility,
    pub taint: TaintClass,
    pub authority: String,
    pub statement: String,
    pub payload: Value,
    pub memory_revision: MemoryRevision,
    pub project_sequence: ProjectSequence,
    pub write_id: WriteId,
}
