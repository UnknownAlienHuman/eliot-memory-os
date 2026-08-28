//! Canonical-projection views report cell — passive report/view handles only.
//! Architecture A13.2 (Kernel and failure domains): minimal live Kernel preserves canonical history, fencing, health and recovery entrypoint and does not depend on model/Dreamer/graph/provider/UI; this cell owns no canonical state, authority, or write path.
//! Implementation I16.1 (Four surfaces): operational logs, metrics, durable audit, and reports — reports are Human/agent projections generated from canonical state ("prose not truth"); this cell is the I16.1 report/projection truth-boundary handle for lifecycle, sleep, autonomy-run and truncation views. Reports/projections are not truth/authority; they are derived, rebuildable, and must not confer canonical write authority.
//! Source anchors: `crates/eliot-store/src/canonical_projection.rs:20-24` (`CanonicalLifecycleView`), `:42-47` (`CanonicalSleepView`), `:49-57` (`CanonicalAutonomyRunView`), `:59-66` (`SleepCandidatesResponse`), `:68-73` (`CanonicalTruncation`) and `crates/eliot-store/src/canonical_record.rs:13-24` (`CanonicalRecord<T>` handle, retained in `canonical_record.rs`).
//! Responsibility: `CanonicalLifecycleView`, `CanonicalSleepView`, `CanonicalAutonomyRunView`, `SleepCandidatesResponse`, `CanonicalTruncation` only — exact `Clone`, `Debug`, `Default` (where present), `Serialize`, `Deserialize` derives and field order, `serde` shape, and visibility preserved verbatim. This is a read-only derived projection with no canonical authority.
//! Explicit non-ownership: no `CanonicalRecord` definition/authority (retained in `canonical_record.rs`), no `CanonicalReplayView` (retained in `canonical_projection.rs`), no `CanonicalStore`/`CognitiveProjection*`/observation/secret/activation semantics, no `capacity`/`recall_ranking`/`replay_view` L2/recall/replay, no provider/handshake/migration/atomic-write, no Dreamer/Luna/frozen/integrated scope, no write-ownership or lifecycle authority. Mechanical split only — no semantic redesign; public API, `serde` shape, and report-only/no-authority semantics unchanged.

#![forbid(unsafe_code)]

use eliot_types::{
    AutonomyRunContract, AutonomyRunTransitionReceipt, MemoryStateTransition,
    MemoryTrajectoryCorrectness, MinorityPressureRecord, ProjectId, SleepCandidateArtifact,
    SleepConsolidationBundle, SleepConsolidationRun, TaskId,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::canonical_record::CanonicalRecord;

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct CanonicalLifecycleView {
    pub transitions: Vec<CanonicalRecord<MemoryStateTransition>>,
    pub trajectories: Vec<CanonicalRecord<MemoryTrajectoryCorrectness>>,
    pub minority_pressure: Vec<CanonicalRecord<MinorityPressureRecord>>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct CanonicalSleepView {
    pub bundles: Vec<CanonicalRecord<SleepConsolidationBundle>>,
    pub runs: Vec<CanonicalRecord<SleepConsolidationRun>>,
    pub artifacts: Vec<CanonicalRecord<SleepCandidateArtifact>>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct CanonicalAutonomyRunView {
    pub contract: Option<CanonicalRecord<AutonomyRunContract>>,
    pub transitions: Vec<CanonicalRecord<AutonomyRunTransitionReceipt>>,
    pub budget_ledgers: Vec<CanonicalRecord<Value>>,
    pub work_graphs: Vec<CanonicalRecord<Value>>,
    pub tripwires: Vec<CanonicalRecord<Value>>,
    pub recoveries: Vec<CanonicalRecord<Value>>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SleepCandidatesResponse {
    pub op: String,
    pub project_id: ProjectId,
    pub task_id: Option<TaskId>,
    pub candidates: Vec<CanonicalRecord<Value>>,
    pub truncation: CanonicalTruncation,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CanonicalTruncation {
    pub truncated: bool,
    pub limit: u16,
    pub returned: u16,
}
