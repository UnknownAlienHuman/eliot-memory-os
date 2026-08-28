use eliot_types::{
    AutonomyRunContract, AutonomyRunTransitionReceipt, CanonicalMetaMetricEvidence,
    CanonicalReplayExecutionRecord, CanonicalTraceCompletenessContract,
    ExperimentalMetaPolicyCandidate, HarnessExperimentRecord, MemoryStateTransition,
    MemoryTrajectoryCorrectness, MetaIsolationRejectionRecord, MetaPolicyExecutionReceipt,
    MinorityPressureRecord, ProjectId, ReplayAudit, ReplayRun, SealedReplayCaseRecord,
    SealedReplayInputSnapshotRecord, SealedReplaySetRecord, SleepCandidateArtifact,
    SleepConsolidationBundle, SleepConsolidationRun, TaskId,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;

pub use crate::canonical_record::CanonicalRecord;

pub const MAX_CANONICAL_RECORDS: u16 = 128;
pub const MAX_CURRENT_UL_ARTIFACTS: usize = 4_096;
pub const UL_ARTIFACT_PAGE_SIZE: u16 = 256;

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct CanonicalLifecycleView {
    pub transitions: Vec<CanonicalRecord<MemoryStateTransition>>,
    pub trajectories: Vec<CanonicalRecord<MemoryTrajectoryCorrectness>>,
    pub minority_pressure: Vec<CanonicalRecord<MinorityPressureRecord>>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct CanonicalReplayView {
    pub trace_contracts: Vec<CanonicalRecord<CanonicalTraceCompletenessContract>>,
    pub sealed_sets: Vec<CanonicalRecord<SealedReplaySetRecord>>,
    pub sealed_cases: Vec<CanonicalRecord<SealedReplayCaseRecord>>,
    pub sealed_snapshots: Vec<CanonicalRecord<SealedReplayInputSnapshotRecord>>,
    pub sealed_executions: Vec<CanonicalRecord<CanonicalReplayExecutionRecord>>,
    pub replay_runs: Vec<CanonicalRecord<ReplayRun>>,
    pub replay_audits: Vec<CanonicalRecord<ReplayAudit>>,
    pub harness_experiments: Vec<CanonicalRecord<HarnessExperimentRecord>>,
    pub meta_metrics: Vec<CanonicalRecord<CanonicalMetaMetricEvidence>>,
    pub isolation_rejections: Vec<CanonicalRecord<MetaIsolationRejectionRecord>>,
    pub policy_candidates: Vec<CanonicalRecord<ExperimentalMetaPolicyCandidate>>,
    pub policy_executions: Vec<CanonicalRecord<MetaPolicyExecutionReceipt>>,
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
