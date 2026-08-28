use eliot_types::{
    CanonicalMetaMetricEvidence, CanonicalReplayExecutionRecord,
    CanonicalTraceCompletenessContract, ExperimentalMetaPolicyCandidate, HarnessExperimentRecord,
    MetaIsolationRejectionRecord, MetaPolicyExecutionReceipt, ReplayAudit, ReplayRun,
    SealedReplayCaseRecord, SealedReplayInputSnapshotRecord, SealedReplaySetRecord,
};
use serde::{Deserialize, Serialize};

pub use crate::canonical_projection_views::{
    CanonicalAutonomyRunView, CanonicalLifecycleView, CanonicalSleepView, CanonicalTruncation,
    SleepCandidatesResponse,
};
pub use crate::canonical_record::CanonicalRecord;

pub const MAX_CANONICAL_RECORDS: u16 = 128;
pub const MAX_CURRENT_UL_ARTIFACTS: usize = 4_096;
pub const UL_ARTIFACT_PAGE_SIZE: u16 = 256;

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
