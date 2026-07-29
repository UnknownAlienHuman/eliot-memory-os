use base64::Engine as _;
use base64::engine::general_purpose::STANDARD_NO_PAD;
use eliot_types::{
    AutonomyRunContract, AutonomyRunTransitionReceipt, CanonicalMetaMetricEvidence,
    CanonicalReplayExecutionRecord, CanonicalTraceCompletenessContract,
    ExperimentalMetaPolicyCandidate, HarnessExperimentRecord, MemoryRevision,
    MemoryStateTransition, MemoryTrajectoryCorrectness, MetaIsolationRejectionRecord,
    MetaPolicyExecutionReceipt, MinorityPressureRecord, ProjectId, ProjectSequence, ReplayAudit,
    ReplayRun, SealedReplayCaseRecord, SealedReplayInputSnapshotRecord, SealedReplaySetRecord,
    SleepCandidateArtifact, SleepConsolidationBundle, SleepConsolidationRun, TaskId,
    WriteReceiptRef,
};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::Value;

pub const MAX_CANONICAL_RECORDS: u16 = 128;
pub const MAX_CURRENT_UL_ARTIFACTS: usize = 4_096;
pub const UL_ARTIFACT_PAGE_SIZE: u16 = 256;

#[derive(Clone, Debug, Serialize)]
pub struct CanonicalRecord<T> {
    pub record_id: String,
    pub receipt_kind: String,
    pub project_id: ProjectId,
    pub task_id: Option<TaskId>,
    pub subject_ref: String,
    pub receipt_body: T,
    pub canonical_receipt: WriteReceiptRef,
    pub memory_revision: Option<MemoryRevision>,
    pub project_sequence: Option<ProjectSequence>,
}

#[derive(Deserialize)]
struct CanonicalRecordWire {
    record_id: String,
    receipt_kind: String,
    project_id: ProjectId,
    task_id: Option<TaskId>,
    subject_ref: String,
    #[serde(default)]
    receipt_body: Value,
    #[serde(default)]
    receipt_body_json_b64: Option<String>,
    canonical_receipt: WriteReceiptRef,
    memory_revision: Option<MemoryRevision>,
    project_sequence: Option<ProjectSequence>,
}

impl<'de, T> Deserialize<'de> for CanonicalRecord<T>
where
    T: DeserializeOwned,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = CanonicalRecordWire::deserialize(deserializer)?;
        let receipt_body = if let Some(encoded) = wire.receipt_body_json_b64 {
            let bytes = STANDARD_NO_PAD
                .decode(encoded)
                .map_err(serde::de::Error::custom)?;
            serde_json::from_slice(&bytes).map_err(serde::de::Error::custom)?
        } else {
            serde_json::from_value(wire.receipt_body).map_err(serde::de::Error::custom)?
        };
        Ok(Self {
            record_id: wire.record_id,
            receipt_kind: wire.receipt_kind,
            project_id: wire.project_id,
            task_id: wire.task_id,
            subject_ref: wire.subject_ref,
            receipt_body,
            canonical_receipt: wire.canonical_receipt,
            memory_revision: wire.memory_revision,
            project_sequence: wire.project_sequence,
        })
    }
}

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

#[cfg(test)]
mod tests {
    use super::CanonicalRecord;
    use base64::Engine as _;
    use base64::engine::general_purpose::STANDARD_NO_PAD;
    use eliot_types::{ProjectId, ReceiptId, WriteId};
    use serde_json::{Value, json};

    fn wire_record(receipt_body: &Value) -> Value {
        json!({
            "record_id": WriteId::new_v7().to_string(),
            "receipt_kind": "autonomy_budget_ledger",
            "project_id": ProjectId::new_v7(),
            "task_id": null,
            "subject_ref": "autonomy:operator-runtime-proof",
            "receipt_body": receipt_body,
            "canonical_receipt": {
                "receipt_id": ReceiptId::new_v7(),
                "write_id": WriteId::new_v7(),
            },
            "memory_revision": 1,
            "project_sequence": 1,
        })
    }

    #[test]
    fn canonical_record_prefers_lossless_json_bytes() -> Result<(), Box<dyn std::error::Error>> {
        let expected = json!({"target_ref": "memory:operator-runtime-proof"});
        let mut wire = wire_record(&json!({"target_ref": "memory:operator"}));
        wire["receipt_body_json_b64"] =
            Value::String(STANDARD_NO_PAD.encode(serde_json::to_vec(&expected)?));

        let record: CanonicalRecord<Value> = serde_json::from_value(wire)?;
        assert_eq!(record.receipt_body, expected);
        Ok(())
    }

    #[test]
    fn canonical_record_reads_legacy_receipt_body_without_lossless_field()
    -> Result<(), Box<dyn std::error::Error>> {
        let legacy = json!({"state": "active"});
        let record: CanonicalRecord<Value> = serde_json::from_value(wire_record(&legacy))?;

        assert_eq!(record.receipt_body, legacy);
        Ok(())
    }
}
