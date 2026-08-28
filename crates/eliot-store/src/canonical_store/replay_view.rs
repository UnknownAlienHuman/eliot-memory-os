//! Canonical store read-only replay/integrity view.
//!
//! Owns the production read-only replay and integrity closure for the
//! canonical store: `canonical_records`, `canonical_records_by_kind`,
//! `replay_view`, `replay_integrity_records`, `meta_integrity_records` and
//! the strictly coupled `ReplayIntegrityRecords`/`MetaIntegrityRecords`
//! helpers. No semantic projection, write/envelope, migration,
//! `execute_value`/`decode` core, recall/L2, cognitive projection, or blob
//! retention authority lives here.
//!
//! Architecture: A4.3 Git-like history and recoverable fallibility, A12.3 One governed write path, A13.8 Integrity, ARCH-AUTH-01, ARCH-SEC-02, ARCH-RES-03 — read-only replay/integrity view topology; parent `canonical_store` retains the store, receipt, and transport boundary.
//! Implementation: I2.2, I2.23 — extracted replay/integrity module owns only
//! its read-only view; parent remains the sole write/receipt authority.
//! Forbidden: read-only replay integrity projection only, no migration execute write envelope cognitive recall blob canonical write authority — no new dependencies or broad re-exports.

use super::CanonicalStore;
use super::{decode_value, string_fragments};
use crate::canonical_meta_integrity_records::MetaIntegrityRecords;
use crate::{
    CanonicalRecord, CanonicalReplayView, MAX_CANONICAL_RECORDS, NamedSurqlOp, StoreError,
};
use eliot_types::{
    CanonicalReplayExecutionRecord, CanonicalTraceCompletenessContract, HarnessExperimentRecord,
    ProjectId, ReplayAudit, ReplayRun, SealedReplayCaseRecord, SealedReplayInputSnapshotRecord,
    SealedReplaySetRecord, TaskId,
};
use serde::de::DeserializeOwned;
use serde_json::json;

struct ReplayIntegrityRecords {
    trace_contracts: Vec<CanonicalRecord<CanonicalTraceCompletenessContract>>,
    sealed_sets: Vec<CanonicalRecord<SealedReplaySetRecord>>,
    sealed_cases: Vec<CanonicalRecord<SealedReplayCaseRecord>>,
    sealed_snapshots: Vec<CanonicalRecord<SealedReplayInputSnapshotRecord>>,
    sealed_executions: Vec<CanonicalRecord<CanonicalReplayExecutionRecord>>,
}

impl CanonicalStore {
    pub async fn canonical_records_by_kind<T>(
        &self,
        project_id: ProjectId,
        task_id: Option<TaskId>,
        receipt_kinds: &[&str],
        limit: u16,
    ) -> Result<Vec<CanonicalRecord<T>>, StoreError>
    where
        T: DeserializeOwned,
    {
        self.canonical_records(project_id, task_id, receipt_kinds, None, limit)
            .await
    }

    pub async fn replay_view(
        &self,
        project_id: ProjectId,
        task_id: Option<TaskId>,
        limit: u16,
    ) -> Result<CanonicalReplayView, StoreError> {
        let integrity = self
            .replay_integrity_records(project_id, task_id, limit)
            .await?;
        let meta = self
            .meta_integrity_records(project_id, task_id, limit)
            .await?;
        let replay_runs = self
            .canonical_records::<ReplayRun>(project_id, task_id, &["replay_run"], None, limit)
            .await?;
        let replay_audits = self
            .canonical_records::<ReplayAudit>(project_id, task_id, &["replay_audit"], None, limit)
            .await?;
        let mut harness_experiments = self
            .canonical_records::<HarnessExperimentRecord>(
                project_id,
                task_id,
                &["harness_experiment", "harness_disposition"],
                None,
                limit,
            )
            .await?;
        for record in &mut harness_experiments {
            if record.receipt_kind == "harness_disposition" {
                record.receipt_body.disposition_receipt = Some(record.canonical_receipt.clone());
            }
        }
        Ok(CanonicalReplayView {
            trace_contracts: integrity.trace_contracts,
            sealed_sets: integrity.sealed_sets,
            sealed_cases: integrity.sealed_cases,
            sealed_snapshots: integrity.sealed_snapshots,
            sealed_executions: integrity.sealed_executions,
            replay_runs,
            replay_audits,
            harness_experiments,
            meta_metrics: meta.metrics,
            isolation_rejections: meta.isolation_rejections,
            policy_candidates: meta.policy_candidates,
            policy_executions: meta.policy_executions,
        })
    }

    async fn replay_integrity_records(
        &self,
        project_id: ProjectId,
        task_id: Option<TaskId>,
        limit: u16,
    ) -> Result<ReplayIntegrityRecords, StoreError> {
        let trace_contracts = self
            .canonical_records(
                project_id,
                task_id,
                &["trace_completeness_contract"],
                None,
                limit,
            )
            .await?;
        let sealed_sets = self
            .canonical_records(project_id, task_id, &["replay_set"], None, limit)
            .await?;
        let sealed_cases = self
            .canonical_records(project_id, task_id, &["replay_case"], None, limit)
            .await?;
        let sealed_snapshots = self
            .canonical_records(project_id, task_id, &["replay_input_snapshot"], None, limit)
            .await?;
        let sealed_executions = self
            .canonical_records(project_id, task_id, &["sealed_replay_run"], None, limit)
            .await?;
        Ok(ReplayIntegrityRecords {
            trace_contracts,
            sealed_sets,
            sealed_cases,
            sealed_snapshots,
            sealed_executions,
        })
    }

    async fn meta_integrity_records(
        &self,
        project_id: ProjectId,
        task_id: Option<TaskId>,
        limit: u16,
    ) -> Result<MetaIntegrityRecords, StoreError> {
        let metrics = self
            .canonical_records(project_id, task_id, &["meta_metric_evidence"], None, limit)
            .await?;
        let isolation_rejections = self
            .canonical_records(
                project_id,
                task_id,
                &["meta_isolation_rejection"],
                None,
                limit,
            )
            .await?;
        let policy_candidates = self
            .canonical_records(
                project_id,
                task_id,
                &["experimental_policy_candidate"],
                None,
                limit,
            )
            .await?;
        let policy_executions = self
            .canonical_records(
                project_id,
                task_id,
                &["meta_policy_promotion", "meta_policy_rollback"],
                None,
                limit,
            )
            .await?;
        Ok(MetaIntegrityRecords {
            metrics,
            isolation_rejections,
            policy_candidates,
            policy_executions,
        })
    }

    pub(super) async fn canonical_records<T>(
        &self,
        project_id: ProjectId,
        task_id: Option<TaskId>,
        receipt_kinds: &[&str],
        subject_ref: Option<&str>,
        limit: u16,
    ) -> Result<Vec<CanonicalRecord<T>>, StoreError>
    where
        T: DeserializeOwned,
    {
        let has_subject_ref = subject_ref.is_some();
        let subject_ref_fragments = subject_ref.map_or_else(Vec::new, string_fragments);
        let value = self
            .execute_value(
                NamedSurqlOp::CanonicalRecords,
                json!({
                    "project_id": project_id,
                    "task_id": task_id,
                    "receipt_kinds": receipt_kinds,
                    "has_subject_ref": has_subject_ref,
                    "subject_ref_fragments": subject_ref_fragments,
                    "limit": limit.clamp(1, MAX_CANONICAL_RECORDS),
                }),
            )
            .await?;
        decode_value(NamedSurqlOp::CanonicalRecords, value)
    }
}
