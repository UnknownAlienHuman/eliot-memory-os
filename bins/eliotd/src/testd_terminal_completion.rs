//! Authenticated TestD terminal handoff into the canonical Governor owner.
//!
//! The TestD transport carries only a durable job id and finish-receipt
//! digest. This module rehydrates request identity, operation, task revision,
//! and the exact pre-dispatch canonical verifier plan from the TestD owner,
//! then re-reads the current Governor plan before publishing.

use std::time::{SystemTime, UNIX_EPOCH};

use eliot_contracts::{OperationId, TaskId, canonical_json_bytes};
use eliot_governor::CanonicalPlanBinding;
use eliot_instrument_api::InstrumentInvocation;
use eliot_protocol::RequestIdentity;
use eliot_store_api::{WriteReceipt, WriteReceiptStatus};
use eliot_testd_core::{
    TestdStore, TestdTerminalCompletionNotice, TestdVerifierDispatchBinding, TestJob,
    verification_receipt_sha256,
};

use crate::{DaemonComposition, DaemonError};

fn completion_error(error: impl std::fmt::Display) -> DaemonError {
    DaemonError::Lifecycle(format!("TestD terminal completion: {error}"))
}

fn unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(1, |duration| {
            u64::try_from(duration.as_millis().min(u128::from(u64::MAX))).unwrap_or(u64::MAX)
        })
}

impl DaemonComposition {
    /// Captures the current canonical verifier plan with its admitted owner
    /// identity. Call this before inserting/dispatching the productive TestD
    /// job; the returned binding is persisted in the durable TestD row.
    pub fn testd_verifier_dispatch_binding(
        &self,
        identity: &RequestIdentity,
        operation_id: &OperationId,
        task_id: &TaskId,
        task_revision: u64,
        invocation: &InstrumentInvocation,
    ) -> Result<TestdVerifierDispatchBinding, DaemonError> {
        identity.validate().map_err(completion_error)?;
        if identity.request.metadata.task_id.as_ref() != Some(task_id)
            || identity
                .request
                .state_fence
                .task_revision
                .as_ref()
                .map(|revision| revision.value())
                != Some(task_revision)
            || task_revision == 0
        {
            return Err(completion_error(
                "admitted identity does not bind the requested task revision",
            ));
        }
        if invocation.request != identity.request.metadata
            || invocation.request.task_id.as_ref() != Some(task_id)
            || invocation.request.state_fence != identity.request.state_fence
        {
            return Err(completion_error(
                "TestD invocation does not match the admitted request identity",
            ));
        }
        invocation.validate().map_err(completion_error)?;
        let current_task = self
            .governor
            .owners()
            .task
            .task(task_id)
            .ok_or_else(|| completion_error("canonical task owner is absent"))?;
        if current_task.revision != task_revision
            || current_task.state_fence != identity.request.state_fence
        {
            return Err(completion_error(
                "TestD invocation does not bind the current canonical task revision",
            ));
        }
        let plan = self
            .governor
            .read_current_plan(&identity.request.state_fence)
            .map_err(completion_error)?;
        plan.validate().map_err(completion_error)?;
        let verifier = plan.verifier.as_ref().ok_or_else(|| {
            completion_error("current canonical plan is missing the task-bound verifier request")
        })?;
        if plan.task_id != *task_id
            || verifier.instrument != invocation.instrument
            || verifier.kind != invocation.kind
            || verifier.profile != invocation.profile
            || verifier.target != invocation.target
            || verifier.arguments != invocation.arguments
            || verifier.declared_scope != invocation.declared_scope
            || verifier.input_artifacts != invocation.input_artifacts
        {
            return Err(completion_error(
                "TestD invocation differs from the current canonical verifier plan",
            ));
        }
        let bytes = canonical_json_bytes(&plan).map_err(completion_error)?;
        let canonical_plan_json = String::from_utf8(bytes.clone()).map_err(completion_error)?;
        Ok(TestdVerifierDispatchBinding {
            request_identity: identity.clone(),
            operation_id: operation_id.to_string(),
            canonical_plan_json,
            canonical_plan_sha256: eliot_contracts::sha256_hex(&bytes),
        })
    }

    /// Persists the admitted identity and current canonical verifier plan in
    /// the durable TestD row before Kernel launch. The invocation and process
    /// operation are rehydrated from the submitted TestD owner row; productive
    /// claims remain ineligible until this write commits.
    pub fn persist_testd_verifier_dispatch_before_launch(
        &self,
        testd: &TestdStore,
        job_id: &str,
        identity: &RequestIdentity,
    ) -> Result<TestJob, DaemonError> {
        let job = testd
            .get(job_id)
            .map_err(completion_error)?
            .ok_or_else(|| completion_error("queued TestD owner row is absent"))?;
        if job.job_id != job_id {
            return Err(completion_error(
                "TestD owner key differs from the requested dispatch job",
            ));
        }
        let task_id = identity
            .request
            .metadata
            .task_id
            .as_ref()
            .ok_or_else(|| completion_error("admitted request has no task id"))?;
        let task_revision = identity
            .request
            .state_fence
            .task_revision
            .as_ref()
            .map(|revision| revision.value())
            .ok_or_else(|| completion_error("admitted request has no task revision"))?;
        let operation_id = OperationId::new(job.process.operation_id.clone())
            .map_err(completion_error)?;
        let binding = self.testd_verifier_dispatch_binding(
            identity,
            &operation_id,
            task_id,
            task_revision,
            &job.invocation,
        )?;
        testd
            .bind_verifier_dispatch(job_id, binding, unix_ms())
            .map_err(completion_error)
    }

    /// Consumes one pending authenticated TestD notification. The returned
    /// receipt is the canonical WriteReceipt from Governor; the durable TestD
    /// row is updated only after that commit has been observed.
    pub async fn publish_testd_terminal_completion(
        &mut self,
        notice: &TestdTerminalCompletionNotice,
        testd: &TestdStore,
    ) -> Result<WriteReceipt, DaemonError> {
        let job = testd
            .get(&notice.job_id)
            .map_err(completion_error)?
            .ok_or_else(|| completion_error("durable TestD job is absent"))?;
        let publication = job
            .terminal_publication
            .as_ref()
            .ok_or_else(|| completion_error("authenticated terminal notification is absent"))?;
        if publication.receipt_sha256 != notice.receipt_sha256 {
            return Err(completion_error(
                "terminal notification digest differs from its durable owner row",
            ));
        }
        let receipt = job
            .verification_receipt
            .as_ref()
            .ok_or_else(|| completion_error("durable finish receipt is absent"))?;
        if verification_receipt_sha256(receipt).map_err(completion_error)?
            != notice.receipt_sha256
        {
            return Err(completion_error(
                "terminal notification does not bind the exact durable finish receipt",
            ));
        }
        if job.lease.is_some() {
            return Err(completion_error("TestD job still has an active worker lease"));
        }
        let binding = job
            .verifier_dispatch
            .as_ref()
            .ok_or_else(|| completion_error("pre-dispatch Governor binding is absent"))?;
        binding
            .validate_for_job(&job)
            .map_err(completion_error)?;
        let bound_plan: CanonicalPlanBinding = serde_json::from_str(&binding.canonical_plan_json)
            .map_err(completion_error)?;
        bound_plan.validate().map_err(completion_error)?;
        let current_plan = self
            .governor
            .read_current_plan(&binding.request_identity.request.state_fence)
            .map_err(completion_error)?;
        if current_plan != bound_plan {
            return Err(completion_error(
                "canonical verifier plan changed after TestD dispatch",
            ));
        }
        let task_id = binding
            .request_identity
            .request
            .metadata
            .task_id
            .clone()
            .ok_or_else(|| completion_error("admitted request has no task id"))?;
        let task_revision = binding
            .request_identity
            .request
            .state_fence
            .task_revision
            .as_ref()
            .map(|revision| revision.value())
            .ok_or_else(|| completion_error("admitted request has no task revision"))?;
        let operation_id =
            OperationId::new(binding.operation_id.clone()).map_err(completion_error)?;
        if let Some(receipt_json) = &publication.committed_receipt_json {
            let committed: WriteReceipt =
                serde_json::from_str(receipt_json).map_err(completion_error)?;
            validate_committed_receipt(&committed, binding, &operation_id)
                .map_err(completion_error)?;
            return Ok(committed);
        }
        let committed = self
            .governor
            .publish_testd_verifier_execution_fact(
                &binding.request_identity,
                &operation_id,
                &task_id,
                task_revision,
                &job.job_id,
                testd,
            )
            .await
            .map_err(completion_error)?
            .ok_or_else(|| {
                completion_error(
                    "Governor reported an existing verifier fact without its committed WriteReceipt",
                )
            })?;
        validate_committed_receipt(&committed, binding, &operation_id)
            .map_err(completion_error)?;
        let bytes = canonical_json_bytes(&committed).map_err(completion_error)?;
        let receipt_json = String::from_utf8(bytes).map_err(completion_error)?;
        testd
            .record_terminal_publication_receipt(
                &job.job_id,
                &notice.receipt_sha256,
                receipt_json,
                unix_ms(),
            )
            .map_err(completion_error)?;
        Ok(committed)
    }

    /// Drains one bounded batch from the durable TestD terminal owner. The
    /// daemon reactive-feed owner calls this API; each item is rehydrated and
    /// committed independently before its canonical receipt is recorded.
    pub async fn publish_pending_testd_terminal_completions(
        &mut self,
        testd: &TestdStore,
        limit: usize,
    ) -> Result<Vec<WriteReceipt>, DaemonError> {
        let pending = testd
            .pending_terminal_publications(limit)
            .map_err(completion_error)?;
        let mut committed = Vec::with_capacity(pending.len());
        for notice in pending {
            committed.push(
                self.publish_testd_terminal_completion(&notice, testd)
                    .await?,
            );
        }
        Ok(committed)
    }
}

fn validate_committed_receipt(
    receipt: &WriteReceipt,
    binding: &TestdVerifierDispatchBinding,
    operation_id: &OperationId,
) -> Result<(), String> {
    receipt.validate().map_err(|error| error.to_string())?;
    let expected_operation = format!("{}/verifier-execution", operation_id.as_str());
    let expected_idempotency = format!(
        "{}:verifier-execution",
        binding.request_identity.idempotency_key
    );
    if receipt.status != WriteReceiptStatus::Committed
        || receipt.operation_id.as_str() != expected_operation
        || receipt.idempotency_key != expected_idempotency
        || receipt.state_fence != binding.request_identity.request.state_fence
    {
        return Err("Governor response is not the exact committed verifier WriteReceipt".to_owned());
    }
    Ok(())
}
