//! Authenticated `TestD` terminal handoff into the canonical Governor owner.
//!
//! The `TestD` transport carries only a durable job id and finish-receipt
//! digest. This module rehydrates request identity, operation, task revision,
//! and the exact pre-dispatch canonical verifier plan from the `TestD` owner,
//! then re-reads the current Governor plan before publishing.

use std::collections::HashSet;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::daemon_kernel_client::TESTD_OWNER_POLL_LIMIT;
use crate::{DaemonComposition, DaemonError, DaemonKernelClient};
use eliot_agent_contracts::AgentAttemptId;
use eliot_contracts::{
    ArtifactId, OperationId, PolicyRevision, TaskId, TaskRevision, canonical_json_bytes, sha256_hex,
};
use eliot_governor::{CanonicalPlanBinding, LearningRecordPayload};
use eliot_instrument_api::InstrumentInvocation;
use eliot_learning_contracts::identity::SourceLineage;
use eliot_learning_contracts::{
    AttemptLearningDeltaCandidate, ChangeOperation, ChangeSurface, ContractBinding, InverseChange,
    ProofCeiling, TargetId, ValueState,
};
use eliot_protocol::RequestIdentity;
use eliot_store_api::{LearningRecordKind, NamedReadResponse, ScopeId};
use eliot_store_api::{WriteReceipt, WriteReceiptStatus};
use eliot_testd_core::{
    JobState as TestdJobState, TestJob, TestdPendingVerifierDispatch, TestdStore,
    TestdTerminalCompletionEvidence, TestdTerminalCompletionNotice, TestdVerifierDispatchBinding,
    verification_receipt_sha256,
};

fn completion_error(error: impl std::fmt::Display) -> DaemonError {
    DaemonError::Lifecycle(format!("TestD terminal completion: {error}"))
}

/// Build the real learning candidate contract from authenticated TestD
/// terminal evidence. The daemon does not persist an owner-defined JSON blob:
/// the stored document is the canonical `AttemptLearningDeltaCandidate`, with
/// the durable verifier receipt and finish decision represented only by
/// owner-issued evidence handles and lineage.
fn terminal_learning_candidate(
    job: &TestJob,
    identity: &RequestIdentity,
    decision: &eliot_governor::FinishDecisionReceipt,
    scope_id: &ScopeId,
    verifier_receipt_sha256: &str,
    expires_at_unix_ms: u64,
) -> Result<AttemptLearningDeltaCandidate, DaemonError> {
    let task_id = identity
        .request
        .metadata
        .task_id
        .clone()
        .ok_or_else(|| completion_error("learning candidate request has no task id"))?;
    if decision.task_id != task_id.as_str() {
        return Err(completion_error(
            "learning candidate task differs from the authenticated finish decision",
        ));
    }
    let source = SourceLineage {
        owner: identity.request.metadata.source_id.clone(),
        snapshot: ArtifactId::new(verifier_receipt_sha256).map_err(completion_error)?,
        revision: TaskRevision::new(decision.task_revision).map_err(completion_error)?,
        digest: verifier_receipt_sha256.to_owned(),
    };
    let binding = ContractBinding {
        schema_version: 1,
        policy_revision: PolicyRevision::new(1).map_err(completion_error)?,
        request_id: identity.request.metadata.request_id.clone(),
        operation_id: OperationId::new(format!("testd-learning-candidate-{}", job.job_id))
            .map_err(completion_error)?,
        product_id: identity.request.metadata.product_id.clone(),
        task_id,
        scope: eliot_receipts::WorkScopeId::new(scope_id.as_str()).map_err(completion_error)?,
        state_fence: identity.request.state_fence.clone(),
        source,
        proof_ceiling: ProofCeiling::CandidateArtifact,
    };
    let target = TargetId::new(format!("testd-target-{}", job.job_id)).map_err(completion_error)?;
    let after_digest = sha256_hex(
        &canonical_json_bytes(&serde_json::json!({
            "domain": "eliot.testd.learning-candidate.v1",
            "job_id": job.job_id,
            "verifier_receipt_sha256": verifier_receipt_sha256,
            "task_id": decision.task_id,
            "expires_at_unix_ms": expires_at_unix_ms,
        }))
        .map_err(completion_error)?,
    );
    let after = ValueState {
        present: true,
        digest: Some(after_digest),
    };
    let before = after.clone();
    let mut candidate = AttemptLearningDeltaCandidate {
        binding,
        attempt_id: AgentAttemptId::new(format!("testd-attempt-{}", job.job_id))
            .map_err(completion_error)?,
        delta_id: ArtifactId::new(format!("testd-candidate-{}", job.job_id))
            .map_err(completion_error)?,
        target: target.clone(),
        base_view_digest: verifier_receipt_sha256.to_owned(),
        pre_observation_discriminator: ArtifactId::new(format!(
            "testd-pre-observation-{}",
            job.job_id
        ))
        .map_err(completion_error)?,
        intended_strategy: ArtifactId::new(format!("testd-intended-{}", job.job_id))
            .map_err(completion_error)?,
        attempted_strategy: ArtifactId::new(format!("testd-attempted-{}", job.job_id))
            .map_err(completion_error)?,
        changes: vec![ChangeOperation::Add {
            target: target.clone(),
            surface: ChangeSurface::Strategy,
            after: after.clone(),
        }],
        inverses: vec![InverseChange {
            forward_target: target.clone(),
            inverse: ChangeOperation::Remove {
                target,
                surface: ChangeSurface::Strategy,
                before,
            },
        }],
        evidence: vec![ArtifactId::new(verifier_receipt_sha256).map_err(completion_error)?],
        evaluator_receipts: vec![
            ArtifactId::new(format!("testd-evaluator-{}", job.job_id)).map_err(completion_error)?,
        ],
        baseline: Vec::new(),
        control: Vec::new(),
        confounders: Vec::new(),
        dependencies: Vec::new(),
        equivalent_retry: None,
        proof_ceiling: ProofCeiling::CandidateArtifact,
        canonical_digest: String::new(),
    };
    candidate.seal().map_err(completion_error)?;
    if candidate.binding.state_fence != identity.request.state_fence
        || candidate.binding.scope.as_str() != scope_id.as_str()
        || expires_at_unix_ms == 0
    {
        return Err(completion_error(
            "learning candidate binding drifted from the authenticated terminal request",
        ));
    }
    Ok(candidate)
}

const TESTD_LEARNING_READ_PAGE_SIZE: u16 = 8;
const TESTD_LEARNING_READ_MAX_PAGES: usize = 1024;

fn learning_child_identity(
    identity: &RequestIdentity,
    record: &eliot_store_api::LearningRecordIdentity,
) -> Result<RequestIdentity, DaemonError> {
    identity.validate().map_err(completion_error)?;
    let key = eliot_governor::learning_record_idempotency_key(
        identity.request.metadata.request_id.as_str(),
        record,
    )
    .map_err(completion_error)?;
    let digest = sha256_hex(key.as_bytes());
    let mut child = identity.clone();
    child.idempotency_key = key;
    child.cancellation_id = format!("learning-cancel-v1-{digest}");
    child.validate().map_err(completion_error)?;
    Ok(child)
}

fn validate_learning_commit_receipt(
    receipt: &WriteReceipt,
    request_id: &str,
    proposal: &eliot_governor::LearningRecordProposal,
) -> Result<(), DaemonError> {
    receipt.validate().map_err(completion_error)?;
    if receipt.status != WriteReceiptStatus::Committed {
        return Err(completion_error(
            "learning commit did not return a durable committed receipt",
        ));
    }
    let expected_operation =
        eliot_governor::learning_record_operation_id(request_id, &proposal.identity)
            .map_err(completion_error)?;
    if receipt.operation_id != expected_operation
        || receipt.state_fence != proposal.identity.state_fence
    {
        return Err(completion_error(
            "learning commit receipt identity or fence differs from the proposal",
        ));
    }
    let decoded = eliot_store_api::decode_learning_mutation(
        proposal.request.operation,
        &proposal.request.parameters,
    )
    .map_err(completion_error)?;
    if receipt.idempotency_key != decoded.idempotency_key {
        return Err(completion_error(
            "learning commit receipt idempotency differs from the named record request",
        ));
    }
    Ok(())
}

fn readback_contains_identity(
    response: &NamedReadResponse,
    proposal: &eliot_governor::LearningRecordProposal,
) -> bool {
    let Some(records) = response
        .payload
        .get("records")
        .and_then(serde_json::Value::as_array)
    else {
        return false;
    };
    let expected_fence = serde_json::to_value(&proposal.identity.state_fence).ok();
    let Ok(expected_scope_digest) =
        eliot_store_api::learning_scope_digest(&proposal.identity.scope_id)
    else {
        return false;
    };
    let Ok(expected_fence_digest) =
        eliot_store_api::learning_fence_digest(&proposal.identity.state_fence)
    else {
        return false;
    };
    records.iter().any(|record| {
        record
            .get("record_kind")
            .and_then(serde_json::Value::as_str)
            == Some(proposal.identity.record_kind.as_str())
            && record.get("handle").and_then(serde_json::Value::as_str)
                == Some(proposal.identity.handle.as_str())
            && record
                .get("record_digest")
                .and_then(serde_json::Value::as_str)
                == Some(proposal.identity.record_digest.as_str())
            && record
                .get("record_json")
                .and_then(serde_json::Value::as_str)
                .is_some_and(|document| {
                    eliot_store_api::learning_record_document_digest(document)
                        .is_ok_and(|digest| digest == proposal.identity.record_digest)
                })
            && record
                .get("expires_at_unix_ms")
                .and_then(serde_json::Value::as_u64)
                == Some(proposal.identity.expires_at_unix_ms)
            && record.get("scope_id").and_then(serde_json::Value::as_str)
                == Some(proposal.identity.scope_id.as_str())
            && record
                .get("scope_digest")
                .and_then(serde_json::Value::as_str)
                == Some(expected_scope_digest.as_str())
            && record
                .get("fence_digest")
                .and_then(serde_json::Value::as_str)
                == Some(expected_fence_digest.as_str())
            && record.get("state_fence") == expected_fence.as_ref()
    })
}

fn unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(1, |duration| {
            u64::try_from(duration.as_millis().min(u128::from(u64::MAX))).unwrap_or(u64::MAX)
        })
}

fn terminal_state_name(state: TestdJobState) -> Result<&'static str, DaemonError> {
    match state {
        TestdJobState::Succeeded => Ok("succeeded"),
        TestdJobState::Failed => Ok("failed"),
        TestdJobState::Cancelled => Ok("cancelled"),
        _ => Err(completion_error(
            "terminal evidence is not a settled terminal job",
        )),
    }
}

impl DaemonComposition {
    /// Captures the current canonical verifier plan with its admitted owner
    /// identity. Call this before inserting/dispatching the productive `TestD`
    /// job; the returned binding is persisted in the durable `TestD` row.
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
    /// the durable `TestD` row before Kernel launch. The invocation and process
    /// operation are rehydrated from the submitted `TestD` owner row; productive
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
        let operation_id =
            OperationId::new(job.process.operation_id.clone()).map_err(completion_error)?;
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

    /// Consumes one pending authenticated `TestD` notification. The returned
    /// receipt is the canonical `WriteReceipt` from Governor; the durable `TestD`
    /// row is updated only after that commit has been observed.
    pub async fn publish_testd_terminal_completion(
        &self,
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
        if verification_receipt_sha256(receipt).map_err(completion_error)? != notice.receipt_sha256
        {
            return Err(completion_error(
                "terminal notification does not bind the exact durable finish receipt",
            ));
        }
        if job.lease.is_some() {
            return Err(completion_error(
                "TestD job still has an active worker lease",
            ));
        }
        let binding = job
            .verifier_dispatch
            .as_ref()
            .ok_or_else(|| completion_error("pre-dispatch Governor binding is absent"))?;
        binding.validate_for_job(&job).map_err(completion_error)?;
        let bound_plan: CanonicalPlanBinding =
            serde_json::from_str(&binding.canonical_plan_json).map_err(completion_error)?;
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
        let committed = Box::pin(self.governor.publish_testd_verifier_execution_fact(
            &binding.request_identity,
            &operation_id,
            &task_id,
            task_revision,
            &job.job_id,
            testd,
        ))
        .await
        .map_err(completion_error)?
        .ok_or_else(|| {
            completion_error(
                "Governor reported an existing verifier fact without its committed WriteReceipt",
            )
        })?;
        validate_committed_receipt(&committed, binding, &operation_id).map_err(completion_error)?;
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

    /// Drains one bounded batch from the durable `TestD` terminal owner. The
    /// daemon reactive-feed owner calls this API; each item is rehydrated and
    /// committed independently before its canonical receipt is recorded.
    pub async fn publish_pending_testd_terminal_completions(
        &self,
        testd: &TestdStore,
        limit: usize,
    ) -> Result<Vec<WriteReceipt>, DaemonError> {
        let pending = testd
            .pending_terminal_publications(limit)
            .map_err(completion_error)?;
        let mut committed = Vec::with_capacity(pending.len());
        for notice in pending {
            committed.push(Box::pin(self.publish_testd_terminal_completion(&notice, testd)).await?);
        }
        Ok(committed)
    }

    /// Reads one exact same-scope, same-fence learning page through the
    /// authenticated Kernel named-read route. This is the production read
    /// caller for the closed learning surface; it never opens a store client.
    pub async fn read_learning_record_range_page(
        &self,
        kernel: &DaemonKernelClient,
        scope_id: ScopeId,
        record_kind: Option<LearningRecordKind>,
        max_records: u16,
        cursor: Option<String>,
    ) -> Result<NamedReadResponse, DaemonError> {
        if self.readiness() != eliot_governor::CompositionReadiness::Ready {
            return Err(DaemonError::Composition(
                eliot_governor::CompositionError::NotReady,
            ));
        }
        let request = eliot_store_api::learning_record_read_request_page(
            scope_id,
            record_kind,
            max_records,
            self.governor.kernel_snapshot().state_fence().clone(),
            cursor,
        );
        crate::KernelContextReadClient::check_execute_capability(&request)
            .map_err(|error| DaemonError::Kernel(error.to_string()))?;
        let response = kernel
            .store_named_async(request.clone())
            .await
            .map_err(|error| DaemonError::Kernel(error.to_string()))?;
        crate::KernelContextReadClient::check_execute_response(&request, &response)
            .map_err(|error| DaemonError::Kernel(error.to_string()))?;
        Ok(response)
    }

    /// Reads the first learning page for compatibility callers that only need
    /// a bounded observation. Durable owner confirmation uses
    /// [`Self::read_learning_record_until_identity`] so a record on a later
    /// page cannot be mistaken for a missing commit.
    pub async fn read_learning_record_range(
        &self,
        kernel: &DaemonKernelClient,
        scope_id: ScopeId,
        record_kind: Option<LearningRecordKind>,
        max_records: u16,
    ) -> Result<NamedReadResponse, DaemonError> {
        self.read_learning_record_range_page(kernel, scope_id, record_kind, max_records, None)
            .await
    }

    /// Paginates the authenticated learning read until the exact committed
    /// identity is observed or the owner-minted continuation is exhausted.
    /// A missing, malformed, repeating, or unbounded cursor fails closed;
    /// acknowledgement is never based on a first-page assumption.
    pub async fn read_learning_record_until_identity(
        &self,
        kernel: &DaemonKernelClient,
        scope_id: ScopeId,
        proposal: &eliot_governor::LearningRecordProposal,
    ) -> Result<NamedReadResponse, DaemonError> {
        let mut cursor = None;
        let mut seen_cursors = HashSet::new();
        let mut all_records = Vec::<serde_json::Value>::new();
        let mut revision_heads = None;
        let mut total_matched = None;
        let mut found_identity = false;

        for _ in 0..TESTD_LEARNING_READ_MAX_PAGES {
            let response = self
                .read_learning_record_range_page(
                    kernel,
                    scope_id.clone(),
                    Some(proposal.identity.record_kind),
                    TESTD_LEARNING_READ_PAGE_SIZE,
                    cursor.clone(),
                )
                .await?;
            let payload = response
                .payload
                .as_object()
                .ok_or_else(|| completion_error("learning readback payload is not an object"))?;
            let page_records = payload
                .get("records")
                .and_then(serde_json::Value::as_array)
                .ok_or_else(|| completion_error("learning readback records are not an array"))?;
            let page_matched = payload
                .get("matched_total")
                .and_then(serde_json::Value::as_u64)
                .ok_or_else(|| completion_error("learning readback omitted matched_total"))?;
            if u64::try_from(page_records.len()).ok() != Some(page_matched) {
                return Err(completion_error(
                    "learning readback matched_total does not match the returned page",
                ));
            }
            let page_total = payload
                .get("total_matched")
                .and_then(serde_json::Value::as_u64)
                .ok_or_else(|| completion_error("learning readback omitted total_matched"))?;
            if let Some(previous_total) = total_matched
                && previous_total != page_total
            {
                return Err(completion_error(
                    "learning readback total changed during fenced pagination",
                ));
            }
            total_matched = Some(page_total);
            if let Some(previous_heads) = &revision_heads
                && previous_heads != &response.revision_heads
            {
                return Err(completion_error(
                    "learning readback revision heads changed during fenced pagination",
                ));
            }
            revision_heads = Some(response.revision_heads.clone());
            all_records.extend(page_records.iter().cloned());
            found_identity |= readback_contains_identity(&response, proposal);

            let end_of_stream = payload
                .get("end_of_stream")
                .and_then(serde_json::Value::as_bool)
                .ok_or_else(|| completion_error("learning readback omitted end_of_stream"))?;
            let truncated = payload
                .get("truncated")
                .and_then(serde_json::Value::as_bool)
                .ok_or_else(|| completion_error("learning readback omitted truncated"))?;
            if end_of_stream == truncated {
                return Err(completion_error(
                    "learning readback has inconsistent end-of-stream/truncation proof",
                ));
            }
            if end_of_stream {
                if !found_identity {
                    break;
                }
                let total = total_matched.ok_or_else(|| {
                    completion_error("learning readback omitted its total stream proof")
                })?;
                if u64::try_from(all_records.len()).ok() != Some(total) {
                    return Err(completion_error(
                        "learning readback pages do not account for the exact stream total",
                    ));
                }
                let mut merged = response;
                let merged_payload = merged.payload.as_object_mut().ok_or_else(|| {
                    completion_error("learning readback payload is not an object")
                })?;
                merged_payload.insert("records".to_owned(), serde_json::Value::Array(all_records));
                merged_payload.insert("matched_total".to_owned(), serde_json::Value::from(total));
                merged_payload.insert("end_of_stream".to_owned(), serde_json::Value::Bool(true));
                merged_payload.insert("truncated".to_owned(), serde_json::Value::Bool(false));
                merged_payload.insert("next_cursor".to_owned(), serde_json::Value::Null);
                return Ok(merged);
            }

            let Some(next) = payload
                .get("next_cursor")
                .and_then(serde_json::Value::as_str)
                .filter(|value| !value.trim().is_empty())
            else {
                return Err(completion_error(
                    "learning readback ended without an explicit end-of-stream proof",
                ));
            };
            if !seen_cursors.insert(next.to_owned()) {
                return Err(completion_error(
                    "learning readback returned a repeating continuation cursor",
                ));
            }
            cursor = Some(next.to_owned());
        }
        Err(completion_error(
            "learning readback exhausted before an exact committed identity and total proof were observed",
        ))
    }

    /// Drives one bounded `TestD` owner step through the authenticated Kernel
    /// owner routes only. This is the production caller of the Governor
    /// finish path for productive verifier evidence:
    ///
    /// ```text
    /// query pending verifier dispatches (owner poll)
    /// -> compute the canonical plan binding from the Governor read
    /// -> persist the binding through the owner bind leg
    /// -> query pending terminal evidence (owner poll)
    /// -> publish the verifier-execution fact (rehydrate -> canonical write)
    /// -> submit the finish candidate draft (rehydrate -> FinishService::evaluate -> persisted decision)
    /// -> acknowledge the terminal with the committed verifier-execution receipt (owner ack leg)
    /// ```
    ///
    /// The daemon never opens the `TestD` database: every row arrives through
    /// the Kernel owner polls above. The candidate draft carries only the
    /// terminal job identity and the evidence-led candidate outcome; the
    /// Governor rehydrates canonical evidence and derives the decision, so
    /// worker success never becomes a Task outcome here. One poisoned row
    /// is recorded as a diagnostic and skipped — it never fails the daemon
    /// closed, and a fence-moved row simply rejects owner-side on the next
    /// poll. Transport failures abort the step so the supervisor restarts
    /// the daemon onto a fresh handshake.
    pub async fn drive_testd_owner_finish_once(
        &mut self,
        kernel: &DaemonKernelClient,
    ) -> Result<TestdOwnerDrainOutcome, DaemonError> {
        if self.readiness() != eliot_governor::CompositionReadiness::Ready {
            return Err(completion_error(
                "TestD owner drain needs a Ready Governor composition",
            ));
        }
        let mut outcome = TestdOwnerDrainOutcome::default();
        let pending = kernel
            .query_testd_pending_dispatches_async(TESTD_OWNER_POLL_LIMIT)
            .await
            .map_err(|error| DaemonError::Kernel(error.to_string()))?;
        for entry in &pending {
            match self.bind_one_testd_dispatch(kernel, entry).await {
                Ok(()) => outcome.dispatch_bindings_persisted += 1,
                Err(error) => {
                    outcome.rows_skipped += 1;
                    emit_drain_skip(&entry.job.job_id, &error);
                }
            }
        }
        let terminals = kernel
            .query_testd_terminal_evidence_async(TESTD_OWNER_POLL_LIMIT)
            .await
            .map_err(|error| DaemonError::Kernel(error.to_string()))?;
        for evidence in &terminals {
            match self.drain_one_testd_terminal(kernel, evidence).await {
                Ok(()) => {
                    outcome.terminals_drained += 1;
                    outcome.finish_decisions_persisted += 1;
                    outcome.terminals_acked += 1;
                }
                Err(error) => {
                    outcome.rows_skipped += 1;
                    emit_drain_skip(&evidence.job.job_id, &error);
                }
            }
        }
        Ok(outcome)
    }

    /// Binds one pending productive dispatch: the canonical plan binding is
    /// computed from the current Governor read and persisted owner-side
    /// against the exact admitted identity.
    async fn bind_one_testd_dispatch(
        &self,
        kernel: &DaemonKernelClient,
        entry: &TestdPendingVerifierDispatch,
    ) -> Result<(), DaemonError> {
        let identity = &entry.request_identity;
        let job = &entry.job;
        let task_id = identity
            .request
            .metadata
            .task_id
            .clone()
            .ok_or_else(|| completion_error("pending dispatch has no admitted task id"))?;
        let task_revision = identity
            .request
            .state_fence
            .task_revision
            .as_ref()
            .map(|revision| revision.value())
            .ok_or_else(|| completion_error("pending dispatch has no task revision fence"))?;
        let operation_id =
            OperationId::new(job.process.operation_id.clone()).map_err(completion_error)?;
        let binding = self.testd_verifier_dispatch_binding(
            identity,
            &operation_id,
            &task_id,
            task_revision,
            &job.invocation,
        )?;
        kernel
            .acknowledge_testd_verifier_dispatch_async(&job.job_id, binding)
            .await
            .map_err(|error| DaemonError::Kernel(error.to_string()))?;
        Ok(())
    }

    /// Drains one terminal evidence row: publishes the verifier-execution
    /// fact, submits the evidence-led finish candidate through the Governor
    /// production caller, then acknowledges the terminal owner-side.
    async fn drain_one_testd_terminal(
        &mut self,
        kernel: &DaemonKernelClient,
        evidence: &TestdTerminalCompletionEvidence,
    ) -> Result<(), DaemonError> {
        let identity = &evidence.request_identity;
        let job = &evidence.job;
        // Boxed: the committed receipt is held across the finish/ack awaits
        // and `WriteReceipt` carries the full issue-#18 digest bindings, so
        // keeping it inline would push this drain future past the
        // large-future bound. Same value, same move into the ack leg.
        let committed = Box::new(
            self.governor
                .publish_testd_verifier_execution_fact_from_evidence(evidence)
                .await
                .map_err(DaemonError::Finish)?
                .ok_or_else(|| {
                    completion_error(
                        "Governor reported a verifier fact without its committed receipt",
                    )
                })?,
        );
        let draft = finish_draft_from_testd_terminal_evidence(job, identity)?;
        let operation_id = OperationId::new(format!("testd-owner-finish-{}", job.job_id))
            .map_err(completion_error)?;
        let decision = self.finish_attempt(identity, operation_id, draft).await?;
        if decision.state_fence != identity.request.state_fence
            || decision.task_id
                != identity
                    .request
                    .metadata
                    .task_id
                    .as_ref()
                    .map(ToString::to_string)
                    .unwrap_or_default()
        {
            return Err(completion_error(
                "finish decision is not bound to the terminal request identity",
            ));
        }
        let now_unix_ms = unix_ms();
        let scope_id =
            ScopeId::new(job.invocation.declared_scope.clone()).map_err(completion_error)?;
        let verifier_receipt = job
            .verification_receipt
            .as_ref()
            .ok_or_else(|| completion_error("terminal evidence has no durable verifier receipt"))?;
        let observed_at_unix_ms = verifier_receipt
            .finished_at
            .known_time_ms
            .or(verifier_receipt.finished_at.valid_time_ms)
            .ok_or_else(|| completion_error("verifier receipt has no durable terminal clock"))?;
        let observed_at_unix_ms = u64::try_from(observed_at_unix_ms)
            .map_err(|_| completion_error("verifier clock is negative"))?;
        let expires_at_unix_ms = observed_at_unix_ms.saturating_add(24 * 60 * 60 * 1_000);
        let verifier_receipt_sha256 =
            verification_receipt_sha256(verifier_receipt).map_err(completion_error)?;
        let _terminal_state = terminal_state_name(job.state)?;
        let candidate = terminal_learning_candidate(
            job,
            identity,
            &decision,
            &scope_id,
            &verifier_receipt_sha256,
            expires_at_unix_ms,
        )?;
        let provisional = LearningRecordPayload::Candidate(&candidate)
            .into_proposal(
                &scope_id,
                &identity.request.state_fence,
                expires_at_unix_ms,
                format!("learning-terminal-{}", job.job_id),
            )
            .map_err(completion_error)?;
        let learning_identity = learning_child_identity(identity, &provisional.identity)?;
        let proposal = LearningRecordPayload::Candidate(&candidate)
            .into_proposal(
                &scope_id,
                &identity.request.state_fence,
                expires_at_unix_ms,
                learning_identity.idempotency_key.clone(),
            )
            .map_err(completion_error)?;
        let learning_receipt = self
            .commit_learning_record_proposal(
                &learning_identity,
                &proposal,
                vec![verifier_receipt_sha256.clone()],
            )
            .await?;
        validate_learning_commit_receipt(
            &learning_receipt,
            learning_identity.request.metadata.request_id.as_str(),
            &proposal,
        )?;
        let readback = self
            .read_learning_record_until_identity(kernel, scope_id, &proposal)
            .await?;
        let claim = eliot_governor::LearningRecordAdmissionClaim {
            admission: eliot_governor::LearningAdmissionClaim {
                schema_version: eliot_governor::LEARNING_ADMISSION_SCHEMA_VERSION,
                source_campaign_id: candidate.binding.source.owner.as_str().to_owned(),
                target_task_id: decision.task_id.clone(),
                fence: identity.request.state_fence.clone(),
                overlay_id: None,
                candidate_id: Some(candidate.delta_id.as_str().to_owned()),
                scope_ref: proposal.identity.scope_id.clone(),
                authority_ref: verifier_receipt_sha256.clone(),
                retention_ref: format!("testd-retention-{}", job.job_id),
                evaluator_ref: format!("testd-evaluator-{}", job.job_id),
                rollback_ref: format!("testd-rollback-{}", job.job_id),
            },
            record: eliot_governor::LearningRecordAdmissionBinding::from_identity(
                &proposal.identity,
            ),
        };
        let (_permit, _effectiveness) = self.admit_learning_record_after_commit(
            &proposal,
            &claim,
            &learning_receipt,
            &readback,
            now_unix_ms,
        )?;
        kernel
            .acknowledge_testd_terminal_completion_async(&job.job_id, *committed)
            .await
            .map_err(|error| DaemonError::Kernel(error.to_string()))?;
        Ok(())
    }
}

/// Outcome of one bounded `TestD` owner drain step. Every counter names work
/// the Kernel owner committed; skipped rows were recorded as diagnostics.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct TestdOwnerDrainOutcome {
    /// Verifier-dispatch bindings persisted through the owner bind leg.
    pub dispatch_bindings_persisted: usize,
    /// Terminal rows whose verifier fact, finish decision, and ack all
    /// committed.
    pub terminals_drained: usize,
    /// Finish decisions persisted through `FinishService::evaluate`.
    pub finish_decisions_persisted: usize,
    /// Terminal receipts acknowledged owner-side.
    pub terminals_acked: usize,
    /// Rows recorded as diagnostics and skipped this step.
    pub rows_skipped: usize,
}

/// Builds the evidence-led finish candidate for one terminal `TestD` row.
/// The requested outcome reports the terminal job state; it never promotes
/// worker success into a Task outcome — the Governor rehydrates canonical
/// evidence and derives the decision, and a candidate never asserts a
/// verifier run.
fn finish_draft_from_testd_terminal_evidence(
    job: &TestJob,
    identity: &RequestIdentity,
) -> Result<eliot_governor::FinishAttemptDraft, DaemonError> {
    let task_id = identity
        .request
        .metadata
        .task_id
        .clone()
        .ok_or_else(|| completion_error("terminal evidence has no admitted task id"))?;
    let expected_task_revision = identity
        .request
        .state_fence
        .task_revision
        .as_ref()
        .map(|revision| revision.value())
        .ok_or_else(|| completion_error("terminal evidence has no task revision fence"))?;
    let requested_outcome = match job.state {
        TestdJobState::Succeeded => eliot_governor::RequestedFinishOutcome::CompleteCandidate,
        TestdJobState::Failed => eliot_governor::RequestedFinishOutcome::FailedVerification,
        TestdJobState::Cancelled => eliot_governor::RequestedFinishOutcome::Cancelled,
        _ => {
            return Err(completion_error(
                "terminal evidence is not a settled terminal job",
            ));
        }
    };
    Ok(eliot_governor::FinishAttemptDraft {
        task_id: task_id.as_str().to_owned(),
        expected_task_revision,
        requested_outcome,
        artifact_refs: vec![job.job_id.clone(), job.process.operation_id.clone()],
        observation_refs: Vec::new(),
        // Verifier ownership remains in the canonical evidence projection;
        // a TestD terminal candidate cannot assert a verifier run.
        verifier_run_refs: Vec::new(),
        remaining_unknowns_declared_by_caller: Vec::new(),
        rationale_candidate: format!("testd-owner-terminal:{}", job.job_id),
    })
}

fn emit_drain_skip(job_id: &str, error: &DaemonError) {
    let _ = crate::diagnostics::ErrorRecord::of(
        crate::diagnostics::OwningComponent::DaemonRuntime,
        "testd-owner-drain-skip",
        &format!("job {job_id}: {error}"),
    )
    .emit();
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
        return Err(
            "Governor response is not the exact committed verifier WriteReceipt".to_owned(),
        );
    }
    Ok(())
}
