//! Authenticated child-operation binding for current-source Git commands.
//!
//! The selected-source request and every Git process operation have distinct
//! protocol identities. This boundary proves their retained request lineage,
//! then routes only the exact owner-leased child request through the existing
//! private P-03 process gateway. It does not mint Governor leases, derive
//! child identities, or launch a native process.

use eliot_contracts::TaskId;
use eliot_ipc::Session;
use eliot_kernel_service::{
    ProcessExecutionRejection, ProcessExecutionRequest, ProcessExecutionResponse,
};
use eliot_process::{
    ActionLeaseRef, FencingToken, ProcessExecutionAdmissionRequest, ProcessIntent,
    ProcessSessionBinding,
};
use eliot_protocol::RequestIdentity;

use super::{KernelComposition, observe_process_in_context};

/// Forms the inert P-03 Start request from the original Git `ProcessIntent`
/// plus the real Governor-issued ActionLease reference and original fence.
/// This validates only the process contract shape; no authority is minted.
pub(crate) fn build_current_source_git_start_request(
    intent: ProcessIntent,
    action_lease_ref: ActionLeaseRef,
    state_fence: FencingToken,
    recipient_module_id: String,
    deadline_unix_ms: u64,
) -> Result<ProcessExecutionRequest, ProcessExecutionRejection> {
    let admission = ProcessExecutionAdmissionRequest::new(
        recipient_module_id,
        intent,
        action_lease_ref,
        state_fence,
        deadline_unix_ms,
    )
    .map_err(|_| ProcessExecutionRejection {
        code: "SOURCE_GIT_PROCESS_ADMISSION_INVALID".to_owned(),
        detail: "owner-issued Git process admission did not satisfy the P-03 request contract"
            .to_owned(),
    })?;
    Ok(ProcessExecutionRequest::Start(admission))
}

/// Executes one already-authorized Git child operation after retaining the
/// original selected-source request as its parent context.
///
/// `child_identity` and `request` must come from the Governor's original
/// per-command ActionContract/ActionLease and process admission producer. The
/// operation ID is never copied from or substituted with the parent ID.
pub(crate) async fn execute_current_source_git_process_request(
    composition: &KernelComposition,
    session: &Session,
    session_binding: ProcessSessionBinding,
    parent_identity: &RequestIdentity,
    child_identity: &RequestIdentity,
    admitted_task_id: &TaskId,
    request: ProcessExecutionRequest,
) -> ProcessExecutionResponse {
    let context = super::super::kernel_diagnostics::operation_context(None, None, None, None);
    observe_process_in_context(&context, "kernel.process.request_received", "attempt");
    if let Err(rejection) =
        validate_git_child_lineage(parent_identity, child_identity, admitted_task_id, session)
    {
        observe_process_in_context(
            &context,
            "kernel.process.request_rejected",
            "source_binding",
        );
        return ProcessExecutionResponse::Rejected(rejection);
    }
    if let Err(rejection) = super::lsp_admission::validate_current_source_request(
        child_identity,
        admitted_task_id,
        &request,
        session,
    ) {
        observe_process_in_context(&context, "kernel.process.request_rejected", "child_binding");
        return ProcessExecutionResponse::Rejected(rejection);
    }

    // The parent is provenance only. P-03 receives the owner-created child
    // identity and exact request; its action lease, fence, replay state, path
    // proof and one-shot permit are independently enforced in the existing
    // process admission and gateway path.
    composition
        .execute_process_request_inner(
            session,
            session_binding,
            request,
            Some((child_identity, admitted_task_id)),
            &context,
        )
        .await
}

fn validate_git_child_lineage(
    parent: &RequestIdentity,
    child: &RequestIdentity,
    task_id: &TaskId,
    session: &Session,
) -> Result<(), ProcessExecutionRejection> {
    validate_git_child_identity_lineage(
        parent,
        child,
        task_id,
        &session.module_generation.state_fence,
    )
}

fn validate_git_child_identity_lineage(
    parent: &RequestIdentity,
    child: &RequestIdentity,
    task_id: &TaskId,
    session_fence: &eliot_contracts::StateFence,
) -> Result<(), ProcessExecutionRejection> {
    let reject = |code: &str, detail: &str| ProcessExecutionRejection {
        code: code.to_owned(),
        detail: detail.to_owned(),
    };
    parent.validate().map_err(|_| {
        reject(
            "SOURCE_PARENT_IDENTITY_INVALID",
            "original selected-source parent identity failed protocol validation",
        )
    })?;
    child.validate().map_err(|_| {
        reject(
            "SOURCE_CHILD_IDENTITY_INVALID",
            "owner-issued Git child identity failed protocol validation",
        )
    })?;

    let parent_request = &parent.request;
    let child_request = &child.request;
    let parent_metadata = &parent_request.metadata;
    let child_metadata = &child_request.metadata;
    if parent_metadata.request_id == child_metadata.request_id
        || parent.deadline_unix_ms != child.deadline_unix_ms
        || parent_metadata.product_id != child_metadata.product_id
        || parent_metadata.source_id != child_metadata.source_id
        || parent_metadata.session_id != child_metadata.session_id
        || parent_metadata.task_id.as_ref() != Some(task_id)
        || child_metadata.task_id.as_ref() != Some(task_id)
        || &parent_request.state_fence != session_fence
        || parent_metadata.state_fence != parent_request.state_fence
        || child_request.state_fence != parent_request.state_fence
        || child_metadata.state_fence != child_request.state_fence
    {
        return Err(reject(
            "SOURCE_CHILD_LINEAGE_MISMATCH",
            "Git child does not retain the selected-source task, source, product, deadline, and exact session fence",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use eliot_contracts::{
        ClockReading, EpochId, EpochLineageId, ProductId, RequestId, RequestMetadata,
        ResourceGeneration, SessionId, SourceId, StateFence,
    };
    use eliot_kernel_service::ProcessExecutionRequest;
    use eliot_process::{
        EnvironmentInheritance, EnvironmentProjection, Generation, ImageId, JobId, OperationId,
        ProcessTreeId, ResourceLimits, SessionId as ProcessSessionId,
    };
    use std::collections::BTreeMap;
    use std::num::NonZeroU64;

    fn lineage_fence(sequence: u64, generation: u64) -> StateFence {
        let lineage =
            EpochLineageId::new("550e8400-e29b-41d4-a716-446655440000").expect("valid lineage");
        StateFence::new(
            EpochId::new(
                lineage,
                NonZeroU64::new(sequence).expect("nonzero sequence"),
            ),
            ResourceGeneration::new(generation).expect("nonzero generation"),
        )
    }

    fn identity(
        request_id: &str,
        session_id: &str,
        task_id: &str,
        fence: StateFence,
    ) -> RequestIdentity {
        let clock = ClockReading {
            valid_time_ms: Some(1),
            known_time_ms: Some(1),
            transaction_sequence: None,
            monotonic_ns: Some(1),
        };
        let idempotency_key = format!("{request_id}-idempotency");
        let cancellation_id = format!("{request_id}-cancel");
        RequestIdentity {
            request: eliot_receipts::RequestBinding {
                metadata: RequestMetadata {
                    request_id: RequestId::new(request_id).expect("request id"),
                    session_id: Some(SessionId::new(session_id).expect("session id")),
                    task_id: Some(TaskId::new(task_id).expect("task id")),
                    product_id: ProductId::new("eliotd").expect("product id"),
                    source_id: SourceId::new("selected-source").expect("source id"),
                    state_fence: fence.clone(),
                    clock,
                },
                state_fence: fence,
            },
            idempotency_key,
            deadline_unix_ms: 4_000_000_000_000,
            cancellation_id,
        }
    }

    fn process_intent() -> ProcessIntent {
        let lineage =
            EpochLineageId::new("550e8400-e29b-41d4-a716-446655440000").expect("valid lineage");
        let epoch = EpochId::new(lineage, NonZeroU64::new(1).expect("nonzero sequence"));
        ProcessIntent::new(
            OperationId::new("git-process-op").expect("operation"),
            ProcessTreeId::new("git-process-tree").expect("tree"),
            JobId::new("git-process-job").expect("job"),
            ImageId::new("git-process-image").expect("image"),
            ProcessSessionId::new("git-session").expect("session"),
            Generation::new(1).expect("generation"),
            r"C:\Program Files\Git\cmd\git.exe",
            "a".repeat(64),
            vec!["write-tree".to_owned()],
            r"C:\workspace",
            EnvironmentProjection::new(BTreeMap::new(), Vec::new(), EnvironmentInheritance::None)
                .expect("environment"),
            ResourceLimits::new(30_000, None, None, 4_096, 4_096, 4).expect("process limits"),
        )
        .expect("intent")
    }

    #[test]
    fn start_builder_preserves_the_owner_process_intent_and_lease() {
        let operation = process_intent().operation_id().as_str().to_owned();
        let request = build_current_source_git_start_request(
            process_intent(),
            ActionLeaseRef::new("governor-git-lease").expect("owner lease"),
            FencingToken::new(
                EpochId::new(
                    EpochLineageId::new("550e8400-e29b-41d4-a716-446655440000")
                        .expect("valid lineage"),
                    NonZeroU64::new(1).expect("nonzero sequence"),
                ),
                Generation::new(1).expect("generation"),
                "git-fence",
            )
            .expect("fence"),
            "eliot-kernel".to_owned(),
            4_000_000_000_000,
        )
        .expect("well-formed original P-03 material");
        let ProcessExecutionRequest::Start(admission) = request else {
            unreachable!("Git operation producer always returns a P-03 Start")
        };
        assert_eq!(admission.intent().operation_id().as_str(), operation);
        assert_eq!(admission.action_lease_ref().as_str(), "governor-git-lease");
        assert_eq!(admission.intent().argv(), &["write-tree"]);
    }

    #[test]
    fn start_builder_refuses_invalid_owner_admission_shape() {
        let result = build_current_source_git_start_request(
            process_intent(),
            ActionLeaseRef::new("governor-git-lease").expect("owner lease"),
            FencingToken::new(
                EpochId::new(
                    EpochLineageId::new("550e8400-e29b-41d4-a716-446655440000")
                        .expect("valid lineage"),
                    NonZeroU64::new(2).expect("nonzero sequence"),
                ),
                Generation::new(2).expect("generation"),
                "git-fence-mismatch",
            )
            .expect("different fence"),
            "eliot-kernel".to_owned(),
            0,
        );
        assert!(matches!(
            result,
            Err(ProcessExecutionRejection {
                code,
                ..
            }) if code == "SOURCE_GIT_PROCESS_ADMISSION_INVALID"
        ));
    }

    #[test]
    fn child_lineage_accepts_original_session_task_fence_and_distinct_operation() {
        let fence = lineage_fence(1, 1);
        let task = TaskId::new("task-live-source").expect("task");
        let parent = identity(
            "selected-source-parent",
            "session-current",
            "task-live-source",
            fence.clone(),
        );
        let child = identity(
            "git-process-op",
            "session-current",
            "task-live-source",
            fence.clone(),
        );
        let request = build_current_source_git_start_request(
            process_intent(),
            ActionLeaseRef::new("governor-git-lease").expect("owner lease"),
            FencingToken::new(
                EpochId::new(
                    EpochLineageId::new("550e8400-e29b-41d4-a716-446655440000")
                        .expect("valid lineage"),
                    NonZeroU64::new(1).expect("nonzero sequence"),
                ),
                Generation::new(1).expect("generation"),
                "git-fence",
            )
            .expect("fence"),
            "eliot-kernel".to_owned(),
            parent.deadline_unix_ms,
        )
        .expect("owner process request");
        let ProcessExecutionRequest::Start(admission) = request else {
            unreachable!("Git operation producer always returns a P-03 Start")
        };

        assert!(validate_git_child_identity_lineage(&parent, &child, &task, &fence).is_ok());
        assert_ne!(
            parent.request.metadata.request_id,
            child.request.metadata.request_id
        );
        assert_eq!(
            child.request.metadata.request_id.as_str(),
            admission.intent().operation_id().as_str()
        );
    }

    #[test]
    fn child_lineage_refuses_session_task_fence_deadline_and_operation_drift() {
        let fence = lineage_fence(1, 1);
        let task = TaskId::new("task-live-source").expect("task");
        let parent = identity(
            "selected-source-parent",
            "session-current",
            "task-live-source",
            fence.clone(),
        );
        let child = identity(
            "git-process-op",
            "session-current",
            "task-live-source",
            fence.clone(),
        );
        assert!(validate_git_child_identity_lineage(&parent, &child, &task, &fence).is_ok());

        let foreign_session = identity(
            "git-process-op",
            "session-foreign",
            "task-live-source",
            fence.clone(),
        );
        assert!(matches!(
            validate_git_child_identity_lineage(&parent, &foreign_session, &task, &fence),
            Err(ProcessExecutionRejection { code, .. }) if code == "SOURCE_CHILD_LINEAGE_MISMATCH"
        ));

        let foreign_task = identity(
            "git-process-op",
            "session-current",
            "task-foreign",
            fence.clone(),
        );
        assert!(matches!(
            validate_git_child_identity_lineage(&parent, &foreign_task, &task, &fence),
            Err(ProcessExecutionRejection { code, .. }) if code == "SOURCE_CHILD_LINEAGE_MISMATCH"
        ));

        let foreign_fence = lineage_fence(2, 2);
        let foreign_fence_child = identity(
            "git-process-op",
            "session-current",
            "task-live-source",
            foreign_fence,
        );
        assert!(matches!(
            validate_git_child_identity_lineage(&parent, &foreign_fence_child, &task, &fence),
            Err(ProcessExecutionRejection { code, .. }) if code == "SOURCE_CHILD_LINEAGE_MISMATCH"
        ));

        let mut foreign_deadline = child.clone();
        foreign_deadline.deadline_unix_ms += 1;
        assert!(matches!(
            validate_git_child_identity_lineage(&parent, &foreign_deadline, &task, &fence),
            Err(ProcessExecutionRejection { code, .. }) if code == "SOURCE_CHILD_LINEAGE_MISMATCH"
        ));

        let aliased_operation = identity(
            parent.request.metadata.request_id.as_str(),
            "session-current",
            "task-live-source",
            fence.clone(),
        );
        assert!(matches!(
            validate_git_child_identity_lineage(&parent, &aliased_operation, &task, &fence),
            Err(ProcessExecutionRejection { code, .. }) if code == "SOURCE_CHILD_LINEAGE_MISMATCH"
        ));
    }
}
