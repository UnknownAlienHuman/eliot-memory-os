//! Original request binding for the authenticated current-source process
//! route.
//!
//! This adapter does not mint the process intent, lease, fence, deadline,
//! profile grant, or source proof.  It checks that the original EBP request
//! identity still names the exact inert P-03 request before forwarding it to
//! the Kernel's existing private process gateway.

use eliot_contracts::TaskId;
use eliot_ipc::Session;
use eliot_kernel_service::{ProcessExecutionRejection, ProcessExecutionRequest};
use eliot_protocol::RequestIdentity;

/// A source-process payload joined to its validated original EBP identity.
///
/// The value is created only after the request identity and process request
/// agree on operation, the exact admitted task, fence, recipient, and (for
/// Start) the original deadline. It is local to the Kernel call stack, is not
/// authority, and cannot be serialized into a reusable admission token.
pub(super) struct BoundCurrentSourceProcessRequest {
    request: ProcessExecutionRequest,
    task_id: TaskId,
    identity: RequestIdentity,
}

impl BoundCurrentSourceProcessRequest {
    pub(super) fn bind(
        identity: &RequestIdentity,
        task_id: &TaskId,
        request: ProcessExecutionRequest,
        session: &Session,
    ) -> Result<Self, ProcessExecutionRejection> {
        validate_current_source_request(identity, task_id, &request, session)?;
        Ok(Self {
            request,
            task_id: task_id.clone(),
            identity: identity.clone(),
        })
    }

    pub(super) fn into_parts(self) -> (ProcessExecutionRequest, RequestIdentity, TaskId) {
        (self.request, self.identity, self.task_id)
    }
}

pub(super) fn validate_current_source_request(
    identity: &RequestIdentity,
    admitted_task_id: &TaskId,
    request: &ProcessExecutionRequest,
    session: &Session,
) -> Result<(), ProcessExecutionRejection> {
    let reject = |code: &str, detail: &str| ProcessExecutionRejection {
        code: code.to_owned(),
        detail: detail.to_owned(),
    };
    identity.validate().map_err(|_| {
        reject(
            "SOURCE_REQUEST_IDENTITY_INVALID",
            "original source request identity failed protocol validation",
        )
    })?;
    request.validate().map_err(|_| {
        reject(
            "SOURCE_PROCESS_REQUEST_INVALID",
            "source process request failed process contract validation",
        )
    })?;

    let operation_id = request.operation_id().ok_or_else(|| {
        reject(
            "SOURCE_PROCESS_OPERATION_MISSING",
            "source process request omitted its original operation identity",
        )
    })?;
    if identity.request.state_fence != session.module_generation.state_fence
        || identity.request.metadata.state_fence != identity.request.state_fence
        || identity.request.metadata.task_id.as_ref() != Some(admitted_task_id)
        || identity.request.metadata.request_id.as_str() != operation_id.as_str()
    {
        return Err(reject(
            "SOURCE_REQUEST_BINDING_MISMATCH",
            "source process operation is not bound to the original task request and session fence",
        ));
    }

    if let ProcessExecutionRequest::Start(admission) = request
        && (admission.recipient_module_id() != session.module_generation.module_id.as_str()
            || admission.deadline_unix_ms() != identity.deadline_unix_ms
            || !admission
                .state_fence()
                .authority_epoch()
                .is_same_authority(&identity.request.state_fence.authority_epoch)
            || admission.state_fence().generation().get()
                != identity.request.state_fence.resource_generation.value()
            || admission.intent().operation_id().as_str()
                != identity.request.metadata.request_id.as_str())
    {
        return Err(reject(
            "SOURCE_PROCESS_ADMISSION_MISMATCH",
            "source process start differs from the original recipient, deadline, operation, or exact state fence",
        ));
    }

    Ok(())
}
