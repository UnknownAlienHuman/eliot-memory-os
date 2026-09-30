//! Read-only daemon projection of one original Kernel native-worker admission.
//!
//! The caller supplies the existing native claim ID and the exact live
//! Task Controller attempt as lookup selectors. Kernel resolves the current
//! queue owner, retained dispatch request/receipt, and ORS claim row, then
//! validates their original cross-references and live currentness. This path
//! creates no claim, admission receipt, launch, or Task Controller attempt.

#[cfg(windows)]
use eliot_contracts::{canonical_json_bytes, sha256_hex};
#[cfg(windows)]
use eliot_kernel_service::{
    NATIVE_WORKER_EXECUTION_ADMISSION_READ_WIRE_ID,
    NATIVE_WORKER_EXECUTION_ADMISSION_READ_WIRE_VERSION, NativeWorkerExecutionAdmissionEvidence,
    NativeWorkerExecutionAdmissionPhase, NativeWorkerExecutionAdmissionReadRequest,
    NativeWorkerExecutionAdmissionReadResponse,
};
#[cfg(windows)]
use eliot_protocol::{TaskControllerAttempt, TaskControllerInvocation};
#[cfg(windows)]
use serde_json::Value;

#[cfg(windows)]
use crate::{
    ACTIVE_DAEMON_CALLER, KernelComposition, Session, TransportError,
    daemon_session_guard::caller_binding,
};

/// Closed daemon operation name. The authenticated daemon dispatcher and
/// frame-operation mirror must both register this exact value.
pub(crate) const NATIVE_WORKER_EXECUTION_ADMISSION_READ_OPERATION: &str =
    "native_worker_execution_admission_read";

impl KernelComposition {
    /// Reads original prelaunch execution-admission evidence for one exact
    /// current Task Controller attempt. A missing, stale, launched, or
    /// mismatched owner record fails closed.
    #[cfg(windows)]
    pub(crate) fn read_native_worker_execution_admission(
        &self,
        session: &Session,
        request: &NativeWorkerExecutionAdmissionReadRequest,
    ) -> Result<NativeWorkerExecutionAdmissionReadResponse, TransportError> {
        request
            .validate()
            .map_err(|_| TransportError::SessionFenced)?;
        if session.module_generation.module_id.as_str() != ACTIVE_DAEMON_CALLER {
            return Err(TransportError::SessionFenced);
        }
        self.require_current_daemon_session(session)?;
        let (owner, _) = caller_binding(session)?;
        if owner.module_id() != ACTIVE_DAEMON_CALLER
            || owner.generation().get() != session.module_generation.generation.value()
            || !owner
                .authority_epoch()
                .is_same_authority(&session.authority_epoch)
            || !request
                .task_controller_attempt
                .state_fence
                .is_compatible_with(&session.module_generation.state_fence)
        {
            return Err(TransportError::SessionFenced);
        }

        let (envelope, invocation) = self
            .task_controller_attempt_owner(session, &request.task_controller_attempt)?
            .ok_or(TransportError::SessionFenced)?;
        let attempt = &request.task_controller_attempt;
        let published_claim_id = invocation
            .task_input
            .get("native_worker_claim_id")
            .and_then(serde_json::Value::as_str)
            .ok_or(TransportError::SessionFenced)?;
        if invocation.task_id != attempt.task_id
            || invocation.work_scope_id != attempt.scope_id
            || envelope.state_fence != attempt.state_fence
            || published_claim_id != request.native_worker_claim_id
        {
            return Err(TransportError::SessionFenced);
        }

        let original = super::dispatch_launch::native_worker_prelaunch_admission(
            &request.native_worker_claim_id,
        )
        .map_err(|_| TransportError::SessionFenced)?;
        if original.phase != NativeWorkerExecutionAdmissionPhase::Reserved {
            return Err(TransportError::SessionFenced);
        }
        let durable = self
            .load_claim_record(&request.native_worker_claim_id)
            .map_err(|_| TransportError::SessionFenced)?;
        let evidence = NativeWorkerExecutionAdmissionEvidence::from_owner_records(
            &original.request,
            &original.claim_receipt,
            &durable,
        )
        .map_err(|_| TransportError::SessionFenced)?;
        validate_original_orientation_job_binding(
            &invocation,
            attempt,
            &evidence.request,
            published_claim_id,
        )?;
        self.validate_prelaunch_native_worker_execution_admission(&evidence)
            .map_err(|_| TransportError::SessionFenced)?;

        let response = NativeWorkerExecutionAdmissionReadResponse {
            wire_id: NATIVE_WORKER_EXECUTION_ADMISSION_READ_WIRE_ID.to_owned(),
            wire_version: NATIVE_WORKER_EXECUTION_ADMISSION_READ_WIRE_VERSION,
            task_controller_attempt: attempt.clone(),
            execution_admission: evidence,
            launch_phase: original.phase,
        };
        response
            .validate_against(request)
            .map_err(|_| TransportError::SessionFenced)?;
        Ok(response)
    }

    /// Verifies and returns the exact original Kernel claim ID embedded in
    /// one claimed Orientation invocation. The nested durable owner payload
    /// must name the same opaque ID and bind the native claim's original job,
    /// attempt, task, scope, and complete fence before it can be echoed.
    #[cfg(windows)]
    pub(crate) fn verified_native_worker_claim_id_for_task_controller_claim(
        &self,
        session: &Session,
        invocation: &TaskControllerInvocation,
        attempt: &TaskControllerAttempt,
    ) -> Result<Option<String>, TransportError> {
        let Some(claim_id) = invocation
            .task_input
            .get("native_worker_claim_id")
            .and_then(Value::as_str)
        else {
            return Ok(None);
        };
        let request = NativeWorkerExecutionAdmissionReadRequest {
            wire_id: NATIVE_WORKER_EXECUTION_ADMISSION_READ_WIRE_ID.to_owned(),
            wire_version: NATIVE_WORKER_EXECUTION_ADMISSION_READ_WIRE_VERSION,
            task_controller_attempt: attempt.clone(),
            native_worker_claim_id: claim_id.to_owned(),
        };
        let response = self.read_native_worker_execution_admission(session, &request)?;
        Ok(Some(response.execution_admission.request.claim_id))
    }
}

#[cfg(windows)]
fn validate_original_orientation_job_binding(
    invocation: &TaskControllerInvocation,
    attempt: &TaskControllerAttempt,
    native: &eliot_kernel_service::NativeWorkerClaimRequest,
    published_claim_id: &str,
) -> Result<(), TransportError> {
    let request = invocation
        .task_input
        .get("request")
        .ok_or(TransportError::SessionFenced)?;
    let operation = request
        .get("operation")
        .filter(|value| value.get("operation").and_then(Value::as_str) == Some("SUBMIT_JOB"))
        .ok_or(TransportError::SessionFenced)?;
    let submission = operation
        .get("submission")
        .ok_or(TransportError::SessionFenced)?;
    let runtime_reference = submission
        .get("runtime_owner_execution_input")
        .ok_or(TransportError::SessionFenced)?;
    let runtime_bytes = submission
        .get("runtime_owner_execution_input_bytes")
        .and_then(Value::as_array)
        .ok_or(TransportError::SessionFenced)?
        .iter()
        .map(|value| {
            value
                .as_u64()
                .and_then(|byte| u8::try_from(byte).ok())
                .ok_or(TransportError::SessionFenced)
        })
        .collect::<Result<Vec<_>, _>>()?;
    let byte_length =
        u64::try_from(runtime_bytes.len()).map_err(|_| TransportError::SessionFenced)?;
    if runtime_reference.get("byte_length").and_then(Value::as_u64) != Some(byte_length)
        || runtime_reference.get("sha256").and_then(Value::as_str)
            != Some(sha256_hex(&runtime_bytes).as_str())
    {
        return Err(TransportError::SessionFenced);
    }
    let runtime: Value =
        serde_json::from_slice(&runtime_bytes).map_err(|_| TransportError::SessionFenced)?;
    if canonical_json_bytes(&runtime).map_err(|_| TransportError::SessionFenced)? != runtime_bytes {
        return Err(TransportError::SessionFenced);
    }

    let job_id = submission
        .get("job_id")
        .and_then(Value::as_str)
        .ok_or(TransportError::SessionFenced)?;
    let durable_attempt_id = submission
        .get("attempt_id")
        .and_then(Value::as_str)
        .ok_or(TransportError::SessionFenced)?;
    let scope_id = submission
        .get("work_scope")
        .and_then(|scope| scope.get("scope_id"))
        .and_then(Value::as_str)
        .ok_or(TransportError::SessionFenced)?;
    let submission_fence = submission
        .get("work_scope")
        .and_then(|scope| scope.get("state_fence"))
        .ok_or(TransportError::SessionFenced)?;
    let request_identity = request
        .get("request_identity")
        .ok_or(TransportError::SessionFenced)?;
    let operation_fence = request_identity
        .get("operation")
        .and_then(|operation| operation.get("state_fence"))
        .ok_or(TransportError::SessionFenced)?;
    let request_context = request_identity
        .get("request")
        .and_then(|request| request.get("request"))
        .ok_or(TransportError::SessionFenced)?;
    let request_metadata = request_context
        .get("metadata")
        .ok_or(TransportError::SessionFenced)?;
    let request_task_id = request_metadata
        .get("task_id")
        .and_then(Value::as_str)
        .ok_or(TransportError::SessionFenced)?;
    let request_session_id = request_metadata
        .get("session_id")
        .and_then(Value::as_str)
        .ok_or(TransportError::SessionFenced)?;
    let request_metadata_fence = request_metadata
        .get("state_fence")
        .ok_or(TransportError::SessionFenced)?;
    let state_fence =
        serde_json::to_value(&attempt.state_fence).map_err(|_| TransportError::SessionFenced)?;
    let runtime_scope = runtime
        .get("work_scope")
        .and_then(|scope| scope.get("scope_id"))
        .and_then(Value::as_str);
    let runtime_fence = runtime.get("state_fence");
    if runtime
        .get("native_worker_claim_id")
        .and_then(Value::as_str)
        != Some(published_claim_id)
        || runtime.get("job_id").and_then(Value::as_str) != Some(job_id)
        || runtime.get("attempt_id").and_then(Value::as_str) != Some(durable_attempt_id)
        || runtime.get("task_id").and_then(Value::as_str) != Some(attempt.task_id.as_str())
        || runtime_scope != Some(scope_id)
        || runtime_scope != Some(attempt.scope_id.as_str())
        || runtime_fence != Some(&state_fence)
        || submission_fence != &state_fence
        || operation_fence != &state_fence
        || request_metadata_fence != &state_fence
        || request_task_id != attempt.task_id.as_str()
        || request_session_id != attempt.session_id
        || native.claim_id != published_claim_id
        || native.parent_job_id != job_id
        || native.attempt_id != durable_attempt_id
        || native.task_id != attempt.task_id.as_str()
        || native.work_scope_id != attempt.scope_id
        || native.state_fence != attempt.state_fence
        || !native
            .authority_epoch
            .is_same_authority(&attempt.authority_epoch)
    {
        return Err(TransportError::SessionFenced);
    }
    Ok(())
}
