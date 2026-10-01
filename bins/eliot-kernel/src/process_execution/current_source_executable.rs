//! Authenticated, read-only native observation of the current admitted LSP
//! executable. This returns owner data; it does not issue a process permit.

use std::path::PathBuf;

use eliot_ipc::Session;
use eliot_ors::{HostRequestKind, HostRequestState, OperationIdentity};
use eliot_process::ProcessIntent;
use eliot_protocol::{RequestIdentity, SelectedSourceCaptureInvocation};
use serde::{Deserialize, Serialize};

use crate::{KernelComposition, TransportError};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CurrentSourceExecutableObservationRequest {
    host_request_operation_id: OperationIdentity,
    host_request_digest: String,
    work_scope_id: String,
    work_scope_root_locator: String,
    executable_locator: String,
    admitted_content_sha256: String,
    admitted_instrument: String,
    child_identity: RequestIdentity,
    process_intent: ProcessIntent,
}

#[derive(Serialize)]
struct CurrentSourceExecutableObservation {
    request_identity: RequestIdentity,
    instrument: String,
    canonical_path: String,
    content_digest: String,
    tool_version: Option<String>,
    environment_digest: String,
    arguments: Vec<String>,
    native_file_identity: eliot_platform_windows::FileIdentity,
}

pub(crate) const OPERATION: &str = "current_source_executable.observe";

impl KernelComposition {
    /// Observes the exact executable named by a Governor-recovered admitted
    /// profile while the original WorkScope HostRequest remains current.
    ///
    /// `executable_locator` and `admitted_content_sha256` are selectors only.
    /// Until an original toolchain-root owner is available, the Kernel uses
    /// its own retained work root as the only permitted executable root; it
    /// never accepts a caller-supplied executable-root authority. The
    /// platform holds the no-follow path lease while hashing the file and
    /// returns the native file identity with the machine-derived bytes. The
    /// caller must still compare that data with the exact current profile and
    /// provider owners before it can be used as admission evidence.
    pub(crate) fn observe_current_source_executable_operation(
        &self,
        session: &Session,
        payload: serde_json::Value,
        parent_identity: Option<&RequestIdentity>,
    ) -> Result<serde_json::Value, TransportError> {
        let parent_identity = parent_identity.ok_or(TransportError::SessionFenced)?;
        parent_identity
            .validate()
            .map_err(|_| TransportError::SessionFenced)?;
        let _ = super::super::caller_binding(session)?;
        if !parent_identity
            .request
            .state_fence
            .authority_epoch
            .is_same_authority(&session.authority_epoch)
            || parent_identity
                .request
                .state_fence
                .resource_generation
                .value()
                != session.module_generation.generation.value()
            || parent_identity.request.metadata.state_fence
                != parent_identity.request.state_fence
        {
            return Err(TransportError::SessionFenced);
        }

        let mut payload = payload;
        let object = payload
            .as_object_mut()
            .ok_or(TransportError::SessionFenced)?;
        if object
            .remove("operation")
            .and_then(|value| value.as_str().map(str::to_owned))
            .as_deref()
            != Some(OPERATION)
        {
            return Err(TransportError::SessionFenced);
        }
        let request: CurrentSourceExecutableObservationRequest =
            serde_json::from_value(payload).map_err(|_| TransportError::SessionFenced)?;
        if !is_sha256(&request.host_request_digest)
            || !is_sha256(&request.admitted_content_sha256)
            || request.work_scope_id.trim().is_empty()
            || request.work_scope_id.chars().any(char::is_control)
            || request.work_scope_root_locator.trim().is_empty()
            || request.work_scope_root_locator.chars().any(char::is_control)
            || request.admitted_instrument.trim().is_empty()
            || request.admitted_instrument.chars().any(char::is_control)
        {
            return Err(TransportError::SessionFenced);
        }

        let host_request = self
            .generation_gateway
            .ors
            .load_host_request(
                &request.host_request_operation_id,
                &request.host_request_digest,
            )
            .map_err(|_| TransportError::SessionFenced)?
            .ok_or(TransportError::UnknownRequest)?;
        if host_request.kind != HostRequestKind::SelectedSourceCapture
            || host_request.state != HostRequestState::Admitted
            || host_request.request_digest != request.host_request_digest
            || host_request.capability_ref.as_str()
                != eliot_protocol::SELECTED_SOURCE_CAPTURE_CAPABILITY
            || host_request.request_id.as_str()
                != parent_identity.request.metadata.request_id.as_str()
            || host_request.idempotency_key.as_str() != parent_identity.idempotency_key
            || host_request.cancellation_id.as_str() != parent_identity.cancellation_id
            || host_request.session_ref.as_ref().map(|value| value.as_str())
                != parent_identity
                    .request
                    .metadata
                    .session_id
                    .as_ref()
                    .map(|value| value.as_str())
            || host_request.task_ref.as_ref().map(|value| value.as_str())
                != parent_identity
                    .request
                    .metadata
                    .task_id
                    .as_ref()
                    .map(|value| value.as_str())
            || host_request.scope_ref.as_ref().map(|value| value.as_str())
                != Some(request.work_scope_id.as_str())
            || host_request.deadline_unix_ms != parent_identity.deadline_unix_ms
            || host_request.authority_epoch
                != parent_identity.request.state_fence.authority_epoch
            || host_request.fence_digest
                != crate::sha256_json(&parent_identity.request.state_fence)
                    .map_err(|_| TransportError::SessionFenced)?
        {
            return Err(TransportError::IdentityConflict);
        }
        let invocation: SelectedSourceCaptureInvocation = serde_json::from_value(
            host_request
                .payload_body
                .clone()
                .ok_or(TransportError::SessionFenced)?,
        )
        .map_err(|_| TransportError::SessionFenced)?;
        invocation
            .validate()
            .map_err(|_| TransportError::SessionFenced)?;
        let expected_instrument = match invocation.operation {
            eliot_protocol::SelectedSourceCaptureOperation::Diagnostics => {
                "eliot.instrument.rust-analyzer.diagnostics"
            }
            eliot_protocol::SelectedSourceCaptureOperation::ProbeVersion => {
                "eliot.instrument.rust-analyzer.version"
            }
        };
        if request.admitted_instrument != expected_instrument {
            return Err(TransportError::IdentityConflict);
        }

        let task_id = parent_identity
            .request
            .metadata
            .task_id
            .as_ref()
            .ok_or(TransportError::SessionFenced)?;
        let child_identity = &request.child_identity;
        child_identity
            .validate()
            .map_err(|_| TransportError::SessionFenced)?;
        if child_identity.request.metadata.request_id
            == parent_identity.request.metadata.request_id
            || child_identity.request.metadata.task_id.as_ref() != Some(task_id)
            || child_identity.request.metadata.session_id
                != parent_identity.request.metadata.session_id
            || child_identity.request.metadata.product_id
                != parent_identity.request.metadata.product_id
            || child_identity.request.metadata.source_id
                != parent_identity.request.metadata.source_id
            || child_identity.deadline_unix_ms != parent_identity.deadline_unix_ms
            || child_identity.request.state_fence != parent_identity.request.state_fence
            || child_identity.request.metadata.state_fence
                != parent_identity.request.state_fence
            || request.process_intent.operation_id().as_str()
                != child_identity.request.metadata.request_id.as_str()
            || request.process_intent.executable() != request.executable_locator
            || request.process_intent.executable_sha256()
                != request.admitted_content_sha256
            || request.process_intent.generation().get()
                != parent_identity.request.state_fence.resource_generation.value()
        {
            return Err(TransportError::IdentityConflict);
        }
        request
            .process_intent
            .validate()
            .map_err(|_| TransportError::IdentityConflict)?;

        let work_root = std::fs::canonicalize(&self.work_root)
            .map_err(|_| TransportError::SessionFenced)?;
        let selected_root = std::fs::canonicalize(&request.work_scope_root_locator)
            .map_err(|_| TransportError::SessionFenced)?;
        if selected_root != work_root {
            return Err(TransportError::IdentityConflict);
        }
        let executable = PathBuf::from(&request.executable_locator);
        if !executable.is_absolute() {
            return Err(TransportError::SessionFenced);
        }
        let canonical_executable = std::fs::canonicalize(&executable)
            .map_err(|_| TransportError::SessionFenced)?;
        if !executable_observation_is_confined(
            &work_root,
            &canonical_executable,
            &request.executable_locator,
            request.process_intent.working_directory(),
        ) {
            return Err(TransportError::SessionFenced);
        }
        let lease = self
            .platform
            .retain_process_path_lease(
                &canonical_executable,
                &work_root,
                &request.admitted_content_sha256,
            )
            .map_err(|_| TransportError::SessionFenced)?;
        let observation = eliot_process_executor::ExecutableObservation::observe_from_intent(
            &request.process_intent,
            None,
        )
        .map_err(|_| TransportError::IdentityConflict)?;
        lease
            .validate(
                &canonical_executable,
                &work_root,
                &request.admitted_content_sha256,
            )
            .map_err(|_| TransportError::IdentityConflict)?;
        let result = CurrentSourceExecutableObservation {
            request_identity: child_identity.clone(),
            instrument: request.admitted_instrument,
            canonical_path: observation.canonical_path,
            content_digest: observation.content_digest,
            tool_version: observation.tool_version,
            environment_digest: observation.environment_digest,
            arguments: observation.arguments,
            native_file_identity: lease.executable_identity(),
        };
        Ok(serde_json::json!({
            "status": "known",
            "value": result,
            "recovery": null,
        }))
    }
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn executable_observation_is_confined(
    work_root: &std::path::Path,
    canonical_executable: &std::path::Path,
    requested_locator: &str,
    working_directory: &str,
) -> bool {
    canonical_executable.starts_with(work_root)
        && canonical_executable.to_string_lossy() == requested_locator
        && working_directory == work_root.to_string_lossy()
}

#[cfg(test)]
mod tests {
    use super::executable_observation_is_confined;
    use std::path::Path;

    #[test]
    fn current_source_executable_observation_uses_kernel_owned_root() {
        let root = Path::new(r"C:\eliot\work");
        let executable = Path::new(r"C:\eliot\work\tools\rust-analyzer.exe");
        assert!(executable_observation_is_confined(
            root,
            executable,
            r"C:\eliot\work\tools\rust-analyzer.exe",
            r"C:\eliot\work",
        ));
    }

    #[test]
    fn current_source_executable_observation_refuses_external_toolchain_root() {
        let root = Path::new(r"C:\eliot\work");
        let executable = Path::new(r"C:\Users\agent\.cargo\bin\rust-analyzer.exe");
        assert!(!executable_observation_is_confined(
            root,
            executable,
            r"C:\Users\agent\.cargo\bin\rust-analyzer.exe",
            r"C:\eliot\work",
        ));
    }
}
