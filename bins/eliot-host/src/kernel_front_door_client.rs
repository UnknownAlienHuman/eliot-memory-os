//! Authenticated Kernel front-door client closure.
//!
//! Architecture anchors (eliot-architecture-docs-fa941135):
//! `eliot-architecture-docs-fa941135.ELIOT_ARCHITECTURE.A2.2`,
//! `eliot-architecture-docs-fa941135.ELIOT_ARCHITECTURE.A2.3`,
//! `eliot-architecture-docs-fa941135.ELIOT_ARCHITECTURE.ARCH-AUTH-01`,
//! `eliot-architecture-docs-fa941135.ELIOT_ARCHITECTURE.ARCH-SEC-02`, and
//! `eliot-architecture-docs-fa941135.ELIOT_ARCHITECTURE.ARCH-RES-01`.
//! Implementation anchors (eliot-architecture-docs-fa941135):
//! `eliot-architecture-docs-fa941135.ELIOT_IMPLEMENTATION.I1.2`,
//! `eliot-architecture-docs-fa941135.ELIOT_IMPLEMENTATION.I1.4`,
//! `eliot-architecture-docs-fa941135.ELIOT_IMPLEMENTATION.I2.2`, and
//! `eliot-architecture-docs-fa941135.ELIOT_IMPLEMENTATION.I2.23`.
//!
//! Host owns physical Kernel process lifecycle and authenticated connection
//! mechanics only. This module never owns Kernel or Governor semantic
//! readiness, transition, or authority; it preserves those decisions in the
//! existing Host composition root.

use std::path::Path;
use std::time::Duration;

use eliot_contracts::ResourceGeneration;
use eliot_ipc::{NamedPipeTransport, PeerIdentity};
use eliot_kernel_service::{
    HostKernelCandidateBinding, KernelActivationReceipt, KernelControlCommand,
    KernelControlRequest, KernelControlResponse,
};
use eliot_platform::PlatformHandle;
use eliot_platform_windows::{ProcessIdentity, observe_named_pipe_peer_process_in_job};

use super::{HostError, LOCAL_SERVICE_SID};

#[cfg(windows)]
pub(super) fn kernel_control_request(
    candidate: &HostKernelCandidateBinding,
    generation: ResourceGeneration,
    command: KernelControlCommand,
    sequence: u64,
) -> Result<KernelControlRequest, HostError> {
    KernelControlRequest {
        wire_id: eliot_kernel_service::KERNEL_CONTROL_WIRE_ID.to_owned(),
        wire_version: eliot_kernel_service::KERNEL_CONTROL_WIRE_VERSION,
        message_id: PlatformHandle::new(format!("{}:{sequence}", candidate.activation_id.as_str()))
            .map_err(|error| HostError::ProcessContour(error.to_string()))?,
        sequence,
        peer_process_id: std::process::id(),
        generation,
        candidate: candidate.clone(),
        command,
        payload_digest: String::new(),
    }
    .with_computed_digest()
    .map_err(|error| HostError::ProcessContour(error.to_string()))
}

#[cfg(windows)]
pub(super) fn activation_response_or_reconcile(
    response: Result<KernelControlResponse, HostError>,
    expected_message_id: &PlatformHandle,
    expected_request_digest: &str,
) -> Result<Option<KernelActivationReceipt>, HostError> {
    let Ok(response) = response else {
        return Ok(None);
    };
    if response.message_id != *expected_message_id
        || response.request_digest != expected_request_digest
    {
        return Ok(None);
    }
    if let Some(error) = response.error {
        return Err(HostError::ProcessContour(format!(
            "Kernel rejected Activate: {error}"
        )));
    }
    Ok(response.activation_receipt)
}

#[cfg(windows)]
pub(super) fn validate_authenticated_kernel_peer(
    peer: &PeerIdentity,
    expected_pid: u32,
    expected_start_time_100ns: u64,
    expected_image: &Path,
) -> Result<(), HostError> {
    let peer = peer.process_binding().ok_or_else(|| {
        HostError::ProcessContour("Kernel peer identity is unavailable".to_owned())
    })?;
    let observed_image = std::fs::canonicalize(peer.image_path())
        .map_err(|error| HostError::ProcessContour(error.to_string()))?;
    let approved_image = std::fs::canonicalize(expected_image)
        .map_err(|error| HostError::ProcessContour(error.to_string()))?;
    if peer.process_id() != expected_pid
        || peer.start_time_100ns() != expected_start_time_100ns
        || observed_image != approved_image
    {
        return Err(HostError::ProcessContour(
            "authenticated Kernel peer is not the retained approved process".to_owned(),
        ));
    }
    Ok(())
}

#[cfg(windows)]
fn kernel_front_door_expectation(
    candidate: &HostKernelCandidateBinding,
    kernel_process: &ProcessIdentity,
) -> Result<eliot_platform_windows::KernelFrontDoorServerExpectation, HostError> {
    let binding = observe_named_pipe_peer_process_in_job(
        candidate.job_object_id.as_str(),
        kernel_process.process_id,
    )
    .map_err(|error| HostError::ProcessContour(error.to_string()))?;
    let observed = binding.process_binding().identity();
    if observed != kernel_process {
        return Err(HostError::ProcessContour(
            "Kernel Job observation is not the retained process identity".to_owned(),
        ));
    }
    if binding
        .process_binding()
        .executable_file_identity()
        .is_none()
    {
        return Err(HostError::ProcessContour(
            "Kernel process executable FileIdentity is unavailable".to_owned(),
        ));
    }
    let expected_extra_sid = candidate
        .agent_bridge_admission
        .as_ref()
        .map(|descriptor| descriptor.approved_user_sid.clone());
    let acl_mode = kernel_front_door_acl_mode(expected_extra_sid.as_deref());
    eliot_platform_windows::KernelFrontDoorServerExpectation::new(
        LOCAL_SERVICE_SID,
        0,
        candidate.artifact_hash.as_str(),
        acl_mode,
    )
    .map(|expectation| expectation.with_process_and_job_binding(binding))
    .map_err(|error| HostError::ProcessContour(error.to_string()))
}

#[cfg(windows)]
pub(super) fn kernel_front_door_acl_mode(
    approved_user_sid: Option<&str>,
) -> eliot_platform_windows::KernelFrontDoorAclMode {
    match approved_user_sid {
        None => eliot_platform_windows::KernelFrontDoorAclMode::ServiceOnly,
        Some(client_sid) => {
            eliot_platform_windows::KernelFrontDoorAclMode::SystemAndLocalServiceWithClient {
                client_sid: client_sid.to_owned(),
            }
        }
    }
}

#[cfg(windows)]
pub(super) async fn connect_authenticated_kernel_front_door(
    candidate: &HostKernelCandidateBinding,
    kernel_process: &ProcessIdentity,
) -> Result<NamedPipeTransport, HostError> {
    let expected_extra_sid = candidate
        .agent_bridge_admission
        .as_ref()
        .map(|descriptor| descriptor.approved_user_sid.as_str());
    let expectation = kernel_front_door_expectation(candidate, kernel_process)?;
    let transport = NamedPipeTransport::connect_authenticated_kernel_front_door(
        candidate.pipe_identity.as_str(),
        Duration::from_secs(5),
        &expectation,
    )
    .await
    .map_err(|error| HostError::ProcessContour(error.to_string()))?;
    match (
        transport.kernel_front_door_observed_extra_sid(),
        expected_extra_sid,
    ) {
        (None, None) => Ok(transport),
        (Some(observed), Some(expected)) if observed == expected => Ok(transport),
        _ => Err(HostError::ProcessContour(
            "Kernel front-door extra SID does not match the retained bridge policy".to_owned(),
        )),
    }
}
