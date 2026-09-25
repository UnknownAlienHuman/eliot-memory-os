//! Authenticated Kernel front-door client closure.
//!
//! Architecture: `docs/architecture/ELIOT_ARCHITECTURE.md` handles `A2.2`
//! and `A2.3`, plus Decision Anchors `ARCH-AUTH-01`, `ARCH-SEC-02`, and
//! `ARCH-RES-01`. Implementation:
//! `docs/architecture/ELIOT_IMPLEMENTATION.md` handles `I1.2`, `I1.4`, and
//! `I2.23`. Normative precedence remains in `docs/ARCHITECTURE_CONTRACT.md`.
//!
//! Host owns physical Kernel process lifecycle and authenticated connection
//! mechanics only. This module never owns Kernel or Governor semantic
//! readiness, transition, or authority; it preserves those decisions in the
//! existing Host composition root.

use std::path::Path;
use std::time::Duration;

use eliot_contracts::{
    ArtifactId, ContractId, ContractVersion, RequestMetadata, ResourceGeneration,
};
use eliot_ipc::{NamedPipeTransport, PeerIdentity};
use eliot_kernel_service::{
    HostKernelCandidateBinding, KernelActivationReceipt, KernelControlCommand,
    KernelControlRequest, KernelControlResponse, USER_AUTOMATION_KERNEL_CAPABILITY,
    USER_AUTOMATION_KERNEL_MODULE_ID, USER_AUTOMATION_KERNEL_OPERATION,
    USER_AUTOMATION_KERNEL_PRINCIPAL_BINDING, USER_AUTOMATION_KERNEL_PRIVACY_CLASS,
    UserAutomationHostOwnerBinding,
};
use eliot_platform::PlatformHandle;
use eliot_platform_windows::{ProcessIdentity, observe_named_pipe_peer_process_in_job};

#[cfg(windows)]
use eliot_contracts::{canonical_json_bytes, sha256_hex};
#[cfg(windows)]
use eliot_host_service::{HostDurableJobOwner, HostDurableJobOwnerError};
#[cfg(windows)]
use eliot_ipc::{DeliveryOutcome, TransportLimits, client_hello_frame, decode_server_hello_frame};
#[cfg(windows)]
use eliot_protocol::dreamer_job::{DurableJobRequest, DurableJobResponse};
#[cfg(windows)]
use eliot_protocol::{
    ClientHello, EncodingProfile, Frame, FrameKind, MessageType, ProtocolPayload, ProtocolVersion,
};
#[cfg(windows)]
use eliot_runtime_contracts::{
    HealthVector, ModuleContract, ModuleGeneration, ModuleGenerationState,
};

use super::{HostError, LOCAL_SERVICE_SID};

// F-LOG-HOST-3 (#978) Kernel front-door observation helpers.
//
// Through the #889 facade only
// (`super::host_diagnostics::observe_entrypoint_with_detail`); the Event Log
// seam stays typed-Unavailable
// (`super::windows_event_log::event_log_sink_status`), never implemented here
// (#984 still open). No terminal is owned here: the single terminal for a
// failed front-door/activation stays with the outermost #891 contour;
// handshake, auth, activation, before-start, timeout, disconnect, and unknown
// correlate by stage order only.
//
// Observation-only contract: every helper projects facts already produced by
// the semantic owner. Arguments are static literals only — never pipe
// identities, PIDs, start-times, image paths, SIDs, digests, message ids, or
// arbitrary error text — so bounding limits size, not sensitivity (I15.4).
// Sink outcome never alters result/order/status/cleanup. There is no mutable
// global dedup cache.
#[cfg(windows)]
fn kernel_front_door_note_event_log_unavailable() {
    let _ = super::windows_event_log::event_log_sink_status();
}

#[cfg(windows)]
fn kernel_front_door_observe(detail: &str) {
    kernel_front_door_note_event_log_unavailable();
    super::host_diagnostics::observe_entrypoint_with_detail(
        super::host_diagnostics::EntrypointStage::ScmDispatch,
        detail,
    );
}

#[cfg(windows)]
pub(super) fn kernel_control_request(
    candidate: &HostKernelCandidateBinding,
    generation: ResourceGeneration,
    command: KernelControlCommand,
    sequence: u64,
) -> Result<KernelControlRequest, HostError> {
    // WORK_UNIT_CASE: 978/7 — control request built; handshake/auth material
    // stays distinct from activation, no secrets observed.
    kernel_front_door_observe("host.kernel-front-door control requested");
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
    // WORK_UNIT_CASE: 978/9 — reconcile decision requested; transport loss
    // (timeout/disconnect/unknown) reconciles as None without inventing
    // evidence, distinct from a before-start rejection below.
    kernel_front_door_observe("host.kernel-front-door reconcile requested");
    let Ok(response) = response else {
        // WORK_UNIT_CASE: 978/9 — disconnect/unknown observed as reconcile;
        // no invented receipt, exact None propagates.
        kernel_front_door_observe("host.kernel-front-door disconnect observed");
        return Ok(None);
    };
    if response.message_id != *expected_message_id
        || response.request_digest != expected_request_digest
    {
        // WORK_UNIT_CASE: 978/9 — unknown binding observed as reconcile;
        // mismatched identity never promotes into activation.
        kernel_front_door_observe("host.kernel-front-door unknown observed");
        return Ok(None);
    }
    if let Some(error) = response.error {
        // WORK_UNIT_CASE: 978/9 — before-start rejection observed; exact
        // rejection propagates, no secrets observed.
        kernel_front_door_observe("host.kernel-front-door before-start observed");
        return Err(HostError::ProcessContour(format!(
            "Kernel rejected Activate: {error}"
        )));
    }
    // WORK_UNIT_CASE: 978/9 — timeout observed as reconcile when no receipt
    // is carried; a carried receipt is activation evidence, not a timeout.
    if response.activation_receipt.is_none() {
        kernel_front_door_observe("host.kernel-front-door timeout observed");
    } else {
        kernel_front_door_observe("host.kernel-front-door activation observed");
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
    // WORK_UNIT_CASE: 978/7 — auth requested; peer authentication stays
    // distinct from nonce/handshake/activation, no secrets observed.
    kernel_front_door_observe("host.kernel-front-door auth requested");
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
    // WORK_UNIT_CASE: 978/7 — authenticated peer observed; start-identity
    // (PID + start-time + image) matched, distinct from activation.
    kernel_front_door_observe("host.kernel-front-door authenticated peer observed");
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
    // WORK_UNIT_CASE: 978/7 — handshake requested; authenticated connect is
    // distinct from nonce issuance and activation, no secrets observed.
    kernel_front_door_observe("host.kernel-front-door handshake requested");
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
        (None, None) => {
            // WORK_UNIT_CASE: 978/7 — handshake observed; exact transport
            // propagates unchanged.
            kernel_front_door_observe("host.kernel-front-door handshake observed");
            Ok(transport)
        }
        (Some(observed), Some(expected)) if observed == expected => {
            // WORK_UNIT_CASE: 978/7 — handshake observed; exact transport
            // propagates unchanged.
            kernel_front_door_observe("host.kernel-front-door handshake observed");
            Ok(transport)
        }
        _ => Err(HostError::ProcessContour(
            "Kernel front-door extra SID does not match the retained bridge policy".to_owned(),
        )),
    }
}

/// Host-side Durable Job owner joined to the live Kernel front door.
///
/// The owner retains only the Host-approved candidate, the Kernel-authored
/// activation receipt, and the OS-observed Kernel process. Each operation
/// opens the existing authenticated front door, proves the generation-bound
/// Host session, and sends one typed Dreamer request. It never opens Store,
/// derives a job, or retries an uncertain mutation.
///
/// Task Scheduler may wake Host only from the admitted intent; the `WakeIntent`
/// itself grants no task, route, tool, effect or delivery authority.
#[cfg(windows)]
pub(super) struct HostKernelUserAutomationOwner {
    candidate: HostKernelCandidateBinding,
    activation: KernelActivationReceipt,
    kernel_process: ProcessIdentity,
    activation_digest: String,
}

#[cfg(windows)]
impl HostKernelUserAutomationOwner {
    pub(super) fn new(
        candidate: HostKernelCandidateBinding,
        activation: KernelActivationReceipt,
        kernel_process: ProcessIdentity,
    ) -> Result<Self, HostError> {
        candidate
            .validate()
            .map_err(|error| HostError::ProcessContour(error.to_string()))?;
        let candidate_digest = candidate
            .compute_digest()
            .map_err(|error| HostError::ProcessContour(error.to_string()))?;
        if activation.candidate_binding_digest != candidate_digest
            || activation.authority_epoch != candidate.kernel_epoch
            || activation.generation.value() == 0
            || kernel_process.process_id != candidate.job_binding.root.process.process_id
            || kernel_process.start_time_100ns
                != candidate.job_binding.root.process.start_time_100ns
            || !kernel_process
                .image_path
                .eq_ignore_ascii_case(&candidate.job_binding.root.process.image_path)
        {
            return Err(HostError::ProcessContour(
                "Kernel UserAutomation owner is not bound to the retained active contour"
                    .to_owned(),
            ));
        }
        let activation_digest = sha256_hex(
            &canonical_json_bytes(&activation)
                .map_err(|error| HostError::ProcessContour(error.to_string()))?,
        );
        Ok(Self {
            candidate,
            activation,
            kernel_process,
            activation_digest,
        })
    }

    pub(super) fn owner_binding(&self) -> Result<UserAutomationHostOwnerBinding, HostError> {
        let candidate_binding_sha256 = self
            .candidate
            .compute_digest()
            .map_err(|error| HostError::ProcessContour(error.to_string()))?;
        let state_fence = eliot_contracts::StateFence::new(
            self.candidate.kernel_epoch.clone(),
            self.activation.generation,
        );
        let binding = UserAutomationHostOwnerBinding {
            candidate_binding_sha256,
            activation_receipt_sha256: self.activation_digest.clone(),
            state_fence,
            expected_peer_process_id: self.kernel_process.process_id,
            expected_peer_start_time_100ns: self.kernel_process.start_time_100ns,
            expected_peer_image_path: self.kernel_process.image_path.clone(),
        };
        binding
            .validate()
            .map_err(|error| HostError::ProcessContour(error.to_string()))?;
        Ok(binding)
    }

    fn client_hello(&self) -> Result<ClientHello, HostDurableJobOwnerError> {
        let module_id = ContractId::new(USER_AUTOMATION_KERNEL_MODULE_ID)
            .map_err(|error| owner_unavailable(error.to_string()))?;
        let artifact_id = ArtifactId::new(self.candidate.artifact_hash.as_str())
            .map_err(|error| owner_unavailable(error.to_string()))?;
        let state_fence = eliot_contracts::StateFence::new(
            self.candidate.kernel_epoch.clone(),
            self.activation.generation,
        );
        let module_contract = ModuleContract {
            module_id: module_id.clone(),
            version: ContractVersion::new(1, 0, 0),
            artifact_id: artifact_id.clone(),
            protocols: vec![
                "eliot.s03.ebp.v1".to_owned(),
                "eliot.kernel.dreamer-job.v1".to_owned(),
            ],
            required_capabilities: vec![USER_AUTOMATION_KERNEL_CAPABILITY.to_owned()],
            optional_capabilities: Vec::new(),
            advisory_capabilities: Vec::new(),
            state_owner: "eliot-host".to_owned(),
            failure_domain: "eliot-host-user-automation".to_owned(),
            hot_replace: false,
        };
        Ok(ClientHello {
            protocol_range: eliot_protocol::ProtocolRange {
                minimum: ProtocolVersion::CURRENT,
                maximum: ProtocolVersion::CURRENT,
            },
            module_bridge_identity: USER_AUTOMATION_KERNEL_MODULE_ID.to_owned(),
            artifact_hash: artifact_id.clone(),
            module_contract,
            module_generation: ModuleGeneration {
                module_id,
                generation: self.activation.generation,
                artifact_id,
                state: ModuleGenerationState::Active,
                health: HealthVector::healthy(),
                state_fence,
            },
            launch_nonce: self.activation_digest.clone(),
            capabilities: vec![USER_AUTOMATION_KERNEL_CAPABILITY.to_owned()],
            privacy_classes: vec![USER_AUTOMATION_KERNEL_PRIVACY_CLASS.to_owned()],
            max_frame: u32::try_from(eliot_protocol::MAX_FRAME_BYTES)
                .map_err(|error| owner_unavailable(error.to_string()))?,
            authority_epoch: self.candidate.kernel_epoch.clone(),
        })
    }

    #[allow(clippy::too_many_lines)]
    async fn execute_dreamer_job(
        &self,
        context: &RequestMetadata,
        request: DurableJobRequest,
    ) -> Result<DurableJobResponse, HostDurableJobOwnerError> {
        request
            .validate()
            .map_err(|error| HostDurableJobOwnerError::Rejected(error.to_string()))?;
        let request_id = request
            .request_identity
            .request
            .request
            .metadata
            .request_id
            .clone();
        let connection_id = format!(
            "host-user-automation:{}:{}",
            self.activation.operation_id.as_str(),
            request_id.as_str()
        );
        let mut transport =
            connect_authenticated_kernel_front_door(&self.candidate, &self.kernel_process)
                .await
                .map_err(|error| owner_unavailable(error.to_string()))?;
        validate_authenticated_kernel_peer(
            transport.peer_identity(),
            self.kernel_process.process_id,
            self.kernel_process.start_time_100ns,
            Path::new(self.kernel_process.image_path.as_str()),
        )
        .map_err(|error| owner_unavailable(error.to_string()))?;
        let limits = TransportLimits::default();
        let hello = self.client_hello()?;
        let hello_frame = client_hello_frame(&connection_id, &hello)
            .map_err(|error| owner_unavailable(error.to_string()))?;
        match transport
            .send_frame(&hello_frame, limits)
            .await
            .map_err(|error| owner_unavailable(error.to_string()))?
        {
            DeliveryOutcome::Delivered => {}
            DeliveryOutcome::UnknownOutcome => {
                return Err(owner_unknown(
                    "Kernel Host UserAutomation handshake delivery is unknown",
                ));
            }
        }
        let server_frame = transport
            .receive_frame(limits)
            .await
            .map_err(|error| owner_unavailable(error.to_string()))?;
        let server = decode_server_hello_frame(&server_frame, &connection_id)
            .map_err(|error| owner_unavailable(error.to_string()))?;
        let projection = server
            .config_snapshot
            .get("eliot.user_automation")
            .and_then(serde_json::Value::as_object)
            .ok_or_else(|| {
                owner_unavailable("Kernel UserAutomation server projection is missing")
            })?;
        let projected_privacy = projection
            .get("privacy_classes")
            .and_then(serde_json::Value::as_array)
            .ok_or_else(|| {
                owner_unavailable("Kernel UserAutomation privacy projection is missing")
            })?;
        let projected_capability = projection
            .get("capability")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| {
                owner_unavailable("Kernel UserAutomation capability projection is missing")
            })?;
        let projected_effects = projection
            .get("effects")
            .and_then(serde_json::Value::as_array)
            .ok_or_else(|| {
                owner_unavailable("Kernel UserAutomation effects projection is missing")
            })?;
        let projected_candidate = projection
            .get("candidate_binding_sha256")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| {
                owner_unavailable("Kernel UserAutomation candidate projection is missing")
            })?;
        let projected_activation = projection
            .get("activation_receipt_sha256")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| {
                owner_unavailable("Kernel UserAutomation activation projection is missing")
            })?;
        let projected_connection = projection
            .get("connection_id")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| {
                owner_unavailable("Kernel UserAutomation connection projection is missing")
            })?;
        let candidate_digest = self
            .candidate
            .compute_digest()
            .map_err(|error| owner_unavailable(error.to_string()))?;
        let projected_privacy_exact = projected_privacy.len() == 1
            && projected_privacy[0].as_str() == Some(USER_AUTOMATION_KERNEL_PRIVACY_CLASS);
        let projected_effects_empty = projected_effects.is_empty();
        if server.authority_epoch != self.candidate.kernel_epoch
            || server.session_principal_binding != USER_AUTOMATION_KERNEL_PRINCIPAL_BINDING
            || server.allowed_capabilities.len() != 1
            || server.allowed_capabilities[0] != USER_AUTOMATION_KERNEL_CAPABILITY
            || !server.allowed_effects.is_empty()
            || projected_capability != USER_AUTOMATION_KERNEL_CAPABILITY
            || !projected_privacy_exact
            || !projected_effects_empty
            || projected_candidate != candidate_digest
            || projected_activation != self.activation_digest
            || projected_connection != connection_id
        {
            return Err(owner_unavailable(
                "Kernel Host UserAutomation session binding is not exact",
            ));
        }

        let frame = Frame {
            protocol_version: server.selected_protocol,
            encoding_profile: EncodingProfile::JsonV1,
            connection_id: connection_id.clone(),
            request_id: Some(request_id.clone()),
            kind: FrameKind::Request,
            message_type: MessageType::Execute,
            request_identity: Some(request.request_identity.request.clone()),
            payload: ProtocolPayload::Json(serde_json::json!({
                "operation": USER_AUTOMATION_KERNEL_OPERATION,
                "context": context,
                "request": request,
            })),
            trace_context: std::collections::BTreeMap::new(),
        };
        frame
            .validate()
            .map_err(|error| HostDurableJobOwnerError::Rejected(error.to_string()))?;
        match transport
            .send_frame(&frame, limits)
            .await
            .map_err(|error| owner_unknown(error.to_string()))?
        {
            DeliveryOutcome::Delivered => {}
            DeliveryOutcome::UnknownOutcome => {
                return Err(owner_unknown(
                    "Kernel Durable Job delivery crossed an unknown boundary",
                ));
            }
        }
        let response_frame = transport
            .receive_frame(limits)
            .await
            .map_err(|error| owner_unknown(error.to_string()))?;
        if response_frame.connection_id != connection_id
            || response_frame.kind != FrameKind::Response
            || response_frame.message_type != MessageType::Result
            || response_frame.request_id.as_ref() != Some(&request_id)
        {
            return Err(owner_unknown(
                "Kernel Durable Job response correlation is not exact",
            ));
        }
        let ProtocolPayload::Json(payload) = response_frame.payload else {
            return Err(owner_unknown(
                "Kernel Durable Job response payload is invalid",
            ));
        };
        if payload.get("status").and_then(serde_json::Value::as_str) == Some("error") {
            let reason = payload
                .get("error")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("Kernel Durable Job rejected the request")
                .to_owned();
            return Err(classify_kernel_owner_error(reason));
        }
        let response: DurableJobResponse =
            serde_json::from_value(payload).map_err(|error| owner_unknown(error.to_string()))?;
        response
            .validate_for(&request)
            .map_err(|error| HostDurableJobOwnerError::Rejected(error.to_string()))?;
        Ok(response)
    }
}

#[cfg(windows)]
impl HostDurableJobOwner for HostKernelUserAutomationOwner {
    async fn dreamer_job(
        &self,
        context: &RequestMetadata,
        request: DurableJobRequest,
    ) -> Result<DurableJobResponse, eliot_host_service::HostDurableJobOwnerError> {
        self.execute_dreamer_job(context, request).await
    }
}

#[cfg(windows)]
fn owner_unavailable(reason: impl Into<String>) -> HostDurableJobOwnerError {
    HostDurableJobOwnerError::Unavailable(reason.into())
}

#[cfg(windows)]
fn owner_unknown(reason: impl Into<String>) -> HostDurableJobOwnerError {
    HostDurableJobOwnerError::UnknownOutcome(reason.into())
}

#[cfg(windows)]
fn classify_kernel_owner_error(reason: String) -> HostDurableJobOwnerError {
    let folded = reason.to_ascii_lowercase();
    if folded.contains("unknown")
        || folded.contains("outcome")
        || folded.contains("timeout")
        || folded.contains("timed out")
        || folded.contains("fenced")
    {
        owner_unknown(reason)
    } else if folded.contains("unavailable") || folded.contains("not ready") {
        owner_unavailable(reason)
    } else {
        HostDurableJobOwnerError::Rejected(reason)
    }
}
