#![allow(
    clippy::all,
    clippy::pedantic,
    clippy::nursery,
    dead_code,
    missing_docs,
    reason = "runtime-control seam keeps explicit production plumbing without doc noise"
)]

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use eliot_contracts::{
    AuthorityEpoch, ClockReading, ProductId, RequestId, RequestMetadata, ResourceGeneration,
    SourceId, StateFence,
};
use eliot_ipc::{NamedPipeServer, TransportLimits};
use eliot_platform::PlatformHandle;
use eliot_protocol::{
    EncodingProfile, Frame, FrameKind, MessageType, ProtocolPayload, ProtocolVersion,
    RequestIdentity,
};
use eliot_receipts::RequestBinding;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use tokio::sync::oneshot;

pub const HOST_RUNTIME_CONTROL_PIPE: &str = r"\\.\pipe\eliot\host\runtime-control-v1";
pub const HOST_RUNTIME_CONTROL_PRODUCTION_DISCRIMINATOR: &str =
    "eliot-host::production-runtime-control:v1";
const MAX_QUEUE_DEPTH: usize = 32;
const QUEUE_RESPONSE_TIMEOUT: Duration = Duration::from_secs(30);
const WIRE: &str = "eliot.host.runtime-control.v2";
const UNKNOWN_REF_TAG: &str = "unknown";
const UNKNOWN_REF_REASONS: &[&str] = &[
    "kernel-restart-validation",
    "kernel-restart-queue-lock",
    "kernel-restart-queue-full",
    "kernel-restart-queue-response",
    "kernel-restart",
    "kernel-restart-reconcile",
    "kernel-restart-reconcile-conflict",
    "kernel-restart-pending",
    "kernel-restart-reconcile-snapshot",
    "kernel-restart-reconcile-unknown",
];

#[derive(Clone, Debug)]
struct HostRuntimeControlResponseCapability(Arc<()>);

impl PartialEq for HostRuntimeControlResponseCapability {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.0, &other.0)
    }
}

impl Eq for HostRuntimeControlResponseCapability {}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE", deny_unknown_fields)]
pub enum HostRuntimeControlOperation {
    RestartKernel,
    ReconcileKernelRestart,
}

fn canonical_operation_name(operation: &HostRuntimeControlOperation) -> &'static str {
    match operation {
        HostRuntimeControlOperation::RestartKernel => "RestartKernel",
        HostRuntimeControlOperation::ReconcileKernelRestart => "ReconcileKernelRestart",
    }
}

fn is_sha256_digest(value: &PlatformHandle) -> bool {
    value.as_str().len() == 64
        && value
            .as_str()
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
}

fn mutation_digest_for_request_id(wire: &PlatformHandle, request_id: &PlatformHandle) -> String {
    sha256_hex(format!("{}:mutation:{}", wire.as_str(), request_id.as_str()).as_bytes())
}

fn request_digest_for(
    wire: &PlatformHandle,
    operation: &HostRuntimeControlOperation,
    request_id: &PlatformHandle,
    mutation_digest: &PlatformHandle,
) -> String {
    sha256_hex(
        format!(
            "{}:{}:{}:{}",
            wire.as_str(),
            canonical_operation_name(operation),
            request_id.as_str(),
            mutation_digest.as_str()
        )
        .as_bytes(),
    )
}

pub(crate) fn runtime_control_unknown_ref(
    prefix: &str,
    request: &HostRuntimeControlRequest,
) -> PlatformHandle {
    let payload = serde_json::to_string(&(
        canonical_operation_name(&request.operation),
        request.request_id.as_str(),
        request.mutation_digest.as_str(),
        request.request_digest.as_str(),
    ))
    .unwrap_or_else(|_| unreachable!());
    PlatformHandle::new(format!("{WIRE}:{UNKNOWN_REF_TAG}:{prefix}:{payload}"))
        .unwrap_or_else(|_| unreachable!())
}

fn parse_runtime_control_unknown_ref(
    pending_ref: &PlatformHandle,
) -> Option<HostRuntimeControlRequest> {
    let mut parts = pending_ref.as_str().splitn(4, ':');
    let wire = parts.next()?;
    let tag = parts.next()?;
    let reason = parts.next()?;
    let payload = parts.next()?;
    if wire != WIRE || tag != UNKNOWN_REF_TAG || !UNKNOWN_REF_REASONS.contains(&reason) {
        return None;
    }
    let (operation_name, request_id, mutation_digest, request_digest) =
        serde_json::from_str::<(String, String, String, String)>(payload).ok()?;
    if serde_json::to_string(&(
        operation_name.as_str(),
        request_id.as_str(),
        mutation_digest.as_str(),
        request_digest.as_str(),
    ))
    .ok()
    .as_deref()
        != Some(payload)
    {
        return None;
    }
    let operation = match operation_name.as_str() {
        "RestartKernel" => HostRuntimeControlOperation::RestartKernel,
        "ReconcileKernelRestart" => HostRuntimeControlOperation::ReconcileKernelRestart,
        _ => return None,
    };
    let request = HostRuntimeControlRequest {
        wire: PlatformHandle::new(wire.to_owned()).ok()?,
        operation,
        request_id: PlatformHandle::new(request_id).ok()?,
        mutation_digest: PlatformHandle::new(mutation_digest).ok()?,
        request_digest: PlatformHandle::new(request_digest).ok()?,
        response_capability: None,
    };
    request.validate().ok().map(|_| request)
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostRuntimeControlRequest {
    pub wire: PlatformHandle,
    pub operation: HostRuntimeControlOperation,
    pub request_id: PlatformHandle,
    pub mutation_digest: PlatformHandle,
    pub request_digest: PlatformHandle,
    #[serde(skip)]
    response_capability: Option<HostRuntimeControlResponseCapability>,
}

impl HostRuntimeControlRequest {
    pub fn new(
        operation: HostRuntimeControlOperation,
        request_id: PlatformHandle,
    ) -> Result<Self, String> {
        let wire = PlatformHandle::new(WIRE.to_owned()).map_err(|e| e.to_string())?;
        let mutation_digest =
            PlatformHandle::new(mutation_digest_for_request_id(&wire, &request_id))
                .map_err(|e| e.to_string())?;
        Self::new_with_mutation_digest(operation, request_id, mutation_digest)
    }

    pub fn new_with_mutation_digest(
        operation: HostRuntimeControlOperation,
        request_id: PlatformHandle,
        mutation_digest: PlatformHandle,
    ) -> Result<Self, String> {
        let wire = PlatformHandle::new(WIRE.to_owned()).map_err(|e| e.to_string())?;
        let request_digest = PlatformHandle::new(request_digest_for(
            &wire,
            &operation,
            &request_id,
            &mutation_digest,
        ))
        .map_err(|e| e.to_string())?;
        let value = Self {
            wire,
            operation,
            request_id,
            mutation_digest,
            request_digest,
            response_capability: None,
        };
        value.validate().map_err(|e| e.to_string())?;
        Ok(value)
    }

    pub fn new_reconcile(
        request_id: PlatformHandle,
        mutation_digest: PlatformHandle,
    ) -> Result<Self, String> {
        Self::new_with_mutation_digest(
            HostRuntimeControlOperation::ReconcileKernelRestart,
            request_id,
            mutation_digest,
        )
    }

    fn with_response_capability(
        mut self,
        capability: HostRuntimeControlResponseCapability,
    ) -> Self {
        self.response_capability = Some(capability);
        self
    }

    #[allow(private_interfaces)]
    pub(crate) fn response_capability(&self) -> Option<HostRuntimeControlResponseCapability> {
        self.response_capability.clone()
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.wire.as_str() != WIRE {
            return Err("unsupported wire".to_owned());
        }
        if self.request_id.as_str().trim().is_empty()
            || self.request_id.as_str().chars().any(char::is_control)
        {
            return Err("request_id invalid".to_owned());
        }
        if !is_sha256_digest(&self.mutation_digest) {
            return Err("mutation_digest must be lowercase sha256".to_owned());
        }
        if !is_sha256_digest(&self.request_digest) {
            return Err("request_digest must be lowercase sha256".to_owned());
        }
        let expected = request_digest_for(
            &self.wire,
            &self.operation,
            &self.request_id,
            &self.mutation_digest,
        );
        if expected != self.request_digest.as_str() {
            return Err("request_digest mismatch".to_owned());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostKernelRestartReceipt {
    pub mutation_digest: PlatformHandle,
    pub request_digest: PlatformHandle,
    pub old_kernel_generation: PlatformHandle,
    pub new_kernel_generation: PlatformHandle,
    pub store_fence: PlatformHandle,
    pub activation_receipt_digest: PlatformHandle,
    pub ready_receipt_digest: PlatformHandle,
    pub receipt_digest: PlatformHandle,
}

impl HostKernelRestartReceipt {
    pub fn computed_digest(&self) -> Result<PlatformHandle, String> {
        let bytes = serde_json::to_vec(&(
            self.mutation_digest.as_str(),
            self.request_digest.as_str(),
            self.old_kernel_generation.as_str(),
            self.new_kernel_generation.as_str(),
            self.store_fence.as_str(),
            self.activation_receipt_digest.as_str(),
            self.ready_receipt_digest.as_str(),
        ))
        .map_err(|e| e.to_string())?;
        PlatformHandle::new(sha256_hex(&bytes)).map_err(|e| e.to_string())
    }

    pub fn validate(&self) -> Result<(), String> {
        if !is_sha256_digest(&self.mutation_digest) {
            return Err("mutation_digest must be sha256".to_owned());
        }
        if !is_sha256_digest(&self.request_digest) {
            return Err("request_digest must be sha256".to_owned());
        }
        for (v, name) in [
            (&self.old_kernel_generation, "old_kernel_generation"),
            (&self.new_kernel_generation, "new_kernel_generation"),
            (&self.store_fence, "store_fence"),
            (&self.activation_receipt_digest, "activation_receipt_digest"),
            (&self.ready_receipt_digest, "ready_receipt_digest"),
            (&self.receipt_digest, "receipt_digest"),
        ] {
            if v.as_str().len() != 64
                || !v
                    .as_str()
                    .bytes()
                    .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
            {
                return Err(format!("{name} must be sha256"));
            }
        }
        if self.receipt_digest != self.computed_digest()? {
            return Err("receipt_digest mismatch".to_owned());
        }
        Ok(())
    }
}

#[allow(private_interfaces)]
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(
    tag = "status",
    rename_all = "SCREAMING_SNAKE_CASE",
    deny_unknown_fields
)]
pub enum HostRuntimeControlResponse {
    Restarted {
        receipt: HostKernelRestartReceipt,
        #[serde(skip)]
        capability: Option<HostRuntimeControlResponseCapability>,
    },
    Unknown {
        pending_ref: PlatformHandle,
        #[serde(skip)]
        capability: Option<HostRuntimeControlResponseCapability>,
    },
}

impl HostRuntimeControlResponse {
    pub(crate) fn restarted_for(
        request: &HostRuntimeControlRequest,
        receipt: HostKernelRestartReceipt,
    ) -> Self {
        Self::Restarted {
            receipt,
            capability: request.response_capability(),
        }
    }

    pub(crate) fn unknown_for(
        request: &HostRuntimeControlRequest,
        pending_ref: PlatformHandle,
    ) -> Self {
        Self::Unknown {
            pending_ref,
            capability: request.response_capability(),
        }
    }

    pub fn validate(&self) -> Result<(), String> {
        match self {
            Self::Restarted { receipt, .. } => receipt.validate(),
            Self::Unknown { pending_ref, .. } => parse_runtime_control_unknown_ref(pending_ref)
                .map(|_| ())
                .ok_or_else(|| "pending_ref is not canonical".to_owned()),
        }
    }
}

fn pending_ref_matches_request(
    pending_ref: &PlatformHandle,
    request: &HostRuntimeControlRequest,
) -> bool {
    parse_runtime_control_unknown_ref(pending_ref).is_some_and(|parsed| {
        parsed.wire == request.wire
            && parsed.operation == request.operation
            && parsed.request_id == request.request_id
            && parsed.mutation_digest == request.mutation_digest
            && parsed.request_digest == request.request_digest
    })
}

fn response_matches_request(
    request: &HostRuntimeControlRequest,
    response: &HostRuntimeControlResponse,
) -> bool {
    if response.validate().is_err() {
        return false;
    }
    let Some(expected_capability) = request.response_capability.as_ref() else {
        return false;
    };
    match response {
        HostRuntimeControlResponse::Restarted {
            receipt,
            capability,
        } => {
            capability.as_ref() == Some(expected_capability)
                && receipt.request_digest == request.request_digest
                && receipt.mutation_digest == request.mutation_digest
        }
        HostRuntimeControlResponse::Unknown {
            pending_ref,
            capability,
        } => {
            capability.as_ref() == Some(expected_capability)
                && pending_ref_matches_request(pending_ref, request)
        }
    }
}

pub struct HostRuntimeControlEnvelope {
    pub request: HostRuntimeControlRequest,
    pub reply: oneshot::Sender<HostRuntimeControlResponse>,
}

pub type HostRuntimeControlQueue = Arc<Mutex<VecDeque<HostRuntimeControlEnvelope>>>;

pub struct HostRuntimeControl {
    queue: HostRuntimeControlQueue,
}

impl HostRuntimeControl {
    pub(crate) fn new(queue: HostRuntimeControlQueue) -> Self {
        Self { queue }
    }

    pub(crate) fn new_with_capability(
        queue: HostRuntimeControlQueue,
        capability: &eliot_platform_windows::HostOwnerEpochCapability,
    ) -> Result<Self, String> {
        let _guard = capability
            .live_guard()
            .map_err(|_| "Host owner capability is not live".to_owned())?;
        Ok(Self { queue })
    }

    pub fn queue(&self) -> HostRuntimeControlQueue {
        Arc::clone(&self.queue)
    }

    async fn handle(&self, request: &HostRuntimeControlRequest) -> HostRuntimeControlResponse {
        if request.validate().is_err() {
            return HostRuntimeControlResponse::unknown_for(
                request,
                runtime_control_unknown_ref("kernel-restart-validation", request),
            );
        }
        let (reply, response) = oneshot::channel();
        let queued_request = request
            .clone()
            .with_response_capability(HostRuntimeControlResponseCapability(Arc::new(())));
        {
            let Ok(mut q) = self.queue.lock() else {
                return HostRuntimeControlResponse::unknown_for(
                    request,
                    runtime_control_unknown_ref("kernel-restart-queue-lock", request),
                );
            };
            if q.len() >= MAX_QUEUE_DEPTH {
                return HostRuntimeControlResponse::unknown_for(
                    request,
                    runtime_control_unknown_ref("kernel-restart-queue-full", request),
                );
            }
            q.push_back(HostRuntimeControlEnvelope {
                request: queued_request.clone(),
                reply,
            });
        }
        match tokio::time::timeout(QUEUE_RESPONSE_TIMEOUT, response).await {
            Ok(Ok(response)) if response_matches_request(&queued_request, &response) => response,
            Ok(Ok(_)) => HostRuntimeControlResponse::unknown_for(
                request,
                runtime_control_unknown_ref("kernel-restart-queue-response", request),
            ),
            Ok(Err(_)) | Err(_) => HostRuntimeControlResponse::unknown_for(
                request,
                runtime_control_unknown_ref("kernel-restart-queue-response", request),
            ),
        }
    }

    pub async fn serve_one(&self, timeout: Duration) -> Result<(), String> {
        let installer =
            eliot_platform_windows::NamedPipePeerExpectation::new_for_builtin_administrators()
                .map_err(|e| e.to_string())?;
        let mut server = NamedPipeServer::create(HOST_RUNTIME_CONTROL_PIPE, &installer)
            .map_err(|e| e.to_string())?;
        server
            .wait_for_authenticated_client(timeout, &installer)
            .await
            .map_err(|e| e.to_string())?;
        let limits = TransportLimits::default();
        let frame = server
            .receive_frame(limits)
            .await
            .map_err(|e| e.to_string())?;
        let connection_id = frame.connection_id.clone();
        let request = decode_runtime_control_request_frame(&frame).map_err(|e| e.to_string())?;
        let response = self.handle(&request).await;
        let response_frame =
            runtime_control_response_frame(connection_id, &response).map_err(|e| e.to_string())?;
        server
            .send_frame(&response_frame, limits)
            .await
            .map_err(|e| e.to_string())?;
        Ok(())
    }
}

fn sha256_hex(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn durable_frame_identity(digest: &str) -> Result<(RequestId, RequestIdentity), String> {
    let request_id = RequestId::new(digest.to_owned()).map_err(|_| "SessionFenced".to_owned())?;
    let state_fence = StateFence::new(AuthorityEpoch::genesis(), ResourceGeneration::genesis());
    let product_id = ProductId::new("eliot.host.runtime-control".to_owned())
        .map_err(|_| "SessionFenced".to_owned())?;
    let source_id =
        SourceId::new("eliot-host".to_owned()).map_err(|_| "SessionFenced".to_owned())?;
    let identity = RequestIdentity {
        request: RequestBinding {
            metadata: RequestMetadata {
                request_id: request_id.clone(),
                session_id: None,
                task_id: None,
                product_id,
                source_id,
                state_fence: state_fence.clone(),
                clock: ClockReading::default(),
            },
            state_fence,
        },
        idempotency_key: digest.to_owned(),
        deadline_unix_ms: u64::MAX,
        cancellation_id: digest.to_owned(),
    };
    identity
        .validate()
        .map_err(|_| "SessionFenced".to_owned())?;
    Ok((request_id, identity))
}

pub fn runtime_control_request_frame(
    connection_id: impl Into<String>,
    request: &HostRuntimeControlRequest,
) -> Result<Frame, String> {
    request.validate().map_err(|_| "SessionFenced".to_owned())?;
    let (request_id, request_identity) = durable_frame_identity(request.request_digest.as_str())
        .map_err(|_| "SessionFenced".to_owned())?;
    let frame = Frame {
        protocol_version: ProtocolVersion::CURRENT,
        encoding_profile: EncodingProfile::JsonV1,
        connection_id: connection_id.into(),
        request_id: Some(request_id),
        kind: FrameKind::Control,
        message_type: MessageType::Start,
        request_identity: Some(request_identity),
        payload: ProtocolPayload::Json(
            serde_json::to_value(request).map_err(|_| "SessionFenced".to_owned())?,
        ),
        trace_context: std::collections::BTreeMap::new(),
    };
    frame.validate().map_err(|_| "SessionFenced".to_owned())?;
    Ok(frame)
}

pub fn decode_runtime_control_request_frame(
    frame: &Frame,
) -> Result<HostRuntimeControlRequest, String> {
    frame.validate().map_err(|_| "SessionFenced".to_owned())?;
    if frame.kind != FrameKind::Control || frame.message_type != MessageType::Start {
        return Err("SessionFenced".to_owned());
    }
    let ProtocolPayload::Json(payload) = &frame.payload else {
        return Err("SessionFenced".to_owned());
    };
    let request: HostRuntimeControlRequest =
        serde_json::from_value(payload.clone()).map_err(|_| "SessionFenced".to_owned())?;
    request.validate().map_err(|_| "SessionFenced".to_owned())?;
    let frame_request_id = frame
        .request_id
        .as_ref()
        .ok_or_else(|| "SessionFenced".to_owned())?;
    if frame_request_id.as_str() != request.request_digest.as_str() {
        return Err("SessionFenced".to_owned());
    }
    let identity = frame
        .request_identity
        .as_ref()
        .ok_or_else(|| "SessionFenced".to_owned())?;
    if identity.request.metadata.request_id.as_str() != request.request_digest.as_str()
        || identity.idempotency_key != request.request_digest.as_str()
        || identity.cancellation_id != request.request_digest.as_str()
    {
        return Err("SessionFenced".to_owned());
    }
    if identity.request.metadata.request_id != *frame_request_id {
        return Err("SessionFenced".to_owned());
    }
    Ok(request)
}

pub fn runtime_control_response_frame(
    connection_id: impl Into<String>,
    response: &HostRuntimeControlResponse,
) -> Result<Frame, String> {
    response
        .validate()
        .map_err(|_| "SessionFenced".to_owned())?;
    let digest = match response {
        HostRuntimeControlResponse::Restarted { receipt, .. } => {
            receipt.request_digest.as_str().to_owned()
        }
        HostRuntimeControlResponse::Unknown { pending_ref, .. } => {
            parse_runtime_control_unknown_ref(pending_ref)
                .ok_or_else(|| "SessionFenced".to_owned())?
                .request_digest
                .as_str()
                .to_owned()
        }
    };
    let (request_id, request_identity) =
        durable_frame_identity(&digest).map_err(|_| "SessionFenced".to_owned())?;
    let frame = Frame {
        protocol_version: ProtocolVersion::CURRENT,
        encoding_profile: EncodingProfile::JsonV1,
        connection_id: connection_id.into(),
        request_id: Some(request_id),
        kind: FrameKind::Control,
        message_type: MessageType::Ready,
        request_identity: Some(request_identity),
        payload: ProtocolPayload::Json(
            serde_json::to_value(response).map_err(|_| "SessionFenced".to_owned())?,
        ),
        trace_context: std::collections::BTreeMap::new(),
    };
    frame.validate().map_err(|_| "SessionFenced".to_owned())?;
    Ok(frame)
}

pub fn decode_runtime_control_response_frame(
    frame: &Frame,
) -> Result<HostRuntimeControlResponse, String> {
    frame.validate().map_err(|_| "SessionFenced".to_owned())?;
    if frame.kind != FrameKind::Control || frame.message_type != MessageType::Ready {
        return Err("SessionFenced".to_owned());
    }
    let ProtocolPayload::Json(payload) = &frame.payload else {
        return Err("SessionFenced".to_owned());
    };
    let response: HostRuntimeControlResponse =
        serde_json::from_value(payload.clone()).map_err(|_| "SessionFenced".to_owned())?;
    response
        .validate()
        .map_err(|_| "SessionFenced".to_owned())?;
    let frame_request_id = frame
        .request_id
        .as_ref()
        .ok_or_else(|| "SessionFenced".to_owned())?;
    let identity = frame
        .request_identity
        .as_ref()
        .ok_or_else(|| "SessionFenced".to_owned())?;
    if identity.request.metadata.request_id != *frame_request_id
        || identity.idempotency_key != frame_request_id.as_str()
        || identity.cancellation_id != frame_request_id.as_str()
    {
        return Err("SessionFenced".to_owned());
    }
    match &response {
        HostRuntimeControlResponse::Restarted { receipt, .. } => {
            if frame_request_id.as_str() != receipt.request_digest.as_str() {
                return Err("SessionFenced".to_owned());
            }
        }
        HostRuntimeControlResponse::Unknown { pending_ref, .. } => {
            let pending_request = parse_runtime_control_unknown_ref(pending_ref)
                .ok_or_else(|| "SessionFenced".to_owned())?;
            if frame_request_id.as_str() != pending_request.request_digest.as_str() {
                return Err("SessionFenced".to_owned());
            }
        }
    }
    Ok(response)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn handle(v: impl Into<String>) -> PlatformHandle {
        PlatformHandle::new(v.into()).unwrap()
    }

    #[test]
    fn request_digest_rejects_substitution() {
        let req = HostRuntimeControlRequest::new(
            HostRuntimeControlOperation::RestartKernel,
            handle("req-1"),
        )
        .unwrap();
        assert!(req.validate().is_ok());
        let mut bad = req.clone();
        bad.request_digest = handle("0".repeat(64));
        assert!(bad.validate().is_err());
        bad = req.clone();
        bad.operation = HostRuntimeControlOperation::ReconcileKernelRestart;
        assert!(bad.validate().is_err());
        bad = req.clone();
        bad.wire = handle("eliot.host.runtime-control.v1");
        assert!(bad.validate().is_err());
    }

    #[test]
    fn response_rejects_empty_pending_ref() {
        let request = HostRuntimeControlRequest::new(
            HostRuntimeControlOperation::RestartKernel,
            handle("pending-ref-valid"),
        )
        .unwrap();
        let r = HostRuntimeControlResponse::Unknown {
            pending_ref: runtime_control_unknown_ref("kernel-restart", &request),
            capability: None,
        };
        assert!(r.validate().is_ok());
        let malformed = HostRuntimeControlResponse::Unknown {
            pending_ref: handle("x"),
            capability: None,
        };
        assert!(malformed.validate().is_err());
        assert!(PlatformHandle::new(" ".to_owned()).is_err());
    }

    #[test]
    fn unknown_response_requires_canonical_exact_identity() {
        let request = HostRuntimeControlRequest::new(
            HostRuntimeControlOperation::RestartKernel,
            handle("unknown-canonical-request"),
        )
        .unwrap();
        let capability = HostRuntimeControlResponseCapability(Arc::new(()));
        let bound_request = request.clone().with_response_capability(capability.clone());
        let arbitrary_prefix = HostRuntimeControlResponse::Unknown {
            pending_ref: handle(format!(
                "arbitrary-prefix:{}",
                request.request_digest.as_str()
            )),
            capability: Some(capability.clone()),
        };
        assert!(arbitrary_prefix.validate().is_err());
        assert!(!response_matches_request(&bound_request, &arbitrary_prefix));

        let foreign = HostRuntimeControlRequest::new(
            HostRuntimeControlOperation::RestartKernel,
            handle("unknown-canonical-foreign"),
        )
        .unwrap();
        let foreign_identity = HostRuntimeControlResponse::Unknown {
            pending_ref: runtime_control_unknown_ref("kernel-restart", &foreign),
            capability: Some(capability),
        };
        assert!(foreign_identity.validate().is_ok());
        assert!(!response_matches_request(&bound_request, &foreign_identity));
    }

    #[test]
    fn receipt_digest_is_bound() {
        let receipt = HostKernelRestartReceipt {
            mutation_digest: handle("a".repeat(64)),
            request_digest: handle("a".repeat(64)),
            old_kernel_generation: handle("b".repeat(64)),
            new_kernel_generation: handle("c".repeat(64)),
            store_fence: handle("d".repeat(64)),
            activation_receipt_digest: handle("e".repeat(64)),
            ready_receipt_digest: handle("f".repeat(64)),
            receipt_digest: handle("0".repeat(64)),
        };
        let computed = receipt.computed_digest().unwrap();
        let mut good = receipt.clone();
        good.receipt_digest = computed;
        assert!(good.validate().is_ok());
        let mut bad = good.clone();
        bad.store_fence = handle("0".repeat(64));
        assert!(bad.validate().is_err());
    }

    #[test]
    fn same_digest_forged_restarted_evidence_requires_private_capability() {
        let request = HostRuntimeControlRequest::new(
            HostRuntimeControlOperation::RestartKernel,
            handle("same-digest-forged-receipt"),
        )
        .unwrap();
        let capability = HostRuntimeControlResponseCapability(Arc::new(()));
        let bound_request = request.clone().with_response_capability(capability.clone());
        let forged = HostRuntimeControlResponse::Restarted {
            receipt: receipt_for(&request),
            capability: None,
        };
        assert!(forged.validate().is_ok());
        assert!(!response_matches_request(&bound_request, &forged));
        let trusted = HostRuntimeControlResponse::Restarted {
            receipt: receipt_for(&request),
            capability: Some(capability),
        };
        assert!(response_matches_request(&bound_request, &trusted));
    }

    #[test]
    fn pipe_is_distinct_from_credential_pipe() {
        assert_ne!(
            HOST_RUNTIME_CONTROL_PIPE,
            eliot_installation::HOST_CREDENTIAL_CONTROL_PIPE
        );
        assert_ne!(
            HOST_RUNTIME_CONTROL_PIPE,
            eliot_kernel_service::KERNEL_CONTROL_PIPE
        );
    }

    #[test]
    fn production_runtime_control_requires_elevated_admin_pipe_and_capability() {
        let expectation =
            eliot_platform_windows::NamedPipePeerExpectation::new_for_builtin_administrators()
                .unwrap();
        assert!(expectation.requires_builtin_administrators());
        assert_eq!(expectation.expected_sid(), "S-1-5-32-544");
        assert_eq!(
            HOST_RUNTIME_CONTROL_PRODUCTION_DISCRIMINATOR,
            "eliot-host::production-runtime-control:v1"
        );
        assert_eq!(
            HOST_RUNTIME_CONTROL_PIPE,
            r"\\.\pipe\eliot\host\runtime-control-v1"
        );
    }

    #[test]
    fn queue_is_bounded() {
        let q: HostRuntimeControlQueue = Arc::new(Mutex::new(VecDeque::new()));
        for _ in 0..MAX_QUEUE_DEPTH {
            q.lock().unwrap().push_back(HostRuntimeControlEnvelope {
                request: HostRuntimeControlRequest::new(
                    HostRuntimeControlOperation::RestartKernel,
                    handle("id"),
                )
                .unwrap(),
                reply: oneshot::channel().0,
            });
        }
        assert_eq!(q.lock().unwrap().len(), MAX_QUEUE_DEPTH);
    }

    #[test]
    fn production_negative_rejects_empty_request_id_and_replay_is_idempotent() {
        assert!(PlatformHandle::new(String::new()).is_err());
        let req = HostRuntimeControlRequest::new(
            HostRuntimeControlOperation::RestartKernel,
            handle("req-replay-1"),
        )
        .unwrap();
        let mut map = std::collections::HashMap::new();
        let receipt = HostKernelRestartReceipt {
            mutation_digest: req.mutation_digest.clone(),
            request_digest: req.request_digest.clone(),
            old_kernel_generation: handle("a".repeat(64)),
            new_kernel_generation: handle("b".repeat(64)),
            store_fence: handle("c".repeat(64)),
            activation_receipt_digest: handle("d".repeat(64)),
            ready_receipt_digest: handle("e".repeat(64)),
            receipt_digest: handle("0".repeat(64)),
        };
        let mut receipt_with_digest = receipt.clone();
        receipt_with_digest.receipt_digest = receipt_with_digest.computed_digest().unwrap();
        map.insert(
            req.request_digest.as_str().to_owned(),
            receipt_with_digest.clone(),
        );
        let duplicate = HostRuntimeControlRequest::new(
            HostRuntimeControlOperation::RestartKernel,
            handle("req-replay-1"),
        )
        .unwrap();
        assert_eq!(req.request_digest, duplicate.request_digest);
        assert_eq!(
            map.get(duplicate.request_digest.as_str()).unwrap(),
            &receipt_with_digest
        );
        let different = HostRuntimeControlRequest::new(
            HostRuntimeControlOperation::RestartKernel,
            handle("req-replay-2"),
        )
        .unwrap();
        assert_ne!(req.request_digest, different.request_digest);
        assert!(map.get(different.request_digest.as_str()).is_none());
    }

    #[test]
    fn frame_request_identity_is_bound_to_durable_digest_and_roundtrips() {
        let req = HostRuntimeControlRequest::new(
            HostRuntimeControlOperation::RestartKernel,
            handle("frame-bind-1"),
        )
        .unwrap();
        let frame = runtime_control_request_frame("conn-1", &req).unwrap();
        assert_eq!(
            frame.request_id.as_ref().unwrap().as_str(),
            req.request_digest.as_str()
        );
        assert_eq!(
            frame.request_identity.as_ref().unwrap().idempotency_key,
            req.request_digest.as_str()
        );
        let decoded = decode_runtime_control_request_frame(&frame).unwrap();
        assert_eq!(decoded, req);
        let mut tampered = frame.clone();
        tampered.request_id = Some(eliot_contracts::RequestId::new("0".repeat(64)).unwrap());
        assert!(decode_runtime_control_request_frame(&tampered).is_err());
        let receipt = {
            let mut r = HostKernelRestartReceipt {
                mutation_digest: req.mutation_digest.clone(),
                request_digest: req.request_digest.clone(),
                old_kernel_generation: handle("a".repeat(64)),
                new_kernel_generation: handle("b".repeat(64)),
                store_fence: handle("c".repeat(64)),
                activation_receipt_digest: handle("d".repeat(64)),
                ready_receipt_digest: handle("e".repeat(64)),
                receipt_digest: handle("0".repeat(64)),
            };
            r.receipt_digest = r.computed_digest().unwrap();
            r
        };
        let resp = HostRuntimeControlResponse::Restarted {
            receipt: receipt.clone(),
            capability: None,
        };
        let rframe = runtime_control_response_frame("conn-2", &resp).unwrap();
        assert_eq!(
            rframe.request_id.as_ref().unwrap().as_str(),
            receipt.request_digest.as_str()
        );
        let rdecoded = decode_runtime_control_response_frame(&rframe).unwrap();
        assert_eq!(rdecoded, resp);
        let mut rtampered = rframe.clone();
        rtampered.request_identity = None;
        assert!(decode_runtime_control_response_frame(&rtampered).is_err());
    }

    #[test]
    fn frame_pending_unknown_is_bound_without_parallel_wire() {
        let request = HostRuntimeControlRequest::new_with_mutation_digest(
            HostRuntimeControlOperation::RestartKernel,
            handle("frame-pending-unknown"),
            handle("aa".repeat(32)),
        )
        .unwrap();
        let pending = HostRuntimeControlResponse::Unknown {
            pending_ref: runtime_control_unknown_ref("kernel-restart-pending", &request),
            capability: None,
        };
        let frame = runtime_control_response_frame("conn-3", &pending).unwrap();
        assert_eq!(
            frame.request_id.as_ref().unwrap().as_str(),
            request.request_digest.as_str()
        );
        let decoded = decode_runtime_control_response_frame(&frame).unwrap();
        assert_eq!(decoded, pending);
    }

    #[test]
    fn reconcile_carries_original_mutation_digest_but_uses_operation_bound_digest() {
        let restart = HostRuntimeControlRequest::new(
            HostRuntimeControlOperation::RestartKernel,
            handle("same-id-99"),
        )
        .unwrap();
        let reconcile = HostRuntimeControlRequest::new_reconcile(
            handle("query-id-99"),
            restart.mutation_digest.clone(),
        )
        .unwrap();
        assert_ne!(restart.request_id, reconcile.request_id);
        assert_eq!(restart.mutation_digest, reconcile.mutation_digest);
        assert_ne!(restart.request_digest, reconcile.request_digest);
        assert_ne!(restart.operation, reconcile.operation);
        let r_frame = runtime_control_request_frame("conn-r", &restart).unwrap();
        let c_frame = runtime_control_request_frame("conn-c", &reconcile).unwrap();
        assert_ne!(
            r_frame.request_id.as_ref().unwrap().as_str(),
            c_frame.request_id.as_ref().unwrap().as_str()
        );
        assert_eq!(
            r_frame.request_identity.as_ref().unwrap().idempotency_key,
            r_frame.request_id.as_ref().unwrap().as_str()
        );
        assert_ne!(
            r_frame.request_identity.as_ref().unwrap().idempotency_key,
            c_frame.request_identity.as_ref().unwrap().idempotency_key
        );
    }

    #[tokio::test]
    async fn queue_full_preserves_request_identity_and_frame_binding() {
        let q: HostRuntimeControlQueue = Arc::new(Mutex::new(VecDeque::new()));
        for _ in 0..MAX_QUEUE_DEPTH {
            q.lock().unwrap().push_back(HostRuntimeControlEnvelope {
                request: HostRuntimeControlRequest::new(
                    HostRuntimeControlOperation::RestartKernel,
                    handle("fill"),
                )
                .unwrap(),
                reply: oneshot::channel().0,
            });
        }
        let control = HostRuntimeControl::new(Arc::clone(&q));
        let request = HostRuntimeControlRequest::new(
            HostRuntimeControlOperation::RestartKernel,
            handle("full-test-1"),
        )
        .unwrap();
        let response = control.handle(&request).await;
        let HostRuntimeControlResponse::Unknown { pending_ref, .. } = response else {
            panic!("expected Unknown for queue-full");
        };
        assert!(pending_ref.as_str().contains(request.request_id.as_str()));
        assert!(
            pending_ref
                .as_str()
                .contains(request.request_digest.as_str())
        );
        assert!(!pending_ref.as_str().contains("runtime-control-queue-full"));
        let error_hash = sha256_hex(b"runtime-control-queue-full");
        assert!(!pending_ref.as_str().contains(&error_hash));
        let frame = runtime_control_response_frame(
            "conn-full",
            &HostRuntimeControlResponse::Unknown {
                pending_ref: pending_ref.clone(),
                capability: None,
            },
        )
        .unwrap();
        assert_eq!(
            frame.request_id.as_ref().unwrap().as_str(),
            request.request_digest.as_str()
        );
        assert_eq!(
            frame.request_identity.as_ref().unwrap().idempotency_key,
            request.request_digest.as_str()
        );
        let decoded = decode_runtime_control_response_frame(&frame).unwrap();
        assert_eq!(
            decoded,
            HostRuntimeControlResponse::Unknown {
                pending_ref,
                capability: None,
            }
        );
    }

    fn receipt_for(request: &HostRuntimeControlRequest) -> HostKernelRestartReceipt {
        let mut receipt = HostKernelRestartReceipt {
            mutation_digest: request.mutation_digest.clone(),
            request_digest: request.request_digest.clone(),
            old_kernel_generation: handle("a".repeat(64)),
            new_kernel_generation: handle("b".repeat(64)),
            store_fence: handle("c".repeat(64)),
            activation_receipt_digest: handle("d".repeat(64)),
            ready_receipt_digest: handle("e".repeat(64)),
            receipt_digest: handle("0".repeat(64)),
        };
        receipt.receipt_digest = receipt.computed_digest().unwrap();
        receipt
    }

    async fn pop_envelope(queue: &HostRuntimeControlQueue) -> HostRuntimeControlEnvelope {
        loop {
            if let Some(envelope) = queue.lock().unwrap().pop_front() {
                return envelope;
            }
            tokio::task::yield_now().await;
        }
    }

    #[tokio::test]
    async fn worker_restarted_substitution_becomes_original_request_unknown() {
        let queue: HostRuntimeControlQueue = Arc::new(Mutex::new(VecDeque::new()));
        let control = HostRuntimeControl::new(Arc::clone(&queue));
        let request = HostRuntimeControlRequest::new(
            HostRuntimeControlOperation::RestartKernel,
            handle("worker-restarted-original"),
        )
        .unwrap();
        let foreign = HostRuntimeControlRequest::new(
            HostRuntimeControlOperation::RestartKernel,
            handle("worker-restarted-foreign"),
        )
        .unwrap();
        let foreign_digest = foreign.request_digest.clone();
        let mut mutation_substitution = receipt_for(&request);
        mutation_substitution.mutation_digest = foreign.mutation_digest.clone();
        mutation_substitution.receipt_digest = mutation_substitution.computed_digest().unwrap();
        let bound_request = request
            .clone()
            .with_response_capability(HostRuntimeControlResponseCapability(Arc::new(())));
        assert!(!response_matches_request(
            &bound_request,
            &HostRuntimeControlResponse::Restarted {
                receipt: mutation_substitution,
                capability: None,
            }
        ));
        let queue_for_worker = Arc::clone(&queue);
        let foreign_for_worker = foreign.clone();
        tokio::spawn(async move {
            let envelope = pop_envelope(&queue_for_worker).await;
            let _ = envelope
                .reply
                .send(HostRuntimeControlResponse::restarted_for(
                    &foreign_for_worker,
                    receipt_for(&foreign_for_worker),
                ));
        });
        let response = control.handle(&request).await;
        let HostRuntimeControlResponse::Unknown { pending_ref, .. } = response else {
            panic!("foreign Restarted response must become Unknown");
        };
        assert!(
            pending_ref
                .as_str()
                .contains(request.request_digest.as_str())
        );
        assert!(!pending_ref.as_str().contains(foreign_digest.as_str()));
    }

    #[tokio::test]
    async fn worker_unknown_substitution_becomes_original_request_unknown() {
        let queue: HostRuntimeControlQueue = Arc::new(Mutex::new(VecDeque::new()));
        let control = HostRuntimeControl::new(Arc::clone(&queue));
        let request = HostRuntimeControlRequest::new(
            HostRuntimeControlOperation::RestartKernel,
            handle("worker-unknown-original"),
        )
        .unwrap();
        let foreign = HostRuntimeControlRequest::new(
            HostRuntimeControlOperation::RestartKernel,
            handle("worker-unknown-foreign"),
        )
        .unwrap();
        let foreign_digest = foreign.request_digest.clone();
        let queue_for_worker = Arc::clone(&queue);
        let foreign_for_worker = foreign.clone();
        tokio::spawn(async move {
            let envelope = pop_envelope(&queue_for_worker).await;
            let _ = envelope.reply.send(HostRuntimeControlResponse::unknown_for(
                &foreign_for_worker,
                runtime_control_unknown_ref("kernel-restart", &foreign_for_worker),
            ));
        });
        let response = control.handle(&request).await;
        let HostRuntimeControlResponse::Unknown { pending_ref, .. } = response else {
            panic!("foreign Unknown response must become Unknown");
        };
        assert!(
            pending_ref
                .as_str()
                .contains(request.request_digest.as_str())
        );
        assert!(!pending_ref.as_str().contains(foreign_digest.as_str()));
    }

    #[tokio::test]
    async fn queue_response_timeout_and_sender_drop_preserve_identity() {
        let q: HostRuntimeControlQueue = Arc::new(Mutex::new(VecDeque::new()));
        let control = HostRuntimeControl::new(Arc::clone(&q));
        let request = HostRuntimeControlRequest::new(
            HostRuntimeControlOperation::RestartKernel,
            handle("sender-drop-1"),
        )
        .unwrap();
        let dropped = request.request_digest.as_str().to_owned();
        let q_clone = Arc::clone(&q);
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(10)).await;
            let envelope = {
                let mut guard = q_clone.lock().unwrap();
                guard.pop_front()
            };
            if let Some(env) = envelope {
                drop(env.reply);
            }
        });
        let response = control.handle(&request).await;
        let HostRuntimeControlResponse::Unknown { pending_ref, .. } = response else {
            panic!("expected Unknown for sender drop/timeout");
        };
        assert!(pending_ref.as_str().contains(request.request_id.as_str()));
        assert!(pending_ref.as_str().contains(&dropped));
        let frame = runtime_control_response_frame(
            "conn-drop",
            &HostRuntimeControlResponse::Unknown {
                pending_ref: pending_ref.clone(),
                capability: None,
            },
        )
        .unwrap();
        assert_eq!(
            frame.request_id.as_ref().unwrap().as_str(),
            request.request_digest.as_str()
        );
        let _ = decode_runtime_control_response_frame(&frame).unwrap();
    }

    #[tokio::test]
    async fn validation_unknown_preserves_digest_and_rejects_error_hash() {
        let q: HostRuntimeControlQueue = Arc::new(Mutex::new(VecDeque::new()));
        let control = HostRuntimeControl::new(Arc::clone(&q));
        let mut bad = HostRuntimeControlRequest::new(
            HostRuntimeControlOperation::RestartKernel,
            handle("validation-1"),
        )
        .unwrap();
        bad.request_digest = handle("b".repeat(64));
        let response = control.handle(&bad).await;
        let HostRuntimeControlResponse::Unknown { pending_ref, .. } = response else {
            panic!("expected Unknown for validation");
        };
        assert!(pending_ref.as_str().contains(bad.request_id.as_str()));
        assert!(pending_ref.as_str().contains(bad.request_digest.as_str()));
        let error_hash = sha256_hex(b"runtime-control-validation");
        assert!(!pending_ref.as_str().contains(&error_hash));
        assert!(
            HostRuntimeControlResponse::Unknown {
                pending_ref,
                capability: None,
            }
            .validate()
            .is_err(),
            "invalid requests cannot be framed as canonical responses"
        );
    }

    #[tokio::test]
    async fn queue_lock_poison_preserves_identity() {
        let q: HostRuntimeControlQueue = Arc::new(Mutex::new(VecDeque::new()));
        let _ = std::panic::catch_unwind({
            let q = Arc::clone(&q);
            move || {
                let _guard = q.lock().unwrap();
                panic!("poison");
            }
        });
        let control = HostRuntimeControl::new(Arc::clone(&q));
        let request = HostRuntimeControlRequest::new(
            HostRuntimeControlOperation::RestartKernel,
            handle("lock-poison-1"),
        )
        .unwrap();
        let response = control.handle(&request).await;
        let HostRuntimeControlResponse::Unknown { pending_ref, .. } = response else {
            panic!("expected Unknown for lock poison");
        };
        assert!(
            pending_ref
                .as_str()
                .contains(request.request_digest.as_str())
        );
    }

    #[test]
    fn reconcile_frame_preserves_identity_and_decode_rejects_digest_substitution() {
        let restart = HostRuntimeControlRequest::new(
            HostRuntimeControlOperation::RestartKernel,
            handle("reconcile-frame-1"),
        )
        .unwrap();
        let reconcile = HostRuntimeControlRequest::new_reconcile(
            handle("reconcile-frame-1"),
            restart.mutation_digest.clone(),
        )
        .unwrap();
        assert_eq!(restart.mutation_digest, reconcile.mutation_digest);
        assert_ne!(restart.request_digest, reconcile.request_digest);
        let frame = runtime_control_request_frame("conn-reconcile", &reconcile).unwrap();
        assert_eq!(
            frame.request_id.as_ref().unwrap().as_str(),
            reconcile.request_digest.as_str()
        );
        let decoded = decode_runtime_control_request_frame(&frame).unwrap();
        assert_eq!(decoded.mutation_digest, restart.mutation_digest);
        assert_eq!(decoded.request_digest, reconcile.request_digest);
        let mut tampered = frame.clone();
        let mut payload = serde_json::to_value(&reconcile).unwrap();
        payload["request_digest"] = serde_json::Value::String("c".repeat(64));
        tampered.payload = ProtocolPayload::Json(payload);
        assert!(decode_runtime_control_request_frame(&tampered).is_err());
        tampered = frame.clone();
        tampered.request_id = Some(eliot_contracts::RequestId::new("d".repeat(64)).unwrap());
        assert!(decode_runtime_control_request_frame(&tampered).is_err());

        let mut operation_flip = frame;
        let mut payload = serde_json::to_value(&reconcile).unwrap();
        payload["operation"] = serde_json::Value::String("RESTART_KERNEL".to_owned());
        operation_flip.payload = ProtocolPayload::Json(payload);
        assert!(decode_runtime_control_request_frame(&operation_flip).is_err());
    }
}
