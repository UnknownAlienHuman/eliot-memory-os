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
const WIRE: &str = "eliot.host.runtime-control.v1";

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE", deny_unknown_fields)]
pub enum HostRuntimeControlOperation {
    RestartKernel,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostRuntimeControlRequest {
    pub wire: PlatformHandle,
    pub operation: HostRuntimeControlOperation,
    pub request_id: PlatformHandle,
    pub request_digest: PlatformHandle,
}

impl HostRuntimeControlRequest {
    pub fn new(
        operation: HostRuntimeControlOperation,
        request_id: PlatformHandle,
    ) -> Result<Self, String> {
        let wire = PlatformHandle::new(WIRE.to_owned()).map_err(|e| e.to_string())?;
        let digest = PlatformHandle::new(sha256_hex(
            format!(
                "{}:{}:{}",
                wire.as_str(),
                format!("{operation:?}"),
                request_id.as_str()
            )
            .as_bytes(),
        ))
        .map_err(|e| e.to_string())?;
        let value = Self {
            wire,
            operation,
            request_id,
            request_digest: digest,
        };
        value.validate().map_err(|e| e.to_string())?;
        Ok(value)
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
        if self.request_digest.as_str().len() != 64
            || !self
                .request_digest
                .as_str()
                .bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
        {
            return Err("request_digest must be lowercase sha256".to_owned());
        }
        let expected = sha256_hex(
            format!(
                "{}:{}:{}",
                self.wire.as_str(),
                format!("{:?}", self.operation),
                self.request_id.as_str()
            )
            .as_bytes(),
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
        if self.request_digest.as_str().len() != 64
            || !self
                .request_digest
                .as_str()
                .bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
        {
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

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(
    tag = "status",
    rename_all = "SCREAMING_SNAKE_CASE",
    deny_unknown_fields
)]
pub enum HostRuntimeControlResponse {
    Restarted { receipt: HostKernelRestartReceipt },
    Unknown { pending_ref: PlatformHandle },
}

impl HostRuntimeControlResponse {
    pub fn validate(&self) -> Result<(), String> {
        match self {
            Self::Restarted { receipt } => receipt.validate(),
            Self::Unknown { pending_ref } => {
                if pending_ref.as_str().trim().is_empty() {
                    return Err("pending_ref invalid".to_owned());
                }
                Ok(())
            }
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
            return unknown("runtime-control-validation");
        }
        let (reply, response) = oneshot::channel();
        {
            let Ok(mut q) = self.queue.lock() else {
                return unknown("runtime-control-queue-lock");
            };
            if q.len() >= MAX_QUEUE_DEPTH {
                return unknown("runtime-control-queue-full");
            }
            q.push_back(HostRuntimeControlEnvelope {
                request: request.clone(),
                reply,
            });
        }
        match tokio::time::timeout(QUEUE_RESPONSE_TIMEOUT, response).await {
            Ok(Ok(r)) => r,
            Ok(Err(_)) | Err(_) => unknown("runtime-control-queue-response"),
        }
    }

    pub async fn serve_one(&self, timeout: Duration) -> Result<(), String> {
        let installer = eliot_platform_windows::current_process_named_pipe_expectation()
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

fn unknown(label: &str) -> HostRuntimeControlResponse {
    HostRuntimeControlResponse::Unknown {
        pending_ref: PlatformHandle::new(label).unwrap_or_else(|_| unreachable!()),
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
        HostRuntimeControlResponse::Restarted { receipt } => {
            receipt.request_digest.as_str().to_owned()
        }
        HostRuntimeControlResponse::Unknown { pending_ref } => {
            let s = pending_ref.as_str();
            if let Some(pos) = s.rfind(':') {
                let suffix = &s[pos + 1..];
                if suffix.len() == 64
                    && suffix
                        .bytes()
                        .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
                {
                    suffix.to_owned()
                } else {
                    s.to_owned()
                }
            } else {
                s.to_owned()
            }
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
        HostRuntimeControlResponse::Restarted { receipt } => {
            if frame_request_id.as_str() != receipt.request_digest.as_str() {
                return Err("SessionFenced".to_owned());
            }
        }
        HostRuntimeControlResponse::Unknown { pending_ref } => {
            let s = pending_ref.as_str();
            let expected = if let Some(pos) = s.rfind(':') {
                let suffix = &s[pos + 1..];
                if suffix.len() == 64
                    && suffix
                        .bytes()
                        .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
                {
                    suffix
                } else {
                    s
                }
            } else {
                s
            };
            if frame_request_id.as_str() != expected {
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
    }

    #[test]
    fn response_rejects_empty_pending_ref() {
        let r = HostRuntimeControlResponse::Unknown {
            pending_ref: handle("x"),
        };
        assert!(r.validate().is_ok());
        assert!(PlatformHandle::new(" ".to_owned()).is_err());
    }

    #[test]
    fn receipt_digest_is_bound() {
        let receipt = HostKernelRestartReceipt {
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
        let digest = "aa".repeat(32);
        let pending = HostRuntimeControlResponse::Unknown {
            pending_ref: handle(format!("kernel-restart-pending:{digest}")),
        };
        let frame = runtime_control_response_frame("conn-3", &pending).unwrap();
        assert_eq!(frame.request_id.as_ref().unwrap().as_str(), digest);
        let decoded = decode_runtime_control_response_frame(&frame).unwrap();
        assert_eq!(decoded, pending);
    }
}
