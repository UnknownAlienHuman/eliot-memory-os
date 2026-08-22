#![allow(
    clippy::all,
    clippy::pedantic,
    clippy::nursery,
    dead_code,
    missing_docs,
    reason = "Host runtime-control endpoint keeps explicit production plumbing"
)]

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use std::time::Duration;

pub use eliot_host_service::runtime_control::{
    HOST_RUNTIME_CONTROL_PRODUCTION_DISCRIMINATOR, HostKernelRestartReceipt,
    HostRuntimeControlOperation, HostRuntimeControlRequest, HostRuntimeControlResponse,
    HostStoreRecoveryReceipt, decode_runtime_control_request_frame, runtime_control_response_frame,
    runtime_control_unknown_ref,
};
use eliot_host_service::runtime_control::{operation_unknown_ref, response_matches_request};
use eliot_ipc::{NamedPipeServer, TransportLimits};
use tokio::sync::oneshot;

pub const HOST_RUNTIME_CONTROL_PIPE: &str = r"\\.\pipe\eliot\host\runtime-control-v1";
const MAX_QUEUE_DEPTH: usize = 32;
const QUEUE_RESPONSE_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Clone, Debug)]
struct ResponseCorrelation(Arc<()>);

struct HostRuntimeControlReply {
    response: HostRuntimeControlResponse,
    correlation: ResponseCorrelation,
}

pub struct HostRuntimeControlEnvelope {
    request: HostRuntimeControlRequest,
    reply: oneshot::Sender<HostRuntimeControlReply>,
    correlation: ResponseCorrelation,
}

impl HostRuntimeControlEnvelope {
    pub fn request(&self) -> &HostRuntimeControlRequest {
        &self.request
    }

    pub fn respond(
        self,
        response: HostRuntimeControlResponse,
    ) -> Result<(), HostRuntimeControlResponse> {
        self.reply
            .send(HostRuntimeControlReply {
                response,
                correlation: self.correlation,
            })
            .map_err(|reply| reply.response)
    }
}

pub type HostRuntimeControlQueue = Arc<Mutex<VecDeque<HostRuntimeControlEnvelope>>>;

fn response_matches_private_correlation(
    expected: &ResponseCorrelation,
    reply: &HostRuntimeControlReply,
    request: &HostRuntimeControlRequest,
) -> bool {
    Arc::ptr_eq(&expected.0, &reply.correlation.0)
        && response_matches_request(request, &reply.response)
}

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
                operation_unknown_ref(&request.operation, "validation", request),
            );
        }
        let (reply, response) = oneshot::channel();
        let correlation = ResponseCorrelation(Arc::new(()));
        {
            let Ok(mut queue) = self.queue.lock() else {
                return HostRuntimeControlResponse::unknown_for(
                    request,
                    operation_unknown_ref(&request.operation, "queue-lock", request),
                );
            };
            if queue.len() >= MAX_QUEUE_DEPTH {
                return HostRuntimeControlResponse::unknown_for(
                    request,
                    operation_unknown_ref(&request.operation, "queue-full", request),
                );
            }
            queue.push_back(HostRuntimeControlEnvelope {
                request: request.clone(),
                reply,
                correlation: correlation.clone(),
            });
        }
        match tokio::time::timeout(QUEUE_RESPONSE_TIMEOUT, response).await {
            Ok(Ok(reply))
                if Arc::ptr_eq(&correlation.0, &reply.correlation.0)
                    && response_matches_request(request, &reply.response) =>
            {
                reply.response
            }
            Ok(Ok(_)) => HostRuntimeControlResponse::unknown_for(
                request,
                operation_unknown_ref(&request.operation, "queue-response", request),
            ),
            Ok(Err(_)) | Err(_) => HostRuntimeControlResponse::unknown_for(
                request,
                operation_unknown_ref(&request.operation, "queue-response", request),
            ),
        }
    }

    pub async fn serve_one(&self, timeout: Duration) -> Result<(), String> {
        let installer =
            eliot_platform_windows::NamedPipePeerExpectation::new_for_builtin_administrators()
                .map_err(|error| error.to_string())?;
        let mut server = NamedPipeServer::create(HOST_RUNTIME_CONTROL_PIPE, &installer)
            .map_err(|error| error.to_string())?;
        server
            .wait_for_authenticated_client(timeout, &installer)
            .await
            .map_err(|error| error.to_string())?;
        let limits = TransportLimits::default();
        let frame = server
            .receive_frame(limits)
            .await
            .map_err(|error| error.to_string())?;
        let connection_id = frame.connection_id.clone();
        let request = decode_runtime_control_request_frame(&frame)?;
        let response = self.handle(&request).await;
        let response_frame = runtime_control_response_frame(connection_id, &response)?;
        server
            .send_frame(&response_frame, limits)
            .await
            .map_err(|error| error.to_string())?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use eliot_host_service::runtime_control::runtime_control_request_frame;
    use eliot_platform::PlatformHandle;

    fn handle(value: &str) -> PlatformHandle {
        PlatformHandle::new(value.to_owned()).unwrap_or_else(|_| unreachable!())
    }

    #[test]
    fn endpoint_uses_builtin_administrator_policy() {
        let expectation =
            eliot_platform_windows::NamedPipePeerExpectation::new_for_builtin_administrators()
                .unwrap_or_else(|_| unreachable!());
        assert!(expectation.requires_builtin_administrators());
        assert_eq!(expectation.expected_sid(), "S-1-5-32-544");
        assert_eq!(
            HOST_RUNTIME_CONTROL_PIPE,
            r"\\.\pipe\eliot\host\runtime-control-v1"
        );
    }

    #[test]
    fn shared_wire_roundtrip_has_no_in_process_capability_field() {
        let request = HostRuntimeControlRequest::new(
            HostRuntimeControlOperation::RestartKernel,
            handle("host-wire-test"),
        )
        .unwrap_or_else(|_| unreachable!());
        let frame = runtime_control_request_frame("host-test-connection", &request)
            .unwrap_or_else(|_| unreachable!());
        let value = serde_json::to_value(&request).unwrap_or_else(|_| unreachable!());
        assert!(value.get("response_capability").is_none());
        assert!(decode_runtime_control_request_frame(&frame).is_ok());
    }

    #[test]
    fn same_digest_forged_response_requires_the_private_queue_correlation() {
        let request = HostRuntimeControlRequest::new(
            HostRuntimeControlOperation::RestartKernel,
            handle("same-digest-response"),
        )
        .unwrap_or_else(|_| unreachable!());
        let response = HostRuntimeControlResponse::Unknown {
            pending_ref: runtime_control_unknown_ref("kernel-restart", &request),
        };
        assert!(response_matches_request(&request, &response));

        let expected = ResponseCorrelation(Arc::new(()));
        let forged = HostRuntimeControlReply {
            response: response.clone(),
            correlation: ResponseCorrelation(Arc::new(())),
        };
        assert!(!response_matches_private_correlation(
            &expected, &forged, &request
        ));

        let trusted = HostRuntimeControlReply {
            response,
            correlation: expected.clone(),
        };
        assert!(response_matches_private_correlation(
            &expected, &trusted, &request
        ));
    }
}
