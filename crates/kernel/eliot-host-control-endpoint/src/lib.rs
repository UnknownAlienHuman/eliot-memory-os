//! Capability-bound Host runtime-control named-pipe endpoint.
//!
//! The canonical wire contract remains owned by `eliot-host-service`; this
//! cell owns only the bounded authenticated endpoint and its in-process queue.

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
    HOST_RUNTIME_CONTROL_PRODUCTION_DISCRIMINATOR, HostDemandStartReceipt,
    HostDemandStartRuntimeRequest, HostDemandStartSafetyClass, HostDemandStartState,
    HostDemandStartWakeRequest, HostKernelRestartReceipt, HostReactiveContextRuntimeRequest,
    HostRuntimeControlOperation, HostRuntimeControlRequest, HostRuntimeControlResponse,
    HostStoreRecoveryReceipt, decode_runtime_control_request_frame, runtime_control_response_frame,
    runtime_control_unknown_ref,
};
use eliot_host_service::runtime_control::{operation_unknown_ref, response_matches_request};
use eliot_ipc::{NamedPipeServer, PeerIdentity, ProcessBinding, TransportLimits};
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
    peer: AuthenticatedHostRuntimePeer,
    reply: oneshot::Sender<HostRuntimeControlReply>,
    correlation: ResponseCorrelation,
}

/// Handle-authenticated caller binding for one Host runtime-control pipe
/// connection. The connection identifier is minted by the server; frame
/// fields supplied by the caller are correlation data only.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthenticatedHostRuntimePeer {
    peer: PeerIdentity,
    principal_sid: String,
    session_id: String,
    process: ProcessBinding,
    connection_id: String,
}

impl AuthenticatedHostRuntimePeer {
    fn from_transport(peer: &PeerIdentity) -> Result<Self, String> {
        peer.validate().map_err(|error| error.to_string())?;
        let (principal_sid, session_id) = Self::principal_session(peer)?;
        let process = peer
            .process_binding()
            .ok_or_else(|| "authenticated Host peer has no process binding".to_owned())?;
        Ok(Self {
            peer: peer.clone(),
            principal_sid: principal_sid.to_owned(),
            session_id: session_id.to_owned(),
            process: process.clone(),
            connection_id: format!("host-runtime-control:{}", uuid::Uuid::new_v4().simple()),
        })
    }

    fn principal_session(peer: &PeerIdentity) -> Result<(&str, &str), String> {
        match peer {
            PeerIdentity::Authenticated {
                user_identity,
                session_identity,
                ..
            } => Ok((user_identity, session_identity)),
            PeerIdentity::Unavailable { .. } => {
                Err("Host runtime-control peer identity is unavailable".to_owned())
            }
        }
    }

    pub fn peer_identity(&self) -> &PeerIdentity {
        &self.peer
    }

    pub fn principal_sid(&self) -> &str {
        &self.principal_sid
    }

    pub fn session_id(&self) -> &str {
        &self.session_id
    }

    pub fn process_binding(&self) -> &ProcessBinding {
        &self.process
    }

    pub fn connection_id(&self) -> &str {
        &self.connection_id
    }
}

impl HostRuntimeControlEnvelope {
    pub fn request(&self) -> &HostRuntimeControlRequest {
        &self.request
    }

    pub fn peer(&self) -> &AuthenticatedHostRuntimePeer {
        &self.peer
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
    pub fn new_with_capability(
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

    async fn handle(
        &self,
        request: &HostRuntimeControlRequest,
        peer: AuthenticatedHostRuntimePeer,
    ) -> HostRuntimeControlResponse {
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
                peer,
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
        let peer = AuthenticatedHostRuntimePeer::from_transport(server.peer_identity())?;
        let response = self.handle(&request, peer).await;
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
