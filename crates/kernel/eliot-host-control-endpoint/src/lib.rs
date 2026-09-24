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
    HOST_RUNTIME_CONTROL_PRODUCTION_DISCRIMINATOR, HostKernelRestartReceipt,
    HostReactiveContextRuntimeRequest, HostRuntimeControlOperation, HostRuntimeControlRequest,
    HostRuntimeControlResponse, HostStoreRecoveryReceipt, decode_runtime_control_request_frame,
    runtime_control_response_frame, runtime_control_unknown_ref,
};
use eliot_host_service::runtime_control::{operation_unknown_ref, response_matches_request};
pub use eliot_host_service::{
    UserAutomationHostChannelBinding, UserAutomationHostExecutionEndpoint,
    UserAutomationHostExecutionRequest, UserAutomationHostExecutionResponse,
    UserAutomationRuntimeError, decode_user_automation_host_execution_open_frame,
    decode_user_automation_host_execution_request_frame,
    user_automation_host_execution_open_response_frame,
    user_automation_host_execution_response_frame,
};
use eliot_host_service::{UserAutomationHostExecutionSession, UserAutomationHostOwnerBinding};
use eliot_ipc::{NamedPipeServer, TransportLimits};
use tokio::sync::oneshot;

pub mod backup;
pub use backup::{
    AcceptedOwnerMethod, BackupOperationKind, accepted_host_backup_methods, authority_matches,
    is_supported, register_backup_methods, rehearsal_resolves_cutover, requires_cutover_admission,
};

pub const HOST_RUNTIME_CONTROL_PIPE: &str = r"\\.\pipe\eliot\host\runtime-control-v1";
const MAX_QUEUE_DEPTH: usize = 32;
const QUEUE_RESPONSE_TIMEOUT: Duration = Duration::from_secs(30);
const USER_AUTOMATION_QUEUE_RESPONSE_TIMEOUT: Duration = Duration::from_secs(30);

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

struct HostUserAutomationExecutionReply {
    response: UserAutomationHostExecutionResponse,
    correlation: ResponseCorrelation,
}

/// One authenticated UserAutomation request waiting for the explicit Host
/// owner endpoint.  The request is retained until the owner returns a
/// correlated response; no queue consumer may replace its carrier.
pub struct HostUserAutomationExecutionEnvelope {
    request: UserAutomationHostExecutionRequest,
    session: UserAutomationHostExecutionSession,
    reply: oneshot::Sender<HostUserAutomationExecutionReply>,
    correlation: ResponseCorrelation,
}

impl HostUserAutomationExecutionEnvelope {
    /// Returns the exact authenticated carrier admitted by the transport.
    #[must_use]
    pub const fn request(&self) -> &UserAutomationHostExecutionRequest {
        &self.request
    }

    /// Returns the opaque server-authored session retained for this carrier.
    #[must_use]
    pub const fn session(&self) -> &UserAutomationHostExecutionSession {
        &self.session
    }

    /// Completes this request with a response bound to the same carrier.
    ///
    /// The transport performs a second validation before serializing the
    /// response, so a queue consumer cannot substitute another request's
    /// response without producing a fail-closed transport result.
    pub fn respond(
        self,
        response: UserAutomationHostExecutionResponse,
    ) -> Result<(), UserAutomationHostExecutionResponse> {
        self.reply
            .send(HostUserAutomationExecutionReply {
                response,
                correlation: self.correlation,
            })
            .map_err(|reply| reply.response)
    }
}

/// Bounded queue shared by the authenticated endpoint and the Host owner
/// contour.  It carries no fallback owner and never manufactures a Durable
/// Job or WakeIntent result.
pub type HostUserAutomationExecutionQueue =
    Arc<Mutex<VecDeque<HostUserAutomationExecutionEnvelope>>>;

/// Removes one queued UserAutomation carrier for an owner contour.
pub fn pop_user_automation_execution(
    queue: &HostUserAutomationExecutionQueue,
) -> Option<HostUserAutomationExecutionEnvelope> {
    queue.lock().ok()?.pop_front()
}

/// Returns an explicit unavailable response for every request while the
/// root-owned Durable Job gateway has not been composed.
///
/// This is a fail-closed boundary only.  It is deliberately separate from
/// [`process_user_automation_execution_queue`], which requires an explicit
/// typed Host endpoint and is the production owner integration point.
pub fn reject_unbound_user_automation_execution(queue: &HostUserAutomationExecutionQueue) -> usize {
    let mut rejected = 0;
    while let Some(envelope) = pop_user_automation_execution(queue) {
        let response = UserAutomationHostExecutionResponse::failed_for(
            envelope.request(),
            UserAutomationRuntimeError::Unavailable(
                "Host UserAutomation owner is not composed".to_owned(),
            ),
        );
        let _ = envelope.respond(response);
        rejected += 1;
    }
    rejected
}

/// Processes all currently queued UserAutomation carriers through the
/// explicit owner endpoint.  Callers must supply a concrete
/// [`UserAutomationHostExecutionEndpoint`] whose Durable Job and Wake ports
/// are already bound to their canonical owners.
pub async fn process_user_automation_execution_queue<D, W>(
    queue: &HostUserAutomationExecutionQueue,
    endpoint: &UserAutomationHostExecutionEndpoint<D, W>,
) -> usize
where
    D: eliot_host_service::UserAutomationDurableJobPort,
    W: eliot_host_service::UserAutomationWakePort,
{
    let mut processed = 0;
    while let Some(envelope) = pop_user_automation_execution(queue) {
        let response = endpoint
            .execute_authenticated_response(envelope.request.clone(), envelope.session.clone())
            .await;
        let _ = envelope.respond(response);
        processed += 1;
    }
    processed
}

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
    user_automation_queue: HostUserAutomationExecutionQueue,
    user_automation_owner: Option<UserAutomationHostOwnerBinding>,
}

impl HostRuntimeControl {
    pub fn new_with_capability(
        queue: HostRuntimeControlQueue,
        capability: &eliot_platform_windows::HostOwnerEpochCapability,
    ) -> Result<Self, String> {
        Self::new_with_capability_and_user_automation(
            queue,
            Arc::new(Mutex::new(VecDeque::new())),
            capability,
        )
    }

    /// Creates the endpoint with both the existing runtime-control queue and
    /// the typed UserAutomation owner queue.
    pub fn new_with_capability_and_user_automation(
        queue: HostRuntimeControlQueue,
        user_automation_queue: HostUserAutomationExecutionQueue,
        capability: &eliot_platform_windows::HostOwnerEpochCapability,
    ) -> Result<Self, String> {
        let _guard = capability
            .live_guard()
            .map_err(|_| "Host owner capability is not live".to_owned())?;
        Ok(Self {
            queue,
            user_automation_queue,
            user_automation_owner: None,
        })
    }

    /// Creates the runtime-control endpoint with the retained Kernel owner
    /// anchor used to authenticate UserAutomation carriers before enqueue.
    pub fn new_with_capability_and_user_automation_bound(
        queue: HostRuntimeControlQueue,
        user_automation_queue: HostUserAutomationExecutionQueue,
        capability: &eliot_platform_windows::HostOwnerEpochCapability,
        owner: UserAutomationHostOwnerBinding,
    ) -> Result<Self, String> {
        let _guard = capability
            .live_guard()
            .map_err(|_| "Host owner capability is not live".to_owned())?;
        owner.validate().map_err(|error| error.to_string())?;
        Ok(Self {
            queue,
            user_automation_queue,
            user_automation_owner: Some(owner),
        })
    }

    pub fn queue(&self) -> HostRuntimeControlQueue {
        Arc::clone(&self.queue)
    }

    /// Returns the bounded typed UserAutomation owner queue.
    pub fn user_automation_queue(&self) -> HostUserAutomationExecutionQueue {
        Arc::clone(&self.user_automation_queue)
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

    async fn handle_user_automation(
        &self,
        request: UserAutomationHostExecutionRequest,
        server: &NamedPipeServer,
        channel: UserAutomationHostChannelBinding,
    ) -> UserAutomationHostExecutionResponse {
        let Some(owner) = self.user_automation_owner.as_ref() else {
            return UserAutomationHostExecutionResponse::failed_for(
                &request,
                UserAutomationRuntimeError::Unavailable(
                    "Host UserAutomation owner is not composed".to_owned(),
                ),
            );
        };
        let session = match UserAutomationHostExecutionSession::issue(
            channel,
            request.request_sha256.clone(),
            server.peer_identity().clone(),
            owner.clone(),
        ) {
            Ok(session) => session,
            Err(error) => {
                return UserAutomationHostExecutionResponse::failed_for(&request, error);
            }
        };
        if session.authorize_request(&request).is_err() {
            return UserAutomationHostExecutionResponse::failed_for(
                &request,
                UserAutomationRuntimeError::IdentityConflict,
            );
        }
        let (reply, response) = oneshot::channel();
        let correlation = ResponseCorrelation(Arc::new(()));
        {
            let Ok(mut queue) = self.user_automation_queue.lock() else {
                return UserAutomationHostExecutionResponse::failed_for(
                    &request,
                    UserAutomationRuntimeError::Unavailable(
                        "UserAutomation owner queue lock is poisoned".to_owned(),
                    ),
                );
            };
            if queue.len() >= MAX_QUEUE_DEPTH {
                return UserAutomationHostExecutionResponse::failed_for(
                    &request,
                    UserAutomationRuntimeError::Rejected(
                        "UserAutomation owner queue is full".to_owned(),
                    ),
                );
            }
            // This endpoint is only the authenticated queue boundary. It is
            // neither a durable mutation owner nor a replay ledger: an exact
            // retry after an UnknownOutcome must reach the canonical Store or
            // Host journal owner, including after this process restarts.
            queue.push_back(HostUserAutomationExecutionEnvelope {
                request: request.clone(),
                session,
                reply,
                correlation: correlation.clone(),
            });
        }
        match tokio::time::timeout(USER_AUTOMATION_QUEUE_RESPONSE_TIMEOUT, response).await {
            Ok(Ok(reply))
                if Arc::ptr_eq(&correlation.0, &reply.correlation.0)
                    && reply.response.validate_for(&request).is_ok() =>
            {
                reply.response
            }
            Ok(Ok(_)) => UserAutomationHostExecutionResponse::failed_for(
                &request,
                UserAutomationRuntimeError::IdentityConflict,
            ),
            Ok(Err(_)) | Err(_) => UserAutomationHostExecutionResponse::failed_for(
                &request,
                UserAutomationRuntimeError::UnknownOutcome(
                    "UserAutomation owner response crossed an unknown boundary".to_owned(),
                ),
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
        if let Ok(open_id) = decode_user_automation_host_execution_open_frame(&frame) {
            let owner = self
                .user_automation_owner
                .as_ref()
                .ok_or_else(|| "Host UserAutomation owner is not composed".to_owned())?;
            let channel = UserAutomationHostChannelBinding::issue_server_authored(
                server.peer_identity(),
                owner,
            )
            .map_err(|error| error.to_string())?;
            let open_response =
                user_automation_host_execution_open_response_frame(&open_id, &channel)
                    .map_err(|error| error.to_string())?;
            server
                .send_frame(&open_response, limits)
                .await
                .map_err(|error| error.to_string())?;
            let request_frame = server
                .receive_frame(limits)
                .await
                .map_err(|error| error.to_string())?;
            let request = decode_user_automation_host_execution_request_frame(&request_frame)
                .map_err(|error| error.to_string())?;
            let response = self
                .handle_user_automation(request.clone(), &server, channel)
                .await;
            let response_frame = user_automation_host_execution_response_frame(&request, &response)
                .map_err(|error| error.to_string())?;
            server
                .send_frame(&response_frame, limits)
                .await
                .map_err(|error| error.to_string())?;
            return Ok(());
        }
        let connection_id = frame.connection_id.clone();
        let response_frame = match decode_runtime_control_request_frame(&frame) {
            Ok(request) => {
                let response = self.handle(&request).await;
                runtime_control_response_frame(connection_id, &response)?
            }
            Err(_) => {
                let request = decode_user_automation_host_execution_request_frame(&frame)
                    .map_err(|error| error.to_string())?;
                let response = UserAutomationHostExecutionResponse::failed_for(
                    &request,
                    UserAutomationRuntimeError::IdentityConflict,
                );
                user_automation_host_execution_response_frame(&request, &response)
                    .map_err(|error| error.to_string())?
            }
        };
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
