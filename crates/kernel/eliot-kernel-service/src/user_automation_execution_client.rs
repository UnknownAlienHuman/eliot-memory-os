//! Authenticated Kernel-to-Host client for UserAutomation execution owners.
//!
//! The client carries only closed, typed projections.  The authenticated
//! transport supplies the existing connection, descriptor, peer-admission
//! receipt, and State Fence binding; this module does not mint a grant,
//! scheduler identity, Durable Job identity, or Host journal record.

use std::collections::BTreeSet;
#[cfg(windows)]
use std::time::Duration;

use eliot_contracts::{RequestId, RequestMetadata, StateFence, canonical_json_bytes, sha256_hex};
use eliot_kernel_core::user_automation::AutomationExecutionReference;
#[cfg(windows)]
use eliot_ipc::{DeliveryOutcome, NamedPipeTransport, TransportLimits};
use eliot_protocol::{EncodingProfile, Frame, FrameKind, MessageType, ProtocolPayload,
    ProtocolVersion, RequestIdentity};
use eliot_receipts::RequestBinding;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::{
    UserAutomationDurableJobPort, UserAutomationRuntimeAdmission, UserAutomationRuntimeError,
    UserAutomationWakeCancellation, UserAutomationWakePort,
};

/// Stable wire identity for the typed UserAutomation Host execution carrier.
pub const USER_AUTOMATION_HOST_EXECUTION_WIRE_ID: &str = "eliot.user_automation.host_execution";
/// Current semantic revision of the typed UserAutomation Host execution wire.
pub const USER_AUTOMATION_HOST_EXECUTION_WIRE_VERSION: u16 = 1;
/// Authenticated Kernel front-door module identity used by the Host owner join.
///
/// This is a transport principal only.  The Kernel derives its requester role
/// from this authenticated session and still validates the typed Dreamer
/// operation and State Fence before calling the canonical Store gateway.
pub const USER_AUTOMATION_KERNEL_MODULE_ID: &str = "eliot-host-user-automation";
/// Shared least-privilege capability advertised by the Host owner session.
pub const USER_AUTOMATION_KERNEL_CAPABILITY: &str = "eliot.kernel.dreamer-job";
/// Stable server principal projection for the Host owner session.
pub const USER_AUTOMATION_KERNEL_PRINCIPAL_BINDING: &str =
    "eliot-kernel::host-user-automation:v1";
/// Existing authenticated Host runtime-control pipe carrying this typed route.
pub const USER_AUTOMATION_HOST_EXECUTION_PIPE: &str =
    r"\\.\pipe\eliot\host\runtime-control-v1";
const USER_AUTOMATION_HOST_EXECUTION_TRACE_KEY: &str =
    "eliot.user_automation.host-execution-discriminator";
const USER_AUTOMATION_HOST_EXECUTION_TRACE_VALUE: &str =
    "eliot-user-automation::host-execution:v1";

/// Evidence binding supplied by the already authenticated Kernel-to-Host
/// channel.
///
/// These values are transport evidence and selectors only.  They must be
/// copied from the existing authenticated route and never manufactured by a
/// UserAutomation caller.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserAutomationHostChannelBinding {
    /// Kernel-created identity of the authenticated transport connection.
    pub connection_id: String,
    /// Digest of the immutable Kernel/Host admission descriptor.
    pub descriptor_sha256: String,
    /// Digest of the authenticated peer-admission receipt.
    pub peer_admission_receipt_sha256: String,
    /// Fence observed by the authenticated channel.
    pub state_fence: StateFence,
}

impl UserAutomationHostChannelBinding {
    /// Validates the shape and fence of retained channel evidence.
    pub fn validate(&self) -> Result<(), UserAutomationRuntimeError> {
        validate_text(&self.connection_id, "channel.connection_id")?;
        validate_sha256(&self.descriptor_sha256, "channel.descriptor_sha256")?;
        validate_sha256(
            &self.peer_admission_receipt_sha256,
            "channel.peer_admission_receipt_sha256",
        )?;
        self.state_fence
            .validate()
            .map_err(|error| rejected(format!("channel state fence: {error}")))
    }
}

/// Closed failure projection returned by the Host endpoint when an owner
/// cannot complete the typed operation. A transport failure remains outside
/// this enum and is classified as an unknown outcome by the client.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind", deny_unknown_fields)]
pub enum UserAutomationHostExecutionFailure {
    /// The Host owner is not currently available.
    Unavailable {
        /// Closed reason supplied by the Host owner.
        reason: String,
    },
    /// The owner may have committed and the result must be reconciled.
    UnknownOutcome {
        /// Closed reason supplied by the Host owner.
        reason: String,
    },
    /// The typed request was rejected before an owner effect.
    Rejected {
        /// Closed reason supplied by the Host owner.
        reason: String,
    },
    /// The response was bound to another request or fence.
    IdentityConflict,
}

impl UserAutomationHostExecutionFailure {
    fn from_runtime_error(error: UserAutomationRuntimeError) -> Self {
        match error {
            UserAutomationRuntimeError::Unavailable(reason) => Self::Unavailable { reason },
            UserAutomationRuntimeError::UnknownOutcome(reason) => {
                Self::UnknownOutcome { reason }
            }
            UserAutomationRuntimeError::Rejected(reason) => Self::Rejected { reason },
            UserAutomationRuntimeError::IdentityConflict => Self::IdentityConflict,
        }
    }

    fn into_runtime_error(self) -> UserAutomationRuntimeError {
        match self {
            Self::Unavailable { reason } => UserAutomationRuntimeError::Unavailable(reason),
            Self::UnknownOutcome { reason } => {
                UserAutomationRuntimeError::UnknownOutcome(reason)
            }
            Self::Rejected { reason } => UserAutomationRuntimeError::Rejected(reason),
            Self::IdentityConflict => UserAutomationRuntimeError::IdentityConflict,
        }
    }

    fn validate(&self) -> Result<(), UserAutomationRuntimeError> {
        match self {
            Self::Unavailable { reason }
            | Self::UnknownOutcome { reason }
            | Self::Rejected { reason } => validate_text(reason, "failure.reason"),
            Self::IdentityConflict => Ok(()),
        }
    }
}

/// One typed UserAutomation execution operation sent over the authenticated
/// Host channel.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "operation", deny_unknown_fields)]
pub enum UserAutomationHostExecutionOperation {
    /// Admit one owner-issued occurrence to the existing Durable Job owner.
    AdmitOccurrence {
        /// Authenticated, preflight-approved occurrence admission.
        request: UserAutomationRuntimeAdmission,
    },
    /// Cancel exact owner-issued future wake targets.
    CancelPendingWakes {
        /// Same-fence, unadmitted-only cancellation request.
        request: UserAutomationWakeCancellation,
    },
}

/// Typed Kernel-to-Host request carrier for one UserAutomation execution
/// operation.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserAutomationHostExecutionRequest {
    /// Stable carrier wire identity.
    pub wire_id: String,
    /// Carrier semantic revision.
    pub wire_version: u16,
    /// Existing authenticated channel evidence.
    pub channel: UserAutomationHostChannelBinding,
    /// Closed operation payload.
    pub operation: UserAutomationHostExecutionOperation,
    /// Lowercase SHA-256 over the carrier with this field empty.
    pub request_sha256: String,
}

impl UserAutomationHostExecutionRequest {
    /// Builds and hashes one typed admission carrier.
    pub fn admit_occurrence(
        channel: UserAutomationHostChannelBinding,
        request: UserAutomationRuntimeAdmission,
    ) -> Result<Self, UserAutomationRuntimeError> {
        Self::new(
            channel,
            UserAutomationHostExecutionOperation::AdmitOccurrence { request },
        )
    }

    /// Builds and hashes one typed wake-cancellation carrier.
    pub fn cancel_pending_wakes(
        channel: UserAutomationHostChannelBinding,
        request: UserAutomationWakeCancellation,
    ) -> Result<Self, UserAutomationRuntimeError> {
        Self::new(
            channel,
            UserAutomationHostExecutionOperation::CancelPendingWakes { request },
        )
    }

    fn new(
        channel: UserAutomationHostChannelBinding,
        operation: UserAutomationHostExecutionOperation,
    ) -> Result<Self, UserAutomationRuntimeError> {
        let value = Self {
            wire_id: USER_AUTOMATION_HOST_EXECUTION_WIRE_ID.to_owned(),
            wire_version: USER_AUTOMATION_HOST_EXECUTION_WIRE_VERSION,
            channel,
            operation,
            request_sha256: String::new(),
        };
        value.validate_without_digest()?;
        let request_sha256 = value.compute_digest()?;
        let value = Self {
            request_sha256,
            ..value
        };
        value.validate()?;
        Ok(value)
    }

    /// Validates the complete typed carrier and its canonical digest.
    pub fn validate(&self) -> Result<(), UserAutomationRuntimeError> {
        self.validate_without_digest()?;
        validate_sha256(&self.request_sha256, "request_sha256")?;
        let expected = self.compute_digest()?;
        if self.request_sha256 != expected {
            return Err(rejected("UserAutomation Host request digest mismatch"));
        }
        Ok(())
    }

    /// Returns the canonical digest used for response correlation.
    pub fn compute_digest(&self) -> Result<String, UserAutomationRuntimeError> {
        let mut unsigned = self.clone();
        unsigned.request_sha256.clear();
        let bytes = canonical_json_bytes(&unsigned)
            .map_err(|error| rejected(format!("UserAutomation Host request encoding: {error}")))?;
        Ok(sha256_hex(&bytes))
    }

    /// Returns the request State Fence without interpreting the operation.
    #[must_use]
    pub fn state_fence(&self) -> &StateFence {
        &self.channel.state_fence
    }

    fn validate_without_digest(&self) -> Result<(), UserAutomationRuntimeError> {
        if self.wire_id != USER_AUTOMATION_HOST_EXECUTION_WIRE_ID
            || self.wire_version != USER_AUTOMATION_HOST_EXECUTION_WIRE_VERSION
        {
            return Err(rejected("unsupported UserAutomation Host execution wire"));
        }
        self.channel.validate()?;
        match &self.operation {
            UserAutomationHostExecutionOperation::AdmitOccurrence { request } => {
                request
                    .validate()
                    .map_err(|error| rejected(format!("Durable Job admission: {error}")))?;
                if request.durable_job.is_none() {
                    return Err(rejected(
                        "concrete Host Durable Job admission requires owner-issued material",
                    ));
                }
                if request.context.state_fence != self.channel.state_fence {
                    return Err(rejected("admission channel fence mismatch"));
                }
            }
            UserAutomationHostExecutionOperation::CancelPendingWakes { request } => {
                request
                    .validate()
                    .map_err(|error| rejected(format!("Wake cancellation: {error}")))?;
                if request.targets.is_empty() {
                    return Err(rejected(
                        "concrete Host wake cancellation requires owner-issued targets",
                    ));
                }
                if request.state_fence != self.channel.state_fence {
                    return Err(rejected("cancellation channel fence mismatch"));
                }
            }
        }
        Ok(())
    }
}

/// Typed response returned by the Host execution endpoint.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "result", deny_unknown_fields)]
pub enum UserAutomationHostExecutionResponse {
    /// Durable Job admission result.
    Admitted {
        /// Digest of the exact request carrier answered.
        request_sha256: String,
        /// Fence observed by the Host owner.
        state_fence: StateFence,
        /// Existing Durable Job projection.
        execution: AutomationExecutionReference,
    },
    /// Wake cancellation result.
    Cancelled {
        /// Digest of the exact request carrier answered.
        request_sha256: String,
        /// Fence observed by the Host owner.
        state_fence: StateFence,
        /// Exact wake identities whose cancellation was committed or replayed.
        wake_ids: Vec<String>,
    },
    /// Closed Host-owner failure projection.
    Failed {
        /// Digest of the exact request carrier answered.
        request_sha256: String,
        /// Fence observed while producing the failure projection.
        state_fence: StateFence,
        /// Typed failure class; no success is inferred from an error response.
        failure: UserAutomationHostExecutionFailure,
    },
}

impl UserAutomationHostExecutionResponse {
    /// Builds a failure response bound to the exact request carrier.
    #[must_use]
    pub fn failed_for(
        request: &UserAutomationHostExecutionRequest,
        error: UserAutomationRuntimeError,
    ) -> Self {
        Self::Failed {
            request_sha256: request.request_sha256.clone(),
            state_fence: request.channel.state_fence.clone(),
            failure: UserAutomationHostExecutionFailure::from_runtime_error(error),
        }
    }

    /// Validates one response against its exact carrier and operation.
    pub fn validate_for(
        &self,
        request: &UserAutomationHostExecutionRequest,
    ) -> Result<(), UserAutomationRuntimeError> {
        request.validate()?;
        let (request_sha256, state_fence) = match self {
            Self::Admitted {
                request_sha256,
                state_fence,
                ..
            }
            | Self::Cancelled {
                request_sha256,
                state_fence,
                ..
            } => (request_sha256, state_fence),
            Self::Failed {
                request_sha256,
                state_fence,
                failure,
            } => {
                failure.validate()?;
                (request_sha256, state_fence)
            }
        };
        if request_sha256 != &request.request_sha256 || state_fence != request.state_fence() {
            return Err(UserAutomationRuntimeError::IdentityConflict);
        }
        match (&request.operation, self) {
            (
                UserAutomationHostExecutionOperation::AdmitOccurrence { request },
                Self::Admitted { execution, .. },
            ) => {
                let occurrence_id = request
                    .invocation
                    .occurrence_identity()
                    .map_err(|error| rejected(format!("occurrence identity: {error}")))?;
                execution
                    .validate()
                    .map_err(|error| rejected(format!("execution reference: {error}")))?;
                // `AutomationExecutionReference` has no fence field.  The
                // carrier fence above is the response fence; the stable
                // occurrence projection is checked here.
                if execution.occurrence_id != occurrence_id {
                    return Err(UserAutomationRuntimeError::IdentityConflict);
                }
                Ok(())
            }
            (
                UserAutomationHostExecutionOperation::CancelPendingWakes { .. },
                Self::Cancelled { wake_ids, .. },
            ) => validate_unique_text(wake_ids),
            (_, Self::Failed { .. }) => Ok(()),
            (
                UserAutomationHostExecutionOperation::AdmitOccurrence { .. },
                Self::Cancelled { .. },
            )
            | (
                UserAutomationHostExecutionOperation::CancelPendingWakes { .. },
                Self::Admitted { .. },
            ) => Err(UserAutomationRuntimeError::IdentityConflict),
        }
    }
}

/// Returns the metadata that binds the protocol frame to the typed carrier.
fn request_context(request: &UserAutomationHostExecutionRequest) -> &RequestMetadata {
    match &request.operation {
        UserAutomationHostExecutionOperation::AdmitOccurrence { request } => &request.context,
        UserAutomationHostExecutionOperation::CancelPendingWakes { request } => &request.context,
    }
}

fn frame_identity(
    request: &UserAutomationHostExecutionRequest,
) -> Result<(RequestId, RequestIdentity), UserAutomationRuntimeError> {
    let request_id = RequestId::new(request.request_sha256.clone())
        .map_err(|_| rejected("UserAutomation frame request identity is invalid"))?;
    let mut metadata = request_context(request).clone();
    metadata.request_id = request_id.clone();
    let identity = RequestIdentity {
        request: RequestBinding {
            metadata,
            state_fence: request.channel.state_fence.clone(),
        },
        idempotency_key: request.request_sha256.clone(),
        deadline_unix_ms: u64::MAX,
        cancellation_id: request.request_sha256.clone(),
    };
    identity
        .validate()
        .map_err(|_| rejected("UserAutomation frame identity is invalid"))?;
    Ok((request_id, identity))
}

fn frame_trace_context() -> std::collections::BTreeMap<String, String> {
    std::collections::BTreeMap::from([(
        USER_AUTOMATION_HOST_EXECUTION_TRACE_KEY.to_owned(),
        USER_AUTOMATION_HOST_EXECUTION_TRACE_VALUE.to_owned(),
    )])
}

fn validate_frame_trace_context(frame: &Frame) -> Result<(), UserAutomationRuntimeError> {
    if frame.trace_context.len() != 1
        || frame
            .trace_context
            .get(USER_AUTOMATION_HOST_EXECUTION_TRACE_KEY)
            .map(String::as_str)
            != Some(USER_AUTOMATION_HOST_EXECUTION_TRACE_VALUE)
    {
        return Err(rejected("UserAutomation frame trace discriminator is invalid"));
    }
    Ok(())
}

/// Serializes one typed UserAutomation request into an authenticated EBP
/// frame. The frame identity is derived from the carrier digest and the
/// carrier's existing metadata/fence; no authority is minted here.
pub fn user_automation_host_execution_request_frame(
    request: &UserAutomationHostExecutionRequest,
) -> Result<Frame, UserAutomationRuntimeError> {
    request.validate()?;
    let (request_id, request_identity) = frame_identity(request)?;
    let frame = Frame {
        protocol_version: ProtocolVersion::CURRENT,
        encoding_profile: EncodingProfile::JsonV1,
        connection_id: request.channel.connection_id.clone(),
        request_id: Some(request_id),
        kind: FrameKind::Request,
        message_type: MessageType::Execute,
        request_identity: Some(request_identity),
        payload: ProtocolPayload::Json(
            serde_json::to_value(request)
                .map_err(|_| rejected("UserAutomation request encoding failed"))?,
        ),
        trace_context: frame_trace_context(),
    };
    frame
        .validate()
        .map_err(|_| rejected("UserAutomation request frame is invalid"))?;
    Ok(frame)
}

/// Decodes and validates one typed UserAutomation request frame.
pub fn decode_user_automation_host_execution_request_frame(
    frame: &Frame,
) -> Result<UserAutomationHostExecutionRequest, UserAutomationRuntimeError> {
    frame
        .validate()
        .map_err(|_| rejected("UserAutomation request frame is invalid"))?;
    validate_frame_trace_context(frame)?;
    if frame.kind != FrameKind::Request || frame.message_type != MessageType::Execute {
        return Err(rejected("UserAutomation request frame kind is invalid"));
    }
    let ProtocolPayload::Json(payload) = &frame.payload else {
        return Err(rejected("UserAutomation request frame payload is invalid"));
    };
    let request: UserAutomationHostExecutionRequest = serde_json::from_value(payload.clone())
        .map_err(|_| rejected("UserAutomation request payload is undecodable"))?;
    request.validate()?;
    if frame.connection_id != request.channel.connection_id {
        return Err(UserAutomationRuntimeError::IdentityConflict);
    }
    let frame_request_id = frame
        .request_id
        .as_ref()
        .ok_or_else(|| rejected("UserAutomation request frame has no request id"))?;
    let identity = frame
        .request_identity
        .as_ref()
        .ok_or_else(|| rejected("UserAutomation request frame has no identity"))?;
    if frame_request_id.as_str() != request.request_sha256
        || identity.request.metadata.request_id != *frame_request_id
        || identity.request.state_fence != request.channel.state_fence
        || identity.idempotency_key != request.request_sha256
        || identity.cancellation_id != request.request_sha256
    {
        return Err(UserAutomationRuntimeError::IdentityConflict);
    }
    Ok(request)
}

/// Serializes one response against the exact request it answers.
pub fn user_automation_host_execution_response_frame(
    request: &UserAutomationHostExecutionRequest,
    response: &UserAutomationHostExecutionResponse,
) -> Result<Frame, UserAutomationRuntimeError> {
    response.validate_for(request)?;
    let (request_id, request_identity) = frame_identity(request)?;
    let frame = Frame {
        protocol_version: ProtocolVersion::CURRENT,
        encoding_profile: EncodingProfile::JsonV1,
        connection_id: request.channel.connection_id.clone(),
        request_id: Some(request_id),
        kind: FrameKind::Response,
        message_type: MessageType::Result,
        request_identity: Some(request_identity),
        payload: ProtocolPayload::Json(
            serde_json::to_value(response)
                .map_err(|_| rejected("UserAutomation response encoding failed"))?,
        ),
        trace_context: frame_trace_context(),
    };
    frame
        .validate()
        .map_err(|_| rejected("UserAutomation response frame is invalid"))?;
    Ok(frame)
}

/// Decodes one response and binds it to the exact request carrier.
pub fn decode_user_automation_host_execution_response_frame(
    frame: &Frame,
    request: &UserAutomationHostExecutionRequest,
) -> Result<UserAutomationHostExecutionResponse, UserAutomationRuntimeError> {
    frame
        .validate()
        .map_err(|_| rejected("UserAutomation response frame is invalid"))?;
    validate_frame_trace_context(frame)?;
    if frame.kind != FrameKind::Response || frame.message_type != MessageType::Result {
        return Err(rejected("UserAutomation response frame kind is invalid"));
    }
    if frame.connection_id != request.channel.connection_id {
        return Err(UserAutomationRuntimeError::IdentityConflict);
    }
    let ProtocolPayload::Json(payload) = &frame.payload else {
        return Err(rejected("UserAutomation response frame payload is invalid"));
    };
    let response: UserAutomationHostExecutionResponse = serde_json::from_value(payload.clone())
        .map_err(|_| rejected("UserAutomation response payload is undecodable"))?;
    response.validate_for(request)?;
    let frame_request_id = frame
        .request_id
        .as_ref()
        .ok_or_else(|| rejected("UserAutomation response frame has no request id"))?;
    let identity = frame
        .request_identity
        .as_ref()
        .ok_or_else(|| rejected("UserAutomation response frame has no identity"))?;
    if frame_request_id.as_str() != request.request_sha256
        || identity.request.metadata.request_id != *frame_request_id
        || identity.request.state_fence != request.channel.state_fence
        || identity.idempotency_key != request.request_sha256
        || identity.cancellation_id != request.request_sha256
    {
        return Err(UserAutomationRuntimeError::IdentityConflict);
    }
    Ok(response)
}

/// Authenticated typed transport used by the Kernel execution client.
///
/// Implementations are composed from the existing authenticated Kernel-to-Host
/// channel.  They must reject an unauthenticated peer before invoking the Host
/// endpoint and must preserve unknown transport outcomes as
/// [`UserAutomationRuntimeError::UnknownOutcome`].
#[allow(async_fn_in_trait)]
pub trait UserAutomationHostExecutionTransport: Send + Sync {
    /// Returns the exact channel evidence retained after authentication.
    fn channel_binding(&self) -> &UserAutomationHostChannelBinding;

    /// Sends one typed carrier to the authenticated Host endpoint.
    async fn execute(
        &self,
        request: UserAutomationHostExecutionRequest,
    ) -> Result<UserAutomationHostExecutionResponse, UserAutomationRuntimeError>;
}

/// Concrete Windows transport for the authenticated Kernel-to-Host execution
/// route. The named pipe remains the only transport owner; the mutex only
/// serializes request/response frames on one connection.
#[cfg(windows)]
pub struct AuthenticatedUserAutomationHostExecutionTransport {
    channel: UserAutomationHostChannelBinding,
    transport: tokio::sync::Mutex<NamedPipeTransport>,
    limits: TransportLimits,
}

#[cfg(windows)]
impl AuthenticatedUserAutomationHostExecutionTransport {
    /// Connects to the Host runtime-control pipe with the existing
    /// handle-bound builtin-administrator authentication policy.
    pub async fn connect(
        channel: UserAutomationHostChannelBinding,
        timeout: Duration,
    ) -> Result<Self, UserAutomationRuntimeError> {
        channel.validate()?;
        let transport = eliot_ipc::NamedPipeTransport::connect_authenticated_builtin_administrators(
            USER_AUTOMATION_HOST_EXECUTION_PIPE,
            timeout,
        )
        .await
        .map_err(|error| UserAutomationRuntimeError::Unavailable(error.to_string()))?;
        Ok(Self {
            channel,
            transport: tokio::sync::Mutex::new(transport),
            limits: TransportLimits::default(),
        })
    }

    /// Returns the transport-level bounds used for every frame.
    #[must_use]
    pub const fn limits(&self) -> TransportLimits {
        self.limits
    }
}

#[cfg(windows)]
#[allow(async_fn_in_trait)]
impl UserAutomationHostExecutionTransport for AuthenticatedUserAutomationHostExecutionTransport {
    fn channel_binding(&self) -> &UserAutomationHostChannelBinding {
        &self.channel
    }

    async fn execute(
        &self,
        request: UserAutomationHostExecutionRequest,
    ) -> Result<UserAutomationHostExecutionResponse, UserAutomationRuntimeError> {
        if request.channel != self.channel {
            return Err(UserAutomationRuntimeError::IdentityConflict);
        }
        let frame = user_automation_host_execution_request_frame(&request)?;
        let mut transport = self.transport.lock().await;
        let outcome = transport
            .send_frame(&frame, self.limits)
            .await
            .map_err(|error| UserAutomationRuntimeError::UnknownOutcome(error.to_string()))?;
        if outcome != DeliveryOutcome::Delivered {
            return Err(UserAutomationRuntimeError::UnknownOutcome(
                "UserAutomation request delivery crossed an unknown boundary".to_owned(),
            ));
        }
        let response_frame = transport
            .receive_frame(self.limits)
            .await
            .map_err(|error| UserAutomationRuntimeError::UnknownOutcome(error.to_string()))?;
        decode_user_automation_host_execution_response_frame(&response_frame, &request)
    }
}

/// Kernel-side client implementing both UserAutomation runtime owner ports.
pub struct UserAutomationHostExecutionClient<T> {
    transport: T,
}

impl<T> UserAutomationHostExecutionClient<T>
where
    T: UserAutomationHostExecutionTransport,
{
    /// Binds the client to one already authenticated Host channel.
    pub fn new(transport: T) -> Result<Self, UserAutomationRuntimeError> {
        transport.channel_binding().validate()?;
        Ok(Self { transport })
    }

    /// Returns the composed transport for root-owned channel integration.
    #[must_use]
    pub const fn transport(&self) -> &T {
        &self.transport
    }

    async fn execute(
        &self,
        request: UserAutomationHostExecutionRequest,
    ) -> Result<UserAutomationHostExecutionResponse, UserAutomationRuntimeError> {
        let response = self.transport.execute(request.clone()).await?;
        response.validate_for(&request)?;
        match response {
            UserAutomationHostExecutionResponse::Failed { failure, .. } => {
                Err(failure.into_runtime_error())
            }
            response => Ok(response),
        }
    }
}

impl<T> UserAutomationDurableJobPort for UserAutomationHostExecutionClient<T>
where
    T: UserAutomationHostExecutionTransport,
{
    async fn admit_occurrence(
        &self,
        request: UserAutomationRuntimeAdmission,
    ) -> Result<AutomationExecutionReference, UserAutomationRuntimeError> {
        let carrier = UserAutomationHostExecutionRequest::admit_occurrence(
            self.transport.channel_binding().clone(),
            request,
        )?;
        match self.execute(carrier).await? {
            UserAutomationHostExecutionResponse::Admitted { execution, .. } => Ok(execution),
            UserAutomationHostExecutionResponse::Cancelled { .. } => {
                Err(UserAutomationRuntimeError::IdentityConflict)
            }
            UserAutomationHostExecutionResponse::Failed { failure, .. } => {
                Err(failure.into_runtime_error())
            }
        }
    }
}

impl<T> UserAutomationWakePort for UserAutomationHostExecutionClient<T>
where
    T: UserAutomationHostExecutionTransport,
{
    async fn cancel_pending_wakes(
        &self,
        request: UserAutomationWakeCancellation,
    ) -> Result<Vec<String>, UserAutomationRuntimeError> {
        let carrier = UserAutomationHostExecutionRequest::cancel_pending_wakes(
            self.transport.channel_binding().clone(),
            request,
        )?;
        match self.execute(carrier).await? {
            UserAutomationHostExecutionResponse::Cancelled { wake_ids, .. } => Ok(wake_ids),
            UserAutomationHostExecutionResponse::Admitted { .. } => {
                Err(UserAutomationRuntimeError::IdentityConflict)
            }
            UserAutomationHostExecutionResponse::Failed { failure, .. } => {
                Err(failure.into_runtime_error())
            }
        }
    }
}

fn rejected(reason: impl Into<String>) -> UserAutomationRuntimeError {
    UserAutomationRuntimeError::Rejected(reason.into())
}

fn validate_text(value: &str, field: &'static str) -> Result<(), UserAutomationRuntimeError> {
    if value.trim().is_empty() || value.chars().any(char::is_control) {
        return Err(rejected(format!("{field} is invalid")));
    }
    Ok(())
}

fn validate_sha256(value: &str, field: &'static str) -> Result<(), UserAutomationRuntimeError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(rejected(format!("{field} must be lowercase sha256")));
    }
    Ok(())
}

fn validate_unique_text(values: &[String]) -> Result<(), UserAutomationRuntimeError> {
    let mut unique = BTreeSet::new();
    for value in values {
        validate_text(value, "wake_id")?;
        if !unique.insert(value.as_str()) {
            return Err(rejected("duplicate wake cancellation identity"));
        }
    }
    Ok(())
}
