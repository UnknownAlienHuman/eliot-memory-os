//! Authenticated Kernel-to-Host client for UserAutomation execution owners.
//!
//! The client carries only closed, typed projections.  The authenticated
//! transport supplies the existing connection, descriptor, peer-admission
//! receipt, and State Fence binding; this module does not mint a grant,
//! scheduler identity, Durable Job identity, or Host journal record.

use std::collections::BTreeSet;

use eliot_contracts::{StateFence, canonical_json_bytes, sha256_hex};
use eliot_kernel_core::user_automation::AutomationExecutionReference;
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
}

impl UserAutomationHostExecutionResponse {
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
        Ok(response)
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
