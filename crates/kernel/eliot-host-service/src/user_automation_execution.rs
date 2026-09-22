//! Host endpoint for the typed `UserAutomation` execution carrier.
//!
//! Root-owned authenticated channel routing calls this endpoint after the
//! existing Kernel-to-Host session has been accepted.  The endpoint verifies
//! the retained channel binding and delegates to the concrete Durable Job and
//! Host journal adapters; it owns no dispatch table or lifecycle state.

use eliot_kernel_service::{
    UserAutomationDurableJobPort, UserAutomationHostChannelBinding,
    UserAutomationHostExecutionOperation, UserAutomationHostExecutionRequest,
    UserAutomationHostExecutionResponse, UserAutomationRuntimeError, UserAutomationWakePort,
};

/// Host-side typed endpoint over the existing Durable Job and `WakeIntent`
/// owners.
pub struct UserAutomationHostExecutionEndpoint<D, W> {
    channel: UserAutomationHostChannelBinding,
    durable_job: D,
    wake: W,
}

impl<D, W> UserAutomationHostExecutionEndpoint<D, W>
where
    D: UserAutomationDurableJobPort,
    W: UserAutomationWakePort,
{
    /// Composes the endpoint with already-owned runtime adapters and the exact
    /// authenticated channel binding retained by root composition.
    pub fn new(
        channel: UserAutomationHostChannelBinding,
        durable_job: D,
        wake: W,
    ) -> Result<Self, UserAutomationRuntimeError> {
        channel.validate()?;
        Ok(Self {
            channel,
            durable_job,
            wake,
        })
    }

    /// Handles one authenticated typed carrier and returns a correlated
    /// response.  A channel or carrier mismatch is rejected before an owner
    /// call.
    pub async fn execute(
        &self,
        request: UserAutomationHostExecutionRequest,
    ) -> Result<UserAutomationHostExecutionResponse, UserAutomationRuntimeError> {
        request.validate()?;
        if request.channel != self.channel {
            return Err(UserAutomationRuntimeError::IdentityConflict);
        }
        let request_sha256 = request.request_sha256.clone();
        let state_fence = request.channel.state_fence.clone();
        match request.operation {
            UserAutomationHostExecutionOperation::AdmitOccurrence { request } => {
                let execution = self.durable_job.admit_occurrence(request).await?;
                Ok(UserAutomationHostExecutionResponse::Admitted {
                    request_sha256,
                    state_fence,
                    execution,
                })
            }
            UserAutomationHostExecutionOperation::CancelPendingWakes { request } => {
                let wake_ids = self.wake.cancel_pending_wakes(request).await?;
                Ok(UserAutomationHostExecutionResponse::Cancelled {
                    request_sha256,
                    state_fence,
                    wake_ids,
                })
            }
        }
    }

    /// Handles one carrier while preserving owner failures as a correlated
    /// typed response for the authenticated transport.
    pub async fn execute_response(
        &self,
        request: UserAutomationHostExecutionRequest,
    ) -> UserAutomationHostExecutionResponse {
        match self.execute(request.clone()).await {
            Ok(response) => response,
            Err(error) => UserAutomationHostExecutionResponse::failed_for(&request, error),
        }
    }

    /// Returns the exact channel binding accepted by this endpoint.
    #[must_use]
    pub const fn channel(&self) -> &UserAutomationHostChannelBinding {
        &self.channel
    }
}
