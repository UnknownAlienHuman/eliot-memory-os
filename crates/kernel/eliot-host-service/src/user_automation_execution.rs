//! Host endpoint for the typed `UserAutomation` execution carrier.
//!
//! Root-owned authenticated channel routing calls this endpoint after the
//! existing Kernel-to-Host session has been accepted.  The endpoint verifies
//! the retained channel binding and delegates to the concrete Durable Job and
//! Host journal adapters; it owns no dispatch table or lifecycle state.

use eliot_contracts::StateFence;
use eliot_kernel_service::{
    UserAutomationDurableJobPort, UserAutomationHostChannelBinding,
    UserAutomationHostExecutionOperation, UserAutomationHostExecutionRequest,
    UserAutomationHostExecutionResponse, UserAutomationHostExecutionSession,
    UserAutomationHostOwnerBinding, UserAutomationRuntimeError, UserAutomationWakePort,
};

/// Host-side typed endpoint over the existing Durable Job and `WakeIntent`
/// owners.
pub struct UserAutomationHostExecutionEndpoint<D, W> {
    channel: Option<UserAutomationHostChannelBinding>,
    owner: Option<UserAutomationHostOwnerBinding>,
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
            channel: Some(channel),
            owner: None,
            durable_job,
            wake,
        })
    }

    /// Composes the production endpoint with the retained Host owner anchor.
    /// Incoming carrier channel fields remain correlation data; the opaque
    /// server session is the admission proof used before either owner call.
    pub fn new_with_owner_binding(
        owner: UserAutomationHostOwnerBinding,
        durable_job: D,
        wake: W,
    ) -> Result<Self, UserAutomationRuntimeError> {
        owner.validate()?;
        Ok(Self {
            channel: None,
            owner: Some(owner),
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
        if self
            .channel
            .as_ref()
            .is_some_and(|channel| request.channel != *channel)
        {
            return Err(UserAutomationRuntimeError::IdentityConflict);
        }
        if self.owner.is_some() {
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
            UserAutomationHostExecutionOperation::ReadPendingWake { request } => {
                let readback = self.wake.read_pending_wake(request).await?;
                Ok(UserAutomationHostExecutionResponse::WakeRead {
                    request_sha256,
                    state_fence,
                    readback,
                })
            }
            // Cancellation, enumeration, exact batch readback, and horizon
            // publication bind a server-authenticated channel. This convenience
            // dispatch has no server-authored session and cannot authorize any
            // of them.
            UserAutomationHostExecutionOperation::CancelPendingWakes { .. }
            | UserAutomationHostExecutionOperation::EnumeratePendingWakes { .. }
            | UserAutomationHostExecutionOperation::ReadCancellationBatch { .. }
            | UserAutomationHostExecutionOperation::PublishOccurrenceWake { .. }
            | UserAutomationHostExecutionOperation::PublishWakeHorizon { .. }
            | UserAutomationHostExecutionOperation::ReadWakeHorizonPublication { .. } => {
                Err(UserAutomationRuntimeError::IdentityConflict)
            }
        }
    }

    /// Answers the two operations whose result is the wake owner's own retained
    /// journal record.
    ///
    /// The ordinary lookup and the manual publication are different owner calls
    /// over different request types, but the same kind of answer: the record this
    /// Host journal actually retains. Both project into the same correlated
    /// `WakeRead` response, so the correlation fields the transport requires are
    /// stamped in exactly one place and neither operation can answer with a
    /// response shape its carrier pairing does not admit.
    async fn dispatch_wake_read(
        &self,
        operation: UserAutomationHostExecutionOperation,
        request_sha256: String,
        state_fence: StateFence,
    ) -> Result<UserAutomationHostExecutionResponse, UserAutomationRuntimeError> {
        let readback = match operation {
            UserAutomationHostExecutionOperation::ReadPendingWake { request } => {
                self.wake.read_pending_wake(request).await?
            }
            UserAutomationHostExecutionOperation::PublishOccurrenceWake { request } => {
                self.wake.publish_occurrence_wake(request).await?
            }
            // The caller only routes the two record-bearing operations here; a
            // different owner effect reaching this seam is a dispatch defect and
            // is refused rather than answered with a foreign record.
            _ => return Err(UserAutomationRuntimeError::IdentityConflict),
        };
        Ok(UserAutomationHostExecutionResponse::WakeRead {
            request_sha256,
            state_fence,
            readback,
        })
    }

    /// Handles one carrier after the named-pipe server has attached its
    /// server-authored session. Foreign, replayed, or stale carriers are
    /// rejected before the Durable Job or Host journal owner is called.
    pub async fn execute_authenticated(
        &self,
        request: UserAutomationHostExecutionRequest,
        session: UserAutomationHostExecutionSession,
    ) -> Result<UserAutomationHostExecutionResponse, UserAutomationRuntimeError> {
        request.validate()?;
        let owner = self.owner.as_ref().ok_or_else(|| {
            UserAutomationRuntimeError::Unavailable(
                "UserAutomation endpoint has no retained owner binding".to_owned(),
            )
        })?;
        if session.owner() != owner {
            return Err(UserAutomationRuntimeError::IdentityConflict);
        }
        session.authorize_request(&request)?;
        let request_sha256 = request.request_sha256.clone();
        let state_fence = owner.state_fence.clone();
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
                let channel_binding_sha256 = session.authenticated_channel_binding_digest()?;
                let receipt = request
                    .enumeration_receipt
                    .as_deref()
                    .ok_or(UserAutomationRuntimeError::IdentityConflict)?;
                receipt
                    .validate_authenticated_channel(&channel_binding_sha256)
                    .map_err(|_| UserAutomationRuntimeError::IdentityConflict)?;
                let wake_ids = self.wake.cancel_pending_wakes(request).await?;
                Ok(UserAutomationHostExecutionResponse::Cancelled {
                    request_sha256,
                    state_fence,
                    wake_ids,
                })
            }
            // The two operations whose answer is the wake owner's own retained
            // journal record — the ordinary lookup and the manual publication —
            // share one dispatch arm and one response projection, because the
            // retained record is the proof in both cases. Their port methods and
            // request types differ, so only the projection is shared.
            operation @ (UserAutomationHostExecutionOperation::ReadPendingWake { .. }
            | UserAutomationHostExecutionOperation::PublishOccurrenceWake { .. }) => {
                self.dispatch_wake_read(operation, request_sha256, state_fence)
                    .await
            }
            UserAutomationHostExecutionOperation::EnumeratePendingWakes { request } => {
                let channel_binding_sha256 = session.authenticated_channel_binding_digest()?;
                let receipt = self
                    .wake
                    .enumerate_pending_wakes_authenticated(request, channel_binding_sha256)
                    .await?;
                Ok(UserAutomationHostExecutionResponse::WakeEnumeration {
                    request_sha256,
                    state_fence,
                    receipt: Box::new(receipt),
                })
            }
            UserAutomationHostExecutionOperation::ReadCancellationBatch { request } => {
                let channel_binding_sha256 = session.authenticated_channel_binding_digest()?;
                let readback = self
                    .wake
                    .read_cancellation_batch_authenticated(request, channel_binding_sha256.clone())
                    .await?;
                Ok(
                    UserAutomationHostExecutionResponse::WakeCancellationBatchReadback {
                        request_sha256,
                        state_fence,
                        authenticated_channel_binding_sha256: channel_binding_sha256,
                        readback: Box::new(readback),
                    },
                )
            }
            // Publication and its readback share one owner answer. The wake
            // owner is the sole writer of its journal, so the returned
            // acknowledgement is the owner's own accounting of the exact
            // requested occurrence set and nothing is inferred from the
            // request.
            UserAutomationHostExecutionOperation::PublishWakeHorizon { request } => {
                let publication = self.wake.publish_wake_horizon(request).await?;
                Ok(
                    UserAutomationHostExecutionResponse::WakeHorizonPublication {
                        request_sha256,
                        state_fence,
                        publication: Box::new(publication),
                    },
                )
            }
            UserAutomationHostExecutionOperation::ReadWakeHorizonPublication { request } => {
                let publication = self.wake.read_wake_horizon_publication(request).await?;
                Ok(
                    UserAutomationHostExecutionResponse::WakeHorizonPublication {
                        request_sha256,
                        state_fence,
                        publication: Box::new(publication),
                    },
                )
            }
        }
    }

    /// Correlated response form of [`Self::execute_authenticated`].
    pub async fn execute_authenticated_response(
        &self,
        request: UserAutomationHostExecutionRequest,
        session: UserAutomationHostExecutionSession,
    ) -> UserAutomationHostExecutionResponse {
        match self.execute_authenticated(request.clone(), session).await {
            Ok(response) => response,
            Err(error) => UserAutomationHostExecutionResponse::failed_for(&request, error),
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
    pub const fn channel(&self) -> Option<&UserAutomationHostChannelBinding> {
        self.channel.as_ref()
    }
}
