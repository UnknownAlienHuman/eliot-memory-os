//! Host-side Durable Job adapter for `UserAutomation` occurrences.
//!
//! This module is a thin owner join.  It validates the owner-issued typed
//! Durable Job material, calls the existing Kernel Store gateway, validates
//! the exact response, and projects the real job identity/state.  It owns no
//! queue, job journal, receipt, grant, or retry policy.

use eliot_contracts::RequestMetadata;
use eliot_kernel_service::{
    AutomationExecutionReference, UserAutomationDurableJobPort, UserAutomationRuntimeAdmission,
    UserAutomationHostExecutionSession, UserAutomationRuntimeError,
};
use eliot_protocol::dreamer_job::{DurableJobRequest, DurableJobResponse};
use thiserror::Error;

/// Error classes returned by the existing Durable Job owner.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum HostDurableJobOwnerError {
    /// The owner or its authenticated Store route is unavailable.
    #[error("Durable Job owner unavailable: {0}")]
    Unavailable(String),
    /// The owner cannot determine whether the submitted operation committed.
    #[error("Durable Job owner outcome is unknown: {0}")]
    UnknownOutcome(String),
    /// The owner rejected the typed request.
    #[error("Durable Job owner rejected the request: {0}")]
    Rejected(String),
}

/// Existing Durable Job owner called by [`HostDurableJobAdapter`].
#[allow(async_fn_in_trait)]
pub trait HostDurableJobOwner: Send + Sync {
    /// Submits the complete owner-issued request through the canonical owner.
    async fn dreamer_job(
        &self,
        context: &RequestMetadata,
        request: DurableJobRequest,
    ) -> Result<DurableJobResponse, HostDurableJobOwnerError>;

    /// Submits one request after the Host runtime-control endpoint has
    /// retained its server-authored authenticated Kernel session.  The
    /// default preserves the owner port for existing non-UserAutomation
    /// callers; the production Kernel front-door owner overrides it so the
    /// inbound peer/session is checked before opening the canonical route.
    async fn dreamer_job_authenticated(
        &self,
        context: &RequestMetadata,
        request: DurableJobRequest,
        _session: &UserAutomationHostExecutionSession,
    ) -> Result<DurableJobResponse, HostDurableJobOwnerError> {
        self.dreamer_job(context, request).await
    }
}

/// Concrete Host adapter over an existing Durable Job owner.
pub struct HostDurableJobAdapter<'a, O: ?Sized> {
    owner: &'a O,
    session: Option<UserAutomationHostExecutionSession>,
}

impl<'a, O: ?Sized> HostDurableJobAdapter<'a, O> {
    /// Borrows the canonical Durable Job owner without creating another
    /// lifecycle or persistence surface.
    #[must_use]
    pub const fn new(owner: &'a O) -> Self {
        Self {
            owner,
            session: None,
        }
    }

    /// Borrows the canonical owner and retains the opaque server-authored
    /// session for the authenticated UserAutomation call path.
    #[must_use]
    pub fn new_authenticated(
        owner: &'a O,
        session: UserAutomationHostExecutionSession,
    ) -> Self {
        Self {
            owner,
            session: Some(session),
        }
    }
}

impl<O: HostDurableJobOwner + ?Sized> UserAutomationDurableJobPort
    for HostDurableJobAdapter<'_, O>
{
    async fn admit_occurrence(
        &self,
        request: UserAutomationRuntimeAdmission,
    ) -> Result<AutomationExecutionReference, UserAutomationRuntimeError> {
        request
            .validate()
            .map_err(|error| rejected(format!("Durable Job admission: {error}")))?;
        let material = request.durable_job.as_ref().ok_or_else(|| {
            rejected("concrete Host Durable Job admission requires owner-issued material")
        })?;
        material
            .validate_for(
                &request.context,
                &request.authenticated_principal,
                &request.invocation,
            )
            .map_err(|error| rejected(format!("Durable Job material: {error}")))?;

        let response = match self.session.as_ref() {
            Some(session) => self
                .owner
                .dreamer_job_authenticated(
                    &request.context,
                    material.request.clone(),
                    session,
                )
                .await,
            None => self
                .owner
                .dreamer_job(&request.context, material.request.clone())
                .await,
        }
        .map_err(map_owner_error)?;
        response
            .validate_for(&material.request)
            .map_err(|error| rejected(format!("Durable Job response: {error}")))?;
        if response.scope.state_fence != request.context.state_fence {
            return Err(UserAutomationRuntimeError::IdentityConflict);
        }

        let execution = AutomationExecutionReference {
            occurrence_id: material.occurrence_id.clone(),
            durable_job_ref: response.job_id.as_str().to_owned(),
            state: response.state,
        };
        execution
            .validate()
            .map_err(|error| rejected(format!("execution reference: {error}")))?;
        Ok(execution)
    }
}

/// Production binding for the existing Kernel Store gateway's Durable Job
/// operation.  The gateway retains route, admission, fence, and EBP recovery
/// ownership; this implementation only exposes the owner call to the Host
/// adapter.
#[cfg(windows)]
impl HostDurableJobOwner for eliot_kernel_service::KernelStoreGateway {
    async fn dreamer_job(
        &self,
        context: &RequestMetadata,
        request: DurableJobRequest,
    ) -> Result<DurableJobResponse, HostDurableJobOwnerError> {
        self.dreamer_job(context, request)
            .await
            .map_err(classify_gateway_error)
    }
}

fn map_owner_error(error: HostDurableJobOwnerError) -> UserAutomationRuntimeError {
    match error {
        HostDurableJobOwnerError::Unavailable(reason) => {
            UserAutomationRuntimeError::Unavailable(reason)
        }
        HostDurableJobOwnerError::UnknownOutcome(reason) => {
            UserAutomationRuntimeError::UnknownOutcome(reason)
        }
        HostDurableJobOwnerError::Rejected(reason) => UserAutomationRuntimeError::Rejected(reason),
    }
}

#[cfg(windows)]
fn classify_gateway_error(reason: String) -> HostDurableJobOwnerError {
    let lower = reason.to_ascii_lowercase();
    if lower.contains("unknown")
        || lower.contains("reconcil")
        || lower.contains("outcome")
        || lower.contains("possibly effected")
    {
        HostDurableJobOwnerError::UnknownOutcome(reason)
    } else if lower.contains("unavailable")
        || lower.contains("transport")
        || lower.contains("named pipe")
        || lower.contains("not ready")
    {
        HostDurableJobOwnerError::Unavailable(reason)
    } else {
        HostDurableJobOwnerError::Rejected(reason)
    }
}

fn rejected(reason: impl Into<String>) -> UserAutomationRuntimeError {
    UserAutomationRuntimeError::Rejected(reason.into())
}
