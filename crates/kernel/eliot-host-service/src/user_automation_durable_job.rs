//! Host-side Durable Job adapter for `UserAutomation` occurrences.
//!
//! This module is a thin owner join.  It validates the owner-issued typed
//! Durable Job material, calls the existing Kernel Store gateway, validates
//! the exact response, and projects the real job identity/state.  It owns no
//! queue, job journal, receipt, grant, or retry policy.

use eliot_contracts::RequestMetadata;
use eliot_kernel_service::{
    AutomationExecutionReference, CommitRecoveryError, DreamerJobFailure,
    UserAutomationDurableJobPort, UserAutomationRuntimeAdmission, UserAutomationRuntimeError,
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
}

/// Concrete Host adapter over an existing Durable Job owner.
pub struct HostDurableJobAdapter<'a, O: ?Sized> {
    owner: &'a O,
}

impl<'a, O: ?Sized> HostDurableJobAdapter<'a, O> {
    /// Borrows the canonical Durable Job owner without creating another
    /// lifecycle or persistence surface.
    #[must_use]
    pub const fn new(owner: &'a O) -> Self {
        Self { owner }
    }
}

impl<O: HostDurableJobOwner + ?Sized> UserAutomationDurableJobPort
    for HostDurableJobAdapter<'_, O>
{
    async fn admit_occurrence(
        &self,
        request: impl Into<Box<UserAutomationRuntimeAdmission>>,
    ) -> Result<AutomationExecutionReference, UserAutomationRuntimeError> {
        let request: Box<UserAutomationRuntimeAdmission> = request.into();
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

        let response = self
            .owner
            .dreamer_job(&request.context, material.request.clone())
            .await
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
            .map_err(classify_gateway_failure)
    }
}

/// Projects the gateway's typed route failure onto this adapter's closed
/// owner-error set.
///
/// The gateway answers `Result<DurableJobResponse, DreamerJobFailure>` (issue
/// #2764 item 6), a closed typed carrier, so the class is decided from the
/// variant that owns the fact and never by sniffing rendered prose. Only
/// [`DreamerJobFailure::Refused`] carries free text — it is the route's
/// pre-store checks, its rebind fence, and the transport client's own refusal
/// rendering — so that one channel keeps the keyword classifier it always had,
/// in [`classify_refusal_text`].
///
/// The mapping, and why each variant lands where it does:
///
/// * [`DreamerJobFailure::Recovered`] is
///   [`HostDurableJobOwnerError::UnknownOutcome`]. The commit is settled, but
///   the `DurableJobResponse` this adapter needs in order to admit the
///   occurrence was never produced, so the admission has no determined result
///   and no `AutomationExecutionReference` can be built. `Rejected` would be
///   the unsafe direction here: it asserts nothing was sent, and reporting a
///   proven commit as rejected is precisely what invites a blind resubmission.
///   The exact proven outcome, the bound receipt evidence and the outstanding
///   `Status`/`Reconcile` read obligation stay in the reason text, which is
///   that variant's own `Display`; the same carrier reaches the Kernel route's
///   transport edge as a structured recovery object rather than as this prose.
/// * [`CommitRecoveryError::OrsUnavailable`] is
///   [`HostDurableJobOwnerError::Unavailable`]: the durable recovery owner
///   itself could not be read, which is an unreachable owner rather than an
///   answer about the request.
/// * [`CommitRecoveryError::UnknownCommitOpen`] and
///   [`CommitRecoveryError::ReceiptQueryFailed`] are
///   [`HostDurableJobOwnerError::UnknownOutcome`]: the commit outcome stays
///   exactly as unknown as it was, so no retry is licensed.
/// * every other recovery refusal is [`HostDurableJobOwnerError::Rejected`].
///   Each is a deterministic refusal observed before or without a send — a
///   paused Ordering Scope, evidence that does not bind the admitted identity, a
///   retained record that conflicts, an unresolvable Ordering Scope, or a
///   pre-effect contract refusal — so nothing was committed and the same
///   material may be presented again later.
#[cfg(windows)]
fn classify_gateway_failure(failure: DreamerJobFailure) -> HostDurableJobOwnerError {
    match failure {
        DreamerJobFailure::Refused(reason) => classify_refusal_text(reason),
        DreamerJobFailure::Recovered(outcome) => {
            HostDurableJobOwnerError::UnknownOutcome(outcome.to_string())
        }
        DreamerJobFailure::Recovery(error) => {
            let reason = error.to_string();
            match error {
                CommitRecoveryError::OrsUnavailable { .. } => {
                    HostDurableJobOwnerError::Unavailable(reason)
                }
                CommitRecoveryError::UnknownCommitOpen { .. }
                | CommitRecoveryError::ReceiptQueryFailed { .. } => {
                    HostDurableJobOwnerError::UnknownOutcome(reason)
                }
                CommitRecoveryError::ScopePaused { .. }
                | CommitRecoveryError::ReceiptIdentityConflict { .. }
                | CommitRecoveryError::RetainedRecordConflict { .. }
                | CommitRecoveryError::OrderingScopeUnresolved { .. }
                | CommitRecoveryError::CommitRefused { .. } => {
                    HostDurableJobOwnerError::Rejected(reason)
                }
            }
        }
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

/// Classifies one free-text refusal produced by the route's own pre-store
/// checks, its rebind fence, or the transport client.
///
/// This is the only channel that is text by construction, so it is the only
/// one read as text. Every other route failure is decided from its typed
/// variant in [`classify_gateway_failure`]; a rendered recovery outcome is
/// never re-sniffed here, because the word "unknown" in a retained-record
/// refusal does not mean the *presented* operation's commit is unknown and
/// classifying on it would report a proven noncommit as a possible one.
#[cfg(windows)]
fn classify_refusal_text(reason: String) -> HostDurableJobOwnerError {
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
