//! Host-side Durable Job adapter for `UserAutomation` occurrences.
//!
//! This module is a thin owner join.  It validates the owner-issued typed
//! Durable Job material, calls the existing Kernel Store gateway, validates
//! the exact response, and projects the real job identity/state.  It owns no
//! queue, job journal, receipt, grant, or retry policy.

use eliot_contracts::RequestMetadata;
use eliot_kernel_service::{
    AutomationExecutionReference, UserAutomationDurableJobPort, UserAutomationRuntimeAdmission,
    UserAutomationRuntimeError,
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
    ///
    /// This class is reserved for a genuinely undetermined mutation: the
    /// outcome is unknown and no evidence resolves it. A mutation whose
    /// disposition IS proven by an exact receipt is not this class (issue #2764
    /// item 6) — it carries its recorded outcome in
    /// [`HostDurableJobOwnerError::OutcomeSettled`] instead, so "the commit
    /// provably happened" and "we cannot tell" never share one code.
    #[error("Durable Job owner outcome is unknown: {0}")]
    UnknownOutcome(String),
    /// The mutation's disposition is proven, but the ledger answer for it is
    /// still unread.
    ///
    /// Issue #2764 item 6: a `WriteReceipt` proves a mutation disposition, not
    /// the missing `DurableJobResponse`. This class carries that exact recorded
    /// fact — the operation/key, the terminal outcome, the receipt evidence and
    /// the remaining `Status`/`Reconcile` obligation — so a caller can act on
    /// the difference between a proven commit and an undetermined one without
    /// parsing prose. It is distinct from `UnknownOutcome` because nothing here
    /// is unknown about whether the mutation committed.
    #[error("Durable Job owner mutation disposition is settled: {0}")]
    OutcomeSettled(String),
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
        // The send future is boxed like the gateway's own recovery sends: the
        // admitted transition it carries is large, and this adapter is the only
        // remaining poller of that future. A pure read or a receipt lookup is
        // not an attempt; only this call is.
        let attempt = Box::pin(self.dreamer_job(context, request)).await;
        attempt.map_err(|error| classify_gateway_error(&error))
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
        // A proven mutation disposition is carried as itself rather than being
        // re-labelled an unknown outcome (#2764 item 6): the commit is settled,
        // and the runtime class that says so is the one the caller must see.
        HostDurableJobOwnerError::OutcomeSettled(reason) => {
            UserAutomationRuntimeError::OutcomeSettled(reason)
        }
        HostDurableJobOwnerError::Rejected(reason) => UserAutomationRuntimeError::Rejected(reason),
    }
}

/// Maps the gateway's typed Dreamer failure onto this adapter's owner classes.
///
/// The typed carrier is consulted before the rendered text, so a recovered
/// mutation whose ledger answer is still unread is reported as the
/// `UnknownOutcome` it is rather than being re-derived from prose (issue #2764
/// item 6): the proof is a mutation disposition, not the missing
/// `DurableJobResponse`, so the caller still owes a ledger read. The rendered
/// sentence travels with the reason exactly as before.
#[cfg(windows)]
fn classify_gateway_error(
    error: &eliot_kernel_service::DreamerJobGatewayError,
) -> HostDurableJobOwnerError {
    if let Some(recovered) = error.uncertain() {
        return match recovered {
            eliot_kernel_service::DreamerCommitUncertain::UnknownCommitOpen { .. } => {
                HostDurableJobOwnerError::UnknownOutcome(error.to_string())
            }
            // Reconciled, already dispositioned, or dispositioned with a
            // pause-release limitation: the commit IS settled — an exact
            // receipt resolved it and its digest is bound — and only the ledger
            // answer is unread. These three arms are not the same fact as
            // `UnknownCommitOpen`, and they are not the same fact as each other,
            // so they are reported as the proven disposition they are rather
            // than being flattened into one code. Collapsing them here would
            // re-discard, one layer out, exactly the distinction the carrier
            // exists to preserve.
            eliot_kernel_service::DreamerCommitUncertain::Reconciled { .. }
            | eliot_kernel_service::DreamerCommitUncertain::AlreadyDispositioned { .. }
            | eliot_kernel_service::DreamerCommitUncertain::ReconciledWithRefreshLimitation {
                ..
            } => HostDurableJobOwnerError::OutcomeSettled(error.to_string()),
        };
    }
    classify_gateway_text(error.to_string())
}

#[cfg(windows)]
fn classify_gateway_text(reason: String) -> HostDurableJobOwnerError {
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
