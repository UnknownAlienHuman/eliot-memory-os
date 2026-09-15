//! Private Governor-backed task lifecycle port adapters.
//!
//! The forwarding adapter translates between the daemon task-command path and
//! one Governor [`GovernorTaskLifecycle`](eliot_governor::GovernorTaskLifecycle)
//! borrowed from the single [`DaemonComposition`](super::DaemonComposition) by
//! its `task_lifecycle` accessor. It forwards authenticated input and
//! translates typed results only:
//!
//! - No policy, admission, or semantic rules live here. Duplicate, epoch,
//!   fence, identifier, task-revision compare-and-swap, and exact
//!   legal-transition checks stay with the Governor task owner; this adapter
//!   never invents a proposal, context, or command.
//! - `view` is an authenticated read of the current owner at the admitted
//!   fence. A stale fence fails closed in the Governor owner, never as a
//!   local default.
//! - `propose_task` and `apply_task` forward the exact admitted identity,
//!   operation identity, proposal, context, and [`TaskCommand`](eliot_task::TaskCommand)
//!   to the Governor canonical path. The command enum is closed: only the
//!   owner-defined transitions commit, and only a `Committed` store receipt
//!   counts as admission; rejected, cancelled and dead-letter outcomes stay
//!   pending as typed store failures, and a lost acknowledgement reconciles
//!   the same operation receipt.
//! - The adapter publishes nothing itself: the Governor scratch clone is
//!   discarded and owners rebuild only via `refresh_from_kernel` at the
//!   returned receipt revision.
//!
//! The adapter performs no I/O of its own beyond awaiting the inner Governor
//! owner, so it cannot block the single-thread async reactor beyond the
//! already-admitted canonical commit. The current Kernel binding is observed
//! through the Governor composition, never through a second client.

#![forbid(unsafe_code)]

use eliot_governor::{GovernorTaskLifecycle, KernelTransitionPort, TaskLifecycleError};

/// Forwards the task-command path to the single Governor task owner.
///
/// The wrapper owns the inner Governor adapter (which itself borrows the
/// single Governor owner triple) and forwards each call unchanged. It adds no
/// validation, retry, or state of its own; every typed success or fail-closed
/// error comes from the Governor owner.
pub(crate) struct ForwardingTaskLifecycle<'a, P: ?Sized> {
    inner: GovernorTaskLifecycle<'a, P>,
}

impl<'a, P: ?Sized> ForwardingTaskLifecycle<'a, P> {
    /// Wraps the single Governor task lifecycle owner for forwarding.
    pub(crate) fn new(inner: GovernorTaskLifecycle<'a, P>) -> Self {
        Self { inner }
    }
}

impl<P: KernelTransitionPort + ?Sized> ForwardingTaskLifecycle<'_, P> {
    /// Forwards one authenticated task record read to the Governor owner.
    pub(crate) fn view(
        &self,
        ctx: &eliot_contracts::RequestMetadata,
        task_id: &eliot_contracts::TaskId,
    ) -> Result<Option<eliot_task::TaskRecord>, TaskLifecycleError> {
        self.inner.view(ctx, task_id)
    }

    /// Forwards one task proposal to the Governor canonical path and returns
    /// only the exact issued receipt.
    pub(crate) async fn propose_task(
        &self,
        identity: &eliot_protocol::RequestIdentity,
        operation_id: eliot_contracts::OperationId,
        proposal: eliot_task::TaskProposal,
    ) -> Result<eliot_store_api::WriteReceipt, TaskLifecycleError> {
        self.inner
            .propose_task(identity, operation_id, proposal)
            .await
    }

    /// Forwards one guarded task command to the Governor canonical path and
    /// returns only the exact issued receipt.
    pub(crate) async fn apply_task(
        &self,
        identity: &eliot_protocol::RequestIdentity,
        operation_id: eliot_contracts::OperationId,
        task_id: eliot_contracts::TaskId,
        context: eliot_task::TaskCommandContext,
        command: eliot_task::TaskCommand,
    ) -> Result<eliot_store_api::WriteReceipt, TaskLifecycleError> {
        self.inner
            .apply_task(identity, operation_id, task_id, context, command)
            .await
    }
}
