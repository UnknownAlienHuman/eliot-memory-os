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
//!   operation identity, proposal, and — for an applied command — the guarded
//!   task command ([`GuardedTaskCommand`](eliot_governor::GuardedTaskCommand),
//!   which binds its subject task, its admitted State Fence, and its closed
//!   [`TaskCommand`](eliot_governor::TaskCommand))
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

use eliot_governor::{
    GovernorTaskLifecycle, GuardedTaskCommand, KernelTransitionPort, TaskControllerCampaignSources,
    TaskLifecycleError, TaskProposal, TaskRecord,
};
use eliot_learning_contracts::LearningStateViewRecipe;

/// Forwards the task-command path to the single Governor task owner.
///
/// The wrapper owns the inner Governor adapter (which itself borrows the
/// single Governor owner triple) and forwards each call unchanged. It adds no
/// validation, retry, or state of its own; every typed success or fail-closed
/// error comes from the Governor owner.
pub struct ForwardingTaskLifecycle<'a, P: ?Sized> {
    inner: GovernorTaskLifecycle<'a, P>,
}

impl<'a, P: ?Sized> ForwardingTaskLifecycle<'a, P> {
    /// Wraps the single Governor task lifecycle owner for forwarding.
    pub fn new(inner: GovernorTaskLifecycle<'a, P>) -> Self {
        Self { inner }
    }
}

impl<P: KernelTransitionPort + ?Sized> ForwardingTaskLifecycle<'_, P> {
    /// Forwards one authenticated task record read to the Governor owner.
    pub fn view(
        &self,
        ctx: &eliot_contracts::RequestMetadata,
        task_id: &eliot_contracts::TaskId,
    ) -> Result<Option<TaskRecord>, TaskLifecycleError> {
        self.inner.view(ctx, task_id)
    }

    /// Forwards one task proposal to the Governor canonical path and returns
    /// only the exact issued receipt.
    pub async fn propose_task(
        &self,
        identity: &eliot_protocol::RequestIdentity,
        operation_id: eliot_contracts::OperationId,
        proposal: TaskProposal,
    ) -> Result<eliot_store_api::WriteReceipt, TaskLifecycleError> {
        self.inner
            .propose_task(identity, operation_id, proposal)
            .await
    }

    /// Forwards a task proposal that atomically publishes its typed campaign
    /// learning-state recipe through the Task Controller's canonical
    /// `UpdateTaskState` commit.
    pub async fn propose_task_with_learning_state_recipe(
        &self,
        identity: &eliot_protocol::RequestIdentity,
        operation_id: eliot_contracts::OperationId,
        proposal: TaskProposal,
        recipe: LearningStateViewRecipe,
    ) -> Result<eliot_store_api::WriteReceipt, TaskLifecycleError> {
        self.inner
            .propose_task_with_learning_state_recipe(identity, operation_id, proposal, recipe)
            .await
    }

    /// Forwards a task proposal carrying the complete owner-role publication
    /// matrix through the authenticated Task Controller transition.
    pub async fn propose_task_with_complete_campaign_sources(
        &self,
        identity: &eliot_protocol::RequestIdentity,
        operation_id: eliot_contracts::OperationId,
        proposal: TaskProposal,
        recipe: LearningStateViewRecipe,
        owner_publications: Vec<eliot_store_api::CampaignSourcePublication>,
    ) -> Result<eliot_store_api::WriteReceipt, TaskLifecycleError> {
        self.inner
            .propose_task_with_complete_campaign_sources(
                identity,
                operation_id,
                proposal,
                recipe,
                owner_publications,
            )
            .await
    }

    /// Forwards a guarded task command carrying the complete owner-role
    /// publication matrix through the authenticated Task Controller transition.
    pub async fn apply_task_with_complete_campaign_sources(
        &self,
        identity: &eliot_protocol::RequestIdentity,
        operation_id: eliot_contracts::OperationId,
        guarded: GuardedTaskCommand,
        recipe: LearningStateViewRecipe,
        owner_publications: Vec<eliot_store_api::CampaignSourcePublication>,
    ) -> Result<eliot_store_api::WriteReceipt, TaskLifecycleError> {
        self.inner
            .apply_task_with_complete_campaign_sources(
                identity,
                operation_id,
                guarded,
                recipe,
                owner_publications,
            )
            .await
    }

    /// Forwards a complete owner-material proposal to the Governor owner. The
    /// builder runs only after the Task Controller has produced its native
    /// objective/plan/acceptance/open-items rows.
    pub async fn propose_task_with_complete_campaign_owner_materials<F>(
        &self,
        identity: &eliot_protocol::RequestIdentity,
        operation_id: eliot_contracts::OperationId,
        proposal: TaskProposal,
        recipe: LearningStateViewRecipe,
        owner_builder: F,
    ) -> Result<eliot_store_api::WriteReceipt, TaskLifecycleError>
    where
        F: FnOnce(
            &TaskControllerCampaignSources,
        ) -> Result<Vec<eliot_store_api::CampaignSourcePublication>, String>,
    {
        self.inner
            .propose_task_with_complete_campaign_owner_materials(
                identity,
                operation_id,
                proposal,
                recipe,
                owner_builder,
            )
            .await
    }

    /// Forwards a complete owner-material task command to the Governor owner.
    pub async fn apply_task_with_complete_campaign_owner_materials<F>(
        &self,
        identity: &eliot_protocol::RequestIdentity,
        operation_id: eliot_contracts::OperationId,
        guarded: GuardedTaskCommand,
        recipe: LearningStateViewRecipe,
        owner_builder: F,
    ) -> Result<eliot_store_api::WriteReceipt, TaskLifecycleError>
    where
        F: FnOnce(
            &TaskControllerCampaignSources,
        ) -> Result<Vec<eliot_store_api::CampaignSourcePublication>, String>,
    {
        self.inner
            .apply_task_with_complete_campaign_owner_materials(
                identity,
                operation_id,
                guarded,
                recipe,
                owner_builder,
            )
            .await
    }

    /// returns only the exact issued receipt.
    pub async fn apply_task(
        &self,
        identity: &eliot_protocol::RequestIdentity,
        operation_id: eliot_contracts::OperationId,
        guarded: GuardedTaskCommand,
    ) -> Result<eliot_store_api::WriteReceipt, TaskLifecycleError> {
        self.inner.apply_task(identity, operation_id, guarded).await
    }

    /// Forwards a guarded task command that atomically publishes its typed
    /// campaign learning-state recipe through the Task Controller's canonical
    /// `UpdateTaskState` commit.
    pub async fn apply_task_with_learning_state_recipe(
        &self,
        identity: &eliot_protocol::RequestIdentity,
        operation_id: eliot_contracts::OperationId,
        guarded: GuardedTaskCommand,
        recipe: LearningStateViewRecipe,
    ) -> Result<eliot_store_api::WriteReceipt, TaskLifecycleError> {
        self.inner
            .apply_task_with_learning_state_recipe(identity, operation_id, guarded, recipe)
            .await
    }
}
