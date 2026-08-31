use std::collections::BTreeMap;

use eliot_contracts::{AuthorityEpoch, ClockReading, StateFence};
use serde::{Deserialize, Serialize};

use crate::coordination;
use crate::{
    ActiveWorkLeaseProjection, AgentHeartbeat, AgentResultDraft, AgentResultReceipt, AgentSession,
    CheckpointReceipt, CoordinationError, CoordinationEvent, CoordinationEventDraft,
    CoordinationEventReceipt, HeartbeatAck, IntegrationCandidateDraft,
    IntegrationCandidateReceipt, IntegrationLeaseDecision, IntegrationLeaseRequest,
    MailboxMessageDraft, MailboxReceipt, ReassignWorkRequest, RegisterSession, WorkCheckpoint,
    WorkItem, WorkLeaseDecision, WorkLeaseIssuanceProvenance, WorkLeaseRequest,
};

/// Production durable coordination owner.
///
/// The flattened `inner` field preserves the established snapshot shape. The
/// additive issuance map retains immutable same-call WorkLease provenance under
/// the same owner, so a later heartbeat, expiry or reassignment cannot rewrite
/// the result of an exact acquisition retry.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct CoordinationOwner {
    #[serde(flatten)]
    pub(crate) inner: coordination::CoordinationOwner,
    #[serde(default)]
    pub(crate) work_lease_issuance_by_request:
        BTreeMap<String, WorkLeaseIssuanceProvenance>,
}

impl CoordinationOwner {
    /// Creates an empty owner at the genesis causal sequence.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Rebuilds and validates one complete owner snapshot.
    pub fn from_snapshot(snapshot: Self) -> Result<Self, CoordinationError> {
        let owner = Self {
            inner: coordination::CoordinationOwner::from_snapshot(snapshot.inner)?,
            work_lease_issuance_by_request: snapshot.work_lease_issuance_by_request,
        };
        owner.validate_issuance_snapshot()?;
        Ok(owner)
    }

    /// Returns the current causal event sequence.
    #[must_use]
    pub fn current_sequence(&self) -> u64 {
        self.inner.current_sequence()
    }

    /// Returns the immutable coordination event history.
    #[must_use]
    pub fn events(&self) -> &[CoordinationEvent] {
        self.inner.events()
    }

    /// Reads one exact active Session under the current epoch and fence.
    pub fn read_active_session(
        &self,
        session_id: &str,
        now: u64,
        authority_epoch: AuthorityEpoch,
        state_fence: &StateFence,
    ) -> Result<AgentSession, CoordinationError> {
        self.inner
            .read_active_session(session_id, now, authority_epoch, state_fence)
    }

    /// Reads one exact active WorkItem/WorkLease projection.
    pub fn read_active_work_lease(
        &self,
        work_item_id: &str,
        session_id: &str,
        now: u64,
        authority_epoch: AuthorityEpoch,
        state_fence: &StateFence,
    ) -> Result<ActiveWorkLeaseProjection, CoordinationError> {
        self.inner.read_active_work_lease(
            work_item_id,
            session_id,
            now,
            authority_epoch,
            state_fence,
        )
    }

    /// Reads the sole active WorkLease without silently selecting ambiguity.
    pub fn read_unique_active_work_lease(
        &self,
        now: u64,
        authority_epoch: AuthorityEpoch,
        state_fence: &StateFence,
    ) -> Result<ActiveWorkLeaseProjection, CoordinationError> {
        self.inner
            .read_unique_active_work_lease(now, authority_epoch, state_fence)
    }

    /// Registers one actor Session.
    pub fn register_session(
        &mut self,
        request: RegisterSession,
    ) -> Result<AgentSession, CoordinationError> {
        self.inner.register_session(request)
    }

    /// Registers one ready WorkItem.
    pub fn register_work(
        &mut self,
        item: WorkItem,
        request_id: &str,
        actor_id: &str,
        observed_at: ClockReading,
    ) -> Result<(), CoordinationError> {
        self.inner
            .register_work(item, request_id, actor_id, observed_at)
    }

    /// Compatibility acquisition path without canonical issuance projection.
    ///
    /// Current consumers that need authority identity must use
    /// [`Self::acquire_work_with_issuance`]. This method remains while existing
    /// owner consumers migrate under issue #368.
    pub fn acquire_work(
        &mut self,
        request: WorkLeaseRequest,
    ) -> Result<WorkLeaseDecision, CoordinationError> {
        self.inner.acquire_work(request)
    }

    /// Renews one exact active lease.
    pub fn heartbeat(&mut self, request: AgentHeartbeat) -> Result<HeartbeatAck, CoordinationError> {
        self.inner.heartbeat(request)
    }

    /// Sends one durable mailbox item.
    pub fn send_message(
        &mut self,
        request: MailboxMessageDraft,
    ) -> Result<MailboxReceipt, CoordinationError> {
        self.inner.send_message(request)
    }

    /// Records one checkpoint for an active lease.
    pub fn checkpoint(
        &mut self,
        request: WorkCheckpoint,
    ) -> Result<CheckpointReceipt, CoordinationError> {
        self.inner.checkpoint(request)
    }

    /// Records one candidate result for an active lease.
    pub fn submit_result(
        &mut self,
        request: AgentResultDraft,
    ) -> Result<AgentResultReceipt, CoordinationError> {
        self.inner.submit_result(request)
    }

    /// Reassigns one work item after fencing its previous lease.
    pub fn reassign(
        &mut self,
        request: ReassignWorkRequest,
    ) -> Result<WorkLeaseDecision, CoordinationError> {
        self.inner.reassign(request)
    }

    /// Records one integration candidate without applying it.
    pub fn submit_integration_candidate(
        &mut self,
        request: IntegrationCandidateDraft,
    ) -> Result<IntegrationCandidateReceipt, CoordinationError> {
        self.inner.submit_integration_candidate(request)
    }

    /// Acquires the single integration writer for one target scope.
    pub fn acquire_integration(
        &mut self,
        request: IntegrationLeaseRequest,
    ) -> Result<IntegrationLeaseDecision, CoordinationError> {
        self.inner.acquire_integration(request)
    }

    /// Appends one caller-supplied coordination event.
    pub fn record_coordination_event(
        &mut self,
        request: CoordinationEventDraft,
    ) -> Result<CoordinationEventReceipt, CoordinationError> {
        self.inner.record_coordination_event(request)
    }

    pub(crate) fn stored_issuance(
        &self,
        request_id: &str,
    ) -> Option<&WorkLeaseIssuanceProvenance> {
        self.work_lease_issuance_by_request.get(request_id)
    }

    pub(crate) fn store_issuance(
        &mut self,
        request_id: String,
        provenance: WorkLeaseIssuanceProvenance,
    ) -> Result<(), CoordinationError> {
        if self
            .work_lease_issuance_by_request
            .contains_key(&request_id)
        {
            return Err(CoordinationError::IdempotencyConflict(request_id));
        }
        self.work_lease_issuance_by_request
            .insert(request_id, provenance);
        Ok(())
    }

    fn validate_issuance_snapshot(&self) -> Result<(), CoordinationError> {
        for (request_id, provenance) in &self.work_lease_issuance_by_request {
            if request_id != &provenance.source_request().request_id
                || provenance.validate().is_err()
            {
                return Err(CoordinationError::InvalidState);
            }
        }
        Ok(())
    }
}
