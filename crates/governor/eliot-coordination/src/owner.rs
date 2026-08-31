use std::collections::{BTreeMap, btree_map::Entry};

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
/// additive issuance map retains immutable same-call `WorkLease` provenance
/// under the same owner, so heartbeat, expiry, reassignment, or recovery cannot
/// rewrite the original issuance result.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct CoordinationOwner {
    #[serde(flatten)]
    pub(crate) inner: coordination::CoordinationOwner,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
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

    /// Reads one exact active `Session` under the current epoch and fence.
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

    /// Reads one exact active `WorkItem` and `WorkLease` projection.
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

    /// Reads the sole active `WorkLease` without silently selecting ambiguity.
    pub fn read_unique_active_work_lease(
        &self,
        now: u64,
        authority_epoch: AuthorityEpoch,
        state_fence: &StateFence,
    ) -> Result<ActiveWorkLeaseProjection, CoordinationError> {
        self.inner
            .read_unique_active_work_lease(now, authority_epoch, state_fence)
    }

    /// Registers one actor `Session`.
    pub fn register_session(
        &mut self,
        request: RegisterSession,
    ) -> Result<AgentSession, CoordinationError> {
        self.inner.register_session(request)
    }

    /// Registers one ready `WorkItem`.
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

    /// Compatibility acquisition path without canonical issuance provenance.
    ///
    /// Current consumers that need authority identity must use
    /// [`Self::acquire_work_with_issuance`]. A lease first accepted through this
    /// compatibility path cannot be upgraded to canonical issuance later.
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

    pub(crate) fn insert_candidate_issuance(
        issuance_by_request: &mut BTreeMap<String, WorkLeaseIssuanceProvenance>,
        request_id: String,
        provenance: WorkLeaseIssuanceProvenance,
    ) -> Result<(), CoordinationError> {
        match issuance_by_request.entry(request_id.clone()) {
            Entry::Vacant(entry) => {
                entry.insert(provenance);
                Ok(())
            }
            Entry::Occupied(_) => Err(CoordinationError::IdempotencyConflict(request_id)),
        }
    }

    fn validate_issuance_snapshot(&self) -> Result<(), CoordinationError> {
        for (request_id, provenance) in &self.work_lease_issuance_by_request {
            if request_id.as_str() != provenance.source_request().request_id.as_str()
                || provenance.validate().is_err()
            {
                return Err(CoordinationError::InvalidState);
            }

            let mut matching_events = self
                .events()
                .iter()
                .filter(|event| event.idempotency_key.as_str() == request_id.as_str());
            let event = matching_events
                .next()
                .ok_or(CoordinationError::InvalidState)?;
            if matching_events.next().is_some() || event != &provenance.source_decision().event {
                return Err(CoordinationError::InvalidState);
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use eliot_contracts::ResourceGeneration;
    use serde::de::value::{Error as ValueError, MapDeserializer, SeqDeserializer};
    use serde::de::{Deserializer, IntoDeserializer, Visitor};

    type TestResult<T = ()> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

    enum SnapshotValue {
        U64(u64),
        Map(BTreeMap<String, SnapshotValue>),
        Seq(Vec<SnapshotValue>),
    }

    impl<'de> IntoDeserializer<'de, ValueError> for SnapshotValue {
        type Deserializer = Self;

        fn into_deserializer(self) -> Self::Deserializer {
            self
        }
    }

    impl<'de> Deserializer<'de> for SnapshotValue {
        type Error = ValueError;

        fn deserialize_any<V>(self, visitor: V) -> Result<V::Value, Self::Error>
        where
            V: Visitor<'de>,
        {
            match self {
                Self::U64(value) => visitor.visit_u64(value),
                Self::Map(values) => {
                    visitor.visit_map(MapDeserializer::new(values.into_iter()))
                }
                Self::Seq(values) => {
                    visitor.visit_seq(SeqDeserializer::new(values.into_iter()))
                }
            }
        }

        serde::forward_to_deserialize_any! {
            bool i8 i16 i32 i64 i128 u8 u16 u32 u64 u128 f32 f64 char str string
            bytes byte_buf option unit unit_struct newtype_struct seq tuple tuple_struct map
            struct enum identifier ignored_any
        }
    }

    fn empty_map() -> SnapshotValue {
        SnapshotValue::Map(BTreeMap::new())
    }

    fn old_empty_snapshot() -> SnapshotValue {
        SnapshotValue::Map(BTreeMap::from([
            ("sequence".to_owned(), SnapshotValue::U64(0)),
            ("sessions".to_owned(), empty_map()),
            ("work".to_owned(), empty_map()),
            ("leases".to_owned(), empty_map()),
            ("integrations".to_owned(), empty_map()),
            ("messages".to_owned(), empty_map()),
            ("event_by_request".to_owned(), empty_map()),
            ("events".to_owned(), SnapshotValue::Seq(Vec::new())),
        ]))
    }

    fn fence() -> StateFence {
        StateFence::new(AuthorityEpoch::genesis(), ResourceGeneration::genesis())
    }

    fn clock() -> ClockReading {
        ClockReading {
            valid_time_ms: None,
            known_time_ms: None,
            transaction_sequence: None,
            monotonic_ns: None,
        }
    }

    fn issued_owner() -> TestResult<CoordinationOwner> {
        let mut owner = CoordinationOwner::new();
        let state_fence = fence();
        owner.register_session(RegisterSession {
            request_id: "register-session".to_owned(),
            session_id: "session-1".to_owned(),
            principal_id: "principal-1".to_owned(),
            route_ref: "route-1".to_owned(),
            authority_epoch: AuthorityEpoch::genesis(),
            state_fence: state_fence.clone(),
            now: 10,
            heartbeat_deadline: 100,
        })?;
        owner.register_work(
            WorkItem {
                work_item_id: "work-1".to_owned(),
                task_id: "task-1".to_owned(),
                state: crate::WorkState::Ready,
                state_fence: state_fence.clone(),
                owner_session_id: None,
                lease_id: None,
                attempt: 0,
                checkpoint_ref: None,
                result_ref: None,
            },
            "register-work",
            "principal-1",
            clock(),
        )?;
        owner.acquire_work_with_issuance(WorkLeaseRequest {
            request_id: "claim-work".to_owned(),
            lease_id: "legacy-lease-1".to_owned(),
            work_item_id: "work-1".to_owned(),
            session_id: "session-1".to_owned(),
            authority_epoch: AuthorityEpoch::genesis(),
            state_fence,
            now: 20,
            lease_duration: 40,
        })?;
        Ok(owner)
    }

    #[test]
    fn old_snapshot_without_issuance_projection_remains_decodable() -> TestResult {
        let decoded = CoordinationOwner::deserialize(old_empty_snapshot())?;
        let recovered = CoordinationOwner::from_snapshot(decoded)?;
        assert_eq!(recovered.current_sequence(), 0);
        assert!(recovered.events().is_empty());
        assert!(recovered.work_lease_issuance_by_request.is_empty());
        Ok(())
    }

    #[test]
    fn issuance_without_its_causal_event_is_rejected_on_recovery() -> TestResult {
        let issued = issued_owner()?;
        let snapshot = CoordinationOwner {
            inner: coordination::CoordinationOwner::new(),
            work_lease_issuance_by_request: issued.work_lease_issuance_by_request,
        };
        let error = match CoordinationOwner::from_snapshot(snapshot) {
            Ok(_) => return Err("snapshot without issuance event unexpectedly recovered".into()),
            Err(error) => error,
        };
        assert_eq!(error, CoordinationError::InvalidState);
        Ok(())
    }
}
