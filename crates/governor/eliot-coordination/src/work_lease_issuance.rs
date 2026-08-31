use std::collections::BTreeMap;

use eliot_contracts::{
    AuthorityEpoch, StateFence, WORK_LEASE_NAMESPACE, WORK_LEASE_WIRE_REVISION,
    WorkLeaseId as CanonicalWorkLeaseId, canonical_json_bytes, sha256_hex,
};
use schemars::JsonSchema;
use serde::de::value::{Error as ValueError, MapDeserializer, StringDeserializer};
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Revision of the complete owner-issued `WorkLease` evidence encoding.
pub const WORK_LEASE_ISSUANCE_REVISION: &str = "eliot.governor.work-lease-issuance.v1";

#[derive(Clone, Copy, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum WorkLeaseIssuanceDisposition {
    OwnerIssued,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Error, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum WorkLeaseIssuanceError {
    #[error("canonical WorkLease issuance must occur in the same owner call as acquisition")]
    PostHocIssuanceRejected,
    #[error("accepted WorkLease issuance evidence is internally inconsistent")]
    InconsistentOwnerEvidence,
    #[error("WorkLease issuance evidence could not be encoded canonically")]
    EvidenceEncodingRejected,
    #[error("canonical WorkLease identity contract rejected owner-issued evidence")]
    CanonicalContractRejected,
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum WorkLeaseIssuanceFailure {
    #[error(transparent)]
    Coordination(#[from] super::CoordinationError),
    #[error(transparent)]
    Evidence(#[from] WorkLeaseIssuanceError),
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkLeaseIssuanceProvenance {
    canonical_work_lease_id: CanonicalWorkLeaseId,
    source_request: super::WorkLeaseRequest,
    source_decision: super::WorkLeaseDecision,
    evidence_commitment_sha256: String,
}

impl WorkLeaseIssuanceProvenance {
    #[must_use]
    pub const fn canonical_work_lease_id(&self) -> &CanonicalWorkLeaseId {
        &self.canonical_work_lease_id
    }

    #[must_use]
    pub const fn source_request(&self) -> &super::WorkLeaseRequest {
        &self.source_request
    }

    #[must_use]
    pub const fn source_decision(&self) -> &super::WorkLeaseDecision {
        &self.source_decision
    }

    #[must_use]
    pub fn evidence_commitment_sha256(&self) -> &str {
        &self.evidence_commitment_sha256
    }

    fn validate(&self) -> Result<(), WorkLeaseIssuanceError> {
        validate_request_binding(&self.source_request, &self.source_decision)?;
        let expected = issue_provenance(self.source_request.clone(), self.source_decision.clone())?;
        if expected.canonical_work_lease_id != self.canonical_work_lease_id
            || expected.evidence_commitment_sha256 != self.evidence_commitment_sha256
        {
            return Err(WorkLeaseIssuanceError::InconsistentOwnerEvidence);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WorkLeaseIssuanceResult {
    decision: super::WorkLeaseDecision,
    provenance: WorkLeaseIssuanceProvenance,
}

impl WorkLeaseIssuanceResult {
    #[must_use]
    pub const fn disposition(&self) -> WorkLeaseIssuanceDisposition {
        WorkLeaseIssuanceDisposition::OwnerIssued
    }

    #[must_use]
    pub const fn decision(&self) -> &super::WorkLeaseDecision {
        &self.decision
    }

    #[must_use]
    pub const fn provenance(&self) -> &WorkLeaseIssuanceProvenance {
        &self.provenance
    }

    #[must_use]
    pub fn work_lease_id(&self) -> &CanonicalWorkLeaseId {
        self.provenance.canonical_work_lease_id()
    }

    #[must_use]
    pub fn evidence_commitment_sha256(&self) -> &str {
        self.provenance.evidence_commitment_sha256()
    }
}

#[derive(Serialize)]
struct WorkLeaseIssuanceEvidence<'a> {
    revision: &'static str,
    source_request: &'a super::WorkLeaseRequest,
    source_decision: &'a super::WorkLeaseDecision,
}

impl super::CoordinationOwner {
    /// Acquires a lease and records its canonical identity in the same call.
    pub fn acquire_work_with_issuance(
        &mut self,
        request: super::WorkLeaseRequest,
    ) -> Result<WorkLeaseIssuanceResult, WorkLeaseIssuanceFailure> {
        self.acquire_work_with_issuance_using(request, issue_provenance)
    }

    fn acquire_work_with_issuance_using<F>(
        &mut self,
        request: super::WorkLeaseRequest,
        provenance_issuer: F,
    ) -> Result<WorkLeaseIssuanceResult, WorkLeaseIssuanceFailure>
    where
        F: FnOnce(
            super::WorkLeaseRequest,
            super::WorkLeaseDecision,
        ) -> Result<WorkLeaseIssuanceProvenance, WorkLeaseIssuanceError>,
    {
        if let Some(existing) = self.work_lease_issuance_by_request.get(&request.request_id) {
            if existing.source_request() != &request {
                return Err(
                    super::CoordinationError::IdempotencyConflict(request.request_id).into(),
                );
            }
            existing.validate()?;
            return Ok(WorkLeaseIssuanceResult {
                decision: existing.source_decision().clone(),
                provenance: existing.clone(),
            });
        }

        reject_legacy_replay(self, &request)?;
        validate_fresh_request(self, &request)?;
        if self.leases.contains_key(&request.lease_id) {
            return Err(super::CoordinationError::Duplicate(request.lease_id).into());
        }

        let mut candidate = self.clone();
        let decision = candidate.acquire_work(request.clone())?;
        validate_candidate_records(&candidate, &request, &decision)?;
        let provenance = provenance_issuer(request.clone(), decision.clone())?;
        provenance.validate()?;
        if self
            .work_lease_issuance_by_request
            .values()
            .any(|old| old.canonical_work_lease_id() == provenance.canonical_work_lease_id())
        {
            return Err(WorkLeaseIssuanceError::InconsistentOwnerEvidence.into());
        }

        let mut issuance = self.work_lease_issuance_by_request.clone();
        if issuance
            .insert(request.request_id, provenance.clone())
            .is_some()
        {
            return Err(WorkLeaseIssuanceError::InconsistentOwnerEvidence.into());
        }
        self.sequence = candidate.sequence;
        self.sessions = candidate.sessions;
        self.work = candidate.work;
        self.leases = candidate.leases;
        self.integrations = candidate.integrations;
        self.messages = candidate.messages;
        self.event_by_request = candidate.event_by_request;
        self.events = candidate.events;
        self.work_lease_issuance_by_request = issuance;
        Ok(WorkLeaseIssuanceResult {
            decision,
            provenance,
        })
    }

    #[must_use]
    pub fn work_lease_issuance(&self, request_id: &str) -> Option<WorkLeaseIssuanceProvenance> {
        self.work_lease_issuance_by_request.get(request_id).cloned()
    }

    pub(crate) fn validate_issuance_snapshot(&self) -> Result<(), super::CoordinationError> {
        let mut canonical_ids = BTreeMap::new();
        for (request_id, provenance) in &self.work_lease_issuance_by_request {
            if request_id.trim().is_empty() || provenance.source_request().request_id != *request_id
            {
                return Err(super::CoordinationError::InvalidState);
            }
            provenance
                .validate()
                .map_err(|_| super::CoordinationError::InvalidState)?;
            if canonical_ids
                .insert(provenance.canonical_work_lease_id().clone(), request_id)
                .is_some()
            {
                return Err(super::CoordinationError::InvalidState);
            }
            let request = provenance.source_request();
            let decision = provenance.source_decision();
            if self.event_by_request.get(request_id) != Some(&decision.event)
                || !self.events.contains(&decision.event)
            {
                return Err(super::CoordinationError::InvalidState);
            }
            let lease = self
                .leases
                .get(&decision.lease.lease_id)
                .ok_or(super::CoordinationError::InvalidState)?;
            if lease.lease_id != decision.lease.lease_id
                || lease.work_item_id != decision.lease.work_item_id
                || lease.holder_session_id != decision.lease.holder_session_id
                || lease.authority_epoch != decision.lease.authority_epoch
                || lease.state_fence != decision.lease.state_fence
                || lease.issued_at != decision.lease.issued_at
                || lease.expires_at == 0
                || lease.issued_at > lease.expires_at
                || lease.last_heartbeat < lease.issued_at
                || lease.last_heartbeat > lease.expires_at
            {
                return Err(super::CoordinationError::InvalidState);
            }
            let session = self
                .sessions
                .get(&request.session_id)
                .ok_or(super::CoordinationError::InvalidState)?;
            if session.session_id != request.session_id
                || session.authority_epoch != request.authority_epoch
                || session.state_fence != request.state_fence
            {
                return Err(super::CoordinationError::InvalidState);
            }
            let item = self
                .work
                .get(&request.work_item_id)
                .ok_or(super::CoordinationError::InvalidState)?;
            if item.work_item_id != request.work_item_id || item.state_fence != request.state_fence
            {
                return Err(super::CoordinationError::InvalidState);
            }
        }
        Ok(())
    }

    pub(crate) fn validate_current_bindings(
        &self,
        authority_epoch: AuthorityEpoch,
        state_fence: &StateFence,
    ) -> Result<(), super::CoordinationError> {
        for session in self
            .sessions
            .values()
            .filter(|session| session.state == super::SessionState::Active)
        {
            if session.authority_epoch != authority_epoch || session.state_fence != *state_fence {
                return Err(super::CoordinationError::FenceMismatch);
            }
            super::validate_active_session_heartbeat(session, None)?;
        }
        for item in self.work.values().filter(|item| {
            matches!(
                item.state,
                super::WorkState::Claimed
                    | super::WorkState::Running
                    | super::WorkState::Checkpointed
                    | super::WorkState::Reassigned
            )
        }) {
            let session_id = item
                .owner_session_id
                .as_deref()
                .ok_or(super::CoordinationError::InvalidState)?;
            let lease_id = item
                .lease_id
                .as_deref()
                .ok_or(super::CoordinationError::InvalidState)?;
            if item.state_fence != *state_fence {
                return Err(super::CoordinationError::FenceMismatch);
            }
            let session = self
                .sessions
                .get(session_id)
                .ok_or(super::CoordinationError::InvalidState)?;
            let lease = self
                .leases
                .get(lease_id)
                .ok_or(super::CoordinationError::InvalidState)?;
            if session.state != super::SessionState::Active
                || session.authority_epoch != authority_epoch
                || session.state_fence != *state_fence
                || lease.lease_id != lease_id
                || lease.work_item_id != item.work_item_id
                || lease.holder_session_id != session_id
                || lease.authority_epoch != authority_epoch
                || lease.state_fence != *state_fence
                || lease.issued_at == 0
                || lease.expires_at == 0
                || lease.issued_at > lease.expires_at
                || lease.last_heartbeat < lease.issued_at
                || lease.last_heartbeat > lease.expires_at
            {
                return Err(super::CoordinationError::FenceMismatch);
            }
        }
        Ok(())
    }
}

fn validate_fresh_request(
    owner: &super::CoordinationOwner,
    request: &super::WorkLeaseRequest,
) -> Result<(), super::CoordinationError> {
    for (value, field) in [
        (&request.request_id, "request_id"),
        (&request.lease_id, "lease_id"),
        (&request.work_item_id, "work_item_id"),
        (&request.session_id, "session_id"),
    ] {
        super::text(value, field)?;
    }
    owner.common(request.authority_epoch, &request.state_fence)?;
    super::nonzero(request.now, "now")?;
    if request.lease_duration == 0 || request.now.checked_add(request.lease_duration).is_none() {
        return Err(super::CoordinationError::InvalidField("lease_duration"));
    }
    let session = owner.read_active_session(
        &request.session_id,
        request.now,
        request.authority_epoch,
        &request.state_fence,
    )?;
    if session.state_fence != request.state_fence {
        return Err(super::CoordinationError::FenceMismatch);
    }
    Ok(())
}

fn reject_legacy_replay(
    owner: &super::CoordinationOwner,
    request: &super::WorkLeaseRequest,
) -> Result<(), WorkLeaseIssuanceFailure> {
    let Some(event) = owner
        .events
        .iter()
        .find(|event| event.idempotency_key == request.request_id)
    else {
        return Ok(());
    };
    if !event_matches_request(event, request) {
        return Err(
            super::CoordinationError::IdempotencyConflict(request.request_id.clone()).into(),
        );
    }
    Err(WorkLeaseIssuanceError::PostHocIssuanceRejected.into())
}

fn validate_candidate_records(
    owner: &super::CoordinationOwner,
    request: &super::WorkLeaseRequest,
    decision: &super::WorkLeaseDecision,
) -> Result<(), WorkLeaseIssuanceError> {
    let session = owner
        .sessions
        .get(&request.session_id)
        .ok_or(WorkLeaseIssuanceError::InconsistentOwnerEvidence)?;
    let item = owner
        .work
        .get(&request.work_item_id)
        .ok_or(WorkLeaseIssuanceError::InconsistentOwnerEvidence)?;
    let lease = owner
        .leases
        .get(&request.lease_id)
        .ok_or(WorkLeaseIssuanceError::InconsistentOwnerEvidence)?;
    if session.state != super::SessionState::Active
        || session.authority_epoch != request.authority_epoch
        || session.state_fence != request.state_fence
        || item.state != super::WorkState::Claimed
        || item.owner_session_id.as_deref() != Some(request.session_id.as_str())
        || item.lease_id.as_deref() != Some(request.lease_id.as_str())
        || item.state_fence != request.state_fence
        || lease != &decision.lease
    {
        return Err(WorkLeaseIssuanceError::InconsistentOwnerEvidence);
    }
    validate_request_binding(request, decision)
}

fn event_matches_request(
    event: &super::CoordinationEvent,
    request: &super::WorkLeaseRequest,
) -> bool {
    event.kind == super::CoordinationEventKind::WorkClaimed
        && event.idempotency_key == request.request_id
        && event.event_id == format!("claim:{}", request.lease_id)
        && event.subject_id == request.work_item_id
        && event.actor_id == request.session_id
        && event.authority_epoch == request.authority_epoch
        && event.state_fence == request.state_fence
        && event.payload_digest == request.lease_id
}

fn validate_request_binding(
    request: &super::WorkLeaseRequest,
    decision: &super::WorkLeaseDecision,
) -> Result<(), WorkLeaseIssuanceError> {
    let expires_at = request
        .now
        .checked_add(request.lease_duration)
        .ok_or(WorkLeaseIssuanceError::InconsistentOwnerEvidence)?;
    let lease = &decision.lease;
    if lease.lease_id != request.lease_id
        || lease.work_item_id != request.work_item_id
        || lease.holder_session_id != request.session_id
        || lease.authority_epoch != request.authority_epoch
        || lease.state_fence != request.state_fence
        || lease.issued_at != request.now
        || lease.expires_at != expires_at
        || lease.expires_at <= lease.issued_at
        || lease.last_heartbeat != request.now
        || !event_matches_request(&decision.event, request)
        || decision.event.sequence == 0
        || decision.event.predecessor != decision.event.sequence.checked_sub(1)
    {
        return Err(WorkLeaseIssuanceError::InconsistentOwnerEvidence);
    }
    request
        .state_fence
        .validate()
        .map_err(|_| WorkLeaseIssuanceError::InconsistentOwnerEvidence)
}

fn issue_provenance(
    source_request: super::WorkLeaseRequest,
    source_decision: super::WorkLeaseDecision,
) -> Result<WorkLeaseIssuanceProvenance, WorkLeaseIssuanceError> {
    let evidence = WorkLeaseIssuanceEvidence {
        revision: WORK_LEASE_ISSUANCE_REVISION,
        source_request: &source_request,
        source_decision: &source_decision,
    };
    let bytes = canonical_json_bytes(&evidence)
        .map_err(|_| WorkLeaseIssuanceError::EvidenceEncodingRejected)?;
    let evidence_commitment_sha256 = sha256_hex(&bytes);
    let canonical_work_lease_id = canonical_work_lease_id(&evidence_commitment_sha256)?;
    Ok(WorkLeaseIssuanceProvenance {
        canonical_work_lease_id,
        source_request,
        source_decision,
        evidence_commitment_sha256,
    })
}

fn canonical_work_lease_id(value: &str) -> Result<CanonicalWorkLeaseId, WorkLeaseIssuanceError> {
    let fields = [
        ("namespace", WORK_LEASE_NAMESPACE),
        ("revision", WORK_LEASE_WIRE_REVISION),
        ("value", value),
    ];
    let entries = fields.into_iter().map(|(key, field_value)| {
        (
            StringDeserializer::<ValueError>::new(key.to_owned()),
            StringDeserializer::<ValueError>::new(field_value.to_owned()),
        )
    });
    CanonicalWorkLeaseId::deserialize(MapDeserializer::<_, ValueError>::new(entries))
        .map_err(|_| WorkLeaseIssuanceError::CanonicalContractRejected)
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use eliot_contracts::{ClockReading, ResourceGeneration};

    use super::*;

    fn fence() -> StateFence {
        StateFence::new(AuthorityEpoch::genesis(), ResourceGeneration::genesis())
    }

    fn ready_owner() -> (super::super::CoordinationOwner, StateFence) {
        let mut owner = super::super::CoordinationOwner::new();
        let state_fence = fence();
        owner
            .register_session(super::super::RegisterSession {
                request_id: "register-session".to_owned(),
                session_id: "session-1".to_owned(),
                principal_id: "principal-1".to_owned(),
                route_ref: "route-1".to_owned(),
                authority_epoch: AuthorityEpoch::genesis(),
                state_fence: state_fence.clone(),
                now: 10,
                heartbeat_deadline: 100,
            })
            .expect("session registration");
        owner
            .register_work(
                super::super::WorkItem {
                    work_item_id: "work-1".to_owned(),
                    task_id: "task-1".to_owned(),
                    state: super::super::WorkState::Ready,
                    state_fence: state_fence.clone(),
                    owner_session_id: None,
                    lease_id: None,
                    attempt: 0,
                    checkpoint_ref: None,
                    result_ref: None,
                },
                "register-work",
                "principal-1",
                ClockReading::default(),
            )
            .expect("work registration");
        (owner, state_fence)
    }

    fn request(state_fence: &StateFence) -> super::super::WorkLeaseRequest {
        super::super::WorkLeaseRequest {
            request_id: "claim-work".to_owned(),
            lease_id: "lease-1".to_owned(),
            work_item_id: "work-1".to_owned(),
            session_id: "session-1".to_owned(),
            authority_epoch: AuthorityEpoch::genesis(),
            state_fence: state_fence.clone(),
            now: 20,
            lease_duration: 40,
        }
    }

    #[test]
    fn issuance_replay_is_exact_and_changed_input_conflicts() {
        let (mut owner, state_fence) = ready_owner();
        let claim = request(&state_fence);
        let first = owner
            .acquire_work_with_issuance(claim.clone())
            .expect("issuance");
        assert_eq!(
            first,
            owner.acquire_work_with_issuance(claim).expect("replay")
        );

        let mut changed = request(&state_fence);
        changed.lease_duration += 1;
        assert_eq!(
            owner.acquire_work_with_issuance(changed),
            Err(WorkLeaseIssuanceFailure::Coordination(
                super::super::CoordinationError::IdempotencyConflict("claim-work".to_owned())
            ))
        );
        assert_eq!(owner.events().len(), 3);
    }

    #[test]
    fn failed_provenance_keeps_the_transition_unpublished() {
        let (mut owner, state_fence) = ready_owner();
        let sequence = owner.current_sequence();
        let result = owner
            .acquire_work_with_issuance_using(request(&state_fence), |_request, _| {
                Err(WorkLeaseIssuanceError::EvidenceEncodingRejected)
            });
        assert_eq!(
            result,
            Err(WorkLeaseIssuanceFailure::Evidence(
                WorkLeaseIssuanceError::EvidenceEncodingRejected
            ))
        );
        assert_eq!(owner.current_sequence(), sequence);
        assert_eq!(owner.events().len(), 2);
        assert!(owner.work_lease_issuance("claim-work").is_none());
        assert!(
            owner
                .acquire_work_with_issuance(request(&state_fence))
                .is_ok()
        );
    }

    #[test]
    fn issuance_provenance_survives_heartbeat_and_recovery() {
        let (mut owner, state_fence) = ready_owner();
        let issued = owner
            .acquire_work_with_issuance(request(&state_fence))
            .expect("issuance");
        owner
            .heartbeat(super::super::AgentHeartbeat {
                request_id: "heartbeat-work".to_owned(),
                session_id: "session-1".to_owned(),
                lease_id: "lease-1".to_owned(),
                authority_epoch: AuthorityEpoch::genesis(),
                state_fence: state_fence.clone(),
                now: 25,
                extend_to: 80,
            })
            .expect("heartbeat");

        let recovered = super::super::CoordinationOwner::from_snapshot(owner)
            .expect("recovery after heartbeat");
        assert_eq!(
            recovered.work_lease_issuance("claim-work"),
            Some(issued.provenance().clone())
        );
    }
}
