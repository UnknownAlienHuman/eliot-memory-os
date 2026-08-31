use crate::{
    CoordinationError, CoordinationEvent, CoordinationEventKind, CoordinationOwner,
    WorkLeaseDecision, WorkLeaseRequest,
};
use eliot_contracts::{
    WORK_LEASE_NAMESPACE, WORK_LEASE_WIRE_REVISION, WorkLeaseId as CanonicalWorkLeaseId,
    canonical_json_bytes, sha256_hex,
};
use schemars::JsonSchema;
use serde::de::value::{Error as ValueError, MapDeserializer, StringDeserializer};
use serde::{Deserialize, Deserializer, Serialize, de};
use thiserror::Error;

const WORK_LEASE_ISSUANCE_REVISION: &str = "eliot.governor.work-lease-issuance.v1";

/// Classification of a successful current-owner `WorkLease` issuance.
#[derive(Clone, Copy, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum WorkLeaseIssuanceDisposition {
    /// The production coordination owner accepted the lease and emitted one
    /// immutable canonical identity from the exact same-call evidence.
    OwnerIssued,
}

/// Fail-closed defect in accepted owner evidence or its canonical form.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Error, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum WorkLeaseIssuanceError {
    /// A lease was accepted through the compatibility acquisition path and
    /// therefore cannot be upgraded to canonical issuance after the fact.
    #[error("canonical WorkLease issuance must occur in the same owner call as acquisition")]
    PostHocIssuanceRejected,
    /// The accepted request and returned owner records are not one coherent
    /// lease transition.
    #[error("accepted WorkLease issuance evidence is internally inconsistent")]
    InconsistentOwnerEvidence,
    /// The exact request and decision evidence could not be encoded canonically.
    #[error("WorkLease issuance evidence could not be encoded canonically")]
    EvidenceEncodingRejected,
    /// The canonical C0 `WorkLease` identity contract rejected the commitment.
    #[error("canonical WorkLease identity contract rejected owner-issued evidence")]
    CanonicalContractRejected,
}

/// Typed failure from the combined coordination and issuance boundary.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum WorkLeaseIssuanceFailure {
    /// The coordination owner rejected or could not apply the lease transition.
    #[error(transparent)]
    Coordination(#[from] CoordinationError),
    /// The transition or its immutable issuance evidence failed closed.
    #[error(transparent)]
    Evidence(#[from] WorkLeaseIssuanceError),
}

/// Immutable evidence that one accepted coordination transition issued one
/// canonical owner-neutral `WorkLease` identity.
///
/// The raw `lease_id` inside the source request and decision remains attributed
/// compatibility evidence only. The SHA-256 commitment is not independent
/// authority: authority exists through the same-call result from the current
/// [`CoordinationOwner`] and the continuing fenced lease lifecycle.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WorkLeaseIssuanceProvenance {
    canonical_work_lease_id: CanonicalWorkLeaseId,
    source_request: WorkLeaseRequest,
    source_decision: WorkLeaseDecision,
    evidence_commitment_sha256: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WorkLeaseIssuanceProvenanceWire {
    canonical_work_lease_id: CanonicalWorkLeaseId,
    source_request: WorkLeaseRequest,
    source_decision: WorkLeaseDecision,
    evidence_commitment_sha256: String,
}

impl<'de> Deserialize<'de> for WorkLeaseIssuanceProvenance {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = WorkLeaseIssuanceProvenanceWire::deserialize(deserializer)?;
        let provenance = Self {
            canonical_work_lease_id: wire.canonical_work_lease_id,
            source_request: wire.source_request,
            source_decision: wire.source_decision,
            evidence_commitment_sha256: wire.evidence_commitment_sha256,
        };
        provenance.validate().map_err(de::Error::custom)?;
        Ok(provenance)
    }
}

impl WorkLeaseIssuanceProvenance {
    /// Returns the canonical C0 `WorkLease` identity.
    #[must_use]
    pub const fn canonical_work_lease_id(&self) -> &CanonicalWorkLeaseId {
        &self.canonical_work_lease_id
    }

    /// Returns the exact request accepted by the coordination owner.
    #[must_use]
    pub const fn source_request(&self) -> &WorkLeaseRequest {
        &self.source_request
    }

    /// Returns the immutable accepted lease decision and causal event.
    #[must_use]
    pub const fn source_decision(&self) -> &WorkLeaseDecision {
        &self.source_decision
    }

    /// Returns the SHA-256 commitment to the canonical issuance evidence.
    #[must_use]
    pub fn evidence_commitment_sha256(&self) -> &str {
        &self.evidence_commitment_sha256
    }

    pub(crate) fn validate(&self) -> Result<(), WorkLeaseIssuanceError> {
        validate_request_binding(&self.source_request, &self.source_decision)?;
        validate_owner_evidence(&self.source_request, &self.source_decision)?;
        let expected = issue_provenance(
            self.source_request.clone(),
            self.source_decision.clone(),
        )?;
        if expected.canonical_work_lease_id != self.canonical_work_lease_id
            || expected.evidence_commitment_sha256 != self.evidence_commitment_sha256
        {
            return Err(WorkLeaseIssuanceError::InconsistentOwnerEvidence);
        }
        Ok(())
    }
}

/// Successful result of asking the current coordination owner to acquire and
/// identify one `WorkLease` in the same call.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WorkLeaseIssuanceResult {
    decision: WorkLeaseDecision,
    provenance: WorkLeaseIssuanceProvenance,
}

impl WorkLeaseIssuanceResult {
    /// Returns the only successful disposition admitted by this boundary.
    #[must_use]
    pub const fn disposition(&self) -> WorkLeaseIssuanceDisposition {
        WorkLeaseIssuanceDisposition::OwnerIssued
    }

    /// Returns the immutable accepted current-owner lease decision.
    #[must_use]
    pub const fn decision(&self) -> &WorkLeaseDecision {
        &self.decision
    }

    /// Returns the immutable canonical issuance provenance.
    #[must_use]
    pub const fn provenance(&self) -> &WorkLeaseIssuanceProvenance {
        &self.provenance
    }
}

#[derive(Serialize)]
struct WorkLeaseIssuanceEvidence<'a> {
    revision: &'static str,
    source_request: &'a WorkLeaseRequest,
    source_decision: &'a WorkLeaseDecision,
}

impl CoordinationOwner {
    /// Acquires one `WorkLease` and emits canonical issuance provenance from the
    /// exact accepted owner transition.
    ///
    /// The transition is first executed against a private candidate snapshot.
    /// Only after the fresh event and canonical provenance are validated are the
    /// lifecycle state and issuance map published together. Exact retry returns
    /// the original immutable issuance. A compatibility acquisition that did
    /// not issue provenance in its accepting call can never be upgraded later.
    pub fn acquire_work_with_issuance(
        &mut self,
        request: WorkLeaseRequest,
    ) -> Result<WorkLeaseIssuanceResult, WorkLeaseIssuanceFailure> {
        self.acquire_work_with_issuance_using(request, issue_provenance)
    }

    fn acquire_work_with_issuance_using<F>(
        &mut self,
        request: WorkLeaseRequest,
        provenance_issuer: F,
    ) -> Result<WorkLeaseIssuanceResult, WorkLeaseIssuanceFailure>
    where
        F: FnOnce(
            WorkLeaseRequest,
            WorkLeaseDecision,
        ) -> Result<WorkLeaseIssuanceProvenance, WorkLeaseIssuanceError>,
    {
        if let Some(existing) = self.stored_issuance(&request.request_id) {
            if existing.source_request() != &request {
                return Err(CoordinationError::IdempotencyConflict(request.request_id).into());
            }
            existing.validate()?;
            return Ok(WorkLeaseIssuanceResult {
                decision: existing.source_decision().clone(),
                provenance: existing.clone(),
            });
        }

        reject_legacy_or_conflicting_replay(self, &request)?;
        validate_fresh_request(&request)?;
        reject_reused_lease_identity(self, &request)?;

        let before_sequence = self.current_sequence();
        let expected_sequence = before_sequence
            .checked_add(1)
            .ok_or(CoordinationError::InvalidField("sequence"))?;
        let before_event_count = self.events().len();
        let expected_event_count = before_event_count
            .checked_add(1)
            .ok_or(CoordinationError::InvalidField("event_count"))?;

        let mut candidate_inner = self.inner.clone();
        let decision = candidate_inner.acquire_work(request.clone())?;
        if candidate_inner.current_sequence() != expected_sequence
            || candidate_inner.events().len() != expected_event_count
            || candidate_inner.events().last() != Some(&decision.event)
            || decision.event.sequence != expected_sequence
        {
            return Err(WorkLeaseIssuanceError::InconsistentOwnerEvidence.into());
        }

        validate_request_binding(&request, &decision)?;
        validate_owner_evidence(&request, &decision)?;
        let provenance = provenance_issuer(request.clone(), decision.clone())?;
        provenance.validate()?;

        let mut candidate_issuance = self.work_lease_issuance_by_request.clone();
        Self::insert_candidate_issuance(
            &mut candidate_issuance,
            request.request_id,
            provenance.clone(),
        )?;

        self.inner = candidate_inner;
        self.work_lease_issuance_by_request = candidate_issuance;
        Ok(WorkLeaseIssuanceResult {
            decision,
            provenance,
        })
    }
}

fn reject_legacy_or_conflicting_replay(
    owner: &CoordinationOwner,
    request: &WorkLeaseRequest,
) -> Result<(), WorkLeaseIssuanceFailure> {
    let mut matching_events = owner
        .events()
        .iter()
        .filter(|event| event.idempotency_key == request.request_id);
    let Some(event) = matching_events.next() else {
        return Ok(());
    };
    if matching_events.next().is_some() {
        return Err(WorkLeaseIssuanceError::InconsistentOwnerEvidence.into());
    }
    if !event_matches_request(event, request) {
        return Err(CoordinationError::IdempotencyConflict(request.request_id.clone()).into());
    }

    let mut probe = owner.inner.clone();
    let decision = probe.acquire_work(request.clone()).map_err(|_| {
        WorkLeaseIssuanceFailure::Coordination(CoordinationError::IdempotencyConflict(
            request.request_id.clone(),
        ))
    })?;
    if !legacy_stable_binding_matches(request, &decision) {
        return Err(CoordinationError::IdempotencyConflict(request.request_id.clone()).into());
    }
    Err(WorkLeaseIssuanceError::PostHocIssuanceRejected.into())
}

fn reject_reused_lease_identity(
    owner: &CoordinationOwner,
    request: &WorkLeaseRequest,
) -> Result<(), CoordinationError> {
    if owner.events().iter().any(|event| {
        event.kind == CoordinationEventKind::WorkClaimed
            && event.payload_digest == request.lease_id
    }) {
        return Err(CoordinationError::Duplicate(request.lease_id.clone()));
    }
    Ok(())
}

fn validate_fresh_request(request: &WorkLeaseRequest) -> Result<(), CoordinationError> {
    for (value, field) in [
        (&request.request_id, "request_id"),
        (&request.lease_id, "lease_id"),
        (&request.work_item_id, "work_item_id"),
        (&request.session_id, "session_id"),
    ] {
        if value.trim().is_empty() || value.chars().any(char::is_control) {
            return Err(CoordinationError::InvalidField(field));
        }
    }
    if request.authority_epoch != request.state_fence.authority_epoch {
        return Err(CoordinationError::EpochMismatch);
    }
    request
        .state_fence
        .validate()
        .map_err(|_| CoordinationError::FenceMismatch)?;
    if request.now == 0 {
        return Err(CoordinationError::InvalidField("now"));
    }
    if request.lease_duration == 0
        || request.now.checked_add(request.lease_duration).is_none()
    {
        return Err(CoordinationError::InvalidField("lease_duration"));
    }
    Ok(())
}

fn event_matches_request(event: &CoordinationEvent, request: &WorkLeaseRequest) -> bool {
    event.kind == CoordinationEventKind::WorkClaimed
        && event.event_id == format!("claim:{}", request.lease_id)
        && event.subject_id == request.work_item_id
        && event.actor_id == request.session_id
        && event.authority_epoch == request.authority_epoch
        && event.state_fence == request.state_fence
        && event.payload_digest == request.lease_id
}

fn legacy_stable_binding_matches(
    request: &WorkLeaseRequest,
    decision: &WorkLeaseDecision,
) -> bool {
    let lease = &decision.lease;
    let expected_expires_at = request.now.checked_add(request.lease_duration);
    lease.lease_id == request.lease_id
        && lease.work_item_id == request.work_item_id
        && lease.holder_session_id == request.session_id
        && lease.authority_epoch == request.authority_epoch
        && lease.state_fence == request.state_fence
        && lease.issued_at == request.now
        && lease.last_heartbeat == lease.issued_at
        && expected_expires_at == Some(lease.expires_at)
        && event_matches_request(&decision.event, request)
}

fn validate_request_binding(
    request: &WorkLeaseRequest,
    decision: &WorkLeaseDecision,
) -> Result<(), WorkLeaseIssuanceError> {
    let expected_expires_at = request
        .now
        .checked_add(request.lease_duration)
        .ok_or(WorkLeaseIssuanceError::InconsistentOwnerEvidence)?;
    let lease = &decision.lease;
    let event = &decision.event;
    if lease.lease_id != request.lease_id
        || lease.work_item_id != request.work_item_id
        || lease.holder_session_id != request.session_id
        || lease.authority_epoch != request.authority_epoch
        || lease.state_fence != request.state_fence
        || lease.issued_at != request.now
        || lease.expires_at != expected_expires_at
        || lease.last_heartbeat != request.now
        || event.idempotency_key != request.request_id
        || !event_matches_request(event, request)
    {
        return Err(WorkLeaseIssuanceError::InconsistentOwnerEvidence);
    }
    Ok(())
}

fn validate_owner_evidence(
    request: &WorkLeaseRequest,
    decision: &WorkLeaseDecision,
) -> Result<(), WorkLeaseIssuanceError> {
    if decision.event.sequence == 0
        || request.lease_duration == 0
        || request.request_id.trim().is_empty()
        || request.lease_id.trim().is_empty()
        || request.work_item_id.trim().is_empty()
        || request.session_id.trim().is_empty()
    {
        return Err(WorkLeaseIssuanceError::InconsistentOwnerEvidence);
    }
    Ok(())
}

fn issue_provenance(
    source_request: WorkLeaseRequest,
    source_decision: WorkLeaseDecision,
) -> Result<WorkLeaseIssuanceProvenance, WorkLeaseIssuanceError> {
    let evidence = WorkLeaseIssuanceEvidence {
        revision: WORK_LEASE_ISSUANCE_REVISION,
        source_request: &source_request,
        source_decision: &source_decision,
    };
    let evidence_bytes = canonical_json_bytes(&evidence)
        .map_err(|_| WorkLeaseIssuanceError::EvidenceEncodingRejected)?;
    let evidence_commitment_sha256 = sha256_hex(&evidence_bytes);
    let canonical_work_lease_id = canonical_work_lease_id(&evidence_commitment_sha256)?;
    Ok(WorkLeaseIssuanceProvenance {
        canonical_work_lease_id,
        source_request,
        source_decision,
        evidence_commitment_sha256,
    })
}

fn canonical_work_lease_id(
    value: &str,
) -> Result<CanonicalWorkLeaseId, WorkLeaseIssuanceError> {
    let fields = [
        ("namespace".to_owned(), WORK_LEASE_NAMESPACE.to_owned()),
        ("revision".to_owned(), WORK_LEASE_WIRE_REVISION.to_owned()),
        ("value".to_owned(), value.to_owned()),
    ];
    let entries = fields.into_iter().map(|(key, field_value)| {
        (
            StringDeserializer::<ValueError>::new(key),
            StringDeserializer::<ValueError>::new(field_value),
        )
    });
    CanonicalWorkLeaseId::deserialize(MapDeserializer::<_, ValueError>::new(entries))
        .map_err(|_| WorkLeaseIssuanceError::CanonicalContractRejected)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{RegisterSession, WorkItem, WorkState};
    use eliot_contracts::{AuthorityEpoch, ClockReading, ResourceGeneration, StateFence};

    fn state_fence() -> StateFence {
        StateFence::new(AuthorityEpoch::genesis(), ResourceGeneration::genesis())
    }

    fn owner_and_request() -> Result<(CoordinationOwner, WorkLeaseRequest), CoordinationError> {
        let mut owner = CoordinationOwner::new();
        let fence = state_fence();
        owner.register_session(RegisterSession {
            request_id: "register-session".to_owned(),
            session_id: "session-1".to_owned(),
            principal_id: "principal-1".to_owned(),
            route_ref: "route-1".to_owned(),
            authority_epoch: AuthorityEpoch::genesis(),
            state_fence: fence.clone(),
            now: 10,
            heartbeat_deadline: 100,
        })?;
        owner.register_work(
            WorkItem {
                work_item_id: "work-1".to_owned(),
                task_id: "task-1".to_owned(),
                state: WorkState::Ready,
                state_fence: fence.clone(),
                owner_session_id: None,
                lease_id: None,
                attempt: 0,
                checkpoint_ref: None,
                result_ref: None,
            },
            "register-work",
            "principal-1",
            ClockReading {
                valid_time_ms: None,
                known_time_ms: None,
                transaction_sequence: None,
                monotonic_ns: None,
            },
        )?;
        let request = WorkLeaseRequest {
            request_id: "claim-work".to_owned(),
            lease_id: "legacy-lease-1".to_owned(),
            work_item_id: "work-1".to_owned(),
            session_id: "session-1".to_owned(),
            authority_epoch: AuthorityEpoch::genesis(),
            state_fence: fence,
            now: 20,
            lease_duration: 40,
        };
        Ok((owner, request))
    }

    #[test]
    fn evidence_failure_does_not_publish_lease_or_issuance_state() -> Result<(), CoordinationError> {
        let (mut owner, request) = owner_and_request()?;
        let before_sequence = owner.current_sequence();
        let before_events = owner.events().to_vec();

        let failure = owner.acquire_work_with_issuance_using(
            request.clone(),
            |_request, _decision| Err(WorkLeaseIssuanceError::EvidenceEncodingRejected),
        );
        assert_eq!(
            failure,
            Err(WorkLeaseIssuanceFailure::Evidence(
                WorkLeaseIssuanceError::EvidenceEncodingRejected
            ))
        );
        assert_eq!(owner.current_sequence(), before_sequence);
        assert_eq!(owner.events(), before_events);

        let accepted = owner.acquire_work_with_issuance(request);
        assert!(accepted.is_ok());
        assert_eq!(owner.current_sequence(), before_sequence + 1);
        Ok(())
    }
}
