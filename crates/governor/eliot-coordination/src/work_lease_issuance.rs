use crate::{
    CoordinationError, CoordinationEventKind, CoordinationOwner, WorkLeaseDecision,
    WorkLeaseRequest,
};
use eliot_contracts::{
    WORK_LEASE_NAMESPACE, WORK_LEASE_WIRE_REVISION, WorkLeaseId as CanonicalWorkLeaseId,
    canonical_json_bytes, sha256_hex,
};
use serde::de::value::{Error as ValueError, MapDeserializer, StringDeserializer};
use serde::{Deserialize, Deserializer, Serialize, de};
use thiserror::Error;

const WORK_LEASE_ISSUANCE_REVISION: &str = "eliot.governor.work-lease-issuance.v1";

/// Classification of a successful current-owner WorkLease issuance.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WorkLeaseIssuanceDisposition {
    /// The production coordination owner accepted the lease and emitted one
    /// immutable canonical identity from the exact same-call evidence.
    OwnerIssued,
}

/// Fail-closed defect in the accepted owner evidence or its canonical form.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum WorkLeaseIssuanceError {
    /// The accepted request and returned owner records are not one coherent
    /// lease transition.
    #[error("accepted WorkLease issuance evidence is internally inconsistent")]
    InconsistentOwnerEvidence,
    /// The exact request/decision evidence could not be encoded canonically.
    #[error("WorkLease issuance evidence could not be encoded canonically")]
    EvidenceEncodingRejected,
    /// The canonical C0 WorkLease identity contract rejected the commitment.
    #[error("canonical WorkLease identity contract rejected owner-issued evidence")]
    CanonicalContractRejected,
}

/// Typed failure from the combined coordination and issuance boundary.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum WorkLeaseIssuanceFailure {
    /// The existing coordination owner rejected or could not apply the lease
    /// transition.
    #[error(transparent)]
    Coordination(#[from] CoordinationError),
    /// The lease transition was accepted, but its exact issuance evidence could
    /// not safely produce the canonical identity.
    #[error(transparent)]
    Evidence(#[from] WorkLeaseIssuanceError),
}

/// Immutable evidence that one accepted coordination transition issued one
/// canonical owner-neutral WorkLease identity.
///
/// The raw `lease_id` inside the source request/decision remains attributed
/// compatibility evidence only. The SHA-256 commitment is not independent
/// authority: the authority-bearing fact is the same-call result from the
/// current [`CoordinationOwner`] and the continuing fenced lease lifecycle.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
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
    /// Returns the canonical C0 WorkLease identity.
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
/// identify one WorkLease in the same call.
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
    /// Acquires one WorkLease and emits canonical issuance provenance from the
    /// exact accepted owner transition.
    ///
    /// An exact retry returns the original immutable issuance even after the
    /// live lease has been renewed or otherwise advanced. Changed bytes under
    /// the same request identity fail before another owner mutation.
    pub fn acquire_work_with_issuance(
        &mut self,
        request: WorkLeaseRequest,
    ) -> Result<WorkLeaseIssuanceResult, WorkLeaseIssuanceFailure> {
        if let Some(existing) = self.stored_issuance(&request.request_id) {
            if existing.source_request() != &request {
                return Err(CoordinationError::IdempotencyConflict(
                    request.request_id,
                )
                .into());
            }
            existing.validate()?;
            return Ok(WorkLeaseIssuanceResult {
                decision: existing.source_decision().clone(),
                provenance: existing.clone(),
            });
        }

        preflight_existing_request(self, &request)?;
        let source_request = request.clone();
        let decision = self.inner.acquire_work(request)?;
        validate_request_binding(&source_request, &decision)?;
        validate_owner_evidence(&source_request, &decision)?;
        let provenance = issue_provenance(source_request.clone(), decision.clone())?;
        self.store_issuance(source_request.request_id, provenance.clone())?;
        Ok(WorkLeaseIssuanceResult {
            decision,
            provenance,
        })
    }
}

fn preflight_existing_request(
    owner: &CoordinationOwner,
    request: &WorkLeaseRequest,
) -> Result<(), CoordinationError> {
    let Some(event) = owner
        .events()
        .iter()
        .find(|event| event.idempotency_key == request.request_id)
    else {
        return Ok(());
    };
    if event.kind != CoordinationEventKind::WorkClaimed
        || event.subject_id != request.work_item_id
        || event.actor_id != request.session_id
        || event.payload_digest != request.lease_id
        || event.authority_epoch != request.authority_epoch
        || event.state_fence != request.state_fence
    {
        return Err(CoordinationError::IdempotencyConflict(
            request.request_id.clone(),
        ));
    }
    Ok(())
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
        || event.subject_id != request.work_item_id
        || event.actor_id != request.session_id
        || event.authority_epoch != request.authority_epoch
        || event.state_fence != request.state_fence
        || event.payload_digest != request.lease_id
    {
        return Err(WorkLeaseIssuanceError::InconsistentOwnerEvidence);
    }
    Ok(())
}

fn validate_owner_evidence(
    request: &WorkLeaseRequest,
    decision: &WorkLeaseDecision,
) -> Result<(), WorkLeaseIssuanceError> {
    if decision.event.kind != CoordinationEventKind::WorkClaimed
        || decision.event.event_id != format!("claim:{}", request.lease_id)
        || decision.event.sequence == 0
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
