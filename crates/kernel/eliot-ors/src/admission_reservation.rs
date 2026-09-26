//! Durable Kernel-owned work-admission reservation state.
//!
//! The record is operational evidence only. Claim references remain opaque
//! owner references; this module does not interpret policy or issue canonical
//! work-admission authority.

use serde::{Deserialize, Serialize};

use crate::{
    EpochLineage, OpaqueLabel, OperationIdentity, OperationalMutationReceipt, OrsError,
    StateFenceSnapshot,
};
use eliot_receipts::ReceiptIdentity;

/// Immutable, digest-bound reference to one owner-defined admission claim.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdmissionReservationClaimRef {
    /// Owner-scoped immutable claim identity.
    pub reference: OpaqueLabel,
    /// Digest of the exact owner-defined claim bytes.
    pub sha256: String,
}

impl AdmissionReservationClaimRef {
    /// Validates the opaque identity and its content digest shape.
    pub fn validate(&self) -> Result<(), OrsError> {
        if self.sha256.len() != 64
            || !self
                .sha256
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(OrsError::InvalidField {
                field: "admission_reservation_claim.sha256",
                reason: "must be a lowercase SHA-256 digest",
            });
        }
        Ok(())
    }
}

/// Complete claim-reference set retained with one admission reservation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdmissionReservationClaims {
    /// Immutable manifest reference for the complete resource-claim set.
    pub resources: AdmissionReservationClaimRef,
    /// Exact scheduler lane claim.
    pub lane: AdmissionReservationClaimRef,
    /// Exact environment claim.
    pub environment: AdmissionReservationClaimRef,
    /// Immutable manifest reference for the complete effect-claim set. The
    /// referenced set may be empty when the admitted work has no effects.
    pub effects: AdmissionReservationClaimRef,
    /// Exact pessimistic cost and quota view claim.
    pub quota_view: AdmissionReservationClaimRef,
}

impl AdmissionReservationClaims {
    /// Validates the complete claim-reference set without interpreting owners.
    pub fn validate(&self) -> Result<(), OrsError> {
        let claims = [
            &self.resources,
            &self.lane,
            &self.environment,
            &self.effects,
            &self.quota_view,
        ];
        let mut identities = std::collections::BTreeMap::new();
        for claim in claims {
            claim.validate()?;
            if let Some(existing) = identities.insert(claim.reference.as_str(), &claim.sha256)
                && existing != &claim.sha256
            {
                return Err(OrsError::DuplicateConflict);
            }
        }
        Ok(())
    }
}

/// Lifecycle of one stable work-admission reservation identity.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AdmissionReservationState {
    /// Claims are durable but cannot authorize provisioning or launch.
    StagedInactive,
    /// Claims were activated against canonical admission and exact fence/epoch.
    Active,
    /// Claims were explicitly released with a durable reason.
    Released,
    /// Inactive claims reached their declared expiry boundary.
    Expired,
    /// An uncertain transition is held for exact reconciliation only.
    Reconciling,
}

/// Typed, durable reservation record. `operation_id` changes for each ORS
/// transition while `reservation_id` and the original binding remain stable.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdmissionReservationRecord {
    /// Stable identity reused by recovery and retry.
    pub reservation_id: OperationIdentity,
    /// Work item whose admission is being reserved.
    pub work_item_id: OperationIdentity,
    /// Attempt identity proposed before canonical admission.
    pub proposed_attempt_id: OperationIdentity,
    /// Immutable identity of the first stage request for this reservation.
    pub stage_operation_id: OperationIdentity,
    /// ORS mutation identity for the current lifecycle revision.
    pub operation_id: OperationIdentity,
    /// Complete immutable resource, lane, environment, effect and quota refs.
    pub claims: AdmissionReservationClaims,
    /// Authority epoch owning this exact admission proposal.
    pub authority_epoch: EpochLineage,
    /// Exact State Fence observed when the reservation was created.
    pub state_fence: StateFenceSnapshot,
    /// Canonical ADMITTED receipt identity, when the canonical owner supplies it.
    pub canonical_admission_receipt: Option<ReceiptIdentity>,
    /// ORS activation receipt identity, when an authorized activation exists.
    pub activation_receipt: Option<ReceiptIdentity>,
    /// Inactive reservation expiry boundary in Unix milliseconds.
    pub expires_at_ms: i64,
    /// Current reservation lifecycle state.
    pub state: AdmissionReservationState,
    /// Receipt-backed terminal disposition reason, when released or expired.
    pub disposition_reason: Option<OpaqueLabel>,
    /// Immutable evidence reference for reconciling/terminal disposition.
    pub disposition_evidence: Option<AdmissionReservationClaimRef>,
    /// Exact request for the latest receipt-backed lifecycle transition.
    pub last_transition: Option<AdmissionReservationTransitionRequest>,
    /// Creation time in Unix milliseconds.
    pub created_at_ms: i64,
    /// Last lifecycle transition time in Unix milliseconds.
    pub updated_at_ms: i64,
}

impl AdmissionReservationRecord {
    /// Validates identity, immutable claims, fence/epoch binding and lifecycle shape.
    pub fn validate(&self) -> Result<(), OrsError> {
        self.claims.validate()?;
        self.authority_epoch.validate()?;
        self.state_fence.validate()?;
        if self.authority_epoch.current.epoch != self.state_fence.observed_authority_epoch {
            return Err(OrsError::FenceMismatch);
        }
        if self.created_at_ms <= 0 || self.updated_at_ms < self.created_at_ms {
            return Err(OrsError::InvalidField {
                field: "admission_reservation.timestamps",
                reason: "creation and update times must be positive and ordered",
            });
        }
        if self.expires_at_ms <= self.created_at_ms {
            return Err(OrsError::InvalidExpiry);
        }
        match self.state {
            AdmissionReservationState::StagedInactive => {
                if self.stage_operation_id != self.operation_id
                    || self.canonical_admission_receipt.is_some()
                    || self.activation_receipt.is_some()
                    || self.disposition_reason.is_some()
                    || self.disposition_evidence.is_some()
                    || self.last_transition.is_some()
                {
                    return Err(OrsError::InvalidTransition);
                }
            }
            AdmissionReservationState::Active => {
                if self.canonical_admission_receipt.is_none()
                    || self.activation_receipt.is_none()
                    || self.disposition_reason.is_some()
                    || self.disposition_evidence.is_some()
                {
                    return Err(OrsError::InvalidTransition);
                }
            }
            AdmissionReservationState::Released | AdmissionReservationState::Expired => {
                if self.disposition_reason.is_none()
                    || self.disposition_evidence.is_none()
                    || self.last_transition.as_ref().is_none_or(|transition| {
                        transition.target_state != self.state
                            || transition.operation_id != self.operation_id
                            || transition.operation_id == self.stage_operation_id
                            || transition.authority_epoch != self.authority_epoch
                            || transition.state_fence != self.state_fence
                            || transition.now_ms != self.updated_at_ms
                            || self.disposition_reason.as_ref() != Some(&transition.reason)
                            || self.disposition_evidence.as_ref() != Some(&transition.evidence)
                    })
                {
                    return Err(OrsError::InvalidTransition);
                }
            }
            AdmissionReservationState::Reconciling => {
                if self.disposition_evidence.is_none()
                    || self.last_transition.as_ref().is_none_or(|transition| {
                        transition.target_state != self.state
                            || transition.operation_id != self.operation_id
                            || transition.operation_id == self.stage_operation_id
                            || transition.authority_epoch != self.authority_epoch
                            || transition.state_fence != self.state_fence
                            || transition.now_ms != self.updated_at_ms
                            || self.disposition_reason.as_ref() != Some(&transition.reason)
                            || self.disposition_evidence.as_ref() != Some(&transition.evidence)
                    })
                {
                    return Err(OrsError::InvalidTransition);
                }
            }
        }
        if let Some(evidence) = &self.disposition_evidence {
            evidence.validate()?;
        }
        Ok(())
    }
}

/// One ORS readback of a reservation and its current store-issued receipt.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct AdmissionReservationSnapshot {
    record: AdmissionReservationRecord,
    receipt: OperationalMutationReceipt,
}

impl AdmissionReservationSnapshot {
    pub(crate) const fn from_store(
        record: AdmissionReservationRecord,
        receipt: OperationalMutationReceipt,
    ) -> Self {
        Self { record, receipt }
    }

    /// Exact typed admission reservation read from ORS.
    pub const fn record(&self) -> &AdmissionReservationRecord {
        &self.record
    }

    /// Store-issued receipt binding the exact persisted current row.
    pub const fn receipt(&self) -> &OperationalMutationReceipt {
        &self.receipt
    }
}

/// Required inputs for one exact staged-inactive reservation transition.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdmissionReservationStage {
    /// Stable reservation identity supplied by the admission owner.
    pub reservation_id: OperationIdentity,
    /// Work identity the reservation covers.
    pub work_item_id: OperationIdentity,
    /// Stable proposed attempt identity.
    pub proposed_attempt_id: OperationIdentity,
    /// ORS operation identity for this first stage.
    pub operation_id: OperationIdentity,
    /// Exact complete owner-defined claims.
    pub claims: AdmissionReservationClaims,
    /// Epoch and State Fence captured by the caller.
    pub authority_epoch: EpochLineage,
    /// Exact State Fence captured with the epoch.
    pub state_fence: StateFenceSnapshot,
    /// Exact expiry boundary.
    pub expires_at_ms: i64,
    /// Stage time in Unix milliseconds.
    pub now_ms: i64,
}

/// Required evidence for a receipt-backed reservation disposition.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdmissionReservationDisposition {
    /// Stable reservation identity.
    pub reservation_id: OperationIdentity,
    /// Fresh ORS transition operation identity.
    pub operation_id: OperationIdentity,
    /// Receipt-backed disposition reason.
    pub reason: OpaqueLabel,
    /// Exact evidence supporting the disposition.
    pub evidence: AdmissionReservationClaimRef,
    /// Exact current ORS receipt observed before this transition.
    pub expected_current_receipt: OperationalMutationReceipt,
    /// Immutable authority and fence binding expected by the caller.
    pub authority_epoch: EpochLineage,
    /// Exact current State Fence expected by the caller.
    pub state_fence: StateFenceSnapshot,
    /// Observed transition time in Unix milliseconds.
    pub now_ms: i64,
}

/// Persisted request identity for an exact transition and its idempotent replay.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdmissionReservationTransitionRequest {
    /// Fresh ORS operation identity.
    pub operation_id: OperationIdentity,
    /// Requested lifecycle target.
    pub target_state: AdmissionReservationState,
    /// Receipt-backed disposition reason.
    pub reason: OpaqueLabel,
    /// Exact evidence supporting the disposition.
    pub evidence: AdmissionReservationClaimRef,
    /// Exact current receipt against which this request was issued.
    pub expected_current_receipt: OperationalMutationReceipt,
    /// Expected immutable authority epoch.
    pub authority_epoch: EpochLineage,
    /// Expected immutable State Fence.
    pub state_fence: StateFenceSnapshot,
    /// Observed transition time in Unix milliseconds.
    pub now_ms: i64,
}
