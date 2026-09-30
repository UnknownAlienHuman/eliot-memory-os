//! Durable Kernel-owned work-admission reservation state.
//!
//! The record is operational evidence only. Claim references remain opaque
//! owner references; this module does not interpret policy or issue canonical
//! work-admission authority.
//!
//! The read-only launch prerequisite at the end of this module is the one
//! narrow verification surface over that state. It grants nothing itself: it
//! re-derives the current disposition and issues a sealed active typestate that
//! only this module can construct.

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

/// Exact owner evidence committed by one activation transition.
///
/// An `Active` reservation must carry BOTH halves of the #1678 saga join: the
/// owner-issued canonical admission receipt returned by the canonical
/// `ADMITTED` readback, and the ORS activation receipt that names this exact
/// reservation. The canonical half is never inferred in Kernel and never
/// fabricated from a successful transport response; it is copied verbatim from
/// the receipt the canonical owner issued. The ORS half names the resulting row.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdmissionReservationActivation {
    /// Owner-issued canonical admission receipt for the exact `ADMITTED` write.
    pub canonical_admission_receipt: ReceiptIdentity,
    /// ORS activation receipt committed alongside the resulting active row.
    pub activation_receipt: ReceiptIdentity,
}

impl AdmissionReservationActivation {
    /// Validates both receipt references as well-shaped owner evidence.
    ///
    /// The two references are checked with the shape rules the receipts crate
    /// itself applies to an issued identity — a lowercase SHA-256 canonical
    /// digest and a `receipt-`-namespaced, non-blank receipt id. Nothing is
    /// recomputed from the record in order to be trusted: the caller's copy is
    /// validated, and the caller is the canonical owner that issued it.
    ///
    /// # Errors
    ///
    /// Returns [`OrsError::InvalidField`] naming the first malformed half.
    pub fn validate(&self) -> Result<(), OrsError> {
        validate_receipt_identity(
            &self.canonical_admission_receipt,
            "admission_reservation_activation.canonical_admission_receipt",
        )?;
        validate_receipt_identity(
            &self.activation_receipt,
            "admission_reservation_activation.activation_receipt",
        )?;
        if self.canonical_admission_receipt == self.activation_receipt {
            return Err(OrsError::InvalidField {
                field: "admission_reservation_activation.activation_receipt",
                reason: "the ORS activation receipt must be distinct from the canonical admission receipt",
            });
        }
        Ok(())
    }
}

/// Validates one `ReceiptIdentity` against the shape rules the receipts owner
/// applies when it issues an identity.
fn validate_receipt_identity(
    identity: &ReceiptIdentity,
    field: &'static str,
) -> Result<(), OrsError> {
    let receipt_id = identity.receipt_id.as_str();
    if receipt_id.trim().is_empty() || receipt_id.chars().any(char::is_control) {
        return Err(OrsError::InvalidField {
            field,
            reason: "receipt identity must be a non-blank control-free label",
        });
    }
    let digest = identity.canonical_sha256.as_str();
    if digest.len() != 64
        || !digest
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(OrsError::InvalidField {
            field,
            reason: "canonical receipt digest must be a lowercase SHA-256 digest",
        });
    }
    Ok(())
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
                    || self.last_transition.as_ref().is_none_or(|transition| {
                        transition.target_state != self.state
                            || transition.operation_id != self.operation_id
                            || transition.operation_id == self.stage_operation_id
                            || transition.authority_epoch != self.authority_epoch
                            || transition.state_fence != self.state_fence
                            || transition.now_ms != self.updated_at_ms
                            || transition
                                .activation
                                .as_ref()
                                .is_none_or(|activation| {
                                    Some(&activation.canonical_admission_receipt)
                                        != self.canonical_admission_receipt.as_ref()
                                        || Some(&activation.activation_receipt)
                                            != self.activation_receipt.as_ref()
                                })
                    })
                {
                    return Err(OrsError::InvalidTransition);
                }
                if let Some(transition) = &self.last_transition
                    && let Some(activation) = &transition.activation
                {
                    activation.validate()?;
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
    /// Owner evidence committed by an `Active` transition. `None` for every
    /// disposition transition, and `Some` for exactly the one that activated
    /// this reservation, so a replay of the same operation identity is
    /// decidable by comparing this whole request.
    #[serde(default)]
    pub activation: Option<AdmissionReservationActivation>,
}

/// Required owner evidence for one exact `StagedInactive`/`Reconciling` →
/// `Active` reservation transition (REQ6, A4).
///
/// Every field here is a fact that must already hold before the row may be
/// activated. The request carries no launch authority by itself: it is the
/// evidence the ORS owner compares against the durable row it is about to
/// mutate, and it is refused field by field on any disagreement. In
/// particular:
///
/// - `expected_current_receipt` is the CAS precondition. It is compared
///   against the current stored receipt, not merely recorded.
/// - `canonical_admission_receipt` is the owner-issued receipt returned by the
///   canonical `ADMITTED` readback. Kernel never infers it from a transport
///   response.
/// - `activation_receipt` is the durable ORS activation receipt that commits
///   the resulting active row and is the reference #1701 must later verify.
/// - `claims` must equal the immutable claims the reservation was staged with;
///   a different claim set under one saga identity is an identity conflict.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdmissionReservationActivationRequest {
    /// Stable reservation identity being activated.
    pub reservation_id: OperationIdentity,
    /// Work item the reservation covers; must match the staged row.
    pub work_item_id: OperationIdentity,
    /// Proposed attempt the reservation covers; must match the staged row.
    pub proposed_attempt_id: OperationIdentity,
    /// Fresh ORS operation identity for this activation transition.
    pub operation_id: OperationIdentity,
    /// Complete immutable claims expected to be exactly the staged claims.
    pub claims: AdmissionReservationClaims,
    /// Owner-issued canonical admission receipt for the exact `ADMITTED` write.
    pub canonical_admission_receipt: ReceiptIdentity,
    /// Durable ORS activation receipt committed with the resulting row.
    pub activation_receipt: ReceiptIdentity,
    /// Exact current ORS receipt observed before this transition.
    pub expected_current_receipt: OperationalMutationReceipt,
    /// Immutable authority and fence binding expected by the caller.
    pub authority_epoch: EpochLineage,
    /// Exact current State Fence expected by the caller.
    pub state_fence: StateFenceSnapshot,
    /// Observed activation time in Unix milliseconds.
    pub now_ms: i64,
}

/// The durable result of one activation: the active snapshot plus the two
/// receipt references that commit it (A4).
///
/// Both references are echoed from the row the store actually persisted, not
/// from the caller's request, so the returned activation receipt is a
/// readback of committed state. `activation_receipt` is the reference #1701
/// must later carry into the launch-prerequisite verifier; it is the same
/// value [`ActiveAdmissionReservation::activation_receipt`] exposes once the
/// verifier has re-derived the active disposition.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct AdmissionReservationActivatedOutcome {
    /// Reservation identity that was activated.
    pub reservation_id: OperationIdentity,
    /// Durable ORS snapshot read back for that exact identity.
    pub snapshot: AdmissionReservationSnapshot,
}

impl AdmissionReservationActivatedOutcome {
    pub(crate) fn from_store(
        reservation_id: OperationIdentity,
        snapshot: AdmissionReservationSnapshot,
    ) -> Self {
        Self {
            reservation_id,
            snapshot,
        }
    }

    /// Owner-issued ORS activation receipt reference committed by this row.
    ///
    /// # Errors
    ///
    /// Returns [`OrsError::InvalidTransition`] when the durable row carries no
    /// activation receipt. `AdmissionReservationRecord::validate` already
    /// refuses that, so this stays a typed refusal rather than a panic.
    pub fn activation_receipt(&self) -> Result<&ReceiptIdentity, OrsError> {
        self.snapshot
            .record()
            .activation_receipt
            .as_ref()
            .ok_or(OrsError::InvalidTransition)
    }

    /// Owner-issued canonical admission receipt reference committed by this row.
    ///
    /// # Errors
    ///
    /// Returns [`OrsError::InvalidTransition`] when the durable row carries no
    /// canonical admission receipt, for the same reason as
    /// [`Self::activation_receipt`].
    pub fn canonical_admission_receipt(&self) -> Result<&ReceiptIdentity, OrsError> {
        self.snapshot
            .record()
            .canonical_admission_receipt
            .as_ref()
            .ok_or(OrsError::InvalidTransition)
    }
}

/// Closed read-only verification result for one launch prerequisite.
///
/// The variants are exactly the dispositions a launch consumer must be able to
/// tell apart. Only [`Self::Active`] carries launch authority, and it carries
/// an [`ActiveAdmissionReservation`] that an ordinary caller can neither build
/// nor deserialize. Every other variant is inert durable evidence naming the
/// exact reason the prerequisite does not hold.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AdmissionReservationLaunchPrerequisite {
    /// No durable reservation covers the expected work item and attempt.
    Missing {
        /// Work item whose admission reservation was expected.
        work_item_id: OperationIdentity,
        /// Proposed attempt whose admission reservation was expected.
        proposed_attempt_id: OperationIdentity,
    },
    /// Claims are durable but were never activated, so they cannot provision or
    /// launch. A staged record that already carried a canonical admission or
    /// activation receipt is not representable:
    /// [`AdmissionReservationRecord::validate`] refuses it, so this verifier
    /// never has to decide what such a record would mean.
    Staged {
        /// Exact durable staged record.
        reservation: AdmissionReservationRecord,
    },
    /// The exact reservation is active under the caller's current authority.
    Active(ActiveAdmissionReservation),
    /// Claims were explicitly released with a durable disposition.
    Released {
        /// Exact durable released record with its retained disposition evidence.
        reservation: AdmissionReservationRecord,
    },
    /// Claims are expired: either the durable `Expired` transition exists, or
    /// the declared `expires_at_ms` boundary already elapsed without a new
    /// activation.
    Expired {
        /// Exact durable record read at the expiry boundary.
        reservation: AdmissionReservationRecord,
    },
    /// An uncertain transition is held for exact reconciliation only and
    /// cannot create a new effect.
    Reconciling {
        /// Exact durable reconciling record with its retained evidence.
        reservation: AdmissionReservationRecord,
    },
    /// The reservation was written under a different State Fence than the
    /// caller's current one, so the world moved since it was staged.
    StaleFence {
        /// Exact durable record observed under the other fence.
        reservation: AdmissionReservationRecord,
        /// State Fence the caller verified against.
        expected_state_fence: StateFenceSnapshot,
    },
    /// The reservation is owned by a different Authority Epoch lineage, so the
    /// caller does not own the proposal it would have to launch.
    ForeignOwner {
        /// Exact durable record owned by the other epoch.
        reservation: AdmissionReservationRecord,
        /// Authority Epoch lineage the caller verified against.
        expected_authority_epoch: EpochLineage,
    },
    /// The reservation names a different work item or proposed attempt than the
    /// caller verified against.
    IdentityConflict {
        /// Exact durable record whose identity conflicts.
        reservation: AdmissionReservationRecord,
        /// Work item the caller verified against.
        expected_work_item_id: OperationIdentity,
        /// Proposed attempt the caller verified against.
        expected_proposed_attempt_id: OperationIdentity,
    },
}

/// Sealed active launch prerequisite.
///
/// This is the only value a launch consumer may treat as active reservation
/// authority. It is produced exclusively by
/// [`verify_admission_reservation_launch_prerequisite`]: its authorising fields
/// are private, it has no public constructor, and it deliberately has no
/// `Deserialize` implementation, so an ordinary caller can neither assemble an
/// accepted "active" typestate from public fields nor recover one from
/// serialized bytes. The verifier is the single issuance point, and it issues
/// only after the durable record, the epoch, the State Fence and the work and
/// attempt identities have all been checked.
///
/// #1701 obtains one by calling the verifier with the reservation snapshot it
/// read back from ORS, plus its own current Authority Epoch lineage, State
/// Fence, work-item and proposed-attempt identities, and current time.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ActiveAdmissionReservation {
    reservation: AdmissionReservationRecord,
    receipt: OperationalMutationReceipt,
}

impl ActiveAdmissionReservation {
    /// Issues the sealed prerequisite. Only this module's verifier may call it.
    const fn verified(
        reservation: AdmissionReservationRecord,
        receipt: OperationalMutationReceipt,
    ) -> Self {
        Self {
            reservation,
            receipt,
        }
    }

    /// Exact active reservation record the verifier accepted.
    pub const fn record(&self) -> &AdmissionReservationRecord {
        &self.reservation
    }

    /// Store-issued ORS mutation receipt bound to the exact persisted row.
    pub const fn receipt(&self) -> &OperationalMutationReceipt {
        &self.receipt
    }

    /// Owner-issued ORS activation receipt reference bound by the record.
    ///
    /// # Errors
    ///
    /// Returns [`OrsError::InvalidTransition`] when the sealed value does not
    /// carry an activation receipt. That cannot happen for a value issued by
    /// the verifier; the check stays a typed refusal so no consumer can read the
    /// absence as a panic it is entitled to trust.
    pub fn activation_receipt(&self) -> Result<&ReceiptIdentity, OrsError> {
        self.reservation
            .activation_receipt
            .as_ref()
            .ok_or(OrsError::InvalidTransition)
    }

    /// Owner-issued canonical admission receipt reference bound by the record.
    ///
    /// # Errors
    ///
    /// Returns [`OrsError::InvalidTransition`] when the sealed value does not
    /// carry a canonical admission receipt, for the same reason as
    /// [`Self::activation_receipt`].
    pub fn canonical_admission_receipt(&self) -> Result<&ReceiptIdentity, OrsError> {
        self.reservation
            .canonical_admission_receipt
            .as_ref()
            .ok_or(OrsError::InvalidTransition)
    }
}

/// Verifies one read-back reservation as the launch prerequisite #1701 must
/// hold before any launch.
///
/// The check is a pure read. It provisions nothing, launches nothing, mutates
/// no durable state, and changes no lifecycle position: it re-derives the
/// current disposition of the reservation it is given. The caller's current
/// Authority Epoch lineage, State Fence, work-item and proposed-attempt
/// identities and time are the launch authority being checked against, so an
/// active reservation under a different epoch, fence, work item, attempt or a
/// passed expiry boundary is refused rather than accepted.
///
/// Only an exact `Active` record carrying both its activation receipt and its
/// canonical admission receipt returns [`AdmissionReservationLaunchPrerequisite::Active`];
/// every other disposition returns its own typed variant and cannot be turned
/// into active authority.
///
/// # Errors
///
/// Returns [`OrsError`] when the expected epoch/fence pair does not hold
/// together, when `now_ms` is not a positive Unix millisecond value, or when
/// the observed durable record violates
/// [`AdmissionReservationRecord::validate`].
pub fn verify_admission_reservation_launch_prerequisite(
    current: Option<&AdmissionReservationSnapshot>,
    expected_work_item_id: &OperationIdentity,
    expected_proposed_attempt_id: &OperationIdentity,
    expected_authority_epoch: &EpochLineage,
    expected_state_fence: &StateFenceSnapshot,
    now_ms: i64,
) -> Result<AdmissionReservationLaunchPrerequisite, OrsError> {
    expected_authority_epoch.validate()?;
    expected_state_fence.validate_against_lineage(expected_authority_epoch)?;
    if now_ms <= 0 {
        return Err(OrsError::InvalidField {
            field: "admission_reservation_launch_prerequisite.now_ms",
            reason: "must be greater than zero",
        });
    }
    let Some(snapshot) = current else {
        return Ok(AdmissionReservationLaunchPrerequisite::Missing {
            work_item_id: expected_work_item_id.clone(),
            proposed_attempt_id: expected_proposed_attempt_id.clone(),
        });
    };
    let record = snapshot.record();
    record.validate()?;
    let reservation = record.clone();
    match reservation.state {
        AdmissionReservationState::StagedInactive => {
            Ok(AdmissionReservationLaunchPrerequisite::Staged { reservation })
        }
        AdmissionReservationState::Released => {
            Ok(AdmissionReservationLaunchPrerequisite::Released { reservation })
        }
        AdmissionReservationState::Expired => {
            Ok(AdmissionReservationLaunchPrerequisite::Expired { reservation })
        }
        AdmissionReservationState::Reconciling => {
            Ok(AdmissionReservationLaunchPrerequisite::Reconciling { reservation })
        }
        AdmissionReservationState::Active => {
            if reservation.canonical_admission_receipt.is_none()
                || reservation.activation_receipt.is_none()
            {
                return Err(OrsError::InvalidTransition);
            }
            if &reservation.work_item_id != expected_work_item_id
                || &reservation.proposed_attempt_id != expected_proposed_attempt_id
            {
                return Ok(AdmissionReservationLaunchPrerequisite::IdentityConflict {
                    reservation,
                    expected_work_item_id: expected_work_item_id.clone(),
                    expected_proposed_attempt_id: expected_proposed_attempt_id.clone(),
                });
            }
            if &reservation.authority_epoch != expected_authority_epoch {
                return Ok(AdmissionReservationLaunchPrerequisite::ForeignOwner {
                    reservation,
                    expected_authority_epoch: expected_authority_epoch.clone(),
                });
            }
            if &reservation.state_fence != expected_state_fence {
                return Ok(AdmissionReservationLaunchPrerequisite::StaleFence {
                    reservation,
                    expected_state_fence: expected_state_fence.clone(),
                });
            }
            if now_ms >= reservation.expires_at_ms {
                return Ok(AdmissionReservationLaunchPrerequisite::Expired { reservation });
            }
            Ok(AdmissionReservationLaunchPrerequisite::Active(
                ActiveAdmissionReservation::verified(reservation, snapshot.receipt().clone()),
            ))
        }
    }
}
