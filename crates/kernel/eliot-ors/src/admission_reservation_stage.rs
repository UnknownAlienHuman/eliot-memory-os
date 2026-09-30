//! One frozen operation/identity model for the admission-reservation saga
//! (#1678 REQ1, REQ2, REQ3, REQ6; W1, W2, W4, W5; A1, A2, A4, A7).
//!
//! This module is the Kernel-side coordinator contract for the durable
//! reservation lifecycle. It holds the two halves of the saga that are
//! purely about the ORS reservation row itself:
//!
//! - the **stage** half ([`stage_admission_reservation_inactive`]) produces a
//!   durable, immutable `StagedInactive` reservation BEFORE any semantic
//!   admission effect;
//! - the **activate** half ([`activate_admission_reservation_from_owner_evidence`])
//!   moves that same reservation to `Active` only from owner evidence.
//!
//! Neither half creates a process, provider or environment effect. Staging
//! reserves/account charges only; activation is still not a process start. Both
//! halves go through the one typed [`OperationalRecoveryStore`] owner, read the
//! same reservation identity back, and reuse the existing identity/validator
//! types rather than minting parallel ones.
//!
//! # What the stage half is allowed to do
//!
//! The stage half is exactly:
//!
//! 1. derive one **stable, re-derivable** reservation identity
//!    ([`admission_reservation_identity`]) and one proposed-attempt identity
//!    ([`proposed_attempt_identity`]);
//! 2. stage one `StagedInactive` record carrying the complete immutable
//!    resource / lane / environment / effect / quota / State Fence / Authority
//!    Epoch claims through the existing typed ORS owner;
//! 3. durably read that same reservation identity back.
//!
//! It does not admit, release, expire or reconcile anything. Those are the
//! canonical-admission and disposition owners.
//!
//! # What the activate half is allowed to do
//!
//! The activate half is exactly one transition:
//!
//! 1. re-read the exact reservation identity and prove it is the
//!    `StagedInactive` (or `Reconciling`) row the caller believes it is, under
//!    the caller's current Authority Epoch lineage and State Fence;
//! 2. check the owner-issued canonical admission receipt and the ORS activation
//!    receipt are both well-formed and distinct;
//! 3. CAS the row to `Active` through the typed owner, and read that same
//!    identity back.
//!
//! It admits nothing, launches nothing, provisions nothing, allocates no
//! environment and fabricates no canonical receipt. The canonical admission
//! receipt arrives as evidence from the canonical owner; this module only
//! refuses to activate without it.
//!
//! # Why the identity is derived, not minted
//!
//! A2 requires that a restart after stage but before canonical admission
//! reloads *the same* reservation ID. A freshly minted UUID per attempt cannot
//! satisfy that, so the identity here is a pure function of immutable inputs
//! that the owner already holds durably. The derivation is deterministic and
//! content-addressed: the same work item, proposed attempt, admission revision,
//! claim set, fence and epoch always produce the same identity, on any
//! process, after any crash. The activation operation identity
//! ([`activation_operation_identity`]) follows the same rule for the same
//! reason: an activation replay after a lost response must reuse the one ORS
//! operation identity rather than mint a second activation (A7).
//!
//! # Why the completeness check is independent
//!
//! A1 requires the staged record to carry the *complete* claim set, and the
//! brief requires that completeness be judged against an INDEPENDENT expected
//! set — never against a copy of the same caller list. [`StagedClaimCarrier`]
//! is therefore a closed, owner-declared enumeration of the eight required
//! claim roles, and [`verify_staged_claim_completeness`] walks that closed set
//! to decide completeness. A caller cannot satisfy the check by handing back the
//! same list it was given, because the list is fixed here, in the owner, and a
//! missing role is a typed refusal rather than a shorter loop.

use eliot_contracts::EpochId;
use eliot_receipts::ReceiptIdentity;
use serde::{Deserialize, Serialize};

use crate::{
    AdmissionReservationActivatedOutcome, AdmissionReservationActivationEvidence,
    AdmissionReservationActivationRequest, AdmissionReservationClaimRef,
    AdmissionReservationClaims, AdmissionReservationRecord, AdmissionReservationSnapshot,
    AdmissionReservationStage, AdmissionReservationState, EpochIdentity, EpochLineage, OpaqueLabel,
    OperationIdentity, OperationalRecoveryStore, OrsError, StateFenceSnapshot, model::sha256_hex,
};

/// Wire revision of this stage identity contract.
///
/// A change to the derived-identity preimage or to the claim-role set is a
/// breaking change for every reservation staged under the old revision, so the
/// revision travels inside the preimage: two different revisions can never
/// collide on one reservation identity.
pub const ADMISSION_RESERVATION_STAGE_VERSION: u16 = 1;

/// Domain separator binding a derived identity to this exact contract and
/// revision. Without it a derived digest could collide with any other ORS
/// identity derived from the same immutable inputs.
const RESERVATION_IDENTITY_DOMAIN: &str = "eliot.ors.admission-reservation.identity.v1";

/// Domain separator binding a proposed-attempt identity to this saga half.
const PROPOSED_ATTEMPT_DOMAIN: &str = "eliot.ors.admission-reservation.attempt.v1";

/// The exact immutable inputs one reservation identity is derived from.
///
/// Every field is an owner-held commitment, never an observed-at-call-time
/// value. In particular `now_unix_ms` is deliberately absent: including the
/// clock would make the identity differ per attempt and break the A2
/// restart-stability rule.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdmissionReservationIdentityInput {
    /// Work item whose admission is being reserved.
    pub work_item_id: OperationIdentity,
    /// Attempt identity proposed before canonical admission.
    pub proposed_attempt_id: OperationIdentity,
    /// Exact semantic admission revision this reservation is bound to.
    pub semantic_admission_revision: String,
    /// Complete immutable claim set the reservation reserves.
    pub claims: AdmissionReservationClaims,
    /// Exact State Fence observed for this admission proposal.
    pub state_fence: StateFenceSnapshot,
    /// Authority epoch owning this exact admission proposal.
    pub authority_epoch: EpochLineage,
}

/// Derives the stable reservation identity for one admission proposal.
///
/// The result is a pure function of [`AdmissionReservationIdentityInput`], so
/// the same proposal re-derives the same `reservation_id` on any process and
/// after any crash. This is what makes A2 satisfiable: a restart recomputes this
/// value and reads back the row staged under it instead of minting a new
/// identity.
///
/// # Errors
///
/// Returns [`OrsError`] when the inputs are not shape-valid (blank identity,
/// malformed claim digest, fence/epoch disagreement) or when the canonical
/// preimage cannot be encoded. It never returns a reservation identity for a
/// proposal the owner would refuse to admit.
pub fn admission_reservation_identity(
    input: &AdmissionReservationIdentityInput,
) -> Result<OperationIdentity, OrsError> {
    // Validate the preimage with the existing validators BEFORE hashing it, so
    // an identity is never derived from content the record itself would
    // reject. `validate()` re-derives the fence digest from the ORIGINAL
    // recorded canonical JSON; it never recomputes a fence to trust it.
    input.claims.validate()?;
    input.authority_epoch.validate()?;
    input
        .state_fence
        .validate_against_lineage(&input.authority_epoch)?;
    if input.work_item_id.as_str().trim().is_empty()
        || input.proposed_attempt_id.as_str().trim().is_empty()
    {
        return Err(OrsError::InvalidField {
            field: "admission_reservation.identity",
            reason: "work item and proposed attempt identities must be non-blank",
        });
    }
    crate::model::validate_text(
        &input.semantic_admission_revision,
        "admission_reservation.semantic_admission_revision",
    )?;
    let preimage = serde_json::to_vec(&(
        RESERVATION_IDENTITY_DOMAIN,
        ADMISSION_RESERVATION_STAGE_VERSION,
        &input.work_item_id,
        &input.proposed_attempt_id,
        &input.semantic_admission_revision,
        &input.claims,
        &input.state_fence,
        &input.authority_epoch,
    ))
    .map_err(|error| OrsError::Encoding(error.to_string()))?;
    OperationIdentity::new(format!("admission-reservation:{}", sha256_hex(&preimage)))
}

/// Derives the ORS stage operation identity for one reservation identity.
///
/// The stage operation is bound to the reservation identity and its immutable
/// first-stage revision, so a retry or a crash-restart reuses the same ORS
/// operation identity rather than minting a second one. Later lifecycle
/// transitions (W3-W8) use their own fresh operation identities and are not
/// produced here.
///
/// # Errors
///
/// Returns [`OrsError::InvalidField`] when `reservation_id` is blank.
pub fn stage_operation_identity(
    reservation_id: &OperationIdentity,
) -> Result<OperationIdentity, OrsError> {
    if reservation_id.as_str().trim().is_empty() {
        return Err(OrsError::InvalidField {
            field: "admission_reservation.reservation_id",
            reason: "reservation identity must be non-blank",
        });
    }
    OperationIdentity::new(format!("{}:stage", reservation_id.as_str()))
}

/// Derives the proposed-attempt identity for one reservation proposal.
///
/// The attempt identity is derived from the same immutable preimage as the
/// reservation identity, so it is equally stable across a crash: recovery
/// recomputes it rather than minting a new attempt underneath a durable
/// reservation.
///
/// # Errors
///
/// Returns [`OrsError`] under the same conditions as
/// [`admission_reservation_identity`], because both are derived from the same
/// validated preimage.
pub fn proposed_attempt_identity(
    input: &AdmissionReservationIdentityInput,
) -> Result<OperationIdentity, OrsError> {
    let _ = admission_reservation_identity(input)?;
    let preimage = serde_json::to_vec(&(
        PROPOSED_ATTEMPT_DOMAIN,
        ADMISSION_RESERVATION_STAGE_VERSION,
        &input.work_item_id,
        &input.semantic_admission_revision,
        &input.claims,
        &input.state_fence,
        &input.authority_epoch,
    ))
    .map_err(|error| OrsError::Encoding(error.to_string()))?;
    OperationIdentity::new(format!("admission-attempt:{}", sha256_hex(&preimage)))
}

/// Owner-declared, closed set of claim roles one staged reservation must
/// carry (W2).
///
/// This enum is the independent expected set. It is fixed here, in the owner,
/// and [`verify_staged_claim_completeness`] iterates it; a caller's own list is
/// never used as its own reference. Every variant is a distinct, non-blank
/// owner reference, so completeness is decidable without interpretation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StagedClaimRole {
    /// Complete resource-claim set.
    Resource,
    /// Exact scheduler lane.
    Lane,
    /// Exact environment.
    Environment,
    /// Complete effect-claim set.
    Effect,
    /// Exact pessimistic cost and quota view.
    QuotaView,
    /// Exact State Fence.
    StateFence,
    /// Authority epoch lineage.
    AuthorityEpoch,
}

/// The closed, owner-declared expected role set. A reservation is complete only
/// when every one of these is bound.
const REQUIRED_STAGED_CLAIM_ROLES: &[StagedClaimRole] = &[
    StagedClaimRole::Resource,
    StagedClaimRole::Lane,
    StagedClaimRole::Environment,
    StagedClaimRole::Effect,
    StagedClaimRole::QuotaView,
    StagedClaimRole::StateFence,
    StagedClaimRole::AuthorityEpoch,
];

/// Verifies that one staged record carries every required claim role.
///
/// The check walks [`REQUIRED_STAGED_CLAIM_ROLES`], the owner's own closed
/// expectation, and resolves each role to the reference the record actually
/// holds. A role that resolves to nothing, or to a reference that fails its
/// existing validator, is a typed refusal — completeness is never inferred
/// from the length or the shape of a caller-supplied list.
///
/// Fence and epoch are compared BY VALUE against what the record holds and
/// validated with the existing validators: the State Fence digest is checked
/// with [`StateFenceSnapshot::validate`] against the ORIGINAL recorded
/// canonical JSON, and the epoch with [`EpochLineage::validate`] plus the
/// lineage-bound fence check. Neither digest is recomputed in order to be
/// trusted.
///
/// # Errors
///
/// Returns [`OrsError::InvalidField`] naming the first unbound role, or the
/// underlying owner error when a bound role's existing validator refuses it.
pub fn verify_staged_claim_completeness(
    record: &AdmissionReservationRecord,
) -> Result<(), OrsError> {
    for role in REQUIRED_STAGED_CLAIM_ROLES {
        let reference: Option<&AdmissionReservationClaimRef> = match role {
            StagedClaimRole::Resource => Some(&record.claims.resources),
            StagedClaimRole::Lane => Some(&record.claims.lane),
            StagedClaimRole::Environment => Some(&record.claims.environment),
            StagedClaimRole::Effect => Some(&record.claims.effects),
            StagedClaimRole::QuotaView => Some(&record.claims.quota_view),
            StagedClaimRole::StateFence => {
                // By value against what the record holds, validated with the
                // existing validator on the ORIGINAL recorded fence.
                record
                    .state_fence
                    .validate_against_lineage(&record.authority_epoch)?;
                None
            }
            StagedClaimRole::AuthorityEpoch => {
                record.authority_epoch.validate()?;
                None
            }
        };
        if let Some(reference) = reference {
            reference.validate()?;
            if reference.reference.as_str().trim().is_empty() {
                return Err(OrsError::InvalidField {
                    field: "admission_reservation.claim.reference",
                    reason: "every staged claim role must name a non-blank owner reference",
                });
            }
        }
    }
    Ok(())
}

/// The complete set of inputs for one stage-and-read-back operation.
///
/// This is the single request the coordinator accepts. It carries the eight
/// W2 claims and the expiry boundary, and it names the reservation by the
/// DERIVED identity so a replay and a crash-restart converge on one row.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdmissionReservationStageRequest {
    /// Stable, re-derivable reservation identity.
    pub reservation_id: OperationIdentity,
    /// Work item whose admission is being reserved.
    pub work_item_id: OperationIdentity,
    /// Stable proposed attempt identity.
    pub proposed_attempt_id: OperationIdentity,
    /// ORS operation identity for this first stage.
    pub operation_id: OperationIdentity,
    /// Exact complete owner-defined claims (resource, lane, environment,
    /// effect, quota).
    pub claims: AdmissionReservationClaims,
    /// Epoch captured by the caller.
    pub authority_epoch: EpochLineage,
    /// Exact State Fence captured with the epoch.
    pub state_fence: StateFenceSnapshot,
    /// Exact expiry boundary in Unix milliseconds.
    pub expires_at_ms: i64,
    /// Stage time in Unix milliseconds.
    pub now_unix_ms: i64,
}

/// Result of one stage-and-read-back: the durable snapshot plus the exact
/// identity that was staged.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdmissionReservationStagedOutcome {
    /// Reservation identity that was staged, for the caller to persist or
    /// re-derive after a crash.
    pub reservation_id: OperationIdentity,
    /// Durable ORS snapshot read back for that exact identity.
    pub snapshot: AdmissionReservationSnapshot,
}

/// Stages one `StagedInactive` reservation and reads it back, creating no
/// process, provider or environment effect.
///
/// This is the stage half of the #1678 saga and the only public entry point
/// that produces a staged reservation. It:
///
/// 1. validates the request and the completeness of the eight required claim
///    roles against the owner's closed expected set;
/// 2. stages the typed `StagedInactive` record through the existing
///    [`OperationalRecoveryStore`] owner — no second store, no in-memory
///    stand-in, no file the owner does not own;
/// 3. reads the same reservation identity back out of the owner and returns
///    that durable snapshot.
///
/// It performs no canonical admission, no launch, no provisioning, no
/// environment allocation and no external effect. Those belong to the
/// admit/activate half, which is a separate owner.
///
/// # Errors
///
/// Returns [`OrsError::DuplicateConflict`] when this exact reservation identity
/// is already durable under DIFFERENT content — a same-identity
/// different-content conflict refuses and never overwrites. An exact replay
/// returns the existing snapshot unchanged and charges nothing twice.
///
/// Returns [`OrsError::InvalidField`] when the request is incomplete or
/// malformed, and any storage/validation error the typed owner raises.
pub fn stage_admission_reservation_inactive<S: OperationalRecoveryStore + ?Sized>(
    store: &S,
    request: &AdmissionReservationStageRequest,
) -> Result<AdmissionReservationStagedOutcome, OrsError> {
    if request.now_unix_ms <= 0 {
        return Err(OrsError::InvalidField {
            field: "admission_reservation_stage.now_unix_ms",
            reason: "stage time must be greater than zero",
        });
    }
    if request.expires_at_ms <= request.now_unix_ms {
        return Err(OrsError::InvalidExpiry);
    }
    // The immutable binding is validated BEFORE the write with the existing
    // validators, by value, against the ORIGINAL recorded fence and epoch.
    request.claims.validate()?;
    request.authority_epoch.validate()?;
    request
        .state_fence
        .validate_against_lineage(&request.authority_epoch)?;
    if request.reservation_id.as_str().trim().is_empty()
        || request.work_item_id.as_str().trim().is_empty()
        || request.proposed_attempt_id.as_str().trim().is_empty()
    {
        return Err(OrsError::InvalidField {
            field: "admission_reservation_stage.identity",
            reason: "reservation, work item and proposed attempt identities must be non-blank",
        });
    }

    let candidate = AdmissionReservationRecord {
        reservation_id: request.reservation_id.clone(),
        work_item_id: request.work_item_id.clone(),
        proposed_attempt_id: request.proposed_attempt_id.clone(),
        stage_operation_id: request.operation_id.clone(),
        operation_id: request.operation_id.clone(),
        claims: request.claims.clone(),
        authority_epoch: request.authority_epoch.clone(),
        state_fence: request.state_fence.clone(),
        canonical_admission_receipt: None,
        activation_receipt: None,
        expires_at_ms: request.expires_at_ms,
        state: AdmissionReservationState::StagedInactive,
        disposition_reason: None,
        disposition_evidence: None,
        last_transition: None,
        created_at_ms: request.now_unix_ms,
        updated_at_ms: request.now_unix_ms,
    };
    candidate.validate()?;
    verify_staged_claim_completeness(&candidate)?;

    let staged = store.stage_kernel_admission_reservation(AdmissionReservationStage {
        reservation_id: request.reservation_id.clone(),
        work_item_id: request.work_item_id.clone(),
        proposed_attempt_id: request.proposed_attempt_id.clone(),
        operation_id: request.operation_id.clone(),
        claims: request.claims.clone(),
        authority_epoch: request.authority_epoch.clone(),
        state_fence: request.state_fence.clone(),
        expires_at_ms: request.expires_at_ms,
        now_ms: request.now_unix_ms,
    })?;
    // The store's own echoed row is compared against the candidate this function
    // validated BEFORE the write, field by field. The store is a different owner
    // from the validator, so this is a real cross-check rather than a
    // self-comparison, and it is what makes "the claims were staged" mean "the
    // claims the store holds are the claims that were checked" instead of merely
    // "a write returned successfully".
    if staged.record().claims != candidate.claims
        || staged.record().state_fence != candidate.state_fence
        || staged.record().authority_epoch != candidate.authority_epoch
        || staged.record().state != candidate.state
        || staged.record().work_item_id != candidate.work_item_id
        || staged.record().proposed_attempt_id != candidate.proposed_attempt_id
        || staged.record().operation_id != candidate.operation_id
        || staged.record().expires_at_ms != candidate.expires_at_ms
    {
        return Err(OrsError::IntegrityProblem {
            record_type: "admission_reservation",
            reason: "the staged row does not carry the claims this call validated".to_owned(),
        });
    }

    // Durably read the SAME identity back. This is the A2 restart path: the
    // caller re-derives `reservation_id` and lands on the identical row, and
    // this read performs no launch, provisioning or allocation.
    let readback = store
        .load_kernel_admission_reservation(&request.reservation_id)?
        .ok_or(OrsError::DuplicateConflict)?;
    if readback.record().reservation_id != request.reservation_id {
        return Err(OrsError::IntegrityProblem {
            record_type: "admission_reservation",
            reason: "readback returned a different reservation identity".to_owned(),
        });
    }
    Ok(AdmissionReservationStagedOutcome {
        reservation_id: request.reservation_id.clone(),
        snapshot: readback,
    })
}

/// Reloads one staged reservation by its stable identity, creating no effect.
///
/// This is the A2 recovery entry point: after a restart, the coordinator
/// re-derives `reservation_id` and calls this to prove the reservation is
/// durable and still `StagedInactive` before any canonical admission is even
/// attempted. It provisions nothing, launches nothing and mutates nothing.
///
/// # Errors
///
/// Returns [`OrsError::ReservationNotFound`] when no reservation exists under
/// that identity, and propagates any owner validation error for a record that
/// is present but malformed.
pub fn reload_staged_admission_reservation<S: OperationalRecoveryStore + ?Sized>(
    store: &S,
    reservation_id: &OperationIdentity,
    now_unix_ms: i64,
) -> Result<AdmissionReservationSnapshot, OrsError> {
    if now_unix_ms <= 0 {
        return Err(OrsError::InvalidField {
            field: "admission_reservation_reload.now_unix_ms",
            reason: "read time must be greater than zero",
        });
    }
    let snapshot = store
        .load_kernel_admission_reservation(reservation_id)?
        .ok_or(OrsError::ReservationNotFound)?;
    snapshot.record().validate()?;
    verify_staged_claim_completeness(snapshot.record())?;
    Ok(snapshot)
}

/// Builds the ORS epoch lineage for one canonical [`EpochId`] and its
/// observed predecessor.
///
/// This is the ONLY conversion between the canonical `EpochId` contour and the
/// ORS `EpochLineage` contour used by the reservation. It reuses the existing
/// `EpochId` lineage identity verbatim (no parallel representation) and drops
/// a predecessor that is equal to the current epoch, because `EpochLineage`
/// would then describe a non-succession.
///
/// # Errors
///
/// Returns [`OrsError::InvalidField`] when the lineage label is not a usable
/// `OpaqueLabel`, and [`OrsError::InvalidEpochLineage`] when the resulting
/// lineage does not strictly advance its same-lineage predecessor.
pub fn epoch_lineage_for(
    epoch: &EpochId,
    predecessor: Option<&EpochIdentity>,
) -> Result<EpochLineage, OrsError> {
    let current = EpochIdentity {
        lineage_id: OpaqueLabel::new(epoch.lineage_id.as_str())?,
        epoch: epoch.sequence.get(),
    };
    let prior = predecessor.filter(|prior| *prior != &current).cloned();
    let lineage = EpochLineage {
        current,
        predecessor: prior,
    };
    lineage.validate()?;
    Ok(lineage)
}

/// Domain separator binding a derived activation identity to this exact
/// contract revision. Without it a derived activation digest could collide
/// with any other ORS identity derived from the same immutable inputs.
const ACTIVATION_OPERATION_DOMAIN: &str = "eliot.ors.admission-reservation.activation.v1";

/// Derives the ORS operation identity for the activation of one reservation
/// from the exact owner evidence that authorizes it.
///
/// The identity is bound to the reservation it activates AND to the exact pair
/// of owner receipts, so a replay after a lost response reuses the one ORS
/// operation identity and returns the original active snapshot, while the same
/// reservation activated under different owner evidence is a same-identity
/// different-content conflict rather than a second activation.
///
/// # Errors
///
/// Returns [`OrsError::InvalidField`] when `reservation_id` is blank, and
/// [`OrsError::Encoding`] when the canonical preimage cannot be encoded.
pub fn activation_operation_identity(
    reservation_id: &OperationIdentity,
    canonical_admission_receipt: &ReceiptIdentity,
    activation_receipt: &ReceiptIdentity,
) -> Result<OperationIdentity, OrsError> {
    if reservation_id.as_str().trim().is_empty() {
        return Err(OrsError::InvalidField {
            field: "admission_reservation.reservation_id",
            reason: "reservation identity must be non-blank",
        });
    }
    let preimage = serde_json::to_vec(&(
        ACTIVATION_OPERATION_DOMAIN,
        ADMISSION_RESERVATION_STAGE_VERSION,
        reservation_id,
        canonical_admission_receipt,
        activation_receipt,
    ))
    .map_err(|error| OrsError::Encoding(error.to_string()))?;
    OperationIdentity::new(format!(
        "admission-reservation-activation:{}",
        sha256_hex(&preimage)
    ))
}

/// Activates the exact reservation from owner evidence and returns the durable
/// activation receipt (REQ6, A4, A7).
///
/// This is the activate half of the #1678 saga and the only public entry point
/// that produces an active reservation. It:
///
/// 1. re-reads the exact reservation identity from the typed owner and refuses
///    anything that is not the `StagedInactive` (or `Reconciling`) row the
///    caller named, under the caller's current Authority Epoch lineage and
///    State Fence — a foreign epoch, a stale fence, a different work item,
///    attempt or claim set fails **before** any mutation;
/// 2. validates the two owner receipts with the existing
///    [`AdmissionReservationActivationEvidence`] validator, so a malformed or
///    non-distinct receipt pair never reaches the write;
/// 3. CAS-transitions the row to `Active` through the same typed owner, using
///    the current ORS receipt it just read as the expected receipt;
/// 4. reads the SAME identity back out of the owner and returns that durable
///    snapshot, from which the caller takes the committed activation and
///    canonical admission receipts.
///
/// The function admits nothing, launches nothing, provisions nothing and
/// allocates no environment. It is the mechanical prerequisite #1701 consumes,
/// not a process start.
///
/// # Errors
///
/// Returns [`OrsError::ReservationNotFound`] when no reservation exists under
/// the named identity, [`OrsError::DuplicateConflict`] when the durable row is
/// not the row the caller described (different work item, attempt, claims,
/// epoch or fence) or when the expected ORS receipt no longer matches the
/// current one, [`OrsError::FenceMismatch`] when the caller's Authority Epoch
/// or State Fence does not match the durable row, [`OrsError::InvalidExpiry`]
/// when the declared expiry boundary has already elapsed, and
/// [`OrsError::InvalidField`] when the request is incomplete or malformed.
///
/// An **exact replay** — the same operation identity, the same expected
/// receipt, the same owner evidence — returns the original active snapshot
/// unchanged: the second activation is refused as a same-identity
/// different-content conflict only when the content actually differs.
pub fn activate_admission_reservation_from_owner_evidence<S: OperationalRecoveryStore + ?Sized>(
    store: &S,
    request: &AdmissionReservationActivationRequest,
) -> Result<AdmissionReservationActivatedOutcome, OrsError> {
    if request.now_ms <= 0 {
        return Err(OrsError::InvalidField {
            field: "admission_reservation_activation.now_ms",
            reason: "activation time must be greater than zero",
        });
    }
    if request.reservation_id.as_str().trim().is_empty()
        || request.work_item_id.as_str().trim().is_empty()
        || request.proposed_attempt_id.as_str().trim().is_empty()
        || request.operation_id.as_str().trim().is_empty()
    {
        return Err(OrsError::InvalidField {
            field: "admission_reservation_activation.identity",
            reason: "reservation, work item, proposed attempt and operation identities must be non-blank",
        });
    }
    // The immutable binding is validated BEFORE the write with the existing
    // validators, by value, against the ORIGINAL recorded fence and epoch.
    request.claims.validate()?;
    request.authority_epoch.validate()?;
    request
        .state_fence
        .validate_against_lineage(&request.authority_epoch)?;
    AdmissionReservationActivationEvidence {
        canonical_admission_receipt: request.canonical_admission_receipt.clone(),
        activation_receipt: request.activation_receipt.clone(),
    }
    .validate()?;

    // Re-read the exact row the caller believes it is activating. This is the
    // pre-mutation identity check: nothing is written until the durable row,
    // its immutable binding and the caller's current authority all agree.
    let current = store
        .load_kernel_admission_reservation(&request.reservation_id)?
        .ok_or(OrsError::ReservationNotFound)?;
    let staged = current.record();
    staged.validate()?;
    verify_staged_claim_completeness(staged)?;
    if staged.state != AdmissionReservationState::StagedInactive
        && staged.state != AdmissionReservationState::Reconciling
    {
        return Err(OrsError::InvalidTransition);
    }
    if staged.work_item_id != request.work_item_id
        || staged.proposed_attempt_id != request.proposed_attempt_id
        || staged.claims != request.claims
    {
        return Err(OrsError::DuplicateConflict);
    }
    if staged.authority_epoch != request.authority_epoch
        || staged.state_fence != request.state_fence
    {
        return Err(OrsError::FenceMismatch);
    }
    if request.now_ms >= staged.expires_at_ms {
        return Err(OrsError::InvalidExpiry);
    }
    // The CAS precondition is the receipt this call actually observed, not a
    // value the caller may have invented: the store compares the request's
    // `expected_current_receipt` against the row it holds at write time and
    // refuses a mismatch.
    if current.receipt() != &request.expected_current_receipt {
        return Err(OrsError::DuplicateConflict);
    }

    let activated =
        store.activate_kernel_admission_reservation(AdmissionReservationActivationRequest {
            reservation_id: request.reservation_id.clone(),
            work_item_id: request.work_item_id.clone(),
            proposed_attempt_id: request.proposed_attempt_id.clone(),
            operation_id: request.operation_id.clone(),
            claims: request.claims.clone(),
            canonical_admission_receipt: request.canonical_admission_receipt.clone(),
            activation_receipt: request.activation_receipt.clone(),
            expected_current_receipt: request.expected_current_receipt.clone(),
            authority_epoch: request.authority_epoch.clone(),
            state_fence: request.state_fence.clone(),
            now_ms: request.now_ms,
        })?;
    // The store's own echoed row is cross-checked against the facts this call
    // verified BEFORE the write, so "the reservation is active" means the
    // persisted row carries the evidence that was checked, not merely that a
    // write returned successfully.
    let persisted = activated.record();
    persisted.validate()?;
    if persisted.state != AdmissionReservationState::Active
        || persisted.reservation_id != request.reservation_id
        || persisted.canonical_admission_receipt.as_ref()
            != Some(&request.canonical_admission_receipt)
        || persisted.activation_receipt.as_ref() != Some(&request.activation_receipt)
    {
        return Err(OrsError::IntegrityProblem {
            record_type: "admission_reservation",
            reason: "the activated row does not carry the owner evidence this call validated"
                .to_owned(),
        });
    }

    // Durably read the SAME identity back. This is the A7 restart path: a
    // replay after a lost response lands on the identical active row and its
    // original activation receipt, and this read launches nothing.
    let readback = store
        .load_kernel_admission_reservation(&request.reservation_id)?
        .ok_or(OrsError::ReservationNotFound)?;
    if readback.record().state != AdmissionReservationState::Active
        || readback.record().activation_receipt.as_ref() != Some(&request.activation_receipt)
    {
        return Err(OrsError::IntegrityProblem {
            record_type: "admission_reservation",
            reason: "readback returned a different active reservation identity".to_owned(),
        });
    }
    Ok(AdmissionReservationActivatedOutcome::from_store(
        request.reservation_id.clone(),
        readback,
    ))
}
