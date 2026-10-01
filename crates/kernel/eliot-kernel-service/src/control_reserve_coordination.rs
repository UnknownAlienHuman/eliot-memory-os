//! Activation-time capacity-claim revalidation and permit-joined launch
//! coordination (issue #1679, W11).
//!
//! #1678 staged reservations record the exact capacity/quota-view claim their
//! staging decision depended on, but a staged claim alone authorizes nothing:
//! activation must revalidate it against the current profile and revisions
//! under the accepted policy (exact profile identity, exact profile revision,
//! same Authority Epoch tuple; anything else fails closed). #1701 launch
//! consumers start a process only when they hold both their process/control
//! permit evidence and the active admission reservation for the same
//! operation. Neither edge manufactures protected capacity and neither
//! collapses capacity evidence and semantic authority into one receipt.
//!
//! This module is the #1679 side of that coordination: the revalidation
//! policy and the launch join. Recording the staged claim stays with #1678,
//! issuing process permits stays with the P-03 dispatch authority, issuing
//! capacity bindings stays with each bottleneck owner, and reservation
//! liveness stays with the ORS lifecycle owner. This module only checks
//! caller-presented owner evidence against the current profile and against
//! each other, and it constructs no [`CapacityPermitBinding`], no permit, no
//! reservation, and no profile of its own.
//!
//! Caller: STITCH. The #1678 activation path calls
//! [`revalidate_staged_claim_at_activation`] with the recorded claim and the
//! current owner-supplied profile before advancing execution, and the #1701
//! launch consumers call [`authorize_capacity_coordinated_launch`] with the
//! revalidated claim plus the three same-operation evidences before starting
//! a process. No caller is manufactured here.

use eliot_contracts::EpochId;
use eliot_ors::ReservationRecord;
use eliot_process::ProcessExecutionBinding;
use eliot_runtime_contracts::{CapacityClass, CapacityPermitBinding, ControlReserveProfile};

use crate::KernelServiceError;

/// Exact capacity/quota-view claim recorded with one #1678 staged reservation.
///
/// Every field restates what the staging decision depended on: the staged
/// operation, the profile identity and immutable revision it was compiled
/// against, and the Authority Epoch tuple current at staging time. Recording
/// is #1678's job; this type is the revalidation policy's view of that
/// record. A claim carries no capacity and grants no authority by itself.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StagedCapacityClaim {
    /// Staged operation identity; must equal the reservation operation.
    pub operation_id: String,
    /// Profile identity the staging decision was compiled against.
    pub profile_id: String,
    /// Immutable profile revision the staging decision was compiled against.
    pub profile_revision: String,
    /// Authority Epoch tuple current at staging time.
    pub authority_epoch: EpochId,
}

/// A staged claim that passed activation-time revalidation.
///
/// Constructible only through [`revalidate_staged_claim_at_activation`], so
/// holding one proves the claim still names the current profile identity,
/// revision, and Authority Epoch. It remains evidence, not authority: it
/// holds no capacity and cannot be spent, released, or replayed as a permit.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RevalidatedCapacityClaim {
    operation_id: String,
    profile_id: String,
    profile_revision: String,
    authority_epoch: EpochId,
}

impl RevalidatedCapacityClaim {
    /// Operation identity the revalidated claim was staged for.
    #[must_use]
    pub fn operation_id(&self) -> &str {
        &self.operation_id
    }

    /// Profile identity confirmed current at activation time.
    #[must_use]
    pub fn profile_id(&self) -> &str {
        &self.profile_id
    }

    /// Profile revision confirmed current at activation time.
    #[must_use]
    pub fn profile_revision(&self) -> &str {
        &self.profile_revision
    }

    /// Authority Epoch tuple confirmed current at activation time.
    #[must_use]
    pub const fn authority_epoch(&self) -> &EpochId {
        &self.authority_epoch
    }
}

/// Revalidates one staged capacity claim against the current profile.
///
/// The accepted policy is exact and fail-closed: the current profile must
/// validate through its own [`ControlReserveProfile::validate`], and the
/// claim must name the same profile identity, the same immutable revision,
/// and the same Authority Epoch tuple (lineage-aware
/// [`EpochId::is_same_authority`]; equal sequences across lineages stay
/// unrelated). A changed profile, a changed epoch, or an invalid current
/// profile refuses with a typed [`KernelServiceError::InvalidField`]. Nothing
/// is allocated, issued, or manufactured here.
///
/// # Errors
///
/// Returns [`KernelServiceError::InvalidField`] for a blank claim field, an
/// invalid current profile, or a claim that no longer names the current
/// profile identity, revision, or Authority Epoch.
pub fn revalidate_staged_claim_at_activation(
    claim: &StagedCapacityClaim,
    current: &ControlReserveProfile,
) -> Result<RevalidatedCapacityClaim, KernelServiceError> {
    if claim.operation_id.trim().is_empty() {
        return Err(KernelServiceError::InvalidField {
            field: "reserve.capacity-claim.operation-id",
            reason: "must-be-non-blank",
        });
    }
    if claim.profile_id.trim().is_empty() {
        return Err(KernelServiceError::InvalidField {
            field: "reserve.capacity-claim.profile-id",
            reason: "must-be-non-blank",
        });
    }
    if claim.profile_revision.trim().is_empty() {
        return Err(KernelServiceError::InvalidField {
            field: "reserve.capacity-claim.profile-revision",
            reason: "must-be-non-blank",
        });
    }
    current
        .validate()
        .map_err(|_| KernelServiceError::InvalidField {
            field: "reserve.capacity-profile",
            reason: "profile-invalid",
        })?;
    if claim.profile_id != current.profile_id {
        return Err(KernelServiceError::InvalidField {
            field: "reserve.capacity-claim.profile-id",
            reason: "profile-identity-changed",
        });
    }
    if claim.profile_revision != current.profile_revision {
        return Err(KernelServiceError::InvalidField {
            field: "reserve.capacity-claim.profile-revision",
            reason: "profile-revision-changed",
        });
    }
    if !claim
        .authority_epoch
        .is_same_authority(&current.authority_epoch_ref)
    {
        return Err(KernelServiceError::InvalidField {
            field: "reserve.capacity-claim.authority-epoch",
            reason: "authority-epoch-changed",
        });
    }
    Ok(RevalidatedCapacityClaim {
        operation_id: claim.operation_id.clone(),
        profile_id: claim.profile_id.clone(),
        profile_revision: claim.profile_revision.clone(),
        authority_epoch: claim.authority_epoch.clone(),
    })
}

/// Launch authorization joining one revalidated claim to its three
/// same-operation evidences.
///
/// The authorization keeps the four inputs distinct — the revalidated
/// activation claim, the active admission reservation identity, the consumed
/// process-permit digest, and the owner-issued capacity permit identity —
/// and exposes each through its own accessor. It mints no combined receipt
/// identity or digest, so capacity evidence and semantic authority cannot
/// collapse into one receipt here. It grants no capacity: single-use
/// enforcement stays with the issuing owners, and the presented
/// [`CapacityPermitBinding`] is only checked, never constructed or upgraded,
/// so a normal launch can never proceed on a protected binding (or the
/// reverse) by relabelling.
///
/// Reservation liveness stays with the ORS lifecycle owner: the presented
/// [`ReservationRecord`] must be in a non-terminal state, otherwise the
/// reservation is retained history rather than an active admission.
///
/// # Errors
///
/// Returns [`KernelServiceError::InvalidField`] when the reservation is
/// terminal, when any evidence names a different operation, when the capacity
/// binding is invalid or names the wrong class, profile, or Authority Epoch,
/// or when the process binding names a different Authority Epoch.
pub fn authorize_capacity_coordinated_launch(
    claim: &RevalidatedCapacityClaim,
    reservation: &ReservationRecord,
    process: &ProcessExecutionBinding,
    capacity: &CapacityPermitBinding,
    required_class: CapacityClass,
) -> Result<CapacityCoordinatedLaunch, KernelServiceError> {
    if reservation.state.is_terminal() {
        return Err(KernelServiceError::InvalidField {
            field: "reserve.launch-reservation",
            reason: "reservation-not-active",
        });
    }
    if reservation.token.operation_id.as_str() != claim.operation_id() {
        return Err(KernelServiceError::InvalidField {
            field: "reserve.launch-reservation",
            reason: "reservation-operation-mismatch",
        });
    }
    if process.operation_id().as_str() != claim.operation_id() {
        return Err(KernelServiceError::InvalidField {
            field: "launch.process-binding",
            reason: "process-operation-mismatch",
        });
    }
    if capacity.operation_id.as_str() != claim.operation_id() {
        return Err(KernelServiceError::InvalidField {
            field: "launch.capacity-binding",
            reason: "capacity-operation-mismatch",
        });
    }
    capacity
        .validate()
        .map_err(|_| KernelServiceError::InvalidField {
            field: "launch.capacity-binding",
            reason: "capacity-binding-invalid",
        })?;
    if capacity.capacity_class != required_class
        || capacity.operation.capacity_class() != required_class
    {
        return Err(KernelServiceError::InvalidField {
            field: "launch.capacity-class",
            reason: "capacity-class-mismatch",
        });
    }
    if capacity.profile_id != claim.profile_id()
        || capacity.profile_revision != claim.profile_revision()
    {
        return Err(KernelServiceError::InvalidField {
            field: "launch.capacity-binding",
            reason: "capacity-profile-changed",
        });
    }
    if !capacity
        .authority_epoch_ref
        .is_same_authority(claim.authority_epoch())
    {
        return Err(KernelServiceError::InvalidField {
            field: "launch.capacity-binding",
            reason: "capacity-authority-changed",
        });
    }
    if !process
        .authority_epoch()
        .is_same_authority(claim.authority_epoch())
    {
        return Err(KernelServiceError::InvalidField {
            field: "launch.process-binding",
            reason: "process-authority-changed",
        });
    }
    Ok(CapacityCoordinatedLaunch {
        operation_id: claim.operation_id().to_owned(),
        profile_id: claim.profile_id().to_owned(),
        profile_revision: claim.profile_revision().to_owned(),
        authority_epoch: claim.authority_epoch().clone(),
        required_class,
        reservation_id: reservation.token.reservation_id.as_str().to_owned(),
        process_permit_digest: process.permit_digest().to_owned(),
        capacity_permit_id: capacity.permit_id.clone(),
    })
}

/// One coordinated launch authorization: four distinct evidences, no merged
/// receipt.
///
/// Each accessor returns exactly one input evidence; there is deliberately no
/// combined authorization identity or digest to mistake for a second permit.
/// The owners behind the three evidences still enforce single use.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CapacityCoordinatedLaunch {
    operation_id: String,
    profile_id: String,
    profile_revision: String,
    authority_epoch: EpochId,
    required_class: CapacityClass,
    reservation_id: String,
    process_permit_digest: String,
    capacity_permit_id: String,
}

impl CapacityCoordinatedLaunch {
    /// Launch operation every joined evidence names.
    #[must_use]
    pub fn operation_id(&self) -> &str {
        &self.operation_id
    }

    /// Profile identity revalidated at activation.
    #[must_use]
    pub fn profile_id(&self) -> &str {
        &self.profile_id
    }

    /// Profile revision revalidated at activation.
    #[must_use]
    pub fn profile_revision(&self) -> &str {
        &self.profile_revision
    }

    /// Authority Epoch tuple every joined evidence shares.
    #[must_use]
    pub const fn authority_epoch(&self) -> &EpochId {
        &self.authority_epoch
    }

    /// Capacity class this launch runs under; the presented binding named no
    /// other class.
    #[must_use]
    pub const fn required_class(&self) -> CapacityClass {
        self.required_class
    }

    /// Active admission reservation identity (semantic authority evidence).
    #[must_use]
    pub fn reservation_id(&self) -> &str {
        &self.reservation_id
    }

    /// Consumed process-permit digest (process authority evidence).
    #[must_use]
    pub fn process_permit_digest(&self) -> &str {
        &self.process_permit_digest
    }

    /// Owner-issued capacity permit identity (capacity evidence).
    #[must_use]
    pub fn capacity_permit_id(&self) -> &str {
        &self.capacity_permit_id
    }
}
