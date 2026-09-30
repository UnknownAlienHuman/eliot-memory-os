//! Host control-reserve partitions for process launch and cancellation/termination.
//!
//! Issue #1679, W3 Host wave: the Host Supervisor service boundary (P-05),
//! the existing Host owner for process launch and cancellation/termination,
//! enforces disjoint normal-workload and protected-control partitions for its
//! two frozen bottlenecks ([`HOST_LAUNCH_BOTTLENECK`] and
//! [`HOST_CANCELLATION_BOTTLENECK`]). Normal work can saturate the normal
//! partition without consuming protected cancellation/recovery capacity: an
//! admitted cancellation or recovery record keeps the protected Host path
//! while ordinary work observes exhaustion. Only [`NormalWorkClass`]
//! operations typecheck on the normal acquisition paths and only
//! [`ControlOperationClass`] operations typecheck on the protected paths, so
//! ordinary work cannot reach protected Host capacity by relabelling its
//! priority or class.
//!
//! Exhausted normal capacity renders as a versioned
//! [`I14BackpressureResponseV1`] with disposition `BUSY` naming exactly the
//! saturated Host bottleneck in its exact unit: process launch slots in
//! process slots, cancellation/termination operations in concurrent
//! operations. `STORAGE_BACKPRESSURE` is not used here: the existing
//! [`I14BackpressureResponseV1::validate`] pins that disposition to the ORS
//! durable queue bytes, so a Host observation would fail closed instead of
//! emitting evidence. Every response is validated by the existing
//! [`I14BackpressureResponseV1::validate`] before it is returned, so an
//! inconsistent observation fails closed instead of emitting a
//! disposition-only or generic queue-full answer. Each response method reads
//! the live reserve it reports and refuses while that reserve still admits
//! the request, so pressure evidence is never manufactured.
//!
//! W4 Host wave: every [`HostPermit`] is owner-issued non-clone evidence bound
//! to capacity class, bottleneck/unit/granted amount, typed operation,
//! operation identity, owner and the typed [`AuthorityEpoch`] observed at
//! acquisition, mirroring the ORS evidence grade. Every denial names the exact
//! bottleneck, shed work and observed epoch. A stale epoch, changed operation
//! or changed owner fails before consumption because the evidence no longer
//! matches the current owner state; there is no epoch-blind permit to replay.
//!
//! Each claimed Host dimension publishes its live partition evidence through
//! [`HostReserve::publish_owner_rows`] as validated
//! [`BottleneckCapacityProfile`] rows: exactly one row per Host dimension, in
//! frozen contract order, each naming exactly its own bottleneck. Every row is
//! re-validated by the existing [`BottleneckCapacityProfile::validate`] before
//! it is returned, so a missing owner, generation, physical total, protected
//! partition, enforcement, proof, evidence or invalidation reference fails
//! here rather than joining the Kernel profile composition as a claimed
//! guarantee. Rows for any other bottleneck are never produced here: one
//! owner's numbers are never presented as proof for another dimension.
//!
//! This module has no production caller yet (STITCH): it publishes the owner
//! evidence the Kernel profile composition will join, and the composition join
//! itself is another wave, so no caller is manufactured here. There is no emergency
//! partition here; recording reserve loss stays with the front-door
//! last-resort slot until a later wave wires Host-side loss reporting.
//! DISCLOSED LIMIT: `profile_revision` on the responses is caller-supplied
//! metadata echoed into the directive; the `Current` currentness claim refers
//! to the live-observed saturation at call time, not to a re-read of the
//! profile revision. Full installed-saturation proof stays #11 Product scope.

use std::num::NonZeroU64;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use eliot_contracts::{ArtifactId, AuthorityEpoch, OperationId};
use eliot_runtime_contracts::{
    AffectedOperationClass, BackpressureDisposition, BottleneckAvailability,
    BottleneckCapacityProfile, BottleneckCoverageState, BottleneckObservationV1,
    CapacityBottleneck, CapacityClass, CapacityEnforcement, CapacityLimit, CapacityUnit,
    ControlOperationClass, EarliestRecoveryCondition, EvidenceCoverageState,
    HumanActionRequirement, I14_BACKPRESSURE_RESPONSE_VERSION, I14BackpressureCause,
    I14BackpressureResponseV1, I14CurrentnessState, I14EscalationCondition, I14ForbiddenAction,
    I14RecoveryAction, I14RecoveryDirectiveV1, I14RequiredAuthority, I14ResolutionState,
    I14WorkOutcome, NormalWorkClass, RecoveryCommitStatus, StatePreservationStatus,
    frozen_bottleneck_owner_map,
};
use thiserror::Error;

/// The exact process-launch-slot bottleneck enforced by [`HostReserve`].
pub const HOST_LAUNCH_BOTTLENECK: CapacityBottleneck = CapacityBottleneck::ProcessLaunchSlots;

/// The exact cancellation/termination-operation bottleneck enforced by
/// [`HostReserve`].
pub const HOST_CANCELLATION_BOTTLENECK: CapacityBottleneck =
    CapacityBottleneck::ProcessCancellationTermination;

/// Typed Host reserve failures. None grants semantic or completion authority.
#[derive(Debug, Error)]
pub enum HostReserveError {
    /// An owner, operation or field identity is blank or malformed.
    #[error("{field} is invalid: {reason}")]
    InvalidField {
        /// Failing field name.
        field: &'static str,
        /// Why the field failed.
        reason: &'static str,
    },
    /// The existing contract rejected an assembled Host backpressure response.
    #[error("runtime contract rejected Host reserve response: {0}")]
    Contract(String),
    /// The normal partition cannot satisfy the request; the protected
    /// partition is untouched.
    #[error(
        "Host normal capacity exhausted for {bottleneck:?}: work {work_class:?} operation {operation_id} owned by {owner} epoch {epoch:?}"
    )]
    NormalCapacityExhausted {
        /// Bottleneck whose normal partition is saturated.
        bottleneck: CapacityBottleneck,
        /// Shed normal work class.
        work_class: NormalWorkClass,
        /// Operation that was not admitted.
        operation_id: String,
        /// Requesting owner.
        owner: String,
        /// Authority epoch observed at denial.
        epoch: AuthorityEpoch,
    },
    /// The protected partition cannot satisfy the request.
    #[error(
        "Host protected reserve exhausted for {bottleneck:?}: control operation {operation:?} operation {operation_id} owned by {owner} epoch {epoch:?}"
    )]
    ProtectedReserveExhausted {
        /// Bottleneck whose protected partition is saturated.
        bottleneck: CapacityBottleneck,
        /// Control operation that was not admitted.
        operation: ControlOperationClass,
        /// Operation that was not admitted.
        operation_id: String,
        /// Requesting owner.
        owner: String,
        /// Authority epoch observed at denial.
        epoch: AuthorityEpoch,
    },
}

/// Which Host dimension a permit holds.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HostDimension {
    /// Process launch slots, counted in process slots.
    LaunchSlots,
    /// Cancellation/termination operations, counted in concurrent operations.
    CancellationTermination,
}

impl HostDimension {
    /// Returns the frozen bottleneck enforced for this dimension.
    #[must_use]
    pub const fn bottleneck(self) -> CapacityBottleneck {
        match self {
            Self::LaunchSlots => HOST_LAUNCH_BOTTLENECK,
            Self::CancellationTermination => HOST_CANCELLATION_BOTTLENECK,
        }
    }
}

/// Typed operation identity carried by every [`HostPermit`].
///
/// The variant determines the only admissible [`CapacityClass`]: a normal work
/// class cannot name a protected operation and vice versa, so ordinary work
/// fails to typecheck against the protected acquisition paths instead of
/// failing at runtime.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HostPermitOperation {
    /// Ordinary workload operation.
    Normal(NormalWorkClass),
    /// Protected cancellation/recovery operation.
    Protected(ControlOperationClass),
}

impl HostPermitOperation {
    /// Returns the capacity class this operation draws from.
    #[must_use]
    pub const fn capacity_class(self) -> CapacityClass {
        match self {
            Self::Normal(_) => CapacityClass::NormalWorkload,
            Self::Protected(_) => CapacityClass::ProtectedControl,
        }
    }
}

/// Composition-resolved references identifying one Host owner-evidence
/// publication: the live partition capacities read from the reserve itself
/// and their physical total, and the [`CapacityEnforcement::ConfigurationPartition`]
/// mechanism those partitions are held under. The composition supplies the
/// references that identify the observation: its own owner-generation
/// reference for the Host owner, the independent proof-profile reference, and
/// the current evidence and invalidation references. Both halves are required:
/// [`HostReserve::publish_owner_rows`] fails closed through the existing
/// [`BottleneckCapacityProfile::validate`] when any reference is missing or
/// non-canonical, so the composition must resolve canonical (strictly
/// ascending, duplicate-free) reference sets rather than have them defaulted
/// or sorted here.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HostOwnerEvidenceContext {
    /// Owner generation/revision reference for the Host process-tree owner.
    pub owner_generation_ref: String,
    /// Independent proof-profile reference produced for the Host dimensions.
    pub proof_profile_ref: String,
    /// Current owner evidence references supporting the published rows.
    pub evidence_refs: Vec<String>,
    /// Exact invalidation set of the published rows.
    pub invalidation_set: Vec<String>,
}

#[derive(Debug)]
struct HostReserveInner {
    launch_normal_capacity: u64,
    launch_protected_capacity: u64,
    cancellation_normal_capacity: u64,
    cancellation_protected_capacity: u64,
    launch_normal_in_flight: AtomicU64,
    launch_protected_in_flight: AtomicU64,
    cancellation_normal_in_flight: AtomicU64,
    cancellation_protected_in_flight: AtomicU64,
}

/// The Host control reserve: disjoint normal/protected partitions for the two
/// Host bottlenecks, owned by the Host Supervisor service boundary.
///
/// Acquiring from one partition never observes or consumes another:
/// saturating normal launch slots or normal cancellation/termination
/// operations leaves the full protected capacity available for admitted
/// cancellation/recovery records and vice versa. Acquisition is non-blocking
/// and atomic; release is automatic when the returned [`HostPermit`] drops.
#[derive(Clone, Debug)]
pub struct HostReserve {
    inner: Arc<HostReserveInner>,
}

/// One held Host capacity permit, bound to dimension, class, operation, owner
/// and Authority Epoch. Releasing is automatic on drop and returns exactly
/// the consumed partition and amount.
///
/// The permit is bound to the typed Authority Epoch the caller resolved at
/// acquisition: evidence from a fenced epoch never authorizes consumption
/// under the current one. Permits are deliberately not [`Clone`]: duplicating
/// a permit handle must never duplicate the underlying capacity.
#[derive(Debug)]
pub struct HostPermit {
    inner: Arc<HostReserveInner>,
    dimension: HostDimension,
    class: CapacityClass,
    amount: u64,
    operation: HostPermitOperation,
    operation_id: String,
    owner: String,
    epoch: AuthorityEpoch,
}

impl HostPermit {
    /// Returns the capacity class (partition) this permit holds.
    #[must_use]
    pub const fn capacity_class(&self) -> CapacityClass {
        self.class
    }

    /// Returns which Host dimension this permit was granted from.
    #[must_use]
    pub const fn dimension(&self) -> HostDimension {
        self.dimension
    }

    /// Returns the bottleneck this permit was granted from.
    #[must_use]
    pub const fn bottleneck(&self) -> CapacityBottleneck {
        self.dimension.bottleneck()
    }

    /// Returns the exact unit this permit was granted in.
    #[must_use]
    pub const fn unit(&self) -> CapacityUnit {
        self.dimension.bottleneck().unit()
    }

    /// Returns the amount held in the bottleneck's exact unit.
    #[must_use]
    pub const fn amount(&self) -> u64 {
        self.amount
    }

    /// Returns the typed operation identity carried by this permit.
    #[must_use]
    pub const fn operation(&self) -> HostPermitOperation {
        self.operation
    }

    /// Returns the operation identity this permit was granted for.
    #[must_use]
    pub fn operation_id(&self) -> &str {
        &self.operation_id
    }

    /// Returns the owner this permit was granted to.
    #[must_use]
    pub fn owner(&self) -> &str {
        &self.owner
    }

    /// Returns the Authority Epoch bound at acquisition.
    #[must_use]
    pub const fn epoch(&self) -> AuthorityEpoch {
        self.epoch
    }
}

impl Drop for HostPermit {
    fn drop(&mut self) {
        let slot = match (self.dimension, self.class) {
            (HostDimension::LaunchSlots, CapacityClass::NormalWorkload) => {
                &self.inner.launch_normal_in_flight
            }
            (HostDimension::LaunchSlots, _) => &self.inner.launch_protected_in_flight,
            (HostDimension::CancellationTermination, CapacityClass::NormalWorkload) => {
                &self.inner.cancellation_normal_in_flight
            }
            (HostDimension::CancellationTermination, _) => {
                &self.inner.cancellation_protected_in_flight
            }
        };
        debug_assert!(
            slot.load(Ordering::Acquire) >= self.amount,
            "HOST permit drop without a held partition amount"
        );
        slot.fetch_sub(self.amount, Ordering::AcqRel);
    }
}

/// Atomically adds `amount` to `slot` unless `capacity` would be exceeded.
fn cas_add(slot: &AtomicU64, capacity: u64, amount: u64) -> bool {
    let mut observed = slot.load(Ordering::Acquire);
    loop {
        let Some(next) = observed.checked_add(amount) else {
            return false;
        };
        if next > capacity {
            return false;
        }
        match slot.compare_exchange_weak(observed, next, Ordering::AcqRel, Ordering::Acquire) {
            Ok(_) => return true,
            Err(current) => observed = current,
        }
    }
}

/// Rejects blank, control-character or overlong owner/operation identities.
fn validate_text(value: &str, field: &'static str) -> Result<(), HostReserveError> {
    if value.trim().is_empty() {
        return Err(HostReserveError::InvalidField {
            field,
            reason: "must be non-blank",
        });
    }
    if value.chars().any(char::is_control) {
        return Err(HostReserveError::InvalidField {
            field,
            reason: "must not contain control characters",
        });
    }
    if value.len() > 1_024 {
        return Err(HostReserveError::InvalidField {
            field,
            reason: "must not exceed 1024 UTF-8 bytes",
        });
    }
    Ok(())
}

impl HostReserve {
    /// Creates a Host reserve with disjoint normal and protected partitions
    /// for both Host dimensions.
    ///
    /// Normal work draws only from the normal launch slots and normal
    /// cancellation/termination operations; admitted cancellation/recovery
    /// draws only from the protected launch slots and protected
    /// cancellation/termination operations. Neither class can borrow from the
    /// other.
    ///
    /// # Errors
    ///
    /// Returns [`HostReserveError::InvalidField`] when any partition capacity
    /// is zero.
    pub fn partitioned(
        normal_launch_slots: u64,
        protected_launch_slots: u64,
        normal_cancellation_slots: u64,
        protected_cancellation_slots: u64,
    ) -> Result<Self, HostReserveError> {
        if normal_launch_slots == 0 {
            return Err(HostReserveError::InvalidField {
                field: "host_reserve.normal_launch_slots",
                reason: "must be greater than zero",
            });
        }
        if protected_launch_slots == 0 {
            return Err(HostReserveError::InvalidField {
                field: "host_reserve.protected_launch_slots",
                reason: "must be greater than zero",
            });
        }
        if normal_cancellation_slots == 0 {
            return Err(HostReserveError::InvalidField {
                field: "host_reserve.normal_cancellation_slots",
                reason: "must be greater than zero",
            });
        }
        if protected_cancellation_slots == 0 {
            return Err(HostReserveError::InvalidField {
                field: "host_reserve.protected_cancellation_slots",
                reason: "must be greater than zero",
            });
        }
        Ok(Self {
            inner: Arc::new(HostReserveInner {
                launch_normal_capacity: normal_launch_slots,
                launch_protected_capacity: protected_launch_slots,
                cancellation_normal_capacity: normal_cancellation_slots,
                cancellation_protected_capacity: protected_cancellation_slots,
                launch_normal_in_flight: AtomicU64::new(0),
                launch_protected_in_flight: AtomicU64::new(0),
                cancellation_normal_in_flight: AtomicU64::new(0),
                cancellation_protected_in_flight: AtomicU64::new(0),
            }),
        })
    }

    /// Returns the configured normal launch-slot partition capacity.
    #[must_use]
    pub fn normal_launch_capacity(&self) -> u64 {
        self.inner.launch_normal_capacity
    }

    /// Returns the configured protected launch-slot partition capacity.
    #[must_use]
    pub fn protected_launch_capacity(&self) -> u64 {
        self.inner.launch_protected_capacity
    }

    /// Returns the configured normal cancellation/termination partition capacity.
    #[must_use]
    pub fn normal_cancellation_capacity(&self) -> u64 {
        self.inner.cancellation_normal_capacity
    }

    /// Returns the configured protected cancellation/termination partition capacity.
    #[must_use]
    pub fn protected_cancellation_capacity(&self) -> u64 {
        self.inner.cancellation_protected_capacity
    }

    /// Returns the currently available normal launch slots.
    #[must_use]
    pub fn available_normal_launch(&self) -> u64 {
        self.inner
            .launch_normal_capacity
            .saturating_sub(self.inner.launch_normal_in_flight.load(Ordering::Acquire))
    }

    /// Returns the currently available protected launch slots.
    #[must_use]
    pub fn available_protected_launch(&self) -> u64 {
        self.inner.launch_protected_capacity.saturating_sub(
            self.inner
                .launch_protected_in_flight
                .load(Ordering::Acquire),
        )
    }

    /// Returns the currently available normal cancellation/termination operations.
    #[must_use]
    pub fn available_normal_cancellation(&self) -> u64 {
        self.inner.cancellation_normal_capacity.saturating_sub(
            self.inner
                .cancellation_normal_in_flight
                .load(Ordering::Acquire),
        )
    }

    /// Returns the currently available protected cancellation/termination operations.
    #[must_use]
    pub fn available_protected_cancellation(&self) -> u64 {
        self.inner.cancellation_protected_capacity.saturating_sub(
            self.inner
                .cancellation_protected_in_flight
                .load(Ordering::Acquire),
        )
    }

    /// Attempts to acquire one normal launch slot without blocking.
    ///
    /// Only [`NormalWorkClass`] operations typecheck here, so protected Host
    /// capacity is unreachable through this path by construction. The granted
    /// permit binds `epoch`; a caller presenting it under a different epoch
    /// holds evidence that no longer matches the current owner state.
    ///
    /// # Errors
    ///
    /// Returns [`HostReserveError::InvalidField`] for a blank owner/operation
    /// identity, or [`HostReserveError::NormalCapacityExhausted`] naming the
    /// launch bottleneck, shed work and observed epoch when the normal
    /// partition is saturated. The protected partition is untouched in every
    /// case.
    pub fn try_acquire_normal_launch(
        &self,
        work: NormalWorkClass,
        owner: &str,
        operation_id: &str,
        epoch: AuthorityEpoch,
    ) -> Result<HostPermit, HostReserveError> {
        validate_text(owner, "host_permit.owner")?;
        validate_text(operation_id, "host_permit.operation_id")?;
        if !cas_add(
            &self.inner.launch_normal_in_flight,
            self.inner.launch_normal_capacity,
            1,
        ) {
            return Err(HostReserveError::NormalCapacityExhausted {
                bottleneck: HOST_LAUNCH_BOTTLENECK,
                work_class: work,
                operation_id: operation_id.to_owned(),
                owner: owner.to_owned(),
                epoch,
            });
        }
        Ok(HostPermit {
            inner: self.inner.clone(),
            dimension: HostDimension::LaunchSlots,
            class: CapacityClass::NormalWorkload,
            amount: 1,
            operation: HostPermitOperation::Normal(work),
            operation_id: operation_id.to_owned(),
            owner: owner.to_owned(),
            epoch,
        })
    }

    /// Attempts to acquire one normal cancellation/termination operation slot
    /// without blocking.
    ///
    /// Only [`NormalWorkClass`] operations typecheck here, so protected Host
    /// cancellation capacity is unreachable through this path by
    /// construction. The granted permit binds `epoch`; a caller presenting it
    /// under a different epoch holds evidence that no longer matches the
    /// current owner state.
    ///
    /// # Errors
    ///
    /// Returns [`HostReserveError::InvalidField`] for a blank owner/operation
    /// identity, or [`HostReserveError::NormalCapacityExhausted`] naming the
    /// cancellation bottleneck, shed work and observed epoch when the normal
    /// partition is saturated. The protected partition is untouched in every
    /// case.
    pub fn try_acquire_normal_cancellation(
        &self,
        work: NormalWorkClass,
        owner: &str,
        operation_id: &str,
        epoch: AuthorityEpoch,
    ) -> Result<HostPermit, HostReserveError> {
        validate_text(owner, "host_permit.owner")?;
        validate_text(operation_id, "host_permit.operation_id")?;
        if !cas_add(
            &self.inner.cancellation_normal_in_flight,
            self.inner.cancellation_normal_capacity,
            1,
        ) {
            return Err(HostReserveError::NormalCapacityExhausted {
                bottleneck: HOST_CANCELLATION_BOTTLENECK,
                work_class: work,
                operation_id: operation_id.to_owned(),
                owner: owner.to_owned(),
                epoch,
            });
        }
        Ok(HostPermit {
            inner: self.inner.clone(),
            dimension: HostDimension::CancellationTermination,
            class: CapacityClass::NormalWorkload,
            amount: 1,
            operation: HostPermitOperation::Normal(work),
            operation_id: operation_id.to_owned(),
            owner: owner.to_owned(),
            epoch,
        })
    }

    /// Attempts to acquire one protected launch slot without blocking.
    ///
    /// Only [`ControlOperationClass`] operations typecheck here: ordinary work
    /// cannot name a protected operation and therefore cannot acquire this
    /// partition. This is the path an admitted cancellation/recovery record
    /// keeps while normal launch work is saturated. The granted permit binds
    /// `epoch` so the recovery record proves it was admitted under the current
    /// owner state.
    ///
    /// # Errors
    ///
    /// Returns [`HostReserveError::InvalidField`] for a blank owner/operation
    /// identity, or [`HostReserveError::ProtectedReserveExhausted`] naming
    /// the launch bottleneck, operation, owner, request and observed epoch
    /// when the protected partition is saturated.
    pub fn try_acquire_protected_launch(
        &self,
        operation: ControlOperationClass,
        owner: &str,
        operation_id: &str,
        epoch: AuthorityEpoch,
    ) -> Result<HostPermit, HostReserveError> {
        validate_text(owner, "host_permit.owner")?;
        validate_text(operation_id, "host_permit.operation_id")?;
        if !cas_add(
            &self.inner.launch_protected_in_flight,
            self.inner.launch_protected_capacity,
            1,
        ) {
            return Err(HostReserveError::ProtectedReserveExhausted {
                bottleneck: HOST_LAUNCH_BOTTLENECK,
                operation,
                operation_id: operation_id.to_owned(),
                owner: owner.to_owned(),
                epoch,
            });
        }
        Ok(HostPermit {
            inner: self.inner.clone(),
            dimension: HostDimension::LaunchSlots,
            class: CapacityClass::ProtectedControl,
            amount: 1,
            operation: HostPermitOperation::Protected(operation),
            operation_id: operation_id.to_owned(),
            owner: owner.to_owned(),
            epoch,
        })
    }

    /// Attempts to acquire one protected cancellation/termination operation
    /// slot without blocking.
    ///
    /// Only [`ControlOperationClass`] operations typecheck here: ordinary work
    /// cannot name a protected operation and therefore cannot acquire this
    /// partition. This is the path an admitted cancellation/recovery record
    /// keeps while normal cancellation work is saturated. The granted permit
    /// binds `epoch` so the recovery record proves it was admitted under the
    /// current owner state.
    ///
    /// # Errors
    ///
    /// Returns [`HostReserveError::InvalidField`] for a blank owner/operation
    /// identity, or [`HostReserveError::ProtectedReserveExhausted`] naming
    /// the cancellation bottleneck, operation, owner, request and observed
    /// epoch when the protected partition is saturated.
    pub fn try_acquire_protected_cancellation(
        &self,
        operation: ControlOperationClass,
        owner: &str,
        operation_id: &str,
        epoch: AuthorityEpoch,
    ) -> Result<HostPermit, HostReserveError> {
        validate_text(owner, "host_permit.owner")?;
        validate_text(operation_id, "host_permit.operation_id")?;
        if !cas_add(
            &self.inner.cancellation_protected_in_flight,
            self.inner.cancellation_protected_capacity,
            1,
        ) {
            return Err(HostReserveError::ProtectedReserveExhausted {
                bottleneck: HOST_CANCELLATION_BOTTLENECK,
                operation,
                operation_id: operation_id.to_owned(),
                owner: owner.to_owned(),
                epoch,
            });
        }
        Ok(HostPermit {
            inner: self.inner.clone(),
            dimension: HostDimension::CancellationTermination,
            class: CapacityClass::ProtectedControl,
            amount: 1,
            operation: HostPermitOperation::Protected(operation),
            operation_id: operation_id.to_owned(),
            owner: owner.to_owned(),
            epoch,
        })
    }

    /// Reports exhausted normal launch slots as a `BUSY` response naming
    /// exactly [`HOST_LAUNCH_BOTTLENECK`].
    ///
    /// The response is built only while [`Self::available_normal_launch`] is
    /// zero: pressure evidence is never manufactured for a partition that
    /// still admits work. The protected partition is not read and not
    /// claimed.
    ///
    /// # Errors
    ///
    /// Returns [`HostReserveError::InvalidField`] when normal launch capacity
    /// remains or the operation identity is malformed, or
    /// [`HostReserveError::Contract`] when the assembled directive fails the
    /// existing contract validation.
    pub fn normal_launch_exhaustion_response(
        &self,
        work: NormalWorkClass,
        operation_id: &str,
        profile_revision: ArtifactId,
    ) -> Result<I14BackpressureResponseV1, HostReserveError> {
        if self.available_normal_launch() > 0 {
            return Err(HostReserveError::InvalidField {
                field: "host_reserve.normal_launch_slots",
                reason: "normal launch partition is not saturated; no pressure evidence to report",
            });
        }
        let operation =
            OperationId::new(operation_id).map_err(|_| HostReserveError::InvalidField {
                field: "host_rejection.operation_id",
                reason: "must be a bounded non-blank reference",
            })?;
        HostRejectionParts {
            affected: AffectedOperationClass::Normal(work),
            observation: BottleneckObservationV1 {
                bottleneck: HOST_LAUNCH_BOTTLENECK,
                unit: HOST_LAUNCH_BOTTLENECK.unit(),
                requested_amount: 1,
                availability: BottleneckAvailability::Exhausted {
                    available_amount: 0,
                },
                coverage_state: BottleneckCoverageState::Claimed,
            },
            operation_id: Some(operation),
            profile_revision,
        }
        .into_response(
            BackpressureDisposition::Busy,
            I14WorkOutcome::NotAccepted,
            RecoveryCommitStatus::None,
        )
    }

    /// Reports exhausted normal cancellation/termination operations as a
    /// `BUSY` response naming exactly [`HOST_CANCELLATION_BOTTLENECK`].
    ///
    /// The response is built only while
    /// [`Self::available_normal_cancellation`] is zero: pressure evidence is
    /// never manufactured for a partition that still admits work. The
    /// protected partition is not read and not claimed, so an admitted
    /// cancellation/recovery record keeps its path while this response is
    /// live. `BUSY` (not `STORAGE_BACKPRESSURE`) is the honest disposition:
    /// the existing contract validation pins `STORAGE_BACKPRESSURE` to the
    /// ORS durable queue bytes.
    ///
    /// # Errors
    ///
    /// Returns [`HostReserveError::InvalidField`] when normal cancellation
    /// capacity remains or the operation identity is malformed, or
    /// [`HostReserveError::Contract`] when the assembled directive fails the
    /// existing contract validation.
    pub fn normal_cancellation_exhaustion_response(
        &self,
        work: NormalWorkClass,
        operation_id: &str,
        profile_revision: ArtifactId,
    ) -> Result<I14BackpressureResponseV1, HostReserveError> {
        if self.available_normal_cancellation() > 0 {
            return Err(HostReserveError::InvalidField {
                field: "host_reserve.normal_cancellation_slots",
                reason: "normal cancellation partition is not saturated; no pressure evidence to report",
            });
        }
        let operation =
            OperationId::new(operation_id).map_err(|_| HostReserveError::InvalidField {
                field: "host_rejection.operation_id",
                reason: "must be a bounded non-blank reference",
            })?;
        HostRejectionParts {
            affected: AffectedOperationClass::Normal(work),
            observation: BottleneckObservationV1 {
                bottleneck: HOST_CANCELLATION_BOTTLENECK,
                unit: HOST_CANCELLATION_BOTTLENECK.unit(),
                requested_amount: 1,
                availability: BottleneckAvailability::Exhausted {
                    available_amount: 0,
                },
                coverage_state: BottleneckCoverageState::Claimed,
            },
            operation_id: Some(operation),
            profile_revision,
        }
        .into_response(
            BackpressureDisposition::Busy,
            I14WorkOutcome::NotAccepted,
            RecoveryCommitStatus::None,
        )
    }
}

    /// Publishes the live partition evidence for both Host dimensions as
    /// claimed [`BottleneckCapacityProfile`] rows, in frozen contract order.
    ///
    /// The result carries exactly one row per Host dimension: launch slots
    /// first, cancellation/termination operations second. Each row names the
    /// frozen owner the contract binds to that dimension, the exact bottleneck
    /// unit, the physical total and the disjoint normal and protected
    /// partitions read from this reserve. There is no emergency partition
    /// here, so none is claimed. The owner generation, proof profile, evidence
    /// and invalidation references are composition-supplied metadata echoed
    /// into the rows from `ctx`; the Kernel composition wraps these rows in
    /// its own evidence records with the configuration snapshot and Authority
    /// Epoch it resolved.
    ///
    /// Each row is checked by the existing
    /// [`BottleneckCapacityProfile::validate`] before it is returned, so a
    /// missing owner, generation, physical total, protected partition,
    /// enforcement, proof, evidence or invalidation reference fails here
    /// rather than publishing a row the Kernel composition would have to lower
    /// to `UNKNOWN`.
    ///
    /// # Errors
    ///
    /// Returns [`HostReserveError::Contract`] when the frozen owner map binds
    /// no owner to a Host dimension, when the configured partition capacities
    /// cannot form a positive physical total, or when either assembled row
    /// fails the existing contract validation.
    pub fn publish_owner_rows(
        &self,
        ctx: &HostOwnerEvidenceContext,
    ) -> Result<[BottleneckCapacityProfile; 2], HostReserveError> {
        let launch = host_owner_capacity_row(
            HOST_LAUNCH_BOTTLENECK,
            self.inner.launch_normal_capacity,
            self.inner.launch_protected_capacity,
            ctx,
        )?;
        let cancellation = host_owner_capacity_row(
            HOST_CANCELLATION_BOTTLENECK,
            self.inner.cancellation_normal_capacity,
            self.inner.cancellation_protected_capacity,
            ctx,
        )?;
        Ok([launch, cancellation])
    }
}

/// Exact parts of one Host rejection directive shared by every constructor.
struct HostRejectionParts {
    affected: AffectedOperationClass,
    observation: BottleneckObservationV1,
    operation_id: Option<OperationId>,
    profile_revision: ArtifactId,
}

impl HostRejectionParts {
    /// Assembles the versioned response and validates it with the existing
    /// contract check; an inconsistent observation fails closed here.
    fn into_response(
        self,
        disposition: BackpressureDisposition,
        work_outcome: I14WorkOutcome,
        commit_status: RecoveryCommitStatus,
    ) -> Result<I14BackpressureResponseV1, HostReserveError> {
        let response = I14BackpressureResponseV1 {
            contract_version: I14_BACKPRESSURE_RESPONSE_VERSION,
            disposition,
            directive: I14RecoveryDirectiveV1 {
                cause: I14BackpressureCause::CapacityExhaustion,
                affected_operation_class: self.affected,
                bottlenecks: vec![self.observation],
                work_outcome,
                commit_status,
                state_preservation: StatePreservationStatus::Preserved,
                operation_id: self.operation_id,
                preserve_operation_id: true,
                stage_receipt: None,
                rollback_receipt: None,
                retry_strategy: I14RecoveryAction::AwaitCondition,
                earliest_permitted_condition: EarliestRecoveryCondition::CapacityAvailable,
                earliest_permitted_unix_millis: None,
                actions_temporarily_forbidden: Vec::<I14ForbiddenAction>::new(),
                safe_fallback: None,
                required_authority: I14RequiredAuthority::NoneRequired,
                human_action_required: HumanActionRequirement::NoneRequired,
                evidence_refs: Vec::new(),
                evidence_coverage: EvidenceCoverageState::Unavailable,
                escalation_condition: I14EscalationCondition::None,
                resolution_state: I14ResolutionState::Pending,
                currentness: I14CurrentnessState::Current,
                profile_revision: self.profile_revision,
                state_fence: None,
                authority_epoch: None,
            },
        };
        response
            .validate()
            .map_err(|error| HostReserveError::Contract(error.to_string()))?;
        Ok(response)
    }
}

/// Builds one claimed owner row for a Host dimension from the reserve's
/// configured partition capacities and the composition-resolved references.
///
/// The owner reference is read from the frozen owner map, never restated here;
/// the unit is the bottleneck's own declared unit. The physical total is
/// exactly the sum of the two disjoint partitions, so the existing partition
/// accounting check always bounds them. A zero partition capacity or a missing
/// frozen owner fails closed: the reserve constructor already refuses zero
/// partitions, and a dimension without a frozen owner has no claim to publish.
fn host_owner_capacity_row(
    bottleneck: CapacityBottleneck,
    normal_capacity: u64,
    protected_capacity: u64,
    ctx: &HostOwnerEvidenceContext,
) -> Result<BottleneckCapacityProfile, HostReserveError> {
    let owner = frozen_bottleneck_owner_map()
        .into_iter()
        .find(|bound| bound.bottleneck == bottleneck)
        .map(|bound| bound.owner)
        .ok_or_else(|| {
            HostReserveError::Contract(format!(
                "frozen owner map binds no owner to {bottleneck:?}; no Host row to publish"
            ))
        })?;
    let unit = bottleneck.unit();
    let limit = |field: &'static str, amount: u64| {
        NonZeroU64::new(amount)
            .map(|quantity| CapacityLimit { unit, quantity })
            .ok_or(HostReserveError::InvalidField {
                field,
                reason: "partition capacity must be greater than zero",
            })
    };
    let normal_limit = limit("host_reserve.normal_limit", normal_capacity)?;
    let protected_limit = limit("host_reserve.protected_limit", protected_capacity)?;
    let physical_total =
        normal_capacity
            .checked_add(protected_capacity)
            .ok_or(HostReserveError::InvalidField {
                field: "host_reserve.physical_total_limit",
                reason: "disjoint partition capacities overflow the physical total",
            })?;
    let physical_total_limit =
        NonZeroU64::new(physical_total).ok_or(HostReserveError::InvalidField {
            field: "host_reserve.physical_total_limit",
            reason: "physical total must be greater than zero",
        })?;
    let row = BottleneckCapacityProfile {
        bottleneck,
        coverage_state: BottleneckCoverageState::Claimed,
        owner_ref: owner.to_owned(),
        owner_generation_ref: ctx.owner_generation_ref.clone(),
        unit,
        physical_total_limit: Some(CapacityLimit {
            unit,
            quantity: physical_total_limit,
        }),
        normal_work_applicable: true,
        normal_limit: Some(normal_limit),
        protected_limit: Some(protected_limit),
        emergency_limit: None,
        enforcement: Some(CapacityEnforcement::ConfigurationPartition),
        proof_profile_ref: ctx.proof_profile_ref.clone(),
        evidence_refs: ctx.evidence_refs.clone(),
        invalidation_set: ctx.invalidation_set.clone(),
    };
    row.validate()
        .map_err(|error| HostReserveError::Contract(error.to_string()))?;
    Ok(row)
}
