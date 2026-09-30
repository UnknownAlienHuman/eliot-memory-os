//! ORS control-reserve partitions for transaction slots and durable queue bytes.
//!
//! Issue #1679, W3 ORS wave: the Kernel ORS owner enforces disjoint
//! normal-workload and protected-control partitions for its two frozen
//! bottlenecks ([`ORS_TRANSACTION_BOTTLENECK`] and
//! [`ORS_DURABLE_BYTES_BOTTLENECK`]). Normal work can saturate the normal
//! partition without consuming protected cancellation/recovery capacity: an
//! admitted cancellation or recovery record keeps the protected ORS path while
//! ordinary work observes exhaustion. Only [`NormalWorkClass`] operations
//! typecheck on the normal acquisition paths and only
//! [`ControlOperationClass`] operations typecheck on the protected paths, so a
//! normal Store write, named read, agent or maintenance admission cannot reach
//! protected ORS capacity by relabelling its priority or class.
//!
//! Exhausted normal durable bytes render as a versioned
//! [`I14BackpressureResponseV1`] with disposition `STORAGE_BACKPRESSURE`
//! naming exactly [`ORS_DURABLE_BYTES_BOTTLENECK`] in its byte unit; exhausted
//! normal transaction slots render as `BUSY` naming exactly
//! [`ORS_TRANSACTION_BOTTLENECK`]. Every response is validated by the existing
//! [`I14BackpressureResponseV1::validate`] before it is returned, so an
//! inconsistent observation fails closed instead of emitting a
//! disposition-only or generic queue-full answer. Each response method reads
//! the live reserve it reports and refuses while that reserve still admits
//! the request, so pressure evidence is never manufactured.
//!
//! Each claimed dimension publishes its live partition evidence through
//! [`OrsReserve::publish_claimed_row`] as a validated
//! [`BottleneckCapacityProfile`] row for the Kernel profile composition to
//! join in frozen contract order. Durably staged work renders as
//! `ACCEPTED_PENDING` through [`OrsReserve::durable_stage_pending_response`]
//! only against the staging path's receipt, with poll/reconcile and no blind
//! retry.
//!
//! This module has no production caller yet (STITCH): it publishes the owner
//! evidence the Kernel profile composition will join. There is no emergency
//! partition here; recording reserve loss stays with the front-door
//! last-resort slot until a later wave wires ORS-side loss reporting.
//! DISCLOSED LIMIT: `profile_revision` on the responses is caller-supplied
//! metadata echoed into the directive; the `Current` currentness claim refers
//! to the live-observed saturation at call time, not to a re-read of the
//! profile revision. Full installed-saturation proof stays #11 Product scope.

use std::num::NonZeroU64;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use eliot_contracts::{ArtifactId, AuthorityEpoch, OperationId, ReceiptId};
use eliot_runtime_contracts::{
    AffectedOperationClass, BackpressureDisposition, BottleneckAvailability,
    BottleneckCapacityProfile, BottleneckCoverageState, BottleneckObservationV1,
    CapacityBottleneck, CapacityClass, CapacityEnforcement, CapacityLimit, ControlOperationClass,
    EarliestRecoveryCondition, EvidenceCoverageState, HumanActionRequirement,
    I14_BACKPRESSURE_RESPONSE_VERSION, I14BackpressureCause, I14BackpressureResponseV1,
    I14CurrentnessState, I14EscalationCondition, I14ForbiddenAction, I14RecoveryAction,
    I14RecoveryDirectiveV1, I14RequiredAuthority, I14ResolutionState, I14WorkOutcome,
    NormalWorkClass, RecoveryCommitStatus, StatePreservationStatus, frozen_bottleneck_owner_map,
};
use thiserror::Error;

use crate::model::validate_text;

/// The exact transaction-slot bottleneck enforced by [`OrsReserve`].
pub const ORS_TRANSACTION_BOTTLENECK: CapacityBottleneck = CapacityBottleneck::OrsTransactionSlots;

/// The exact durable-queue-bytes bottleneck enforced by [`OrsReserve`].
pub const ORS_DURABLE_BYTES_BOTTLENECK: CapacityBottleneck =
    CapacityBottleneck::OrsDurableQueueBytes;

/// Typed ORS reserve failures. None grants semantic or completion authority.
#[derive(Debug, Error)]
pub enum OrsReserveError {
    /// An owner, operation or field identity is blank or malformed.
    #[error("{field} is invalid: {reason}")]
    InvalidField {
        /// Failing field name.
        field: &'static str,
        /// Why the field failed.
        reason: &'static str,
    },
    /// The existing contract rejected an assembled ORS backpressure response.
    #[error("runtime contract rejected ORS reserve response: {0}")]
    Contract(String),
    /// The normal partition cannot satisfy the request; the protected
    /// partition is untouched.
    #[error(
        "ORS normal capacity exhausted for {bottleneck:?}: work {work_class:?} operation {operation_id} owned by {owner}"
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
    },
    /// The protected partition cannot satisfy the request.
    #[error(
        "ORS protected reserve exhausted for {bottleneck:?}: control operation {operation:?} operation {operation_id} owned by {owner}"
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
    },
}

/// Which ORS dimension a permit holds.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OrsDimension {
    /// ORS transaction slots, counted in transactions.
    TransactionSlots,
    /// ORS durable queue bytes, counted in bytes.
    DurableQueueBytes,
}

impl OrsDimension {
    /// Returns the frozen bottleneck enforced for this dimension.
    #[must_use]
    pub const fn bottleneck(self) -> CapacityBottleneck {
        match self {
            Self::TransactionSlots => ORS_TRANSACTION_BOTTLENECK,
            Self::DurableQueueBytes => ORS_DURABLE_BYTES_BOTTLENECK,
        }
    }
}

/// Typed operation identity carried by every [`OrsPermit`].
///
/// The variant determines the only admissible [`CapacityClass`]: a normal work
/// class cannot name a protected operation and vice versa, so ordinary work
/// fails to typecheck against the protected acquisition paths instead of
/// failing at runtime.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OrsPermitOperation {
    /// Ordinary workload operation.
    Normal(NormalWorkClass),
    /// Protected cancellation/recovery operation.
    Protected(ControlOperationClass),
}

impl OrsPermitOperation {
    /// Returns the capacity class this operation draws from.
    #[must_use]
    pub const fn capacity_class(self) -> CapacityClass {
        match self {
            Self::Normal(_) => CapacityClass::NormalWorkload,
            Self::Protected(_) => CapacityClass::ProtectedControl,
        }
    }
}

#[derive(Debug)]
struct OrsReserveInner {
    transaction_normal_capacity: u64,
    transaction_protected_capacity: u64,
    durable_normal_capacity_bytes: u64,
    durable_protected_capacity_bytes: u64,
    transaction_normal_in_flight: AtomicU64,
    transaction_protected_in_flight: AtomicU64,
    durable_normal_in_flight_bytes: AtomicU64,
    durable_protected_in_flight_bytes: AtomicU64,
    /// Restart seal flag: while set, every acquisition fails closed with its
    /// typed exhaustion disposition and unknown held capacity stays excluded.
    restart_sealed: AtomicBool,
    /// Epoch observed at the restart seal; unsealing requires the epoch to
    /// have advanced past it (stale ownership fenced).
    sealed_epoch: Mutex<Option<AuthorityEpoch>>,
}

/// The ORS control reserve: disjoint normal/protected partitions for the two
/// ORS bottlenecks, owned by the Kernel ORS owner.
///
/// Acquiring from one partition never observes or consumes another:
/// saturating normal durable bytes or normal transaction slots leaves the full
/// protected capacity available for admitted cancellation/recovery records and
/// vice versa. Acquisition is non-blocking and atomic; release is automatic
/// when the returned [`OrsPermit`] drops.
#[derive(Clone, Debug)]
pub struct OrsReserve {
    inner: Arc<OrsReserveInner>,
}

/// One held ORS capacity permit, bound to dimension, class, operation and
/// owner. Releasing is automatic on drop and returns exactly the consumed
/// partition and amount.
///
/// Permits are deliberately not [`Clone`]: duplicating a permit handle must
/// never duplicate the underlying capacity.
#[derive(Debug)]
pub struct OrsPermit {
    inner: Arc<OrsReserveInner>,
    dimension: OrsDimension,
    class: CapacityClass,
    amount: u64,
    operation: OrsPermitOperation,
    operation_id: String,
    owner: String,
}

impl OrsPermit {
    /// Returns the capacity class (partition) this permit holds.
    #[must_use]
    pub const fn capacity_class(&self) -> CapacityClass {
        self.class
    }

    /// Returns which ORS dimension this permit was granted from.
    #[must_use]
    pub const fn dimension(&self) -> OrsDimension {
        self.dimension
    }

    /// Returns the bottleneck this permit was granted from.
    #[must_use]
    pub const fn bottleneck(&self) -> CapacityBottleneck {
        self.dimension.bottleneck()
    }

    /// Returns the amount held in the bottleneck's exact unit.
    #[must_use]
    pub const fn amount(&self) -> u64 {
        self.amount
    }

    /// Returns the typed operation identity carried by this permit.
    #[must_use]
    pub const fn operation(&self) -> OrsPermitOperation {
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
}

impl Drop for OrsPermit {
    fn drop(&mut self) {
        let slot = match (self.dimension, self.class) {
            (OrsDimension::TransactionSlots, CapacityClass::NormalWorkload) => {
                &self.inner.transaction_normal_in_flight
            }
            (OrsDimension::TransactionSlots, _) => &self.inner.transaction_protected_in_flight,
            (OrsDimension::DurableQueueBytes, CapacityClass::NormalWorkload) => {
                &self.inner.durable_normal_in_flight_bytes
            }
            (OrsDimension::DurableQueueBytes, _) => &self.inner.durable_protected_in_flight_bytes,
        };
        debug_assert!(
            slot.load(Ordering::Acquire) >= self.amount,
            "ORS permit drop without a held partition amount"
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

impl OrsReserve {
    /// Creates an ORS reserve with disjoint normal and protected partitions
    /// for both ORS dimensions.
    ///
    /// Normal work draws only from the normal transaction slots and normal
    /// durable bytes; admitted cancellation/recovery draws only from the
    /// protected transaction slots and protected durable bytes. Neither class
    /// can borrow from the other.
    ///
    /// # Errors
    ///
    /// Returns [`OrsReserveError::InvalidField`] when any partition capacity
    /// is zero.
    pub fn partitioned(
        normal_transaction_slots: u64,
        protected_transaction_slots: u64,
        normal_durable_bytes: NonZeroU64,
        protected_durable_bytes: NonZeroU64,
    ) -> Result<Self, OrsReserveError> {
        if normal_transaction_slots == 0 {
            return Err(OrsReserveError::InvalidField {
                field: "ors_reserve.normal_transaction_slots",
                reason: "must be greater than zero",
            });
        }
        if protected_transaction_slots == 0 {
            return Err(OrsReserveError::InvalidField {
                field: "ors_reserve.protected_transaction_slots",
                reason: "must be greater than zero",
            });
        }
        Ok(Self {
            inner: Arc::new(OrsReserveInner {
                transaction_normal_capacity: normal_transaction_slots,
                transaction_protected_capacity: protected_transaction_slots,
                durable_normal_capacity_bytes: normal_durable_bytes.get(),
                durable_protected_capacity_bytes: protected_durable_bytes.get(),
                transaction_normal_in_flight: AtomicU64::new(0),
                transaction_protected_in_flight: AtomicU64::new(0),
                durable_normal_in_flight_bytes: AtomicU64::new(0),
                durable_protected_in_flight_bytes: AtomicU64::new(0),
                restart_sealed: AtomicBool::new(false),
                sealed_epoch: Mutex::new(None),
            }),
        })
    }

    /// Returns the configured normal transaction-slot partition capacity.
    #[must_use]
    pub fn normal_transaction_capacity(&self) -> u64 {
        self.inner.transaction_normal_capacity
    }

    /// Returns the configured protected transaction-slot partition capacity.
    #[must_use]
    pub fn protected_transaction_capacity(&self) -> u64 {
        self.inner.transaction_protected_capacity
    }

    /// Returns the configured normal durable-byte partition capacity.
    #[must_use]
    pub fn normal_durable_byte_capacity(&self) -> u64 {
        self.inner.durable_normal_capacity_bytes
    }

    /// Returns the configured protected durable-byte partition capacity.
    #[must_use]
    pub fn protected_durable_byte_capacity(&self) -> u64 {
        self.inner.durable_protected_capacity_bytes
    }

    /// Returns the currently available normal transaction slots.
    #[must_use]
    pub fn available_normal_transactions(&self) -> u64 {
        self.inner.transaction_normal_capacity.saturating_sub(
            self.inner
                .transaction_normal_in_flight
                .load(Ordering::Acquire),
        )
    }

    /// Returns the currently available protected transaction slots.
    #[must_use]
    pub fn available_protected_transactions(&self) -> u64 {
        self.inner.transaction_protected_capacity.saturating_sub(
            self.inner
                .transaction_protected_in_flight
                .load(Ordering::Acquire),
        )
    }

    /// Returns the currently available normal durable bytes.
    #[must_use]
    pub fn available_normal_durable_bytes(&self) -> u64 {
        self.inner.durable_normal_capacity_bytes.saturating_sub(
            self.inner
                .durable_normal_in_flight_bytes
                .load(Ordering::Acquire),
        )
    }

    /// Returns the currently available protected durable bytes.
    #[must_use]
    pub fn available_protected_durable_bytes(&self) -> u64 {
        self.inner.durable_protected_capacity_bytes.saturating_sub(
            self.inner
                .durable_protected_in_flight_bytes
                .load(Ordering::Acquire),
        )
    }

    /// Returns whether the reserve is sealed after a restart.
    ///
    /// While sealed, every acquisition fails closed with its typed exhaustion
    /// disposition: unknown held capacity stays excluded until the epoch
    /// advances past the seal (see [`Self::unseal_after_epoch_advance`]).
    #[must_use]
    pub fn restart_sealed(&self) -> bool {
        self.inner.restart_sealed.load(Ordering::Acquire)
    }

    /// Seals the reserve at a restart boundary: restart never restores
    /// capacity by resetting a local counter.
    ///
    /// Every in-flight counter is pinned to its full partition capacity, so
    /// no new acquisition can succeed on the back of a zeroed counter, and
    /// the sealing epoch is recorded. Unknown held capacity stays excluded
    /// until [`Self::unseal_after_epoch_advance`] observes an advanced epoch
    /// (stale ownership fenced). The embedding owner calls this exactly once
    /// when it detects an unclean restart before admitting new work (STITCH).
    pub fn seal_after_restart(&self, epoch: AuthorityEpoch) {
        self.inner
            .transaction_normal_in_flight
            .fetch_max(self.inner.transaction_normal_capacity, Ordering::AcqRel);
        self.inner
            .transaction_protected_in_flight
            .fetch_max(self.inner.transaction_protected_capacity, Ordering::AcqRel);
        self.inner
            .durable_normal_in_flight_bytes
            .fetch_max(self.inner.durable_normal_capacity_bytes, Ordering::AcqRel);
        self.inner.durable_protected_in_flight_bytes.fetch_max(
            self.inner.durable_protected_capacity_bytes,
            Ordering::AcqRel,
        );
        *self
            .inner
            .sealed_epoch
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(epoch);
        self.inner.restart_sealed.store(true, Ordering::Release);
    }

    /// Reconciles the restart seal after the durable recovery epoch is
    /// established.
    ///
    /// Succeeds only when the current epoch has advanced past the sealing
    /// epoch: the advance fences the stale ownership, so the pinned counters
    /// can be released to zero and the seal lifted. Refuses otherwise, so
    /// held capacity is never restored while stale ownership is unfenced.
    /// The caller must have synchronized the front-door fence to the durable
    /// recovery epoch first (STITCH).
    ///
    /// # Errors
    ///
    /// Returns [`OrsReserveError::InvalidField`] when no restart seal is held,
    /// or when the epoch has not advanced past the seal.
    pub fn unseal_after_epoch_advance(
        &self,
        current: AuthorityEpoch,
    ) -> Result<(), OrsReserveError> {
        let mut sealed = self
            .inner
            .sealed_epoch
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        match *sealed {
            None => Err(OrsReserveError::InvalidField {
                field: "ors_reserve.restart_seal",
                reason: "no restart seal is held; nothing to reconcile",
            }),
            Some(sealed_epoch) if sealed_epoch == current => Err(OrsReserveError::InvalidField {
                field: "ors_reserve.restart_seal",
                reason: "epoch has not advanced; stale ownership is not fenced, held capacity stays excluded",
            }),
            Some(_) => {
                self.inner
                    .transaction_normal_in_flight
                    .store(0, Ordering::Release);
                self.inner
                    .transaction_protected_in_flight
                    .store(0, Ordering::Release);
                self.inner
                    .durable_normal_in_flight_bytes
                    .store(0, Ordering::Release);
                self.inner
                    .durable_protected_in_flight_bytes
                    .store(0, Ordering::Release);
                *sealed = None;
                self.inner.restart_sealed.store(false, Ordering::Release);
                Ok(())
            }
        }
    }

    /// Attempts to acquire one normal transaction slot without blocking.
    ///
    /// Only [`NormalWorkClass`] operations typecheck here, so protected ORS
    /// capacity is unreachable through this path by construction.
    ///
    /// # Errors
    ///
    /// Returns [`OrsReserveError::InvalidField`] for a blank owner/operation
    /// identity, or [`OrsReserveError::NormalCapacityExhausted`] naming the
    /// transaction bottleneck and shed work when the normal partition is
    /// saturated. The protected partition is untouched in every case.
    pub fn try_acquire_normal_transaction(
        &self,
        work: NormalWorkClass,
        owner: &str,
        operation_id: &str,
    ) -> Result<OrsPermit, OrsReserveError> {
        validate_text(owner, "ors_permit.owner").map_err(|_| OrsReserveError::InvalidField {
            field: "ors_permit.owner",
            reason: "must be non-blank",
        })?;
        validate_text(operation_id, "ors_permit.operation_id").map_err(|_| {
            OrsReserveError::InvalidField {
                field: "ors_permit.operation_id",
                reason: "must be non-blank",
            }
        })?;
        if self.inner.restart_sealed.load(Ordering::Acquire) {
            return Err(OrsReserveError::NormalCapacityExhausted {
                bottleneck: ORS_TRANSACTION_BOTTLENECK,
                work_class: work,
                operation_id: operation_id.to_owned(),
                owner: owner.to_owned(),
            });
        }
        if !cas_add(
            &self.inner.transaction_normal_in_flight,
            self.inner.transaction_normal_capacity,
            1,
        ) {
            return Err(OrsReserveError::NormalCapacityExhausted {
                bottleneck: ORS_TRANSACTION_BOTTLENECK,
                work_class: work,
                operation_id: operation_id.to_owned(),
                owner: owner.to_owned(),
            });
        }
        Ok(OrsPermit {
            inner: self.inner.clone(),
            dimension: OrsDimension::TransactionSlots,
            class: CapacityClass::NormalWorkload,
            amount: 1,
            operation: OrsPermitOperation::Normal(work),
            operation_id: operation_id.to_owned(),
            owner: owner.to_owned(),
        })
    }

    /// Attempts to acquire `bytes` normal durable bytes without blocking.
    ///
    /// Only [`NormalWorkClass`] operations typecheck here, so protected ORS
    /// durable capacity is unreachable through this path by construction.
    ///
    /// # Errors
    ///
    /// Returns [`OrsReserveError::InvalidField`] for a blank owner/operation
    /// identity, or [`OrsReserveError::NormalCapacityExhausted`] naming the
    /// durable-byte bottleneck and shed work when the normal partition cannot
    /// satisfy the request. The protected partition is untouched in every
    /// case.
    pub fn try_acquire_normal_durable_bytes(
        &self,
        work: NormalWorkClass,
        owner: &str,
        operation_id: &str,
        bytes: NonZeroU64,
    ) -> Result<OrsPermit, OrsReserveError> {
        validate_text(owner, "ors_permit.owner").map_err(|_| OrsReserveError::InvalidField {
            field: "ors_permit.owner",
            reason: "must be non-blank",
        })?;
        validate_text(operation_id, "ors_permit.operation_id").map_err(|_| {
            OrsReserveError::InvalidField {
                field: "ors_permit.operation_id",
                reason: "must be non-blank",
            }
        })?;
        if self.inner.restart_sealed.load(Ordering::Acquire) {
            return Err(OrsReserveError::NormalCapacityExhausted {
                bottleneck: ORS_DURABLE_BYTES_BOTTLENECK,
                work_class: work,
                operation_id: operation_id.to_owned(),
                owner: owner.to_owned(),
            });
        }
        if !cas_add(
            &self.inner.durable_normal_in_flight_bytes,
            self.inner.durable_normal_capacity_bytes,
            bytes.get(),
        ) {
            return Err(OrsReserveError::NormalCapacityExhausted {
                bottleneck: ORS_DURABLE_BYTES_BOTTLENECK,
                work_class: work,
                operation_id: operation_id.to_owned(),
                owner: owner.to_owned(),
            });
        }
        Ok(OrsPermit {
            inner: self.inner.clone(),
            dimension: OrsDimension::DurableQueueBytes,
            class: CapacityClass::NormalWorkload,
            amount: bytes.get(),
            operation: OrsPermitOperation::Normal(work),
            operation_id: operation_id.to_owned(),
            owner: owner.to_owned(),
        })
    }

    /// Attempts to acquire one protected transaction slot without blocking.
    ///
    /// Only [`ControlOperationClass`] operations typecheck here: a normal
    /// Store write, named read, agent admission or module job cannot name a
    /// protected operation and therefore cannot acquire this partition. This
    /// is the path an admitted cancellation/recovery record keeps while
    /// normal transaction work is saturated.
    ///
    /// # Errors
    ///
    /// Returns [`OrsReserveError::InvalidField`] for a blank owner/operation
    /// identity, or [`OrsReserveError::ProtectedReserveExhausted`] naming the
    /// transaction bottleneck, operation, owner and request when the
    /// protected partition is saturated.
    pub fn try_acquire_protected_transaction(
        &self,
        operation: ControlOperationClass,
        owner: &str,
        operation_id: &str,
    ) -> Result<OrsPermit, OrsReserveError> {
        validate_text(owner, "ors_permit.owner").map_err(|_| OrsReserveError::InvalidField {
            field: "ors_permit.owner",
            reason: "must be non-blank",
        })?;
        validate_text(operation_id, "ors_permit.operation_id").map_err(|_| {
            OrsReserveError::InvalidField {
                field: "ors_permit.operation_id",
                reason: "must be non-blank",
            }
        })?;
        if self.inner.restart_sealed.load(Ordering::Acquire) {
            return Err(OrsReserveError::ProtectedReserveExhausted {
                bottleneck: ORS_TRANSACTION_BOTTLENECK,
                operation,
                operation_id: operation_id.to_owned(),
                owner: owner.to_owned(),
            });
        }
        if !cas_add(
            &self.inner.transaction_protected_in_flight,
            self.inner.transaction_protected_capacity,
            1,
        ) {
            return Err(OrsReserveError::ProtectedReserveExhausted {
                bottleneck: ORS_TRANSACTION_BOTTLENECK,
                operation,
                operation_id: operation_id.to_owned(),
                owner: owner.to_owned(),
            });
        }
        Ok(OrsPermit {
            inner: self.inner.clone(),
            dimension: OrsDimension::TransactionSlots,
            class: CapacityClass::ProtectedControl,
            amount: 1,
            operation: OrsPermitOperation::Protected(operation),
            operation_id: operation_id.to_owned(),
            owner: owner.to_owned(),
        })
    }

    /// Attempts to acquire `bytes` protected durable bytes without blocking.
    ///
    /// Only [`ControlOperationClass`] operations typecheck here. This is the
    /// path an admitted cancellation/recovery record keeps while normal
    /// durable-byte work reports `STORAGE_BACKPRESSURE`.
    ///
    /// # Errors
    ///
    /// Returns [`OrsReserveError::InvalidField`] for a blank owner/operation
    /// identity, or [`OrsReserveError::ProtectedReserveExhausted`] naming the
    /// durable-byte bottleneck, operation, owner and request when the
    /// protected partition cannot satisfy the request.
    pub fn try_acquire_protected_durable_bytes(
        &self,
        operation: ControlOperationClass,
        owner: &str,
        operation_id: &str,
        bytes: NonZeroU64,
    ) -> Result<OrsPermit, OrsReserveError> {
        validate_text(owner, "ors_permit.owner").map_err(|_| OrsReserveError::InvalidField {
            field: "ors_permit.owner",
            reason: "must be non-blank",
        })?;
        validate_text(operation_id, "ors_permit.operation_id").map_err(|_| {
            OrsReserveError::InvalidField {
                field: "ors_permit.operation_id",
                reason: "must be non-blank",
            }
        })?;
        if self.inner.restart_sealed.load(Ordering::Acquire) {
            return Err(OrsReserveError::ProtectedReserveExhausted {
                bottleneck: ORS_DURABLE_BYTES_BOTTLENECK,
                operation,
                operation_id: operation_id.to_owned(),
                owner: owner.to_owned(),
            });
        }
        if !cas_add(
            &self.inner.durable_protected_in_flight_bytes,
            self.inner.durable_protected_capacity_bytes,
            bytes.get(),
        ) {
            return Err(OrsReserveError::ProtectedReserveExhausted {
                bottleneck: ORS_DURABLE_BYTES_BOTTLENECK,
                operation,
                operation_id: operation_id.to_owned(),
                owner: owner.to_owned(),
            });
        }
        Ok(OrsPermit {
            inner: self.inner.clone(),
            dimension: OrsDimension::DurableQueueBytes,
            class: CapacityClass::ProtectedControl,
            amount: bytes.get(),
            operation: OrsPermitOperation::Protected(operation),
            operation_id: operation_id.to_owned(),
            owner: owner.to_owned(),
        })
    }

    /// Reports exhausted normal durable bytes as a `STORAGE_BACKPRESSURE`
    /// response naming exactly [`ORS_DURABLE_BYTES_BOTTLENECK`].
    ///
    /// The response is built only while the normal durable partition cannot
    /// satisfy `requested_bytes`: pressure evidence is never manufactured for
    /// a partition that still admits the request. The protected partition is
    /// not read and not claimed, so an admitted cancellation/recovery record
    /// keeps its path while this response is live.
    ///
    /// # Errors
    ///
    /// Returns [`OrsReserveError::InvalidField`] when the normal durable
    /// partition still satisfies the request or the operation identity is
    /// malformed, or [`OrsReserveError::Contract`] when the assembled
    /// directive fails the existing contract validation.
    pub fn normal_durable_exhaustion_response(
        &self,
        work: NormalWorkClass,
        operation_id: &str,
        profile_revision: ArtifactId,
        requested_bytes: NonZeroU64,
    ) -> Result<I14BackpressureResponseV1, OrsReserveError> {
        let available = self.available_normal_durable_bytes();
        if available >= requested_bytes.get() {
            return Err(OrsReserveError::InvalidField {
                field: "ors_reserve.normal_durable_bytes",
                reason: "normal durable partition still admits the request; no pressure evidence to report",
            });
        }
        let operation =
            OperationId::new(operation_id).map_err(|_| OrsReserveError::InvalidField {
                field: "ors_rejection.operation_id",
                reason: "must be a bounded non-blank reference",
            })?;
        OrsRejectionParts {
            affected: AffectedOperationClass::Normal(work),
            observation: BottleneckObservationV1 {
                bottleneck: ORS_DURABLE_BYTES_BOTTLENECK,
                unit: ORS_DURABLE_BYTES_BOTTLENECK.unit(),
                requested_amount: requested_bytes.get(),
                availability: BottleneckAvailability::Exhausted {
                    available_amount: available,
                },
                coverage_state: BottleneckCoverageState::Claimed,
            },
            operation_id: Some(operation),
            profile_revision,
        }
        .into_response(
            BackpressureDisposition::StorageBackpressure,
            I14WorkOutcome::NotAccepted,
            RecoveryCommitStatus::None,
        )
    }

    /// Reports exhausted normal transaction slots as a `BUSY` response naming
    /// exactly [`ORS_TRANSACTION_BOTTLENECK`].
    ///
    /// The response is built only while [`Self::available_normal_transactions`]
    /// is zero: pressure evidence is never manufactured for a partition that
    /// still admits work. The protected partition is not read and not
    /// claimed.
    ///
    /// # Errors
    ///
    /// Returns [`OrsReserveError::InvalidField`] when normal transaction
    /// capacity remains or the operation identity is malformed, or
    /// [`OrsReserveError::Contract`] when the assembled directive fails the
    /// existing contract validation.
    pub fn normal_transaction_exhaustion_response(
        &self,
        work: NormalWorkClass,
        operation_id: &str,
        profile_revision: ArtifactId,
    ) -> Result<I14BackpressureResponseV1, OrsReserveError> {
        if self.available_normal_transactions() > 0 {
            return Err(OrsReserveError::InvalidField {
                field: "ors_reserve.normal_transaction_slots",
                reason: "normal transaction partition is not saturated; no pressure evidence to report",
            });
        }
        let operation =
            OperationId::new(operation_id).map_err(|_| OrsReserveError::InvalidField {
                field: "ors_rejection.operation_id",
                reason: "must be a bounded non-blank reference",
            })?;
        OrsRejectionParts {
            affected: AffectedOperationClass::Normal(work),
            observation: BottleneckObservationV1 {
                bottleneck: ORS_TRANSACTION_BOTTLENECK,
                unit: ORS_TRANSACTION_BOTTLENECK.unit(),
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

    /// Publishes the live partition evidence for one ORS dimension as a
    /// claimed [`BottleneckCapacityProfile`] row.
    ///
    /// The row names the frozen owner the contract binds to this dimension,
    /// the exact bottleneck unit, the physical total and the disjoint normal
    /// and protected partitions read from this reserve. There is no emergency
    /// partition here, so none is claimed. The owner generation, proof
    /// profile, evidence and invalidation references are composition-supplied
    /// metadata echoed into the row; the Kernel composition wraps this row in
    /// its own evidence record with the configuration snapshot and Authority
    /// Epoch it resolved.
    ///
    /// # Errors
    ///
    /// Returns [`OrsReserveError::InvalidField`] for a blank metadata
    /// reference or when the partition accounting cannot be represented, or
    /// [`OrsReserveError::Contract`] when the assembled row fails the
    /// existing contract validation.
    pub fn publish_claimed_row(
        &self,
        dimension: OrsDimension,
        owner_generation_ref: &str,
        proof_profile_ref: &str,
        evidence_ref: &str,
        invalidation_ref: &str,
    ) -> Result<BottleneckCapacityProfile, OrsReserveError> {
        for (value, field) in [
            (owner_generation_ref, "ors_evidence.owner_generation_ref"),
            (proof_profile_ref, "ors_evidence.proof_profile_ref"),
            (evidence_ref, "ors_evidence.evidence_ref"),
            (invalidation_ref, "ors_evidence.invalidation_ref"),
        ] {
            validate_text(value, field).map_err(|_| OrsReserveError::InvalidField {
                field,
                reason: "must be non-blank",
            })?;
        }
        let bottleneck = dimension.bottleneck();
        let bound = frozen_bottleneck_owner_map()
            .into_iter()
            .find(|bound| bound.bottleneck == bottleneck)
            .ok_or(OrsReserveError::InvalidField {
                field: "ors_evidence.bottleneck",
                reason: "the frozen owner map binds no owner to this ORS dimension",
            })?;
        let (normal_capacity, protected_capacity) = match dimension {
            OrsDimension::TransactionSlots => (
                self.inner.transaction_normal_capacity,
                self.inner.transaction_protected_capacity,
            ),
            OrsDimension::DurableQueueBytes => (
                self.inner.durable_normal_capacity_bytes,
                self.inner.durable_protected_capacity_bytes,
            ),
        };
        let physical_total = normal_capacity
            .checked_add(protected_capacity)
            .and_then(NonZeroU64::new)
            .ok_or(OrsReserveError::InvalidField {
                field: "ors_evidence.physical_total_limit",
                reason: "the disjoint partition sum is not a positive capacity",
            })?;
        let unit = bottleneck.unit();
        let limit = |quantity: u64| {
            NonZeroU64::new(quantity)
                .map(|quantity| CapacityLimit { unit, quantity })
                .ok_or(OrsReserveError::InvalidField {
                    field: "ors_evidence.partition_limit",
                    reason: "a claimed partition is not a positive capacity",
                })
        };
        let row = BottleneckCapacityProfile {
            bottleneck,
            coverage_state: BottleneckCoverageState::Claimed,
            owner_ref: bound.owner.to_owned(),
            owner_generation_ref: owner_generation_ref.to_owned(),
            unit,
            physical_total_limit: Some(CapacityLimit {
                unit,
                quantity: physical_total,
            }),
            normal_work_applicable: true,
            normal_limit: Some(limit(normal_capacity)?),
            protected_limit: Some(limit(protected_capacity)?),
            emergency_limit: None,
            enforcement: Some(CapacityEnforcement::ConfigurationPartition),
            proof_profile_ref: proof_profile_ref.to_owned(),
            evidence_refs: vec![evidence_ref.to_owned()],
            invalidation_set: vec![invalidation_ref.to_owned()],
        };
        row.validate()
            .map_err(|error| OrsReserveError::Contract(error.to_string()))?;
        Ok(row)
    }

    /// Reports durably staged ORS work as an `ACCEPTED_PENDING` response.
    ///
    /// `ACCEPTED_PENDING` is emitted only for a durably staged identity: the
    /// caller presents the stage receipt the ORS durable staging path minted
    /// for `operation_id` with `staged_bytes` durably held, and the response
    /// carries that receipt as its staged evidence with a poll/reconcile
    /// instruction under the operation's own authority. Possible
    /// commit/effect never authorizes blind retry: the directive forbids
    /// [`I14ForbiddenAction::BlindRetryAfterPossibleEffect`] and resolves to
    /// [`I14ResolutionState::AwaitingReconciliation`], never to safe retry.
    /// The bottleneck observation is the live normal durable partition read at
    /// call time, so the response reports owner-observed evidence rather than
    /// a manufactured claim.
    ///
    /// This constructor validates the receipt shape and the assembled
    /// directive with the existing contract check; it never stages work
    /// itself. The composition wires the receipt from the real durable
    /// staging path (STITCH).
    ///
    /// # Errors
    ///
    /// Returns [`OrsReserveError::InvalidField`] when the operation identity
    /// or stage receipt is malformed, or [`OrsReserveError::Contract`] when
    /// the assembled directive fails the existing contract validation.
    pub fn durable_stage_pending_response(
        &self,
        work: NormalWorkClass,
        operation_id: &str,
        stage_receipt: &str,
        staged_bytes: NonZeroU64,
        profile_revision: ArtifactId,
    ) -> Result<I14BackpressureResponseV1, OrsReserveError> {
        let operation =
            OperationId::new(operation_id).map_err(|_| OrsReserveError::InvalidField {
                field: "ors_staged.operation_id",
                reason: "must be a bounded non-blank reference",
            })?;
        let receipt = ReceiptId::new(stage_receipt).map_err(|_| OrsReserveError::InvalidField {
            field: "ors_staged.stage_receipt",
            reason: "must be a bounded non-blank reference",
        })?;
        let available = self.available_normal_durable_bytes();
        let availability = if available >= staged_bytes.get() {
            BottleneckAvailability::Available {
                available_amount: available,
            }
        } else {
            BottleneckAvailability::Exhausted {
                available_amount: available,
            }
        };
        let response = I14BackpressureResponseV1 {
            contract_version: I14_BACKPRESSURE_RESPONSE_VERSION,
            disposition: BackpressureDisposition::AcceptedPending,
            directive: I14RecoveryDirectiveV1 {
                cause: I14BackpressureCause::DurableStagePending,
                affected_operation_class: AffectedOperationClass::Normal(work),
                bottlenecks: vec![BottleneckObservationV1 {
                    bottleneck: ORS_DURABLE_BYTES_BOTTLENECK,
                    unit: ORS_DURABLE_BYTES_BOTTLENECK.unit(),
                    requested_amount: staged_bytes.get(),
                    availability,
                    coverage_state: BottleneckCoverageState::Claimed,
                }],
                work_outcome: I14WorkOutcome::Staged,
                commit_status: RecoveryCommitStatus::Staged,
                state_preservation: StatePreservationStatus::Preserved,
                operation_id: Some(operation),
                preserve_operation_id: true,
                stage_receipt: Some(receipt.clone()),
                rollback_receipt: None,
                retry_strategy: I14RecoveryAction::PollOperation,
                earliest_permitted_condition: EarliestRecoveryCondition::NoWaitRequired,
                earliest_permitted_unix_millis: None,
                actions_temporarily_forbidden: vec![
                    I14ForbiddenAction::BlindRetryAfterPossibleEffect,
                ],
                safe_fallback: None,
                required_authority: I14RequiredAuthority::ExistingOperationAuthority,
                human_action_required: HumanActionRequirement::NoneRequired,
                evidence_refs: vec![receipt],
                evidence_coverage: EvidenceCoverageState::Partial,
                escalation_condition: I14EscalationCondition::None,
                resolution_state: I14ResolutionState::AwaitingReconciliation,
                currentness: I14CurrentnessState::Current,
                profile_revision,
                state_fence: None,
                authority_epoch: None,
            },
        };
        response
            .validate()
            .map_err(|error| OrsReserveError::Contract(error.to_string()))?;
        Ok(response)
    }
}

/// Exact parts of one ORS rejection directive shared by every constructor.
struct OrsRejectionParts {
    affected: AffectedOperationClass,
    observation: BottleneckObservationV1,
    operation_id: Option<OperationId>,
    profile_revision: ArtifactId,
}

impl OrsRejectionParts {
    /// Assembles the versioned response and validates it with the existing
    /// contract check; an inconsistent observation fails closed here.
    fn into_response(
        self,
        disposition: BackpressureDisposition,
        work_outcome: I14WorkOutcome,
        commit_status: RecoveryCommitStatus,
    ) -> Result<I14BackpressureResponseV1, OrsReserveError> {
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
            .map_err(|error| OrsReserveError::Contract(error.to_string()))?;
        Ok(response)
    }
}
