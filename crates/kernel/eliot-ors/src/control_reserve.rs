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
//! W4 ORS wave: every [`OrsPermit`] is owner-issued non-clone evidence bound
//! to capacity class, bottleneck/unit/granted amount, typed operation,
//! operation identity, owner and the typed [`AuthorityEpoch`] observed at
//! acquisition, mirroring the front-door [`ControlPermit`] evidence grade.
//! Every denial names the exact bottleneck, shed work and observed epoch. A
//! stale epoch, changed operation or changed owner fails before consumption
//! because the evidence no longer matches the current owner state; there is
//! no epoch-blind permit to replay.
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
//! This module has no production caller yet (STITCH): it publishes the owner
//! evidence the Kernel profile composition joins via
//! [`OrsReserve::publish_owner_rows`] and the kernel-core
//! `join_ors_owner_evidence` composition step. There is no emergency
//! partition here; recording reserve loss stays with the front-door
//! last-resort slot until a later wave wires ORS-side loss reporting.
//! Restart reconciliation (W5) stays with the ORS recovery-journal owner:
//! permits carry the operation identity, owner and epoch the reconciler
//! needs, but this module holds no durable permit ledger and never
//! reconstitutes capacity from a reset counter.
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
        "ORS normal capacity exhausted for {bottleneck:?}: work {work_class:?} operation {operation_id} owned by {owner} epoch {epoch:?}"
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
        "ORS protected reserve exhausted for {bottleneck:?}: control operation {operation:?} operation {operation_id} owned by {owner} epoch {epoch:?}"
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

/// Composition-resolved reference strings the ORS owner binds into its
/// published capacity rows but cannot observe itself.
///
/// The owner supplies every quantity in the row from the live reserve: the
/// frozen bottleneck and unit, the disjoint normal/protected partition limits
/// and their physical total, and the [`CapacityEnforcement::PhysicalPartition`]
/// mechanism those partitions are held under. The composition supplies the
/// references that identify the observation: its own owner-generation
/// reference for the ORS owner, the independent proof-profile reference, and
/// the current evidence and invalidation references. Both halves are required:
/// [`OrsReserve::publish_owner_rows`] fails closed through the existing
/// [`BottleneckCapacityProfile::validate`] when any reference is missing or
/// non-canonical, so the composition must resolve canonical (strictly
/// ascending, duplicate-free) reference sets rather than have them defaulted
/// or sorted here.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OrsOwnerEvidenceContext {
    /// Owner generation/revision reference for the Kernel ORS owner.
    pub owner_generation_ref: String,
    /// Independent proof-profile reference produced for the ORS dimensions.
    pub proof_profile_ref: String,
    /// Current owner evidence references supporting the published rows.
    pub evidence_refs: Vec<String>,
    /// Exact invalidation set of the published rows.
    pub invalidation_set: Vec<String>,
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

/// One held ORS capacity permit, bound to dimension, class, operation, owner
/// and Authority Epoch. Releasing is automatic on drop and returns exactly
/// the consumed partition and amount.
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
    epoch: AuthorityEpoch,
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

    /// Returns the Authority Epoch bound at acquisition.
    #[must_use]
    pub const fn epoch(&self) -> AuthorityEpoch {
        self.epoch
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

    /// Attempts to acquire one normal transaction slot without blocking.
    ///
    /// Only [`NormalWorkClass`] operations typecheck here, so protected ORS
    /// capacity is unreachable through this path by construction. The granted
    /// permit binds `epoch`; a caller presenting it under a different epoch
    /// holds evidence that no longer matches the current owner state.
    ///
    /// # Errors
    ///
    /// Returns [`OrsReserveError::InvalidField`] for a blank owner/operation
    /// identity, or [`OrsReserveError::NormalCapacityExhausted`] naming the
    /// transaction bottleneck, shed work and observed epoch when the normal
    /// partition is saturated. The protected partition is untouched in every
    /// case.
    pub fn try_acquire_normal_transaction(
        &self,
        work: NormalWorkClass,
        owner: &str,
        operation_id: &str,
        epoch: AuthorityEpoch,
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
                epoch,
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
            epoch,
        })
    }

    /// Attempts to acquire `bytes` normal durable bytes without blocking.
    ///
    /// Only [`NormalWorkClass`] operations typecheck here, so protected ORS
    /// durable capacity is unreachable through this path by construction. The
    /// granted permit binds `epoch`; a caller presenting it under a different
    /// epoch holds evidence that no longer matches the current owner state.
    ///
    /// # Errors
    ///
    /// Returns [`OrsReserveError::InvalidField`] for a blank owner/operation
    /// identity, or [`OrsReserveError::NormalCapacityExhausted`] naming the
    /// durable-byte bottleneck, shed work and observed epoch when the normal
    /// partition cannot satisfy the request. The protected partition is
    /// untouched in every case.
    pub fn try_acquire_normal_durable_bytes(
        &self,
        work: NormalWorkClass,
        owner: &str,
        operation_id: &str,
        bytes: NonZeroU64,
        epoch: AuthorityEpoch,
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
                epoch,
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
            epoch,
        })
    }

    /// Attempts to acquire one protected transaction slot without blocking.
    ///
    /// Only [`ControlOperationClass`] operations typecheck here: a normal
    /// Store write, named read, agent admission or module job cannot name a
    /// protected operation and therefore cannot acquire this partition. This
    /// is the path an admitted cancellation/recovery record keeps while
    /// normal transaction work is saturated. The granted permit binds `epoch`
    /// so the recovery record proves it was admitted under the current owner
    /// state.
    ///
    /// # Errors
    ///
    /// Returns [`OrsReserveError::InvalidField`] for a blank owner/operation
    /// identity, or [`OrsReserveError::ProtectedReserveExhausted`] naming the
    /// transaction bottleneck, operation, owner, request and observed epoch
    /// when the protected partition is saturated.
    pub fn try_acquire_protected_transaction(
        &self,
        operation: ControlOperationClass,
        owner: &str,
        operation_id: &str,
        epoch: AuthorityEpoch,
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
                epoch,
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
            epoch,
        })
    }

    /// Attempts to acquire `bytes` protected durable bytes without blocking.
    ///
    /// Only [`ControlOperationClass`] operations typecheck here. This is the
    /// path an admitted cancellation/recovery record keeps while normal
    /// durable-byte work reports `STORAGE_BACKPRESSURE`. The granted permit
    /// binds `epoch` so the recovery record proves it was admitted under the
    /// current owner state.
    ///
    /// # Errors
    ///
    /// Returns [`OrsReserveError::InvalidField`] for a blank owner/operation
    /// identity, or [`OrsReserveError::ProtectedReserveExhausted`] naming the
    /// durable-byte bottleneck, operation, owner, request and observed epoch
    /// when the protected partition cannot satisfy the request.
    pub fn try_acquire_protected_durable_bytes(
        &self,
        operation: ControlOperationClass,
        owner: &str,
        operation_id: &str,
        bytes: NonZeroU64,
        epoch: AuthorityEpoch,
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
                epoch,
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
            epoch,
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

    /// Publishes the two owner-produced capacity rows for the frozen ORS
    /// dimensions: transaction slots and durable queue bytes.
    ///
    /// Every quantity is read from this reserve: the frozen bottleneck and
    /// unit, the configured disjoint normal/protected partition limits and
    /// their physical total, and the [`CapacityEnforcement::PhysicalPartition`]
    /// mechanism those partitions are held under. The published limits are the
    /// configured partition capacities, not the currently available remainder:
    /// availability moves as permits are acquired and released, while the
    /// guarantee the profile records is the partition itself. No emergency
    /// partition is claimed here because the ORS owner holds none; the
    /// preallocated last-resort slot stays with the Kernel front-door owner.
    /// The composition-resolved references come from `ctx` unchanged.
    ///
    /// Each row is checked by the existing
    /// [`BottleneckCapacityProfile::validate`] before it is returned, so a
    /// missing owner, generation, physical total, protected partition,
    /// enforcement, proof, evidence or invalidation reference fails here
    /// rather than publishing a row the Kernel composition would have to
    /// lower to `UNKNOWN`.
    ///
    /// # Errors
    ///
    /// Returns [`OrsReserveError::Contract`] when the frozen owner map binds
    /// no owner to an ORS dimension, when the configured partition capacities
    /// cannot form a positive physical total, or when either assembled row
    /// fails the existing contract validation.
    pub fn publish_owner_rows(
        &self,
        ctx: &OrsOwnerEvidenceContext,
    ) -> Result<[BottleneckCapacityProfile; 2], OrsReserveError> {
        let transaction = owner_capacity_row(
            ORS_TRANSACTION_BOTTLENECK,
            self.inner.transaction_normal_capacity,
            self.inner.transaction_protected_capacity,
            ctx,
        )?;
        let durable = owner_capacity_row(
            ORS_DURABLE_BYTES_BOTTLENECK,
            self.inner.durable_normal_capacity_bytes,
            self.inner.durable_protected_capacity_bytes,
            ctx,
        )?;
        Ok([transaction, durable])
    }
}

/// Builds one claimed owner row for an ORS dimension from the reserve's
/// configured partition capacities and the composition-resolved references.
///
/// The owner reference is read from the frozen owner map, never restated here;
/// the unit is the bottleneck's own declared unit. The physical total is
/// exactly the sum of the two disjoint partitions, so the existing partition
/// accounting check always bounds them. A zero partition capacity or a missing
/// frozen owner fails closed: the reserve constructor already refuses zero
/// partitions, and a dimension without a frozen owner has no claim to publish.
fn owner_capacity_row(
    bottleneck: CapacityBottleneck,
    normal_capacity: u64,
    protected_capacity: u64,
    ctx: &OrsOwnerEvidenceContext,
) -> Result<BottleneckCapacityProfile, OrsReserveError> {
    let owner = frozen_bottleneck_owner_map()
        .into_iter()
        .find(|bound| bound.bottleneck == bottleneck)
        .map(|bound| bound.owner)
        .ok_or_else(|| {
            OrsReserveError::Contract(format!(
                "frozen owner map binds no owner to {bottleneck:?}; no ORS row to publish"
            ))
        })?;
    let unit = bottleneck.unit();
    let limit = |field: &'static str, amount: u64| {
        NonZeroU64::new(amount)
            .map(|quantity| CapacityLimit { unit, quantity })
            .ok_or(OrsReserveError::InvalidField {
                field,
                reason: "partition capacity must be greater than zero",
            })
    };
    let normal_limit = limit("ors_reserve.normal_limit", normal_capacity)?;
    let protected_limit = limit("ors_reserve.protected_limit", protected_capacity)?;
    let physical_total =
        normal_capacity
            .checked_add(protected_capacity)
            .ok_or(OrsReserveError::InvalidField {
                field: "ors_reserve.physical_total_limit",
                reason: "disjoint partition capacities overflow the physical total",
            })?;
    let physical_total_limit =
        NonZeroU64::new(physical_total).ok_or(OrsReserveError::InvalidField {
            field: "ors_reserve.physical_total_limit",
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
        enforcement: Some(CapacityEnforcement::PhysicalPartition),
        proof_profile_ref: ctx.proof_profile_ref.clone(),
        evidence_refs: ctx.evidence_refs.clone(),
        invalidation_set: ctx.invalidation_set.clone(),
    };
    row.validate()
        .map_err(|error| OrsReserveError::Contract(error.to_string()))?;
    Ok(row)
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

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;
    use std::num::NonZeroU64;

    /// Saturating the single normal transaction slot leaves the protected
    /// partition untouched (issue #1679). The positive control comes FIRST and
    /// its permit is held across the assertions: a reserve that refused
    /// everything would also refuse normal work, so only an admitted
    /// cancellation proves the protected slot is genuinely still available
    /// while ordinary work is being shed. The shedding refusal then names the
    /// exact bottleneck, so exhaustion of one dimension is never reported as
    /// global exhaustion.
    #[test]
    fn ors_normal_transaction_saturation_leaves_protected_slot_available() {
        let reserve = OrsReserve::partitioned(
            1,
            2,
            NonZeroU64::new(8).expect("bytes"),
            NonZeroU64::new(8).expect("bytes"),
        )
        .expect("reserve");
        let epoch = AuthorityEpoch::new(1).expect("epoch");

        // Held for the whole test: the permit releases on drop.
        let _held = reserve
            .try_acquire_normal_transaction(
                NormalWorkClass::CanonicalWrite,
                "owner-a",
                "op-tx-fill-1",
                epoch,
            )
            .expect("first slot");

        // Positive control, also held: the admitted cancellation keeps its
        // slot while the normal partition is saturated.
        let _ctl = reserve
            .try_acquire_protected_transaction(
                ControlOperationClass::CancelOperation,
                "owner-a",
                "op-tx-ctl-1",
                epoch,
            )
            .expect("protected path stays open");
        assert_eq!(reserve.available_protected_transactions(), 1);

        let err = reserve
            .try_acquire_normal_transaction(
                NormalWorkClass::CanonicalWrite,
                "owner-a",
                "op-tx-shed-1",
                epoch,
            )
            .expect_err("saturated normal partition must refuse");
        assert!(
            matches!(err, OrsReserveError::NormalCapacityExhausted { bottleneck, .. } if bottleneck == ORS_TRANSACTION_BOTTLENECK)
        );
    }

    /// The durable-byte face of the same property (issue #1679): saturating the
    /// normal durable-byte partition leaves the protected byte partition
    /// untouched, so an admitted cancellation keeps its recovery lane while
    /// ordinary work is shed naming exactly `ORS_DURABLE_BYTES_BOTTLENECK`.
    /// Exhaustion of one dimension is therefore never reported as global
    /// exhaustion, and normal work never borrows the reserve.
    #[test]
    fn ors_normal_durable_saturation_leaves_protected_bytes_available() {
        let reserve = OrsReserve::partitioned(
            4,
            4,
            NonZeroU64::new(2).expect("bytes"),
            NonZeroU64::new(4).expect("bytes"),
        )
        .expect("reserve");
        let epoch = AuthorityEpoch::new(1).expect("epoch");

        // Held for the whole test: the permit releases on drop.
        let _held = reserve
            .try_acquire_normal_durable_bytes(
                NormalWorkClass::CanonicalWrite,
                "owner-a",
                "op-bytes-fill-1",
                NonZeroU64::new(2).expect("bytes"),
                epoch,
            )
            .expect("normal bytes");

        // Positive control, also held: the admitted cancellation keeps its
        // protected byte path while the normal partition is saturated.
        let _ctl = reserve
            .try_acquire_protected_durable_bytes(
                ControlOperationClass::CancelOperation,
                "owner-a",
                "op-bytes-ctl-1",
                NonZeroU64::new(1).expect("bytes"),
                epoch,
            )
            .expect("protected path stays open");
        assert_eq!(reserve.available_protected_durable_bytes(), 3);

        let err = reserve
            .try_acquire_normal_durable_bytes(
                NormalWorkClass::CanonicalWrite,
                "owner-a",
                "op-bytes-shed-1",
                NonZeroU64::new(1).expect("bytes"),
                epoch,
            )
            .expect_err("saturated normal bytes must refuse");
        assert!(
            matches!(err, OrsReserveError::NormalCapacityExhausted { bottleneck, .. } if bottleneck == ORS_DURABLE_BYTES_BOTTLENECK)
        );
    }

    /// The reporting face of the same property (issue #1679):
    /// `normal_durable_exhaustion_response` must never manufacture a
    /// `STORAGE_BACKPRESSURE` response for a durable partition that still
    /// admits the request. A response that names an exhausted resource while
    /// durable staging is available would be false pressure evidence, so the
    /// admitting partition is refused instead.
    #[test]
    fn ors_durable_exhaustion_response_refuses_an_admitting_partition() {
        let reserve = OrsReserve::partitioned(
            4,
            4,
            NonZeroU64::new(8).expect("bytes"),
            NonZeroU64::new(8).expect("bytes"),
        )
        .expect("reserve");
        assert_eq!(reserve.available_normal_durable_bytes(), 8);

        let err = reserve
            .normal_durable_exhaustion_response(
                NormalWorkClass::CanonicalWrite,
                "op-bytes-admitting-1",
                eliot_contracts::ArtifactId::new("profile-rev-1").expect("valid artifact id"),
                NonZeroU64::new(1).expect("bytes"),
            )
            .expect_err("an admitting partition must not produce pressure evidence");
        assert!(matches!(
            err,
            OrsReserveError::InvalidField {
                field: "ors_reserve.normal_durable_bytes",
                ..
            }
        ));
    }

    /// The positive complement of
    /// `ors_durable_exhaustion_response_refuses_an_admitting_partition`: that
    /// test pins no-manufactured-pressure while durable staging is available,
    /// this one pins that a truly saturated normal durable partition yields a
    /// real `STORAGE_BACKPRESSURE` report naming the durable-byte bottleneck.
    #[test]
    fn ors_durable_exhaustion_response_reports_live_saturation() {
        let reserve = OrsReserve::partitioned(
            4,
            4,
            NonZeroU64::new(2).expect("bytes"),
            NonZeroU64::new(4).expect("bytes"),
        )
        .expect("reserve");
        let epoch = AuthorityEpoch::new(1).expect("epoch");

        // Held for the whole test: the permit releases on drop, and the report
        // below must observe the live saturated partition.
        let _held = reserve
            .try_acquire_normal_durable_bytes(
                NormalWorkClass::CanonicalWrite,
                "owner-a",
                "op-bytes-fill-2",
                NonZeroU64::new(2).expect("bytes"),
                epoch,
            )
            .expect("normal bytes");
        assert_eq!(reserve.available_normal_durable_bytes(), 0);

        let response = reserve
            .normal_durable_exhaustion_response(
                NormalWorkClass::CanonicalWrite,
                "op-bytes-report-1",
                eliot_contracts::ArtifactId::new("profile-rev-1").expect("valid artifact id"),
                NonZeroU64::new(1).expect("bytes"),
            )
            .expect("live saturation must report");
        assert!(matches!(
            response.disposition,
            BackpressureDisposition::StorageBackpressure
        ));
    }

    /// The W1 per-owner rows for ORS (issue #1679): the owner publishes live,
    /// validated rows for BOTH its dimensions, naming exactly
    /// `ORS_TRANSACTION_BOTTLENECK` then `ORS_DURABLE_BYTES_BOTTLENECK` with
    /// the frozen-map owners, so the Kernel profile composition joins real owner
    /// evidence. Per I14.3 there is one row per bottleneck in the frozen owner
    /// binding and no borrowed capacity, so each row is checked against the
    /// frozen map rather than a hard-coded owner: a hard-coded owner would only
    /// prove the test agrees with itself.
    #[test]
    fn ors_publish_owner_rows_name_both_frozen_dimensions() {
        let reserve = OrsReserve::partitioned(
            4,
            4,
            NonZeroU64::new(2).expect("bytes"),
            NonZeroU64::new(4).expect("bytes"),
        )
        .expect("reserve");

        let ctx = OrsOwnerEvidenceContext {
            owner_generation_ref: "gen-7".to_owned(),
            proof_profile_ref: "proof-ors-1".to_owned(),
            evidence_refs: vec!["ev-ors-1".to_owned()],
            invalidation_set: vec!["inv-ors-1".to_owned()],
        };
        let rows = reserve.publish_owner_rows(&ctx).expect("owner rows");

        // The constructor returns transaction first, durable second.
        assert_eq!(rows[0].bottleneck, ORS_TRANSACTION_BOTTLENECK);
        assert_eq!(rows[1].bottleneck, ORS_DURABLE_BYTES_BOTTLENECK);
        assert!(
            rows.iter()
                .all(|row| row.coverage_state == BottleneckCoverageState::Claimed)
        );

        for row in &rows {
            let bound = frozen_bottleneck_owner_map()
                .into_iter()
                .find(|b| b.bottleneck == row.bottleneck)
                .expect("frozen ors owner");
            assert_eq!(row.owner_ref, bound.owner);
        }
    }

    /// A claimed row must name one runtime owner AND one owner generation
    /// (norm I14.3), so a blank `owner_generation_ref` must be refused at
    /// publication rather than publishing an unaccountable claimed row:
    /// `publish_owner_rows` funnels every row through the shared
    /// `row.validate()` contract check, and a claimed row without an owner
    /// generation is not valid.
    #[test]
    fn ors_publish_owner_rows_rejects_blank_generation() {
        let reserve = OrsReserve::partitioned(
            4,
            4,
            NonZeroU64::new(2).expect("bytes"),
            NonZeroU64::new(4).expect("bytes"),
        )
        .expect("reserve");

        let ctx = OrsOwnerEvidenceContext {
            owner_generation_ref: String::new(),
            proof_profile_ref: "proof-ors-1".to_owned(),
            evidence_refs: vec!["ev-ors-1".to_owned()],
            invalidation_set: vec!["inv-ors-1".to_owned()],
        };
        let err = reserve
            .publish_owner_rows(&ctx)
            .expect_err("blank generation must never publish a row");
        assert!(matches!(err, OrsReserveError::Contract(_)));
    }

    /// The transaction dimension of issue #1679: the same fail-closed property
    /// as the durable face, applied to the slot dimension.
    /// `normal_transaction_exhaustion_response` must never manufacture
    /// pressure evidence for a normal transaction partition that still admits
    /// work. Per I14.3 pressure evidence exists only for live saturation, so an
    /// admitting partition refuses the response rather than reporting an
    /// exhausted resource that is not exhausted.
    #[test]
    fn ors_transaction_exhaustion_response_refuses_an_admitting_partition() {
        let reserve = OrsReserve::partitioned(
            2,
            2,
            NonZeroU64::new(8).expect("bytes"),
            NonZeroU64::new(8).expect("bytes"),
        )
        .expect("reserve");
        assert_eq!(reserve.available_normal_transactions(), 2);

        let err = reserve
            .normal_transaction_exhaustion_response(
                NormalWorkClass::CanonicalWrite,
                "op-tx-admitting-1",
                eliot_contracts::ArtifactId::new("profile-rev-1").expect("valid artifact id"),
            )
            .expect_err("an admitting partition must not produce pressure evidence");
        assert!(matches!(
            err,
            OrsReserveError::InvalidField {
                field: "ors_reserve.normal_transaction_slots",
                ..
            }
        ));
    }

    /// The positive complement of
    /// `ors_transaction_exhaustion_response_refuses_an_admitting_partition`:
    /// that test pins that an admitting partition refuses to manufacture
    /// pressure evidence, this one pins that a truly saturated normal
    /// transaction partition yields a real `BUSY` report naming the transaction
    /// dimension (issue #1679 A3).
    #[test]
    fn ors_transaction_exhaustion_response_reports_live_saturation() {
        let reserve = OrsReserve::partitioned(
            2,
            2,
            NonZeroU64::new(8).expect("bytes"),
            NonZeroU64::new(8).expect("bytes"),
        )
        .expect("reserve");
        let epoch = AuthorityEpoch::new(1).expect("epoch");

        // Held for the whole test: the permit releases on drop, and the report
        // below must observe the live saturated partition.
        let _held_a = reserve
            .try_acquire_normal_transaction(
                NormalWorkClass::CanonicalWrite,
                "owner-a",
                "op-tx-fill-1",
                epoch,
            )
            .expect("first slot");
        let _held_b = reserve
            .try_acquire_normal_transaction(
                NormalWorkClass::CanonicalWrite,
                "owner-a",
                "op-tx-fill-2",
                epoch,
            )
            .expect("second slot");
        assert_eq!(reserve.available_normal_transactions(), 0);

        let response = reserve
            .normal_transaction_exhaustion_response(
                NormalWorkClass::CanonicalWrite,
                "op-tx-report-1",
                eliot_contracts::ArtifactId::new("profile-rev-1").expect("valid artifact id"),
            )
            .expect("live saturation must report");
        assert!(matches!(
            response.disposition,
            BackpressureDisposition::Busy
        ));
    }

    /// The identity complement of
    /// `ors_transaction_exhaustion_response_reports_live_saturation`: that test
    /// pins a real `BUSY` report from a live-saturated partition, this one pins
    /// that the same saturated partition still refuses a blank operation identity
    /// as `InvalidField { field: "ors_rejection.operation_id" }`, so no report
    /// carries an identity the contract cannot name (issue #1679 A10).
    #[test]
    fn ors_transaction_response_rejects_malformed_operation_id() {
        let reserve = OrsReserve::partitioned(
            1,
            1,
            NonZeroU64::new(8).expect("bytes"),
            NonZeroU64::new(8).expect("bytes"),
        )
        .expect("reserve");
        let epoch = AuthorityEpoch::new(1).expect("epoch");

        // The single normal transaction slot is consumed and held: the permit
        // releases on drop, so the refusal below comes from the malformed
        // identity and not from an unsaturated partition.
        let _held = reserve
            .try_acquire_normal_transaction(
                NormalWorkClass::CanonicalWrite,
                "owner-a",
                "op-tx-fill-1",
                epoch,
            )
            .expect("slot");
        assert_eq!(reserve.available_normal_transactions(), 0);

        let err = reserve
            .normal_transaction_exhaustion_response(
                NormalWorkClass::CanonicalWrite,
                "",
                eliot_contracts::ArtifactId::new("profile-rev-1").expect("valid artifact id"),
            )
            .expect_err("malformed operation identity must never produce a report");
        assert!(matches!(
            err,
            OrsReserveError::InvalidField {
                field: "ors_rejection.operation_id",
                ..
            }
        ));
    }

    /// The byte-dimension identity complement of
    /// `ors_transaction_exhaustion_response_reports_live_saturation`: that test
    /// pins a real `BUSY` report from a live-saturated partition, this one pins
    /// that the saturated durable byte partition still refuses a blank operation
    /// identity as `InvalidField { field: "ors_rejection.operation_id" }`, so no
    /// report carries an identity the contract cannot name (issue #1679 A10).
    #[test]
    fn ors_durable_response_rejects_malformed_operation_id() {
        let reserve = OrsReserve::partitioned(
            4,
            4,
            NonZeroU64::new(1).expect("bytes"),
            NonZeroU64::new(4).expect("bytes"),
        )
        .expect("reserve");
        let epoch = AuthorityEpoch::new(1).expect("epoch");

        let _held = reserve
            .try_acquire_normal_durable_bytes(
                NormalWorkClass::CanonicalWrite,
                "owner-a",
                "op-bytes-fill-1",
                NonZeroU64::new(1).expect("bytes"),
                epoch,
            )
            .expect("normal bytes");
        assert_eq!(reserve.available_normal_durable_bytes(), 0);

        let err = reserve
            .normal_durable_exhaustion_response(
                NormalWorkClass::CanonicalWrite,
                "",
                eliot_contracts::ArtifactId::new("profile-rev-1").expect("valid artifact id"),
                NonZeroU64::new(1).expect("bytes"),
            )
            .expect_err("malformed operation identity must never produce a report");
        assert!(matches!(
            err,
            OrsReserveError::InvalidField {
                field: "ors_rejection.operation_id",
                ..
            }
        ));
    }

    /// The constructor floor of issue #1679: a reserve with no normal
    /// transaction slots can never admit any ORS work, so building one must fail
    /// at build rather than surprise a caller at runtime with an always-shedding
    /// partition. The refusal names the exact field.
    #[test]
    fn ors_partitioned_zero_normal_transactions_fails_closed() {
        let Err(err) = OrsReserve::partitioned(
            0,
            2,
            NonZeroU64::new(8).expect("bytes"),
            NonZeroU64::new(8).expect("bytes"),
        ) else {
            panic!("zero normal transactions must fail at build");
        };
        assert!(matches!(
            err,
            OrsReserveError::InvalidField {
                field: "ors_reserve.normal_transaction_slots",
                ..
            }
        ));
    }

    /// The protected-partition complement of the normal floor (issue #1679):
    /// a reserve with no protected transaction slots can never admit protected
    /// ORS work, so building one must fail at build rather than surprise a
    /// caller at runtime with an always-shedding partition. The refusal names
    /// the exact field.
    #[test]
    fn ors_partitioned_zero_protected_transactions_fails_closed() {
        let Err(err) = OrsReserve::partitioned(
            4,
            0,
            NonZeroU64::new(2).expect("bytes"),
            NonZeroU64::new(4).expect("bytes"),
        ) else {
            panic!("zero protected transactions must fail at build");
        };
        assert!(matches!(
            err,
            OrsReserveError::InvalidField {
                field: "ors_reserve.protected_transaction_slots",
                ..
            }
        ));
    }

    /// The owner-identity complement of the acquisition paths (issue #1679
    /// A10): every permit binds owner, operation and epoch, so a blank owner
    /// must never hold an ORS permit. The refusal names the exact field
    /// `ors_permit.owner` before any partition capacity is consumed.
    #[test]
    fn ors_acquire_rejects_blank_owner() {
        let reserve = OrsReserve::partitioned(
            2,
            2,
            NonZeroU64::new(8).expect("bytes"),
            NonZeroU64::new(8).expect("bytes"),
        )
        .expect("reserve");
        let epoch = AuthorityEpoch::new(1).expect("epoch");

        let Err(err) = reserve.try_acquire_normal_transaction(
            NormalWorkClass::CanonicalWrite,
            "",
            "op-owner-1",
            epoch,
        ) else {
            panic!("blank owner must never hold a permit");
        };
        assert!(matches!(
            err,
            OrsReserveError::InvalidField {
                field: "ors_permit.owner",
                ..
            }
        ));
    }

    /// The operation-identity complement of the owner check (issue #1679
    /// A10): every permit binds owner, operation and epoch, so a blank
    /// operation id must never hold an ORS permit. The refusal names the
    /// exact field `ors_permit.operation_id` before any partition capacity is
    /// consumed.
    #[test]
    fn ors_acquire_rejects_blank_operation_id() {
        let reserve = OrsReserve::partitioned(
            2,
            2,
            NonZeroU64::new(8).expect("bytes"),
            NonZeroU64::new(8).expect("bytes"),
        )
        .expect("reserve");
        let epoch = AuthorityEpoch::new(1).expect("epoch");

        let Err(err) = reserve.try_acquire_normal_transaction(
            NormalWorkClass::CanonicalWrite,
            "owner-a",
            "",
            epoch,
        ) else {
            panic!("blank operation id must never hold a permit");
        };
        assert!(matches!(
            err,
            OrsReserveError::InvalidField {
                field: "ors_permit.operation_id",
                ..
            }
        ));
    }

    /// Protected-partition exhaustion names its dimension (issue
    /// #1679 A6/W4): a full protected transaction partition refuses
    /// with `ProtectedReserveExhausted` naming exactly
    /// `ORS_TRANSACTION_BOTTLENECK`, so exhaustion of one dimension
    /// is never reported as global exhaustion (I14.3). The fill permit
    /// is held across the assertions: it releases on drop.
    #[test]
    fn ors_protected_transaction_exhaustion_names_bottleneck() {
        let reserve = OrsReserve::partitioned(
            2,
            1,
            NonZeroU64::new(8).expect("bytes"),
            NonZeroU64::new(8).expect("bytes"),
        )
        .expect("reserve");
        let epoch = AuthorityEpoch::new(1).expect("epoch");

        // Held for the whole test: the permit releases on drop.
        let _held = reserve
            .try_acquire_protected_transaction(
                ControlOperationClass::CancelOperation,
                "owner-a",
                "op-tx-fill-1",
                epoch,
            )
            .expect("protected slot");
        assert_eq!(reserve.available_protected_transactions(), 0);

        let Err(err) = reserve.try_acquire_protected_transaction(
            ControlOperationClass::CancelOperation,
            "owner-a",
            "op-tx-shed-1",
            epoch,
        ) else {
            panic!("saturated protected partition must refuse");
        };
        assert!(
            matches!(err, OrsReserveError::ProtectedReserveExhausted { bottleneck, .. } if bottleneck == ORS_TRANSACTION_BOTTLENECK)
        );
    }

    /// The durable-byte face of the same property (issue #1679 A6/W4): a full
    /// protected durable-byte partition refuses with
    /// `ProtectedReserveExhausted` naming exactly
    /// `ORS_DURABLE_BYTES_BOTTLENECK`, so exhaustion of one dimension is never
    /// reported as global exhaustion (I14.3). The fill permit is held across the
    /// assertions: it releases on drop.
    #[test]
    fn ors_protected_durable_exhaustion_names_bottleneck() {
        let reserve = OrsReserve::partitioned(
            2,
            2,
            NonZeroU64::new(8).expect("bytes"),
            NonZeroU64::new(1).expect("bytes"),
        )
        .expect("reserve");
        let epoch = AuthorityEpoch::new(1).expect("epoch");

        // Held for the whole test: the permit releases on drop.
        let _held = reserve
            .try_acquire_protected_durable_bytes(
                ControlOperationClass::CancelOperation,
                "owner-a",
                "op-bytes-fill-1",
                NonZeroU64::new(1).expect("bytes"),
                epoch,
            )
            .expect("protected bytes");
        assert_eq!(reserve.available_protected_durable_bytes(), 0);

        let Err(err) = reserve.try_acquire_protected_durable_bytes(
            ControlOperationClass::CancelOperation,
            "owner-a",
            "op-bytes-shed-1",
            NonZeroU64::new(1).expect("bytes"),
            epoch,
        ) else {
            panic!("saturated protected partition must refuse");
        };
        assert!(
            matches!(err, OrsReserveError::ProtectedReserveExhausted { bottleneck, .. } if bottleneck == ORS_DURABLE_BYTES_BOTTLENECK)
        );
    }

    /// A fresh reserve reports exactly the partition capacities it was
    /// configured with (issue #1679): quantities are copied from
    /// configuration and never derived or scaled at construction, so no
    /// capacity can be invented while building the reserve (I14.3).
    #[test]
    fn ors_reserve_reports_configured_capacities() {
        let reserve = OrsReserve::partitioned(
            3,
            5,
            NonZeroU64::new(7).expect("bytes"),
            NonZeroU64::new(9).expect("bytes"),
        )
        .expect("reserve");

        assert_eq!(reserve.available_normal_transactions(), 3);
        assert_eq!(reserve.available_protected_transactions(), 5);
        assert_eq!(reserve.available_normal_durable_bytes(), 7);
        assert_eq!(reserve.available_protected_durable_bytes(), 9);
    }
}
