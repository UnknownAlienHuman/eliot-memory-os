//! Store control-reserve partitions for connections, transactions and pending-write memory.
//!
//! Issue #1679, W3 Store wave: the Store bridge generation enforces disjoint
//! normal-workload and protected-control partitions for its three frozen
//! bottlenecks ([`STORE_CONNECTION_BOTTLENECK`],
//! [`STORE_TRANSACTION_BOTTLENECK`] and [`STORE_PENDING_WRITE_BOTTLENECK`]).
//! The physical owners are the existing Store contour pieces: the connection
//! pool in [`crate::db_client_set::DbClientSet`], the named-transaction write
//! path that executes one named parameterized transaction per staged
//! `PreparedTransition` (I5.1, I5.19), and the pending-write/outbox memory in
//! [`crate::control_wal::ControlWal`]. This reserve is the partition mechanism
//! those owners will draw from; it performs no I/O, grants no semantic or
//! completion authority, and parses no payload meaning.
//!
//! Normal work can saturate a normal partition without consuming protected
//! cancellation/recovery capacity: an admitted cancellation or recovery record
//! keeps the protected Store path while ordinary work observes exhaustion.
//! Only [`NormalWorkClass`] operations typecheck on the normal acquisition
//! paths and only [`ControlOperationClass`] operations typecheck on the
//! protected paths, so a normal Store write, named read, agent, model, swarm,
//! report or maintenance admission cannot reach protected Store capacity by
//! relabelling its priority or class. There is no emergency acquisition path
//! at all: the emergency slot stays with the Kernel front-door last-resort
//! partition, which alone records reserve-exhaustion loss.
//!
//! Each claimed dimension publishes its live partition evidence through
//! [`StoreReserve::publish_claimed_row`] as a validated
//! [`BottleneckCapacityProfile`] row. The row is validated by the existing
//! [`BottleneckCapacityProfile::validate`] before it is returned, so an
//! inconsistent observation fails closed instead of emitting a guessed number.
//!
//! This module has no production caller yet (STITCH): it publishes the owner
//! evidence the Kernel profile composition will join, and that composition
//! binds the profile revision it resolves. Exhausted normal Store partitions
//! render as versioned [`I14BackpressureResponseV1`] answers with disposition
//! `BUSY` naming exactly the saturated Store bottleneck in its exact unit;
//! `STORAGE_BACKPRESSURE` is never rendered here because the frozen validator
//! pins that disposition to ORS durable bytes. Every response is validated by
//! the existing [`I14BackpressureResponseV1::validate`] before it is returned,
//! so an inconsistent observation fails closed instead of emitting a
//! disposition-only or generic queue-full answer. There is no emergency
//! partition here; recording reserve loss stays with the front-door
//! last-resort slot until a later wave wires Store-side loss reporting. Full
//! installed-saturation proof stays #11 Product scope.

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

/// The exact connection-slot bottleneck enforced by [`StoreReserve`].
pub const STORE_CONNECTION_BOTTLENECK: CapacityBottleneck =
    CapacityBottleneck::StoreConnectionSlots;

/// The exact transaction-slot bottleneck enforced by [`StoreReserve`].
pub const STORE_TRANSACTION_BOTTLENECK: CapacityBottleneck =
    CapacityBottleneck::StoreTransactionSlots;

/// The exact pending-write-memory bottleneck enforced by [`StoreReserve`].
pub const STORE_PENDING_WRITE_BOTTLENECK: CapacityBottleneck =
    CapacityBottleneck::StorePendingWriteMemory;

/// Typed Store reserve failures. None grants semantic or completion authority.
#[derive(Debug, Error)]
pub enum StoreReserveError {
    /// An owner, operation or field identity is blank or malformed.
    #[error("{field} is invalid: {reason}")]
    InvalidField {
        /// Failing field name.
        field: &'static str,
        /// Why the field failed.
        reason: &'static str,
    },
    /// The existing contract rejected an assembled Store evidence row.
    #[error("runtime contract rejected Store reserve evidence row: {0}")]
    Contract(String),
    /// The normal partition cannot satisfy the request; the protected
    /// partition is untouched.
    #[error(
        "Store normal capacity exhausted for {bottleneck:?}: work {work_class:?} operation {operation_id} owned by {owner}"
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
        "Store protected reserve exhausted for {bottleneck:?}: control operation {operation:?} operation {operation_id} owned by {owner}"
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

/// Which Store dimension a permit holds.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StoreDimension {
    /// Store bridge connections, counted in connections.
    ConnectionSlots,
    /// Store named transactions, counted in transactions.
    TransactionSlots,
    /// Store pending-write/outbox memory, counted in bytes.
    PendingWriteMemory,
}

impl StoreDimension {
    /// Returns the frozen bottleneck enforced for this dimension.
    #[must_use]
    pub const fn bottleneck(self) -> CapacityBottleneck {
        match self {
            Self::ConnectionSlots => STORE_CONNECTION_BOTTLENECK,
            Self::TransactionSlots => STORE_TRANSACTION_BOTTLENECK,
            Self::PendingWriteMemory => STORE_PENDING_WRITE_BOTTLENECK,
        }
    }
}

/// Typed operation identity carried by every [`StorePermit`].
///
/// The variant determines the only admissible [`CapacityClass`]: a normal work
/// class cannot name a protected operation and vice versa, so ordinary work
/// fails to typecheck against the protected acquisition paths instead of
/// failing at runtime.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StorePermitOperation {
    /// Ordinary workload operation.
    Normal(NormalWorkClass),
    /// Protected cancellation/recovery operation.
    Protected(ControlOperationClass),
}

impl StorePermitOperation {
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
struct StoreReserveInner {
    connection_normal_capacity: u64,
    connection_protected_capacity: u64,
    transaction_normal_capacity: u64,
    transaction_protected_capacity: u64,
    pending_normal_capacity_bytes: u64,
    pending_protected_capacity_bytes: u64,
    connection_normal_in_flight: AtomicU64,
    connection_protected_in_flight: AtomicU64,
    transaction_normal_in_flight: AtomicU64,
    transaction_protected_in_flight: AtomicU64,
    pending_normal_in_flight_bytes: AtomicU64,
    pending_protected_in_flight_bytes: AtomicU64,
}

/// The Store control reserve: disjoint normal/protected partitions for the
/// three Store bottlenecks, owned by the Store bridge generation.
///
/// Acquiring from one partition never observes or consumes another:
/// saturating a normal partition leaves the full protected capacity available
/// for admitted cancellation/recovery records and vice versa. Acquisition is
/// non-blocking and atomic; release is automatic when the returned
/// [`StorePermit`] drops.
#[derive(Clone, Debug)]
pub struct StoreReserve {
    inner: Arc<StoreReserveInner>,
}

/// One held Store capacity permit, bound to dimension, class, operation and
/// owner. Releasing is automatic on drop and returns exactly the consumed
/// partition and amount.
///
/// The permit is bound to the typed Authority Epoch the caller resolved at
/// acquisition: evidence from a fenced epoch never authorizes consumption
/// under the current one. Permits are deliberately not [`Clone`]: duplicating
/// a permit handle must never duplicate the underlying capacity.
#[derive(Debug)]
pub struct StorePermit {
    inner: Arc<StoreReserveInner>,
    dimension: StoreDimension,
    class: CapacityClass,
    amount: u64,
    operation: StorePermitOperation,
    operation_id: String,
    owner: String,
    authority_epoch: AuthorityEpoch,
}

impl StorePermit {
    /// Returns the capacity class (partition) this permit holds.
    #[must_use]
    pub const fn capacity_class(&self) -> CapacityClass {
        self.class
    }

    /// Returns which Store dimension this permit was granted from.
    #[must_use]
    pub const fn dimension(&self) -> StoreDimension {
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
    pub const fn operation(&self) -> StorePermitOperation {
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

    /// Returns the typed Authority Epoch this permit was granted under.
    #[must_use]
    pub const fn authority_epoch(&self) -> AuthorityEpoch {
        self.authority_epoch
    }
}

impl Drop for StorePermit {
    fn drop(&mut self) {
        let slot = match (self.dimension, self.class) {
            (StoreDimension::ConnectionSlots, CapacityClass::NormalWorkload) => {
                &self.inner.connection_normal_in_flight
            }
            (StoreDimension::ConnectionSlots, _) => &self.inner.connection_protected_in_flight,
            (StoreDimension::TransactionSlots, CapacityClass::NormalWorkload) => {
                &self.inner.transaction_normal_in_flight
            }
            (StoreDimension::TransactionSlots, _) => &self.inner.transaction_protected_in_flight,
            (StoreDimension::PendingWriteMemory, CapacityClass::NormalWorkload) => {
                &self.inner.pending_normal_in_flight_bytes
            }
            (StoreDimension::PendingWriteMemory, _) => {
                &self.inner.pending_protected_in_flight_bytes
            }
        };
        debug_assert!(
            slot.load(Ordering::Acquire) >= self.amount,
            "Store permit drop without a held partition amount"
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

/// Bounded owner/operation identity check.
///
/// Mirrors the Kernel ORS owner's text bounds without adding a cross-crate
/// edge to durable ORS state: non-blank, no control characters, at most 1024
/// UTF-8 bytes.
fn validate_owner_text(value: &str, field: &'static str) -> Result<(), StoreReserveError> {
    if value.trim().is_empty() {
        return Err(StoreReserveError::InvalidField {
            field,
            reason: "must be non-blank",
        });
    }
    if value.chars().any(char::is_control) {
        return Err(StoreReserveError::InvalidField {
            field,
            reason: "must not contain control characters",
        });
    }
    if value.len() > 1_024 {
        return Err(StoreReserveError::InvalidField {
            field,
            reason: "must not exceed 1024 UTF-8 bytes",
        });
    }
    Ok(())
}

impl StoreReserve {
    /// Creates a Store reserve with disjoint normal and protected partitions
    /// for all three Store dimensions.
    ///
    /// Normal work draws only from the normal connection slots, normal
    /// transaction slots and normal pending-write bytes; admitted
    /// cancellation/recovery draws only from the protected connection slots,
    /// protected transaction slots and protected pending-write bytes. Neither
    /// class can borrow from the other.
    ///
    /// # Errors
    ///
    /// Returns [`StoreReserveError::InvalidField`] when any slot partition
    /// capacity is zero.
    pub fn partitioned(
        normal_connection_slots: u64,
        protected_connection_slots: u64,
        normal_transaction_slots: u64,
        protected_transaction_slots: u64,
        normal_pending_write_bytes: NonZeroU64,
        protected_pending_write_bytes: NonZeroU64,
    ) -> Result<Self, StoreReserveError> {
        for (value, field) in [
            (
                normal_connection_slots,
                "store_reserve.normal_connection_slots",
            ),
            (
                protected_connection_slots,
                "store_reserve.protected_connection_slots",
            ),
            (
                normal_transaction_slots,
                "store_reserve.normal_transaction_slots",
            ),
            (
                protected_transaction_slots,
                "store_reserve.protected_transaction_slots",
            ),
        ] {
            if value == 0 {
                return Err(StoreReserveError::InvalidField {
                    field,
                    reason: "must be greater than zero",
                });
            }
        }
        Ok(Self {
            inner: Arc::new(StoreReserveInner {
                connection_normal_capacity: normal_connection_slots,
                connection_protected_capacity: protected_connection_slots,
                transaction_normal_capacity: normal_transaction_slots,
                transaction_protected_capacity: protected_transaction_slots,
                pending_normal_capacity_bytes: normal_pending_write_bytes.get(),
                pending_protected_capacity_bytes: protected_pending_write_bytes.get(),
                connection_normal_in_flight: AtomicU64::new(0),
                connection_protected_in_flight: AtomicU64::new(0),
                transaction_normal_in_flight: AtomicU64::new(0),
                transaction_protected_in_flight: AtomicU64::new(0),
                pending_normal_in_flight_bytes: AtomicU64::new(0),
                pending_protected_in_flight_bytes: AtomicU64::new(0),
            }),
        })
    }

    /// Returns the configured normal connection-slot partition capacity.
    #[must_use]
    pub fn normal_connection_capacity(&self) -> u64 {
        self.inner.connection_normal_capacity
    }

    /// Returns the configured protected connection-slot partition capacity.
    #[must_use]
    pub fn protected_connection_capacity(&self) -> u64 {
        self.inner.connection_protected_capacity
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

    /// Returns the configured normal pending-write-byte partition capacity.
    #[must_use]
    pub fn normal_pending_write_byte_capacity(&self) -> u64 {
        self.inner.pending_normal_capacity_bytes
    }

    /// Returns the configured protected pending-write-byte partition capacity.
    #[must_use]
    pub fn protected_pending_write_byte_capacity(&self) -> u64 {
        self.inner.pending_protected_capacity_bytes
    }

    /// Returns the currently available normal connection slots.
    #[must_use]
    pub fn available_normal_connections(&self) -> u64 {
        self.inner.connection_normal_capacity.saturating_sub(
            self.inner
                .connection_normal_in_flight
                .load(Ordering::Acquire),
        )
    }

    /// Returns the currently available protected connection slots.
    #[must_use]
    pub fn available_protected_connections(&self) -> u64 {
        self.inner.connection_protected_capacity.saturating_sub(
            self.inner
                .connection_protected_in_flight
                .load(Ordering::Acquire),
        )
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

    /// Returns the currently available normal pending-write bytes.
    #[must_use]
    pub fn available_normal_pending_write_bytes(&self) -> u64 {
        self.inner.pending_normal_capacity_bytes.saturating_sub(
            self.inner
                .pending_normal_in_flight_bytes
                .load(Ordering::Acquire),
        )
    }

    /// Returns the currently available protected pending-write bytes.
    #[must_use]
    pub fn available_protected_pending_write_bytes(&self) -> u64 {
        self.inner.pending_protected_capacity_bytes.saturating_sub(
            self.inner
                .pending_protected_in_flight_bytes
                .load(Ordering::Acquire),
        )
    }

    /// Attempts to acquire one normal connection slot without blocking.
    ///
    /// Only [`NormalWorkClass`] operations typecheck here, so protected Store
    /// capacity is unreachable through this path by construction. The returned
    /// permit is bound to `authority_epoch` alongside class, bottleneck, unit,
    /// amount, typed operation, operation identity and owner.
    ///
    /// # Errors
    ///
    /// Returns [`StoreReserveError::InvalidField`] for a blank owner/operation
    /// identity, or [`StoreReserveError::NormalCapacityExhausted`] naming the
    /// connection bottleneck and shed work when the normal partition is
    /// saturated. The protected partition is untouched in every case.
    pub fn try_acquire_normal_connection(
        &self,
        work: NormalWorkClass,
        owner: &str,
        operation_id: &str,
        authority_epoch: AuthorityEpoch,
    ) -> Result<StorePermit, StoreReserveError> {
        validate_owner_text(owner, "store_permit.owner")?;
        validate_owner_text(operation_id, "store_permit.operation_id")?;
        if !cas_add(
            &self.inner.connection_normal_in_flight,
            self.inner.connection_normal_capacity,
            1,
        ) {
            return Err(StoreReserveError::NormalCapacityExhausted {
                bottleneck: STORE_CONNECTION_BOTTLENECK,
                work_class: work,
                operation_id: operation_id.to_owned(),
                owner: owner.to_owned(),
            });
        }
        Ok(StorePermit {
            inner: self.inner.clone(),
            dimension: StoreDimension::ConnectionSlots,
            class: CapacityClass::NormalWorkload,
            amount: 1,
            operation: StorePermitOperation::Normal(work),
            operation_id: operation_id.to_owned(),
            owner: owner.to_owned(),
            authority_epoch,
        })
    }

    /// Attempts to acquire one normal transaction slot without blocking.
    ///
    /// Only [`NormalWorkClass`] operations typecheck here, so protected Store
    /// transaction capacity is unreachable through this path by construction.
    /// The returned permit is bound to `authority_epoch` alongside class,
    /// bottleneck, unit, amount, typed operation, operation identity and
    /// owner.
    ///
    /// # Errors
    ///
    /// Returns [`StoreReserveError::InvalidField`] for a blank owner/operation
    /// identity, or [`StoreReserveError::NormalCapacityExhausted`] naming the
    /// transaction bottleneck and shed work when the normal partition is
    /// saturated. The protected partition is untouched in every case.
    pub fn try_acquire_normal_transaction(
        &self,
        work: NormalWorkClass,
        owner: &str,
        operation_id: &str,
        authority_epoch: AuthorityEpoch,
    ) -> Result<StorePermit, StoreReserveError> {
        validate_owner_text(owner, "store_permit.owner")?;
        validate_owner_text(operation_id, "store_permit.operation_id")?;
        if !cas_add(
            &self.inner.transaction_normal_in_flight,
            self.inner.transaction_normal_capacity,
            1,
        ) {
            return Err(StoreReserveError::NormalCapacityExhausted {
                bottleneck: STORE_TRANSACTION_BOTTLENECK,
                work_class: work,
                operation_id: operation_id.to_owned(),
                owner: owner.to_owned(),
            });
        }
        Ok(StorePermit {
            inner: self.inner.clone(),
            dimension: StoreDimension::TransactionSlots,
            class: CapacityClass::NormalWorkload,
            amount: 1,
            operation: StorePermitOperation::Normal(work),
            operation_id: operation_id.to_owned(),
            owner: owner.to_owned(),
            authority_epoch,
        })
    }

    /// Attempts to acquire `bytes` normal pending-write bytes without blocking.
    ///
    /// Only [`NormalWorkClass`] operations typecheck here, so protected Store
    /// pending-write capacity is unreachable through this path by construction.
    /// The returned permit is bound to `authority_epoch` alongside class,
    /// bottleneck, unit, amount, typed operation, operation identity and
    /// owner.
    ///
    /// # Errors
    ///
    /// Returns [`StoreReserveError::InvalidField`] for a blank owner/operation
    /// identity, or [`StoreReserveError::NormalCapacityExhausted`] naming the
    /// pending-write bottleneck and shed work when the normal partition cannot
    /// satisfy the request. The protected partition is untouched in every
    /// case.
    pub fn try_acquire_normal_pending_write_bytes(
        &self,
        work: NormalWorkClass,
        owner: &str,
        operation_id: &str,
        bytes: NonZeroU64,
        authority_epoch: AuthorityEpoch,
    ) -> Result<StorePermit, StoreReserveError> {
        validate_owner_text(owner, "store_permit.owner")?;
        validate_owner_text(operation_id, "store_permit.operation_id")?;
        if !cas_add(
            &self.inner.pending_normal_in_flight_bytes,
            self.inner.pending_normal_capacity_bytes,
            bytes.get(),
        ) {
            return Err(StoreReserveError::NormalCapacityExhausted {
                bottleneck: STORE_PENDING_WRITE_BOTTLENECK,
                work_class: work,
                operation_id: operation_id.to_owned(),
                owner: owner.to_owned(),
            });
        }
        Ok(StorePermit {
            inner: self.inner.clone(),
            dimension: StoreDimension::PendingWriteMemory,
            class: CapacityClass::NormalWorkload,
            amount: bytes.get(),
            operation: StorePermitOperation::Normal(work),
            operation_id: operation_id.to_owned(),
            owner: owner.to_owned(),
            authority_epoch,
        })
    }

    /// Attempts to acquire one protected connection slot without blocking.
    ///
    /// Only [`ControlOperationClass`] operations typecheck here: a normal
    /// Store write, named read, agent, model, swarm, report or maintenance
    /// admission cannot name a protected operation and therefore cannot
    /// acquire this partition. This is the path an admitted
    /// cancellation/recovery record keeps while normal connection work is
    /// saturated. The returned permit is bound to `authority_epoch` alongside
    /// class, bottleneck, unit, amount, typed operation, operation identity
    /// and owner.
    ///
    /// # Errors
    ///
    /// Returns [`StoreReserveError::InvalidField`] for a blank owner/operation
    /// identity, or [`StoreReserveError::ProtectedReserveExhausted`] naming the
    /// connection bottleneck, operation, owner and request when the protected
    /// partition is saturated.
    pub fn try_acquire_protected_connection(
        &self,
        operation: ControlOperationClass,
        owner: &str,
        operation_id: &str,
        authority_epoch: AuthorityEpoch,
    ) -> Result<StorePermit, StoreReserveError> {
        validate_owner_text(owner, "store_permit.owner")?;
        validate_owner_text(operation_id, "store_permit.operation_id")?;
        if !cas_add(
            &self.inner.connection_protected_in_flight,
            self.inner.connection_protected_capacity,
            1,
        ) {
            return Err(StoreReserveError::ProtectedReserveExhausted {
                bottleneck: STORE_CONNECTION_BOTTLENECK,
                operation,
                operation_id: operation_id.to_owned(),
                owner: owner.to_owned(),
            });
        }
        Ok(StorePermit {
            inner: self.inner.clone(),
            dimension: StoreDimension::ConnectionSlots,
            class: CapacityClass::ProtectedControl,
            amount: 1,
            operation: StorePermitOperation::Protected(operation),
            operation_id: operation_id.to_owned(),
            owner: owner.to_owned(),
            authority_epoch,
        })
    }

    /// Attempts to acquire one protected transaction slot without blocking.
    ///
    /// Only [`ControlOperationClass`] operations typecheck here. This is the
    /// path an admitted cancellation/recovery record keeps while normal Store
    /// transaction work is saturated. The returned permit is bound to
    /// `authority_epoch` alongside class, bottleneck, unit, amount, typed
    /// operation, operation identity and owner.
    ///
    /// # Errors
    ///
    /// Returns [`StoreReserveError::InvalidField`] for a blank owner/operation
    /// identity, or [`StoreReserveError::ProtectedReserveExhausted`] naming the
    /// transaction bottleneck, operation, owner and request when the protected
    /// partition is saturated.
    pub fn try_acquire_protected_transaction(
        &self,
        operation: ControlOperationClass,
        owner: &str,
        operation_id: &str,
        authority_epoch: AuthorityEpoch,
    ) -> Result<StorePermit, StoreReserveError> {
        validate_owner_text(owner, "store_permit.owner")?;
        validate_owner_text(operation_id, "store_permit.operation_id")?;
        if !cas_add(
            &self.inner.transaction_protected_in_flight,
            self.inner.transaction_protected_capacity,
            1,
        ) {
            return Err(StoreReserveError::ProtectedReserveExhausted {
                bottleneck: STORE_TRANSACTION_BOTTLENECK,
                operation,
                operation_id: operation_id.to_owned(),
                owner: owner.to_owned(),
            });
        }
        Ok(StorePermit {
            inner: self.inner.clone(),
            dimension: StoreDimension::TransactionSlots,
            class: CapacityClass::ProtectedControl,
            amount: 1,
            operation: StorePermitOperation::Protected(operation),
            operation_id: operation_id.to_owned(),
            owner: owner.to_owned(),
            authority_epoch,
        })
    }

    /// Attempts to acquire `bytes` protected pending-write bytes without
    /// blocking.
    ///
    /// Only [`ControlOperationClass`] operations typecheck here. This is the
    /// path an admitted cancellation/recovery record keeps while normal
    /// pending-write work is saturated. The returned permit is bound to
    /// `authority_epoch` alongside class, bottleneck, unit, amount, typed
    /// operation, operation identity and owner.
    ///
    /// # Errors
    ///
    /// Returns [`StoreReserveError::InvalidField`] for a blank owner/operation
    /// identity, or [`StoreReserveError::ProtectedReserveExhausted`] naming the
    /// pending-write bottleneck, operation, owner and request when the
    /// protected partition cannot satisfy the request.
    pub fn try_acquire_protected_pending_write_bytes(
        &self,
        operation: ControlOperationClass,
        owner: &str,
        operation_id: &str,
        bytes: NonZeroU64,
        authority_epoch: AuthorityEpoch,
    ) -> Result<StorePermit, StoreReserveError> {
        validate_owner_text(owner, "store_permit.owner")?;
        validate_owner_text(operation_id, "store_permit.operation_id")?;
        if !cas_add(
            &self.inner.pending_protected_in_flight_bytes,
            self.inner.pending_protected_capacity_bytes,
            bytes.get(),
        ) {
            return Err(StoreReserveError::ProtectedReserveExhausted {
                bottleneck: STORE_PENDING_WRITE_BOTTLENECK,
                operation,
                operation_id: operation_id.to_owned(),
                owner: owner.to_owned(),
            });
        }
        Ok(StorePermit {
            inner: self.inner.clone(),
            dimension: StoreDimension::PendingWriteMemory,
            class: CapacityClass::ProtectedControl,
            amount: bytes.get(),
            operation: StorePermitOperation::Protected(operation),
            operation_id: operation_id.to_owned(),
            owner: owner.to_owned(),
            authority_epoch,
        })
    }

    /// Publishes the live partition evidence for one Store dimension as a
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
    /// Returns [`StoreReserveError::InvalidField`] for a blank metadata
    /// reference or when the partition accounting cannot be represented, or
    /// [`StoreReserveError::Contract`] when the assembled row fails the
    /// existing contract validation.
    pub fn publish_claimed_row(
        &self,
        dimension: StoreDimension,
        owner_generation_ref: &str,
        proof_profile_ref: &str,
        evidence_ref: &str,
        invalidation_ref: &str,
    ) -> Result<BottleneckCapacityProfile, StoreReserveError> {
        validate_owner_text(owner_generation_ref, "store_evidence.owner_generation_ref")?;
        validate_owner_text(proof_profile_ref, "store_evidence.proof_profile_ref")?;
        validate_owner_text(evidence_ref, "store_evidence.evidence_ref")?;
        validate_owner_text(invalidation_ref, "store_evidence.invalidation_ref")?;
        let bottleneck = dimension.bottleneck();
        let bound = frozen_bottleneck_owner_map()
            .into_iter()
            .find(|bound| bound.bottleneck == bottleneck)
            .ok_or(StoreReserveError::InvalidField {
                field: "store_evidence.bottleneck",
                reason: "the frozen owner map binds no owner to this Store dimension",
            })?;
        let (normal_capacity, protected_capacity) = match dimension {
            StoreDimension::ConnectionSlots => (
                self.inner.connection_normal_capacity,
                self.inner.connection_protected_capacity,
            ),
            StoreDimension::TransactionSlots => (
                self.inner.transaction_normal_capacity,
                self.inner.transaction_protected_capacity,
            ),
            StoreDimension::PendingWriteMemory => (
                self.inner.pending_normal_capacity_bytes,
                self.inner.pending_protected_capacity_bytes,
            ),
        };
        let physical_total = normal_capacity
            .checked_add(protected_capacity)
            .and_then(NonZeroU64::new)
            .ok_or(StoreReserveError::InvalidField {
                field: "store_evidence.physical_total_limit",
                reason: "the disjoint partition sum is not a positive capacity",
            })?;
        let unit = bottleneck.unit();
        let limit = |quantity: u64| {
            NonZeroU64::new(quantity)
                .map(|quantity| CapacityLimit { unit, quantity })
                .ok_or(StoreReserveError::InvalidField {
                    field: "store_evidence.partition_limit",
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
            .map_err(|error| StoreReserveError::Contract(error.to_string()))?;
        Ok(row)
    }

    /// Reports exhausted normal connection slots as a `BUSY` response naming
    /// exactly [`STORE_CONNECTION_BOTTLENECK`].
    ///
    /// `STORAGE_BACKPRESSURE` is never rendered here: the frozen validator
    /// pins that disposition to ORS durable bytes. The response is built only
    /// while [`Self::available_normal_connections`] is zero: pressure evidence
    /// is never manufactured for a partition that still admits work. The
    /// protected partition is not read and not claimed.
    ///
    /// # Errors
    ///
    /// Returns [`StoreReserveError::InvalidField`] when normal connection
    /// capacity remains or the operation identity is malformed, or
    /// [`StoreReserveError::Contract`] when the assembled directive fails the
    /// existing contract validation.
    pub fn normal_connection_exhaustion_response(
        &self,
        work: NormalWorkClass,
        operation_id: &str,
        profile_revision: ArtifactId,
    ) -> Result<I14BackpressureResponseV1, StoreReserveError> {
        if self.available_normal_connections() > 0 {
            return Err(StoreReserveError::InvalidField {
                field: "store_reserve.normal_connection_slots",
                reason: "normal connection partition is not saturated; no pressure evidence to report",
            });
        }
        let operation =
            OperationId::new(operation_id).map_err(|_| StoreReserveError::InvalidField {
                field: "store_rejection.operation_id",
                reason: "must be a bounded non-blank reference",
            })?;
        StoreRejectionParts {
            affected: AffectedOperationClass::Normal(work),
            observation: BottleneckObservationV1 {
                bottleneck: STORE_CONNECTION_BOTTLENECK,
                unit: STORE_CONNECTION_BOTTLENECK.unit(),
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

    /// Reports exhausted normal transaction slots as a `BUSY` response naming
    /// exactly [`STORE_TRANSACTION_BOTTLENECK`].
    ///
    /// `STORAGE_BACKPRESSURE` is never rendered here: the frozen validator
    /// pins that disposition to ORS durable bytes. The response is built only
    /// while [`Self::available_normal_transactions`] is zero: pressure
    /// evidence is never manufactured for a partition that still admits work.
    /// The protected partition is not read and not claimed.
    ///
    /// # Errors
    ///
    /// Returns [`StoreReserveError::InvalidField`] when normal transaction
    /// capacity remains or the operation identity is malformed, or
    /// [`StoreReserveError::Contract`] when the assembled directive fails the
    /// existing contract validation.
    pub fn normal_transaction_exhaustion_response(
        &self,
        work: NormalWorkClass,
        operation_id: &str,
        profile_revision: ArtifactId,
    ) -> Result<I14BackpressureResponseV1, StoreReserveError> {
        if self.available_normal_transactions() > 0 {
            return Err(StoreReserveError::InvalidField {
                field: "store_reserve.normal_transaction_slots",
                reason: "normal transaction partition is not saturated; no pressure evidence to report",
            });
        }
        let operation =
            OperationId::new(operation_id).map_err(|_| StoreReserveError::InvalidField {
                field: "store_rejection.operation_id",
                reason: "must be a bounded non-blank reference",
            })?;
        StoreRejectionParts {
            affected: AffectedOperationClass::Normal(work),
            observation: BottleneckObservationV1 {
                bottleneck: STORE_TRANSACTION_BOTTLENECK,
                unit: STORE_TRANSACTION_BOTTLENECK.unit(),
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

    /// Reports exhausted normal pending-write bytes as a `BUSY` response
    /// naming exactly [`STORE_PENDING_WRITE_BOTTLENECK`].
    ///
    /// `STORAGE_BACKPRESSURE` is never rendered here: the frozen validator
    /// pins that disposition to ORS durable bytes. The response is built only
    /// while the normal pending-write partition cannot satisfy
    /// `requested_bytes`: pressure evidence is never manufactured for a
    /// partition that still admits the request. The protected partition is not
    /// read and not claimed, so an admitted cancellation/recovery record keeps
    /// its path while this response is live.
    ///
    /// # Errors
    ///
    /// Returns [`StoreReserveError::InvalidField`] when the normal
    /// pending-write partition still satisfies the request or the operation
    /// identity is malformed, or [`StoreReserveError::Contract`] when the
    /// assembled directive fails the existing contract validation.
    pub fn normal_pending_write_exhaustion_response(
        &self,
        work: NormalWorkClass,
        operation_id: &str,
        profile_revision: ArtifactId,
        requested_bytes: NonZeroU64,
    ) -> Result<I14BackpressureResponseV1, StoreReserveError> {
        let available = self.available_normal_pending_write_bytes();
        if available >= requested_bytes.get() {
            return Err(StoreReserveError::InvalidField {
                field: "store_reserve.normal_pending_write_bytes",
                reason: "normal pending-write partition still admits the request; no pressure evidence to report",
            });
        }
        let operation =
            OperationId::new(operation_id).map_err(|_| StoreReserveError::InvalidField {
                field: "store_rejection.operation_id",
                reason: "must be a bounded non-blank reference",
            })?;
        StoreRejectionParts {
            affected: AffectedOperationClass::Normal(work),
            observation: BottleneckObservationV1 {
                bottleneck: STORE_PENDING_WRITE_BOTTLENECK,
                unit: STORE_PENDING_WRITE_BOTTLENECK.unit(),
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
            BackpressureDisposition::Busy,
            I14WorkOutcome::NotAccepted,
            RecoveryCommitStatus::None,
        )
    }
}

/// Exact parts of one Store rejection directive shared by every constructor.
struct StoreRejectionParts {
    affected: AffectedOperationClass,
    observation: BottleneckObservationV1,
    operation_id: Option<OperationId>,
    profile_revision: ArtifactId,
}

impl StoreRejectionParts {
    /// Assembles the versioned response and validates it with the existing
    /// contract check; an inconsistent observation fails closed here.
    fn into_response(
        self,
        disposition: BackpressureDisposition,
        work_outcome: I14WorkOutcome,
        commit_status: RecoveryCommitStatus,
    ) -> Result<I14BackpressureResponseV1, StoreReserveError> {
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
            .map_err(|error| StoreReserveError::Contract(error.to_string()))?;
        Ok(response)
    }
}
