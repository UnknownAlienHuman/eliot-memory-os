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
//! binds the profile revision and Authority Epoch it resolves. There is no
//! emergency partition here; recording reserve loss stays with the front-door
//! last-resort slot until a later wave wires Store-side loss reporting.
//! DISCLOSED LIMIT: versioned I14 backpressure responses are not rendered here.
//! The frozen validator pins `STORAGE_BACKPRESSURE` to ORS durable bytes, so a
//! Store exhaustion response would be `BUSY`; rendering it needs the
//! identity types the Store contour does not own, and is owed to the response
//! wave once the composition joins this evidence. Full installed-saturation
//! proof stays #11 Product scope.

use std::num::NonZeroU64;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use eliot_runtime_contracts::{
    BottleneckCapacityProfile, BottleneckCoverageState, CapacityBottleneck, CapacityClass,
    CapacityEnforcement, CapacityLimit, ControlOperationClass, NormalWorkClass,
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
/// Permits are deliberately not [`Clone`]: duplicating a permit handle must
/// never duplicate the underlying capacity.
#[derive(Debug)]
pub struct StorePermit {
    inner: Arc<StoreReserveInner>,
    dimension: StoreDimension,
    class: CapacityClass,
    amount: u64,
    operation: StorePermitOperation,
    operation_id: String,
    owner: String,
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
    /// capacity is unreachable through this path by construction.
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
        })
    }

    /// Attempts to acquire one normal transaction slot without blocking.
    ///
    /// Only [`NormalWorkClass`] operations typecheck here, so protected Store
    /// transaction capacity is unreachable through this path by construction.
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
        })
    }

    /// Attempts to acquire `bytes` normal pending-write bytes without blocking.
    ///
    /// Only [`NormalWorkClass`] operations typecheck here, so protected Store
    /// pending-write capacity is unreachable through this path by construction.
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
        })
    }

    /// Attempts to acquire one protected connection slot without blocking.
    ///
    /// Only [`ControlOperationClass`] operations typecheck here: a normal
    /// Store write, named read, agent, model, swarm, report or maintenance
    /// admission cannot name a protected operation and therefore cannot
    /// acquire this partition. This is the path an admitted
    /// cancellation/recovery record keeps while normal connection work is
    /// saturated.
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
        })
    }

    /// Attempts to acquire one protected transaction slot without blocking.
    ///
    /// Only [`ControlOperationClass`] operations typecheck here. This is the
    /// path an admitted cancellation/recovery record keeps while normal Store
    /// transaction work is saturated.
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
        })
    }

    /// Attempts to acquire `bytes` protected pending-write bytes without
    /// blocking.
    ///
    /// Only [`ControlOperationClass`] operations typecheck here. This is the
    /// path an admitted cancellation/recovery record keeps while normal
    /// pending-write work is saturated.
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::num::NonZeroU64;

    /// Saturating the single normal connection slot leaves the protected
    /// partition untouched (issue #1679). The positive control comes FIRST and
    /// its permit is held across the assertions: a reserve that refused
    /// everything would also refuse normal work, so only an admitted
    /// cancellation proves the protected slot is genuinely still available
    /// while ordinary Store writes are being shed. The shedding refusal then
    /// names the exact bottleneck, so exhaustion of one dimension is never
    /// reported as global exhaustion.
    #[test]
    fn store_normal_connection_saturation_leaves_protected_slot_available() {
        let reserve = StoreReserve::partitioned(
            1,
            2,
            4,
            4,
            NonZeroU64::new(8).expect("bytes"),
            NonZeroU64::new(8).expect("bytes"),
        )
        .expect("reserve");

        // Held for the whole test: the permit releases on drop.
        let _held = reserve
            .try_acquire_normal_connection(
                NormalWorkClass::CanonicalWrite,
                "owner-a",
                "op-conn-fill-1",
            )
            .expect("first slot");

        // Positive control, also held: the admitted cancellation keeps its
        // slot while the normal partition is saturated.
        let _ctl = reserve
            .try_acquire_protected_connection(
                ControlOperationClass::CancelOperation,
                "owner-a",
                "op-conn-ctl-1",
            )
            .expect("protected path stays open");
        assert_eq!(reserve.available_protected_connections(), 1);

        let err = reserve
            .try_acquire_normal_connection(
                NormalWorkClass::CanonicalWrite,
                "owner-a",
                "op-conn-shed-1",
            )
            .expect_err("saturated normal partition must refuse");
        assert!(
            matches!(err, StoreReserveError::NormalCapacityExhausted { bottleneck, .. } if bottleneck == STORE_CONNECTION_BOTTLENECK)
        );
    }

    /// Store pending-write memory is the third Store dimension, so saturating
    /// the normal pending-write byte partition leaves the protected
    /// pending-write path available (issue #1679). The positive control comes
    /// FIRST and its permit is held across the assertions: a reserve that
    /// refused everything would also refuse normal work, so only an admitted
    /// cancellation proves the protected byte budget is genuinely still
    /// available while ordinary Store writes are being shed. The shedding
    /// refusal then names the exact bottleneck, so exhaustion of one dimension
    /// is never reported as global exhaustion.
    #[test]
    fn store_normal_pending_saturation_leaves_protected_bytes_available() {
        let reserve = StoreReserve::partitioned(
            4,
            4,
            4,
            4,
            NonZeroU64::new(2).expect("bytes"),
            NonZeroU64::new(4).expect("bytes"),
        )
        .expect("reserve");

        // Held for the whole test: the permit releases on drop.
        let _held = reserve
            .try_acquire_normal_pending_write_bytes(
                NormalWorkClass::CanonicalWrite,
                "owner-a",
                "op-pend-fill-1",
                NonZeroU64::new(2).expect("bytes"),
            )
            .expect("normal pending bytes");

        // Positive control, also held: the admitted cancellation keeps its
        // bytes while the normal partition is saturated.
        let _ctl = reserve
            .try_acquire_protected_pending_write_bytes(
                ControlOperationClass::CancelOperation,
                "owner-a",
                "op-pend-ctl-1",
                NonZeroU64::new(1).expect("bytes"),
            )
            .expect("protected path stays open");
        assert_eq!(reserve.available_protected_pending_write_bytes(), 3);

        let err = reserve
            .try_acquire_normal_pending_write_bytes(
                NormalWorkClass::CanonicalWrite,
                "owner-a",
                "op-pend-shed-1",
                NonZeroU64::new(1).expect("bytes"),
            )
            .expect_err("saturated normal pending bytes must refuse");
        assert!(
            matches!(err, StoreReserveError::NormalCapacityExhausted { bottleneck, .. } if bottleneck == STORE_PENDING_WRITE_BOTTLENECK)
        );
    }

    /// Store transaction slots are the second Store dimension, so saturating
    /// the normal transaction-slot partition leaves the protected transaction
    /// path available (issue #1679). The positive control comes FIRST and its
    /// permit is held across the assertions: a reserve that refused everything
    /// would also refuse normal work, so only an admitted cancellation proves
    /// the protected slot is genuinely still available while ordinary Store
    /// transactions are being shed. The shedding refusal then names the exact
    /// bottleneck, so exhaustion of one dimension is never reported as global
    /// exhaustion.
    #[test]
    fn store_normal_transaction_saturation_leaves_protected_slot_available() {
        let reserve = StoreReserve::partitioned(
            4,
            4,
            1,
            2,
            NonZeroU64::new(8).expect("bytes"),
            NonZeroU64::new(8).expect("bytes"),
        )
        .expect("reserve");

        // Held for the whole test: the permit releases on drop.
        let _held = reserve
            .try_acquire_normal_transaction(
                NormalWorkClass::CanonicalWrite,
                "owner-a",
                "op-tx-fill-1",
            )
            .expect("first slot");

        // Positive control, also held: the admitted cancellation keeps its
        // slot while the normal partition is saturated.
        let _ctl = reserve
            .try_acquire_protected_transaction(
                ControlOperationClass::CancelOperation,
                "owner-a",
                "op-tx-ctl-1",
            )
            .expect("protected path stays open");
        assert_eq!(reserve.available_protected_transactions(), 1);

        let err = reserve
            .try_acquire_normal_transaction(
                NormalWorkClass::CanonicalWrite,
                "owner-a",
                "op-tx-shed-1",
            )
            .expect_err("saturated normal partition must refuse");
        assert!(
            matches!(err, StoreReserveError::NormalCapacityExhausted { bottleneck, .. } if bottleneck == STORE_TRANSACTION_BOTTLENECK)
        );
    }

    /// The Store owner must publish a live, validated
    /// [`BottleneckCapacityProfile`] row for the Kernel profile composition to
    /// join (issue #1679): the row names exactly
    /// [`STORE_CONNECTION_BOTTLENECK`] with the frozen-map owner, so the
    /// composition joins real owner evidence rather than a borrowed or
    /// invented capacity story.
    #[test]
    fn store_publish_claimed_row_names_frozen_connection_owner() {
        let reserve = StoreReserve::partitioned(
            4,
            4,
            1,
            2,
            NonZeroU64::new(8).expect("bytes"),
            NonZeroU64::new(8).expect("bytes"),
        )
        .expect("reserve");

        // A returned row already passed `row.validate()`, so a contract
        // failure here would be the fail-closed property itself.
        let row = reserve
            .publish_claimed_row(
                StoreDimension::ConnectionSlots,
                "gen-7",
                "proof-store-1",
                "ev-store-1",
                "inv-store-1",
            )
            .expect("claimed row");

        assert_eq!(row.bottleneck, STORE_CONNECTION_BOTTLENECK);
        assert_eq!(row.coverage_state, BottleneckCoverageState::Claimed);

        // The owner string is read from the frozen contract rather than
        // restated here: a hard-coded owner would only prove that the test
        // agrees with itself.
        let bound = frozen_bottleneck_owner_map()
            .into_iter()
            .find(|b| b.bottleneck == STORE_CONNECTION_BOTTLENECK)
            .expect("frozen connection owner");
        assert_eq!(row.owner_ref, bound.owner);

        // This owner claims no emergency partition.
        assert!(row.emergency_limit.is_none());
    }

    /// The Store owner must publish a live, validated
    /// [`BottleneckCapacityProfile`] row for the Kernel profile composition to
    /// join (issue #1679): the row names exactly
    /// [`STORE_TRANSACTION_BOTTLENECK`] with the frozen-map owner, so the
    /// composition joins real owner evidence rather than a borrowed or
    /// invented capacity story.
    #[test]
    fn store_publish_claimed_row_names_frozen_transaction_owner() {
        let reserve = StoreReserve::partitioned(
            4,
            4,
            1,
            2,
            NonZeroU64::new(8).expect("bytes"),
            NonZeroU64::new(8).expect("bytes"),
        )
        .expect("reserve");

        // A returned row already passed `row.validate()`, so a contract
        // failure here would be the fail-closed property itself.
        let row = reserve
            .publish_claimed_row(
                StoreDimension::TransactionSlots,
                "gen-7",
                "proof-store-2",
                "ev-store-2",
                "inv-store-2",
            )
            .expect("claimed row");

        assert_eq!(row.bottleneck, STORE_TRANSACTION_BOTTLENECK);
        assert_eq!(row.coverage_state, BottleneckCoverageState::Claimed);

        // The owner string is read from the frozen contract rather than
        // restated here: a hard-coded owner would only prove that the test
        // agrees with itself.
        let bound = frozen_bottleneck_owner_map()
            .into_iter()
            .find(|b| b.bottleneck == STORE_TRANSACTION_BOTTLENECK)
            .expect("frozen transaction owner");
        assert_eq!(row.owner_ref, bound.owner);

        // This owner claims no emergency partition.
        assert!(row.emergency_limit.is_none());
    }

    /// The Store owner must publish a live, validated
    /// [`BottleneckCapacityProfile`] row for the Kernel profile composition to
    /// join (issue #1679): the row names exactly
    /// [`STORE_PENDING_WRITE_BOTTLENECK`] with the frozen-map owner, so the
    /// composition joins real owner evidence rather than a borrowed or
    /// invented capacity story.
    #[test]
    fn store_publish_claimed_row_names_frozen_pending_owner() {
        let reserve = StoreReserve::partitioned(
            4,
            4,
            1,
            2,
            NonZeroU64::new(8).expect("bytes"),
            NonZeroU64::new(8).expect("bytes"),
        )
        .expect("reserve");

        // A returned row already passed `row.validate()`, so a contract
        // failure here would be the fail-closed property itself.
        let row = reserve
            .publish_claimed_row(
                StoreDimension::PendingWriteMemory,
                "gen-7",
                "proof-store-3",
                "ev-store-3",
                "inv-store-3",
            )
            .expect("claimed row");

        assert_eq!(row.bottleneck, STORE_PENDING_WRITE_BOTTLENECK);
        assert_eq!(row.coverage_state, BottleneckCoverageState::Claimed);

        // The owner string is read from the frozen contract rather than
        // restated here: a hard-coded owner would only prove that the test
        // agrees with itself.
        let bound = frozen_bottleneck_owner_map()
            .into_iter()
            .find(|b| b.bottleneck == STORE_PENDING_WRITE_BOTTLENECK)
            .expect("frozen pending owner");
        assert_eq!(row.owner_ref, bound.owner);

        // This owner claims no emergency partition.
        assert!(row.emergency_limit.is_none());
    }

    /// The Store constructor floor (issue #1679): a reserve with no
    /// normal connection partition can never admit Store work, so
    /// building one must fail at build (I14.3: partitions are
    /// non-borrowable; zero capacity is a build error, not a
    /// runtime surprise).
    #[test]
    fn store_partitioned_zero_normal_connections_fails_closed() {
        let Err(err) = StoreReserve::partitioned(
            0,
            4,
            1,
            2,
            NonZeroU64::new(8).expect("bytes"),
            NonZeroU64::new(8).expect("bytes"),
        ) else {
            panic!("zero normal connections must fail at build");
        };
        assert!(matches!(
            err,
            StoreReserveError::InvalidField {
                field: "store_reserve.normal_connection_slots",
                ..
            }
        ));
    }

    /// The Store constructor floor (issue #1679) applies to the transaction
    /// partition exactly as it does to the connection partition: a reserve
    /// with no normal transaction partition can never admit Store work, so
    /// building one must fail at build (I14.3: partitions are non-borrowable;
    /// zero capacity is a build error, not a runtime surprise).
    #[test]
    fn store_partitioned_zero_normal_transactions_fails_closed() {
        let Err(err) = StoreReserve::partitioned(
            4,
            4,
            0,
            2,
            NonZeroU64::new(8).expect("bytes"),
            NonZeroU64::new(8).expect("bytes"),
        ) else {
            panic!("zero normal transactions must fail at build");
        };
        assert!(matches!(
            err,
            StoreReserveError::InvalidField {
                field: "store_reserve.normal_transaction_slots",
                ..
            }
        ));
    }

    /// Owner-identity validation at acquisition (issue #1679 A10): every
    /// permit binds owner and operation identity, so a blank owner is
    /// refused by name at acquisition instead of yielding a permit that
    /// carries no accountable owner (I14.3).
    #[test]
    fn store_acquire_rejects_blank_owner() {
        let reserve = StoreReserve::partitioned(
            4,
            4,
            1,
            2,
            NonZeroU64::new(8).expect("bytes"),
            NonZeroU64::new(8).expect("bytes"),
        )
        .expect("reserve");

        let Err(err) = reserve.try_acquire_normal_connection(
            NormalWorkClass::CanonicalWrite,
            "",
            "op-owner-1",
        ) else {
            panic!("blank owner must never hold a permit");
        };
        assert!(matches!(
            err,
            StoreReserveError::InvalidField {
                field: "store_permit.owner",
                ..
            }
        ));
    }

    /// Owner-identity validation at publication (issue #1679 A10/W1): a claimed
    /// row is never published under a blank owner-generation reference, because
    /// the evidence row would name no accountable generation once it became
    /// visible to readers (I14.3).
    #[test]
    fn store_publish_claimed_row_rejects_blank_generation() {
        let reserve = StoreReserve::partitioned(
            4,
            4,
            1,
            2,
            NonZeroU64::new(8).expect("bytes"),
            NonZeroU64::new(8).expect("bytes"),
        )
        .expect("reserve");

        let err = reserve
            .publish_claimed_row(
                StoreDimension::ConnectionSlots,
                "",
                "proof-store-1",
                "ev-store-1",
                "inv-store-1",
            )
            .expect_err("blank generation must never publish a row");
        assert!(matches!(
            err,
            StoreReserveError::InvalidField {
                field: "store_evidence.owner_generation_ref",
                ..
            }
        ));
    }

    /// Protected-partition exhaustion names its dimension (issue #1679 A6/W4).
    /// The single protected connection slot is filled first and its permit is
    /// held across the assertions, so the refusal observes a live saturated
    /// partition rather than a released one. The refusal names
    /// `STORE_CONNECTION_BOTTLENECK`: exhaustion of one dimension is a local
    /// disposition, never a global one (I14.3).
    #[test]
    fn store_protected_connection_exhaustion_names_bottleneck() {
        let reserve = StoreReserve::partitioned(
            4,
            1,
            1,
            2,
            NonZeroU64::new(8).expect("bytes"),
            NonZeroU64::new(8).expect("bytes"),
        )
        .expect("reserve");

        // Held for the whole test: the permit releases on drop.
        let _held = reserve
            .try_acquire_protected_connection(
                ControlOperationClass::CancelOperation,
                "owner-a",
                "op-conn-fill-1",
            )
            .expect("protected slot");
        assert_eq!(reserve.available_protected_connections(), 0);

        let Err(err) = reserve.try_acquire_protected_connection(
            ControlOperationClass::CancelOperation,
            "owner-a",
            "op-conn-shed-1",
        ) else {
            panic!("saturated protected partition must refuse");
        };
        assert!(
            matches!(err, StoreReserveError::ProtectedReserveExhausted { bottleneck, .. } if bottleneck == STORE_CONNECTION_BOTTLENECK)
        );
    }

    /// Protected-partition exhaustion names its dimension (issue #1679 A6/W4).
    /// The single protected transaction slot is filled first and its permit
    /// is held across the assertions, so the refusal observes a live
    /// saturated partition rather than a released one. The refusal names
    /// `STORE_TRANSACTION_BOTTLENECK`: exhaustion of one dimension is a
    /// local disposition, never a global one (I14.3).
    #[test]
    fn store_protected_transaction_exhaustion_names_bottleneck() {
        let reserve = StoreReserve::partitioned(
            4,
            4,
            1,
            1,
            NonZeroU64::new(8).expect("bytes"),
            NonZeroU64::new(8).expect("bytes"),
        )
        .expect("reserve");

        // Held for the whole test: the permit releases on drop.
        let _held = reserve
            .try_acquire_protected_transaction(
                ControlOperationClass::CancelOperation,
                "owner-a",
                "op-tx-fill-1",
            )
            .expect("protected slot");
        assert_eq!(reserve.available_protected_transactions(), 0);

        let Err(err) = reserve.try_acquire_protected_transaction(
            ControlOperationClass::CancelOperation,
            "owner-a",
            "op-tx-shed-1",
        ) else {
            panic!("saturated protected partition must refuse");
        };
        assert!(
            matches!(err, StoreReserveError::ProtectedReserveExhausted { bottleneck, .. } if bottleneck == STORE_TRANSACTION_BOTTLENECK)
        );
    }

    /// Protected-partition exhaustion names its dimension (issue #1679 A6/W4).
    /// The single protected pending-write byte is filled first and its permit
    /// is held across the assertions, so the refusal observes a live
    /// saturated partition rather than a released one. The refusal names
    /// `STORE_PENDING_WRITE_BOTTLENECK`: exhaustion of one dimension is a
    /// local disposition, never a global one (I14.3).
    #[test]
    fn store_protected_pending_exhaustion_names_bottleneck() {
        let reserve = StoreReserve::partitioned(
            4,
            4,
            1,
            1,
            NonZeroU64::new(8).expect("bytes"),
            NonZeroU64::new(1).expect("bytes"),
        )
        .expect("reserve");

        // Held for the whole test: the permit releases on drop.
        let _held = reserve
            .try_acquire_protected_pending_write_bytes(
                ControlOperationClass::CancelOperation,
                "owner-a",
                "op-pend-fill-1",
                NonZeroU64::new(1).expect("bytes"),
            )
            .expect("protected bytes");
        assert_eq!(reserve.available_protected_pending_write_bytes(), 0);

        let Err(err) = reserve.try_acquire_protected_pending_write_bytes(
            ControlOperationClass::CancelOperation,
            "owner-a",
            "op-pend-shed-1",
            NonZeroU64::new(1).expect("bytes"),
        ) else {
            panic!("saturated protected partition must refuse");
        };
        assert!(
            matches!(err, StoreReserveError::ProtectedReserveExhausted { bottleneck, .. } if bottleneck == STORE_PENDING_WRITE_BOTTLENECK)
        );
    }

    /// No-scaling construction (issue #1679): a fresh reserve reports
    /// exactly its configured partition capacities (I14.3: quantities
    /// are copied from configuration, never derived or scaled).
    #[test]
    fn store_reserve_reports_configured_capacities() {
        let reserve = StoreReserve::partitioned(
            3,
            5,
            7,
            9,
            NonZeroU64::new(11).expect("bytes"),
            NonZeroU64::new(13).expect("bytes"),
        )
        .expect("reserve");
        assert_eq!(reserve.available_normal_connections(), 3);
        assert_eq!(reserve.available_protected_connections(), 5);
        assert_eq!(reserve.available_normal_transactions(), 7);
        assert_eq!(reserve.available_protected_transactions(), 9);
        assert_eq!(reserve.available_normal_pending_write_bytes(), 11);
        assert_eq!(reserve.available_protected_pending_write_bytes(), 13);
    }
}
