//! Store control-reserve partitions for connections, transactions and pending-write memory.
//!
//! Issue #1679, W3 Store wave: the Store bridge generation enforces disjoint
//! normal-workload and protected-control partitions for its three frozen
//! bottlenecks ([`STORE_CONNECTION_BOTTLENECK`],
//! [`STORE_TRANSACTION_BOTTLENECK`] and [`STORE_PENDING_WRITE_BOTTLENECK`]).
//! Normal work can saturate the normal partition without consuming protected
//! cancellation/recovery capacity: an admitted cancellation or recovery record
//! keeps the protected Store path while ordinary work observes exhaustion.
//! Only [`NormalWorkClass`] operations typecheck on the normal acquisition
//! paths and only [`ControlOperationClass`] operations typecheck on the
//! protected paths, so ordinary work cannot reach protected Store capacity by
//! relabelling its priority or class.
//!
//! Exhausted normal capacity renders as a versioned
//! [`I14BackpressureResponseV1`] with disposition `BUSY` naming exactly the
//! saturated Store bottleneck in its exact unit. `STORAGE_BACKPRESSURE` is not
//! used here: the existing [`I14BackpressureResponseV1::validate`] pins that
//! disposition to the ORS durable queue bytes, so a Store observation would
//! fail closed instead of emitting evidence. Every response is validated by
//! the existing [`I14BackpressureResponseV1::validate`] before it is returned,
//! so an inconsistent observation fails closed instead of emitting a
//! disposition-only or generic queue-full answer. Each response method reads
//! the live reserve it reports and refuses while that reserve still admits
//! the request, so pressure evidence is never manufactured.
//!
//! This module has no production caller yet (STITCH): it publishes the owner
//! evidence the Store profile composition will join. There is no emergency
//! partition here; recording reserve loss stays with the front-door
//! last-resort slot until a later wave wires Store-side loss reporting.
//! DISCLOSED LIMIT: `profile_revision` on the responses is caller-supplied
//! metadata echoed into the directive; the `Current` currentness claim refers
//! to the live-observed saturation at call time, not to a re-read of the
//! profile revision. Full installed-saturation proof stays #11 Product scope.

use std::num::NonZeroU64;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use eliot_contracts::{ArtifactId, OperationId};
use eliot_runtime_contracts::{
    AffectedOperationClass, BackpressureDisposition, BottleneckAvailability,
    BottleneckCoverageState, BottleneckObservationV1, CapacityBottleneck, CapacityClass,
    ControlOperationClass, EarliestRecoveryCondition, EvidenceCoverageState,
    HumanActionRequirement, I14_BACKPRESSURE_RESPONSE_VERSION, I14BackpressureCause,
    I14BackpressureResponseV1, I14CurrentnessState, I14EscalationCondition, I14ForbiddenAction,
    I14RecoveryAction, I14RecoveryDirectiveV1, I14RequiredAuthority, I14ResolutionState,
    I14WorkOutcome, NormalWorkClass, RecoveryCommitStatus, StatePreservationStatus,
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
    /// The existing contract rejected an assembled Store backpressure response.
    #[error("runtime contract rejected Store reserve response: {0}")]
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
    /// Store connection slots, counted in connections.
    ConnectionSlots,
    /// Store transaction slots, counted in transactions.
    TransactionSlots,
    /// Store pending-write memory, counted in bytes.
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
/// saturating normal connections, normal transactions or normal pending-write
/// memory leaves the full protected capacity available for admitted
/// cancellation/recovery records and vice versa. Acquisition is non-blocking
/// and atomic; release is automatic when the returned [`StorePermit`] drops.
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
            "STORE permit drop without a held partition amount"
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
fn validate_text(value: &str, field: &'static str) -> Result<(), StoreReserveError> {
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
    /// Returns [`StoreReserveError::InvalidField`] when any partition capacity
    /// is zero.
    pub fn partitioned(
        normal_connection_slots: u64,
        protected_connection_slots: u64,
        normal_transaction_slots: u64,
        protected_transaction_slots: u64,
        normal_pending_bytes: NonZeroU64,
        protected_pending_bytes: NonZeroU64,
    ) -> Result<Self, StoreReserveError> {
        if normal_connection_slots == 0 {
            return Err(StoreReserveError::InvalidField {
                field: "store_reserve.normal_connection_slots",
                reason: "must be greater than zero",
            });
        }
        if protected_connection_slots == 0 {
            return Err(StoreReserveError::InvalidField {
                field: "store_reserve.protected_connection_slots",
                reason: "must be greater than zero",
            });
        }
        if normal_transaction_slots == 0 {
            return Err(StoreReserveError::InvalidField {
                field: "store_reserve.normal_transaction_slots",
                reason: "must be greater than zero",
            });
        }
        if protected_transaction_slots == 0 {
            return Err(StoreReserveError::InvalidField {
                field: "store_reserve.protected_transaction_slots",
                reason: "must be greater than zero",
            });
        }
        Ok(Self {
            inner: Arc::new(StoreReserveInner {
                connection_normal_capacity: normal_connection_slots,
                connection_protected_capacity: protected_connection_slots,
                transaction_normal_capacity: normal_transaction_slots,
                transaction_protected_capacity: protected_transaction_slots,
                pending_normal_capacity_bytes: normal_pending_bytes.get(),
                pending_protected_capacity_bytes: protected_pending_bytes.get(),
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
    pub fn normal_pending_byte_capacity(&self) -> u64 {
        self.inner.pending_normal_capacity_bytes
    }

    /// Returns the configured protected pending-write-byte partition capacity.
    #[must_use]
    pub fn protected_pending_byte_capacity(&self) -> u64 {
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
    pub fn available_normal_pending_bytes(&self) -> u64 {
        self.inner.pending_normal_capacity_bytes.saturating_sub(
            self.inner
                .pending_normal_in_flight_bytes
                .load(Ordering::Acquire),
        )
    }

    /// Returns the currently available protected pending-write bytes.
    #[must_use]
    pub fn available_protected_pending_bytes(&self) -> u64 {
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
        validate_text(owner, "store_permit.owner")?;
        validate_text(operation_id, "store_permit.operation_id")?;
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
    /// capacity is unreachable through this path by construction.
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
        validate_text(owner, "store_permit.owner")?;
        validate_text(operation_id, "store_permit.operation_id")?;
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
    /// pending-write capacity is unreachable through this path by
    /// construction.
    ///
    /// # Errors
    ///
    /// Returns [`StoreReserveError::InvalidField`] for a blank owner/operation
    /// identity, or [`StoreReserveError::NormalCapacityExhausted`] naming the
    /// pending-write bottleneck and shed work when the normal partition cannot
    /// satisfy the request. The protected partition is untouched in every
    /// case.
    pub fn try_acquire_normal_pending_bytes(
        &self,
        work: NormalWorkClass,
        owner: &str,
        operation_id: &str,
        bytes: NonZeroU64,
    ) -> Result<StorePermit, StoreReserveError> {
        validate_text(owner, "store_permit.owner")?;
        validate_text(operation_id, "store_permit.operation_id")?;
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
    /// Only [`ControlOperationClass`] operations typecheck here: ordinary work
    /// cannot name a protected operation and therefore cannot acquire this
    /// partition. This is the path an admitted cancellation/recovery record
    /// keeps while normal connection work is saturated.
    ///
    /// # Errors
    ///
    /// Returns [`StoreReserveError::InvalidField`] for a blank owner/operation
    /// identity, or [`StoreReserveError::ProtectedReserveExhausted`] naming
    /// the connection bottleneck, operation, owner and request when the
    /// protected partition is saturated.
    pub fn try_acquire_protected_connection(
        &self,
        operation: ControlOperationClass,
        owner: &str,
        operation_id: &str,
    ) -> Result<StorePermit, StoreReserveError> {
        validate_text(owner, "store_permit.owner")?;
        validate_text(operation_id, "store_permit.operation_id")?;
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
    /// Only [`ControlOperationClass`] operations typecheck here: ordinary work
    /// cannot name a protected operation and therefore cannot acquire this
    /// partition. This is the path an admitted cancellation/recovery record
    /// keeps while normal transaction work is saturated.
    ///
    /// # Errors
    ///
    /// Returns [`StoreReserveError::InvalidField`] for a blank owner/operation
    /// identity, or [`StoreReserveError::ProtectedReserveExhausted`] naming
    /// the transaction bottleneck, operation, owner and request when the
    /// protected partition is saturated.
    pub fn try_acquire_protected_transaction(
        &self,
        operation: ControlOperationClass,
        owner: &str,
        operation_id: &str,
    ) -> Result<StorePermit, StoreReserveError> {
        validate_text(owner, "store_permit.owner")?;
        validate_text(operation_id, "store_permit.operation_id")?;
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

    /// Attempts to acquire `bytes` protected pending-write bytes without blocking.
    ///
    /// Only [`ControlOperationClass`] operations typecheck here. This is the
    /// path an admitted cancellation/recovery record keeps while normal
    /// pending-write work reports `BUSY`.
    ///
    /// # Errors
    ///
    /// Returns [`StoreReserveError::InvalidField`] for a blank owner/operation
    /// identity, or [`StoreReserveError::ProtectedReserveExhausted`] naming
    /// the pending-write bottleneck, operation, owner and request when the
    /// protected partition cannot satisfy the request.
    pub fn try_acquire_protected_pending_bytes(
        &self,
        operation: ControlOperationClass,
        owner: &str,
        operation_id: &str,
        bytes: NonZeroU64,
    ) -> Result<StorePermit, StoreReserveError> {
        validate_text(owner, "store_permit.owner")?;
        validate_text(operation_id, "store_permit.operation_id")?;
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

    /// Reports exhausted normal connection slots as a `BUSY` response naming
    /// exactly [`STORE_CONNECTION_BOTTLENECK`].
    ///
    /// The response is built only while
    /// [`Self::available_normal_connections`] is zero: pressure evidence is
    /// never manufactured for a partition that still admits work. The
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
    /// The response is built only while [`Self::available_normal_transactions`]
    /// is zero: pressure evidence is never manufactured for a partition that
    /// still admits work. The protected partition is not read and not
    /// claimed.
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

    /// Reports exhausted normal pending-write memory as a `BUSY` response
    /// naming exactly [`STORE_PENDING_WRITE_BOTTLENECK`].
    ///
    /// The response is built only while the normal pending-write partition
    /// cannot satisfy `requested_bytes`: pressure evidence is never
    /// manufactured for a partition that still admits the request. The
    /// protected partition is not read and not claimed, so an admitted
    /// cancellation/recovery record keeps its path while this response is
    /// live. `BUSY` (not `STORAGE_BACKPRESSURE`) is the honest disposition:
    /// the existing contract validation pins `STORAGE_BACKPRESSURE` to the
    /// ORS durable queue bytes.
    ///
    /// # Errors
    ///
    /// Returns [`StoreReserveError::InvalidField`] when the normal
    /// pending-write partition still satisfies the request or the operation
    /// identity is malformed, or [`StoreReserveError::Contract`] when the
    /// assembled directive fails the existing contract validation.
    pub fn normal_pending_exhaustion_response(
        &self,
        work: NormalWorkClass,
        operation_id: &str,
        profile_revision: ArtifactId,
        requested_bytes: NonZeroU64,
    ) -> Result<I14BackpressureResponseV1, StoreReserveError> {
        let available = self.available_normal_pending_bytes();
        if available >= requested_bytes.get() {
            return Err(StoreReserveError::InvalidField {
                field: "store_reserve.normal_pending_bytes",
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
