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
//! Owner-issued permit evidence (issue #1679, W4) rides on
//! [`OrsReserve::issue_permit`]: the owner validates one canonical
//! [`CapacityRequest`] carrying the exact bottleneck, unit and amount under
//! its typed [`RequestedOperationClass`] tag, acquires from the tagged
//! partition, and returns the non-clone [`OrsPermit`] together with the
//! owner-minted [`CapacityPermitBinding`]. The tag alone selects the
//! partition — `Normal` draws only the normal partition, `Protected` only
//! the protected partition — so a normal Store write, named read, agent or
//! maintenance admission can never acquire protected ORS capacity by
//! relabelling priority or class: relabelling is unrepresentable, not merely
//! refused. The binding matches its request only through
//! [`CapacityPermitBinding::matches_request`]; changed content conflicts
//! instead of replaying. This owner holds no emergency partition, so an
//! `Emergency` tag is refused with a typed denial; recording reserve loss
//! stays with the front-door last-resort slot.
//! DISCLOSED LIMIT: `owner_generation`, the request epoch, the profile
//! identity/revision and the issue clock are composition-supplied and echoed
//! into the binding; this module opens no clock, reads no profile and holds
//! no live Authority Epoch source, so epoch/generation/profile staleness is
//! decided by the Kernel composition through `matches_request` and the
//! profile join, exactly as the W2 compiler already does for owner rows.
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
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use eliot_contracts::{ArtifactId, OperationId, ResourceGeneration};
use eliot_runtime_contracts::{
    AffectedOperationClass, BackpressureDisposition, BottleneckAvailability,
    BottleneckCoverageState, BottleneckObservationV1, CapacityBottleneck, CapacityClass,
    CapacityPermitBinding, CapacityRequest, ControlOperationClass, EarliestRecoveryCondition,
    EmergencyOperationClass, EvidenceCoverageState, HumanActionRequirement,
    I14_BACKPRESSURE_RESPONSE_VERSION, I14BackpressureCause, I14BackpressureResponseV1,
    I14CurrentnessState, I14EscalationCondition, I14ForbiddenAction, I14RecoveryAction,
    I14RecoveryDirectiveV1, I14RequiredAuthority, I14ResolutionState, I14WorkOutcome,
    NormalWorkClass, RecoveryCommitStatus, RequestedOperationClass, StatePreservationStatus,
    frozen_bottleneck_owner_map,
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
    /// The request names the emergency class, which this owner cannot issue.
    ///
    /// The ORS reserve holds no emergency partition, so no counter is touched
    /// and no capacity is consumed; recording reserve loss stays with the
    /// front-door last-resort slot.
    #[error(
        "ORS emergency capacity not issuable for {bottleneck:?}: emergency operation {operation:?} operation {operation_id} owned by {owner}"
    )]
    EmergencyNotIssuable {
        /// Bottleneck whose emergency capacity was requested.
        bottleneck: CapacityBottleneck,
        /// Emergency operation that was not admitted.
        operation: EmergencyOperationClass,
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
    /// Owner-minted permit sequence; never reset, so two issuances never
    /// share a permit identity.
    permit_sequence: AtomicU64,
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
                permit_sequence: AtomicU64::new(0),
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

    /// Issues one owner-bound permit for a validated capacity request.
    ///
    /// The W4 request/issue path for the two ORS bottlenecks: the request
    /// names the exact bottleneck, unit and amount under its typed
    /// [`RequestedOperationClass`] tag, and the owner returns the non-clone
    /// [`OrsPermit`] together with the minted [`CapacityPermitBinding`]. The
    /// tag alone selects the partition — `Normal` draws only the normal
    /// partition, `Protected` only the protected partition — so no priority
    /// or class relabelling can move a normal Store write, named read, agent
    /// or maintenance operation onto protected ORS capacity. An `Emergency`
    /// tag is refused with [`OrsReserveError::EmergencyNotIssuable`]: this
    /// owner holds no emergency partition. The binding matches its request
    /// only through [`CapacityPermitBinding::matches_request`]; changed
    /// content conflicts instead of replaying.
    ///
    /// The caller supplies its clock (`now_ms`) and the issuing owner
    /// generation: the reserve owns no generation counter and no clock, so
    /// both bindings arrive with the call. The request epoch and profile
    /// identity/revision are recorded as presented; this owner holds no live
    /// Authority Epoch source, so staleness against current evidence is
    /// decided by the Kernel composition through `matches_request` and the
    /// profile join. The binding carries no wall-clock expiry (`u64::MAX`);
    /// the permit lifetime is the handle lifetime (drop) and staleness is
    /// fenced by epoch, profile revision and generations.
    ///
    /// # Errors
    ///
    /// Returns [`OrsReserveError::Contract`] when the request or the minted
    /// binding fails the existing contract validation,
    /// [`OrsReserveError::InvalidField`] when the request names another
    /// owner's bottleneck, when a transaction request names an amount other
    /// than one slot (this owner issues single-slot transaction permits; hold
    /// one permit per slot), or when the issuing clock is negative,
    /// [`OrsReserveError::EmergencyNotIssuable`] for the emergency class, or
    /// the tagged saturation disposition
    /// ([`OrsReserveError::NormalCapacityExhausted`]/
    /// [`OrsReserveError::ProtectedReserveExhausted`]) naming the exact
    /// bottleneck.
    pub fn issue_permit(
        &self,
        request: &CapacityRequest,
        owner_generation: ResourceGeneration,
        now_ms: i64,
    ) -> Result<(OrsPermit, CapacityPermitBinding), OrsReserveError> {
        request
            .validate()
            .map_err(|error| OrsReserveError::Contract(error.to_string()))?;
        if request.requested_bottleneck != ORS_TRANSACTION_BOTTLENECK
            && request.requested_bottleneck != ORS_DURABLE_BYTES_BOTTLENECK
        {
            return Err(OrsReserveError::InvalidField {
                field: "capacity_request.requested_bottleneck",
                reason: "this owner enforces only ORS_TRANSACTION_SLOTS and ORS_DURABLE_QUEUE_BYTES; no other dimension is issuable here",
            });
        }
        if request.requested_bottleneck == ORS_TRANSACTION_BOTTLENECK
            && request.requested_limit.quantity.get() != 1
        {
            return Err(OrsReserveError::InvalidField {
                field: "capacity_request.requested_limit",
                reason: "the ORS owner issues single-slot transaction permits; hold one permit per slot",
            });
        }
        let issued_at_ms = u64::try_from(now_ms).map_err(|_| OrsReserveError::InvalidField {
            field: "capacity_request.issued_at_ms",
            reason: "the issuing clock must be non-negative",
        })?;
        let owner = frozen_bottleneck_owner_map()
            .into_iter()
            .find(|bound| bound.bottleneck == request.requested_bottleneck)
            .ok_or(OrsReserveError::InvalidField {
                field: "capacity_request.requested_bottleneck",
                reason: "the frozen owner map binds no ORS owner to the requested dimension",
            })?;
        let dimension = if request.requested_bottleneck == ORS_TRANSACTION_BOTTLENECK {
            OrsDimension::TransactionSlots
        } else {
            OrsDimension::DurableQueueBytes
        };
        let permit = match request.operation {
            RequestedOperationClass::Normal(work) => match dimension {
                OrsDimension::TransactionSlots => self.try_acquire_normal_transaction(
                    work,
                    &request.requesting_owner_ref,
                    &request.operation_id,
                )?,
                OrsDimension::DurableQueueBytes => self.try_acquire_normal_durable_bytes(
                    work,
                    &request.requesting_owner_ref,
                    &request.operation_id,
                    request.requested_limit.quantity,
                )?,
            },
            RequestedOperationClass::Protected(operation) => match dimension {
                OrsDimension::TransactionSlots => self.try_acquire_protected_transaction(
                    operation,
                    &request.requesting_owner_ref,
                    &request.operation_id,
                )?,
                OrsDimension::DurableQueueBytes => self.try_acquire_protected_durable_bytes(
                    operation,
                    &request.requesting_owner_ref,
                    &request.operation_id,
                    request.requested_limit.quantity,
                )?,
            },
            RequestedOperationClass::Emergency(operation) => {
                return Err(OrsReserveError::EmergencyNotIssuable {
                    bottleneck: request.requested_bottleneck,
                    operation,
                    operation_id: request.operation_id.clone(),
                    owner: request.requesting_owner_ref.clone(),
                });
            }
        };
        let sequence = self.inner.permit_sequence.fetch_add(1, Ordering::AcqRel);
        let binding = CapacityPermitBinding {
            permit_id: format!(
                "ORS-{}-{sequence}-{}",
                request.operation.as_contract_str(),
                request.operation_id
            ),
            operation_id: request.operation_id.clone(),
            capacity_class: request.operation.capacity_class(),
            operation: request.operation,
            bottleneck: request.requested_bottleneck,
            granted_limit: request.requested_limit,
            capacity_owner_ref: owner.owner.to_owned(),
            capacity_owner_generation_ref: owner_generation,
            requesting_owner_ref: request.requesting_owner_ref.clone(),
            requesting_generation_ref: request.requesting_generation_ref,
            authority_epoch_ref: request.authority_epoch_ref.clone(),
            profile_id: request.profile_id.clone(),
            profile_revision: request.profile_revision.clone(),
            issued_at_ms,
            expires_at_ms: u64::MAX,
            owner_evidence_refs: vec![
                self.issue_evidence(dimension, request.operation.capacity_class())
            ],
        };
        debug_assert!(
            binding.validate().is_ok(),
            "ORS minted permit binding must satisfy the contract"
        );
        debug_assert!(
            binding.matches_request(request),
            "ORS minted permit binding must match its request"
        );
        Ok((permit, binding))
    }

    /// Records the owner's contemporaneous partition observation for one issuance.
    fn issue_evidence(&self, dimension: OrsDimension, class: CapacityClass) -> String {
        let (bottleneck, capacity, available) = match (dimension, class) {
            (OrsDimension::TransactionSlots, CapacityClass::NormalWorkload) => (
                ORS_TRANSACTION_BOTTLENECK,
                self.inner.transaction_normal_capacity,
                self.available_normal_transactions(),
            ),
            (OrsDimension::TransactionSlots, _) => (
                ORS_TRANSACTION_BOTTLENECK,
                self.inner.transaction_protected_capacity,
                self.available_protected_transactions(),
            ),
            (OrsDimension::DurableQueueBytes, CapacityClass::NormalWorkload) => (
                ORS_DURABLE_BYTES_BOTTLENECK,
                self.inner.durable_normal_capacity_bytes,
                self.available_normal_durable_bytes(),
            ),
            (OrsDimension::DurableQueueBytes, _) => (
                ORS_DURABLE_BYTES_BOTTLENECK,
                self.inner.durable_protected_capacity_bytes,
                self.available_protected_durable_bytes(),
            ),
        };
        format!(
            "ors-reserve:{}:{} capacity {capacity} in-flight {}",
            bottleneck.as_contract_str(),
            class.as_contract_str(),
            capacity.saturating_sub(available),
        )
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
