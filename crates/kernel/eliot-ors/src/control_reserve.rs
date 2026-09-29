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
//! Every [`OrsPermit`] is owner-issued non-clone evidence bound to permit and
//! operation identities, capacity/operation class, issuing owner generation,
//! requester generation, exact bottleneck/unit/granted amount, profile
//! revision, typed Authority Epoch, issue/expiry and owner-derived evidence.
//! A caller-provided queue position, PID, process survival or copied profile
//! row is not a permit: only [`OrsPermitOperation`] typechecks on the
//! acquisition paths, and every binding is recorded by the owner at issue.
//! Stale profile/generation/epoch comparison belongs to the Kernel
//! composition (contract admission step 1: validate exact
//! profile/product/config/generation identity): the owner records the
//! bindings, the composer validates them against current evidence.
//! DISCLOSED LIMIT: `owner_generation`, `requester_generation`,
//! `profile_revision`, `epoch` and the issue/expiry timestamps are
//! composition-supplied and echoed into the permit; this module opens no clock
//! and reads no profile.
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

use eliot_contracts::{ArtifactId, AuthorityEpoch, OperationId, ResourceGeneration};
use eliot_runtime_contracts::{
    AffectedOperationClass, BackpressureDisposition, BottleneckAvailability,
    BottleneckCoverageState, BottleneckObservationV1, CapacityBottleneck, CapacityClass,
    CapacityUnit, ControlOperationClass, EarliestRecoveryCondition, EvidenceCoverageState,
    HumanActionRequirement, I14_BACKPRESSURE_RESPONSE_VERSION, I14BackpressureCause,
    I14BackpressureResponseV1, I14CurrentnessState, I14EscalationCondition, I14ForbiddenAction,
    I14RecoveryAction, I14RecoveryDirectiveV1, I14RequiredAuthority, I14ResolutionState,
    I14WorkOutcome, NormalWorkClass, RecoveryCommitStatus, StatePreservationStatus,
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

/// Owner-supplied bindings for one [`OrsPermit`] acquisition (issue #1679, W4).
///
/// The bundle keeps the typed acquisition paths at two arguments: the closed
/// operation class plus this evidence record. Every field is recorded into the
/// issued permit by the owner; nothing is inferred from a live process, PID,
/// queue entry or surviving counter. Profile/generation/epoch values are
/// composition-supplied current evidence (contract admission step 1); the
/// Kernel composition validates them, this owner records them.
#[derive(Clone, Debug)]
pub struct OrsPermitRequest<'a> {
    /// Requesting owner label (validated non-blank, bounded).
    pub owner: &'a str,
    /// Operation identity the permit is granted for.
    pub operation_id: &'a str,
    /// Owner-issued permit identity, distinct from the operation identity.
    pub permit_id: &'a str,
    /// Issuing ORS owner generation (owner side of the frozen owner binding).
    pub owner_generation: ResourceGeneration,
    /// Requesting owner's generation.
    pub requester_generation: ResourceGeneration,
    /// Profile revision the request was admitted under.
    pub profile_revision: ArtifactId,
    /// Typed Authority Epoch the request was admitted under.
    pub epoch: AuthorityEpoch,
    /// Caller-observed issue time (Unix millis); no clock is opened here.
    pub issued_at_ms: i64,
    /// Caller-observed expiry (Unix millis), if the grant expires.
    pub expires_at_ms: Option<i64>,
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
    permit_id: OperationId,
    operation_id: String,
    owner: String,
    owner_generation: ResourceGeneration,
    requester_generation: ResourceGeneration,
    profile_revision: ArtifactId,
    epoch: AuthorityEpoch,
    issued_at_ms: i64,
    expires_at_ms: Option<i64>,
    owner_evidence: String,
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

    /// Returns the owner-issued permit identity, distinct from the operation identity.
    #[must_use]
    pub fn permit_id(&self) -> &str {
        self.permit_id.as_str()
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

    /// Returns the issuing ORS owner generation recorded at issue.
    #[must_use]
    pub const fn owner_generation(&self) -> ResourceGeneration {
        self.owner_generation
    }

    /// Returns the requesting owner's generation recorded at issue.
    #[must_use]
    pub const fn requester_generation(&self) -> ResourceGeneration {
        self.requester_generation
    }

    /// Returns the profile revision recorded at issue.
    #[must_use]
    pub fn profile_revision(&self) -> &str {
        self.profile_revision.as_str()
    }

    /// Returns the typed Authority Epoch recorded at issue.
    #[must_use]
    pub const fn epoch(&self) -> AuthorityEpoch {
        self.epoch
    }

    /// Returns the caller-observed issue time recorded at issue (Unix millis).
    #[must_use]
    pub const fn issued_at_ms(&self) -> i64 {
        self.issued_at_ms
    }

    /// Returns the caller-observed expiry recorded at issue, if the grant expires.
    #[must_use]
    pub const fn expires_at_ms(&self) -> Option<i64> {
        self.expires_at_ms
    }

    /// Returns the owner-derived evidence reference recorded at issue.
    #[must_use]
    pub fn owner_evidence(&self) -> &str {
        &self.owner_evidence
    }

    /// Returns the exact unit of the bottleneck this permit was granted from.
    #[must_use]
    pub const fn unit(&self) -> CapacityUnit {
        self.dimension.bottleneck().unit()
    }

    /// Returns `true` only when every presented binding matches the recorded
    /// evidence: same operation identity, same owner, same Authority Epoch
    /// and same profile revision. Changed content never matches; the owner
    /// refuses consumption before it happens and the composition treats a
    /// mismatch as a conflict, never as a replay.
    #[must_use]
    pub fn binding_matches(
        &self,
        operation_id: &str,
        owner: &str,
        epoch: AuthorityEpoch,
        profile_revision: &ArtifactId,
    ) -> bool {
        self.operation_id == operation_id
            && self.owner == owner
            && self.epoch == epoch
            && self.profile_revision == *profile_revision
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
    /// Validates the caller-presented bindings of one permit request before
    /// any partition counter is touched. Returns the validated permit
    /// identity for the issuing constructor.
    fn checked_request(request: &OrsPermitRequest<'_>) -> Result<OperationId, OrsReserveError> {
        validate_text(request.owner, "ors_permit.owner").map_err(|_| {
            OrsReserveError::InvalidField {
                field: "ors_permit.owner",
                reason: "must be non-blank",
            }
        })?;
        validate_text(request.operation_id, "ors_permit.operation_id").map_err(|_| {
            OrsReserveError::InvalidField {
                field: "ors_permit.operation_id",
                reason: "must be non-blank",
            }
        })?;
        let permit_id =
            OperationId::new(request.permit_id).map_err(|_| OrsReserveError::InvalidField {
                field: "ors_permit.permit_id",
                reason: "must be a bounded non-blank reference",
            })?;
        if let Some(expires_at_ms) = request.expires_at_ms {
            if expires_at_ms <= request.issued_at_ms {
                return Err(OrsReserveError::InvalidField {
                    field: "ors_permit.expires_at_ms",
                    reason: "must be after issued_at_ms",
                });
            }
        }
        Ok(permit_id)
    }

    /// Issues the owner-bound permit after the partition counter was claimed.
    /// The evidence reference is derived by the owner from the claimed
    /// partition and the recorded bindings; callers cannot supply it.
    fn issue_permit(
        inner: Arc<OrsReserveInner>,
        dimension: OrsDimension,
        class: CapacityClass,
        amount: u64,
        operation: OrsPermitOperation,
        request: &OrsPermitRequest<'_>,
        permit_id: OperationId,
    ) -> OrsPermit {
        let owner_evidence = format!(
            "ors-reserve/{:?}/{:?}/owner-gen-{}/req-gen-{}/amt-{amount}",
            dimension.bottleneck(),
            class,
            request.owner_generation.value(),
            request.requester_generation.value(),
        );
        OrsPermit {
            inner,
            dimension,
            class,
            amount,
            operation,
            permit_id,
            operation_id: request.operation_id.to_owned(),
            owner: request.owner.to_owned(),
            owner_generation: request.owner_generation,
            requester_generation: request.requester_generation,
            profile_revision: request.profile_revision.clone(),
            epoch: request.epoch,
            issued_at_ms: request.issued_at_ms,
            expires_at_ms: request.expires_at_ms,
            owner_evidence,
        }
    }

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
    /// capacity is unreachable through this path by construction. The issued
    /// [`OrsPermit`] records the full owner evidence from `request`:
    /// permit/operation identities, owner and requester generations, exact
    /// bottleneck/unit/amount, profile revision, Authority Epoch, issue/expiry
    /// and owner-derived evidence.
    ///
    /// # Errors
    ///
    /// Returns [`OrsReserveError::InvalidField`] for a blank owner/operation/
    /// permit identity or an expiry that does not follow issue, or
    /// [`OrsReserveError::NormalCapacityExhausted`] naming the transaction
    /// bottleneck and shed work when the normal partition is saturated. The
    /// protected partition is untouched in every case.
    pub fn try_acquire_normal_transaction(
        &self,
        work: NormalWorkClass,
        request: OrsPermitRequest<'_>,
    ) -> Result<OrsPermit, OrsReserveError> {
        let permit_id = Self::checked_request(&request)?;
        if !cas_add(
            &self.inner.transaction_normal_in_flight,
            self.inner.transaction_normal_capacity,
            1,
        ) {
            return Err(OrsReserveError::NormalCapacityExhausted {
                bottleneck: ORS_TRANSACTION_BOTTLENECK,
                work_class: work,
                operation_id: request.operation_id.to_owned(),
                owner: request.owner.to_owned(),
            });
        }
        Ok(Self::issue_permit(
            self.inner.clone(),
            OrsDimension::TransactionSlots,
            CapacityClass::NormalWorkload,
            1,
            OrsPermitOperation::Normal(work),
            &request,
            permit_id,
        ))
    }

    /// Attempts to acquire `bytes` normal durable bytes without blocking.
    ///
    /// Only [`NormalWorkClass`] operations typecheck here, so protected ORS
    /// durable capacity is unreachable through this path by construction. The
    /// issued [`OrsPermit`] records the full owner evidence from `request`.
    ///
    /// # Errors
    ///
    /// Returns [`OrsReserveError::InvalidField`] for a blank owner/operation/
    /// permit identity or an expiry that does not follow issue, or
    /// [`OrsReserveError::NormalCapacityExhausted`] naming the durable-byte
    /// bottleneck and shed work when the normal partition cannot satisfy the
    /// request. The protected partition is untouched in every case.
    pub fn try_acquire_normal_durable_bytes(
        &self,
        work: NormalWorkClass,
        request: OrsPermitRequest<'_>,
        bytes: NonZeroU64,
    ) -> Result<OrsPermit, OrsReserveError> {
        let permit_id = Self::checked_request(&request)?;
        if !cas_add(
            &self.inner.durable_normal_in_flight_bytes,
            self.inner.durable_normal_capacity_bytes,
            bytes.get(),
        ) {
            return Err(OrsReserveError::NormalCapacityExhausted {
                bottleneck: ORS_DURABLE_BYTES_BOTTLENECK,
                work_class: work,
                operation_id: request.operation_id.to_owned(),
                owner: request.owner.to_owned(),
            });
        }
        Ok(Self::issue_permit(
            self.inner.clone(),
            OrsDimension::DurableQueueBytes,
            CapacityClass::NormalWorkload,
            bytes.get(),
            OrsPermitOperation::Normal(work),
            &request,
            permit_id,
        ))
    }

    /// Attempts to acquire one protected transaction slot without blocking.
    ///
    /// Only [`ControlOperationClass`] operations typecheck here: a normal
    /// Store write, named read, agent admission or module job cannot name a
    /// protected operation and therefore cannot acquire this partition. This
    /// is the path an admitted cancellation/recovery record keeps while
    /// normal transaction work is saturated. The issued [`OrsPermit`] records
    /// the full owner evidence from `request`.
    ///
    /// # Errors
    ///
    /// Returns [`OrsReserveError::InvalidField`] for a blank owner/operation/
    /// permit identity or an expiry that does not follow issue, or
    /// [`OrsReserveError::ProtectedReserveExhausted`] naming the transaction
    /// bottleneck, operation, owner and request when the protected partition
    /// is saturated.
    pub fn try_acquire_protected_transaction(
        &self,
        operation: ControlOperationClass,
        request: OrsPermitRequest<'_>,
    ) -> Result<OrsPermit, OrsReserveError> {
        let permit_id = Self::checked_request(&request)?;
        if !cas_add(
            &self.inner.transaction_protected_in_flight,
            self.inner.transaction_protected_capacity,
            1,
        ) {
            return Err(OrsReserveError::ProtectedReserveExhausted {
                bottleneck: ORS_TRANSACTION_BOTTLENECK,
                operation,
                operation_id: request.operation_id.to_owned(),
                owner: request.owner.to_owned(),
            });
        }
        Ok(Self::issue_permit(
            self.inner.clone(),
            OrsDimension::TransactionSlots,
            CapacityClass::ProtectedControl,
            1,
            OrsPermitOperation::Protected(operation),
            &request,
            permit_id,
        ))
    }

    /// Attempts to acquire `bytes` protected durable bytes without blocking.
    ///
    /// Only [`ControlOperationClass`] operations typecheck here. This is the
    /// path an admitted cancellation/recovery record keeps while normal
    /// durable-byte work reports `STORAGE_BACKPRESSURE`. The issued
    /// [`OrsPermit`] records the full owner evidence from `request`.
    ///
    /// # Errors
    ///
    /// Returns [`OrsReserveError::InvalidField`] for a blank owner/operation/
    /// permit identity or an expiry that does not follow issue, or
    /// [`OrsReserveError::ProtectedReserveExhausted`] naming the durable-byte
    /// bottleneck, operation, owner and request when the protected partition
    /// cannot satisfy the request.
    pub fn try_acquire_protected_durable_bytes(
        &self,
        operation: ControlOperationClass,
        request: OrsPermitRequest<'_>,
        bytes: NonZeroU64,
    ) -> Result<OrsPermit, OrsReserveError> {
        let permit_id = Self::checked_request(&request)?;
        if !cas_add(
            &self.inner.durable_protected_in_flight_bytes,
            self.inner.durable_protected_capacity_bytes,
            bytes.get(),
        ) {
            return Err(OrsReserveError::ProtectedReserveExhausted {
                bottleneck: ORS_DURABLE_BYTES_BOTTLENECK,
                operation,
                operation_id: request.operation_id.to_owned(),
                owner: request.owner.to_owned(),
            });
        }
        Ok(Self::issue_permit(
            self.inner.clone(),
            OrsDimension::DurableQueueBytes,
            CapacityClass::ProtectedControl,
            bytes.get(),
            OrsPermitOperation::Protected(operation),
            &request,
            permit_id,
        ))
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
