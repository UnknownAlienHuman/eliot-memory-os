//! Disk control-reserve partitions for queued artifact writes.
//!
//! Issue #1679, disk wave: the existing single-owner filesystem CAS
//! (artifact/blob) disk owner, the S-04 [`crate::BlobStoreService`] with its
//! root-claim-protected write path, enforces disjoint normal-workload and
//! protected-control partitions for its frozen bottleneck
//! ([`DISK_QUEUE_BOTTLENECK`]). Normal work can saturate the normal partition
//! without consuming protected cancellation/recovery capacity: an admitted
//! cancellation or recovery record keeps the protected disk path while
//! ordinary work observes exhaustion. Only [`NormalWorkClass`] operations
//! typecheck on the normal acquisition path and only
//! [`ControlOperationClass`] operations typecheck on the protected path, so
//! ordinary work cannot reach protected disk capacity by relabelling its
//! priority or class.
//!
//! Exhausted normal capacity renders as a versioned
//! [`I14BackpressureResponseV1`] with disposition `BUSY` naming exactly the
//! saturated disk bottleneck in its exact unit: disk-queue slots in
//! disk-queue slots. `STORAGE_BACKPRESSURE` is not used here: the existing
//! [`I14BackpressureResponseV1::validate`] pins that disposition to the ORS
//! durable queue bytes, so a disk observation would fail closed instead of
//! emitting evidence. Every response is validated by the existing
//! [`I14BackpressureResponseV1::validate`] before it is returned, so an
//! inconsistent observation fails closed instead of emitting a
//! disposition-only or generic queue-full answer. The response method reads
//! the live reserve it reports and refuses while that reserve still admits
//! the request, so pressure evidence is never manufactured.
//!
//! This module has no production caller yet (STITCH): it publishes the owner
//! evidence the disk profile composition will join. There is no emergency
//! partition here; recording reserve loss stays with the front-door
//! last-resort slot until a later wave wires disk-side loss reporting.
//! DISCLOSED LIMIT: `profile_revision` on the response is caller-supplied
//! metadata echoed into the directive; the `Current` currentness claim refers
//! to the live-observed saturation at call time, not to a re-read of the
//! profile revision. Full installed-saturation proof stays #11 Product scope.

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

/// The exact disk queue/write bottleneck enforced by [`DiskReserve`].
pub const DISK_QUEUE_BOTTLENECK: CapacityBottleneck = CapacityBottleneck::DiskQueueWriteCapacity;

/// Typed disk reserve failures. None grants semantic or completion authority.
#[derive(Debug, Error)]
pub enum DiskReserveError {
    /// An owner or operation identity is blank or malformed.
    #[error("{field} is invalid: {reason}")]
    InvalidField {
        /// Failing field name.
        field: &'static str,
        /// Why the field failed.
        reason: &'static str,
    },
    /// The existing contract rejected an assembled disk backpressure response.
    #[error("runtime contract rejected disk reserve response: {0}")]
    Contract(String),
    /// The normal partition cannot satisfy the request; the protected
    /// partition is untouched.
    #[error(
        "disk normal capacity exhausted for {bottleneck:?}: work {work_class:?} operation {operation_id} owned by {owner}"
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
        "disk protected reserve exhausted for {bottleneck:?}: control operation {operation:?} operation {operation_id} owned by {owner}"
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

/// Typed operation identity carried by every [`DiskPermit`].
///
/// The variant determines the only admissible [`CapacityClass`]: a normal work
/// class cannot name a protected operation and vice versa, so ordinary work
/// fails to typecheck against the protected acquisition path instead of
/// failing at runtime.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DiskPermitOperation {
    /// Ordinary workload operation.
    Normal(NormalWorkClass),
    /// Protected cancellation/recovery operation.
    Protected(ControlOperationClass),
}

impl DiskPermitOperation {
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
struct DiskReserveInner {
    normal_capacity: u64,
    protected_capacity: u64,
    normal_in_flight: AtomicU64,
    protected_in_flight: AtomicU64,
}

/// The disk control reserve: disjoint normal/protected partitions for queued
/// disk writes, owned by the existing single-owner filesystem CAS
/// (artifact/blob) disk owner.
///
/// Acquiring from one partition never observes or consumes the other:
/// saturating normal disk-queue slots leaves the full protected capacity
/// available for admitted cancellation/recovery records and vice versa.
/// Acquisition is non-blocking and atomic; release is automatic when the
/// returned [`DiskPermit`] drops.
#[derive(Clone, Debug)]
pub struct DiskReserve {
    inner: Arc<DiskReserveInner>,
}

/// One held disk capacity permit, bound to class, operation and owner.
/// Releasing is automatic on drop and returns exactly the consumed partition.
///
/// Permits are deliberately not [`Clone`]: duplicating a permit handle must
/// never duplicate the underlying capacity.
#[derive(Debug)]
pub struct DiskPermit {
    inner: Arc<DiskReserveInner>,
    class: CapacityClass,
    operation: DiskPermitOperation,
    operation_id: String,
    owner: String,
}

impl DiskPermit {
    /// Returns the capacity class (partition) this permit holds.
    #[must_use]
    pub const fn capacity_class(&self) -> CapacityClass {
        self.class
    }

    /// Returns the bottleneck this permit was granted from.
    #[must_use]
    pub const fn bottleneck(&self) -> CapacityBottleneck {
        DISK_QUEUE_BOTTLENECK
    }

    /// Returns the amount held in the bottleneck's exact unit (disk-queue
    /// slots).
    #[must_use]
    pub const fn amount(&self) -> u64 {
        1
    }

    /// Returns the typed operation identity carried by this permit.
    #[must_use]
    pub const fn operation(&self) -> DiskPermitOperation {
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

impl Drop for DiskPermit {
    fn drop(&mut self) {
        let slot = match self.class {
            CapacityClass::NormalWorkload => &self.inner.normal_in_flight,
            _ => &self.inner.protected_in_flight,
        };
        debug_assert!(
            slot.load(Ordering::Acquire) >= 1,
            "disk permit drop without a held partition slot"
        );
        slot.fetch_sub(1, Ordering::AcqRel);
    }
}

/// Atomically adds one slot to `slot` unless `capacity` would be exceeded.
fn cas_add_one(slot: &AtomicU64, capacity: u64) -> bool {
    let mut observed = slot.load(Ordering::Acquire);
    loop {
        let Some(next) = observed.checked_add(1) else {
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
fn validate_text(value: &str, field: &'static str) -> Result<(), DiskReserveError> {
    if value.trim().is_empty() {
        return Err(DiskReserveError::InvalidField {
            field,
            reason: "must be non-blank",
        });
    }
    if value.chars().any(char::is_control) {
        return Err(DiskReserveError::InvalidField {
            field,
            reason: "must not contain control characters",
        });
    }
    if value.len() > 1_024 {
        return Err(DiskReserveError::InvalidField {
            field,
            reason: "must not exceed 1024 UTF-8 bytes",
        });
    }
    Ok(())
}

impl DiskReserve {
    /// Creates a disk reserve with disjoint normal and protected partitions
    /// for queued disk writes.
    ///
    /// Normal work draws only from the normal disk-queue slots; admitted
    /// cancellation/recovery draws only from the protected disk-queue slots.
    /// Neither class can borrow from the other.
    ///
    /// # Errors
    ///
    /// Returns [`DiskReserveError::InvalidField`] when either disk-queue
    /// partition capacity is zero.
    pub fn partitioned(
        normal_queue_slots: u64,
        protected_queue_slots: u64,
    ) -> Result<Self, DiskReserveError> {
        if normal_queue_slots == 0 {
            return Err(DiskReserveError::InvalidField {
                field: "disk_reserve.normal_queue_slots",
                reason: "must be greater than zero",
            });
        }
        if protected_queue_slots == 0 {
            return Err(DiskReserveError::InvalidField {
                field: "disk_reserve.protected_queue_slots",
                reason: "must be greater than zero",
            });
        }
        Ok(Self {
            inner: Arc::new(DiskReserveInner {
                normal_capacity: normal_queue_slots,
                protected_capacity: protected_queue_slots,
                normal_in_flight: AtomicU64::new(0),
                protected_in_flight: AtomicU64::new(0),
            }),
        })
    }

    /// Returns the configured normal disk-queue-slot partition capacity.
    #[must_use]
    pub fn normal_queue_capacity(&self) -> u64 {
        self.inner.normal_capacity
    }

    /// Returns the configured protected disk-queue-slot partition capacity.
    #[must_use]
    pub fn protected_queue_capacity(&self) -> u64 {
        self.inner.protected_capacity
    }

    /// Returns the currently available normal disk-queue slots.
    #[must_use]
    pub fn available_normal_queue(&self) -> u64 {
        self.inner
            .normal_capacity
            .saturating_sub(self.inner.normal_in_flight.load(Ordering::Acquire))
    }

    /// Returns the currently available protected disk-queue slots.
    #[must_use]
    pub fn available_protected_queue(&self) -> u64 {
        self.inner
            .protected_capacity
            .saturating_sub(self.inner.protected_in_flight.load(Ordering::Acquire))
    }

    /// Attempts to acquire one normal disk-queue slot without blocking.
    ///
    /// Only [`NormalWorkClass`] operations typecheck here, so protected disk
    /// capacity is unreachable through this path by construction.
    ///
    /// # Errors
    ///
    /// Returns [`DiskReserveError::InvalidField`] for a blank owner/operation
    /// identity, or [`DiskReserveError::NormalCapacityExhausted`] naming the
    /// disk bottleneck and shed work when the normal partition is saturated.
    /// The protected partition is untouched in every case.
    pub fn try_acquire_normal_slot(
        &self,
        work: NormalWorkClass,
        owner: &str,
        operation_id: &str,
    ) -> Result<DiskPermit, DiskReserveError> {
        validate_text(owner, "disk_permit.owner")?;
        validate_text(operation_id, "disk_permit.operation_id")?;
        if !cas_add_one(&self.inner.normal_in_flight, self.inner.normal_capacity) {
            return Err(DiskReserveError::NormalCapacityExhausted {
                bottleneck: DISK_QUEUE_BOTTLENECK,
                work_class: work,
                operation_id: operation_id.to_owned(),
                owner: owner.to_owned(),
            });
        }
        Ok(DiskPermit {
            inner: self.inner.clone(),
            class: CapacityClass::NormalWorkload,
            operation: DiskPermitOperation::Normal(work),
            operation_id: operation_id.to_owned(),
            owner: owner.to_owned(),
        })
    }

    /// Attempts to acquire one protected disk-queue slot without blocking.
    ///
    /// Only [`ControlOperationClass`] operations typecheck here: ordinary work
    /// cannot name a protected operation and therefore cannot acquire this
    /// partition. This is the path an admitted cancellation/recovery record
    /// keeps while normal disk work reports `BUSY`.
    ///
    /// # Errors
    ///
    /// Returns [`DiskReserveError::InvalidField`] for a blank owner/operation
    /// identity, or [`DiskReserveError::ProtectedReserveExhausted`] naming
    /// the disk bottleneck, operation, owner and request when the protected
    /// partition is saturated.
    pub fn try_acquire_protected_slot(
        &self,
        operation: ControlOperationClass,
        owner: &str,
        operation_id: &str,
    ) -> Result<DiskPermit, DiskReserveError> {
        validate_text(owner, "disk_permit.owner")?;
        validate_text(operation_id, "disk_permit.operation_id")?;
        if !cas_add_one(
            &self.inner.protected_in_flight,
            self.inner.protected_capacity,
        ) {
            return Err(DiskReserveError::ProtectedReserveExhausted {
                bottleneck: DISK_QUEUE_BOTTLENECK,
                operation,
                operation_id: operation_id.to_owned(),
                owner: owner.to_owned(),
            });
        }
        Ok(DiskPermit {
            inner: self.inner.clone(),
            class: CapacityClass::ProtectedControl,
            operation: DiskPermitOperation::Protected(operation),
            operation_id: operation_id.to_owned(),
            owner: owner.to_owned(),
        })
    }

    /// Reports exhausted normal disk-queue slots as a `BUSY` response naming
    /// exactly [`DISK_QUEUE_BOTTLENECK`].
    ///
    /// The response is built only while [`Self::available_normal_queue`] is
    /// zero: pressure evidence is never manufactured for a partition that
    /// still admits work. The protected partition is not read and not
    /// claimed, so an admitted cancellation/recovery record keeps its path
    /// while this response is live. `BUSY` (not `STORAGE_BACKPRESSURE`) is
    /// the honest disposition: the existing contract validation pins
    /// `STORAGE_BACKPRESSURE` to the ORS durable queue bytes.
    ///
    /// # Errors
    ///
    /// Returns [`DiskReserveError::InvalidField`] when normal disk-queue
    /// capacity remains or the operation identity is malformed, or
    /// [`DiskReserveError::Contract`] when the assembled directive fails the
    /// existing contract validation.
    pub fn normal_queue_exhaustion_response(
        &self,
        work: NormalWorkClass,
        operation_id: &str,
        profile_revision: ArtifactId,
    ) -> Result<I14BackpressureResponseV1, DiskReserveError> {
        if self.available_normal_queue() > 0 {
            return Err(DiskReserveError::InvalidField {
                field: "disk_reserve.normal_queue_slots",
                reason: "normal disk-queue partition is not saturated; no pressure evidence to report",
            });
        }
        let operation =
            OperationId::new(operation_id).map_err(|_| DiskReserveError::InvalidField {
                field: "disk_rejection.operation_id",
                reason: "must be a bounded non-blank reference",
            })?;
        DiskRejectionParts {
            affected: AffectedOperationClass::Normal(work),
            observation: BottleneckObservationV1 {
                bottleneck: DISK_QUEUE_BOTTLENECK,
                unit: DISK_QUEUE_BOTTLENECK.unit(),
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

/// Exact parts of one disk rejection directive shared by every constructor.
struct DiskRejectionParts {
    affected: AffectedOperationClass,
    observation: BottleneckObservationV1,
    operation_id: Option<OperationId>,
    profile_revision: ArtifactId,
}

impl DiskRejectionParts {
    /// Assembles the versioned response and validates it with the existing
    /// contract check; an inconsistent observation fails closed here.
    fn into_response(
        self,
        disposition: BackpressureDisposition,
        work_outcome: I14WorkOutcome,
        commit_status: RecoveryCommitStatus,
    ) -> Result<I14BackpressureResponseV1, DiskReserveError> {
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
            .map_err(|error| DiskReserveError::Contract(error.to_string()))?;
        Ok(response)
    }
}
