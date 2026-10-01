//! IPC control-reserve partitions for pipe/message bytes and handle slots.
//!
//! Issue #1679, W3 IPC wave: the existing platform/IPC owner, the P-02 bounded
//! transport boundary that already admits frames against bounded queue bytes
//! and binds process handles, enforces disjoint normal-workload and
//! protected-control partitions for its two frozen bottlenecks
//! ([`IPC_PIPE_BOTTLENECK`] and [`IPC_HANDLE_BOTTLENECK`]). Normal work can
//! saturate the normal partition without consuming protected
//! cancellation/recovery capacity: an admitted cancellation or recovery record
//! keeps the protected IPC path while ordinary work observes exhaustion. Only
//! [`NormalWorkClass`] operations typecheck on the normal acquisition paths
//! and only [`ControlOperationClass`] operations typecheck on the protected
//! paths, so ordinary work cannot reach protected IPC capacity by relabelling
//! its priority or class.
//!
//! Exhausted normal capacity renders as a versioned
//! [`I14BackpressureResponseV1`] with disposition `BUSY` naming exactly the
//! saturated IPC bottleneck in its exact unit: pipe/message bytes in bytes,
//! file-descriptor/handle slots in handles. `STORAGE_BACKPRESSURE` is not used
//! here: the existing [`I14BackpressureResponseV1::validate`] pins that
//! disposition to the ORS durable queue bytes, so an IPC observation would
//! fail closed instead of emitting evidence. Every response is validated by
//! the existing [`I14BackpressureResponseV1::validate`] before it is returned,
//! so an inconsistent observation fails closed instead of emitting a
//! disposition-only or generic queue-full answer. Each response method reads
//! the live reserve it reports and refuses while that reserve still admits
//! the request, so pressure evidence is never manufactured.
//!
//! This module has no production caller yet (STITCH): it publishes the owner
//! evidence the IPC profile composition will join. There is no emergency
//! partition here; recording reserve loss stays with the front-door
//! last-resort slot until a later wave wires IPC-side loss reporting.
//!
//! W4 IPC wave: every [`IpcPermit`] is owner-issued non-clone evidence bound
//! to capacity class, bottleneck/unit/granted amount, typed operation,
//! operation identity, owner and the typed [`EpochId`] observed at
//! acquisition, mirroring the ORS evidence grade. Every denial names the exact
//! bottleneck, shed work and observed epoch. A stale epoch, changed operation
//! or changed owner fails before consumption because the evidence no longer
//! matches the current owner state; there is no epoch-blind permit to replay.
//!
//! Each claimed IPC dimension publishes its live partition evidence through
//! [`IpcReserve::publish_owner_rows`] as validated
//! [`BottleneckCapacityProfile`] rows: exactly one row per IPC dimension, in
//! frozen contract order, each naming exactly its own bottleneck. Every row is
//! re-validated by the existing [`BottleneckCapacityProfile::validate`] before
//! it is returned, so a missing owner, generation, physical total, protected
//! partition, enforcement, proof, evidence or invalidation reference fails
//! here rather than joining the Kernel profile composition as a claimed
//! guarantee. Rows for any other bottleneck are never produced here: one
//! owner's numbers are never presented as proof for another dimension.
//!
//! DISCLOSED LIMIT: `profile_revision` on the responses is caller-supplied
//! metadata echoed into the directive; the `Current` currentness claim refers
//! to the live-observed saturation at call time, not to a re-read of the
//! profile revision. Full installed-saturation proof stays #11 Product scope.

use std::num::NonZeroU64;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use eliot_contracts::{ArtifactId, EpochId, OperationId};
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

/// The exact pipe/message-byte bottleneck enforced by [`IpcReserve`].
pub const IPC_PIPE_BOTTLENECK: CapacityBottleneck = CapacityBottleneck::PipeMessageBytes;

/// The exact file-descriptor/handle-slot bottleneck enforced by [`IpcReserve`].
pub const IPC_HANDLE_BOTTLENECK: CapacityBottleneck = CapacityBottleneck::FileDescriptorHandleSlots;

/// Typed IPC reserve failures. None grants semantic or completion authority.
#[derive(Debug, Error)]
pub enum IpcReserveError {
    /// An owner, operation or field identity is blank or malformed.
    #[error("{field} is invalid: {reason}")]
    InvalidField {
        /// Failing field name.
        field: &'static str,
        /// Why the field failed.
        reason: &'static str,
    },
    /// The existing contract rejected an assembled IPC backpressure response.
    #[error("runtime contract rejected IPC reserve response: {0}")]
    Contract(String),
    /// The normal partition cannot satisfy the request; the protected
    /// partition is untouched.
    #[error(
        "IPC normal capacity exhausted for {bottleneck:?}: work {work_class:?} operation {operation_id} owned by {owner} epoch {epoch:?}"
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
        epoch: EpochId,
    },
    /// The protected partition cannot satisfy the request.
    #[error(
        "IPC protected reserve exhausted for {bottleneck:?}: control operation {operation:?} operation {operation_id} owned by {owner} epoch {epoch:?}"
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
        epoch: EpochId,
    },
}

/// Which IPC dimension a permit holds.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IpcDimension {
    /// Pipe/message bytes, counted in bytes.
    PipeMessageBytes,
    /// File-descriptor/handle slots, counted in handles.
    HandleSlots,
}

impl IpcDimension {
    /// Returns the frozen bottleneck enforced for this dimension.
    #[must_use]
    pub const fn bottleneck(self) -> CapacityBottleneck {
        match self {
            Self::PipeMessageBytes => IPC_PIPE_BOTTLENECK,
            Self::HandleSlots => IPC_HANDLE_BOTTLENECK,
        }
    }
}

/// Typed operation identity carried by every [`IpcPermit`].
///
/// The variant determines the only admissible [`CapacityClass`]: a normal work
/// class cannot name a protected operation and vice versa, so ordinary work
/// fails to typecheck against the protected acquisition paths instead of
/// failing at runtime.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IpcPermitOperation {
    /// Ordinary workload operation.
    Normal(NormalWorkClass),
    /// Protected cancellation/recovery operation.
    Protected(ControlOperationClass),
}

impl IpcPermitOperation {
    /// Returns the capacity class this operation draws from.
    #[must_use]
    pub const fn capacity_class(self) -> CapacityClass {
        match self {
            Self::Normal(_) => CapacityClass::NormalWorkload,
            Self::Protected(_) => CapacityClass::ProtectedControl,
        }
    }
}

/// Composition-resolved references identifying one IPC owner-evidence
/// publication: the live partition capacities read from the reserve itself
/// and their physical total, and the [`CapacityEnforcement::ConfigurationPartition`]
/// mechanism those partitions are held under. The composition supplies the
/// references that identify the observation: its own owner-generation
/// reference for the IPC owner, the independent proof-profile reference, and
/// the current evidence and invalidation references. Both halves are required:
/// [`IpcReserve::publish_owner_rows`] fails closed through the existing
/// [`BottleneckCapacityProfile::validate`] when any reference is missing or
/// non-canonical, so the composition must resolve canonical (strictly
/// ascending, duplicate-free) reference sets rather than have them defaulted
/// or sorted here.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IpcOwnerEvidenceContext {
    /// Owner generation/revision reference for the IPC/control-channel owner.
    pub owner_generation_ref: String,
    /// Independent proof-profile reference produced for the IPC dimensions.
    pub proof_profile_ref: String,
    /// Current owner evidence references supporting the published rows.
    pub evidence_refs: Vec<String>,
    /// Exact invalidation set of the published rows.
    pub invalidation_set: Vec<String>,
}

#[derive(Debug)]
struct IpcReserveInner {
    pipe_normal_capacity_bytes: u64,
    pipe_protected_capacity_bytes: u64,
    handle_normal_capacity: u64,
    handle_protected_capacity: u64,
    pipe_normal_in_flight_bytes: AtomicU64,
    pipe_protected_in_flight_bytes: AtomicU64,
    handle_normal_in_flight: AtomicU64,
    handle_protected_in_flight: AtomicU64,
}

/// The IPC control reserve: disjoint normal/protected partitions for the pipe
/// bytes and handle slots, owned by the existing platform/IPC owner.
///
/// Acquiring from one partition never observes or consumes another:
/// saturating normal pipe bytes or normal handle slots leaves the full
/// protected capacity available for admitted cancellation/recovery records
/// and vice versa. Acquisition is non-blocking and atomic; release is
/// automatic when the returned [`IpcPermit`] drops.
#[derive(Clone, Debug)]
pub struct IpcReserve {
    inner: Arc<IpcReserveInner>,
}

/// One held IPC capacity permit, bound to dimension, class, operation, owner
/// and full Authority Epoch tuple. Releasing is automatic on drop and returns exactly
/// the consumed partition and amount.
///
/// The permit is bound to the full typed Authority Epoch tuple resolved at
/// acquisition: evidence from a fenced epoch never authorizes consumption
/// under the current one. Permits are deliberately not [`Clone`]: duplicating
/// a permit handle must never duplicate the underlying capacity.
#[derive(Debug)]
pub struct IpcPermit {
    inner: Arc<IpcReserveInner>,
    dimension: IpcDimension,
    class: CapacityClass,
    amount: u64,
    operation: IpcPermitOperation,
    operation_id: String,
    owner: String,
    epoch: EpochId,
}

impl IpcPermit {
    /// Returns the capacity class (partition) this permit holds.
    #[must_use]
    pub const fn capacity_class(&self) -> CapacityClass {
        self.class
    }

    /// Returns which IPC dimension this permit was granted from.
    #[must_use]
    pub const fn dimension(&self) -> IpcDimension {
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
    pub const fn operation(&self) -> IpcPermitOperation {
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
    pub fn epoch(&self) -> EpochId {
        self.epoch.clone()
    }
}

impl Drop for IpcPermit {
    fn drop(&mut self) {
        let slot = match (self.dimension, self.class) {
            (IpcDimension::PipeMessageBytes, CapacityClass::NormalWorkload) => {
                &self.inner.pipe_normal_in_flight_bytes
            }
            (IpcDimension::PipeMessageBytes, _) => &self.inner.pipe_protected_in_flight_bytes,
            (IpcDimension::HandleSlots, CapacityClass::NormalWorkload) => {
                &self.inner.handle_normal_in_flight
            }
            (IpcDimension::HandleSlots, _) => &self.inner.handle_protected_in_flight,
        };
        debug_assert!(
            slot.load(Ordering::Acquire) >= self.amount,
            "IPC permit drop without a held partition amount"
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
fn validate_text(value: &str, field: &'static str) -> Result<(), IpcReserveError> {
    if value.trim().is_empty() {
        return Err(IpcReserveError::InvalidField {
            field,
            reason: "must be non-blank",
        });
    }
    if value.chars().any(char::is_control) {
        return Err(IpcReserveError::InvalidField {
            field,
            reason: "must not contain control characters",
        });
    }
    if value.len() > 1_024 {
        return Err(IpcReserveError::InvalidField {
            field,
            reason: "must not exceed 1024 UTF-8 bytes",
        });
    }
    Ok(())
}

impl IpcReserve {
    /// Creates an IPC reserve with disjoint normal and protected partitions
    /// for pipe bytes and handle slots.
    ///
    /// Normal work draws only from the normal pipe bytes and normal handle
    /// slots; admitted cancellation/recovery draws only from the protected
    /// pipe bytes and protected handle slots. Neither class can borrow from
    /// the other.
    ///
    /// # Errors
    ///
    /// Returns [`IpcReserveError::InvalidField`] when any handle partition
    /// capacity is zero. Byte partitions are [`NonZeroU64`] by type, so zero
    /// byte capacity is unrepresentable.
    pub fn partitioned(
        normal_pipe_bytes: NonZeroU64,
        protected_pipe_bytes: NonZeroU64,
        normal_handle_slots: u64,
        protected_handle_slots: u64,
    ) -> Result<Self, IpcReserveError> {
        if normal_handle_slots == 0 {
            return Err(IpcReserveError::InvalidField {
                field: "ipc_reserve.normal_handle_slots",
                reason: "must be greater than zero",
            });
        }
        if protected_handle_slots == 0 {
            return Err(IpcReserveError::InvalidField {
                field: "ipc_reserve.protected_handle_slots",
                reason: "must be greater than zero",
            });
        }
        Ok(Self {
            inner: Arc::new(IpcReserveInner {
                pipe_normal_capacity_bytes: normal_pipe_bytes.get(),
                pipe_protected_capacity_bytes: protected_pipe_bytes.get(),
                handle_normal_capacity: normal_handle_slots,
                handle_protected_capacity: protected_handle_slots,
                pipe_normal_in_flight_bytes: AtomicU64::new(0),
                pipe_protected_in_flight_bytes: AtomicU64::new(0),
                handle_normal_in_flight: AtomicU64::new(0),
                handle_protected_in_flight: AtomicU64::new(0),
            }),
        })
    }

    /// Returns the configured normal pipe-byte partition capacity.
    #[must_use]
    pub fn normal_pipe_byte_capacity(&self) -> u64 {
        self.inner.pipe_normal_capacity_bytes
    }

    /// Returns the configured protected pipe-byte partition capacity.
    #[must_use]
    pub fn protected_pipe_byte_capacity(&self) -> u64 {
        self.inner.pipe_protected_capacity_bytes
    }

    /// Returns the configured normal handle-slot partition capacity.
    #[must_use]
    pub fn normal_handle_capacity(&self) -> u64 {
        self.inner.handle_normal_capacity
    }

    /// Returns the configured protected handle-slot partition capacity.
    #[must_use]
    pub fn protected_handle_capacity(&self) -> u64 {
        self.inner.handle_protected_capacity
    }

    /// Returns the currently available normal pipe bytes.
    #[must_use]
    pub fn available_normal_pipe_bytes(&self) -> u64 {
        self.inner.pipe_normal_capacity_bytes.saturating_sub(
            self.inner
                .pipe_normal_in_flight_bytes
                .load(Ordering::Acquire),
        )
    }

    /// Returns the currently available protected pipe bytes.
    #[must_use]
    pub fn available_protected_pipe_bytes(&self) -> u64 {
        self.inner.pipe_protected_capacity_bytes.saturating_sub(
            self.inner
                .pipe_protected_in_flight_bytes
                .load(Ordering::Acquire),
        )
    }

    /// Returns the currently available normal handle slots.
    #[must_use]
    pub fn available_normal_handles(&self) -> u64 {
        self.inner
            .handle_normal_capacity
            .saturating_sub(self.inner.handle_normal_in_flight.load(Ordering::Acquire))
    }

    /// Returns the currently available protected handle slots.
    #[must_use]
    pub fn available_protected_handles(&self) -> u64 {
        self.inner.handle_protected_capacity.saturating_sub(
            self.inner
                .handle_protected_in_flight
                .load(Ordering::Acquire),
        )
    }

    /// Attempts to acquire `bytes` normal pipe/message bytes without blocking.
    ///
    /// Only [`NormalWorkClass`] operations typecheck here, so protected IPC
    /// pipe capacity is unreachable through this path by construction. The granted
    /// permit binds `epoch`; a caller presenting it under a different epoch
    /// holds evidence that no longer matches the current owner state.
    ///
    /// # Errors
    ///
    /// Returns [`IpcReserveError::InvalidField`] for a blank owner/operation
    /// identity, or [`IpcReserveError::NormalCapacityExhausted`] naming the
    /// pipe bottleneck, shed work and observed epoch when the normal partition
    /// cannot satisfy the request. The protected partition is untouched in every
    /// case.
    pub fn try_acquire_normal_pipe_bytes(
        &self,
        work: NormalWorkClass,
        owner: &str,
        operation_id: &str,
        bytes: NonZeroU64,
        epoch: EpochId,
    ) -> Result<IpcPermit, IpcReserveError> {
        validate_text(owner, "ipc_permit.owner")?;
        validate_text(operation_id, "ipc_permit.operation_id")?;
        if !cas_add(
            &self.inner.pipe_normal_in_flight_bytes,
            self.inner.pipe_normal_capacity_bytes,
            bytes.get(),
        ) {
            return Err(IpcReserveError::NormalCapacityExhausted {
                bottleneck: IPC_PIPE_BOTTLENECK,
                work_class: work,
                operation_id: operation_id.to_owned(),
                owner: owner.to_owned(),
                epoch,
            });
        }
        Ok(IpcPermit {
            inner: self.inner.clone(),
            dimension: IpcDimension::PipeMessageBytes,
            class: CapacityClass::NormalWorkload,
            amount: bytes.get(),
            operation: IpcPermitOperation::Normal(work),
            operation_id: operation_id.to_owned(),
            owner: owner.to_owned(),
            epoch,
        })
    }

    /// Attempts to acquire one normal handle slot without blocking.
    ///
    /// Only [`NormalWorkClass`] operations typecheck here, so protected IPC
    /// handle capacity is unreachable through this path by construction. The granted
    /// permit binds `epoch`; a caller presenting it under a different epoch
    /// holds evidence that no longer matches the current owner state.
    ///
    /// # Errors
    ///
    /// Returns [`IpcReserveError::InvalidField`] for a blank owner/operation
    /// identity, or [`IpcReserveError::NormalCapacityExhausted`] naming the
    /// handle bottleneck, shed work and observed epoch when the normal partition
    /// is saturated. The protected partition is untouched in every case.
    pub fn try_acquire_normal_handle(
        &self,
        work: NormalWorkClass,
        owner: &str,
        operation_id: &str,
        epoch: EpochId,
    ) -> Result<IpcPermit, IpcReserveError> {
        validate_text(owner, "ipc_permit.owner")?;
        validate_text(operation_id, "ipc_permit.operation_id")?;
        if !cas_add(
            &self.inner.handle_normal_in_flight,
            self.inner.handle_normal_capacity,
            1,
        ) {
            return Err(IpcReserveError::NormalCapacityExhausted {
                bottleneck: IPC_HANDLE_BOTTLENECK,
                work_class: work,
                operation_id: operation_id.to_owned(),
                owner: owner.to_owned(),
                epoch,
            });
        }
        Ok(IpcPermit {
            inner: self.inner.clone(),
            dimension: IpcDimension::HandleSlots,
            class: CapacityClass::NormalWorkload,
            amount: 1,
            operation: IpcPermitOperation::Normal(work),
            operation_id: operation_id.to_owned(),
            owner: owner.to_owned(),
            epoch,
        })
    }

    /// Attempts to acquire `bytes` protected pipe/message bytes without
    /// blocking.
    ///
    /// Only [`ControlOperationClass`] operations typecheck here: ordinary work
    /// cannot name a protected operation and therefore cannot acquire this
    /// partition. This is the path an admitted cancellation/recovery record
    /// keeps while normal pipe work reports `BUSY`. The granted permit binds
    /// `epoch` so the recovery record proves it was admitted under the current
    /// owner state.
    ///
    /// # Errors
    ///
    /// Returns [`IpcReserveError::InvalidField`] for a blank owner/operation
    /// identity, or [`IpcReserveError::ProtectedReserveExhausted`] naming the
    /// pipe bottleneck, operation, owner, request and observed epoch when the
    /// protected partition cannot satisfy the request.
    pub fn try_acquire_protected_pipe_bytes(
        &self,
        operation: ControlOperationClass,
        owner: &str,
        operation_id: &str,
        bytes: NonZeroU64,
        epoch: EpochId,
    ) -> Result<IpcPermit, IpcReserveError> {
        validate_text(owner, "ipc_permit.owner")?;
        validate_text(operation_id, "ipc_permit.operation_id")?;
        if !cas_add(
            &self.inner.pipe_protected_in_flight_bytes,
            self.inner.pipe_protected_capacity_bytes,
            bytes.get(),
        ) {
            return Err(IpcReserveError::ProtectedReserveExhausted {
                bottleneck: IPC_PIPE_BOTTLENECK,
                operation,
                operation_id: operation_id.to_owned(),
                owner: owner.to_owned(),
                epoch,
            });
        }
        Ok(IpcPermit {
            inner: self.inner.clone(),
            dimension: IpcDimension::PipeMessageBytes,
            class: CapacityClass::ProtectedControl,
            amount: bytes.get(),
            operation: IpcPermitOperation::Protected(operation),
            operation_id: operation_id.to_owned(),
            owner: owner.to_owned(),
            epoch,
        })
    }

    /// Attempts to acquire one protected handle slot without blocking.
    ///
    /// Only [`ControlOperationClass`] operations typecheck here: ordinary work
    /// cannot name a protected operation and therefore cannot acquire this
    /// partition. This is the path an admitted cancellation/recovery record
    /// keeps while normal handle work is saturated. The granted permit binds
    /// `epoch` so the recovery record proves it was admitted under the current
    /// owner state.
    ///
    /// # Errors
    ///
    /// Returns [`IpcReserveError::InvalidField`] for a blank owner/operation
    /// identity, or [`IpcReserveError::ProtectedReserveExhausted`] naming the
    /// handle bottleneck, operation, owner, request and observed epoch when the
    /// protected partition is saturated.
    pub fn try_acquire_protected_handle(
        &self,
        operation: ControlOperationClass,
        owner: &str,
        operation_id: &str,
        epoch: EpochId,
    ) -> Result<IpcPermit, IpcReserveError> {
        validate_text(owner, "ipc_permit.owner")?;
        validate_text(operation_id, "ipc_permit.operation_id")?;
        if !cas_add(
            &self.inner.handle_protected_in_flight,
            self.inner.handle_protected_capacity,
            1,
        ) {
            return Err(IpcReserveError::ProtectedReserveExhausted {
                bottleneck: IPC_HANDLE_BOTTLENECK,
                operation,
                operation_id: operation_id.to_owned(),
                owner: owner.to_owned(),
                epoch,
            });
        }
        Ok(IpcPermit {
            inner: self.inner.clone(),
            dimension: IpcDimension::HandleSlots,
            class: CapacityClass::ProtectedControl,
            amount: 1,
            operation: IpcPermitOperation::Protected(operation),
            operation_id: operation_id.to_owned(),
            owner: owner.to_owned(),
            epoch,
        })
    }

    /// Reports exhausted normal pipe/message bytes as a `BUSY` response naming
    /// exactly [`IPC_PIPE_BOTTLENECK`].
    ///
    /// The response is built only while the normal pipe partition cannot
    /// satisfy `requested_bytes`: pressure evidence is never manufactured for
    /// a partition that still admits the request. The protected partition is
    /// not read and not claimed, so an admitted cancellation/recovery record
    /// keeps its path while this response is live. `BUSY` (not
    /// `STORAGE_BACKPRESSURE`) is the honest disposition: the existing
    /// contract validation pins `STORAGE_BACKPRESSURE` to the ORS durable
    /// queue bytes.
    ///
    /// # Errors
    ///
    /// Returns [`IpcReserveError::InvalidField`] when the normal pipe
    /// partition still satisfies the request or the operation identity is
    /// malformed, or [`IpcReserveError::Contract`] when the assembled
    /// directive fails the existing contract validation.
    pub fn normal_pipe_exhaustion_response(
        &self,
        work: NormalWorkClass,
        operation_id: &str,
        profile_revision: ArtifactId,
        requested_bytes: NonZeroU64,
    ) -> Result<I14BackpressureResponseV1, IpcReserveError> {
        let available = self.available_normal_pipe_bytes();
        if available >= requested_bytes.get() {
            return Err(IpcReserveError::InvalidField {
                field: "ipc_reserve.normal_pipe_bytes",
                reason: "normal pipe partition still admits the request; no pressure evidence to report",
            });
        }
        let operation =
            OperationId::new(operation_id).map_err(|_| IpcReserveError::InvalidField {
                field: "ipc_rejection.operation_id",
                reason: "must be a bounded non-blank reference",
            })?;
        IpcRejectionParts {
            affected: AffectedOperationClass::Normal(work),
            observation: BottleneckObservationV1 {
                bottleneck: IPC_PIPE_BOTTLENECK,
                unit: IPC_PIPE_BOTTLENECK.unit(),
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

    /// Reports exhausted normal handle slots as a `BUSY` response naming
    /// exactly [`IPC_HANDLE_BOTTLENECK`].
    ///
    /// The response is built only while [`Self::available_normal_handles`] is
    /// zero: pressure evidence is never manufactured for a partition that
    /// still admits work. The protected partition is not read and not
    /// claimed.
    ///
    /// # Errors
    ///
    /// Returns [`IpcReserveError::InvalidField`] when normal handle capacity
    /// remains or the operation identity is malformed, or
    /// [`IpcReserveError::Contract`] when the assembled directive fails the
    /// existing contract validation.
    pub fn normal_handle_exhaustion_response(
        &self,
        work: NormalWorkClass,
        operation_id: &str,
        profile_revision: ArtifactId,
    ) -> Result<I14BackpressureResponseV1, IpcReserveError> {
        if self.available_normal_handles() > 0 {
            return Err(IpcReserveError::InvalidField {
                field: "ipc_reserve.normal_handle_slots",
                reason: "normal handle partition is not saturated; no pressure evidence to report",
            });
        }
        let operation =
            OperationId::new(operation_id).map_err(|_| IpcReserveError::InvalidField {
                field: "ipc_rejection.operation_id",
                reason: "must be a bounded non-blank reference",
            })?;
        IpcRejectionParts {
            affected: AffectedOperationClass::Normal(work),
            observation: BottleneckObservationV1 {
                bottleneck: IPC_HANDLE_BOTTLENECK,
                unit: IPC_HANDLE_BOTTLENECK.unit(),
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

    /// Publishes the live partition evidence for both IPC dimensions as
    /// claimed [`BottleneckCapacityProfile`] rows, in frozen contract order.
    ///
    /// The result carries exactly one row per IPC dimension: pipe/message
    /// bytes first, file-descriptor/handle slots second. Each row names the
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
    /// Returns [`IpcReserveError::Contract`] when the frozen owner map binds
    /// no owner to an IPC dimension, when the configured partition capacities
    /// cannot form a positive physical total, or when either assembled row
    /// fails the existing contract validation.
    pub fn publish_owner_rows(
        &self,
        ctx: &IpcOwnerEvidenceContext,
    ) -> Result<[BottleneckCapacityProfile; 2], IpcReserveError> {
        let pipe = ipc_owner_capacity_row(
            IPC_PIPE_BOTTLENECK,
            self.inner.pipe_normal_capacity_bytes,
            self.inner.pipe_protected_capacity_bytes,
            ctx,
        )?;
        let handles = ipc_owner_capacity_row(
            IPC_HANDLE_BOTTLENECK,
            self.inner.handle_normal_capacity,
            self.inner.handle_protected_capacity,
            ctx,
        )?;
        Ok([pipe, handles])
    }
}

/// Builds one claimed owner row for an IPC dimension from the reserve's
/// configured partition capacities and the composition-resolved references.
///
/// The owner reference is read from the frozen owner map, never restated here;
/// the unit is the bottleneck's own declared unit. The physical total is
/// exactly the sum of the two disjoint partitions, so the existing partition
/// accounting check always bounds them. A zero partition capacity or a missing
/// frozen owner fails closed: the reserve constructor already refuses zero
/// partitions, and a dimension without a frozen owner has no claim to publish.
fn ipc_owner_capacity_row(
    bottleneck: CapacityBottleneck,
    normal_capacity: u64,
    protected_capacity: u64,
    ctx: &IpcOwnerEvidenceContext,
) -> Result<BottleneckCapacityProfile, IpcReserveError> {
    let owner = frozen_bottleneck_owner_map()
        .into_iter()
        .find(|bound| bound.bottleneck == bottleneck)
        .map(|bound| bound.owner)
        .ok_or_else(|| {
            IpcReserveError::Contract(format!(
                "frozen owner map binds no owner to {bottleneck:?}; no IPC row to publish"
            ))
        })?;
    let unit = bottleneck.unit();
    let limit = |field: &'static str, amount: u64| {
        NonZeroU64::new(amount)
            .map(|quantity| CapacityLimit { unit, quantity })
            .ok_or(IpcReserveError::InvalidField {
                field,
                reason: "partition capacity must be greater than zero",
            })
    };
    let normal_limit = limit("ipc_reserve.normal_limit", normal_capacity)?;
    let protected_limit = limit("ipc_reserve.protected_limit", protected_capacity)?;
    let physical_total =
        normal_capacity
            .checked_add(protected_capacity)
            .ok_or(IpcReserveError::InvalidField {
                field: "ipc_reserve.physical_total_limit",
                reason: "disjoint partition capacities overflow the physical total",
            })?;
    let physical_total_limit =
        NonZeroU64::new(physical_total).ok_or(IpcReserveError::InvalidField {
            field: "ipc_reserve.physical_total_limit",
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
        .map_err(|error| IpcReserveError::Contract(error.to_string()))?;
    Ok(row)
}

/// Exact parts of one IPC rejection directive shared by every constructor.
struct IpcRejectionParts {
    affected: AffectedOperationClass,
    observation: BottleneckObservationV1,
    operation_id: Option<OperationId>,
    profile_revision: ArtifactId,
}

impl IpcRejectionParts {
    /// Assembles the versioned response and validates it with the existing
    /// contract check; an inconsistent observation fails closed here.
    fn into_response(
        self,
        disposition: BackpressureDisposition,
        work_outcome: I14WorkOutcome,
        commit_status: RecoveryCommitStatus,
    ) -> Result<I14BackpressureResponseV1, IpcReserveError> {
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
            .map_err(|error| IpcReserveError::Contract(error.to_string()))?;
        Ok(response)
    }
}
