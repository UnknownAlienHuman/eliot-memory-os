//! IPC control-reserve partition for pipe/control-channel message bytes.
//!
//! Issue #1679, W3 IPC wave: the IPC/control-channel owner enforces disjoint
//! normal-workload and protected-control partitions for its frozen bottleneck
//! ([`IPC_PIPE_BYTES_BOTTLENECK`]). Normal work can saturate the normal byte
//! partition without consuming protected cancellation/recovery capacity: an
//! admitted cancellation, heartbeat or control-recovery record keeps the
//! protected IPC path while ordinary request traffic observes exhaustion. Only
//! [`NormalWorkClass`] operations typecheck on the normal acquisition path and
//! only [`ControlOperationClass`] operations typecheck on the protected path,
//! so ordinary traffic cannot reach protected pipe capacity by relabelling its
//! priority or class.
//!
//! The enforceable partition mechanism is this reserve's own disjoint atomic
//! byte partitions. The existing per-connection [`crate::AdmissionQueue`]
//! control lane (frame-kind classified, never caller-supplied) remains the
//! transport-level admission bound; this reserve is the owner byte budget that
//! admission will draw from once the composition wires it (STITCH). This
//! module performs no I/O, grants no semantic or completion authority, and
//! parses no payload meaning.
//!
//! Exhausted normal pipe bytes render as a versioned
//! [`I14BackpressureResponseV1`] with disposition `BUSY` naming exactly
//! [`IPC_PIPE_BYTES_BOTTLENECK`] in its byte unit: queue/permit capacity that
//! is temporarily unavailable before staging is `BUSY` per the I14.4 cause
//! mapping, while `STORAGE_BACKPRESSURE` stays pinned to ORS durable bytes by
//! the frozen validator. Every response is validated by the existing
//! [`I14BackpressureResponseV1::validate`] before it is returned, so an
//! inconsistent observation fails closed instead of emitting a
//! disposition-only or generic queue-full answer. The response method reads
//! the live reserve it reports and refuses while that reserve still admits
//! the request, so pressure evidence is never manufactured.
//!
//! The claimed dimension publishes its live partition evidence through
//! [`IpcReserve::publish_claimed_row`] as a validated
//! [`BottleneckCapacityProfile`] row for the Kernel profile composition to
//! join. The file-descriptor/handle dimension
//! ([`CapacityBottleneck::FileDescriptorHandleSlots`]) is not claimed here:
//! the frozen owner map binds it to the joint "platform/process/IPC owner",
//! whose partition mechanism is not resolved to this crate alone, so it stays
//! `UNSUPPORTED`/`UNKNOWN` until that wave rather than borrowing this byte
//! partition's numbers.
//!
//! This module has no production caller yet (STITCH): it publishes the owner
//! evidence the Kernel profile composition will join, and that composition
//! binds the profile revision and Authority Epoch it resolves. There is no
//! emergency partition here; recording reserve loss stays with the front-door
//! last-resort slot until a later wave wires IPC-side loss reporting.
//! DISCLOSED LIMIT: `profile_revision` on the response is caller-supplied
//! metadata echoed into the directive; the `Current` currentness claim refers
//! to the live-observed saturation at call time, not to a re-read of the
//! profile revision. Full installed-saturation proof stays #11 Product scope.

use std::num::NonZeroU64;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

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

/// The exact pipe/control-channel message-bytes bottleneck enforced by
/// [`IpcReserve`].
pub const IPC_PIPE_BYTES_BOTTLENECK: CapacityBottleneck = CapacityBottleneck::PipeMessageBytes;

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
    /// The existing contract rejected an assembled IPC evidence row or
    /// backpressure response.
    #[error("runtime contract rejected IPC reserve record: {0}")]
    Contract(String),
    /// The normal partition cannot satisfy the request; the protected
    /// partition is untouched.
    #[error(
        "IPC normal capacity exhausted for {bottleneck:?}: work {work_class:?} operation {operation_id} owned by {owner}"
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
        "IPC protected reserve exhausted for {bottleneck:?}: control operation {operation:?} operation {operation_id} owned by {owner}"
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

/// Typed operation identity carried by every [`IpcPermit`].
///
/// The variant determines the only admissible [`CapacityClass`]: a normal work
/// class cannot name a protected operation and vice versa, so ordinary pipe
/// traffic fails to typecheck against the protected acquisition path instead
/// of failing at runtime.
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

#[derive(Debug)]
struct IpcReserveInner {
    normal_capacity: u64,
    protected_capacity: u64,
    normal_in_flight: AtomicU64,
    protected_in_flight: AtomicU64,
    /// Restart seal flag: while set, every acquisition fails closed with its
    /// typed exhaustion disposition and unknown held capacity stays excluded.
    restart_sealed: AtomicBool,
    /// Epoch observed at the restart seal; unsealing requires the epoch to
    /// have advanced past it (stale ownership fenced).
    sealed_epoch: Mutex<Option<AuthorityEpoch>>,
}

/// The IPC control reserve: disjoint normal/protected byte partitions for the
/// pipe/control-channel message-bytes bottleneck, owned by the
/// IPC/control-channel owner.
///
/// Acquiring from one partition never observes or consumes another:
/// saturating normal pipe bytes leaves the full protected capacity available
/// for admitted cancellation/recovery records and vice versa. Acquisition is
/// non-blocking and atomic; release is automatic when the returned
/// [`IpcPermit`] drops.
#[derive(Clone, Debug)]
pub struct IpcReserve {
    inner: Arc<IpcReserveInner>,
}

/// One held IPC capacity permit, bound to class, operation and owner.
/// Releasing is automatic on drop and returns exactly the consumed partition
/// and byte amount.
///
/// Permits are deliberately not [`Clone`]: duplicating a permit handle must
/// never duplicate the underlying capacity.
#[derive(Debug)]
pub struct IpcPermit {
    inner: Arc<IpcReserveInner>,
    class: CapacityClass,
    amount_bytes: u64,
    operation: IpcPermitOperation,
    operation_id: String,
    owner: String,
}

impl IpcPermit {
    /// Returns the capacity class (partition) this permit holds.
    #[must_use]
    pub const fn capacity_class(&self) -> CapacityClass {
        self.class
    }

    /// Returns the bottleneck this permit was granted from.
    #[must_use]
    pub const fn bottleneck(&self) -> CapacityBottleneck {
        IPC_PIPE_BYTES_BOTTLENECK
    }

    /// Returns the byte amount held.
    #[must_use]
    pub const fn amount_bytes(&self) -> u64 {
        self.amount_bytes
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
}

impl Drop for IpcPermit {
    fn drop(&mut self) {
        let slot = match self.class {
            CapacityClass::NormalWorkload => &self.inner.normal_in_flight,
            CapacityClass::ProtectedControl | CapacityClass::EmergencyLastResort => {
                &self.inner.protected_in_flight
            }
        };
        debug_assert!(
            slot.load(Ordering::Acquire) >= self.amount_bytes,
            "IPC permit drop without a held partition amount"
        );
        slot.fetch_sub(self.amount_bytes, Ordering::AcqRel);
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
/// Mirrors the Store owner's text bounds without adding a cross-crate edge:
/// non-blank, no control characters, at most 1024 UTF-8 bytes.
fn validate_owner_text(value: &str, field: &'static str) -> Result<(), IpcReserveError> {
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
    /// Creates an IPC reserve with disjoint normal and protected byte
    /// partitions for pipe/control-channel message bytes.
    ///
    /// Normal pipe traffic draws only from the normal byte partition;
    /// admitted cancellation/recovery draws only from the protected byte
    /// partition. Neither class can borrow from the other, and there is no
    /// emergency partition here. `NonZeroU64` partitions are positive by
    /// construction, so construction is infallible.
    #[must_use]
    pub fn partitioned(normal_bytes: NonZeroU64, protected_bytes: NonZeroU64) -> Self {
        Self {
            inner: Arc::new(IpcReserveInner {
                normal_capacity: normal_bytes.get(),
                protected_capacity: protected_bytes.get(),
                normal_in_flight: AtomicU64::new(0),
                protected_in_flight: AtomicU64::new(0),
                restart_sealed: AtomicBool::new(false),
                sealed_epoch: Mutex::new(None),
            }),
        }
    }

    /// Returns the configured normal byte partition capacity.
    #[must_use]
    pub fn normal_byte_capacity(&self) -> u64 {
        self.inner.normal_capacity
    }

    /// Returns the configured protected byte partition capacity.
    #[must_use]
    pub fn protected_byte_capacity(&self) -> u64 {
        self.inner.protected_capacity
    }

    /// Returns the currently available normal pipe bytes.
    #[must_use]
    pub fn available_normal_bytes(&self) -> u64 {
        self.inner
            .normal_capacity
            .saturating_sub(self.inner.normal_in_flight.load(Ordering::Acquire))
    }

    /// Returns the currently available protected pipe bytes.
    #[must_use]
    pub fn available_protected_bytes(&self) -> u64 {
        self.inner
            .protected_capacity
            .saturating_sub(self.inner.protected_in_flight.load(Ordering::Acquire))
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
    /// Both in-flight counters are pinned to their full partition capacity,
    /// so no new acquisition can succeed on the back of a zeroed counter,
    /// and the sealing epoch is recorded. Unknown held capacity stays
    /// excluded until [`Self::unseal_after_epoch_advance`] observes an
    /// advanced epoch (stale ownership fenced). The embedding owner calls
    /// this exactly once when it detects an unclean restart before admitting
    /// new work (STITCH).
    pub fn seal_after_restart(&self, epoch: AuthorityEpoch) {
        self.inner
            .normal_in_flight
            .fetch_max(self.inner.normal_capacity, Ordering::AcqRel);
        self.inner
            .protected_in_flight
            .fetch_max(self.inner.protected_capacity, Ordering::AcqRel);
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
    /// Returns [`IpcReserveError::InvalidField`] when no restart seal is held,
    /// or when the epoch has not advanced past the seal.
    pub fn unseal_after_epoch_advance(
        &self,
        current: AuthorityEpoch,
    ) -> Result<(), IpcReserveError> {
        let mut sealed = self
            .inner
            .sealed_epoch
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        match *sealed {
            None => Err(IpcReserveError::InvalidField {
                field: "ipc_reserve.restart_seal",
                reason: "no restart seal is held; nothing to reconcile",
            }),
            Some(sealed_epoch) if sealed_epoch == current => Err(IpcReserveError::InvalidField {
                field: "ipc_reserve.restart_seal",
                reason: "epoch has not advanced; stale ownership is not fenced, held capacity stays excluded",
            }),
            Some(_) => {
                self.inner.normal_in_flight.store(0, Ordering::Release);
                self.inner
                    .protected_in_flight
                    .store(0, Ordering::Release);
                *sealed = None;
                self.inner.restart_sealed.store(false, Ordering::Release);
                Ok(())
            }
        }
    }

    /// Attempts to acquire `bytes` normal pipe bytes without blocking.
    ///
    /// Only [`NormalWorkClass`] operations typecheck here, so protected IPC
    /// capacity is unreachable through this path by construction.
    ///
    /// # Errors
    ///
    /// Returns [`IpcReserveError::InvalidField`] for a blank owner/operation
    /// identity, or [`IpcReserveError::NormalCapacityExhausted`] naming the
    /// pipe-bytes bottleneck and shed work when the normal partition cannot
    /// satisfy the request. The protected partition is untouched in every
    /// case.
    pub fn try_acquire_normal_bytes(
        &self,
        work: NormalWorkClass,
        owner: &str,
        operation_id: &str,
        bytes: NonZeroU64,
    ) -> Result<IpcPermit, IpcReserveError> {
        validate_owner_text(owner, "ipc_permit.owner")?;
        validate_owner_text(operation_id, "ipc_permit.operation_id")?;
        if self.inner.restart_sealed.load(Ordering::Acquire) {
            return Err(IpcReserveError::NormalCapacityExhausted {
                bottleneck: IPC_PIPE_BYTES_BOTTLENECK,
                work_class: work,
                operation_id: operation_id.to_owned(),
                owner: owner.to_owned(),
            });
        }
        if !cas_add(
            &self.inner.normal_in_flight,
            self.inner.normal_capacity,
            bytes.get(),
        ) {
            return Err(IpcReserveError::NormalCapacityExhausted {
                bottleneck: IPC_PIPE_BYTES_BOTTLENECK,
                work_class: work,
                operation_id: operation_id.to_owned(),
                owner: owner.to_owned(),
            });
        }
        Ok(IpcPermit {
            inner: self.inner.clone(),
            class: CapacityClass::NormalWorkload,
            amount_bytes: bytes.get(),
            operation: IpcPermitOperation::Normal(work),
            operation_id: operation_id.to_owned(),
            owner: owner.to_owned(),
        })
    }

    /// Attempts to acquire `bytes` protected pipe bytes without blocking.
    ///
    /// Only [`ControlOperationClass`] operations typecheck here: ordinary pipe
    /// traffic cannot name a protected operation and therefore cannot acquire
    /// this partition. This is the path an admitted cancellation/recovery
    /// record keeps while normal pipe work reports `BUSY`.
    ///
    /// # Errors
    ///
    /// Returns [`IpcReserveError::InvalidField`] for a blank owner/operation
    /// identity, or [`IpcReserveError::ProtectedReserveExhausted`] naming the
    /// pipe-bytes bottleneck, operation, owner and request when the protected
    /// partition cannot satisfy the request.
    pub fn try_acquire_protected_bytes(
        &self,
        operation: ControlOperationClass,
        owner: &str,
        operation_id: &str,
        bytes: NonZeroU64,
    ) -> Result<IpcPermit, IpcReserveError> {
        validate_owner_text(owner, "ipc_permit.owner")?;
        validate_owner_text(operation_id, "ipc_permit.operation_id")?;
        if self.inner.restart_sealed.load(Ordering::Acquire) {
            return Err(IpcReserveError::ProtectedReserveExhausted {
                bottleneck: IPC_PIPE_BYTES_BOTTLENECK,
                operation,
                operation_id: operation_id.to_owned(),
                owner: owner.to_owned(),
            });
        }
        if !cas_add(
            &self.inner.protected_in_flight,
            self.inner.protected_capacity,
            bytes.get(),
        ) {
            return Err(IpcReserveError::ProtectedReserveExhausted {
                bottleneck: IPC_PIPE_BYTES_BOTTLENECK,
                operation,
                operation_id: operation_id.to_owned(),
                owner: owner.to_owned(),
            });
        }
        Ok(IpcPermit {
            inner: self.inner.clone(),
            class: CapacityClass::ProtectedControl,
            amount_bytes: bytes.get(),
            operation: IpcPermitOperation::Protected(operation),
            operation_id: operation_id.to_owned(),
            owner: owner.to_owned(),
        })
    }

    /// Reports exhausted normal pipe bytes as a `BUSY` response naming exactly
    /// [`IPC_PIPE_BYTES_BOTTLENECK`].
    ///
    /// The response is built only while the normal byte partition cannot
    /// satisfy `requested_bytes`: pressure evidence is never manufactured for
    /// a partition that still admits the request. The protected partition is
    /// not read and not claimed, so an admitted cancellation/recovery record
    /// keeps its path while this response is live.
    ///
    /// # Errors
    ///
    /// Returns [`IpcReserveError::InvalidField`] when the normal byte
    /// partition still satisfies the request or the operation identity is
    /// malformed, or [`IpcReserveError::Contract`] when the assembled
    /// directive fails the existing contract validation.
    pub fn normal_bytes_exhaustion_response(
        &self,
        work: NormalWorkClass,
        operation_id: &str,
        profile_revision: ArtifactId,
        requested_bytes: NonZeroU64,
    ) -> Result<I14BackpressureResponseV1, IpcReserveError> {
        let available = self.available_normal_bytes();
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
                bottleneck: IPC_PIPE_BYTES_BOTTLENECK,
                unit: IPC_PIPE_BYTES_BOTTLENECK.unit(),
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
            I14BackpressureCause::CapacityExhaustion,
            I14WorkOutcome::NotAccepted,
            RecoveryCommitStatus::None,
        )
    }

    /// Publishes the live partition evidence as a claimed
    /// [`BottleneckCapacityProfile`] row for [`IPC_PIPE_BYTES_BOTTLENECK`].
    ///
    /// The row names the frozen owner the contract binds to this dimension,
    /// the exact byte unit, the physical total and the disjoint normal and
    /// protected partitions read from this reserve. There is no emergency
    /// partition here, so none is claimed. The owner generation, proof
    /// profile, evidence and invalidation references are composition-supplied
    /// metadata echoed into the row; the Kernel composition wraps this row in
    /// its own evidence record with the configuration snapshot and Authority
    /// Epoch it resolved.
    ///
    /// # Errors
    ///
    /// Returns [`IpcReserveError::InvalidField`] for a blank metadata
    /// reference or when the partition accounting cannot be represented, or
    /// [`IpcReserveError::Contract`] when the assembled row fails the
    /// existing contract validation.
    pub fn publish_claimed_row(
        &self,
        owner_generation_ref: &str,
        proof_profile_ref: &str,
        evidence_ref: &str,
        invalidation_ref: &str,
    ) -> Result<BottleneckCapacityProfile, IpcReserveError> {
        validate_owner_text(owner_generation_ref, "ipc_evidence.owner_generation_ref")?;
        validate_owner_text(proof_profile_ref, "ipc_evidence.proof_profile_ref")?;
        validate_owner_text(evidence_ref, "ipc_evidence.evidence_ref")?;
        validate_owner_text(invalidation_ref, "ipc_evidence.invalidation_ref")?;
        let bound = frozen_bottleneck_owner_map()
            .into_iter()
            .find(|bound| bound.bottleneck == IPC_PIPE_BYTES_BOTTLENECK)
            .ok_or(IpcReserveError::InvalidField {
                field: "ipc_evidence.bottleneck",
                reason: "the frozen owner map binds no owner to the pipe-bytes dimension",
            })?;
        let physical_total = self
            .inner
            .normal_capacity
            .checked_add(self.inner.protected_capacity)
            .and_then(NonZeroU64::new)
            .ok_or(IpcReserveError::InvalidField {
                field: "ipc_evidence.physical_total_limit",
                reason: "the disjoint partition sum is not a positive capacity",
            })?;
        let unit = IPC_PIPE_BYTES_BOTTLENECK.unit();
        let limit = |quantity: u64| {
            NonZeroU64::new(quantity)
                .map(|quantity| CapacityLimit { unit, quantity })
                .ok_or(IpcReserveError::InvalidField {
                    field: "ipc_evidence.partition_limit",
                    reason: "a claimed partition is not a positive capacity",
                })
        };
        let row = BottleneckCapacityProfile {
            bottleneck: IPC_PIPE_BYTES_BOTTLENECK,
            coverage_state: BottleneckCoverageState::Claimed,
            owner_ref: bound.owner.to_owned(),
            owner_generation_ref: owner_generation_ref.to_owned(),
            unit,
            physical_total_limit: Some(CapacityLimit {
                unit,
                quantity: physical_total,
            }),
            normal_work_applicable: true,
            normal_limit: Some(limit(self.inner.normal_capacity)?),
            protected_limit: Some(limit(self.inner.protected_capacity)?),
            emergency_limit: None,
            enforcement: Some(CapacityEnforcement::ConfigurationPartition),
            proof_profile_ref: proof_profile_ref.to_owned(),
            evidence_refs: vec![evidence_ref.to_owned()],
            invalidation_set: vec![invalidation_ref.to_owned()],
        };
        row.validate()
            .map_err(|error| IpcReserveError::Contract(error.to_string()))?;
        Ok(row)
    }
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
        cause: I14BackpressureCause,
        work_outcome: I14WorkOutcome,
        commit_status: RecoveryCommitStatus,
    ) -> Result<I14BackpressureResponseV1, IpcReserveError> {
        let response = I14BackpressureResponseV1 {
            contract_version: I14_BACKPRESSURE_RESPONSE_VERSION,
            disposition,
            directive: I14RecoveryDirectiveV1 {
                cause,
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
