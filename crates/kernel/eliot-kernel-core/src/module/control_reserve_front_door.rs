//! P-07 control reserve and front-door decision core.
//!
//! The front door is the single synchronous admission point for the Kernel. It
//! combines three owned properties: a partitioned [`ControlReserve`] whose
//! normal-workload capacity normal work can saturate without consuming the
//! protected control/recovery capacity, an idempotency ledger that deduplicates
//! effects, and the [`KernelAuthority`] that verifies non-forgeable receipts.
//! It never performs model inference, storage, or unbounded graph work.
//!
//! Partitioning follows Architecture A13.5 and Implementation I14.3 with the
//! closed capacity vocabulary frozen in
//! `crates/foundation/eliot-runtime-contracts/control-reserve.contract.toml`
//! (issue #293, parent issue #65): normal workload admission
//! ([`NormalWorkClass`]) is structurally unable to consume protected control
//! capacity ([`ControlOperationClass`]) or the preallocated emergency
//! last-resort slot ([`EmergencyOperationClass`]). Every permit is bound to its
//! [`CapacityClass`], [`CapacityBottleneck`], operation identity, owner and
//! front-door epoch; every denial names the exact bottleneck and the shed work
//! instead of collapsing to one scalar string. Reserve accounting stays
//! multidimensional: one exhausted partition never implies another is exhausted,
//! and losing the last-resort path surfaces [`KernelError::ControlGuaranteeLost`]
//! rather than a healthy status.

use std::collections::{BTreeMap, VecDeque};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};

use eliot_contracts::AuthorityEpoch;
use eliot_receipts::ProofCeiling;

use crate::RouteScope;
use crate::authority::{AuthorityGrant, AuthorityReceipt, KernelAuthority};
use crate::error::{KernelError, validate_id};

/// Capacity classes from the frozen control-reserve contract (issue #293).
///
/// These spellings mirror `CapacityClass` in
/// `control-reserve.contract.toml` exactly; no parallel class vocabulary exists.
/// The tag determines the only admissible partition: normal work can neither
/// request nor receive protected or emergency capacity.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum CapacityClass {
    /// Ordinary workload admission (Store writes/reads, agent admission, jobs).
    NormalWorkload,
    /// Reserved control/recovery admission (cancellation, fencing, health,
    /// problem/incident, shutdown, recovery).
    ProtectedControl,
    /// Preallocated last-resort slot, used only to record reserve loss/gap or
    /// enter manual recovery.
    EmergencyLastResort,
}

impl CapacityClass {
    /// Returns the exact contract identifier (`NORMAL_WORKLOAD`, ...).
    #[must_use]
    pub const fn as_contract_str(self) -> &'static str {
        match self {
            Self::NormalWorkload => "NORMAL_WORKLOAD",
            Self::ProtectedControl => "PROTECTED_CONTROL",
            Self::EmergencyLastResort => "EMERGENCY_LAST_RESORT",
        }
    }
}

/// Normal workload classes from the frozen contract (issue #293).
///
/// Every value maps only to [`CapacityClass::NormalWorkload`]: importance, age,
/// retry count or queue pressure can never promote normal work to protected
/// control. A normal Store write, named read or agent admission carries one of
/// these classes and therefore cannot typecheck against the protected
/// acquisition path.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum NormalWorkClass {
    /// Interactive and named-read admission.
    Interactive,
    /// Verification work.
    Verification,
    /// Canonical Store write admission.
    CanonicalWrite,
    /// Ordinary background work.
    NormalBackground,
    /// Model job admission.
    ModelJob,
    /// Swarm/agent admission.
    Swarm,
    /// Reporting work.
    Reporting,
    /// Maintenance work.
    Maintenance,
}

impl NormalWorkClass {
    /// Returns the exact contract identifier (`INTERACTIVE`, ...).
    #[must_use]
    pub const fn as_contract_str(self) -> &'static str {
        match self {
            Self::Interactive => "INTERACTIVE",
            Self::Verification => "VERIFICATION",
            Self::CanonicalWrite => "CANONICAL_WRITE",
            Self::NormalBackground => "NORMAL_BACKGROUND",
            Self::ModelJob => "MODEL_JOB",
            Self::Swarm => "SWARM",
            Self::Reporting => "REPORTING",
            Self::Maintenance => "MAINTENANCE",
        }
    }
}

/// Protected control operation classes from the frozen contract (issue #293).
///
/// Closed set: every value maps only to [`CapacityClass::ProtectedControl`]
/// and the set contains no ordinary read, write, verification, model, swarm,
/// report or maintenance work. Only these operations can acquire a protected
/// permit; a protected label never creates authority for the operation itself.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum ControlOperationClass {
    /// Operation cancellation.
    CancelOperation,
    /// Fencing a stale owner.
    FenceStaleOwner,
    /// Authority revocation.
    RevokeAuthority,
    /// Health/readiness control.
    HealthReadinessControl,
    /// Critical telemetry.
    CriticalTelemetry,
    /// Critical Attention transition.
    CriticalAttentionTransition,
    /// Problem transition.
    ProblemTransition,
    /// Incident transition.
    IncidentTransition,
    /// Persistent notification transition.
    PersistentNotificationTransition,
    /// Safe shutdown.
    SafeShutdown,
    /// Drain.
    Drain,
    /// Recovery.
    Recovery,
    /// Containment.
    Containment,
    /// Exact reconciliation of an unknown outcome.
    UnknownOutcomeReconciliation,
}

impl ControlOperationClass {
    /// Returns the exact contract identifier (`CANCEL_OPERATION`, ...).
    #[must_use]
    pub const fn as_contract_str(self) -> &'static str {
        match self {
            Self::CancelOperation => "CANCEL_OPERATION",
            Self::FenceStaleOwner => "FENCE_STALE_OWNER",
            Self::RevokeAuthority => "REVOKE_AUTHORITY",
            Self::HealthReadinessControl => "HEALTH_READINESS_CONTROL",
            Self::CriticalTelemetry => "CRITICAL_TELEMETRY",
            Self::CriticalAttentionTransition => "CRITICAL_ATTENTION_TRANSITION",
            Self::ProblemTransition => "PROBLEM_TRANSITION",
            Self::IncidentTransition => "INCIDENT_TRANSITION",
            Self::PersistentNotificationTransition => "PERSISTENT_NOTIFICATION_TRANSITION",
            Self::SafeShutdown => "SAFE_SHUTDOWN",
            Self::Drain => "DRAIN",
            Self::Recovery => "RECOVERY",
            Self::Containment => "CONTAINMENT",
            Self::UnknownOutcomeReconciliation => "UNKNOWN_OUTCOME_RECONCILIATION",
        }
    }
}

/// Emergency last-resort operation classes from the frozen contract (#293).
///
/// Closed set mapping only to [`CapacityClass::EmergencyLastResort`]. These
/// operations cannot execute ordinary workload and cannot replace protected
/// capacity; they exist only to record reserve loss/gap or enter recovery when
/// the protected reserve itself is gone.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum EmergencyOperationClass {
    /// Record a reserve-exhaustion gap.
    ReserveExhaustionGapRecord,
    /// Record the loss of the control guarantee.
    ControlGuaranteeLostRecord,
    /// Enter manual/platform recovery.
    EnterManualRecovery,
}

impl EmergencyOperationClass {
    /// Returns the exact contract identifier (`RESERVE_EXHAUSTION_GAP_RECORD`, ...).
    #[must_use]
    pub const fn as_contract_str(self) -> &'static str {
        match self {
            Self::ReserveExhaustionGapRecord => "RESERVE_EXHAUSTION_GAP_RECORD",
            Self::ControlGuaranteeLostRecord => "CONTROL_GUARANTEE_LOST_RECORD",
            Self::EnterManualRecovery => "ENTER_MANUAL_RECOVERY",
        }
    }
}

/// Capacity bottlenecks from the frozen contract (issue #293).
///
/// Complete denominator: one profile row per value, each with its own unit —
/// heterogeneous quantities are never summed into one scalar percentage and one
/// exhausted bottleneck never implies another is exhausted. This slice enforces
/// the front-door bottleneck ([`FRONT_DOOR_BOTTLENECK`]); the ORS, Store,
/// process, notification, CPU/memory, pipe/handle and disk bottlenecks receive
/// their own owner adapters in later issue-#65 waves.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum CapacityBottleneck {
    /// Kernel front-door/control channel (enforced by this module).
    KernelControlChannel,
    /// Kernel runnable control slots.
    KernelRunnableControlSlots,
    /// ORS transaction slots.
    OrsTransactionSlots,
    /// ORS durable queue bytes.
    OrsDurableQueueBytes,
    /// Store bridge connection slots.
    StoreConnectionSlots,
    /// Store bridge transaction slots.
    StoreTransactionSlots,
    /// Store bridge pending-write memory.
    StorePendingWriteMemory,
    /// Host/Kernel process launch slots.
    ProcessLaunchSlots,
    /// Process cancellation/termination path.
    ProcessCancellationTermination,
    /// Governor notification/persistent inbox.
    NotificationPersistentInbox,
    /// CPU control task slots.
    CpuControlTaskSlots,
    /// Protected memory bytes.
    ProtectedMemoryBytes,
    /// Pipe/message bytes.
    PipeMessageBytes,
    /// File descriptor/handle slots.
    FileDescriptorHandleSlots,
    /// Disk queue/write capacity.
    DiskQueueWriteCapacity,
}

impl CapacityBottleneck {
    /// Returns the exact contract identifier (`KERNEL_CONTROL_CHANNEL`, ...).
    #[must_use]
    pub const fn as_contract_str(self) -> &'static str {
        match self {
            Self::KernelControlChannel => "KERNEL_CONTROL_CHANNEL",
            Self::KernelRunnableControlSlots => "KERNEL_RUNNABLE_CONTROL_SLOTS",
            Self::OrsTransactionSlots => "ORS_TRANSACTION_SLOTS",
            Self::OrsDurableQueueBytes => "ORS_DURABLE_QUEUE_BYTES",
            Self::StoreConnectionSlots => "STORE_CONNECTION_SLOTS",
            Self::StoreTransactionSlots => "STORE_TRANSACTION_SLOTS",
            Self::StorePendingWriteMemory => "STORE_PENDING_WRITE_MEMORY",
            Self::ProcessLaunchSlots => "PROCESS_LAUNCH_SLOTS",
            Self::ProcessCancellationTermination => "PROCESS_CANCELLATION_TERMINATION",
            Self::NotificationPersistentInbox => "NOTIFICATION_PERSISTENT_INBOX",
            Self::CpuControlTaskSlots => "CPU_CONTROL_TASK_SLOTS",
            Self::ProtectedMemoryBytes => "PROTECTED_MEMORY_BYTES",
            Self::PipeMessageBytes => "PIPE_MESSAGE_BYTES",
            Self::FileDescriptorHandleSlots => "FILE_DESCRIPTOR_HANDLE_SLOTS",
            Self::DiskQueueWriteCapacity => "DISK_QUEUE_WRITE_CAPACITY",
        }
    }
}

/// The exact bottleneck enforced by [`FrontDoor`] in this slice.
pub const FRONT_DOOR_BOTTLENECK: CapacityBottleneck = CapacityBottleneck::KernelControlChannel;

/// Preallocated emergency last-resort slots (I14.3).
///
/// The slot lives outside normal and protected accounting and is never
/// borrowable by either class.
pub const EMERGENCY_PREALLOCATED_SLOTS: usize = 1;

/// Typed operation identity carried by every [`ControlPermit`].
///
/// The variant determines the only admissible [`CapacityClass`]: a normal work
/// class cannot name a protected operation and vice versa, so a normal Store
/// write, named read or agent admission fails to typecheck against the
/// protected acquisition path instead of failing at runtime.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PermitOperation {
    /// Ordinary workload operation.
    Normal(NormalWorkClass),
    /// Protected control/recovery operation.
    Protected(ControlOperationClass),
    /// Emergency last-resort operation.
    Emergency(EmergencyOperationClass),
    /// Migration-only marker for pre-slice-A holders.
    ///
    /// Consumes the protected partition with the current epoch honestly
    /// recorded as unattributed. New code must use a typed variant; Slice B
    /// (issue #65 service wave) removes the remaining legacy holders.
    LegacyControl,
}

impl PermitOperation {
    /// Returns the capacity class this operation draws from.
    #[must_use]
    pub const fn capacity_class(self) -> CapacityClass {
        match self {
            Self::Normal(_) => CapacityClass::NormalWorkload,
            Self::Emergency(_) => CapacityClass::EmergencyLastResort,
            Self::Protected(_) | Self::LegacyControl => CapacityClass::ProtectedControl,
        }
    }

    /// Returns the contract operation label, or the legacy migration marker.
    #[must_use]
    pub const fn contract_label(self) -> &'static str {
        match self {
            Self::Normal(work) => work.as_contract_str(),
            Self::Protected(operation) => operation.as_contract_str(),
            Self::Emergency(operation) => operation.as_contract_str(),
            Self::LegacyControl => "LEGACY_CONTROL",
        }
    }
}

/// A partitioned control reserve that normal work can never starve.
///
/// The reserve holds three disjoint atomic partitions — normal workload,
/// protected control/recovery, and one preallocated emergency last-resort slot
/// — instead of the former single pool. Acquiring from one partition never
/// observes or consumes another: saturating normal admission leaves the full
/// protected capacity available and vice versa. Acquiring is non-blocking and
/// atomic; releasing is automatic when the returned [`ControlPermit`] drops.
/// Each partition fails closed with its own per-bottleneck disposition
/// carrying operation, owner and epoch identity.
#[derive(Clone, Debug)]
pub struct ControlReserve {
    inner: Arc<PartitionedInner>,
}

#[derive(Debug)]
struct PartitionedInner {
    normal_capacity: usize,
    protected_capacity: usize,
    emergency_capacity: usize,
    normal_in_flight: AtomicUsize,
    protected_in_flight: AtomicUsize,
    emergency_in_flight: AtomicUsize,
}

/// A single held capacity permit, bound to class, bottleneck, operation, owner
/// and epoch. Releasing is automatic on drop and returns exactly the consumed
/// partition.
///
/// Permits are deliberately not [`Clone`]: duplicating a permit handle must
/// never duplicate the underlying capacity.
#[derive(Debug)]
pub struct ControlPermit {
    inner: Arc<PartitionedInner>,
    class: CapacityClass,
    bottleneck: CapacityBottleneck,
    operation: PermitOperation,
    operation_id: String,
    owner: String,
    epoch: AuthorityEpoch,
}

impl ControlPermit {
    /// Returns the capacity class (partition) this permit holds.
    #[must_use]
    pub const fn capacity_class(&self) -> CapacityClass {
        self.class
    }

    /// Returns the bottleneck this permit was granted from.
    #[must_use]
    pub const fn bottleneck(&self) -> CapacityBottleneck {
        self.bottleneck
    }

    /// Returns the typed operation identity carried by this permit.
    #[must_use]
    pub const fn operation(&self) -> PermitOperation {
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

    /// Returns the front-door epoch bound at acquisition.
    #[must_use]
    pub const fn epoch(&self) -> AuthorityEpoch {
        self.epoch
    }
}

impl ControlReserve {
    /// Creates a reserve with symmetric migration partitions.
    ///
    /// Both the normal and protected partitions receive `capacity` slots plus
    /// the one preallocated emergency slot, so pre-slice-A holders observe at
    /// least the capacity they configured while normal saturation stops
    /// consuming protected permits through the new typed paths. Canonical new
    /// code uses [`Self::partitioned`] with exact per-class limits.
    ///
    /// # Errors
    ///
    /// Returns an error when the capacity is zero.
    pub fn new(capacity: usize) -> Result<Self, KernelError> {
        Self::partitioned(capacity, capacity)
    }

    /// Creates a reserve with disjoint normal and protected partitions.
    ///
    /// The emergency last-resort slot ([`EMERGENCY_PREALLOCATED_SLOTS`]) is
    /// always preallocated outside both partitions and is borrowable by
    /// neither class.
    ///
    /// # Errors
    ///
    /// Returns an error when either partition capacity is zero.
    pub fn partitioned(
        normal_capacity: usize,
        protected_capacity: usize,
    ) -> Result<Self, KernelError> {
        if normal_capacity == 0 {
            return Err(KernelError::InvalidField {
                field: "control_reserve.normal_capacity",
                reason: "must be greater than zero",
            });
        }
        if protected_capacity == 0 {
            return Err(KernelError::InvalidField {
                field: "control_reserve.protected_capacity",
                reason: "must be greater than zero",
            });
        }
        Ok(Self {
            inner: Arc::new(PartitionedInner {
                normal_capacity,
                protected_capacity,
                emergency_capacity: EMERGENCY_PREALLOCATED_SLOTS,
                normal_in_flight: AtomicUsize::new(0),
                protected_in_flight: AtomicUsize::new(0),
                emergency_in_flight: AtomicUsize::new(0),
            }),
        })
    }

    /// Returns the configured normal-workload partition capacity.
    #[must_use]
    pub fn normal_capacity(&self) -> usize {
        self.inner.normal_capacity
    }

    /// Returns the configured protected-control partition capacity.
    #[must_use]
    pub fn protected_capacity(&self) -> usize {
        self.inner.protected_capacity
    }

    /// Returns the preallocated emergency last-resort capacity.
    #[must_use]
    pub fn emergency_capacity(&self) -> usize {
        self.inner.emergency_capacity
    }

    /// Returns the legacy single-pool capacity view (the protected partition).
    ///
    /// Migration-only: pre-slice-A code observed one pool, which now maps to
    /// the protected partition that legacy holders consume.
    #[must_use]
    pub fn capacity(&self) -> usize {
        self.inner.protected_capacity
    }

    /// Returns the currently available normal-workload permits.
    #[must_use]
    pub fn available_normal(&self) -> usize {
        self.inner
            .normal_capacity
            .saturating_sub(self.inner.normal_in_flight.load(Ordering::Acquire))
    }

    /// Returns the currently available protected-control permits.
    #[must_use]
    pub fn available_protected(&self) -> usize {
        self.inner
            .protected_capacity
            .saturating_sub(self.inner.protected_in_flight.load(Ordering::Acquire))
    }

    /// Returns the currently available emergency last-resort slots.
    #[must_use]
    pub fn available_emergency(&self) -> usize {
        self.inner
            .emergency_capacity
            .saturating_sub(self.inner.emergency_in_flight.load(Ordering::Acquire))
    }

    /// Returns the legacy single-pool availability view (the protected partition).
    ///
    /// Migration-only: pre-slice-A code observed one counter, which now maps to
    /// the protected partition that legacy holders consume.
    #[must_use]
    pub fn available(&self) -> usize {
        self.available_protected()
    }

    /// Attempts to acquire one normal-workload permit without blocking.
    ///
    /// Only [`NormalWorkClass`] operations typecheck here, so protected and
    /// emergency capacity is unreachable through this path by construction.
    ///
    /// # Errors
    ///
    /// Returns [`KernelError::InvalidField`] for a blank or malformed
    /// owner/operation identity, or [`KernelError::NormalCapacityExhausted`]
    /// naming the bottleneck and shed work when the normal partition is
    /// saturated. The protected partition is untouched in every case.
    pub fn try_acquire_normal(
        &self,
        work: NormalWorkClass,
        owner: &str,
        operation_id: &str,
        epoch: AuthorityEpoch,
    ) -> Result<ControlPermit, KernelError> {
        validate_id(owner, "control_permit.owner")?;
        validate_id(operation_id, "control_permit.operation_id")?;
        if !cas_increment(&self.inner.normal_in_flight, self.inner.normal_capacity) {
            return Err(KernelError::NormalCapacityExhausted {
                bottleneck: FRONT_DOOR_BOTTLENECK,
                work_class: work,
                operation_id: operation_id.to_owned(),
                owner: owner.to_owned(),
                epoch,
            });
        }
        Ok(ControlPermit {
            inner: self.inner.clone(),
            class: CapacityClass::NormalWorkload,
            bottleneck: FRONT_DOOR_BOTTLENECK,
            operation: PermitOperation::Normal(work),
            operation_id: operation_id.to_owned(),
            owner: owner.to_owned(),
            epoch,
        })
    }

    /// Attempts to acquire one protected-control permit without blocking.
    ///
    /// Only [`ControlOperationClass`] operations typecheck here: a normal Store
    /// write, named read, agent admission or module job cannot name a protected
    /// operation and therefore cannot acquire this partition.
    ///
    /// # Errors
    ///
    /// Returns [`KernelError::InvalidField`] for a blank or malformed
    /// owner/operation identity, or [`KernelError::ProtectedReserveExhausted`]
    /// naming the bottleneck, operation, owner and epoch when the protected
    /// partition is saturated.
    pub fn try_acquire_protected(
        &self,
        operation: ControlOperationClass,
        owner: &str,
        operation_id: &str,
        epoch: AuthorityEpoch,
    ) -> Result<ControlPermit, KernelError> {
        validate_id(owner, "control_permit.owner")?;
        validate_id(operation_id, "control_permit.operation_id")?;
        if !cas_increment(
            &self.inner.protected_in_flight,
            self.inner.protected_capacity,
        ) {
            return Err(KernelError::ProtectedReserveExhausted {
                bottleneck: FRONT_DOOR_BOTTLENECK,
                operation,
                operation_id: operation_id.to_owned(),
                owner: owner.to_owned(),
                epoch,
            });
        }
        Ok(ControlPermit {
            inner: self.inner.clone(),
            class: CapacityClass::ProtectedControl,
            bottleneck: FRONT_DOOR_BOTTLENECK,
            operation: PermitOperation::Protected(operation),
            operation_id: operation_id.to_owned(),
            owner: owner.to_owned(),
            epoch,
        })
    }

    /// Attempts to acquire the preallocated emergency last-resort slot.
    ///
    /// Only [`EmergencyOperationClass`] operations typecheck here. The slot is
    /// outside normal and protected accounting and is borrowable by neither.
    ///
    /// # Errors
    ///
    /// Returns [`KernelError::InvalidField`] for a blank or malformed
    /// owner/operation identity, [`KernelError::EmergencySlotUnavailable`] when
    /// the slot is held while a protected path remains to record the gap, or
    /// [`KernelError::ControlGuaranteeLost`] when the protected reserve is also
    /// exhausted and the loss cannot be recorded through any remaining path.
    pub fn try_acquire_emergency(
        &self,
        operation: EmergencyOperationClass,
        owner: &str,
        operation_id: &str,
        epoch: AuthorityEpoch,
    ) -> Result<ControlPermit, KernelError> {
        validate_id(owner, "control_permit.owner")?;
        validate_id(operation_id, "control_permit.operation_id")?;
        if cas_increment(
            &self.inner.emergency_in_flight,
            self.inner.emergency_capacity,
        ) {
            return Ok(ControlPermit {
                inner: self.inner.clone(),
                class: CapacityClass::EmergencyLastResort,
                bottleneck: FRONT_DOOR_BOTTLENECK,
                operation: PermitOperation::Emergency(operation),
                operation_id: operation_id.to_owned(),
                owner: owner.to_owned(),
                epoch,
            });
        }
        if self.available_protected() == 0 {
            return Err(KernelError::ControlGuaranteeLost {
                bottleneck: FRONT_DOOR_BOTTLENECK,
                detail: "emergency last-resort slot unavailable and protected reserve exhausted; reserve loss cannot be recorded through any remaining path"
                    .to_owned(),
            });
        }
        Err(KernelError::EmergencySlotUnavailable {
            bottleneck: FRONT_DOOR_BOTTLENECK,
            operation,
            operation_id: operation_id.to_owned(),
            owner: owner.to_owned(),
            epoch,
        })
    }

    /// Acquires one protected-partition slot with legacy migration attribution.
    ///
    /// The current-epoch lineage is honestly recorded as unattributed
    /// ([`PermitOperation::LegacyControl`]); the operation itself stays unnamed
    /// rather than borrowing a real control-operation label.
    pub(crate) fn acquire_legacy_protected(&self, epoch: AuthorityEpoch) -> Option<ControlPermit> {
        if !cas_increment(
            &self.inner.protected_in_flight,
            self.inner.protected_capacity,
        ) {
            return None;
        }
        Some(ControlPermit {
            inner: self.inner.clone(),
            class: CapacityClass::ProtectedControl,
            bottleneck: FRONT_DOOR_BOTTLENECK,
            operation: PermitOperation::LegacyControl,
            operation_id: "legacy-control".to_owned(),
            owner: "legacy-control-reserve".to_owned(),
            epoch,
        })
    }
}

/// Atomically increments `slot` unless `capacity` is already reached.
fn cas_increment(slot: &AtomicUsize, capacity: usize) -> bool {
    let mut observed = slot.load(Ordering::Acquire);
    loop {
        if observed >= capacity {
            return false;
        }
        match slot.compare_exchange_weak(
            observed,
            observed + 1,
            Ordering::AcqRel,
            Ordering::Acquire,
        ) {
            Ok(_) => return true,
            Err(current) => observed = current,
        }
    }
}

impl Drop for ControlPermit {
    fn drop(&mut self) {
        let slot = match self.class {
            CapacityClass::NormalWorkload => &self.inner.normal_in_flight,
            CapacityClass::ProtectedControl => &self.inner.protected_in_flight,
            CapacityClass::EmergencyLastResort => &self.inner.emergency_in_flight,
        };
        debug_assert!(
            slot.load(Ordering::Acquire) > 0,
            "control permit drop without a held partition slot"
        );
        slot.fetch_sub(1, Ordering::AcqRel);
    }
}

/// The stable denial reason surfaced by the front door.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DecisionDenialReason {
    /// The receipt failed its cryptographic binding.
    ForgedReceipt,
    /// The receipt belongs to a fenced epoch.
    StaleEpoch,
    /// The receipt targets a different route.
    RouteMismatch,
    /// The receipt has expired.
    Expired,
}

/// The result of one front-door admission decision.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AuthorityDecision {
    /// The receipt verified and the granted authority is returned.
    Granted(AuthorityGrant),
    /// The receipt could not authorize the request.
    Denied {
        /// Stable denial reason.
        reason: DecisionDenialReason,
    },
}

impl AuthorityDecision {
    /// Returns the granted authority, if any.
    #[must_use]
    pub fn granted(&self) -> Option<&AuthorityGrant> {
        match self {
            Self::Granted(grant) => Some(grant),
            Self::Denied { .. } => None,
        }
    }

    /// Returns `true` only for a granted decision.
    #[must_use]
    pub const fn is_granted(&self) -> bool {
        matches!(self, Self::Granted(_))
    }
}

/// The outcome of resolving an idempotency key before any effect.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum IdempotencyDisposition {
    /// The key has never been seen.
    New,
    /// The key was seen with the same digest; replay the prior decision.
    Replay(AuthorityDecision),
    /// The key was seen with a different digest.
    Conflict,
}

/// A bounded idempotency ledger that deduplicates effect admission.
///
/// The ledger is FIFO-bounded: when it reaches capacity, the oldest entry is
/// evicted, so a very old replay is re-evaluated rather than silently reused.
#[derive(Debug)]
pub struct IdempotencyLedger {
    capacity: usize,
    entries: BTreeMap<String, (String, AuthorityDecision)>,
    order: VecDeque<String>,
}

impl IdempotencyLedger {
    /// Creates a bounded ledger.
    ///
    /// # Errors
    ///
    /// Returns an error when the capacity is zero.
    pub fn new(capacity: usize) -> Result<Self, KernelError> {
        if capacity == 0 {
            return Err(KernelError::InvalidField {
                field: "idempotency_ledger.capacity",
                reason: "must be greater than zero",
            });
        }
        Ok(Self {
            capacity,
            entries: BTreeMap::new(),
            order: VecDeque::new(),
        })
    }

    /// Resolves an idempotency key against a request digest.
    #[must_use]
    pub fn resolve(&self, key: &str, digest: &str) -> IdempotencyDisposition {
        match self.entries.get(key) {
            Some((prior_digest, decision)) if prior_digest == digest => {
                IdempotencyDisposition::Replay(decision.clone())
            }
            Some(_) => IdempotencyDisposition::Conflict,
            None => IdempotencyDisposition::New,
        }
    }

    /// Records a decision under an idempotency key, evicting the oldest on overflow.
    ///
    /// # Errors
    ///
    /// Returns an error when the key is blank or malformed.
    pub fn record(
        &mut self,
        key: &str,
        digest: &str,
        decision: AuthorityDecision,
    ) -> Result<(), KernelError> {
        validate_id(key, "idempotency_key")?;
        validate_id(digest, "request_digest")?;
        if !self.entries.contains_key(key) {
            self.order.push_back(key.to_owned());
        }
        self.entries
            .insert(key.to_owned(), (digest.to_owned(), decision));
        while self.order.len() > self.capacity {
            if let Some(oldest) = self.order.pop_front() {
                self.entries.remove(&oldest);
            }
        }
        Ok(())
    }
}

/// The Kernel front door: the single synchronous admission decision core.
pub struct FrontDoor {
    authority: KernelAuthority,
    reserve: ControlReserve,
    ledger: Mutex<IdempotencyLedger>,
}

impl FrontDoor {
    /// Creates a front door from an authority holder and bounded parameters.
    ///
    /// Migration provisioning: both the normal and protected partitions receive
    /// `control_capacity` slots plus the preallocated emergency slot, so
    /// pre-slice-A holders observe at least the capacity they configured.
    /// Canonical new code uses [`Self::partitioned`] with exact per-class
    /// limits. Slice B (issue #65 service wave) moves normal Store/daemon
    /// admission onto the normal partition explicitly.
    ///
    /// # Errors
    ///
    /// Returns an error when `control_capacity` or `ledger_capacity` is zero.
    pub fn new(
        authority: KernelAuthority,
        control_capacity: usize,
        ledger_capacity: usize,
    ) -> Result<Self, KernelError> {
        Ok(Self {
            authority,
            reserve: ControlReserve::new(control_capacity)?,
            ledger: Mutex::new(IdempotencyLedger::new(ledger_capacity)?),
        })
    }

    /// Creates a front door with disjoint normal and protected partitions.
    ///
    /// The emergency last-resort slot is always preallocated outside both
    /// partitions (I14.3) and is borrowable by neither class.
    ///
    /// # Errors
    ///
    /// Returns an error when any capacity is zero.
    pub fn partitioned(
        authority: KernelAuthority,
        normal_capacity: usize,
        protected_capacity: usize,
        ledger_capacity: usize,
    ) -> Result<Self, KernelError> {
        Ok(Self {
            authority,
            reserve: ControlReserve::partitioned(normal_capacity, protected_capacity)?,
            ledger: Mutex::new(IdempotencyLedger::new(ledger_capacity)?),
        })
    }

    /// Returns the current authority epoch.
    #[must_use]
    pub const fn epoch(&self) -> eliot_contracts::AuthorityEpoch {
        self.authority.current_epoch()
    }

    /// Returns the configured normal-workload partition capacity.
    #[must_use]
    pub fn normal_capacity(&self) -> usize {
        self.reserve.normal_capacity()
    }

    /// Returns the configured protected-control partition capacity.
    #[must_use]
    pub fn protected_capacity(&self) -> usize {
        self.reserve.protected_capacity()
    }

    /// Returns the preallocated emergency last-resort capacity.
    #[must_use]
    pub fn emergency_capacity(&self) -> usize {
        self.reserve.emergency_capacity()
    }

    /// Returns the currently available control permits (protected partition).
    ///
    /// Migration-only view for pre-slice-A holders; new code observes each
    /// partition through [`Self::available_normal`],
    /// [`Self::available_protected`] and [`Self::available_emergency`].
    #[must_use]
    pub fn available_control(&self) -> usize {
        self.reserve.available_protected()
    }

    /// Returns the currently available normal-workload permits.
    #[must_use]
    pub fn available_normal(&self) -> usize {
        self.reserve.available_normal()
    }

    /// Returns the currently available protected-control permits.
    #[must_use]
    pub fn available_protected(&self) -> usize {
        self.reserve.available_protected()
    }

    /// Returns the currently available emergency last-resort slots.
    #[must_use]
    pub fn available_emergency(&self) -> usize {
        self.reserve.available_emergency()
    }

    /// Admits one authority receipt through the control reserve and ledger.
    ///
    /// Migration path: the call-scoped permit is drawn from the protected
    /// partition with legacy attribution. Callers that need to keep capacity
    /// held across a long effect should use the typed acquisitions
    /// ([`Self::acquire_normal`], [`Self::acquire_protected`],
    /// [`Self::acquire_emergency`]) or, while migrating, [`Self::acquire_control`]
    /// explicitly.
    ///
    /// # Errors
    ///
    /// Returns [`KernelError::ControlReserveExhausted`] or
    /// [`KernelError::IdempotencyConflict`]. Receipt rejections are returned as
    /// [`AuthorityDecision::Denied`], never as an error.
    pub fn authorize(
        &self,
        receipt: &AuthorityReceipt,
        route: &RouteScope,
        now_ms: i64,
        idempotency_key: &str,
        request_digest: &str,
    ) -> Result<AuthorityDecision, KernelError> {
        let _permit = self
            .reserve
            .acquire_legacy_protected(self.authority.current_epoch())
            .ok_or(KernelError::ControlReserveExhausted)?;
        let mut ledger = self.lock_ledger();
        match ledger.resolve(idempotency_key, request_digest) {
            IdempotencyDisposition::Replay(decision) => return Ok(decision),
            IdempotencyDisposition::Conflict => return Err(KernelError::IdempotencyConflict),
            IdempotencyDisposition::New => {}
        }
        let decision = match self.authority.consume(receipt, route, now_ms) {
            Ok(grant) => AuthorityDecision::Granted(grant),
            Err(KernelError::ForgedReceipt) => AuthorityDecision::Denied {
                reason: DecisionDenialReason::ForgedReceipt,
            },
            Err(KernelError::StaleEpoch { .. }) => AuthorityDecision::Denied {
                reason: DecisionDenialReason::StaleEpoch,
            },
            Err(KernelError::RouteMismatch) => AuthorityDecision::Denied {
                reason: DecisionDenialReason::RouteMismatch,
            },
            Err(KernelError::Expired { .. }) => AuthorityDecision::Denied {
                reason: DecisionDenialReason::Expired,
            },
            Err(error) => return Err(error),
        };
        ledger.record(idempotency_key, request_digest, decision.clone())?;
        Ok(decision)
    }

    /// Acquires a control permit explicitly for a long-running control effect.
    ///
    /// Migration-only: draws from the protected partition with legacy
    /// attribution bound to the current epoch. Normal Store/daemon admission
    /// must move to [`Self::acquire_normal`]; only closed
    /// [`ControlOperationClass`] operations may use [`Self::acquire_protected`].
    /// Slice B (issue #65 service wave) migrates the remaining holders.
    ///
    /// # Errors
    ///
    /// Returns [`KernelError::ControlReserveExhausted`] when saturated.
    pub fn acquire_control(&self) -> Result<ControlPermit, KernelError> {
        self.reserve
            .acquire_legacy_protected(self.authority.current_epoch())
            .ok_or(KernelError::ControlReserveExhausted)
    }

    /// Acquires one normal-workload permit for ordinary admission.
    ///
    /// The `work` class typechecks the caller: Store writes
    /// ([`NormalWorkClass::CanonicalWrite`]), named reads
    /// ([`NormalWorkClass::Interactive`]) and agent admission
    /// ([`NormalWorkClass::Swarm`]) draw only from the normal partition and can
    /// never consume protected or emergency capacity. The permit binds the
    /// current front-door epoch; `owner` and `operation_id` attribute the
    /// holder for observability.
    ///
    /// # Errors
    ///
    /// Returns [`KernelError::InvalidField`] for a blank or malformed
    /// owner/operation identity, or [`KernelError::NormalCapacityExhausted`]
    /// naming the bottleneck and shed work when the normal partition is
    /// saturated.
    pub fn acquire_normal(
        &self,
        work: NormalWorkClass,
        owner: &str,
        operation_id: &str,
    ) -> Result<ControlPermit, KernelError> {
        let epoch = self.authority.current_epoch();
        self.reserve
            .try_acquire_normal(work, owner, operation_id, epoch)
    }

    /// Acquires one protected-control permit for a control/recovery operation.
    ///
    /// Only [`ControlOperationClass`] operations typecheck here. The permit
    /// binds the current front-door epoch; `owner` and `operation_id`
    /// attribute the holder for observability.
    ///
    /// # Errors
    ///
    /// Returns [`KernelError::InvalidField`] for a blank or malformed
    /// owner/operation identity, or [`KernelError::ProtectedReserveExhausted`]
    /// naming the bottleneck, operation, owner and epoch when saturated.
    pub fn acquire_protected(
        &self,
        operation: ControlOperationClass,
        owner: &str,
        operation_id: &str,
    ) -> Result<ControlPermit, KernelError> {
        let epoch = self.authority.current_epoch();
        self.reserve
            .try_acquire_protected(operation, owner, operation_id, epoch)
    }

    /// Acquires the preallocated emergency last-resort slot.
    ///
    /// Only [`EmergencyOperationClass`] operations typecheck here: recording
    /// reserve loss/gap or entering manual recovery. The slot is outside
    /// normal and protected accounting and is borrowable by neither.
    ///
    /// # Errors
    ///
    /// Returns [`KernelError::InvalidField`] for a blank or malformed
    /// owner/operation identity, [`KernelError::EmergencySlotUnavailable`]
    /// while a protected path remains, or [`KernelError::ControlGuaranteeLost`]
    /// when no path remains to record the loss.
    pub fn acquire_emergency(
        &self,
        operation: EmergencyOperationClass,
        owner: &str,
        operation_id: &str,
    ) -> Result<ControlPermit, KernelError> {
        let epoch = self.authority.current_epoch();
        self.reserve
            .try_acquire_emergency(operation, owner, operation_id, epoch)
    }

    /// Raises the front-door epoch and fences all previously issued receipts.
    ///
    /// # Errors
    ///
    /// Returns an error when the epoch counter cannot advance.
    pub fn advance_epoch(&mut self) -> Result<eliot_contracts::AuthorityEpoch, KernelError> {
        self.authority.advance_epoch()
    }

    /// Fast-forwards the front-door fence to the durable recovery epoch.
    pub fn synchronize_epoch(
        &mut self,
        target: eliot_contracts::AuthorityEpoch,
    ) -> Result<eliot_contracts::AuthorityEpoch, KernelError> {
        self.authority.synchronize_epoch(target)
    }

    /// Returns whether a grant permits an effect without overclaiming proof.
    #[must_use]
    pub fn permits(
        grant: &AuthorityGrant,
        class: eliot_receipts::EffectClass,
        ceiling: ProofCeiling,
    ) -> bool {
        grant.permits(class, ceiling)
    }

    fn lock_ledger(&self) -> MutexGuard<'_, IdempotencyLedger> {
        self.ledger
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;
    use eliot_contracts::{AuthorityEpoch, ContractId, ResourceGeneration};
    use eliot_receipts::EffectClass;

    fn receipt(authority: &KernelAuthority) -> Result<AuthorityReceipt, KernelError> {
        authority.issue(crate::authority::AuthorityGrantRequest::new(
            ContractId::new("authority-1")?,
            "kernel",
            RouteScope::new("daemon")?,
            ResourceGeneration::genesis(),
            EffectClass::ReversibleMutation,
            ProofCeiling::ScopedVerification,
            100,
            Some(1_000),
        )?)
    }

    #[test]
    fn control_reserve_is_bounded_and_auto_releases() -> Result<(), KernelError> {
        let reserve = ControlReserve::partitioned(2, 2)?;
        let epoch = AuthorityEpoch::genesis();
        let a = reserve
            .try_acquire_protected(
                ControlOperationClass::CancelOperation,
                "test-owner",
                "op-a",
                epoch,
            )
            .expect("first permit");
        let b = reserve
            .try_acquire_protected(
                ControlOperationClass::CancelOperation,
                "test-owner",
                "op-b",
                epoch,
            )
            .expect("second permit");
        assert!(matches!(
            reserve.try_acquire_protected(
                ControlOperationClass::CancelOperation,
                "test-owner",
                "op-c",
                epoch
            ),
            Err(KernelError::ProtectedReserveExhausted { .. })
        ));
        drop(a);
        assert_eq!(reserve.available_protected(), 1);
        assert!(
            reserve
                .try_acquire_protected(
                    ControlOperationClass::CancelOperation,
                    "test-owner",
                    "op-d",
                    epoch
                )
                .is_ok()
        );
        drop(b);
        Ok(())
    }

    #[test]
    fn front_door_grants_valid_and_denies_tampered() -> Result<(), KernelError> {
        let authority = KernelAuthority::new(
            crate::authority::KernelAuthorityKey::from_bytes([3u8; 32]),
            AuthorityEpoch::genesis(),
        );
        let front_door = FrontDoor::new(authority.clone(), 2, 8)?;
        let route = RouteScope::new("daemon")?;
        let receipt = receipt(&authority)?;

        let decision = front_door.authorize(&receipt, &route, 500, "k-1", "d-1")?;
        assert!(decision.is_granted());

        let mut value = serde_json::to_value(&receipt).expect("receipt serializes");
        value["allowed_effect"] = serde_json::json!("EXTERNAL_EFFECT");
        let tampered: AuthorityReceipt =
            serde_json::from_value(value).expect("tampered receipt deserializes");
        let decision = front_door.authorize(&tampered, &route, 500, "k-2", "d-2")?;
        assert!(matches!(
            decision,
            AuthorityDecision::Denied {
                reason: DecisionDenialReason::ForgedReceipt
            }
        ));
        Ok(())
    }

    #[test]
    fn idempotent_replay_and_conflict_are_separate() -> Result<(), KernelError> {
        let authority = KernelAuthority::new(
            crate::authority::KernelAuthorityKey::from_bytes([3u8; 32]),
            AuthorityEpoch::genesis(),
        );
        let front_door = FrontDoor::new(authority.clone(), 2, 8)?;
        let route = RouteScope::new("daemon")?;
        let receipt = receipt(&authority)?;

        let first = front_door.authorize(&receipt, &route, 500, "k-1", "d-1")?;
        let replay = front_door.authorize(&receipt, &route, 500, "k-1", "d-1")?;
        assert_eq!(first, replay);

        assert!(matches!(
            front_door.authorize(&receipt, &route, 500, "k-1", "d-2"),
            Err(KernelError::IdempotencyConflict)
        ));
        Ok(())
    }

    #[test]
    fn control_reserve_exhaustion_fails_closed() -> Result<(), KernelError> {
        let authority = KernelAuthority::new(
            crate::authority::KernelAuthorityKey::from_bytes([3u8; 32]),
            AuthorityEpoch::genesis(),
        );
        let front_door = FrontDoor::new(authority.clone(), 1, 8)?;
        let route = RouteScope::new("daemon")?;
        let receipt = receipt(&authority)?;

        let held = front_door.acquire_control()?;
        assert!(matches!(
            front_door.authorize(&receipt, &route, 500, "k-1", "d-1"),
            Err(KernelError::ControlReserveExhausted)
        ));
        drop(held);
        assert!(
            front_door
                .authorize(&receipt, &route, 500, "k-1", "d-1")?
                .is_granted()
        );
        Ok(())
    }

    #[test]
    fn normal_saturation_leaves_protected_control_available() -> Result<(), KernelError> {
        let authority = KernelAuthority::new(
            crate::authority::KernelAuthorityKey::from_bytes([7u8; 32]),
            AuthorityEpoch::genesis(),
        );
        let front_door = FrontDoor::partitioned(authority, 1, 1, 8)?;

        // A normal Store write consumes the single normal slot.
        let write = front_door.acquire_normal(
            NormalWorkClass::CanonicalWrite,
            "store-bridge",
            "op-store-write-1",
        )?;
        assert_eq!(write.capacity_class(), CapacityClass::NormalWorkload);
        assert_eq!(write.bottleneck(), CapacityBottleneck::KernelControlChannel);
        assert_eq!(
            write.operation(),
            PermitOperation::Normal(NormalWorkClass::CanonicalWrite)
        );

        // A second normal admission (named read) is backpressured with exact
        // bottleneck, operation, owner and epoch identity — it must not spill
        // into the protected partition.
        match front_door.acquire_normal(
            NormalWorkClass::Interactive,
            "agent-admission",
            "op-named-read-1",
        ) {
            Err(KernelError::NormalCapacityExhausted {
                bottleneck,
                work_class,
                operation_id,
                owner,
                epoch,
            }) => {
                assert_eq!(bottleneck, CapacityBottleneck::KernelControlChannel);
                assert_eq!(work_class, NormalWorkClass::Interactive);
                assert_eq!(operation_id, "op-named-read-1");
                assert_eq!(owner, "agent-admission");
                assert_eq!(epoch, AuthorityEpoch::genesis());
            }
            other => panic!("expected typed normal exhaustion, got {other:?}"),
        }

        // The protected reserve is untouched: cancellation still completes
        // while normal work is saturated.
        assert_eq!(front_door.available_protected(), 1);
        let control = front_door.acquire_protected(
            ControlOperationClass::CancelOperation,
            "kernel-control",
            "op-cancel-1",
        )?;
        assert_eq!(control.capacity_class(), CapacityClass::ProtectedControl);
        assert_eq!(
            control.operation(),
            PermitOperation::Protected(ControlOperationClass::CancelOperation)
        );

        drop(write);
        assert_eq!(front_door.available_normal(), 1);
        drop(control);
        Ok(())
    }

    #[test]
    fn protected_and_emergency_permits_are_owner_and_epoch_bound() -> Result<(), KernelError> {
        let authority = KernelAuthority::new(
            crate::authority::KernelAuthorityKey::from_bytes([9u8; 32]),
            AuthorityEpoch::genesis(),
        );
        let front_door = FrontDoor::partitioned(authority, 1, 2, 8)?;
        let epoch = front_door.epoch();

        let permit = front_door.acquire_protected(
            ControlOperationClass::Recovery,
            "kernel-recovery",
            "op-recovery-1",
        )?;
        assert_eq!(permit.capacity_class(), CapacityClass::ProtectedControl);
        assert_eq!(
            permit.bottleneck(),
            CapacityBottleneck::KernelControlChannel
        );
        assert_eq!(permit.owner(), "kernel-recovery");
        assert_eq!(permit.operation_id(), "op-recovery-1");
        assert_eq!(permit.epoch(), epoch);

        // Fill the protected partition; the next control operation observes a
        // typed exhaustion carrying its own operation/owner/epoch identity.
        let held = front_door.acquire_protected(
            ControlOperationClass::FenceStaleOwner,
            "kernel-fencing",
            "op-fence-1",
        )?;
        match front_door.acquire_protected(
            ControlOperationClass::Drain,
            "kernel-drain",
            "op-drain-1",
        ) {
            Err(KernelError::ProtectedReserveExhausted {
                bottleneck,
                operation,
                operation_id,
                owner,
                epoch: observed,
            }) => {
                assert_eq!(bottleneck, CapacityBottleneck::KernelControlChannel);
                assert_eq!(operation, ControlOperationClass::Drain);
                assert_eq!(operation_id, "op-drain-1");
                assert_eq!(owner, "kernel-drain");
                assert_eq!(observed, epoch);
            }
            other => panic!("expected typed protected exhaustion, got {other:?}"),
        }

        // The emergency slot records the gap while a protected path remains.
        let gap = front_door.acquire_emergency(
            EmergencyOperationClass::ReserveExhaustionGapRecord,
            "watchdog",
            "op-gap-1",
        )?;
        assert_eq!(gap.capacity_class(), CapacityClass::EmergencyLastResort);
        drop(held);
        match front_door.acquire_emergency(
            EmergencyOperationClass::ReserveExhaustionGapRecord,
            "watchdog",
            "op-gap-2",
        ) {
            Err(KernelError::EmergencySlotUnavailable {
                bottleneck,
                operation_id,
                ..
            }) => {
                assert_eq!(bottleneck, CapacityBottleneck::KernelControlChannel);
                assert_eq!(operation_id, "op-gap-2");
            }
            other => panic!("expected emergency-slot disposition, got {other:?}"),
        }

        // With the protected reserve re-exhausted, no path remains to record
        // the loss: the system explicitly loses its control guarantee.
        let held_again = front_door.acquire_protected(
            ControlOperationClass::FenceStaleOwner,
            "kernel-fencing",
            "op-fence-2",
        )?;
        match front_door.acquire_emergency(
            EmergencyOperationClass::ControlGuaranteeLostRecord,
            "watchdog",
            "op-gap-3",
        ) {
            Err(KernelError::ControlGuaranteeLost { bottleneck, detail }) => {
                assert_eq!(bottleneck, CapacityBottleneck::KernelControlChannel);
                assert!(!detail.is_empty());
            }
            other => panic!("expected control-guarantee-lost, got {other:?}"),
        }

        drop(permit);
        drop(gap);
        drop(held_again);
        assert_eq!(front_door.available_protected(), 2);
        assert_eq!(front_door.available_emergency(), 1);
        Ok(())
    }

    #[test]
    fn ledger_evicts_oldest_when_full() -> Result<(), KernelError> {
        let mut ledger = IdempotencyLedger::new(2)?;
        ledger.record(
            "a",
            "d",
            AuthorityDecision::Denied {
                reason: DecisionDenialReason::Expired,
            },
        )?;
        ledger.record(
            "b",
            "d",
            AuthorityDecision::Denied {
                reason: DecisionDenialReason::Expired,
            },
        )?;
        ledger.record(
            "c",
            "d",
            AuthorityDecision::Denied {
                reason: DecisionDenialReason::Expired,
            },
        )?;
        assert_eq!(ledger.resolve("a", "d"), IdempotencyDisposition::New);
        assert_eq!(
            ledger.resolve("c", "d"),
            IdempotencyDisposition::Replay(AuthorityDecision::Denied {
                reason: DecisionDenialReason::Expired,
            })
        );
        Ok(())
    }
}
