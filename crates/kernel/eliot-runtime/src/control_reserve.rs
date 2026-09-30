//! Runtime control-reserve partitions for runnable slots and CPU task slots.
//!
//! Issue #1679, W3 runtime wave: the Kernel runtime/control scheduler owner
//! ([`crate::Runtime`]) enforces disjoint normal-workload and
//! protected-control partitions for its two frozen bottlenecks
//! ([`RUNTIME_RUNNABLE_BOTTLENECK`] and [`RUNTIME_CPU_TASK_BOTTLENECK`]).
//! Normal work can saturate the normal partition without consuming protected
//! cancellation/recovery capacity: an admitted cancellation or recovery task
//! keeps the protected path while ordinary work observes exhaustion. Only
//! [`NormalWorkClass`] operations typecheck on the normal acquisition paths
//! and only [`ControlOperationClass`] operations typecheck on the protected
//! paths, so ordinary data work cannot reach protected runtime capacity by
//! relabelling its priority or class.
//!
//! Dimension-to-mechanism binding (the only capacities this reserve enforces):
//!
//! - `KERNEL_RUNNABLE_CONTROL_SLOTS` (`RunnableSlots`): the runtime mailbox
//!   lanes. The normal partition is the data-lane capacity
//!   (`RuntimeConfig::mailbox_capacity`); the protected partition is the
//!   control-lane reserve (`RuntimeConfig::control_reserve`), the physically
//!   separate channel that keeps runnable control signals deliverable while
//!   the data lane is saturated.
//! - `CPU_CONTROL_TASK_SLOTS` (`CpuTaskSlots`): the runtime execution
//!   permits. The normal partition is the data-task concurrency
//!   (`RuntimeConfig::concurrency`); the protected partition is the control
//!   execution reserve (`RuntimeConfig::control_concurrency_reserve`), the
//!   disjoint semaphore normal tasks cannot acquire.
//!
//! Partition sizes are read from the live owner's [`crate::RuntimeConfig`]
//! through [`RuntimeReserve::from_config`], which reuses the existing
//! [`crate::RuntimeConfig::validate`]; no size is defaulted here. The reserve
//! holds no scheduler, no queue and no global lock: four disjoint atomic
//! counters, one per partition, acquired with a single compare-and-swap each.
//!
//! Every [`RuntimePermit`] is owner-issued: permits are constructed only by
//! the [`RuntimeReserve`] acquisition paths, are deliberately not [`Clone`],
//! and release exactly their partition and amount on drop. Each permit is
//! bound to its capacity class, bottleneck (with the exact bottleneck unit),
//! granted amount, typed operation, operation identity, requesting owner, the
//! owner generation and the Authority Epoch the reserve was bound with at
//! construction. The reserve never observes the Authority Epoch itself, so the
//! epoch and owner-generation references are composition-supplied
//! construction evidence echoed into every permit and every published row;
//! the Kernel composition wraps the rows in its own evidence record with the
//! configuration snapshot and Authority Epoch it resolved.
//!
//! [`RuntimeReserve::publish_claimed_row`] publishes the live partition
//! evidence for one runtime dimension as a claimed
//! [`BottleneckCapacityProfile`] row validated by the existing
//! [`BottleneckCapacityProfile::validate`]. The row names the frozen owner the
//! contract binds to the dimension, so the Kernel profile composition joins
//! it in frozen contract order and fails closed on duplicates or
//! contradictions. There is no emergency partition here, so none is claimed;
//! recording reserve loss stays with the front-door last-resort slot.
//!
//! This module has no production caller yet (STITCH): it publishes the owner
//! evidence the Kernel profile composition will join. Rejection/response
//! wiring is a later wave, so this module emits no backpressure dispositions.
//! DISCLOSED LIMIT: the atomic counters here are the permit ledger for the
//! configured partitions; the live task semaphores and mailbox channels of
//! [`crate::Runtime`] remain the execution-time enforcement. Until the
//! composition routes admission through one reserve built from the live
//! configuration, the two accountings are not joined. Full installed
//! saturation proof stays #11 Product scope.
//!
//! `PROTECTED_MEMORY_BYTES` is not implemented here: repository search found
//! no memory-budget owner type that admits byte amounts and reports
//! per-class capacity (`memory_pressure.rs` owns the pressure
//! policy/observation join and explicitly duplicates no reserve accounting;
//! the blob controller owns payload capture with no normal/protected byte
//! partitions). That dimension stays `UNKNOWN` until its owner is found; no
//! number from this reserve is substituted for it.

use std::fmt;
use std::num::NonZeroU64;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use eliot_runtime_contracts::{
    BottleneckCapacityProfile, BottleneckCoverageState, CapacityBottleneck, CapacityClass,
    CapacityEnforcement, CapacityLimit, ControlOperationClass, NormalWorkClass,
    frozen_bottleneck_owner_map,
};

use super::RuntimeConfig;

/// The exact runnable-slot bottleneck enforced by [`RuntimeReserve`].
pub const RUNTIME_RUNNABLE_BOTTLENECK: CapacityBottleneck =
    CapacityBottleneck::KernelRunnableControlSlots;

/// The exact CPU-task-slot bottleneck enforced by [`RuntimeReserve`].
pub const RUNTIME_CPU_TASK_BOTTLENECK: CapacityBottleneck =
    CapacityBottleneck::CpuControlTaskSlots;

/// Maximum length of an owner, operation or reference string, in bytes.
const MAX_REF_LEN: usize = 1_024;

/// Typed runtime reserve failures. None grants execution or semantic authority.
#[derive(Debug)]
pub enum RuntimeReserveError {
    /// An owner, operation or reference identity is blank or malformed, or a
    /// partition capacity is not a positive amount.
    InvalidField {
        /// Failing field name.
        field: &'static str,
        /// Why the field failed.
        reason: &'static str,
    },
    /// The existing contract rejected an assembled runtime reserve row.
    Contract(String),
    /// The normal partition cannot satisfy the request; the protected
    /// partition is untouched.
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

impl fmt::Display for RuntimeReserveError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidField { field, reason } => {
                write!(formatter, "{field} is invalid: {reason}")
            }
            Self::Contract(reason) => {
                write!(formatter, "runtime contract rejected runtime reserve row: {reason}")
            }
            Self::NormalCapacityExhausted {
                bottleneck,
                work_class,
                operation_id,
                owner,
            } => write!(
                formatter,
                "runtime normal capacity exhausted for {bottleneck:?}: work {work_class:?} operation {operation_id} owned by {owner}"
            ),
            Self::ProtectedReserveExhausted {
                bottleneck,
                operation,
                operation_id,
                owner,
            } => write!(
                formatter,
                "runtime protected reserve exhausted for {bottleneck:?}: control operation {operation:?} operation {operation_id} owned by {owner}"
            ),
        }
    }
}

impl std::error::Error for RuntimeReserveError {}

/// Which runtime dimension a permit holds.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RuntimeDimension {
    /// Runnable mailbox slots, counted in runnable slots.
    RunnableSlots,
    /// CPU task execution slots, counted in CPU task slots.
    CpuTaskSlots,
}

impl RuntimeDimension {
    /// Returns the frozen bottleneck enforced for this dimension.
    #[must_use]
    pub const fn bottleneck(self) -> CapacityBottleneck {
        match self {
            Self::RunnableSlots => RUNTIME_RUNNABLE_BOTTLENECK,
            Self::CpuTaskSlots => RUNTIME_CPU_TASK_BOTTLENECK,
        }
    }
}

/// Typed operation identity carried by every [`RuntimePermit`].
///
/// The variant determines the only admissible [`CapacityClass`]: a normal work
/// class cannot name a protected operation and vice versa, so ordinary work
/// fails to typecheck against the protected acquisition paths instead of
/// failing at runtime.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RuntimePermitOperation {
    /// Ordinary workload operation.
    Normal(NormalWorkClass),
    /// Protected cancellation/recovery operation.
    Protected(ControlOperationClass),
}

impl RuntimePermitOperation {
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
struct RuntimeReserveInner {
    runnable_normal_capacity: u64,
    runnable_protected_capacity: u64,
    cpu_normal_capacity: u64,
    cpu_protected_capacity: u64,
    runnable_normal_in_flight: AtomicU64,
    runnable_protected_in_flight: AtomicU64,
    cpu_normal_in_flight: AtomicU64,
    cpu_protected_in_flight: AtomicU64,
    owner_generation_ref: String,
    authority_epoch_ref: String,
}

/// The runtime control reserve: disjoint normal/protected partitions for the
/// two runtime bottlenecks, owned by the Kernel runtime/control scheduler
/// owner.
///
/// Acquiring from one partition never observes or consumes another:
/// saturating normal runnable slots or normal CPU task slots leaves the full
/// protected capacity available for admitted cancellation/recovery work and
/// vice versa. Acquisition is non-blocking and atomic; release is automatic
/// when the returned [`RuntimePermit`] drops.
#[derive(Clone, Debug)]
pub struct RuntimeReserve {
    inner: Arc<RuntimeReserveInner>,
}

/// One held runtime capacity permit, bound to dimension, class, operation,
/// owner and epoch. Releasing is automatic on drop and returns exactly the
/// consumed partition and amount.
///
/// Permits are deliberately not [`Clone`]: duplicating a permit handle must
/// never duplicate the underlying capacity.
#[derive(Debug)]
pub struct RuntimePermit {
    inner: Arc<RuntimeReserveInner>,
    dimension: RuntimeDimension,
    class: CapacityClass,
    amount: u64,
    operation: RuntimePermitOperation,
    operation_id: String,
    owner: String,
}

impl RuntimePermit {
    /// Returns the capacity class (partition) this permit holds.
    #[must_use]
    pub const fn capacity_class(&self) -> CapacityClass {
        self.class
    }

    /// Returns which runtime dimension this permit was granted from.
    #[must_use]
    pub const fn dimension(&self) -> RuntimeDimension {
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
    pub const fn operation(&self) -> RuntimePermitOperation {
        self.operation
    }

    /// Returns the operation identity this permit was granted for.
    #[must_use]
    pub fn operation_id(&self) -> &str {
        &self.operation_id
    }

    /// Returns the requesting owner this permit was granted to.
    #[must_use]
    pub fn owner(&self) -> &str {
        &self.owner
    }

    /// Returns the owner generation this permit was issued under.
    #[must_use]
    pub fn owner_generation_ref(&self) -> &str {
        &self.inner.owner_generation_ref
    }

    /// Returns the Authority Epoch reference this permit is bound to.
    #[must_use]
    pub fn authority_epoch_ref(&self) -> &str {
        &self.inner.authority_epoch_ref
    }
}

impl Drop for RuntimePermit {
    fn drop(&mut self) {
        let slot = match (self.dimension, self.class) {
            (RuntimeDimension::RunnableSlots, CapacityClass::NormalWorkload) => {
                &self.inner.runnable_normal_in_flight
            }
            (RuntimeDimension::RunnableSlots, _) => &self.inner.runnable_protected_in_flight,
            (RuntimeDimension::CpuTaskSlots, CapacityClass::NormalWorkload) => {
                &self.inner.cpu_normal_in_flight
            }
            (RuntimeDimension::CpuTaskSlots, _) => &self.inner.cpu_protected_in_flight,
        };
        debug_assert!(
            slot.load(Ordering::Acquire) >= self.amount,
            "runtime permit drop without a held partition amount"
        );
        slot.fetch_sub(self.amount, Ordering::AcqRel);
    }
}

/// Returns whether a value is usable as an owner, operation or reference
/// identity: non-blank, without control characters, bounded in length.
fn valid_reference(value: &str) -> bool {
    !value.trim().is_empty()
        && value.len() <= MAX_REF_LEN
        && !value.chars().any(char::is_control)
}

fn validate_reference(value: &str, field: &'static str) -> Result<(), RuntimeReserveError> {
    if !valid_reference(value) {
        return Err(RuntimeReserveError::InvalidField {
            field,
            reason: "must be non-blank, without control characters, and at most 1024 bytes",
        });
    }
    Ok(())
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

fn positive_capacity(value: u64, field: &'static str) -> Result<u64, RuntimeReserveError> {
    if value == 0 {
        return Err(RuntimeReserveError::InvalidField {
            field,
            reason: "must be greater than zero",
        });
    }
    Ok(value)
}

impl RuntimeReserve {
    /// Creates a runtime reserve with disjoint normal and protected
    /// partitions for both runtime dimensions, bound to one owner generation
    /// and one Authority Epoch.
    ///
    /// Normal work draws only from the normal runnable slots and normal CPU
    /// task slots; admitted cancellation/recovery draws only from the
    /// protected runnable slots and protected CPU task slots. Neither class
    /// can borrow from the other. Every issued permit echoes
    /// `owner_generation_ref` and `authority_epoch_ref`, so a permit issued
    /// under another generation or epoch never typechecks as current here.
    ///
    /// # Errors
    ///
    /// Returns [`RuntimeReserveError::InvalidField`] when any partition
    /// capacity is zero or when an owner reference is blank or malformed.
    pub fn partitioned(
        normal_runnable_slots: u64,
        protected_runnable_slots: u64,
        normal_cpu_task_slots: u64,
        protected_cpu_task_slots: u64,
        owner_generation_ref: &str,
        authority_epoch_ref: &str,
    ) -> Result<Self, RuntimeReserveError> {
        positive_capacity(normal_runnable_slots, "runtime_reserve.normal_runnable_slots")?;
        positive_capacity(
            protected_runnable_slots,
            "runtime_reserve.protected_runnable_slots",
        )?;
        positive_capacity(
            normal_cpu_task_slots,
            "runtime_reserve.normal_cpu_task_slots",
        )?;
        positive_capacity(
            protected_cpu_task_slots,
            "runtime_reserve.protected_cpu_task_slots",
        )?;
        validate_reference(
            owner_generation_ref,
            "runtime_reserve.owner_generation_ref",
        )?;
        validate_reference(
            authority_epoch_ref,
            "runtime_reserve.authority_epoch_ref",
        )?;
        Ok(Self {
            inner: Arc::new(RuntimeReserveInner {
                runnable_normal_capacity: normal_runnable_slots,
                runnable_protected_capacity: protected_runnable_slots,
                cpu_normal_capacity: normal_cpu_task_slots,
                cpu_protected_capacity: protected_cpu_task_slots,
                runnable_normal_in_flight: AtomicU64::new(0),
                runnable_protected_in_flight: AtomicU64::new(0),
                cpu_normal_in_flight: AtomicU64::new(0),
                cpu_protected_in_flight: AtomicU64::new(0),
                owner_generation_ref: owner_generation_ref.to_owned(),
                authority_epoch_ref: authority_epoch_ref.to_owned(),
            }),
        })
    }

    /// Creates a runtime reserve with partition sizes read from the live
    /// owner's configuration: mailbox data capacity and control reserve for
    /// the runnable-slot dimension, data concurrency and control concurrency
    /// reserve for the CPU-task dimension.
    ///
    /// The configuration is validated with the existing
    /// [`RuntimeConfig::validate`] before any size is read, so a zero
    /// capacity fails here instead of producing a reserve that cannot admit.
    ///
    /// # Errors
    ///
    /// Returns [`RuntimeReserveError::InvalidField`] when the configuration
    /// is not valid, when a configured capacity exceeds the `u64` range, or
    /// when an owner reference is blank or malformed.
    pub fn from_config(
        config: &RuntimeConfig,
        owner_generation_ref: &str,
        authority_epoch_ref: &str,
    ) -> Result<Self, RuntimeReserveError> {
        config
            .validate()
            .map_err(|error| RuntimeReserveError::InvalidField {
                field: "runtime_reserve.config",
                reason: match error {
                    super::ConfigError::ZeroCapacity => "owner configuration carries a zero capacity",
                    super::ConfigError::ZeroDuration => "owner configuration carries a zero duration",
                },
            })?;
        let capacity = |value: usize, field: &'static str| {
            u64::try_from(value).map_err(|_| RuntimeReserveError::InvalidField {
                field,
                reason: "owner configured capacity exceeds the u64 range",
            })
        };
        Self::partitioned(
            capacity(config.mailbox_capacity, "runtime_reserve.normal_runnable_slots")?,
            capacity(
                config.control_reserve,
                "runtime_reserve.protected_runnable_slots",
            )?,
            capacity(config.concurrency, "runtime_reserve.normal_cpu_task_slots")?,
            capacity(
                config.control_concurrency_reserve,
                "runtime_reserve.protected_cpu_task_slots",
            )?,
            owner_generation_ref,
            authority_epoch_ref,
        )
    }

    /// Returns the configured normal runnable-slot partition capacity.
    #[must_use]
    pub fn normal_runnable_capacity(&self) -> u64 {
        self.inner.runnable_normal_capacity
    }

    /// Returns the configured protected runnable-slot partition capacity.
    #[must_use]
    pub fn protected_runnable_capacity(&self) -> u64 {
        self.inner.runnable_protected_capacity
    }

    /// Returns the configured normal CPU-task partition capacity.
    #[must_use]
    pub fn normal_cpu_task_capacity(&self) -> u64 {
        self.inner.cpu_normal_capacity
    }

    /// Returns the configured protected CPU-task partition capacity.
    #[must_use]
    pub fn protected_cpu_task_capacity(&self) -> u64 {
        self.inner.cpu_protected_capacity
    }

    /// Returns the currently available normal runnable slots.
    #[must_use]
    pub fn available_normal_runnable_slots(&self) -> u64 {
        self.inner
            .runnable_normal_capacity
            .saturating_sub(self.inner.runnable_normal_in_flight.load(Ordering::Acquire))
    }

    /// Returns the currently available protected runnable slots.
    #[must_use]
    pub fn available_protected_runnable_slots(&self) -> u64 {
        self.inner
            .runnable_protected_capacity
            .saturating_sub(
                self.inner
                    .runnable_protected_in_flight
                    .load(Ordering::Acquire),
            )
    }

    /// Returns the currently available normal CPU task slots.
    #[must_use]
    pub fn available_normal_cpu_tasks(&self) -> u64 {
        self.inner
            .cpu_normal_capacity
            .saturating_sub(self.inner.cpu_normal_in_flight.load(Ordering::Acquire))
    }

    /// Returns the currently available protected CPU task slots.
    #[must_use]
    pub fn available_protected_cpu_tasks(&self) -> u64 {
        self.inner
            .cpu_protected_capacity
            .saturating_sub(self.inner.cpu_protected_in_flight.load(Ordering::Acquire))
    }

    /// Attempts to acquire one normal runnable slot without blocking.
    ///
    /// Only [`NormalWorkClass`] operations typecheck here, so protected
    /// runtime capacity is unreachable through this path by construction.
    ///
    /// # Errors
    ///
    /// Returns [`RuntimeReserveError::InvalidField`] for a blank owner or
    /// operation identity, or
    /// [`RuntimeReserveError::NormalCapacityExhausted`] naming the runnable
    /// bottleneck and shed work when the normal partition is saturated. The
    /// protected partition is untouched in every case.
    pub fn try_acquire_normal_runnable_slot(
        &self,
        work: NormalWorkClass,
        owner: &str,
        operation_id: &str,
    ) -> Result<RuntimePermit, RuntimeReserveError> {
        validate_reference(owner, "runtime_permit.owner")?;
        validate_reference(operation_id, "runtime_permit.operation_id")?;
        if !cas_add(
            &self.inner.runnable_normal_in_flight,
            self.inner.runnable_normal_capacity,
            1,
        ) {
            return Err(RuntimeReserveError::NormalCapacityExhausted {
                bottleneck: RUNTIME_RUNNABLE_BOTTLENECK,
                work_class: work,
                operation_id: operation_id.to_owned(),
                owner: owner.to_owned(),
            });
        }
        Ok(RuntimePermit {
            inner: self.inner.clone(),
            dimension: RuntimeDimension::RunnableSlots,
            class: CapacityClass::NormalWorkload,
            amount: 1,
            operation: RuntimePermitOperation::Normal(work),
            operation_id: operation_id.to_owned(),
            owner: owner.to_owned(),
        })
    }

    /// Attempts to acquire one normal CPU task slot without blocking.
    ///
    /// Only [`NormalWorkClass`] operations typecheck here, so protected
    /// runtime capacity is unreachable through this path by construction.
    ///
    /// # Errors
    ///
    /// Returns [`RuntimeReserveError::InvalidField`] for a blank owner or
    /// operation identity, or
    /// [`RuntimeReserveError::NormalCapacityExhausted`] naming the CPU-task
    /// bottleneck and shed work when the normal partition is saturated. The
    /// protected partition is untouched in every case.
    pub fn try_acquire_normal_cpu_task(
        &self,
        work: NormalWorkClass,
        owner: &str,
        operation_id: &str,
    ) -> Result<RuntimePermit, RuntimeReserveError> {
        validate_reference(owner, "runtime_permit.owner")?;
        validate_reference(operation_id, "runtime_permit.operation_id")?;
        if !cas_add(
            &self.inner.cpu_normal_in_flight,
            self.inner.cpu_normal_capacity,
            1,
        ) {
            return Err(RuntimeReserveError::NormalCapacityExhausted {
                bottleneck: RUNTIME_CPU_TASK_BOTTLENECK,
                work_class: work,
                operation_id: operation_id.to_owned(),
                owner: owner.to_owned(),
            });
        }
        Ok(RuntimePermit {
            inner: self.inner.clone(),
            dimension: RuntimeDimension::CpuTaskSlots,
            class: CapacityClass::NormalWorkload,
            amount: 1,
            operation: RuntimePermitOperation::Normal(work),
            operation_id: operation_id.to_owned(),
            owner: owner.to_owned(),
        })
    }

    /// Attempts to acquire one protected runnable slot without blocking.
    ///
    /// Only [`ControlOperationClass`] operations typecheck here: ordinary
    /// data work cannot name a protected operation and therefore cannot
    /// acquire this partition. This is the path an admitted
    /// cancellation/recovery record keeps while normal runnable work is
    /// saturated.
    ///
    /// # Errors
    ///
    /// Returns [`RuntimeReserveError::InvalidField`] for a blank owner or
    /// operation identity, or
    /// [`RuntimeReserveError::ProtectedReserveExhausted`] naming the runnable
    /// bottleneck, operation, owner and request when the protected partition
    /// is saturated.
    pub fn try_acquire_protected_runnable_slot(
        &self,
        operation: ControlOperationClass,
        owner: &str,
        operation_id: &str,
    ) -> Result<RuntimePermit, RuntimeReserveError> {
        validate_reference(owner, "runtime_permit.owner")?;
        validate_reference(operation_id, "runtime_permit.operation_id")?;
        if !cas_add(
            &self.inner.runnable_protected_in_flight,
            self.inner.runnable_protected_capacity,
            1,
        ) {
            return Err(RuntimeReserveError::ProtectedReserveExhausted {
                bottleneck: RUNTIME_RUNNABLE_BOTTLENECK,
                operation,
                operation_id: operation_id.to_owned(),
                owner: owner.to_owned(),
            });
        }
        Ok(RuntimePermit {
            inner: self.inner.clone(),
            dimension: RuntimeDimension::RunnableSlots,
            class: CapacityClass::ProtectedControl,
            amount: 1,
            operation: RuntimePermitOperation::Protected(operation),
            operation_id: operation_id.to_owned(),
            owner: owner.to_owned(),
        })
    }

    /// Attempts to acquire one protected CPU task slot without blocking.
    ///
    /// Only [`ControlOperationClass`] operations typecheck here. This is the
    /// path an admitted cancellation/recovery task keeps while normal CPU
    /// task work is saturated.
    ///
    /// # Errors
    ///
    /// Returns [`RuntimeReserveError::InvalidField`] for a blank owner or
    /// operation identity, or
    /// [`RuntimeReserveError::ProtectedReserveExhausted`] naming the CPU-task
    /// bottleneck, operation, owner and request when the protected partition
    /// is saturated.
    pub fn try_acquire_protected_cpu_task(
        &self,
        operation: ControlOperationClass,
        owner: &str,
        operation_id: &str,
    ) -> Result<RuntimePermit, RuntimeReserveError> {
        validate_reference(owner, "runtime_permit.owner")?;
        validate_reference(operation_id, "runtime_permit.operation_id")?;
        if !cas_add(
            &self.inner.cpu_protected_in_flight,
            self.inner.cpu_protected_capacity,
            1,
        ) {
            return Err(RuntimeReserveError::ProtectedReserveExhausted {
                bottleneck: RUNTIME_CPU_TASK_BOTTLENECK,
                operation,
                operation_id: operation_id.to_owned(),
                owner: owner.to_owned(),
            });
        }
        Ok(RuntimePermit {
            inner: self.inner.clone(),
            dimension: RuntimeDimension::CpuTaskSlots,
            class: CapacityClass::ProtectedControl,
            amount: 1,
            operation: RuntimePermitOperation::Protected(operation),
            operation_id: operation_id.to_owned(),
            owner: owner.to_owned(),
        })
    }

    /// Publishes the live partition evidence for one runtime dimension as a
    /// claimed [`BottleneckCapacityProfile`] row.
    ///
    /// The row names the frozen owner the contract binds to this dimension,
    /// the exact bottleneck unit, the physical total and the disjoint normal
    /// and protected partitions read from this reserve. There is no emergency
    /// partition here, so none is claimed. The owner generation is the
    /// generation this reserve was bound with; the proof profile, evidence
    /// and invalidation references are composition-supplied metadata echoed
    /// into the row. The Kernel composition wraps this row in its own
    /// evidence record with the configuration snapshot and Authority Epoch
    /// it resolved, and joins rows in frozen contract order.
    ///
    /// # Errors
    ///
    /// Returns [`RuntimeReserveError::InvalidField`] for a blank metadata
    /// reference, for a dimension the frozen owner map does not bind, or when
    /// the partition accounting cannot be represented, or
    /// [`RuntimeReserveError::Contract`] when the assembled row fails the
    /// existing contract validation.
    pub fn publish_claimed_row(
        &self,
        dimension: RuntimeDimension,
        proof_profile_ref: &str,
        evidence_ref: &str,
        invalidation_ref: &str,
    ) -> Result<BottleneckCapacityProfile, RuntimeReserveError> {
        validate_reference(
            proof_profile_ref,
            "runtime_evidence.proof_profile_ref",
        )?;
        validate_reference(evidence_ref, "runtime_evidence.evidence_ref")?;
        validate_reference(invalidation_ref, "runtime_evidence.invalidation_ref")?;
        let bottleneck = dimension.bottleneck();
        let bound = frozen_bottleneck_owner_map()
            .into_iter()
            .find(|bound| bound.bottleneck == bottleneck)
            .ok_or(RuntimeReserveError::InvalidField {
                field: "runtime_evidence.bottleneck",
                reason: "the frozen owner map binds no owner to this runtime dimension",
            })?;
        let (normal_capacity, protected_capacity) = match dimension {
            RuntimeDimension::RunnableSlots => (
                self.inner.runnable_normal_capacity,
                self.inner.runnable_protected_capacity,
            ),
            RuntimeDimension::CpuTaskSlots => (
                self.inner.cpu_normal_capacity,
                self.inner.cpu_protected_capacity,
            ),
        };
        let physical_total = normal_capacity
            .checked_add(protected_capacity)
            .and_then(NonZeroU64::new)
            .ok_or(RuntimeReserveError::InvalidField {
                field: "runtime_evidence.physical_total_limit",
                reason: "the disjoint partition sum is not a positive capacity",
            })?;
        let unit = bottleneck.unit();
        let limit = |quantity: u64| {
            NonZeroU64::new(quantity)
                .map(|quantity| CapacityLimit { unit, quantity })
                .ok_or(RuntimeReserveError::InvalidField {
                    field: "runtime_evidence.partition_limit",
                    reason: "a claimed partition is not a positive capacity",
                })
        };
        let row = BottleneckCapacityProfile {
            bottleneck,
            coverage_state: BottleneckCoverageState::Claimed,
            owner_ref: bound.owner.to_owned(),
            owner_generation_ref: self.inner.owner_generation_ref.clone(),
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
            .map_err(|error| RuntimeReserveError::Contract(error.to_string()))?;
        Ok(row)
    }
}
