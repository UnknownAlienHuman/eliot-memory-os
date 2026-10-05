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
//!
//! Permit replay is operation-, owner- and epoch-bound through the
//! idempotency ledger: a [`PermitLedgerBinding`] records the exact operation
//! identity, owner, Authority Epoch and profile revision alongside the
//! request digest, and the same key presented with changed content resolves
//! to [`IdempotencyDisposition::Conflict`], never to a replay. Release is
//! exactly-once: [`ControlPermit::release`] consumes the permit and returns
//! bound [`ControlReleaseEvidence`], with drop as the backstop returning the
//! exact partition.
//!
//! Restart never restores capacity by resetting a local counter: the ledger
//! replays nothing across a restart boundary ([`IdempotencyLedger::note_restart`]
//! evicts every entry so old effects are re-evaluated, never silently
//! reused), and [`ControlReserve::seal_after_restart`] pins every partition
//! full so unknown held capacity stays excluded until the epoch advances past
//! the seal ([`ControlReserve::unseal_after_epoch_advance`]), which fences
//! the stale ownership. Owner-generation staleness beyond the epoch fence
//! needs the W3 owner adapters (same disclosed limit as the profile
//! compiler): the front-door slice binds the epoch, not a second generation
//! scheme.
//!
//! Owner-issued permit evidence (issue #1679, W4) rides on the same binding:
//! [`FrontDoor::issue_permit`] validates one [`CapacityRequest`] carrying the
//! exact bottleneck, unit and amount under its typed
//! [`RequestedOperationClass`] tag, acquires exactly one slot from the tagged
//! partition, and returns the non-clone [`ControlPermit`] together with the
//! owner-minted [`CapacityPermitBinding`]. The tag alone selects the partition,
//! so a normal Store write (`CANONICAL_WRITE`), named read (`INTERACTIVE`),
//! verification, background, model, swarm/agent (`SWARM`), reporting or
//! maintenance operation can never acquire a protected or emergency permit by
//! relabelling priority or class (A5): relabelling is unrepresentable, not
//! merely refused. Replay and release stay content-bound (A7): the binding
//! matches its request only through
//! [`CapacityPermitBinding::matches_request`], and release consumes the permit
//! exactly once. The front-door fence is the single-lineage
//! [`KernelAuthority`] sequence, so the request epoch is compared by sequence
//! exactly like [`KernelAuthority::consume`]; full lineage-tuple fencing
//! belongs to the I6.10 authority owner (STITCH).

use std::collections::{BTreeMap, VecDeque};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};

use eliot_contracts::{EpochId, ResourceGeneration};
use eliot_receipts::ProofCeiling;

use crate::RouteScope;
use crate::authority::{AuthorityGrant, AuthorityReceipt, KernelAuthority};
use crate::error::{KernelError, validate_id};

pub use eliot_runtime_contracts::{
    CapacityBottleneck, CapacityClass, CapacityPermitBinding, CapacityRequest,
    ControlOperationClass, EmergencyOperationClass, NormalWorkClass, RequestedOperationClass,
};

/// Runtime owner reference minted on every front-door permit binding.
///
/// Names the [`frozen_bottleneck_owner_map`][eliot_runtime_contracts::frozen_bottleneck_owner_map]
/// row for [`FRONT_DOOR_BOTTLENECK`] ("Kernel front-door/control-channel owner").
pub const FRONT_DOOR_OWNER: &str = "kernel-front-door";

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
    /// Restart seal flag: while set, every acquisition fails closed with its
    /// typed exhaustion disposition and unknown held capacity stays excluded.
    restart_sealed: AtomicBool,
    /// Epoch tuple observed at the restart seal; unsealing requires the fence
    /// to have moved past it (stale ownership fenced).
    sealed_epoch: Mutex<Option<EpochId>>,
    /// Owner-minted permit sequence; never reset, including across restarts,
    /// so two issuances never share a permit identity.
    permit_sequence: AtomicU64,
}

/// A single held capacity permit, bound to class, bottleneck, operation, owner
/// and epoch. Releasing is explicit and exactly-once via [`Self::release`],
/// which consumes the permit; drop is the backstop returning exactly the
/// consumed partition when the permit was not released.
///
/// Permits are deliberately not [`Clone`]: duplicating a permit handle must
/// never duplicate the underlying capacity.
#[derive(Debug)]
pub struct ControlPermit {
    inner: Option<Arc<PartitionedInner>>,
    class: CapacityClass,
    bottleneck: CapacityBottleneck,
    operation: PermitOperation,
    operation_id: String,
    owner: String,
    epoch: EpochId,
}

/// Exactly-once release evidence for one [`ControlPermit`].
///
/// Bound to class, bottleneck, operation label/identity, owner and epoch: a
/// replayed or relabelled release does not match and is refused before any
/// counter moves.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ControlReleaseEvidence {
    class: CapacityClass,
    bottleneck: CapacityBottleneck,
    operation_label: String,
    operation_id: String,
    owner: String,
    epoch: EpochId,
}

impl ControlReleaseEvidence {
    /// Returns the capacity class (partition) the released slot returns to.
    #[must_use]
    pub const fn capacity_class(&self) -> CapacityClass {
        self.class
    }

    /// Returns the bottleneck the released slot returns to.
    #[must_use]
    pub const fn bottleneck(&self) -> CapacityBottleneck {
        self.bottleneck
    }

    /// Returns the contract operation label recorded at acquisition.
    #[must_use]
    pub fn operation_label(&self) -> &str {
        &self.operation_label
    }

    /// Returns the operation identity recorded at acquisition.
    #[must_use]
    pub fn operation_id(&self) -> &str {
        &self.operation_id
    }

    /// Returns the owner recorded at acquisition.
    #[must_use]
    pub fn owner(&self) -> &str {
        &self.owner
    }

    /// Returns the epoch tuple recorded at acquisition.
    #[must_use]
    pub fn epoch(&self) -> EpochId {
        self.epoch.clone()
    }

    /// Returns `true` only when every binding matches the live permit:
    /// same class, bottleneck, operation identity, owner and epoch. Changed
    /// content never matches.
    #[must_use]
    pub fn matches_permit(&self, permit: &ControlPermit) -> bool {
        self.class == permit.class
            && self.bottleneck == permit.bottleneck
            && self.operation_label == permit.operation.contract_label()
            && self.operation_id == permit.operation_id
            && self.owner == permit.owner
            && self.epoch == permit.epoch
    }
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

    /// Returns the front-door epoch tuple bound at acquisition.
    #[must_use]
    pub fn epoch(&self) -> EpochId {
        self.epoch.clone()
    }

    /// Returns `true` only when every presented binding matches the recorded
    /// evidence: same operation identity, same owner and same epoch tuple.
    /// Changed content never matches; it conflicts instead of replaying.
    #[must_use]
    pub fn binding_matches(&self, operation_id: &str, owner: &str, epoch: &EpochId) -> bool {
        self.operation_id == operation_id && self.owner == owner && self.epoch == *epoch
    }

    /// Releases the held slot exactly once, returning bound evidence.
    ///
    /// Consuming `self` makes a second release a compile-time impossibility
    /// through this path; drop afterwards observes the taken slot and moves
    /// no counter.
    #[must_use]
    pub fn release(mut self) -> ControlReleaseEvidence {
        let evidence = ControlReleaseEvidence {
            class: self.class,
            bottleneck: self.bottleneck,
            operation_label: self.operation.contract_label().to_owned(),
            operation_id: self.operation_id.clone(),
            owner: self.owner.clone(),
            epoch: self.epoch.clone(),
        };
        if let Some(inner) = self.inner.take() {
            let slot = match self.class {
                CapacityClass::NormalWorkload => &inner.normal_in_flight,
                CapacityClass::ProtectedControl => &inner.protected_in_flight,
                CapacityClass::EmergencyLastResort => &inner.emergency_in_flight,
            };
            debug_assert!(
                slot.load(Ordering::Acquire) > 0,
                "control permit release without a held partition slot"
            );
            slot.fetch_sub(1, Ordering::AcqRel);
        } else {
            debug_assert!(
                false,
                "control permit released without a held partition slot"
            );
        }
        evidence
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
                restart_sealed: AtomicBool::new(false),
                sealed_epoch: Mutex::new(None),
                permit_sequence: AtomicU64::new(0),
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

    /// Returns whether the reserve is sealed after a restart.
    ///
    /// While sealed, every acquisition fails closed with its typed exhaustion
    /// disposition: unknown held capacity stays excluded until the epoch
    /// advances past the seal (see [`Self::unseal_after_epoch_advance`]).
    /// A sealed reserve reports zero availability everywhere, but the cause
    /// is recorded here rather than inferred from the counters.
    #[must_use]
    pub fn restart_sealed(&self) -> bool {
        self.inner.restart_sealed.load(Ordering::Acquire)
    }

    /// Seals the reserve at a restart boundary: restart never restores
    /// capacity by resetting a local counter.
    ///
    /// Every in-flight counter is pinned to its full partition capacity, so
    /// no new acquisition can succeed on the back of a zeroed counter, and
    /// the sealing epoch tuple is recorded. Unknown held capacity stays
    /// excluded until [`Self::unseal_after_epoch_advance`] observes a fence
    /// that has moved past the seal (stale ownership fenced). The embedding
    /// owner calls this exactly once when it detects an unclean restart
    /// before admitting new work (STITCH).
    pub fn seal_after_restart(&self, epoch: EpochId) {
        self.inner
            .normal_in_flight
            .fetch_max(self.inner.normal_capacity, Ordering::AcqRel);
        self.inner
            .protected_in_flight
            .fetch_max(self.inner.protected_capacity, Ordering::AcqRel);
        self.inner
            .emergency_in_flight
            .fetch_max(self.inner.emergency_capacity, Ordering::AcqRel);
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
    /// Succeeds only when the fence has moved past the sealing tuple: the
    /// move fences the stale ownership, so the pinned counters can be
    /// released to zero and the seal lifted. Refuses otherwise, so held
    /// capacity is never restored while stale ownership is unfenced. The
    /// caller must have synchronized the front-door fence to the durable
    /// recovery epoch first (STITCH).
    ///
    /// # Errors
    ///
    /// Returns [`KernelError::InvalidField`] when no restart seal is held, or
    /// when the fence has not moved past the seal.
    pub fn unseal_after_epoch_advance(&self, current: &EpochId) -> Result<(), KernelError> {
        let mut sealed = self
            .inner
            .sealed_epoch
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        match &*sealed {
            None => {
                return Err(KernelError::InvalidField {
                    field: "control_reserve.restart_seal",
                    reason: "no restart seal is held; nothing to reconcile",
                });
            }
            Some(sealed_epoch) if sealed_epoch == current => {
                return Err(KernelError::InvalidField {
                    field: "control_reserve.restart_seal",
                    reason: "epoch has not advanced; stale ownership is not fenced, held capacity stays excluded",
                });
            }
            Some(_) => {}
        }
        self.inner.normal_in_flight.store(0, Ordering::Release);
        self.inner.protected_in_flight.store(0, Ordering::Release);
        self.inner.emergency_in_flight.store(0, Ordering::Release);
        *sealed = None;
        self.inner.restart_sealed.store(false, Ordering::Release);
        Ok(())
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
        epoch: EpochId,
    ) -> Result<ControlPermit, KernelError> {
        validate_id(owner, "control_permit.owner")?;
        validate_id(operation_id, "control_permit.operation_id")?;
        if self.inner.restart_sealed.load(Ordering::Acquire) {
            return Err(KernelError::NormalCapacityExhausted {
                bottleneck: FRONT_DOOR_BOTTLENECK,
                work_class: work,
                operation_id: operation_id.to_owned(),
                owner: owner.to_owned(),
                epoch,
            });
        }
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
            inner: Some(self.inner.clone()),
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
        epoch: EpochId,
    ) -> Result<ControlPermit, KernelError> {
        validate_id(owner, "control_permit.owner")?;
        validate_id(operation_id, "control_permit.operation_id")?;
        if self.inner.restart_sealed.load(Ordering::Acquire) {
            return Err(KernelError::ProtectedReserveExhausted {
                bottleneck: FRONT_DOOR_BOTTLENECK,
                operation,
                operation_id: operation_id.to_owned(),
                owner: owner.to_owned(),
                epoch,
            });
        }
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
            inner: Some(self.inner.clone()),
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
        epoch: EpochId,
    ) -> Result<ControlPermit, KernelError> {
        validate_id(owner, "control_permit.owner")?;
        validate_id(operation_id, "control_permit.operation_id")?;
        if self.inner.restart_sealed.load(Ordering::Acquire) {
            return Err(KernelError::EmergencySlotUnavailable {
                bottleneck: FRONT_DOOR_BOTTLENECK,
                operation,
                operation_id: operation_id.to_owned(),
                owner: owner.to_owned(),
                epoch,
            });
        }
        if cas_increment(
            &self.inner.emergency_in_flight,
            self.inner.emergency_capacity,
        ) {
            return Ok(ControlPermit {
                inner: Some(self.inner.clone()),
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
    pub(crate) fn acquire_legacy_protected(&self, epoch: EpochId) -> Option<ControlPermit> {
        if self.inner.restart_sealed.load(Ordering::Acquire) {
            return None;
        }
        if !cas_increment(
            &self.inner.protected_in_flight,
            self.inner.protected_capacity,
        ) {
            return None;
        }
        Some(ControlPermit {
            inner: Some(self.inner.clone()),
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
        if let Some(inner) = self.inner.take() {
            let slot = match self.class {
                CapacityClass::NormalWorkload => &inner.normal_in_flight,
                CapacityClass::ProtectedControl => &inner.protected_in_flight,
                CapacityClass::EmergencyLastResort => &inner.emergency_in_flight,
            };
            debug_assert!(
                slot.load(Ordering::Acquire) > 0,
                "control permit drop without a held partition slot"
            );
            slot.fetch_sub(1, Ordering::AcqRel);
        }
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

/// Operation-, owner-, epoch- and profile-bound evidence recorded alongside
/// one idempotency entry (issue #1679, A7).
///
/// The same idempotency key presented with the same digest but changed
/// binding content resolves to [`IdempotencyDisposition::Conflict`]: a replay
/// must be the same operation by the same owner under the same epoch and
/// profile revision, never merely the newest generation presenting an old
/// key.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PermitLedgerBinding {
    operation_id: String,
    owner: String,
    epoch: EpochId,
    profile_revision: String,
}

impl PermitLedgerBinding {
    /// Binds one idempotency entry to its exact operation evidence.
    ///
    /// # Errors
    ///
    /// Returns [`KernelError::InvalidField`] for a blank or malformed
    /// operation/owner/profile identity.
    pub fn new(
        operation_id: &str,
        owner: &str,
        epoch: EpochId,
        profile_revision: &str,
    ) -> Result<Self, KernelError> {
        validate_id(operation_id, "permit_binding.operation_id")?;
        validate_id(owner, "permit_binding.owner")?;
        validate_id(profile_revision, "permit_binding.profile_revision")?;
        Ok(Self {
            operation_id: operation_id.to_owned(),
            owner: owner.to_owned(),
            epoch,
            profile_revision: profile_revision.to_owned(),
        })
    }

    /// Returns the bound operation identity.
    #[must_use]
    pub fn operation_id(&self) -> &str {
        &self.operation_id
    }

    /// Returns the bound owner.
    #[must_use]
    pub fn owner(&self) -> &str {
        &self.owner
    }

    /// Returns the bound Authority Epoch tuple.
    #[must_use]
    pub fn epoch(&self) -> EpochId {
        self.epoch.clone()
    }

    /// Returns the bound profile revision.
    #[must_use]
    pub fn profile_revision(&self) -> &str {
        &self.profile_revision
    }
}

/// One ledger entry: the request digest, the recorded decision and the exact
/// permit binding the decision was recorded under, if any.
#[derive(Clone, Debug)]
struct LedgerEntry {
    digest: String,
    decision: AuthorityDecision,
    binding: Option<PermitLedgerBinding>,
}

/// A bounded idempotency ledger that deduplicates effect admission.
///
/// The ledger is FIFO-bounded: when it reaches capacity, the oldest entry is
/// evicted, so a very old replay is re-evaluated rather than silently reused.
/// Replay is additionally binding-checked: an entry recorded with a
/// [`PermitLedgerBinding`] replays only for the same digest *and* the same
/// binding; changed content conflicts.
#[derive(Debug)]
pub struct IdempotencyLedger {
    capacity: usize,
    entries: BTreeMap<String, LedgerEntry>,
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
    ///
    /// Migration-compatible path for entries recorded without a binding (the
    /// legacy `authorize` flow): an entry recorded *with* a binding never
    /// replays through this path and instead conflicts, so bound evidence
    /// cannot be laundered into an unbound replay.
    #[must_use]
    pub fn resolve(&self, key: &str, digest: &str) -> IdempotencyDisposition {
        self.resolve_bound(key, digest, None)
    }

    /// Resolves an idempotency key against a request digest and the exact
    /// permit binding the caller presents.
    ///
    /// A stored entry replays only when both the digest and the binding
    /// match; any changed content (different digest, or different operation
    /// identity, owner, epoch or profile revision) is a conflict. An absent
    /// key is new and must be evaluated, never reused.
    #[must_use]
    pub fn resolve_bound(
        &self,
        key: &str,
        digest: &str,
        binding: Option<&PermitLedgerBinding>,
    ) -> IdempotencyDisposition {
        match self.entries.get(key) {
            None => IdempotencyDisposition::New,
            Some(entry) if entry.digest != digest => IdempotencyDisposition::Conflict,
            Some(entry) => match (&entry.binding, binding) {
                (None, None) => IdempotencyDisposition::Replay(entry.decision.clone()),
                (Some(stored), Some(presented)) if stored == presented => {
                    IdempotencyDisposition::Replay(entry.decision.clone())
                }
                _ => IdempotencyDisposition::Conflict,
            },
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
        self.record_bound(key, digest, decision, None)
    }

    /// Records a decision under an idempotency key with its exact permit
    /// binding, evicting the oldest entry (and its binding) on overflow.
    ///
    /// # Errors
    ///
    /// Returns an error when the key is blank or malformed.
    pub fn record_bound(
        &mut self,
        key: &str,
        digest: &str,
        decision: AuthorityDecision,
        binding: Option<PermitLedgerBinding>,
    ) -> Result<(), KernelError> {
        validate_id(key, "idempotency_key")?;
        validate_id(digest, "request_digest")?;
        if !self.entries.contains_key(key) {
            self.order.push_back(key.to_owned());
        }
        self.entries.insert(
            key.to_owned(),
            LedgerEntry {
                digest: digest.to_owned(),
                decision,
                binding,
            },
        );
        while self.order.len() > self.capacity {
            if let Some(oldest) = self.order.pop_front() {
                self.entries.remove(&oldest);
            }
        }
        Ok(())
    }

    /// Marks a restart boundary: evicts every entry so no pre-restart effect
    /// is ever replayed from the reset counter.
    ///
    /// After a restart, every key resolves [`IdempotencyDisposition::New`]
    /// and is re-evaluated against current owner evidence; unknown ownership
    /// stays excluded until the owner re-presents it. The ledger is an
    /// admission deduplicator, never durable permit reconciliation.
    pub fn note_restart(&mut self) {
        self.entries.clear();
        self.order.clear();
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

    /// Returns the current authority epoch tuple.
    #[must_use]
    pub fn epoch(&self) -> EpochId {
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
    /// Partition discipline (issue #1679, W8/I14.3): the idempotency resolve
    /// and the authority verification run before any partition is touched. A
    /// forged, fenced, misrouted or expired receipt is recorded and denied
    /// without touching the protected partition, and conflicting replays
    /// never reach a partition. The protected call-scoped hold below is
    /// drawn only for a granted decision after the normal authority checks
    /// pass, and before the grant is recorded: a saturated reserve fails
    /// with [`KernelError::ControlReserveExhausted`] leaving no ledger
    /// entry, so an exact retry re-verifies instead of replaying past the
    /// saturation gate.
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
            Err(KernelError::StaleEpoch { .. } | KernelError::StaleEpochTuple { .. }) => {
                AuthorityDecision::Denied {
                    reason: DecisionDenialReason::StaleEpoch,
                }
            }
            Err(KernelError::RouteMismatch) => AuthorityDecision::Denied {
                reason: DecisionDenialReason::RouteMismatch,
            },
            Err(KernelError::Expired { .. }) => AuthorityDecision::Denied {
                reason: DecisionDenialReason::Expired,
            },
            Err(error) => return Err(error),
        };
        if !decision.is_granted() {
            ledger.record(idempotency_key, request_digest, decision.clone())?;
            return Ok(decision);
        }
        let _permit = self
            .reserve
            .acquire_legacy_protected(self.authority.current_epoch())
            .ok_or(KernelError::ControlReserveExhausted)?;
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

    /// Raises the front-door epoch tuple and fences all previously issued receipts.
    ///
    /// The fence advances by exactly one sequence in the active lineage.
    ///
    /// # Errors
    ///
    /// Returns an error when the sequence counter cannot advance.
    pub fn advance_epoch(&mut self) -> Result<EpochId, KernelError> {
        self.authority.advance_epoch()
    }

    /// Fast-forwards the front-door fence to the durable recovery epoch tuple.
    ///
    /// The target must be the current tuple or a same-lineage forward
    /// adoption; a regression or a cross-lineage target fails closed.
    pub fn synchronize_epoch(&mut self, target: EpochId) -> Result<EpochId, KernelError> {
        self.authority.synchronize_epoch(target)
    }

    /// Marks a restart boundary: no pre-restart effect replays, and no held
    /// capacity is restored by resetting a local counter.
    ///
    /// The idempotency ledger is evicted (every key re-evaluates as new) and
    /// the reserve is sealed at the current epoch (every partition reports
    /// exhaustion). The embedding owner calls this exactly once when it
    /// detects an unclean restart before admitting new work (STITCH).
    pub fn note_restart(&self) {
        self.lock_ledger().note_restart();
        self.reserve
            .seal_after_restart(self.authority.current_epoch());
    }

    /// Issues one owner-bound permit for a validated capacity request.
    ///
    /// The W4 request/issue path for [`FRONT_DOOR_BOTTLENECK`]: the request
    /// names the exact bottleneck, unit and amount under its typed
    /// [`RequestedOperationClass`] tag, and the owner returns the non-clone
    /// [`ControlPermit`] together with the minted [`CapacityPermitBinding`].
    /// The tag alone selects the partition — `Normal` draws only the normal
    /// partition, `Protected` only the protected partition, `Emergency` only
    /// the preallocated slot — so no priority or class relabelling can move a
    /// normal Store write, named read, agent, model, swarm, report or
    /// maintenance operation onto protected or emergency capacity (A5). The
    /// binding matches its request only through
    /// [`CapacityPermitBinding::matches_request`]; changed content conflicts
    /// instead of replaying (A7).
    ///
    /// The caller supplies its clock (`now_ms`, as in [`Self::authorize`])
    /// and the issuing owner generation: the front door owns no generation
    /// counter, so generation binding arrives with the call (STITCH: the
    /// kernel generation owner). The request deadline is recorded, never
    /// enforced: issuance is synchronous. The binding carries no wall-clock
    /// expiry (`u64::MAX`); the permit lifetime is the handle lifetime
    /// (release-or-drop) and staleness is fenced by epoch, profile revision
    /// and generations.
    ///
    /// # Errors
    ///
    /// Returns the typed contract refusal for an illegal request, or
    /// [`KernelError::InvalidField`] when the request names another owner's
    /// bottleneck or an amount other than one slot (this owner issues
    /// single-slot permits; larger holdings need one permit per slot),
    /// [`KernelError::StaleEpochTuple`] when the request epoch tuple is from
    /// another lineage, [`KernelError::StaleEpoch`] when the request sequence
    /// differs within the active lineage, or the tagged saturation
    /// disposition
    /// ([`KernelError::NormalCapacityExhausted`],
    /// [`KernelError::ProtectedReserveExhausted`],
    /// [`KernelError::EmergencySlotUnavailable`]/
    /// [`KernelError::ControlGuaranteeLost`]) naming the exact bottleneck.
    pub fn issue_permit(
        &self,
        request: &CapacityRequest,
        owner_generation: ResourceGeneration,
        now_ms: i64,
    ) -> Result<(ControlPermit, CapacityPermitBinding), KernelError> {
        request.validate()?;
        if request.requested_bottleneck != FRONT_DOOR_BOTTLENECK {
            return Err(KernelError::InvalidField {
                field: "capacity_request.requested_bottleneck",
                reason: "this owner enforces only KERNEL_CONTROL_CHANNEL; no other dimension is issuable here",
            });
        }
        let current = self.authority.current_epoch();
        if !request.authority_epoch_ref.is_same_authority(&current) {
            if request.authority_epoch_ref.lineage_id != current.lineage_id {
                return Err(KernelError::StaleEpochTuple {
                    observed: request.authority_epoch_ref.clone(),
                    active: current,
                });
            }
            return Err(KernelError::StaleEpoch {
                observed: request.authority_epoch_ref.sequence.get(),
                active: current.sequence.get(),
            });
        }
        if request.requested_limit.quantity.get() != 1 {
            return Err(KernelError::InvalidField {
                field: "capacity_request.requested_limit",
                reason: "the front door issues single-slot permits; hold one permit per slot",
            });
        }
        let issued_at_ms = u64::try_from(now_ms).map_err(|_| KernelError::InvalidField {
            field: "capacity_request.issued_at_ms",
            reason: "the issuing clock must be non-negative",
        })?;
        let permit = match request.operation {
            RequestedOperationClass::Normal(work) => self.reserve.try_acquire_normal(
                work,
                &request.requesting_owner_ref,
                &request.operation_id,
                current,
            )?,
            RequestedOperationClass::Protected(operation) => self.reserve.try_acquire_protected(
                operation,
                &request.requesting_owner_ref,
                &request.operation_id,
                current,
            )?,
            RequestedOperationClass::Emergency(operation) => self.reserve.try_acquire_emergency(
                operation,
                &request.requesting_owner_ref,
                &request.operation_id,
                current,
            )?,
        };
        let sequence = self
            .reserve
            .inner
            .permit_sequence
            .fetch_add(1, Ordering::AcqRel);
        let binding = CapacityPermitBinding {
            permit_id: format!(
                "FD-{}-{sequence}-{}",
                request.operation.as_contract_str(),
                request.operation_id
            ),
            operation_id: request.operation_id.clone(),
            capacity_class: request.operation.capacity_class(),
            operation: request.operation,
            bottleneck: FRONT_DOOR_BOTTLENECK,
            granted_limit: request.requested_limit,
            capacity_owner_ref: FRONT_DOOR_OWNER.to_owned(),
            capacity_owner_generation_ref: owner_generation,
            requesting_owner_ref: request.requesting_owner_ref.clone(),
            requesting_generation_ref: request.requesting_generation_ref,
            authority_epoch_ref: request.authority_epoch_ref.clone(),
            profile_id: request.profile_id.clone(),
            profile_revision: request.profile_revision.clone(),
            issued_at_ms,
            expires_at_ms: u64::MAX,
            owner_evidence_refs: vec![self.issue_evidence(request.operation.capacity_class())],
        };
        debug_assert!(
            binding.validate().is_ok(),
            "front-door minted permit binding must satisfy the contract"
        );
        debug_assert!(
            binding.matches_request(request),
            "front-door minted permit binding must match its request"
        );
        Ok((permit, binding))
    }

    /// Records the owner's contemporaneous partition observation for one issuance.
    fn issue_evidence(&self, class: CapacityClass) -> String {
        let (capacity, in_flight) = match class {
            CapacityClass::NormalWorkload => (
                self.reserve.normal_capacity(),
                self.reserve.normal_capacity() - self.reserve.available_normal(),
            ),
            CapacityClass::ProtectedControl => (
                self.reserve.protected_capacity(),
                self.reserve.protected_capacity() - self.reserve.available_protected(),
            ),
            CapacityClass::EmergencyLastResort => (
                self.reserve.emergency_capacity(),
                self.reserve.emergency_capacity() - self.reserve.available_emergency(),
            ),
        };
        format!(
            "front-door:{}:{} capacity {capacity} in-flight {in_flight}",
            FRONT_DOOR_BOTTLENECK.as_contract_str(),
            class.as_contract_str(),
        )
    }

    /// Reconciles held capacity after the durable recovery epoch is
    /// established.
    ///
    /// Succeeds only when the fence has advanced past the restart seal; the
    /// caller must have synchronized to the durable recovery epoch first
    /// (see [`Self::synchronize_epoch`]). Refuses otherwise, so unknown
    /// ownership stays excluded until the current owner reconciles it.
    ///
    /// # Errors
    ///
    /// Returns [`KernelError::InvalidField`] when no restart seal is held, or
    /// when the epoch has not advanced past the seal.
    pub fn reconcile_after_epoch_advance(&self) -> Result<(), KernelError> {
        let current = self.authority.current_epoch();
        self.reserve.unseal_after_epoch_advance(&current)
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
    use eliot_contracts::{ContractId, EpochId, EpochLineageId, ResourceGeneration};
    use eliot_receipts::EffectClass;
    use std::num::NonZeroU64;

    const TEST_LINEAGE: &str = "550e8400-e29b-41d4-a716-446655440000";

    fn genesis_epoch() -> EpochId {
        EpochId::new(
            EpochLineageId::new(TEST_LINEAGE).expect("valid test lineage"),
            NonZeroU64::MIN,
        )
        .expect("valid test epoch")
    }

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
        let epoch = genesis_epoch();
        let a = reserve
            .try_acquire_protected(
                ControlOperationClass::CancelOperation,
                "test-owner",
                "op-a",
                epoch.clone(),
            )
            .expect("first permit");
        let b = reserve
            .try_acquire_protected(
                ControlOperationClass::CancelOperation,
                "test-owner",
                "op-b",
                epoch.clone(),
            )
            .expect("second permit");
        assert!(matches!(
            reserve.try_acquire_protected(
                ControlOperationClass::CancelOperation,
                "test-owner",
                "op-c",
                epoch.clone()
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
            genesis_epoch(),
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
            genesis_epoch(),
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
            genesis_epoch(),
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
            genesis_epoch(),
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
                assert_eq!(epoch, genesis_epoch());
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
    fn normal_saturation_response_refuses_an_unsaturated_partition() -> Result<(), KernelError> {
        let authority = KernelAuthority::new(
            crate::authority::KernelAuthorityKey::from_bytes([11u8; 32]),
            genesis_epoch(),
        );
        let front_door = FrontDoor::partitioned(authority, 1, 1, 8)?;

        // The normal partition still admits work, so it must never be reported
        // as saturated: pressure evidence is not manufactured.
        assert_eq!(front_door.available_normal(), 1);

        let err = front_door
            .normal_saturation_response(
                NormalWorkClass::Interactive,
                "op-unsaturated-1",
                eliot_contracts::ArtifactId::new("profile-rev-1").expect("valid artifact id"),
            )
            .expect_err("an unsaturated partition must not report saturation");
        assert!(matches!(
            err,
            KernelError::InvalidField {
                field: "front_door.normal_partition",
                ..
            }
        ));
        Ok(())
    }

    #[test]
    fn protected_exhaustion_response_refuses_a_remaining_partition() -> Result<(), KernelError> {
        let authority = KernelAuthority::new(
            crate::authority::KernelAuthorityKey::from_bytes([13u8; 32]),
            genesis_epoch(),
        );
        let front_door = FrontDoor::partitioned(authority, 1, 1, 8)?;

        // The protected partition still admits control work, so it must never be
        // reported as exhausted: recovery-boundary evidence is not manufactured
        // for a partition that has not refused anything.
        assert_eq!(front_door.available_protected(), 1);

        let err = front_door
            .protected_exhaustion_response(
                ControlOperationClass::CancelOperation,
                "op-protected-remaining-1",
                eliot_contracts::ArtifactId::new("profile-rev-1").expect("valid artifact id"),
            )
            .expect_err("a remaining protected partition must not report exhaustion");
        assert!(matches!(
            err,
            KernelError::InvalidField {
                field: "front_door.protected_partition",
                ..
            }
        ));
        Ok(())
    }

    #[test]
    fn guarantee_lost_response_refuses_a_remaining_last_resort_path() -> Result<(), KernelError> {
        let authority = KernelAuthority::new(
            crate::authority::KernelAuthorityKey::from_bytes([15u8; 32]),
            genesis_epoch(),
        );
        let front_door = FrontDoor::partitioned(authority, 1, 1, 8)?;

        // The preallocated last-resort emergency slot is still live, so there is
        // no guarantee loss to record: this pins the fail-closed property, not
        // the preallocation constant.
        assert!(front_door.available_emergency() > 0);

        let err = front_door
            .guarantee_lost_response(
                "op-loss-premature-1",
                eliot_contracts::ArtifactId::new("profile-rev-1").expect("valid artifact id"),
            )
            .expect_err("a live last-resort path must not produce a loss record");
        assert!(matches!(
            err,
            KernelError::InvalidField {
                field: "front_door.last_resort_path",
                ..
            }
        ));
        Ok(())
    }

    #[test]
    fn protected_and_emergency_permits_are_owner_and_epoch_bound() -> Result<(), KernelError> {
        let authority = KernelAuthority::new(
            crate::authority::KernelAuthorityKey::from_bytes([9u8; 32]),
            genesis_epoch(),
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
