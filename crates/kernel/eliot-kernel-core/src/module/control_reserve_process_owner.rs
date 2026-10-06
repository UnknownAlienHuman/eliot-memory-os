//! P-07 control reserve: Host/Kernel process-tree owner adapter.
//!
//! The process-tree owner enforces the two frozen process dimensions of the
//! I14.3 denominator — [`PROCESS_LAUNCH_BOTTLENECK`] (`ProcessLaunchSlots`)
//! and [`PROCESS_CANCEL_BOTTLENECK`] (`ProcessCancellationTermination`) —
//! against its own held partitions, exactly like the front-door slice
//! enforces `KernelControlChannel` and the ORS owner enforces its two
//! dimensions. Partitioning follows Implementation I14.3 with the closed
//! capacity vocabulary frozen in
//! `crates/foundation/eliot-runtime-contracts/control-reserve.contract.toml`
//! (issue #1679, W11): a normal process launch can saturate the normal
//! partition without consuming the protected control/recovery partition, and
//! the tag alone selects the partition, so no relabelling can move normal
//! work onto protected capacity (A5). There is no preallocated process slot:
//! the I14.3 last-resort slot is a loss-record slot, not a process slot, so
//! emergency tags are not issuable here and fail closed.
//!
//! The adapter is the declared producer boundary for the #1701 launch
//! consumer: [`ProcessTreeReserve::issue_process_permit`] validates one
//! [`CapacityRequest`] against the live [`ProcessOwnerBoundary`] (current
//! owner generation, Authority Epoch and compiled profile identity/revision),
//! acquires exactly one slot from the tagged partition of the requested
//! process dimension, and returns the non-clone [`ProcessPermit`] together
//! with the owner-minted [`CapacityPermitBinding`]. The binding exactly
//! matches its request through [`CapacityPermitBinding::matches_request`];
//! changed content conflicts instead of replaying (A7). The binding alone
//! carries no slot liveness: the permit handle is the held capacity and must
//! be retained until receipted release. [`ProcessTreeReserve::verify_process_permit`]
//! is the authenticated owner lookup the consumer replays at its
//! launch/recovery boundary: it proves the presented binding is owner-issued
//! and current (owner, request match, profile, epoch) without consulting any
//! counter, so a copied profile string or a stale receipt can never pass as
//! live owner authority.
//!
//! Release is exactly-once: [`ProcessPermit::release`] consumes the permit
//! and returns bound [`ProcessReleaseEvidence`], with drop as the backstop
//! returning the exact partition. Restart never restores capacity by
//! resetting a local counter: [`ProcessTreeReserve::seal_after_restart`]
//! pins every partition full so unknown held capacity stays excluded until
//! the epoch advances past the seal
//! ([`ProcessTreeReserve::unseal_after_epoch_advance`]), which fences the
//! stale ownership. Unknown outcomes therefore retain actual owner exclusion
//! until receipted reconciliation.
//!
//! Partition capacities are composition-configured and strictly positive
//! (the constructor refuses zero): the adapter enforces the bound it was
//! given, it never invents one. A request that names another owner's
//! bottleneck, a non-current profile, a fenced epoch, or an amount other
//! than one slot fails closed before any counter moves.

use std::num::NonZeroU64;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use eliot_contracts::{EpochId, ResourceGeneration};

use crate::error::{KernelError, validate_id};

use eliot_runtime_contracts::{
    BottleneckCapacityProfile, BottleneckCoverageState, CapacityEnforcement, CapacityLimit,
    frozen_bottleneck_owner_map,
};
pub use eliot_runtime_contracts::{
    CapacityBottleneck, CapacityClass, CapacityPermitBinding, CapacityRequest,
    ControlOperationClass, EmergencyOperationClass, NormalWorkClass, RequestedOperationClass,
};

/// Runtime owner reference minted on every process-tree permit binding.
///
/// Names the [`frozen_bottleneck_owner_map`][eliot_runtime_contracts::frozen_bottleneck_owner_map]
/// owner for both process dimensions ("Host/Kernel process-tree owner").
pub const PROCESS_TREE_OWNER: &str = "kernel-process-tree";

/// The process launch/termination-path dimension enforced by this adapter.
pub const PROCESS_LAUNCH_BOTTLENECK: CapacityBottleneck = CapacityBottleneck::ProcessLaunchSlots;

/// The process cancellation/termination dimension enforced by this adapter.
pub const PROCESS_CANCEL_BOTTLENECK: CapacityBottleneck =
    CapacityBottleneck::ProcessCancellationTermination;

/// Returns `true` only for the two frozen dimensions this owner enforces.
#[must_use]
pub const fn is_process_bottleneck(bottleneck: CapacityBottleneck) -> bool {
    matches!(
        bottleneck,
        CapacityBottleneck::ProcessLaunchSlots | CapacityBottleneck::ProcessCancellationTermination
    )
}

/// A partitioned process-capacity reserve held by the process-tree owner.
///
/// The reserve holds four disjoint atomic partitions — normal and protected
/// for each of the two process dimensions — instead of one pool. Acquiring
/// from one partition never observes or consumes another. Acquiring is
/// non-blocking and atomic; releasing is automatic when the returned
/// [`ProcessPermit`] drops. Each partition fails closed with its own
/// per-bottleneck disposition carrying operation, owner and epoch identity.
#[derive(Clone, Debug)]
pub struct ProcessTreeReserve {
    inner: Arc<ProcessPartitionsInner>,
}

#[derive(Debug)]
struct ProcessPartitionsInner {
    launch_normal_capacity: usize,
    launch_protected_capacity: usize,
    cancel_normal_capacity: usize,
    cancel_protected_capacity: usize,
    launch_normal_in_flight: AtomicUsize,
    launch_protected_in_flight: AtomicUsize,
    cancel_normal_in_flight: AtomicUsize,
    cancel_protected_in_flight: AtomicUsize,
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

/// A single held process-capacity permit, bound to class, bottleneck,
/// operation, owner and epoch. Releasing is explicit and exactly-once via
/// [`Self::release`], which consumes the permit; drop is the backstop
/// returning exactly the consumed partition when the permit was not released.
///
/// Permits are deliberately not [`Clone`]: duplicating a permit handle must
/// never duplicate the underlying capacity. The handle is the held slot: a
/// [`CapacityPermitBinding`] carried without its handle is evidence of a
/// past grant, not live capacity.
#[derive(Debug)]
pub struct ProcessPermit {
    inner: Option<Arc<ProcessPartitionsInner>>,
    class: CapacityClass,
    bottleneck: CapacityBottleneck,
    operation: RequestedOperationClass,
    operation_id: String,
    owner: String,
    epoch: EpochId,
}

/// Exactly-once release evidence for one [`ProcessPermit`].
///
/// Bound to class, bottleneck, operation tag/identity, owner and epoch: a
/// replayed or relabelled release does not match and is refused before any
/// counter moves.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProcessReleaseEvidence {
    class: CapacityClass,
    bottleneck: CapacityBottleneck,
    operation: RequestedOperationClass,
    operation_id: String,
    owner: String,
    epoch: EpochId,
}

impl ProcessReleaseEvidence {
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

    /// Returns the operation tag recorded at acquisition.
    #[must_use]
    pub const fn operation(&self) -> RequestedOperationClass {
        self.operation
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
    /// same class, bottleneck, operation tag and identity, owner and epoch.
    /// Changed content never matches.
    #[must_use]
    pub fn matches_permit(&self, permit: &ProcessPermit) -> bool {
        self.class == permit.class
            && self.bottleneck == permit.bottleneck
            && self.operation == permit.operation
            && self.operation_id == permit.operation_id
            && self.owner == permit.owner
            && self.epoch == permit.epoch
    }
}

impl ProcessPermit {
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

    /// Returns the operation tag this permit was granted for.
    #[must_use]
    pub const fn operation(&self) -> RequestedOperationClass {
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

    /// Returns the epoch tuple bound at acquisition.
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
    pub fn release(mut self) -> ProcessReleaseEvidence {
        let evidence = ProcessReleaseEvidence {
            class: self.class,
            bottleneck: self.bottleneck,
            operation: self.operation,
            operation_id: self.operation_id.clone(),
            owner: self.owner.clone(),
            epoch: self.epoch.clone(),
        };
        if let Some(inner) = self.inner.take() {
            let slot = partition_in_flight(&inner, self.bottleneck, self.class);
            debug_assert!(
                slot.load(Ordering::Acquire) > 0,
                "process permit release without a held partition slot"
            );
            slot.fetch_sub(1, Ordering::AcqRel);
        } else {
            debug_assert!(
                false,
                "process permit released without a held partition slot"
            );
        }
        evidence
    }
}

/// Composition-resolved reference strings the process-tree owner binds into
/// its published capacity rows but cannot observe itself.
///
/// The owner supplies every quantity in the rows from the live reserve: the
/// frozen bottlenecks and units, the disjoint normal/protected partition
/// limits and their physical totals, and the
/// [`CapacityEnforcement::PhysicalPartition`] mechanism those partitions are
/// held under. The composition supplies the references that identify the
/// observation: its own owner-generation reference for the process-tree
/// owner, the independent proof-profile reference, and the current evidence
/// and invalidation references. Both halves are required:
/// [`ProcessTreeReserve::publish_owner_rows`] fails closed through the
/// existing contract validation when any reference is missing or
/// non-canonical.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProcessTreeOwnerEvidenceContext {
    /// Owner generation/revision reference for the process-tree owner.
    pub owner_generation_ref: String,
    /// Independent proof-profile reference produced for the dimensions.
    pub proof_profile_ref: String,
    /// Current owner evidence references supporting the published rows.
    pub evidence_refs: Vec<String>,
    /// Exact invalidation set of the published rows.
    pub invalidation_set: Vec<String>,
}

/// The live current-owner/profile/currency input one issuance or lookup is
/// bound to (issue #1679, W11 producer boundary).
///
/// The composition resolves this from the current compiled profile and fence
/// at every call: the issuing owner generation, the current Authority Epoch
/// tuple, the compiled profile identity and revision the request must match,
/// and the caller clock. Nothing here is stored or defaulted: a request
/// compiled against another profile revision, another epoch, or no profile
/// at all fails closed at the boundary instead of issuing against a copied
/// string.
#[derive(Clone, Debug)]
pub struct ProcessOwnerBoundary {
    /// Issuing owner generation bound into the minted binding.
    pub owner_generation: ResourceGeneration,
    /// Current Authority Epoch tuple requests are fenced against.
    pub current_epoch: EpochId,
    /// Compiled profile identity requests must be bound to.
    pub profile_id: String,
    /// Compiled profile revision requests must be bound to.
    pub profile_revision: String,
    /// Caller clock in Unix milliseconds (as in front-door issuance).
    pub now_ms: i64,
}

impl ProcessOwnerBoundary {
    /// Validates boundary legality without granting authority.
    ///
    /// # Errors
    ///
    /// Returns [`KernelError::InvalidField`] when the profile identity or
    /// revision is blank: a boundary with no current profile cannot admit
    /// any request.
    pub fn validate(&self) -> Result<(), KernelError> {
        if self.profile_id.trim().is_empty() || self.profile_revision.trim().is_empty() {
            return Err(KernelError::InvalidField {
                field: "process_owner_boundary.profile_revision",
                reason: "STALE_PROFILE: issuance binds one current profile identity and revision",
            });
        }
        Ok(())
    }
}

/// Returns the configured partition capacity for one dimension and class.
fn partition_capacity(
    inner: &ProcessPartitionsInner,
    bottleneck: CapacityBottleneck,
    class: CapacityClass,
) -> usize {
    match (bottleneck, class) {
        (CapacityBottleneck::ProcessLaunchSlots, CapacityClass::NormalWorkload) => {
            inner.launch_normal_capacity
        }
        (CapacityBottleneck::ProcessLaunchSlots, CapacityClass::ProtectedControl) => {
            inner.launch_protected_capacity
        }
        (CapacityBottleneck::ProcessCancellationTermination, CapacityClass::NormalWorkload) => {
            inner.cancel_normal_capacity
        }
        (CapacityBottleneck::ProcessCancellationTermination, CapacityClass::ProtectedControl) => {
            inner.cancel_protected_capacity
        }
        // No other pair holds capacity: emergency tags are not issuable and
        // foreign bottlenecks never reach a counter.
        (_, _) => 0,
    }
}

/// Returns the live in-flight counter for one dimension and class.
fn partition_in_flight(
    inner: &ProcessPartitionsInner,
    bottleneck: CapacityBottleneck,
    class: CapacityClass,
) -> &AtomicUsize {
    match (bottleneck, class) {
        (CapacityBottleneck::ProcessLaunchSlots, CapacityClass::NormalWorkload) => {
            &inner.launch_normal_in_flight
        }
        (CapacityBottleneck::ProcessLaunchSlots, CapacityClass::ProtectedControl) => {
            &inner.launch_protected_in_flight
        }
        (CapacityBottleneck::ProcessCancellationTermination, CapacityClass::NormalWorkload) => {
            &inner.cancel_normal_in_flight
        }
        (CapacityBottleneck::ProcessCancellationTermination, CapacityClass::ProtectedControl) => {
            &inner.cancel_protected_in_flight
        }
        // Unreachable through the typed paths: permits only exist for the
        // four pairs above (foreign bottlenecks and emergency tags fail
        // closed before any permit is constructed). The fallback keeps the
        // backstop total instead of panicking on an impossible state.
        (_, _) => &inner.cancel_protected_in_flight,
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

impl ProcessTreeReserve {
    /// Creates a reserve with disjoint per-dimension partitions.
    ///
    /// The embedding composition provides every bound: normal and protected
    /// capacities for process launch slots and for cancellation/termination
    /// operations. The adapter enforces the configured bounds, it never
    /// invents them.
    ///
    /// # Errors
    ///
    /// Returns [`KernelError::InvalidField`] when any partition capacity is
    /// zero.
    pub fn partitioned(
        launch_normal_capacity: usize,
        launch_protected_capacity: usize,
        cancel_normal_capacity: usize,
        cancel_protected_capacity: usize,
    ) -> Result<Self, KernelError> {
        for (field, amount) in [
            (
                "process_tree_reserve.launch_normal_capacity",
                launch_normal_capacity,
            ),
            (
                "process_tree_reserve.launch_protected_capacity",
                launch_protected_capacity,
            ),
            (
                "process_tree_reserve.cancel_normal_capacity",
                cancel_normal_capacity,
            ),
            (
                "process_tree_reserve.cancel_protected_capacity",
                cancel_protected_capacity,
            ),
        ] {
            if amount == 0 {
                return Err(KernelError::InvalidField {
                    field,
                    reason: "must be greater than zero",
                });
            }
        }
        Ok(Self {
            inner: Arc::new(ProcessPartitionsInner {
                launch_normal_capacity,
                launch_protected_capacity,
                cancel_normal_capacity,
                cancel_protected_capacity,
                launch_normal_in_flight: AtomicUsize::new(0),
                launch_protected_in_flight: AtomicUsize::new(0),
                cancel_normal_in_flight: AtomicUsize::new(0),
                cancel_protected_in_flight: AtomicUsize::new(0),
                restart_sealed: AtomicBool::new(false),
                sealed_epoch: Mutex::new(None),
                permit_sequence: AtomicU64::new(0),
            }),
        })
    }

    /// Returns the configured normal launch-slot partition capacity.
    #[must_use]
    pub fn launch_normal_capacity(&self) -> usize {
        self.inner.launch_normal_capacity
    }

    /// Returns the configured protected launch-slot partition capacity.
    #[must_use]
    pub fn launch_protected_capacity(&self) -> usize {
        self.inner.launch_protected_capacity
    }

    /// Returns the configured normal cancellation-operation partition capacity.
    #[must_use]
    pub fn cancel_normal_capacity(&self) -> usize {
        self.inner.cancel_normal_capacity
    }

    /// Returns the configured protected cancellation-operation partition capacity.
    #[must_use]
    pub fn cancel_protected_capacity(&self) -> usize {
        self.inner.cancel_protected_capacity
    }

    /// Returns the currently available permits for one dimension and class.
    #[must_use]
    pub fn available(&self, bottleneck: CapacityBottleneck, class: CapacityClass) -> usize {
        partition_capacity(&self.inner, bottleneck, class).saturating_sub(
            partition_in_flight(&self.inner, bottleneck, class).load(Ordering::Acquire),
        )
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
    /// Every in-flight counter is pinned to its full partition capacity, so
    /// no new acquisition can succeed on the back of a zeroed counter, and
    /// the sealing epoch tuple is recorded. Unknown held capacity stays
    /// excluded until [`Self::unseal_after_epoch_advance`] observes a fence
    /// that has moved past the seal (stale ownership fenced). The embedding
    /// owner calls this exactly once when it detects an unclean restart
    /// before admitting new work (STITCH).
    pub fn seal_after_restart(&self, epoch: EpochId) {
        self.inner
            .launch_normal_in_flight
            .fetch_max(self.inner.launch_normal_capacity, Ordering::AcqRel);
        self.inner
            .launch_protected_in_flight
            .fetch_max(self.inner.launch_protected_capacity, Ordering::AcqRel);
        self.inner
            .cancel_normal_in_flight
            .fetch_max(self.inner.cancel_normal_capacity, Ordering::AcqRel);
        self.inner
            .cancel_protected_in_flight
            .fetch_max(self.inner.cancel_protected_capacity, Ordering::AcqRel);
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
    /// capacity is never restored while stale ownership is unfenced.
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
                    field: "process_tree_reserve.restart_seal",
                    reason: "no restart seal is held; nothing to reconcile",
                });
            }
            Some(sealed_epoch) if sealed_epoch == current => {
                return Err(KernelError::InvalidField {
                    field: "process_tree_reserve.restart_seal",
                    reason: "epoch has not advanced; stale ownership is not fenced, held capacity stays excluded",
                });
            }
            Some(_) => {}
        }
        self.inner
            .launch_normal_in_flight
            .store(0, Ordering::Release);
        self.inner
            .launch_protected_in_flight
            .store(0, Ordering::Release);
        self.inner
            .cancel_normal_in_flight
            .store(0, Ordering::Release);
        self.inner
            .cancel_protected_in_flight
            .store(0, Ordering::Release);
        *sealed = None;
        self.inner.restart_sealed.store(false, Ordering::Release);
        Ok(())
    }

    /// Publishes the owner-produced capacity rows for the two frozen process
    /// dimensions (issue #1679 W3/W11).
    ///
    /// Every quantity is read from this reserve: the frozen bottlenecks and
    /// units, the configured disjoint normal/protected partition limits and
    /// their physical totals, and the
    /// [`CapacityEnforcement::PhysicalPartition`] mechanism those partitions
    /// are held under. The published limits are the configured partition
    /// capacities, not the currently available remainder: availability moves
    /// as permits are acquired and released, while the guarantee the profile
    /// records is the partition itself. No emergency partition is claimed
    /// here: there is no preallocated process slot. The
    /// composition-resolved references come from `ctx` unchanged.
    ///
    /// The rows are checked by the existing contract validation before they
    /// are returned, so a missing owner, generation, physical total,
    /// protected partition, enforcement, proof, evidence or invalidation
    /// reference fails here rather than publishing rows the Kernel
    /// composition would have to lower to `UNKNOWN`.
    ///
    /// # Errors
    ///
    /// Returns [`KernelError::InvalidField`] when the frozen owner map binds
    /// no owner to a process dimension or when the configured partition
    /// capacities cannot form a positive physical total, and
    /// [`KernelError::RuntimeContract`] when an assembled row fails the
    /// existing contract validation.
    pub fn publish_owner_rows(
        &self,
        ctx: &ProcessTreeOwnerEvidenceContext,
    ) -> Result<[BottleneckCapacityProfile; 2], KernelError> {
        let launch = owner_capacity_row(
            PROCESS_LAUNCH_BOTTLENECK,
            self.inner.launch_normal_capacity,
            self.inner.launch_protected_capacity,
            ctx,
        )?;
        let cancel = owner_capacity_row(
            PROCESS_CANCEL_BOTTLENECK,
            self.inner.cancel_normal_capacity,
            self.inner.cancel_protected_capacity,
            ctx,
        )?;
        Ok([launch, cancel])
    }

    /// Attempts to acquire one process permit for a typed operation without
    /// blocking.
    ///
    /// Only the two process bottlenecks typecheck through the `bottleneck`
    /// argument: another owner's dimension fails closed here. The operation
    /// tag alone selects the partition — `Normal` draws only the normal
    /// partition of that dimension, `Protected` only the protected one — so
    /// no relabelling can move normal work onto protected capacity (A5).
    /// `Emergency` is not issuable: there is no preallocated process slot.
    ///
    /// # Errors
    ///
    /// Returns [`KernelError::InvalidField`] for a foreign bottleneck, a
    /// blank or malformed owner/operation identity, an emergency tag, or an
    /// amount handled only through [`Self::issue_process_permit`], or the
    /// tagged saturation disposition
    /// ([`KernelError::NormalCapacityExhausted`],
    /// [`KernelError::ProtectedReserveExhausted`]) naming the exact
    /// bottleneck and shed work. The other dimension and the other partition
    /// are untouched in every case.
    pub fn try_acquire_process(
        &self,
        bottleneck: CapacityBottleneck,
        operation: RequestedOperationClass,
        owner: &str,
        operation_id: &str,
        epoch: EpochId,
    ) -> Result<ProcessPermit, KernelError> {
        if !is_process_bottleneck(bottleneck) {
            return Err(KernelError::InvalidField {
                field: "capacity_request.requested_bottleneck",
                reason: "this owner enforces only the process launch/termination dimensions; no other dimension is issuable here",
            });
        }
        validate_id(owner, "process_permit.owner")?;
        validate_id(operation_id, "process_permit.operation_id")?;
        let class = operation.capacity_class();
        if class == CapacityClass::EmergencyLastResort {
            return Err(KernelError::InvalidField {
                field: "capacity_request.operation",
                reason: "no preallocated process slot exists; emergency process launch is not issuable",
            });
        }
        if self.inner.restart_sealed.load(Ordering::Acquire) {
            return Err(saturation_error(
                bottleneck,
                operation,
                owner,
                operation_id,
                epoch,
            ));
        }
        if !cas_increment(
            partition_in_flight(&self.inner, bottleneck, class),
            partition_capacity(&self.inner, bottleneck, class),
        ) {
            return Err(saturation_error(
                bottleneck,
                operation,
                owner,
                operation_id,
                epoch,
            ));
        }
        Ok(ProcessPermit {
            inner: Some(self.inner.clone()),
            class,
            bottleneck,
            operation,
            operation_id: operation_id.to_owned(),
            owner: owner.to_owned(),
            epoch,
        })
    }

    /// Issues one owner-bound process permit for a validated capacity request.
    ///
    /// The W11 producer boundary for the #1701 launch consumer: the request
    /// names the exact process bottleneck, unit and amount under its typed
    /// [`RequestedOperationClass`] tag, and the owner returns the non-clone
    /// [`ProcessPermit`] together with the minted [`CapacityPermitBinding`].
    /// The request must be bound to the live [`ProcessOwnerBoundary`]: same
    /// compiled profile identity and revision (a copied revision from another
    /// profile fails closed here, never converts into capacity), same
    /// Authority lineage and sequence, exactly one slot. The binding carries
    /// the boundary's current profile identity and revision, owner generation
    /// and epoch — never the requester's bare claim — so the consumer can
    /// retain it alongside the active admission under the exact
    /// operation/admission/attempt identity and re-verify it at its
    /// launch/recovery boundary through
    /// [`Self::verify_process_permit`].
    ///
    /// The caller supplies the live boundary (as in front-door issuance the
    /// caller supplies its clock and the issuing owner generation: this
    /// adapter owns no generation counter and no epoch authority of its own).
    /// The request deadline is recorded, never enforced: issuance is
    /// synchronous. The binding carries no wall-clock expiry (`u64::MAX`);
    /// the permit lifetime is the handle lifetime (release-or-drop) and
    /// staleness is fenced by epoch, profile revision and generations.
    ///
    /// # Errors
    ///
    /// Returns the typed contract refusal for an illegal request,
    /// [`KernelError::InvalidField`] when the boundary carries no current
    /// profile, when the request names another owner's bottleneck, a stale
    /// profile, or an amount other than one slot (this owner issues
    /// single-slot permits; larger holdings need one permit per slot),
    /// [`KernelError::StaleEpochTuple`] when the request epoch tuple is from
    /// another lineage, [`KernelError::StaleEpoch`] when the request sequence
    /// differs within the active lineage, or the tagged saturation
    /// disposition ([`KernelError::NormalCapacityExhausted`],
    /// [`KernelError::ProtectedReserveExhausted`]) naming the exact
    /// bottleneck.
    pub fn issue_process_permit(
        &self,
        request: &CapacityRequest,
        boundary: &ProcessOwnerBoundary,
    ) -> Result<(ProcessPermit, CapacityPermitBinding), KernelError> {
        request.validate()?;
        boundary.validate()?;
        if !is_process_bottleneck(request.requested_bottleneck) {
            return Err(KernelError::InvalidField {
                field: "capacity_request.requested_bottleneck",
                reason: "this owner enforces only the process launch/termination dimensions; no other dimension is issuable here",
            });
        }
        if request.profile_id != boundary.profile_id
            || request.profile_revision != boundary.profile_revision
        {
            return Err(KernelError::InvalidField {
                field: "capacity_request.profile_revision",
                reason: "STALE_PROFILE: the request is not bound to the current compiled profile; re-resolve it before issuance",
            });
        }
        if !request
            .authority_epoch_ref
            .is_same_authority(&boundary.current_epoch)
        {
            if request.authority_epoch_ref.lineage_id != boundary.current_epoch.lineage_id {
                return Err(KernelError::StaleEpochTuple {
                    observed: request.authority_epoch_ref.clone(),
                    active: boundary.current_epoch.clone(),
                });
            }
            return Err(KernelError::StaleEpoch {
                observed: request.authority_epoch_ref.sequence.get(),
                active: boundary.current_epoch.sequence.get(),
            });
        }
        if request.requested_limit.quantity.get() != 1 {
            return Err(KernelError::InvalidField {
                field: "capacity_request.requested_limit",
                reason: "the process-tree owner issues single-slot permits; hold one permit per slot",
            });
        }
        let issued_at_ms =
            u64::try_from(boundary.now_ms).map_err(|_| KernelError::InvalidField {
                field: "process_owner_boundary.now_ms",
                reason: "the issuing clock must be non-negative",
            })?;
        let permit = self.try_acquire_process(
            request.requested_bottleneck,
            request.operation,
            &request.requesting_owner_ref,
            &request.operation_id,
            request.authority_epoch_ref.clone(),
        )?;
        let sequence = self.inner.permit_sequence.fetch_add(1, Ordering::AcqRel);
        let binding = CapacityPermitBinding {
            permit_id: format!(
                "PT-{}-{sequence}-{}",
                request.operation.as_contract_str(),
                request.operation_id
            ),
            operation_id: request.operation_id.clone(),
            capacity_class: request.operation.capacity_class(),
            operation: request.operation,
            bottleneck: request.requested_bottleneck,
            granted_limit: request.requested_limit,
            capacity_owner_ref: PROCESS_TREE_OWNER.to_owned(),
            capacity_owner_generation_ref: boundary.owner_generation,
            requesting_owner_ref: request.requesting_owner_ref.clone(),
            requesting_generation_ref: request.requesting_generation_ref,
            authority_epoch_ref: request.authority_epoch_ref.clone(),
            profile_id: boundary.profile_id.clone(),
            profile_revision: boundary.profile_revision.clone(),
            issued_at_ms,
            expires_at_ms: u64::MAX,
            owner_evidence_refs: vec![self.issue_evidence(
                request.requested_bottleneck,
                request.operation.capacity_class(),
            )],
        };
        debug_assert!(
            binding.validate().is_ok(),
            "process-tree minted permit binding must satisfy the contract"
        );
        debug_assert!(
            binding.matches_request(request),
            "process-tree minted permit binding must match its request"
        );
        Ok((permit, binding))
    }

    /// Replays the authenticated owner lookup for one presented binding
    /// against the live boundary (issue #1679, W11 consumer side).
    ///
    /// This is the check the launch/recovery composition runs before any
    /// P-03 effect: the binding must be owner-issued here, must exactly
    /// match the presented request, and must still be current (profile,
    /// epoch). It consults no counter on purpose: slot liveness is the
    /// retained permit handle's property, while this lookup proves the
    /// evidence is genuine and current. A copied profile string, a foreign
    /// owner tag, changed content, or a fenced epoch fails closed; missing
    /// evidence never passes as live authority.
    ///
    /// # Errors
    ///
    /// Returns [`KernelError::InvalidField`] when the binding is illegal,
    /// names another owner, does not match the presented request, or is
    /// bound to a stale profile, [`KernelError::StaleEpochTuple`] when the
    /// binding epoch tuple is from another lineage, or
    /// [`KernelError::StaleEpoch`] when the binding sequence differs within
    /// the active lineage.
    pub fn verify_process_permit(
        binding: &CapacityPermitBinding,
        request: &CapacityRequest,
        boundary: &ProcessOwnerBoundary,
    ) -> Result<(), KernelError> {
        binding.validate()?;
        boundary.validate()?;
        if binding.capacity_owner_ref != PROCESS_TREE_OWNER {
            return Err(KernelError::InvalidField {
                field: "capacity_permit_binding.capacity_owner_ref",
                reason: "FOREIGN_OWNER: this lookup authenticates only process-tree owner bindings",
            });
        }
        if !is_process_bottleneck(binding.bottleneck) {
            return Err(KernelError::InvalidField {
                field: "capacity_permit_binding.bottleneck",
                reason: "FOREIGN_OWNER: this lookup authenticates only the process launch/termination dimensions",
            });
        }
        if !binding.matches_request(request) {
            return Err(KernelError::InvalidField {
                field: "capacity_permit_binding",
                reason: "CONFLICT: the presented binding does not match its request; changed content never replays",
            });
        }
        if binding.profile_id != boundary.profile_id
            || binding.profile_revision != boundary.profile_revision
        {
            return Err(KernelError::InvalidField {
                field: "capacity_permit_binding.profile_revision",
                reason: "STALE_PROFILE: the binding is not bound to the current compiled profile",
            });
        }
        if !binding
            .authority_epoch_ref
            .is_same_authority(&boundary.current_epoch)
        {
            if binding.authority_epoch_ref.lineage_id != boundary.current_epoch.lineage_id {
                return Err(KernelError::StaleEpochTuple {
                    observed: binding.authority_epoch_ref.clone(),
                    active: boundary.current_epoch.clone(),
                });
            }
            return Err(KernelError::StaleEpoch {
                observed: binding.authority_epoch_ref.sequence.get(),
                active: boundary.current_epoch.sequence.get(),
            });
        }
        Ok(())
    }

    /// Records the owner's contemporaneous partition observation for one issuance.
    fn issue_evidence(&self, bottleneck: CapacityBottleneck, class: CapacityClass) -> String {
        let capacity = partition_capacity(&self.inner, bottleneck, class);
        let in_flight = partition_in_flight(&self.inner, bottleneck, class).load(Ordering::Acquire);
        format!(
            "process-tree:{}:{} capacity {capacity} in-flight {in_flight}",
            bottleneck.as_contract_str(),
            class.as_contract_str(),
        )
    }
}

/// Builds the tagged saturation disposition for one refused acquisition.
fn saturation_error(
    bottleneck: CapacityBottleneck,
    operation: RequestedOperationClass,
    owner: &str,
    operation_id: &str,
    epoch: EpochId,
) -> KernelError {
    match operation {
        RequestedOperationClass::Normal(work) => KernelError::NormalCapacityExhausted {
            bottleneck,
            work_class: work,
            operation_id: operation_id.to_owned(),
            owner: owner.to_owned(),
            epoch,
        },
        RequestedOperationClass::Protected(control) => KernelError::ProtectedReserveExhausted {
            bottleneck,
            operation: control,
            operation_id: operation_id.to_owned(),
            owner: owner.to_owned(),
            epoch,
        },
        RequestedOperationClass::Emergency(_) => KernelError::InvalidField {
            field: "capacity_request.operation",
            reason: "no preallocated process slot exists; emergency process launch is not issuable",
        },
    }
}

/// Builds one claimed owner row for a process dimension from the reserve's
/// configured partition capacities and the composition-resolved references.
///
/// The owner reference is read from the frozen owner map, never restated
/// here; the unit is the bottleneck's own declared unit. The physical total
/// is exactly the sum of the two disjoint partitions. A zero partition
/// capacity (unreachable through the constructor, which refuses zero) or a
/// missing frozen owner fails closed: a dimension without a frozen owner has
/// no claim to publish.
fn owner_capacity_row(
    bottleneck: CapacityBottleneck,
    normal_capacity: usize,
    protected_capacity: usize,
    ctx: &ProcessTreeOwnerEvidenceContext,
) -> Result<BottleneckCapacityProfile, KernelError> {
    let owner = frozen_bottleneck_owner_map()
        .into_iter()
        .find(|bound| bound.bottleneck == bottleneck)
        .map(|bound| bound.owner)
        .ok_or(KernelError::InvalidField {
            field: "process_tree_reserve.owner_row",
            reason: "frozen owner map binds no owner to the process dimension",
        })?;
    let unit = bottleneck.unit();
    let limit = |field: &'static str, amount: usize| {
        u64::try_from(amount)
            .ok()
            .and_then(NonZeroU64::new)
            .map(|quantity| CapacityLimit { unit, quantity })
            .ok_or(KernelError::InvalidField {
                field,
                reason: "partition capacity must be a positive value",
            })
    };
    let normal_limit = limit("process_tree_reserve.normal_limit", normal_capacity)?;
    let protected_limit = limit("process_tree_reserve.protected_limit", protected_capacity)?;
    let physical_total =
        normal_capacity
            .checked_add(protected_capacity)
            .ok_or(KernelError::InvalidField {
                field: "process_tree_reserve.physical_total_limit",
                reason: "disjoint partition capacities overflow the physical total",
            })?;
    let physical_total_limit = limit("process_tree_reserve.physical_total_limit", physical_total)?;
    let row = BottleneckCapacityProfile {
        bottleneck,
        coverage_state: BottleneckCoverageState::Claimed,
        owner_ref: owner.to_owned(),
        owner_generation_ref: ctx.owner_generation_ref.clone(),
        unit,
        physical_total_limit: Some(physical_total_limit),
        normal_work_applicable: true,
        normal_limit: Some(normal_limit),
        protected_limit: Some(protected_limit),
        emergency_limit: None,
        enforcement: Some(CapacityEnforcement::PhysicalPartition),
        proof_profile_ref: ctx.proof_profile_ref.clone(),
        evidence_refs: ctx.evidence_refs.clone(),
        invalidation_set: ctx.invalidation_set.clone(),
    };
    row.validate()?;
    Ok(row)
}

impl Drop for ProcessPermit {
    fn drop(&mut self) {
        if let Some(inner) = self.inner.take() {
            let slot = partition_in_flight(&inner, self.bottleneck, self.class);
            debug_assert!(
                slot.load(Ordering::Acquire) > 0,
                "process permit dropped without a held partition slot"
            );
            slot.fetch_sub(1, Ordering::AcqRel);
        }
    }
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;
    use eliot_contracts::EpochLineageId;

    const TEST_LINEAGE: &str = "550e8400-e29b-41d4-a716-446655440000";
    const OTHER_LINEAGE: &str = "660e8400-e29b-41d4-a716-446655440001";

    fn genesis_epoch() -> EpochId {
        EpochId::new(
            EpochLineageId::new(TEST_LINEAGE).expect("valid test lineage"),
            NonZeroU64::MIN,
        )
        .expect("valid test epoch")
    }

    fn advanced_epoch() -> EpochId {
        EpochId::new(
            EpochLineageId::new(TEST_LINEAGE).expect("valid test lineage"),
            NonZeroU64::new(2).expect("nonzero sequence"),
        )
        .expect("valid test epoch")
    }

    fn foreign_epoch() -> EpochId {
        EpochId::new(
            EpochLineageId::new(OTHER_LINEAGE).expect("valid test lineage"),
            NonZeroU64::MIN,
        )
        .expect("valid test epoch")
    }

    fn owner_generation() -> Result<ResourceGeneration, KernelError> {
        ResourceGeneration::new(1).map_err(|_| KernelError::InvalidField {
            field: "test.owner_generation",
            reason: "test generation must construct",
        })
    }

    fn reserve() -> Result<ProcessTreeReserve, KernelError> {
        ProcessTreeReserve::partitioned(2, 2, 2, 2)
    }

    fn boundary(epoch: EpochId) -> Result<ProcessOwnerBoundary, KernelError> {
        Ok(ProcessOwnerBoundary {
            owner_generation: owner_generation()?,
            current_epoch: epoch,
            profile_id: "profile-1".to_owned(),
            profile_revision: "rev-9".to_owned(),
            now_ms: 500,
        })
    }

    fn make_request(
        bottleneck: CapacityBottleneck,
        operation: RequestedOperationClass,
        operation_id: &str,
        epoch: EpochId,
    ) -> CapacityRequest {
        CapacityRequest {
            operation,
            operation_id: operation_id.to_owned(),
            requested_bottleneck: bottleneck,
            requested_limit: CapacityLimit {
                unit: bottleneck.unit(),
                quantity: NonZeroU64::new(1).expect("single slot"),
            },
            requesting_owner_ref: "native-worker".to_owned(),
            requesting_generation_ref: ResourceGeneration::genesis(),
            authority_epoch_ref: epoch,
            profile_id: "profile-1".to_owned(),
            profile_revision: "rev-9".to_owned(),
            deadline_ms: 1_000,
        }
    }

    fn ctx() -> ProcessTreeOwnerEvidenceContext {
        ProcessTreeOwnerEvidenceContext {
            owner_generation_ref: "gen-7".to_owned(),
            proof_profile_ref: "proof-1".to_owned(),
            evidence_refs: vec!["ev-1".to_owned()],
            invalidation_set: vec!["inv-1".to_owned()],
        }
    }

    #[test]
    fn process_owner_rows_claim_both_dimensions() -> Result<(), KernelError> {
        let rows = reserve()?.publish_owner_rows(&ctx())?;
        assert_eq!(rows.len(), 2);
        let launch = &rows[0];
        assert_eq!(launch.bottleneck, PROCESS_LAUNCH_BOTTLENECK);
        assert_eq!(launch.coverage_state, BottleneckCoverageState::Claimed);
        assert_eq!(launch.owner_ref, "Host/Kernel process-tree owner");
        assert_eq!(launch.unit, CapacityBottleneck::ProcessLaunchSlots.unit());
        assert_eq!(
            launch
                .normal_limit
                .as_ref()
                .map(|limit| limit.quantity.get()),
            Some(2)
        );
        assert_eq!(
            launch
                .protected_limit
                .as_ref()
                .map(|limit| limit.quantity.get()),
            Some(2)
        );
        assert_eq!(
            launch
                .physical_total_limit
                .as_ref()
                .map(|limit| limit.quantity.get()),
            Some(4)
        );
        assert!(launch.emergency_limit.is_none());
        let cancel = &rows[1];
        assert_eq!(cancel.bottleneck, PROCESS_CANCEL_BOTTLENECK);
        assert_eq!(cancel.coverage_state, BottleneckCoverageState::Claimed);
        assert_eq!(cancel.owner_ref, "Host/Kernel process-tree owner");
        assert_eq!(
            cancel.unit,
            CapacityBottleneck::ProcessCancellationTermination.unit()
        );
        Ok(())
    }

    #[test]
    fn process_owner_rows_refuse_blank_generation() -> Result<(), KernelError> {
        let mut bad = ctx();
        bad.owner_generation_ref.clear();
        assert!(matches!(
            reserve()?.publish_owner_rows(&bad),
            Err(KernelError::RuntimeContract(_))
        ));
        Ok(())
    }

    #[test]
    fn process_issue_launch_protected_success() -> Result<(), KernelError> {
        let owner = reserve()?;
        let epoch = genesis_epoch();
        let request = make_request(
            PROCESS_LAUNCH_BOTTLENECK,
            RequestedOperationClass::Protected(ControlOperationClass::Recovery),
            "op-launch-1",
            epoch.clone(),
        );
        let (permit, binding) = owner.issue_process_permit(&request, &boundary(epoch)?)?;
        assert!(binding.validate().is_ok());
        assert!(binding.matches_request(&request));
        assert_eq!(binding.capacity_owner_ref, PROCESS_TREE_OWNER);
        assert_eq!(binding.bottleneck, PROCESS_LAUNCH_BOTTLENECK);
        assert_eq!(binding.capacity_class, CapacityClass::ProtectedControl);
        assert_eq!(binding.profile_id, "profile-1");
        assert_eq!(binding.profile_revision, "rev-9");
        assert_eq!(binding.capacity_owner_generation_ref, owner_generation()?);
        assert_eq!(permit.bottleneck(), PROCESS_LAUNCH_BOTTLENECK);
        assert_eq!(permit.operation_id(), "op-launch-1");
        assert_eq!(permit.owner(), "native-worker");
        assert_eq!(
            owner.available(PROCESS_LAUNCH_BOTTLENECK, CapacityClass::ProtectedControl),
            1
        );
        // The other dimension and the normal partition are untouched.
        assert_eq!(
            owner.available(PROCESS_LAUNCH_BOTTLENECK, CapacityClass::NormalWorkload),
            2
        );
        assert_eq!(
            owner.available(PROCESS_CANCEL_BOTTLENECK, CapacityClass::ProtectedControl),
            2
        );
        Ok(())
    }

    #[test]
    fn process_issue_cancel_normal_success() -> Result<(), KernelError> {
        let owner = reserve()?;
        let epoch = genesis_epoch();
        let request = make_request(
            PROCESS_CANCEL_BOTTLENECK,
            RequestedOperationClass::Normal(NormalWorkClass::Maintenance),
            "op-cancel-1",
            epoch.clone(),
        );
        let (_permit, binding) = owner.issue_process_permit(&request, &boundary(epoch)?)?;
        assert!(binding.matches_request(&request));
        assert_eq!(binding.capacity_class, CapacityClass::NormalWorkload);
        assert_eq!(
            owner.available(PROCESS_CANCEL_BOTTLENECK, CapacityClass::NormalWorkload),
            1
        );
        Ok(())
    }

    #[test]
    fn process_issue_refuses_foreign_bottleneck() -> Result<(), KernelError> {
        let owner = reserve()?;
        let epoch = genesis_epoch();
        let request = make_request(
            CapacityBottleneck::KernelControlChannel,
            RequestedOperationClass::Protected(ControlOperationClass::Recovery),
            "op-foreign-1",
            epoch.clone(),
        );
        assert!(matches!(
            owner.issue_process_permit(&request, &boundary(epoch)?),
            Err(KernelError::InvalidField { .. })
        ));
        Ok(())
    }

    #[test]
    fn process_issue_refuses_blank_operation_id() -> Result<(), KernelError> {
        let owner = reserve()?;
        let epoch = genesis_epoch();
        let request = make_request(
            PROCESS_LAUNCH_BOTTLENECK,
            RequestedOperationClass::Protected(ControlOperationClass::Recovery),
            "   ",
            epoch.clone(),
        );
        // Request-legality failures surface as the typed contract refusal.
        assert!(matches!(
            owner.issue_process_permit(&request, &boundary(epoch)?),
            Err(KernelError::RuntimeContract(_))
        ));
        Ok(())
    }

    #[test]
    fn process_issue_refuses_stale_profile() -> Result<(), KernelError> {
        let owner = reserve()?;
        let epoch = genesis_epoch();
        let mut request = make_request(
            PROCESS_LAUNCH_BOTTLENECK,
            RequestedOperationClass::Protected(ControlOperationClass::Recovery),
            "op-stale-1",
            epoch.clone(),
        );
        // A revision copied from another profile is not current: fail closed.
        request.profile_revision = "rev-8".to_owned();
        assert!(matches!(
            owner.issue_process_permit(&request, &boundary(epoch)?),
            Err(KernelError::InvalidField { .. })
        ));
        Ok(())
    }

    #[test]
    fn process_issue_refuses_blank_boundary_profile() -> Result<(), KernelError> {
        let owner = reserve()?;
        let epoch = genesis_epoch();
        let request = make_request(
            PROCESS_LAUNCH_BOTTLENECK,
            RequestedOperationClass::Protected(ControlOperationClass::Recovery),
            "op-noprofile-1",
            epoch.clone(),
        );
        let mut no_profile = boundary(epoch)?;
        no_profile.profile_revision.clear();
        assert!(matches!(
            owner.issue_process_permit(&request, &no_profile),
            Err(KernelError::InvalidField { .. })
        ));
        Ok(())
    }

    #[test]
    fn process_issue_refuses_foreign_lineage() -> Result<(), KernelError> {
        let owner = reserve()?;
        let request = make_request(
            PROCESS_LAUNCH_BOTTLENECK,
            RequestedOperationClass::Protected(ControlOperationClass::Recovery),
            "op-lineage-1",
            foreign_epoch(),
        );
        assert!(matches!(
            owner.issue_process_permit(&request, &boundary(genesis_epoch())?),
            Err(KernelError::StaleEpochTuple { .. })
        ));
        Ok(())
    }

    #[test]
    fn process_issue_refuses_stale_sequence() -> Result<(), KernelError> {
        let owner = reserve()?;
        let request = make_request(
            PROCESS_LAUNCH_BOTTLENECK,
            RequestedOperationClass::Protected(ControlOperationClass::Recovery),
            "op-seq-1",
            genesis_epoch(),
        );
        assert!(matches!(
            owner.issue_process_permit(&request, &boundary(advanced_epoch())?),
            Err(KernelError::StaleEpoch { .. })
        ));
        Ok(())
    }

    #[test]
    fn process_issue_refuses_double_slot() -> Result<(), KernelError> {
        let owner = reserve()?;
        let epoch = genesis_epoch();
        let mut request = make_request(
            PROCESS_LAUNCH_BOTTLENECK,
            RequestedOperationClass::Protected(ControlOperationClass::Recovery),
            "op-double-1",
            epoch.clone(),
        );
        request.requested_limit.quantity = NonZeroU64::new(2).expect("two slots");
        assert!(matches!(
            owner.issue_process_permit(&request, &boundary(epoch)?),
            Err(KernelError::InvalidField { .. })
        ));
        Ok(())
    }

    #[test]
    fn process_issue_refuses_emergency_tag() -> Result<(), KernelError> {
        let owner = reserve()?;
        let epoch = genesis_epoch();
        let request = make_request(
            PROCESS_LAUNCH_BOTTLENECK,
            RequestedOperationClass::Emergency(EmergencyOperationClass::ReserveExhaustionGapRecord),
            "op-emergency-1",
            epoch.clone(),
        );
        // There is no preallocated process slot: emergency is not issuable.
        assert!(matches!(
            owner.issue_process_permit(&request, &boundary(epoch)?),
            Err(KernelError::InvalidField { .. })
        ));
        Ok(())
    }

    #[test]
    fn process_issue_refuses_unit_mismatch() -> Result<(), KernelError> {
        let owner = reserve()?;
        let epoch = genesis_epoch();
        let mut request = make_request(
            PROCESS_LAUNCH_BOTTLENECK,
            RequestedOperationClass::Protected(ControlOperationClass::Recovery),
            "op-unit-1",
            epoch.clone(),
        );
        request.requested_limit.unit = CapacityBottleneck::OrsDurableQueueBytes.unit();
        assert!(matches!(
            owner.issue_process_permit(&request, &boundary(epoch)?),
            Err(KernelError::RuntimeContract(_))
        ));
        Ok(())
    }

    #[test]
    fn process_saturation_names_bottleneck_and_releases_once() -> Result<(), KernelError> {
        let owner = ProcessTreeReserve::partitioned(1, 1, 1, 1)?;
        let epoch = genesis_epoch();
        let first = make_request(
            PROCESS_LAUNCH_BOTTLENECK,
            RequestedOperationClass::Protected(ControlOperationClass::Recovery),
            "op-sat-1",
            epoch.clone(),
        );
        let (permit, _binding) = owner.issue_process_permit(&first, &boundary(epoch.clone())?)?;
        let second = make_request(
            PROCESS_LAUNCH_BOTTLENECK,
            RequestedOperationClass::Protected(ControlOperationClass::Recovery),
            "op-sat-2",
            epoch.clone(),
        );
        let refused = owner.issue_process_permit(&second, &boundary(epoch.clone())?);
        match refused {
            Err(KernelError::ProtectedReserveExhausted { bottleneck, .. }) => {
                assert_eq!(bottleneck, PROCESS_LAUNCH_BOTTLENECK);
            }
            other => panic!("saturation must name the process bottleneck, got {other:?}"),
        }
        // Release returns exactly the consumed slot; drop afterwards moves
        // no counter.
        let evidence = permit.release();
        assert_eq!(evidence.bottleneck(), PROCESS_LAUNCH_BOTTLENECK);
        assert_eq!(evidence.capacity_class(), CapacityClass::ProtectedControl);
        assert_eq!(evidence.operation_id(), "op-sat-1");
        assert_eq!(evidence.owner(), "native-worker");
        assert_eq!(
            owner.available(PROCESS_LAUNCH_BOTTLENECK, CapacityClass::ProtectedControl),
            1
        );
        Ok(())
    }

    #[test]
    fn process_release_evidence_matches_permit() -> Result<(), KernelError> {
        let owner = reserve()?;
        let epoch = genesis_epoch();
        let request = make_request(
            PROCESS_CANCEL_BOTTLENECK,
            RequestedOperationClass::Normal(NormalWorkClass::Maintenance),
            "op-rel-1",
            epoch,
        );
        let boundary_epoch = request.authority_epoch_ref.clone();
        let (permit, _binding) =
            owner.issue_process_permit(&request, &boundary(boundary_epoch)?)?;
        let evidence = permit.release();
        assert_eq!(evidence.capacity_class(), CapacityClass::NormalWorkload);
        assert_eq!(evidence.bottleneck(), PROCESS_CANCEL_BOTTLENECK);
        assert_eq!(evidence.operation_id(), "op-rel-1");
        assert_eq!(evidence.owner(), "native-worker");
        assert_eq!(
            owner.available(PROCESS_CANCEL_BOTTLENECK, CapacityClass::NormalWorkload),
            2
        );
        Ok(())
    }

    #[test]
    fn process_drop_without_release_returns_slot() -> Result<(), KernelError> {
        let owner = ProcessTreeReserve::partitioned(1, 1, 1, 1)?;
        let epoch = genesis_epoch();
        let request = make_request(
            PROCESS_LAUNCH_BOTTLENECK,
            RequestedOperationClass::Normal(NormalWorkClass::NormalBackground),
            "op-drop-1",
            epoch.clone(),
        );
        // Drop the permit without releasing: the backstop returns the slot.
        drop(owner.issue_process_permit(&request, &boundary(epoch)?)?.0);
        assert_eq!(
            owner.available(PROCESS_LAUNCH_BOTTLENECK, CapacityClass::NormalWorkload),
            1
        );
        Ok(())
    }

    #[test]
    fn process_seal_excludes_until_epoch_advances() -> Result<(), KernelError> {
        let owner = reserve()?;
        let epoch = genesis_epoch();
        owner.seal_after_restart(epoch.clone());
        assert!(owner.restart_sealed());
        let request = make_request(
            PROCESS_LAUNCH_BOTTLENECK,
            RequestedOperationClass::Protected(ControlOperationClass::Recovery),
            "op-sealed-1",
            epoch.clone(),
        );
        // Unknown held capacity stays excluded: sealed acquisition refuses.
        assert!(matches!(
            owner.issue_process_permit(&request, &boundary(epoch.clone())?),
            Err(KernelError::ProtectedReserveExhausted { .. })
        ));
        // The seal does not lift on the same epoch: stale ownership unfenced.
        assert!(owner.unseal_after_epoch_advance(&epoch).is_err());
        owner.unseal_after_epoch_advance(&advanced_epoch())?;
        assert!(!owner.restart_sealed());
        // After the fence moves past the seal, a request current against the
        // new epoch is admitted again.
        let reopened = make_request(
            PROCESS_LAUNCH_BOTTLENECK,
            RequestedOperationClass::Protected(ControlOperationClass::Recovery),
            "op-sealed-2",
            advanced_epoch(),
        );
        assert!(
            owner
                .issue_process_permit(&reopened, &boundary(advanced_epoch())?)
                .is_ok()
        );
        Ok(())
    }

    #[test]
    fn process_verify_accepts_current_binding() -> Result<(), KernelError> {
        let owner = reserve()?;
        let epoch = genesis_epoch();
        let request = make_request(
            PROCESS_LAUNCH_BOTTLENECK,
            RequestedOperationClass::Protected(ControlOperationClass::Recovery),
            "op-verify-1",
            epoch.clone(),
        );
        let live = boundary(epoch)?;
        let (_permit, binding) = owner.issue_process_permit(&request, &live)?;
        assert!(ProcessTreeReserve::verify_process_permit(&binding, &request, &live).is_ok());
        Ok(())
    }

    #[test]
    fn process_verify_refuses_changed_request() -> Result<(), KernelError> {
        let owner = reserve()?;
        let epoch = genesis_epoch();
        let request = make_request(
            PROCESS_LAUNCH_BOTTLENECK,
            RequestedOperationClass::Protected(ControlOperationClass::Recovery),
            "op-verify-2",
            epoch.clone(),
        );
        let live = boundary(epoch)?;
        let (_permit, binding) = owner.issue_process_permit(&request, &live)?;
        // Changed content never replays: a relabelled operation id conflicts.
        let mut changed = request.clone();
        changed.operation_id = "op-verify-2x".to_owned();
        assert!(matches!(
            ProcessTreeReserve::verify_process_permit(&binding, &changed, &live),
            Err(KernelError::InvalidField { .. })
        ));
        Ok(())
    }

    #[test]
    fn process_verify_refuses_stale_boundary() -> Result<(), KernelError> {
        let owner = reserve()?;
        let epoch = genesis_epoch();
        let request = make_request(
            PROCESS_LAUNCH_BOTTLENECK,
            RequestedOperationClass::Protected(ControlOperationClass::Recovery),
            "op-verify-3",
            epoch.clone(),
        );
        let live = boundary(epoch)?;
        let (_permit, binding) = owner.issue_process_permit(&request, &live)?;
        // The profile moved on: the once-current binding is now stale.
        let mut moved = live.clone();
        moved.profile_revision = "rev-10".to_owned();
        assert!(matches!(
            ProcessTreeReserve::verify_process_permit(&binding, &request, &moved),
            Err(KernelError::InvalidField { .. })
        ));
        Ok(())
    }

    #[test]
    fn process_verify_refuses_foreign_owner() -> Result<(), KernelError> {
        let owner = reserve()?;
        let epoch = genesis_epoch();
        let request = make_request(
            PROCESS_LAUNCH_BOTTLENECK,
            RequestedOperationClass::Protected(ControlOperationClass::Recovery),
            "op-verify-4",
            epoch.clone(),
        );
        let live = boundary(epoch)?;
        let (_permit, mut binding) = owner.issue_process_permit(&request, &live)?;
        // A binding relabelled to another owner is not this owner's evidence.
        binding.capacity_owner_ref = "someone-else".to_owned();
        assert!(matches!(
            ProcessTreeReserve::verify_process_permit(&binding, &request, &live),
            Err(KernelError::InvalidField { .. })
        ));
        Ok(())
    }
}
