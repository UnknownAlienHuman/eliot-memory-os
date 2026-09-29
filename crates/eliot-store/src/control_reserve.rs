//! Store control-reserve partitions for connections, transactions and
//! pending-write memory.
//!
//! Issue #1679, W5 Store wave: the Store bridge generation enforces disjoint
//! normal-workload and protected-control partitions for its three frozen
//! bottlenecks ([`STORE_CONNECTION_BOTTLENECK`],
//! [`STORE_TRANSACTION_BOTTLENECK`] and [`STORE_PENDING_WRITE_BOTTLENECK`],
//! owned by the frozen "Store bridge generation" binding). Normal Store
//! writes, named reads, agents, models, swarm, reports and maintenance can
//! saturate the normal partitions without consuming protected control
//! capacity, and they cannot acquire a protected permit by relabelling
//! priority or class: only [`ControlOperationClass`] operations typecheck on
//! the protected acquisition paths, and no acquisition path takes a priority,
//! class label or free-form string that could smuggle one class into another.
//! There is no emergency partition here; recording reserve loss stays with
//! the front-door last-resort slot, exactly as in the ORS slice.
//!
//! Every [`StorePermit`] is owner-issued non-clone evidence bound to permit
//! and operation identities, capacity/operation class, issuing bridge
//! generation, requester generation, exact bottleneck/unit/granted amount,
//! profile revision, issue/expiry and owner-derived evidence. The issuing
//! generation is the live [`crate::db_client_set::DbClientSet`] bridge
//! `generation_id`: the exact
//! "Store bridge generation" owner the frozen map binds to these three
//! dimensions. The profile revision is the exact
//! [`eliot_runtime_contracts::ControlReserveProfile`] revision string the
//! request was admitted under.
//!
//! Permits that can outlive the issuing frame carry a [`StorePermitRecord`]:
//! the persistable owner evidence that distinguishes not issued, issued/held,
//! release requested, released, possibly leaked/unknown and stale owner
//! requiring reconciliation. Restart never restores capacity by resetting a
//! local counter: [`StoreReserve::apply_restarted_hold`] re-reserves every
//! non-terminal non-stale record before the reserve admits new work, and
//! unknown/leak-suspected ownership stays reserved (excluded) until owner
//! reconciliation supplies a terminal disposition. The durable handoff of
//! records (ControlWal/redb) and the boot-time reconcile loop belong to a
//! later wave; [`StorePermitRecord::reconcile`] is the pure classifier that
//! loop will drive.
//!
//! ASSUMPTION: this crate has no `eliot-contracts` edge (Cargo deps are frozen
//! for this slice), so the typed Authority Epoch and typed
//! operation/permit-id identities cannot be named here. The permit binds the
//! epoch indirectly through the issuing bridge generation plus the exact
//! profile revision (profile construction already binds the epoch), and every
//! identity field enforces the same bounded non-blank rule the typed owners
//! enforce. The wiring wave that adds the contracts edge tightens these to
//! the typed spellings without changing the partition discipline.
//!
//! [`StoreReserve::publish_claimed_rows`] publishes the three `CLAIMED`
//! [`eliot_runtime_contracts::BottleneckCapacityProfile`] rows for the Kernel
//! profile composition join: one row per Store bottleneck in frozen contract
//! order, each naming the frozen-map owner verbatim, the exact unit, the
//! physical total and both disjoint partitions, and validated with the
//! existing row check before return. Completeness is compared against the
//! independent frozen map (exactly the three Store dimensions under one
//! shared Store owner), never against the rows themselves.
//!
//! [`StoreScopeReserves`] holds one independent [`StoreReserve`] per
//! Store/Ordering Scope or provider path: saturating one scope's normal
//! partition shares no counter with any other scope's protected partition.
//!
//! ASSUMPTION: `owner_generation_ref`, `proof_profile_ref` and scope labels
//! are composition- or caller-supplied current evidence echoed or keyed by
//! this owner; this module opens no clock and reads no profile. The wiring
//! wave that adds the contracts edge tightens the epoch-adjacent spellings
//! without changing the partition discipline.
//!
//! This module has no production caller yet (STITCH): it publishes the owner
//! evidence the Kernel profile composition will join. Wiring needs one line
//! in `crates/eliot-store/src/lib.rs` (`pub mod control_reserve;` plus the
//! re-export), owned by the integration wave.
//! DISCLOSED LIMIT: `owner_generation`, `requester_generation`,
//! `profile_revision` and the issue/expiry timestamps are composition- or
//! caller-supplied and echoed into the permit/record; this module opens no
//! clock and reads no profile.

use std::collections::HashMap;
use std::num::NonZeroU64;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};

use eliot_runtime_contracts::{
    BottleneckCapacityProfile, BottleneckCoverageState, CapacityBottleneck, CapacityClass,
    CapacityEnforcement, CapacityLimit, CapacityUnit, ControlOperationClass, NormalWorkClass,
    frozen_bottleneck_owner_map,
};
use thiserror::Error;
use uuid::Uuid;

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
    /// The normal partition cannot satisfy the request; the protected
    /// partition is untouched.
    #[error(
        "Store normal capacity exhausted for {bottleneck:?}: work {work_class:?} operation {operation_id} owned by {owner} bridge generation {owner_generation}"
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
        /// Issuing bridge generation that refused the request.
        owner_generation: Uuid,
    },
    /// The protected partition cannot satisfy the request.
    #[error(
        "Store protected reserve exhausted for {bottleneck:?}: control operation {operation:?} operation {operation_id} owned by {owner} bridge generation {owner_generation}"
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
        /// Issuing bridge generation that refused the request.
        owner_generation: Uuid,
    },
    /// A release was requested twice for the same permit identity.
    #[error("Store permit {permit_id} is already released; release happens at most once")]
    AlreadyReleased {
        /// Permit identity presented twice.
        permit_id: String,
    },
    /// A restart-time record contradicts live partition accounting.
    #[error("Store restart hold for permit {permit_id} contradicts live accounting: {detail}")]
    RestartReconcileContradiction {
        /// Permit identity that cannot be re-held.
        permit_id: String,
        /// Why the re-hold is impossible.
        detail: String,
    },
    /// The existing contract rejected an assembled Store reserve row.
    #[error("runtime contract rejected Store reserve row: {0}")]
    Contract(String),
    /// The scope registry is unavailable; no scope reserve was created or
    /// returned and no partition counter moved.
    #[error("Store scope registry is unavailable; no scope reserve was created or returned")]
    ScopeRegistryUnavailable,
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
/// class cannot name a protected operation and vice versa, so ordinary Store
/// writes, named reads, agent, model, swarm, report or maintenance work fails
/// to typecheck against the protected acquisition paths instead of failing at
/// runtime. No path accepts a priority or class label, so relabelling cannot
/// promote normal work into the protected partition.
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

    /// Returns the contract operation label carried into release evidence.
    #[must_use]
    pub const fn contract_label(self) -> &'static str {
        match self {
            Self::Normal(work) => work.as_contract_str(),
            Self::Protected(operation) => operation.as_contract_str(),
        }
    }
}

/// Owner-supplied bindings for one [`StorePermit`] acquisition.
///
/// The issuing `owner_generation` is the live
/// [`crate::db_client_set::DbClientSet`] bridge `generation_id` (see
/// [`crate::db_client_set::DbClientSet::generation_id`]); the requester
/// presents its own generation alongside. Profile revision, issue and expiry
/// are composition-supplied current evidence echoed into the permit; this
/// owner records them and the Kernel composition validates them.
#[derive(Clone, Copy, Debug)]
pub struct StorePermitRequest<'a> {
    /// Requesting owner label (validated non-blank, bounded).
    pub owner: &'a str,
    /// Operation identity the permit is granted for.
    pub operation_id: &'a str,
    /// Owner-issued permit identity, distinct from the operation identity.
    pub permit_id: &'a str,
    /// Issuing Store bridge generation (owner side of the frozen binding).
    pub owner_generation: Uuid,
    /// Requesting owner's generation.
    pub requester_generation: Uuid,
    /// Profile revision the request was admitted under.
    pub profile_revision: &'a str,
    /// Caller-observed issue time (Unix millis); no clock is opened here.
    pub issued_at_ms: i64,
    /// Caller-observed expiry (Unix millis), if the grant expires.
    pub expires_at_ms: Option<i64>,
}

/// Lifecycle state of one permit's capacity ownership (issue #1679, W5).
///
/// The six states are exactly the distinguishable positions the issue names:
/// not issued, issued/held, release requested, released, possibly
/// leaked/unknown and stale owner requiring reconciliation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StorePermitState {
    /// No permit was ever issued for this identity.
    NotIssued,
    /// The permit is issued and currently holds partition capacity.
    IssuedHeld,
    /// Release was requested but the exactly-once release has not completed.
    ReleaseRequested,
    /// The permit was released exactly once; no capacity is held.
    Released,
    /// Ownership is possibly leaked or otherwise unknown; capacity stays
    /// reserved (excluded) until reconciliation supplies a terminal
    /// disposition.
    PossiblyLeakedUnknown,
    /// The issuing owner is stale (generation or profile moved); the record
    /// is excluded until the current owner reconciles it.
    StaleOwnerRequiringReconciliation,
}

/// Terminal-or-live disposition of reconciling one [`StorePermitRecord`]
/// against the current owner.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StoreReconcileDisposition {
    /// The record is current and keeps holding its exact amount.
    HeldCurrent,
    /// A requested release now completes; the amount is not re-held and the
    /// owner persists the transition to [`StorePermitState::Released`].
    ReleaseCompletesNow,
    /// Already released: terminal, no capacity effect, idempotent.
    ReleaseCompletedTerminal,
    /// Never issued: terminal, no capacity effect, idempotent.
    NotIssuedTerminal,
    /// Possibly leaked or unknown: stays reserved (excluded from available
    /// capacity) until the owner supplies a terminal disposition.
    ExcludedLeakSuspect,
    /// The issuing owner is stale: excluded, no counter is touched, until the
    /// current owner reconciles the record.
    StaleOwnerRequiresReconciliation,
}

impl StoreReconcileDisposition {
    /// Returns `true` for dispositions after which no further reconciliation
    /// can change the outcome.
    #[must_use]
    pub const fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::ReleaseCompletedTerminal | Self::NotIssuedTerminal
        )
    }

    /// Returns `true` when the disposition keeps the exact amount reserved
    /// (excluded from available capacity), including the unknown/leak-suspect
    /// case that must never be silently freed.
    #[must_use]
    pub const fn keeps_reserved(self) -> bool {
        matches!(self, Self::HeldCurrent | Self::ExcludedLeakSuspect)
    }
}

/// Persistable owner evidence for one permit's capacity ownership.
///
/// This is the record the durable owner (ControlWal/redb, later wave)
/// persists across awaits, process boundaries and restarts. It carries every
/// binding the issue demands so the owner can distinguish the six
/// [`StorePermitState`] positions without trusting a live process, a PID, a
/// queue entry or a surviving counter.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StorePermitRecord {
    /// Owner-issued permit identity.
    pub permit_id: String,
    /// Operation identity the permit was granted for.
    pub operation_id: String,
    /// Requesting owner label.
    pub owner: String,
    /// Which Store dimension holds the amount.
    pub dimension: StoreDimension,
    /// Which partition holds the amount.
    pub class: CapacityClass,
    /// Exact amount held in the bottleneck's unit.
    pub amount: u64,
    /// Contract operation label at issue.
    pub operation_label: String,
    /// Issuing Store bridge generation at issue.
    pub owner_generation: Uuid,
    /// Requesting owner's generation at issue.
    pub requester_generation: Uuid,
    /// Profile revision at issue.
    pub profile_revision: String,
    /// Caller-observed issue time (Unix millis).
    pub issued_at_ms: i64,
    /// Caller-observed expiry (Unix millis), if the grant expires.
    pub expires_at_ms: Option<i64>,
    /// Current lifecycle state of this ownership.
    pub state: StorePermitState,
}

impl StorePermitRecord {
    /// Classifies this record against the current owner without touching any
    /// partition counter: a pure classifier for the durable reconcile loop.
    ///
    /// Released and never-issued records are terminal and idempotent.
    /// Records from a moved bridge generation or a moved profile revision are
    /// stale: they stay excluded and no counter is touched. Unknown or
    /// leak-suspected records stay reserved (excluded) rather than freed.
    #[must_use]
    pub fn reconcile(
        &self,
        current_owner_generation: Uuid,
        current_profile_revision: &str,
    ) -> StoreReconcileDisposition {
        match self.state {
            StorePermitState::Released => StoreReconcileDisposition::ReleaseCompletedTerminal,
            StorePermitState::NotIssued => StoreReconcileDisposition::NotIssuedTerminal,
            StorePermitState::PossiblyLeakedUnknown => {
                StoreReconcileDisposition::ExcludedLeakSuspect
            }
            StorePermitState::IssuedHeld
            | StorePermitState::ReleaseRequested
            | StorePermitState::StaleOwnerRequiringReconciliation => {
                if self.owner_generation != current_owner_generation
                    || self.profile_revision != current_profile_revision
                {
                    StoreReconcileDisposition::StaleOwnerRequiresReconciliation
                } else if matches!(self.state, StorePermitState::ReleaseRequested) {
                    StoreReconcileDisposition::ReleaseCompletesNow
                } else {
                    StoreReconcileDisposition::HeldCurrent
                }
            }
        }
    }
}

/// Exactly-once release evidence for one [`StorePermit`].
///
/// Bound to permit identity, dimension, class, operation label/identity,
/// owner and issuing bridge generation: a replayed or relabelled release
/// does not match and is refused before any counter moves.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StoreReleaseEvidence {
    permit_id: String,
    dimension: StoreDimension,
    class: CapacityClass,
    operation_label: String,
    operation_id: String,
    owner: String,
    owner_generation: Uuid,
}

impl StoreReleaseEvidence {
    /// Returns the released permit identity.
    #[must_use]
    pub fn permit_id(&self) -> &str {
        &self.permit_id
    }

    /// Returns the dimension the released amount returns to.
    #[must_use]
    pub const fn dimension(&self) -> StoreDimension {
        self.dimension
    }

    /// Returns the partition the released amount returns to.
    #[must_use]
    pub const fn class(&self) -> CapacityClass {
        self.class
    }

    /// Returns the contract operation label recorded at issue.
    #[must_use]
    pub fn operation_label(&self) -> &str {
        &self.operation_label
    }

    /// Returns the operation identity recorded at issue.
    #[must_use]
    pub fn operation_id(&self) -> &str {
        &self.operation_id
    }

    /// Returns the owner recorded at issue.
    #[must_use]
    pub fn owner(&self) -> &str {
        &self.owner
    }

    /// Returns the issuing bridge generation recorded at issue.
    #[must_use]
    pub const fn owner_generation(&self) -> Uuid {
        self.owner_generation
    }

    /// Returns `true` only when every binding matches the live permit:
    /// same permit and operation identities, same owner, same issuing
    /// generation, same dimension and class. Changed content never matches.
    #[must_use]
    pub fn matches_permit(&self, permit: &StorePermit) -> bool {
        self.permit_id == permit.permit_id
            && self.operation_id == permit.operation_id
            && self.owner == permit.owner
            && self.owner_generation == permit.owner_generation
            && self.dimension == permit.dimension
            && self.class == permit.class
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
/// saturating normal connections, transactions or pending-write bytes leaves
/// the full protected capacity available for admitted
/// cancellation/recovery/fencing records and vice versa. Acquisition is
/// non-blocking and atomic; release is explicit and exactly-once via
/// [`StorePermit::release`], with drop as the backstop returning exactly the
/// consumed partition and amount.
#[derive(Clone, Debug)]
pub struct StoreReserve {
    inner: Arc<StoreReserveInner>,
}

/// One held Store capacity permit, bound to dimension, class, operation,
/// owner, bridge generation, profile revision and epoch-indirect evidence.
///
/// Permits are deliberately not [`Clone`]: duplicating a permit handle must
/// never duplicate the underlying capacity.
#[derive(Debug)]
pub struct StorePermit {
    slot: Option<Arc<StoreReserveInner>>,
    dimension: StoreDimension,
    class: CapacityClass,
    amount: u64,
    operation: StorePermitOperation,
    permit_id: String,
    operation_id: String,
    owner: String,
    owner_generation: Uuid,
    requester_generation: Uuid,
    profile_revision: String,
    issued_at_ms: i64,
    expires_at_ms: Option<i64>,
    release_requested: bool,
    owner_evidence: String,
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

    /// Returns the exact unit of the bottleneck this permit was granted from.
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
    pub const fn operation(&self) -> StorePermitOperation {
        self.operation
    }

    /// Returns the owner-issued permit identity.
    #[must_use]
    pub fn permit_id(&self) -> &str {
        &self.permit_id
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

    /// Returns the issuing Store bridge generation recorded at issue.
    #[must_use]
    pub const fn owner_generation(&self) -> Uuid {
        self.owner_generation
    }

    /// Returns the requesting owner's generation recorded at issue.
    #[must_use]
    pub const fn requester_generation(&self) -> Uuid {
        self.requester_generation
    }

    /// Returns the profile revision recorded at issue.
    #[must_use]
    pub fn profile_revision(&self) -> &str {
        &self.profile_revision
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

    /// Returns `true` only when every presented binding matches the recorded
    /// evidence: same operation identity, same owner, same issuing bridge
    /// generation and same profile revision. Changed content never matches.
    #[must_use]
    pub fn binding_matches(
        &self,
        operation_id: &str,
        owner: &str,
        owner_generation: Uuid,
        profile_revision: &str,
    ) -> bool {
        self.operation_id == operation_id
            && self.owner == owner
            && self.owner_generation == owner_generation
            && self.profile_revision == profile_revision
    }

    /// Returns whether release was requested but not yet completed.
    #[must_use]
    pub const fn is_release_requested(&self) -> bool {
        self.release_requested
    }

    /// Marks release-requested while still holding the amount.
    ///
    /// The permit keeps holding its partition until [`Self::release`]
    /// completes the exactly-once release or drop returns it; the flag only
    /// moves the [`StorePermitRecord`] snapshot from issued/held to
    /// release-requested for the durable reconcile loop.
    pub fn request_release(&mut self) {
        self.release_requested = true;
    }

    /// Releases the held amount exactly once, returning bound evidence.
    ///
    /// The first call returns the amount to its exact partition and yields
    /// the [`StoreReleaseEvidence`]; consuming `self` makes a second release
    /// a compile-time impossibility through this path, and a permit whose
    /// slot is already gone (taken by an earlier release) fails closed with
    /// [`StoreReserveError::AlreadyReleased`] instead of moving a counter.
    ///
    /// # Errors
    ///
    /// Returns [`StoreReserveError::AlreadyReleased`] when the slot is
    /// already gone.
    pub fn release(mut self) -> Result<StoreReleaseEvidence, StoreReserveError> {
        let Some(slot) = self.slot.take() else {
            return Err(StoreReserveError::AlreadyReleased {
                permit_id: self.permit_id.clone(),
            });
        };
        let (counter, _) = select_slot(&slot, self.dimension, self.class);
        debug_assert!(
            counter.load(Ordering::Acquire) >= self.amount,
            "Store permit release without a held partition amount"
        );
        counter.fetch_sub(self.amount, Ordering::AcqRel);
        Ok(StoreReleaseEvidence {
            permit_id: self.permit_id.clone(),
            dimension: self.dimension,
            class: self.class,
            operation_label: self.operation.contract_label().to_owned(),
            operation_id: self.operation_id.clone(),
            owner: self.owner.clone(),
            owner_generation: self.owner_generation,
        })
    }

    /// Snapshots the persistable owner evidence for this permit.
    ///
    /// A live permit snapshots as issued/held, or as release-requested after
    /// [`Self::request_release`]. The durable owner persists the record and
    /// drives [`StorePermitRecord::reconcile`]; a released permit has no
    /// record because `release` consumes it.
    #[must_use]
    pub fn to_record(&self) -> StorePermitRecord {
        StorePermitRecord {
            permit_id: self.permit_id.clone(),
            operation_id: self.operation_id.clone(),
            owner: self.owner.clone(),
            dimension: self.dimension,
            class: self.class,
            amount: self.amount,
            operation_label: self.operation.contract_label().to_owned(),
            owner_generation: self.owner_generation,
            requester_generation: self.requester_generation,
            profile_revision: self.profile_revision.clone(),
            issued_at_ms: self.issued_at_ms,
            expires_at_ms: self.expires_at_ms,
            state: if self.release_requested {
                StorePermitState::ReleaseRequested
            } else {
                StorePermitState::IssuedHeld
            },
        }
    }
}

impl Drop for StorePermit {
    fn drop(&mut self) {
        if let Some(slot) = self.slot.take() {
            let (counter, _) = select_slot(&slot, self.dimension, self.class);
            debug_assert!(
                counter.load(Ordering::Acquire) >= self.amount,
                "Store permit drop without a held partition amount"
            );
            counter.fetch_sub(self.amount, Ordering::AcqRel);
        }
    }
}

/// Selects the live in-flight counter and its partition capacity for one
/// dimension/class cell. Single selector for acquire, release, drop and
/// restart re-hold paths so no path can address the wrong partition.
fn select_slot(
    inner: &StoreReserveInner,
    dimension: StoreDimension,
    class: CapacityClass,
) -> (&AtomicU64, u64) {
    match (dimension, class) {
        (StoreDimension::ConnectionSlots, CapacityClass::NormalWorkload) => (
            &inner.connection_normal_in_flight,
            inner.connection_normal_capacity,
        ),
        (StoreDimension::ConnectionSlots, _) => (
            &inner.connection_protected_in_flight,
            inner.connection_protected_capacity,
        ),
        (StoreDimension::TransactionSlots, CapacityClass::NormalWorkload) => (
            &inner.transaction_normal_in_flight,
            inner.transaction_normal_capacity,
        ),
        (StoreDimension::TransactionSlots, _) => (
            &inner.transaction_protected_in_flight,
            inner.transaction_protected_capacity,
        ),
        (StoreDimension::PendingWriteMemory, CapacityClass::NormalWorkload) => (
            &inner.pending_normal_in_flight_bytes,
            inner.pending_normal_capacity_bytes,
        ),
        (StoreDimension::PendingWriteMemory, _) => (
            &inner.pending_protected_in_flight_bytes,
            inner.pending_protected_capacity_bytes,
        ),
    }
}

/// Atomically adds `amount` to `slot` unless `capacity` would be exceeded.
/// Same compare-exchange discipline as the ORS slice: one partition, one
/// counter, no global lock.
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

/// Validates one identity label with the same bounded non-blank rule the ORS
/// owner enforces (non-blank, no control characters, at most 1024 UTF-8
/// bytes). Local copy because this crate has no edge to the ORS validator;
/// the rule text is identical by construction, not a second scheme.
fn validate_label(value: &str, field: &'static str) -> Result<(), StoreReserveError> {
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

/// Disjoint partition capacities and live availability for one claimed row.
///
/// Bundles the four `u64` cells [`StoreReserve::publish_claimed_rows`]
/// reports per dimension so the private row builder stays within the argument
/// limit; every value keeps its exact meaning (partition totals and live
/// available amounts, never a shared pool).
struct ClaimedCapacities {
    normal_capacity: u64,
    protected_capacity: u64,
    normal_available: u64,
    protected_available: u64,
}

impl StoreReserve {
    /// Validates the caller-presented bindings before any partition counter
    /// is touched. Nil generations are refused: a bridge generation is a live
    /// [`crate::db_client_set::DbClientSet`] identity, never zero.
    fn checked_request(request: &StorePermitRequest<'_>) -> Result<(), StoreReserveError> {
        validate_label(request.owner, "store_permit.owner")?;
        validate_label(request.operation_id, "store_permit.operation_id")?;
        validate_label(request.permit_id, "store_permit.permit_id")?;
        validate_label(request.profile_revision, "store_permit.profile_revision")?;
        if request.owner_generation.is_nil() {
            return Err(StoreReserveError::InvalidField {
                field: "store_permit.owner_generation",
                reason: "must be a live bridge generation, never nil",
            });
        }
        if request.requester_generation.is_nil() {
            return Err(StoreReserveError::InvalidField {
                field: "store_permit.requester_generation",
                reason: "must be a live generation, never nil",
            });
        }
        if let Some(expires_at_ms) = request.expires_at_ms
            && expires_at_ms <= request.issued_at_ms
        {
            return Err(StoreReserveError::InvalidField {
                field: "store_permit.expires_at_ms",
                reason: "must be after issued_at_ms",
            });
        }
        Ok(())
    }

    /// Issues the owner-bound permit after the partition counter was claimed.
    /// The evidence reference is derived by the owner from the claimed cell
    /// and the recorded bindings; callers cannot supply it.
    fn issue_permit(
        inner: Arc<StoreReserveInner>,
        dimension: StoreDimension,
        class: CapacityClass,
        amount: u64,
        operation: StorePermitOperation,
        request: &StorePermitRequest<'_>,
    ) -> StorePermit {
        let owner_evidence = format!(
            "store-reserve/{:?}/{:?}/bridge-gen-{}/req-gen-{}/amt-{amount}",
            dimension.bottleneck(),
            class,
            request.owner_generation,
            request.requester_generation,
        );
        StorePermit {
            slot: Some(inner),
            dimension,
            class,
            amount,
            operation,
            permit_id: request.permit_id.to_owned(),
            operation_id: request.operation_id.to_owned(),
            owner: request.owner.to_owned(),
            owner_generation: request.owner_generation,
            requester_generation: request.requester_generation,
            profile_revision: request.profile_revision.to_owned(),
            issued_at_ms: request.issued_at_ms,
            expires_at_ms: request.expires_at_ms,
            release_requested: false,
            owner_evidence,
        }
    }

    /// Creates a Store reserve with disjoint normal and protected partitions
    /// for all three Store dimensions.
    ///
    /// Normal work draws only from the normal cells; admitted
    /// cancellation/recovery/fencing draws only from the protected cells.
    /// Neither class can borrow from the other, and no emergency cell exists
    /// in this slice.
    ///
    /// # Errors
    ///
    /// Returns [`StoreReserveError::InvalidField`] when any slot partition
    /// capacity is zero.
    pub fn partitioned(
        normal_connection_slots: u64,
        protected_connection_slots: u64,
        normal_transaction_slots: u64,
        protected_transaction_slots: u64,
        normal_pending_write_bytes: NonZeroU64,
        protected_pending_write_bytes: NonZeroU64,
    ) -> Result<Self, StoreReserveError> {
        for (value, field) in [
            (
                normal_connection_slots,
                "store_reserve.normal_connection_slots",
            ),
            (
                protected_connection_slots,
                "store_reserve.protected_connection_slots",
            ),
            (
                normal_transaction_slots,
                "store_reserve.normal_transaction_slots",
            ),
            (
                protected_transaction_slots,
                "store_reserve.protected_transaction_slots",
            ),
        ] {
            if value == 0 {
                return Err(StoreReserveError::InvalidField {
                    field,
                    reason: "must be greater than zero",
                });
            }
        }
        Ok(Self {
            inner: Arc::new(StoreReserveInner {
                connection_normal_capacity: normal_connection_slots,
                connection_protected_capacity: protected_connection_slots,
                transaction_normal_capacity: normal_transaction_slots,
                transaction_protected_capacity: protected_transaction_slots,
                pending_normal_capacity_bytes: normal_pending_write_bytes.get(),
                pending_protected_capacity_bytes: protected_pending_write_bytes.get(),
                connection_normal_in_flight: AtomicU64::new(0),
                connection_protected_in_flight: AtomicU64::new(0),
                transaction_normal_in_flight: AtomicU64::new(0),
                transaction_protected_in_flight: AtomicU64::new(0),
                pending_normal_in_flight_bytes: AtomicU64::new(0),
                pending_protected_in_flight_bytes: AtomicU64::new(0),
            }),
        })
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
    /// Returns [`StoreReserveError::InvalidField`] for malformed bindings, or
    /// [`StoreReserveError::NormalCapacityExhausted`] naming the connection
    /// bottleneck and shed work when the normal partition is saturated. The
    /// protected partition is untouched in every case.
    pub fn try_acquire_normal_connection(
        &self,
        work: NormalWorkClass,
        request: StorePermitRequest<'_>,
    ) -> Result<StorePermit, StoreReserveError> {
        Self::checked_request(&request)?;
        let (slot, capacity) = select_slot(
            &self.inner,
            StoreDimension::ConnectionSlots,
            CapacityClass::NormalWorkload,
        );
        if !cas_add(slot, capacity, 1) {
            return Err(StoreReserveError::NormalCapacityExhausted {
                bottleneck: STORE_CONNECTION_BOTTLENECK,
                work_class: work,
                operation_id: request.operation_id.to_owned(),
                owner: request.owner.to_owned(),
                owner_generation: request.owner_generation,
            });
        }
        Ok(Self::issue_permit(
            self.inner.clone(),
            StoreDimension::ConnectionSlots,
            CapacityClass::NormalWorkload,
            1,
            StorePermitOperation::Normal(work),
            &request,
        ))
    }

    /// Attempts to acquire one normal transaction slot without blocking.
    ///
    /// Only [`NormalWorkClass`] operations typecheck here.
    ///
    /// # Errors
    ///
    /// Returns [`StoreReserveError::InvalidField`] for malformed bindings, or
    /// [`StoreReserveError::NormalCapacityExhausted`] naming the transaction
    /// bottleneck and shed work when the normal partition is saturated. The
    /// protected partition is untouched in every case.
    pub fn try_acquire_normal_transaction(
        &self,
        work: NormalWorkClass,
        request: StorePermitRequest<'_>,
    ) -> Result<StorePermit, StoreReserveError> {
        Self::checked_request(&request)?;
        let (slot, capacity) = select_slot(
            &self.inner,
            StoreDimension::TransactionSlots,
            CapacityClass::NormalWorkload,
        );
        if !cas_add(slot, capacity, 1) {
            return Err(StoreReserveError::NormalCapacityExhausted {
                bottleneck: STORE_TRANSACTION_BOTTLENECK,
                work_class: work,
                operation_id: request.operation_id.to_owned(),
                owner: request.owner.to_owned(),
                owner_generation: request.owner_generation,
            });
        }
        Ok(Self::issue_permit(
            self.inner.clone(),
            StoreDimension::TransactionSlots,
            CapacityClass::NormalWorkload,
            1,
            StorePermitOperation::Normal(work),
            &request,
        ))
    }

    /// Attempts to acquire `bytes` normal pending-write bytes without blocking.
    ///
    /// Only [`NormalWorkClass`] operations typecheck here.
    ///
    /// # Errors
    ///
    /// Returns [`StoreReserveError::InvalidField`] for malformed bindings, or
    /// [`StoreReserveError::NormalCapacityExhausted`] naming the
    /// pending-write bottleneck and shed work when the normal partition
    /// cannot satisfy the request. The protected partition is untouched in
    /// every case.
    pub fn try_acquire_normal_pending_bytes(
        &self,
        work: NormalWorkClass,
        request: StorePermitRequest<'_>,
        bytes: NonZeroU64,
    ) -> Result<StorePermit, StoreReserveError> {
        Self::checked_request(&request)?;
        let (slot, capacity) = select_slot(
            &self.inner,
            StoreDimension::PendingWriteMemory,
            CapacityClass::NormalWorkload,
        );
        if !cas_add(slot, capacity, bytes.get()) {
            return Err(StoreReserveError::NormalCapacityExhausted {
                bottleneck: STORE_PENDING_WRITE_BOTTLENECK,
                work_class: work,
                operation_id: request.operation_id.to_owned(),
                owner: request.owner.to_owned(),
                owner_generation: request.owner_generation,
            });
        }
        Ok(Self::issue_permit(
            self.inner.clone(),
            StoreDimension::PendingWriteMemory,
            CapacityClass::NormalWorkload,
            bytes.get(),
            StorePermitOperation::Normal(work),
            &request,
        ))
    }

    /// Attempts to acquire one protected connection slot without blocking.
    ///
    /// Only [`ControlOperationClass`] operations typecheck here: a normal
    /// Store write, named read, agent, model, swarm, report or maintenance
    /// admission cannot name a protected operation and therefore cannot reach
    /// this partition by relabelling priority or class.
    ///
    /// # Errors
    ///
    /// Returns [`StoreReserveError::InvalidField`] for malformed bindings, or
    /// [`StoreReserveError::ProtectedReserveExhausted`] naming the connection
    /// bottleneck, operation, owner and bridge generation when the protected
    /// partition is saturated.
    pub fn try_acquire_protected_connection(
        &self,
        operation: ControlOperationClass,
        request: StorePermitRequest<'_>,
    ) -> Result<StorePermit, StoreReserveError> {
        Self::checked_request(&request)?;
        let (slot, capacity) = select_slot(
            &self.inner,
            StoreDimension::ConnectionSlots,
            CapacityClass::ProtectedControl,
        );
        if !cas_add(slot, capacity, 1) {
            return Err(StoreReserveError::ProtectedReserveExhausted {
                bottleneck: STORE_CONNECTION_BOTTLENECK,
                operation,
                operation_id: request.operation_id.to_owned(),
                owner: request.owner.to_owned(),
                owner_generation: request.owner_generation,
            });
        }
        Ok(Self::issue_permit(
            self.inner.clone(),
            StoreDimension::ConnectionSlots,
            CapacityClass::ProtectedControl,
            1,
            StorePermitOperation::Protected(operation),
            &request,
        ))
    }

    /// Attempts to acquire one protected transaction slot without blocking.
    ///
    /// Only [`ControlOperationClass`] operations typecheck here; relabelling
    /// cannot promote normal work into this partition.
    ///
    /// # Errors
    ///
    /// Returns [`StoreReserveError::InvalidField`] for malformed bindings, or
    /// [`StoreReserveError::ProtectedReserveExhausted`] naming the
    /// transaction bottleneck, operation, owner and bridge generation when
    /// the protected partition is saturated.
    pub fn try_acquire_protected_transaction(
        &self,
        operation: ControlOperationClass,
        request: StorePermitRequest<'_>,
    ) -> Result<StorePermit, StoreReserveError> {
        Self::checked_request(&request)?;
        let (slot, capacity) = select_slot(
            &self.inner,
            StoreDimension::TransactionSlots,
            CapacityClass::ProtectedControl,
        );
        if !cas_add(slot, capacity, 1) {
            return Err(StoreReserveError::ProtectedReserveExhausted {
                bottleneck: STORE_TRANSACTION_BOTTLENECK,
                operation,
                operation_id: request.operation_id.to_owned(),
                owner: request.owner.to_owned(),
                owner_generation: request.owner_generation,
            });
        }
        Ok(Self::issue_permit(
            self.inner.clone(),
            StoreDimension::TransactionSlots,
            CapacityClass::ProtectedControl,
            1,
            StorePermitOperation::Protected(operation),
            &request,
        ))
    }

    /// Attempts to acquire `bytes` protected pending-write bytes without blocking.
    ///
    /// Only [`ControlOperationClass`] operations typecheck here; relabelling
    /// cannot promote normal work into this partition.
    ///
    /// # Errors
    ///
    /// Returns [`StoreReserveError::InvalidField`] for malformed bindings, or
    /// [`StoreReserveError::ProtectedReserveExhausted`] naming the
    /// pending-write bottleneck, operation, owner and bridge generation when
    /// the protected partition cannot satisfy the request.
    pub fn try_acquire_protected_pending_bytes(
        &self,
        operation: ControlOperationClass,
        request: StorePermitRequest<'_>,
        bytes: NonZeroU64,
    ) -> Result<StorePermit, StoreReserveError> {
        Self::checked_request(&request)?;
        let (slot, capacity) = select_slot(
            &self.inner,
            StoreDimension::PendingWriteMemory,
            CapacityClass::ProtectedControl,
        );
        if !cas_add(slot, capacity, bytes.get()) {
            return Err(StoreReserveError::ProtectedReserveExhausted {
                bottleneck: STORE_PENDING_WRITE_BOTTLENECK,
                operation,
                operation_id: request.operation_id.to_owned(),
                owner: request.owner.to_owned(),
                owner_generation: request.owner_generation,
            });
        }
        Ok(Self::issue_permit(
            self.inner.clone(),
            StoreDimension::PendingWriteMemory,
            CapacityClass::ProtectedControl,
            bytes.get(),
            StorePermitOperation::Protected(operation),
            &request,
        ))
    }

    /// Re-applies one persisted record after a restart without resetting held
    /// capacity.
    ///
    /// The boot-time reconcile loop calls this for every durable record
    /// before the reserve admits new work. Records that reconcile to a
    /// reserving disposition ([`StoreReconcileDisposition::keeps_reserved`])
    /// re-claim their exact amount in their exact cell, so unknown and
    /// leak-suspected ownership stays excluded from available capacity.
    /// Terminal and stale records claim nothing: released work is not
    /// re-held, and a moved bridge generation or profile revision never
    /// restores capacity by resetting a local counter.
    ///
    /// # Errors
    ///
    /// Returns [`StoreReserveError::RestartReconcileContradiction`] when a
    /// reserving record no longer fits its cell: the restart state
    /// contradicts live accounting and the loop must fail closed, never
    /// silently substitute a smaller hold.
    pub fn apply_restarted_hold(
        &self,
        record: &StorePermitRecord,
        current_owner_generation: Uuid,
        current_profile_revision: &str,
    ) -> Result<StoreReconcileDisposition, StoreReserveError> {
        let disposition = record.reconcile(current_owner_generation, current_profile_revision);
        if disposition.keeps_reserved() && record.amount > 0 {
            let (slot, capacity) = select_slot(&self.inner, record.dimension, record.class);
            if !cas_add(slot, capacity, record.amount) {
                return Err(StoreReserveError::RestartReconcileContradiction {
                    permit_id: record.permit_id.clone(),
                    detail: "persisted hold no longer fits its partition cell".to_owned(),
                });
            }
        }
        Ok(disposition)
    }

    /// Publishes the three `CLAIMED` owner-evidence rows for the Kernel
    /// profile composition join (issue #1679, W3 Store wave).
    ///
    /// One row per Store bottleneck in frozen contract order (connection,
    /// transaction, pending-write memory). Each row names the owner verbatim
    /// from the existing [`frozen_bottleneck_owner_map`] binding for its
    /// exact dimension (never a second owner string), the composition-supplied
    /// bridge-generation reference, the exact bottleneck unit, the physical
    /// total (the disjoint normal plus protected partition enforced here),
    /// both disjoint partitions, [`CapacityEnforcement::PhysicalPartition`]
    /// (normal acquisition paths never address the protected counters and
    /// vice versa; there is no shared pool to borrow from) and no emergency
    /// partition. The evidence reference is owner-derived current evidence:
    /// the live available amount of each partition at publication time.
    /// The invalidation set names the two owner-known invalidation
    /// conditions: a bridge-generation move and a partition-config change.
    /// Every row passes the existing
    /// [`BottleneckCapacityProfile::validate`] before it is returned, so an
    /// inconsistent row fails closed here instead of reaching the composer.
    ///
    /// Completeness is checked against the independent frozen map, not
    /// against these rows: publication fails closed unless the frozen map
    /// binds exactly the three Store bottlenecks to the same owner this
    /// reserve publishes under. A fourth Store-owned dimension, or a moved
    /// Store owner, is a contradiction, never a silently under-claimed
    /// profile.
    ///
    /// # Errors
    ///
    /// Returns [`StoreReserveError::InvalidField`] for a blank or malformed
    /// `owner_generation_ref` or `proof_profile_ref`, when the frozen map no
    /// longer binds a Store bottleneck to one shared Store owner, or when a
    /// partition sum overflows; returns [`StoreReserveError::Contract`] when
    /// an assembled row fails the existing contract validation.
    pub fn publish_claimed_rows(
        &self,
        owner_generation_ref: &str,
        proof_profile_ref: &str,
    ) -> Result<[BottleneckCapacityProfile; 3], StoreReserveError> {
        validate_label(owner_generation_ref, "store_reserve.owner_generation_ref")?;
        validate_label(proof_profile_ref, "store_reserve.proof_profile_ref")?;
        let owner = frozen_store_owner()?;
        let rows = [
            Self::claimed_row(
                StoreDimension::ConnectionSlots,
                owner,
                owner_generation_ref,
                proof_profile_ref,
                ClaimedCapacities {
                    normal_capacity: self.inner.connection_normal_capacity,
                    protected_capacity: self.inner.connection_protected_capacity,
                    normal_available: self.available_normal_connections(),
                    protected_available: self.available_protected_connections(),
                },
            )?,
            Self::claimed_row(
                StoreDimension::TransactionSlots,
                owner,
                owner_generation_ref,
                proof_profile_ref,
                ClaimedCapacities {
                    normal_capacity: self.inner.transaction_normal_capacity,
                    protected_capacity: self.inner.transaction_protected_capacity,
                    normal_available: self.available_normal_transactions(),
                    protected_available: self.available_protected_transactions(),
                },
            )?,
            Self::claimed_row(
                StoreDimension::PendingWriteMemory,
                owner,
                owner_generation_ref,
                proof_profile_ref,
                ClaimedCapacities {
                    normal_capacity: self.inner.pending_normal_capacity_bytes,
                    protected_capacity: self.inner.pending_protected_capacity_bytes,
                    normal_available: self.available_normal_pending_bytes(),
                    protected_available: self.available_protected_pending_bytes(),
                },
            )?,
        ];
        Ok(rows)
    }

    /// Builds the single `CLAIMED` row for one Store dimension and validates
    /// it with the existing contract check.
    fn claimed_row(
        dimension: StoreDimension,
        owner: &'static str,
        owner_generation_ref: &str,
        proof_profile_ref: &str,
        capacities: ClaimedCapacities,
    ) -> Result<BottleneckCapacityProfile, StoreReserveError> {
        let bottleneck = dimension.bottleneck();
        let unit = bottleneck.unit();
        let normal_quantity = NonZeroU64::new(capacities.normal_capacity)
            .ok_or(StoreReserveError::InvalidField {
                field: "store_reserve.normal_limit",
                reason: "the normal partition of a claimed row is positive",
            })?;
        let protected_quantity = NonZeroU64::new(capacities.protected_capacity)
            .ok_or(StoreReserveError::InvalidField {
                field: "store_reserve.protected_limit",
                reason: "the protected partition of a claimed row is positive",
            })?;
        let physical_total = capacities
            .normal_capacity
            .checked_add(capacities.protected_capacity)
            .and_then(NonZeroU64::new)
            .ok_or(StoreReserveError::InvalidField {
                field: "store_reserve.physical_total_limit",
                reason: "CAPACITY_SUM_OVERFLOW: the disjoint partition sum is positive and representable",
            })?;
        let row = BottleneckCapacityProfile {
            bottleneck,
            coverage_state: BottleneckCoverageState::Claimed,
            owner_ref: owner.to_owned(),
            owner_generation_ref: owner_generation_ref.to_owned(),
            unit,
            physical_total_limit: Some(CapacityLimit {
                unit,
                quantity: physical_total,
            }),
            normal_work_applicable: true,
            normal_limit: Some(CapacityLimit {
                unit,
                quantity: normal_quantity,
            }),
            protected_limit: Some(CapacityLimit {
                unit,
                quantity: protected_quantity,
            }),
            emergency_limit: None,
            enforcement: Some(CapacityEnforcement::PhysicalPartition),
            proof_profile_ref: proof_profile_ref.to_owned(),
            evidence_refs: vec![format!(
                "store-reserve/{}/bridge-gen-{owner_generation_ref}/normal-avail-{}/protected-avail-{}",
                bottleneck.as_contract_str(),
                capacities.normal_available,
                capacities.protected_available,
            )],
            invalidation_set: vec![
                "store-reserve/bridge-generation-change".to_owned(),
                "store-reserve/partition-config-change".to_owned(),
            ],
        };
        row.validate()
            .map_err(|error| StoreReserveError::Contract(error.to_string()))?;
        Ok(row)
    }
}

/// Resolves the single shared Store owner from the frozen owner map and
/// checks row completeness against that independent set.
///
/// Returns the owner the frozen map binds the connection dimension to, after
/// proving that the transaction and pending-write dimensions bind the same
/// owner and that no fourth frozen dimension binds it. The three
/// [`STORE_CONNECTION_BOTTLENECK`], [`STORE_TRANSACTION_BOTTLENECK`] and
/// [`STORE_PENDING_WRITE_BOTTLENECK`] constants are the claim; the frozen map
/// is the independent denominator they are compared against.
fn frozen_store_owner() -> Result<&'static str, StoreReserveError> {
    fn contradiction(detail: &'static str) -> StoreReserveError {
        StoreReserveError::InvalidField {
            field: "store_reserve.frozen_owner_map",
            reason: detail,
        }
    }
    let owner_map = frozen_bottleneck_owner_map();
    let owner = owner_map
        .iter()
        .find(|bound| bound.bottleneck == STORE_CONNECTION_BOTTLENECK)
        .map(|bound| bound.owner)
        .ok_or_else(|| contradiction("the frozen map binds no Store connection dimension"))?;
    for bottleneck in [STORE_TRANSACTION_BOTTLENECK, STORE_PENDING_WRITE_BOTTLENECK] {
        let bound_owner = owner_map
            .iter()
            .find(|bound| bound.bottleneck == bottleneck)
            .map(|bound| bound.owner)
            .ok_or_else(|| contradiction("the frozen map binds no Store dimension"))?;
        if bound_owner != owner {
            return Err(contradiction(
                "the Store dimensions bind different frozen owners",
            ));
        }
    }
    let owned_count = owner_map
        .iter()
        .filter(|bound| bound.owner == owner)
        .count();
    if owned_count != 3 {
        return Err(contradiction(
            "the frozen map binds a different number of dimensions to the Store owner",
        ));
    }
    Ok(owner)
}

/// One independent [`StoreReserve`] per Store/Ordering Scope or provider
/// path (issue #1679, A6).
///
/// Saturating one scope's normal partition cannot consume another scope's
/// protected control path because scopes share no counter: every scope label
/// resolves to its own [`StoreReserve`] with its own disjoint
/// normal/protected partitions over the same composition-configured sizes.
/// Distinct [`StoreScopeReserves`] instances (for example one per provider
/// path) share nothing either. A scope label names one Store/Ordering Scope
/// or provider path; labels are composition-supplied and validated with the
/// same bounded non-blank rule the owner enforces everywhere, and no label
/// carries a priority or class that could relabel work across partitions.
#[derive(Debug)]
pub struct StoreScopeReserves {
    normal_connection_slots: u64,
    protected_connection_slots: u64,
    normal_transaction_slots: u64,
    protected_transaction_slots: u64,
    normal_pending_write_bytes: NonZeroU64,
    protected_pending_write_bytes: NonZeroU64,
    scopes: Mutex<HashMap<String, StoreReserve>>,
}

impl StoreScopeReserves {
    /// Creates the per-scope holder with one partition size set shared by
    /// every scope admitted through it.
    ///
    /// Sizes are validated once through the existing
    /// [`StoreReserve::partitioned`] constructor; the probe reserve is
    /// discarded and no capacity is held here.
    ///
    /// # Errors
    ///
    /// Returns [`StoreReserveError::InvalidField`] when any slot partition
    /// size is zero.
    pub fn new(
        normal_connection_slots: u64,
        protected_connection_slots: u64,
        normal_transaction_slots: u64,
        protected_transaction_slots: u64,
        normal_pending_write_bytes: NonZeroU64,
        protected_pending_write_bytes: NonZeroU64,
    ) -> Result<Self, StoreReserveError> {
        let _probe = StoreReserve::partitioned(
            normal_connection_slots,
            protected_connection_slots,
            normal_transaction_slots,
            protected_transaction_slots,
            normal_pending_write_bytes,
            protected_pending_write_bytes,
        )?;
        Ok(Self {
            normal_connection_slots,
            protected_connection_slots,
            normal_transaction_slots,
            protected_transaction_slots,
            normal_pending_write_bytes,
            protected_pending_write_bytes,
            scopes: Mutex::new(HashMap::new()),
        })
    }

    /// Returns the reserve for one scope, creating its independent partitions
    /// on first use.
    ///
    /// The returned reserve shares no counter with any other scope's
    /// reserve: saturating this scope leaves every other scope's normal and
    /// protected partitions untouched.
    ///
    /// # Errors
    ///
    /// Returns [`StoreReserveError::InvalidField`] for a blank or malformed
    /// scope label, or [`StoreReserveError::ScopeRegistryUnavailable`] when
    /// the scope registry cannot be locked.
    pub fn reserve_for_scope(&self, scope: &str) -> Result<StoreReserve, StoreReserveError> {
        validate_label(scope, "store_scope.scope")?;
        let mut scopes = self
            .scopes
            .lock()
            .map_err(|_| StoreReserveError::ScopeRegistryUnavailable)?;
        if let Some(reserve) = scopes.get(scope) {
            return Ok(reserve.clone());
        }
        let reserve = StoreReserve::partitioned(
            self.normal_connection_slots,
            self.protected_connection_slots,
            self.normal_transaction_slots,
            self.protected_transaction_slots,
            self.normal_pending_write_bytes,
            self.protected_pending_write_bytes,
        )?;
        scopes.insert(scope.to_owned(), reserve.clone());
        Ok(reserve)
    }
}
