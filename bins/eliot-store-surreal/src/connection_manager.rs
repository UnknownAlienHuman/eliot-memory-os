//! Bounded bridge connection generations for `eliot-store-surreal`.
//!
//! Architecture: A12.3 One governed write path, A13.6 recovery, A13.9
//! concurrency, ARCH-RES-01 bounded closed dispatch.
//! Implementation: I5.7 `WriteCoordinator` and store transaction limit, I5.9
//! bounded store-client generations, I5.19 unknown-outcome receipt
//! reconciliation, I5.20 Q0–Q4 named reads.
//!
//! The bridge keeps a fixed bounded client set per class — named reads,
//! canonical-write transactions, and an isolated health/admin path — instead
//! of growing one connection per request. Each set carries an explicit
//! generation, a per-class deadline, and a bounded reconnect-backoff
//! schedule. A broken generation is replaced explicitly; in-flight leases of
//! the old generation drain while new acquisitions carry the new one.
//! Generations fence clients, never canonical data: the durable state
//! behind the provider stays shared across every replacement — only handle
//! admission is generation-scoped, so a stale client cannot be admitted
//! after cutover while a valid new client reaches the same shared state.
//! A write whose transport outcome is unknown is never replayed blindly: the
//! caller resolves the exact operation identity through `ResolveWriteReceipt`
//! first ([`UnknownWriteGate`]), and the health/admin path admits only its
//! exactly admitted operations ([`HealthAdminAdmission`]).
//!
//! This cell owns bridge-side admission and generation bookkeeping only. It
//! performs no provider I/O, mints no authority, and owns no canonical write
//! path: permits bound concurrent use of the one composed adapter, and
//! receipt classification reads the immutable [`WriteReceipt`] surface.

use std::num::NonZeroUsize;
use std::sync::{Arc, Mutex};

use eliot_store_api::{
    NamedReadOperation, OperationId, Resubmission, StoreError, WriteReceipt, WriteReceiptStatus,
    activated_read_operations,
};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

/// Which bounded client set a bridge operation draws from.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum ClientClass {
    /// Named Q0–Q4 reads under the read semaphore.
    Read,
    /// Canonical transactions under the `WriteCoordinator` limit.
    Write,
    /// Isolated version/schema/backup/health operations.
    Health,
}

impl ClientClass {
    /// Stable identity used in diagnostics only; never a capability.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Read => "read",
            Self::Write => "write",
            Self::Health => "health",
        }
    }
}

/// Fixed bound, deadline, and reconnect schedule for one client set.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ClientSetPolicy {
    /// Maximum concurrent clients in this set; never grows per request.
    pub bound: NonZeroUsize,
    /// Per-operation deadline in milliseconds for this class.
    pub deadline_ms: u64,
    /// Maximum reconnect attempts before the generation is declared broken.
    pub max_reconnect_attempts: u32,
    /// First reconnect delay in milliseconds; doubles per attempt.
    pub base_backoff_ms: u64,
    /// Ceiling for any single reconnect delay in milliseconds.
    pub max_backoff_ms: u64,
}

impl ClientSetPolicy {
    /// Validates that the bound, deadline, and backoff schedule are non-zero
    /// and internally consistent.
    pub fn validate(&self) -> Result<(), String> {
        if self.deadline_ms == 0 {
            return Err("client set deadline_ms must be non-zero".to_owned());
        }
        if self.max_reconnect_attempts == 0 {
            return Err("client set max_reconnect_attempts must be non-zero".to_owned());
        }
        if self.base_backoff_ms == 0 || self.max_backoff_ms == 0 {
            return Err("client set reconnect backoff must be non-zero".to_owned());
        }
        if self.base_backoff_ms > self.max_backoff_ms {
            return Err("client set base_backoff_ms exceeds max_backoff_ms".to_owned());
        }
        Ok(())
    }

    /// Bounded exponential backoff for a 1-based reconnect attempt.
    ///
    /// Attempt 1 waits `base_backoff_ms`; each later attempt doubles,
    /// saturating at `max_backoff_ms`. Attempts past
    /// `max_reconnect_attempts` keep returning the ceiling so callers observe
    /// the bound instead of overflowing.
    #[must_use]
    pub fn backoff_for_attempt(&self, attempt: u32) -> u64 {
        let shift = attempt.saturating_sub(1).min(63);
        self.base_backoff_ms
            .saturating_mul(1u64 << shift)
            .min(self.max_backoff_ms)
    }
}

/// Fixed bounded read/write/health client sets with explicit generations.
///
/// Cloning shares the same underlying sets: every handle drawn from one
/// composition observes one generation lineage per class.
#[derive(Clone, Debug)]
pub struct StoreConnectionManager {
    read: Arc<Semaphore>,
    write: Arc<Semaphore>,
    health: Arc<Semaphore>,
    policies: ConnectionPolicies,
    state: Arc<Mutex<ManagerState>>,
}

/// Per-class policies bound at composition time.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ConnectionPolicies {
    pub read: ClientSetPolicy,
    pub write: ClientSetPolicy,
    pub health: ClientSetPolicy,
}

#[derive(Debug)]
struct ManagerState {
    read_generation: u64,
    write_generation: u64,
    health_generation: u64,
    read_broken: bool,
    write_broken: bool,
    health_broken: bool,
    read_reconnect_attempts: u32,
    write_reconnect_attempts: u32,
    health_reconnect_attempts: u32,
    read_issued_high_water: u64,
    write_issued_high_water: u64,
    health_issued_high_water: u64,
}

/// I5.7 desktop default for the Kernel's configured store transaction limit:
///
/// ```text
/// writer_executors = min(4, logical_cpu_count)
/// store_transaction_limit = writer_executors
/// ```
///
/// This is the composition default used when the launch descriptor carries
/// no narrower explicit limit. Raising it cannot weaken ordering, ORS
/// capacity, Control Reserve, or receipt reconciliation.
#[must_use]
pub fn default_store_transaction_limit() -> NonZeroUsize {
    const DESKTOP_EXECUTOR_CEILING: usize = 4;
    let logical = std::thread::available_parallelism().map_or(1, NonZeroUsize::get);
    match NonZeroUsize::new(logical.clamp(1, DESKTOP_EXECUTOR_CEILING)) {
        Some(limit) => limit,
        // Unreachable by construction: the clamp floor is 1. The fallback
        // keeps the loosest safe lane instead of panicking.
        None => NonZeroUsize::MIN,
    }
}

/// Fixed bounded read pool for named Q0–Q4 reads.
///
/// Reads never reserve Ordering Scopes, so the read pool is wider than the
/// write lane bound while still fixed: repeated concurrent reads reuse these
/// slots instead of growing connections per request.
pub const DEFAULT_READ_CLIENTS: usize = 8;

/// The health/admin path is exactly one isolated client: health traffic must
/// never queue behind, or consume, a canonical write slot.
pub const DEFAULT_HEALTH_CLIENTS: usize = 1;

impl StoreConnectionManager {
    /// Builds the three bounded sets from explicit per-class policies.
    pub fn new(policies: ConnectionPolicies) -> Result<Self, String> {
        policies.read.validate()?;
        policies.write.validate()?;
        policies.health.validate()?;
        Ok(Self {
            read: Arc::new(Semaphore::new(policies.read.bound.get())),
            write: Arc::new(Semaphore::new(policies.write.bound.get())),
            health: Arc::new(Semaphore::new(policies.health.bound.get())),
            policies,
            state: Arc::new(Mutex::new(ManagerState {
                read_generation: 1,
                write_generation: 1,
                health_generation: 1,
                read_broken: false,
                write_broken: false,
                health_broken: false,
                read_reconnect_attempts: 0,
                write_reconnect_attempts: 0,
                health_reconnect_attempts: 0,
                read_issued_high_water: 0,
                write_issued_high_water: 0,
                health_issued_high_water: 0,
            })),
        })
    }

    /// Builds the manager from the validated launch timeouts:
    /// read/write deadlines follow `query_timeout_ms`, the health deadline
    /// follows `connect_timeout_ms`, and write concurrency is bound to the
    /// Kernel's configured store transaction limit.
    pub fn from_timeouts(
        read_bound: NonZeroUsize,
        store_transaction_limit: NonZeroUsize,
        connect_timeout_ms: u64,
        query_timeout_ms: u64,
    ) -> Result<Self, String> {
        let health_bound = NonZeroUsize::new(DEFAULT_HEALTH_CLIENTS)
            .ok_or_else(|| "health client bound must be non-zero".to_owned())?;
        Self::new(ConnectionPolicies {
            read: ClientSetPolicy {
                bound: read_bound,
                deadline_ms: query_timeout_ms,
                max_reconnect_attempts: 3,
                base_backoff_ms: 100,
                max_backoff_ms: 5_000,
            },
            write: ClientSetPolicy {
                bound: store_transaction_limit,
                deadline_ms: query_timeout_ms,
                max_reconnect_attempts: 3,
                base_backoff_ms: 100,
                max_backoff_ms: 5_000,
            },
            health: ClientSetPolicy {
                bound: health_bound,
                deadline_ms: connect_timeout_ms,
                max_reconnect_attempts: 3,
                base_backoff_ms: 100,
                max_backoff_ms: 5_000,
            },
        })
    }

    /// Builds the manager from raw configured bounds without panicking.
    ///
    /// This is the composition entrypoint: the Kernel-configured store
    /// transaction limit and the read bound arrive as plain `usize` and are
    /// validated here, so no caller constructs a fallible
    /// [`NonZeroUsize`] bound with `expect`. A zero read bound, a zero
    /// write limit, or an inconsistent deadline/backoff policy fails
    /// closed with a typed message before any client set exists.
    pub fn from_configured_limits(
        read_clients: usize,
        store_transaction_limit: usize,
        connect_timeout_ms: u64,
        query_timeout_ms: u64,
    ) -> Result<Self, String> {
        let read_bound = NonZeroUsize::new(read_clients)
            .ok_or_else(|| "configured read client bound must be non-zero".to_owned())?;
        let write_limit = NonZeroUsize::new(store_transaction_limit)
            .ok_or_else(|| "configured store transaction limit must be non-zero".to_owned())?;
        Self::from_timeouts(
            read_bound,
            write_limit,
            connect_timeout_ms,
            query_timeout_ms,
        )
    }

    /// Per-class policy bound at composition time.
    #[must_use]
    pub const fn policy(&self, class: ClientClass) -> ClientSetPolicy {
        match class {
            ClientClass::Read => self.policies.read,
            ClientClass::Write => self.policies.write,
            ClientClass::Health => self.policies.health,
        }
    }

    /// Current explicit generation of one client set. Starts at 1 and only
    /// advances through [`Self::replace_generation`].
    ///
    /// A poisoned set reports generation 0, which is never issued: every
    /// lease compares stale and the set drains instead of serving new work
    /// under a suspect lineage.
    #[must_use]
    pub fn generation(&self, class: ClientClass) -> u64 {
        match self.state.lock() {
            Ok(state) => match class {
                ClientClass::Read => state.read_generation,
                ClientClass::Write => state.write_generation,
                ClientClass::Health => state.health_generation,
            },
            Err(_) => 0,
        }
    }

    /// Live leases currently drawn from one client set.
    #[must_use]
    pub fn in_use(&self, class: ClientClass) -> usize {
        self.policy(class)
            .bound
            .get()
            .saturating_sub(self.semaphore(class).available_permits())
    }

    /// Whether the set's current generation is marked broken. A broken set
    /// refuses new acquisitions until it is explicitly replaced.
    ///
    /// A poisoned set reports broken: acquisitions refuse until the
    /// composition is rebuilt, instead of serving under suspect state.
    #[must_use]
    pub fn is_broken(&self, class: ClientClass) -> bool {
        match self.state.lock() {
            Ok(state) => match class {
                ClientClass::Read => state.read_broken,
                ClientClass::Write => state.write_broken,
                ClientClass::Health => state.health_broken,
            },
            Err(_) => true,
        }
    }

    /// Acquires one bounded client lease without waiting.
    ///
    /// Fails closed with [`StoreError::Unavailable`] when the class is
    /// exhausted or its generation is broken — never by growing the set.
    /// The lease releases its slot on drop, so repeated concurrent use reuses
    /// the fixed set. Every lease carries a manager-issued identity bound to
    /// the generation it was drawn from (see [`Self::validate_lease`]).
    pub fn try_acquire(&self, class: ClientClass) -> Result<ClientLease, StoreError> {
        if self.is_broken(class) {
            return Err(StoreError::Unavailable);
        }
        let generation = self.generation(class);
        if generation == 0 {
            return Err(StoreError::Unavailable);
        }
        let permit = self
            .semaphore(class)
            .clone()
            .try_acquire_owned()
            .map_err(|_| StoreError::Unavailable)?;
        let lease_id = self.issue_lease_id(class);
        Ok(ClientLease {
            class,
            generation,
            lease_id,
            _permit: permit,
        })
    }

    /// Issues the next lease identity for one class under its current
    /// generation. Identities are monotonic per generation and reset on
    /// every explicit replacement, so the `(generation, lease_id)` pair
    /// authenticates a handle without aliasing across generations.
    fn issue_lease_id(&self, class: ClientClass) -> u64 {
        match self.state.lock() {
            Ok(mut state) => {
                let high_water = match class {
                    ClientClass::Read => &mut state.read_issued_high_water,
                    ClientClass::Write => &mut state.write_issued_high_water,
                    ClientClass::Health => &mut state.health_issued_high_water,
                };
                *high_water = high_water.saturating_add(1).max(1);
                *high_water
            }
            // A poisoned set cannot mint authenticated handles: id 0 is
            // never issued and every validation refuses it.
            Err(_) => 0,
        }
    }

    /// Validates a lease at the provider-touch boundary and returns its
    /// generation-fenced access guard.
    ///
    /// Refuses with [`StoreError::Unavailable`] when the lease belongs to a
    /// sealed (replaced) generation, when its identity was never issued by
    /// this manager under the current generation, or when the set's state is
    /// suspect. Generations fence clients, never canonical data: the shared
    /// durable state behind the provider is untouched — only handle
    /// admission is generation-scoped. A stale lease from generation N is
    /// unusable the moment generation N+1 is admitted, a fabricated
    /// identity never clears the high-water check, and a fresh lease under
    /// the admitted generation validates and reaches the same shared
    /// state. Composition must hold the returned [`LeaseAccess`] for the
    /// whole provider interaction.
    pub fn validate_lease(&self, lease: &ClientLease) -> Result<LeaseAccess, StoreError> {
        let current = self.generation(lease.class);
        if lease.generation == 0 || lease.generation != current {
            return Err(StoreError::Unavailable);
        }
        let high_water = match self.state.lock() {
            Ok(state) => match lease.class {
                ClientClass::Read => state.read_issued_high_water,
                ClientClass::Write => state.write_issued_high_water,
                ClientClass::Health => state.health_issued_high_water,
            },
            Err(_) => return Err(StoreError::Unavailable),
        };
        if lease.lease_id == 0 || lease.lease_id > high_water {
            return Err(StoreError::Unavailable);
        }
        Ok(LeaseAccess {
            class: lease.class,
            generation: lease.generation,
            lease_id: lease.lease_id,
        })
    }

    /// Marks the current generation broken after a transport failure.
    /// New acquisitions refuse until [`Self::replace_generation`] runs;
    /// in-flight leases of the old generation drain. A new break opens a
    /// fresh reconnect budget: attempts recorded for the previous break do
    /// not carry over.
    ///
    /// Best-effort when the set is already inconsistent from a prior panic:
    /// [`Self::is_broken`] reports broken regardless, so a lost mark cannot
    /// reopen acquisitions.
    pub fn mark_broken(&self, class: ClientClass) {
        if let Ok(mut state) = self.state.lock() {
            match class {
                ClientClass::Read => {
                    state.read_broken = true;
                    state.read_reconnect_attempts = 0;
                }
                ClientClass::Write => {
                    state.write_broken = true;
                    state.write_reconnect_attempts = 0;
                }
                ClientClass::Health => {
                    state.health_broken = true;
                    state.health_reconnect_attempts = 0;
                }
            }
        }
    }

    /// Records one reconnect attempt against the broken set and returns the
    /// policy-prescribed wait before dialing.
    ///
    /// The returned delay is [`ClientSetPolicy::backoff_for_attempt`] for
    /// the new attempt count: the caller actually waits it, then dials the
    /// transport exactly once. Fails closed when the set is not broken
    /// (nothing to reconnect) or when the attempt would exceed the
    /// policy's `max_reconnect_attempts` (the budget is blown: escalate,
    /// do not silently replace).
    pub fn note_reconnect_attempt(&self, class: ClientClass) -> Result<u64, String> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| "connection state is poisoned".to_owned())?;
        let (broken, attempts, policy) = match class {
            ClientClass::Read => (
                state.read_broken,
                &mut state.read_reconnect_attempts,
                self.policies.read,
            ),
            ClientClass::Write => (
                state.write_broken,
                &mut state.write_reconnect_attempts,
                self.policies.write,
            ),
            ClientClass::Health => (
                state.health_broken,
                &mut state.health_reconnect_attempts,
                self.policies.health,
            ),
        };
        if !broken {
            return Err(format!(
                "client set {} is not broken; no reconnect to record",
                class.as_str()
            ));
        }
        *attempts = attempts.saturating_add(1);
        if *attempts > policy.max_reconnect_attempts {
            return Err(format!(
                "client set {} exhausted its {} reconnect attempts; escalate instead of replacing",
                class.as_str(),
                policy.max_reconnect_attempts
            ));
        }
        Ok(policy.backoff_for_attempt(*attempts))
    }

    /// Explicitly replaces a broken generation and returns the new one.
    ///
    /// Replacement admits the new generation only after the reconnect path
    /// ran: at least one attempt must be recorded through
    /// [`Self::note_reconnect_attempt`] inside the policy budget, otherwise
    /// the set stays broken. A replacement without a marked failure, or
    /// past the reconnect budget, fails closed — generations advance only
    /// as declared, reconnect-evidenced recovery, never silently. Leases of
    /// the sealed generation stay valid only as stale witnesses (see
    /// [`Self::validate_lease`]); new acquisitions carry the new
    /// generation.
    pub fn replace_generation(&self, class: ClientClass) -> Result<u64, String> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| "connection state is poisoned".to_owned())?;
        // Each arm touches only its own class fields in sequence, so no two
        // mutable borrows overlap.
        match class {
            ClientClass::Read => {
                Self::require_reconnect_evidence(
                    class,
                    state.read_broken,
                    state.read_reconnect_attempts,
                    self.policies.read.max_reconnect_attempts,
                )?;
                state.read_generation = state.read_generation.saturating_add(1).max(1);
                state.read_broken = false;
                state.read_reconnect_attempts = 0;
                state.read_issued_high_water = 0;
                Ok(state.read_generation)
            }
            ClientClass::Write => {
                Self::require_reconnect_evidence(
                    class,
                    state.write_broken,
                    state.write_reconnect_attempts,
                    self.policies.write.max_reconnect_attempts,
                )?;
                state.write_generation = state.write_generation.saturating_add(1).max(1);
                state.write_broken = false;
                state.write_reconnect_attempts = 0;
                state.write_issued_high_water = 0;
                Ok(state.write_generation)
            }
            ClientClass::Health => {
                Self::require_reconnect_evidence(
                    class,
                    state.health_broken,
                    state.health_reconnect_attempts,
                    self.policies.health.max_reconnect_attempts,
                )?;
                state.health_generation = state.health_generation.saturating_add(1).max(1);
                state.health_broken = false;
                state.health_reconnect_attempts = 0;
                state.health_issued_high_water = 0;
                Ok(state.health_generation)
            }
        }
    }

    /// Requires a marked failure plus reconnect evidence inside budget
    /// before any generation cutover.
    fn require_reconnect_evidence(
        class: ClientClass,
        broken: bool,
        attempts: u32,
        max_attempts: u32,
    ) -> Result<(), String> {
        if !broken {
            return Err(not_broken(class));
        }
        if attempts == 0 {
            return Err(format!(
                "client set {} has no recorded reconnect attempt; run the reconnect path before replacing its generation",
                class.as_str()
            ));
        }
        if attempts > max_attempts {
            return Err(format!(
                "client set {} exhausted its {max_attempts} reconnect attempts; escalate instead of replacing",
                class.as_str()
            ));
        }
        Ok(())
    }

    /// Restricts bridge reads to the activated named Q0–Q4 catalogue.
    ///
    /// The ten activated reads are all Q0–Q4 observations; the Q5
    /// research/reconstruction cold job has no activated entry and any other
    /// known-but-unsupported operation fails here with
    /// [`StoreError::UnknownOperation`] before any provider I/O.
    pub fn admit_named_read(operation: NamedReadOperation) -> Result<(), StoreError> {
        if activated_read_operations().contains(&operation) {
            Ok(())
        } else {
            Err(StoreError::UnknownOperation)
        }
    }

    fn semaphore(&self, class: ClientClass) -> &Arc<Semaphore> {
        match class {
            ClientClass::Read => &self.read,
            ClientClass::Write => &self.write,
            ClientClass::Health => &self.health,
        }
    }
}

/// One bounded client lease. The slot returns to its fixed set on drop.
///
/// The `(generation, lease_id)` pair binds the handle to the exact
/// generation it was drawn from: [`StoreConnectionManager::validate_lease`]
/// refuses stale and fabricated handles at the provider-touch boundary.
pub struct ClientLease {
    class: ClientClass,
    generation: u64,
    lease_id: u64,
    _permit: OwnedSemaphorePermit,
}

impl std::fmt::Debug for ClientLease {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ClientLease")
            .field("class", &self.class)
            .field("generation", &self.generation)
            .field("lease_id", &self.lease_id)
            .finish_non_exhaustive()
    }
}

impl ClientLease {
    /// Which bounded set this lease was drawn from.
    #[must_use]
    pub const fn class(&self) -> ClientClass {
        self.class
    }

    /// Generation the lease was issued under.
    #[must_use]
    pub const fn generation(&self) -> u64 {
        self.generation
    }

    /// Manager-issued identity, monotonic within one generation.
    #[must_use]
    pub const fn lease_id(&self) -> u64 {
        self.lease_id
    }

    /// Whether the lease still belongs to the set's current generation.
    #[must_use]
    pub fn is_current(&self, manager: &StoreConnectionManager) -> bool {
        self.generation != 0 && self.generation == manager.generation(self.class)
    }
}

/// Generation-fenced access guard for one validated lease.
///
/// Holding this value proves the lease cleared
/// [`StoreConnectionManager::validate_lease`] under the recorded
/// generation: composition threads it through the whole provider
/// interaction so a stale or fabricated handle cannot reach provider
/// state. It carries no slot itself; dropping the [`ClientLease`] still
/// releases the set slot.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LeaseAccess {
    class: ClientClass,
    generation: u64,
    lease_id: u64,
}

impl LeaseAccess {
    /// Which bounded set the validated lease was drawn from.
    #[must_use]
    pub const fn class(&self) -> ClientClass {
        self.class
    }

    /// Admitted generation the access was validated under.
    #[must_use]
    pub const fn generation(&self) -> u64 {
        self.generation
    }

    /// Manager-issued lease identity the access was validated for.
    #[must_use]
    pub const fn lease_id(&self) -> u64 {
        self.lease_id
    }
}

/// Error for a generation replacement requested without a marked failure.
fn not_broken(class: ClientClass) -> String {
    format!(
        "client set {} is not broken; generation replacement requires a marked failure",
        class.as_str()
    )
}

/// Classified outcome of resolving one unknown write by exact operation
/// identity through `ResolveWriteReceipt` (I5.19).
///
/// The classification carries the actual receipt fields the write-admission
/// decision enforces — never a parallel verdict: a dead letter opens an
/// ordering gap instead of authorizing new work, and a proven
/// non-application carries the receipt's resubmission rule for admission
/// to enforce.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ResolvedWriteOutcome {
    /// No receipt exists for the operation identity yet: the outcome is
    /// still unknown.
    Absent,
    /// A valid enveloped `Committed` receipt proves the mutation applied:
    /// reuse it, never replay.
    Committed,
    /// A valid enveloped terminal rejection or cancellation proves the
    /// mutation did not apply. A new attempt is a newly admitted operation
    /// under the carried resubmission rule — never a blind replay, and
    /// never without the admission path enforcing that rule.
    ProvenNotApplied { resubmission: Resubmission },
    /// A valid enveloped `DeadLetter` receipt proves the operation is
    /// unusable and opens an ordering `SequenceGap`. The same work must
    /// not be re-admitted under any identity until the gap is dispositioned
    /// through the canonical `SequenceDisposition` path (I5.19).
    DeadLetterGapOpen,
    /// The lookup answered for another identity, or the receipt is invalid
    /// or envelope-less: the outcome stays unknown.
    ForeignOrInvalid,
}

/// What the bridge may do after receipt resolution and before any new
/// transaction attempt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReplayVerdict {
    /// No replay: return the existing committed receipt.
    UseExistingReceipt,
    /// No replay: the outcome is still unknown; keep reconciling the exact
    /// operation identity.
    MustReconcile,
    /// The original mutation provably did not apply; only a newly admitted
    /// operation may proceed — subject to the receipt's resubmission rule
    /// (see [`UnknownWriteGate::resubmission`]) enforced at admission —
    /// never a blind same-identity replay.
    NewIdentityOnly,
    /// No replay and no re-admission of the same work: the dead-lettered
    /// operation opened an ordering gap that requires canonical
    /// `SequenceDisposition` before anything built on its position moves.
    RequiresGapDisposition,
}

/// Classifies one receipt lookup for the exact operation that went unknown.
#[must_use]
pub fn classify_receipt_lookup(
    operation_id: &OperationId,
    receipt: Option<&WriteReceipt>,
) -> ResolvedWriteOutcome {
    let Some(receipt) = receipt else {
        return ResolvedWriteOutcome::Absent;
    };
    if receipt.operation_id != *operation_id
        || receipt.validate().is_err()
        || receipt.require_reconciliation_envelope().is_err()
    {
        return ResolvedWriteOutcome::ForeignOrInvalid;
    }
    match receipt.status {
        WriteReceiptStatus::Committed => ResolvedWriteOutcome::Committed,
        WriteReceiptStatus::Rejected | WriteReceiptStatus::Cancelled => {
            ResolvedWriteOutcome::ProvenNotApplied {
                resubmission: receipt.resubmission,
            }
        }
        WriteReceiptStatus::DeadLetter => ResolvedWriteOutcome::DeadLetterGapOpen,
    }
}

/// Decides whether any new transaction attempt is permissible after receipt
/// resolution. Unknown stays unknown: only a proven terminal outcome moves
/// the gate, and no arm permits a blind same-identity replay. A dead
/// letter additionally forbids re-admitting the same work until its
/// ordering gap is dispositioned.
#[must_use]
pub const fn decide_replay(outcome: &ResolvedWriteOutcome) -> ReplayVerdict {
    match outcome {
        ResolvedWriteOutcome::Absent | ResolvedWriteOutcome::ForeignOrInvalid => {
            ReplayVerdict::MustReconcile
        }
        ResolvedWriteOutcome::Committed => ReplayVerdict::UseExistingReceipt,
        ResolvedWriteOutcome::ProvenNotApplied { .. } => ReplayVerdict::NewIdentityOnly,
        ResolvedWriteOutcome::DeadLetterGapOpen => ReplayVerdict::RequiresGapDisposition,
    }
}

/// Tracks one ambiguous write from transport failure through exact receipt
/// resolution. The gate opens only for the reconciled verdict; it never
/// authorizes a replay while the outcome is unknown.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UnknownWriteGate {
    operation_id: OperationId,
    outcome: Option<ResolvedWriteOutcome>,
}

impl UnknownWriteGate {
    /// Opens the gate in the unknown state for one exact operation identity.
    #[must_use]
    pub const fn unknown(operation_id: OperationId) -> Self {
        Self {
            operation_id,
            outcome: None,
        }
    }

    /// Exact operation identity under reconciliation.
    #[must_use]
    pub const fn operation_id(&self) -> &OperationId {
        &self.operation_id
    }

    /// Records the receipt-lookup classification for this gate's identity.
    ///
    /// Prefer [`Self::resolve_lookup`]: it classifies the raw receipt
    /// against the gate's own operation identity, so a receipt for another
    /// identity records as foreign and can never resolve this gate.
    pub fn resolve(&mut self, outcome: ResolvedWriteOutcome) {
        self.outcome = Some(outcome);
    }

    /// Classifies one `ResolveWriteReceipt` answer against this gate's own
    /// operation identity and records it.
    ///
    /// A lookup that answered for another identity, or an invalid or
    /// envelope-less receipt, records as foreign and keeps the gate
    /// unknown: [`Self::verdict`] stays [`ReplayVerdict::MustReconcile`].
    pub fn resolve_lookup(&mut self, receipt: Option<&WriteReceipt>) {
        self.outcome = Some(classify_receipt_lookup(&self.operation_id, receipt));
    }

    /// Current verdict: [`ReplayVerdict::MustReconcile`] until a proven
    /// terminal outcome for the exact identity is recorded. A dead letter
    /// resolves to [`ReplayVerdict::RequiresGapDisposition`]: the outcome
    /// is known, but the same work must not move until its ordering gap is
    /// dispositioned.
    #[must_use]
    pub fn verdict(&self) -> ReplayVerdict {
        self.outcome
            .as_ref()
            .map_or(ReplayVerdict::MustReconcile, decide_replay)
    }

    /// Whether the unknown outcome is resolved to a proven terminal
    /// verdict. Unknown — including never-resolved — is always `false`.
    /// Resolution never authorizes a blind same-identity replay: a
    /// committed outcome reuses the existing receipt, a proven
    /// non-application admits only a new operation identity under the
    /// receipt's resubmission rule, and a dead letter requires gap
    /// disposition first.
    #[must_use]
    pub fn is_resolved(&self) -> bool {
        !matches!(self.verdict(), ReplayVerdict::MustReconcile)
    }

    /// Resubmission rule carried by a proven non-application, for the
    /// write-admission path to enforce before admitting any new identity.
    /// `None` until (and unless) the gate resolves to
    /// [`ReplayVerdict::NewIdentityOnly`].
    #[must_use]
    pub const fn resubmission(&self) -> Option<Resubmission> {
        match &self.outcome {
            Some(ResolvedWriteOutcome::ProvenNotApplied { resubmission }) => Some(*resubmission),
            _ => None,
        }
    }
}

/// Exact-operation admission for the isolated health/admin path (I5.9).
///
/// HTTP/admin fallback is never a general transport: each health or recovery
/// operation runs only when separately admitted for that exact operation.
/// Anything else refuses before touching any client set — and therefore
/// never consumes a canonical write slot.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HealthAdminAdmission {
    admitted: Vec<String>,
}

impl HealthAdminAdmission {
    /// Admits exactly the health/readiness observations for the isolated
    /// path. Recovery or backup operations join only through an explicit
    /// extension for their exact operation identity.
    #[must_use]
    pub fn bridge_default() -> Self {
        Self {
            admitted: vec!["store.health".to_owned(), "store.readiness".to_owned()],
        }
    }

    /// Admits one more exact operation for the isolated path.
    pub fn admit_exact(&mut self, operation: &str) {
        if !self.admitted.iter().any(|admitted| admitted == operation) {
            self.admitted.push(operation.to_owned());
        }
    }

    /// Whether this exact operation may use the isolated health/admin path.
    #[must_use]
    pub fn is_admitted(&self, operation: &str) -> bool {
        self.admitted.iter().any(|admitted| admitted == operation)
    }

    /// Requires exact admission before any health/admin client use.
    pub fn require_admitted(&self, operation: &str) -> Result<(), StoreError> {
        if self.is_admitted(operation) {
            Ok(())
        } else {
            Err(StoreError::UnknownOperation)
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use super::*;

    fn policies() -> ConnectionPolicies {
        ConnectionPolicies {
            read: ClientSetPolicy {
                bound: NonZeroUsize::new(2).expect("read bound"),
                deadline_ms: 1_000,
                max_reconnect_attempts: 3,
                base_backoff_ms: 100,
                max_backoff_ms: 5_000,
            },
            write: ClientSetPolicy {
                bound: NonZeroUsize::new(1).expect("write bound"),
                deadline_ms: 1_000,
                max_reconnect_attempts: 3,
                base_backoff_ms: 100,
                max_backoff_ms: 5_000,
            },
            health: ClientSetPolicy {
                bound: NonZeroUsize::new(1).expect("health bound"),
                deadline_ms: 500,
                max_reconnect_attempts: 3,
                base_backoff_ms: 100,
                max_backoff_ms: 5_000,
            },
        }
    }

    #[test]
    fn invalid_policies_refuse_before_any_client_use() {
        let mut invalid = policies();
        invalid.read.deadline_ms = 0;
        assert!(StoreConnectionManager::new(invalid).is_err());
        let mut invalid = policies();
        invalid.write.base_backoff_ms = 9_000;
        assert!(StoreConnectionManager::new(invalid).is_err());
    }

    #[test]
    fn reconnect_backoff_is_bounded_and_monotonic() {
        let policy = policies().write;
        assert_eq!(policy.backoff_for_attempt(1), 100);
        assert_eq!(policy.backoff_for_attempt(2), 200);
        assert_eq!(policy.backoff_for_attempt(3), 400);
        assert_eq!(policy.backoff_for_attempt(100), 5_000);
        assert!(policy.backoff_for_attempt(4) <= policy.max_backoff_ms);
    }

    #[test]
    fn default_transaction_limit_follows_the_i57_desktop_default() {
        let limit = default_store_transaction_limit().get();
        assert!((1..=4).contains(&limit));
    }

    #[test]
    fn read_gate_admits_only_activated_q0_q4_operations() {
        for operation in activated_read_operations() {
            assert!(StoreConnectionManager::admit_named_read(operation).is_ok());
        }
        assert_eq!(
            StoreConnectionManager::admit_named_read(NamedReadOperation::GetModuleCatalogState),
            Err(StoreError::UnknownOperation)
        );
    }

    #[test]
    fn health_admission_is_exact_operation_only() {
        let mut admission = HealthAdminAdmission::bridge_default();
        assert!(admission.require_admitted("store.health").is_ok());
        assert!(admission.require_admitted("store.readiness").is_ok());
        assert_eq!(
            admission.require_admitted("store.apply"),
            Err(StoreError::UnknownOperation)
        );
        admission.admit_exact("store.recovery");
        assert!(admission.require_admitted("store.recovery").is_ok());
        assert_eq!(
            admission.require_admitted("store.recovery.other"),
            Err(StoreError::UnknownOperation)
        );
    }
}
