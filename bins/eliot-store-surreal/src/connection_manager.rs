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
    NamedReadOperation, OperationId, StoreError, WriteReceipt, WriteReceiptStatus,
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
    /// the fixed set.
    pub fn try_acquire(&self, class: ClientClass) -> Result<ClientLease, StoreError> {
        if self.is_broken(class) {
            return Err(StoreError::Unavailable);
        }
        let generation = self.generation(class);
        let permit = self
            .semaphore(class)
            .clone()
            .try_acquire_owned()
            .map_err(|_| StoreError::Unavailable)?;
        Ok(ClientLease {
            class,
            generation,
            _permit: permit,
        })
    }

    /// Marks the current generation broken after a transport failure.
    /// New acquisitions refuse until [`Self::replace_generation`] runs;
    /// in-flight leases of the old generation drain.
    ///
    /// Best-effort when the set is already inconsistent from a prior panic:
    /// [`Self::is_broken`] reports broken regardless, so a lost mark cannot
    /// reopen acquisitions.
    pub fn mark_broken(&self, class: ClientClass) {
        if let Ok(mut state) = self.state.lock() {
            match class {
                ClientClass::Read => state.read_broken = true,
                ClientClass::Write => state.write_broken = true,
                ClientClass::Health => state.health_broken = true,
            }
        }
    }

    /// Explicitly replaces a broken generation and returns the new one.
    /// Fails closed when the set was not marked broken: generations advance
    /// only as declared recovery, never silently.
    pub fn replace_generation(&self, class: ClientClass) -> Result<u64, String> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| "connection state is poisoned".to_owned())?;
        // Each arm touches only its own class fields in sequence, so no two
        // mutable borrows overlap.
        match class {
            ClientClass::Read => {
                if !state.read_broken {
                    return Err(not_broken(class));
                }
                state.read_generation = state.read_generation.saturating_add(1).max(1);
                state.read_broken = false;
                Ok(state.read_generation)
            }
            ClientClass::Write => {
                if !state.write_broken {
                    return Err(not_broken(class));
                }
                state.write_generation = state.write_generation.saturating_add(1).max(1);
                state.write_broken = false;
                Ok(state.write_generation)
            }
            ClientClass::Health => {
                if !state.health_broken {
                    return Err(not_broken(class));
                }
                state.health_generation = state.health_generation.saturating_add(1).max(1);
                state.health_broken = false;
                Ok(state.health_generation)
            }
        }
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
pub struct ClientLease {
    class: ClientClass,
    generation: u64,
    _permit: OwnedSemaphorePermit,
}

impl std::fmt::Debug for ClientLease {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ClientLease")
            .field("class", &self.class)
            .field("generation", &self.generation)
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

    /// Whether the lease still belongs to the set's current generation.
    #[must_use]
    pub fn is_current(&self, manager: &StoreConnectionManager) -> bool {
        self.generation == manager.generation(self.class)
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
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ResolvedWriteOutcome {
    /// No receipt exists for the operation identity yet: the outcome is
    /// still unknown.
    Absent,
    /// A valid enveloped `Committed` receipt proves the mutation applied:
    /// reuse it, never replay.
    Committed,
    /// A valid enveloped terminal non-commit receipt proves the mutation did
    /// not apply. A new attempt is a newly admitted operation under the
    /// catalogue resubmission rules, never a blind replay.
    ProvenNotApplied,
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
    /// operation may proceed, never a blind same-identity replay.
    NewIdentityOnly,
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
        WriteReceiptStatus::Rejected
        | WriteReceiptStatus::DeadLetter
        | WriteReceiptStatus::Cancelled => ResolvedWriteOutcome::ProvenNotApplied,
    }
}

/// Decides whether any new transaction attempt is permissible after receipt
/// resolution. Unknown stays unknown: only a proven terminal outcome moves
/// the gate, and no arm permits a blind same-identity replay.
#[must_use]
pub const fn decide_replay(outcome: &ResolvedWriteOutcome) -> ReplayVerdict {
    match outcome {
        ResolvedWriteOutcome::Absent | ResolvedWriteOutcome::ForeignOrInvalid => {
            ReplayVerdict::MustReconcile
        }
        ResolvedWriteOutcome::Committed => ReplayVerdict::UseExistingReceipt,
        ResolvedWriteOutcome::ProvenNotApplied => ReplayVerdict::NewIdentityOnly,
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
    /// terminal outcome for the exact identity is recorded.
    #[must_use]
    pub fn verdict(&self) -> ReplayVerdict {
        self.outcome
            .as_ref()
            .map_or(ReplayVerdict::MustReconcile, decide_replay)
    }

    /// Whether the unknown outcome is resolved to a proven terminal
    /// verdict. Unknown — including never-resolved — is always `false`.
    /// Resolution never authorizes a blind same-identity replay: a
    /// committed outcome reuses the existing receipt, and a proven
    /// non-application admits only a new operation identity.
    #[must_use]
    pub fn is_resolved(&self) -> bool {
        !matches!(self.verdict(), ReplayVerdict::MustReconcile)
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
