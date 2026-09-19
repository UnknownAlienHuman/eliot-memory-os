//! Bounded reserved-scope write execution (S-CONC-EXECUTE, issue #993).
//!
//! Runtime orchestration over the accepted prerequisites: the #988 pure
//! [`WriteScheduler`](crate::write_scheduler::WriteScheduler), the #987
//! bounded session set ([`ClientSetLimits`](crate::config::ClientSetLimits)),
//! the #989 bounded allocation attempt, and the #990/#991 reserved-write
//! boundary ([`ReservedWriteRequest`]). One [`WriteExecution`] generation
//! owns the scheduler plus the normal-write and protected permit bounds for
//! a single provider generation.
//!
//! Responsibility split (ARCH-MOD-03: one causal responsibility, one owner):
//!
//! - this module owns scheduling, permits, pre-submit rechecks, the
//!   exclusive drain gate, ephemeral recovery reconstruction, metrics, and
//!   the [`ReservedAttemptTransport`] seam;
//! - the transport owns provider effects: submission-gate reads, the exact
//!   #989 attempt, and durable receipt reconciliation. Production wires the
//!   pooled normal-write lane there; deterministic tests script a fake
//!   without a provider.
//!
//! Hard rules enforced here:
//!
//! - Queue only bounded admitted operations with complete scope/reservation
//!   identity: [`ReservedWriteRequest::validate`] is the receiving boundary,
//!   and the scheduler queue bound sheds with `QueueFull`.
//! - A normal-write permit is acquired only after scheduler readiness, and
//!   owner/fence/expiry/cancel/drain are rechecked immediately before a
//!   possible submission. No predecessor, network, or permit wait ever runs
//!   while the scheduler lock is held: every guard drops before the first
//!   await.
//! - Normal writes never touch the historical global write mutex; the only
//!   exclusive lock here is the dedicated migration drain gate, held across
//!   quiescence plus one existing migration/genesis operation.
//! - Before-submit cancellation or capacity failure dispositions without
//!   provider effects. After possible submission, cancellation, panic,
//!   timeout, lost response, or a dropped caller keeps operation and
//!   reservation identity in explicit reconciliation; permit release never
//!   implies semantic completion.
//! - Unknown outcomes pause only dependent scopes; unrelated ready scopes
//!   proceed subject to real bounded capacity.
//! - Recovery rebuilds only ephemeral scheduler state from the durable
//!   reservation/receipt denominator the existing owners supply; unknown or
//!   incomplete recovery blocks normal readiness.
//!
//! Time enters as explicit caller `now_ms` on every path (A14.8
//! deterministic simulation). The drain quiescence loop reuses the same
//! observation instant each round; scripted transports never need it to
//! advance.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::future::Future;
use std::num::NonZeroUsize;
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, AtomicU64, Ordering},
};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use eliot_store_api::{
    CAPABILITY_RESERVED_WRITE, OperationId, OrderingHeadExpectation, PreparedTransition,
    RequestMeta, ReservedWriteRequest, RevisionHeadExpectation, StateFence, StoreError,
    WriteReceipt,
};
use futures_util::future::join_all;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

use crate::config::{ClientSetLimits, SchemaGeneration, validate_execution_profile};
use crate::error::AdapterError;
use crate::write_scheduler::{
    CompletionOutcome, ReservationProjection, ReservedScopeProjection, ScheduleReject,
    WriteScheduler,
};

/// Execution profile owned by one generation.
///
/// The serial profile is the explicitly lower-support compatibility mode:
/// exactly one lane, and reserved submits are refused. The concurrent
/// profile removes the normal-write bottleneck for fully admitted reserved
/// work. Profiles are mutually exclusive per generation; changing profile
/// requires a drained generation transition (uninstall a quiescent
/// execution, install the next), never a runtime switch while writes are
/// active.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExecutionProfile {
    /// Compatibility serial profile: one lane, legacy unreserved path.
    Serial,
    /// Concurrent reserved-scope profile behind the scheduler and permits.
    Concurrent,
}

/// Admission of the legacy unreserved `Apply` path under an execution.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UnreservedAdmission {
    /// Serial profile explicitly admits the legacy serial lane.
    AllowedLegacySerial,
    /// A concurrent generation owns the writable root: unreserved `Apply`
    /// must not bypass its scheduler.
    DeniedConcurrentGeneration,
}

impl UnreservedAdmission {
    /// Whether the legacy path may proceed.
    #[must_use]
    pub const fn allowed(self) -> bool {
        matches!(self, Self::AllowedLegacySerial)
    }
}

/// Evidence required to install the concurrent profile (issue #993, case 2).
///
/// Every field is checked by [`WriteExecution::install_concurrent`]; the
/// production values originate from the adapter's own validated config,
/// observed provider generation, and the authenticated receiving boundary,
/// never from a self-declared valid/eligible flag.
#[derive(Clone, Debug)]
pub struct ConcurrentEvidence {
    /// Must be exactly the accepted `store.reserved_write` declaration.
    pub capability: &'static str,
    /// Generation the provider currently serves (observed via readiness).
    pub observed_generation: SchemaGeneration,
    /// Generation this bridge expects (its validated configuration).
    pub expected_generation: SchemaGeneration,
    /// Current fence the generation executes under.
    pub state_fence: StateFence,
    /// Authenticated Kernel generation identity from the receiving boundary.
    pub kernel_generation: String,
}

impl ConcurrentEvidence {
    fn validate(&self) -> Result<(), AdapterError> {
        if self.capability != CAPABILITY_RESERVED_WRITE {
            return Err(AdapterError::Store(StoreError::InvalidField {
                field: "execution.capability",
                reason: "concurrent execution requires the accepted reserved-write capability",
            }));
        }
        if self.observed_generation.as_str() != self.expected_generation.as_str() {
            return Err(AdapterError::Store(StoreError::InvalidField {
                field: "execution.schema_generation",
                reason: "observed provider generation must equal the expected generation",
            }));
        }
        self.state_fence
            .validate()
            .map_err(StoreError::Foundation)
            .map_err(AdapterError::Store)?;
        if self.kernel_generation.trim().is_empty()
            || self.kernel_generation.chars().any(char::is_control)
        {
            return Err(AdapterError::Store(StoreError::InvalidField {
                field: "execution.kernel_generation",
                reason: "authenticated Kernel generation identity is required",
            }));
        }
        Ok(())
    }
}

/// How a reserved submit was dispositioned.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SubmitDisposition {
    /// Newly queued behind the scheduler bound.
    Accepted,
    /// Same operation identity with the same sealed transition digest was
    /// already queued: idempotent no-op, the original executes.
    AlreadyQueued,
}

/// One executable reserved attempt handed to the transport.
#[derive(Clone, Debug)]
pub struct ExecutableAttempt {
    /// Canonical operation identity (idempotency owner).
    pub operation_id: OperationId,
    /// Authenticated transport context; always wins over payload mirrors.
    pub context: RequestMeta,
    /// Exact immutable semantic input, preserved byte-for-byte.
    pub transition: PreparedTransition,
    /// Preserved revision-head expectations with the shared fence.
    pub expected_revision_heads: Vec<RevisionHeadExpectation>,
    /// Preserved ordering-head expectations covering the reserved scopes.
    pub expected_ordering_heads: Vec<OrderingHeadExpectation>,
    /// Single-coordinator precedence for scheduler evidence.
    pub reservation_order: u64,
    /// Owner expiry in Unix milliseconds; wall timestamps alone are not
    /// authority, but a passed expiry fails closed before submission.
    pub expires_at_ms: i64,
}

/// Provider-side submission gate rechecked immediately before a possible
/// submission (issue #993, case 8).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProviderGate {
    /// The provider generation/owner the transport reached is current.
    pub owner_current: bool,
    /// The durable fence still matches the admitted transition fence.
    pub fence_matches: bool,
    /// The reservation has not passed its owner expiry at observation time.
    pub not_expired: bool,
}

impl ProviderGate {
    /// Fully open gate: submission may proceed.
    #[must_use]
    pub const fn open() -> Self {
        Self {
            owner_current: true,
            fence_matches: true,
            not_expired: true,
        }
    }

    /// Fully closed gate: nothing may be submitted.
    #[must_use]
    pub const fn closed() -> Self {
        Self {
            owner_current: false,
            fence_matches: false,
            not_expired: false,
        }
    }

    /// Whether the attempt may be submitted.
    #[must_use]
    pub const fn submittable(self) -> bool {
        self.owner_current && self.fence_matches && self.not_expired
    }
}

/// Outcome of one permitted provider attempt.
#[derive(Clone, Debug)]
pub enum AttemptOutcome {
    /// Canonical commit observed with its immutable receipt.
    Committed(Box<WriteReceipt>),
    /// Deterministic rejection carrying the exact cause; the reserved
    /// sequence closes and successors proceed. No effect occurred.
    Rejected(StoreError),
    /// Proven non-application without a commit; successors proceed.
    DeadLetter,
    /// Cancelled or failed before any provider effect (transport proves no
    /// submission happened): safe to resubmit under the same identity.
    Cancelled,
    /// Possibly submitted: outcome unknown until exact receipt
    /// reconciliation. Successors on dependent scopes pause; the operation
    /// stays in explicit reconciliation ownership.
    Unknown {
        /// Milliseconds before the affected scope heads reopen for a
        /// reconciled retry; blocks only those heads, never the lane.
        retry_after_ms: u64,
    },
}

/// Outcome of exact durable receipt reconciliation for an unknown operation.
#[derive(Clone, Debug)]
pub enum ReconcileOutcome {
    /// The durable receipt proves the commit; successors resume.
    Committed(Box<WriteReceipt>),
    /// Proven non-application; the ordering position dispositions as dead
    /// letter and successors resume.
    Absent,
    /// Still unknown: the operation stays uncertain and keeps its scopes.
    StillUnknown,
}

/// Provider-effect seam behind the orchestration (test-fakeable transport).
///
/// Production implements the existing pooled normal-write lane, bounded
/// allocation attempt, and durable receipt reads. Deterministic tests script
/// gate, execute, and reconcile answers and record every call, so the
/// orchestration proofs never touch a provider.
#[allow(async_fn_in_trait)]
pub trait ReservedAttemptTransport: Send + Sync {
    /// Reads the current provider-side submission gate for one attempt.
    async fn read_submission_gate(
        &self,
        execution: &WriteExecution,
        attempt: &ExecutableAttempt,
        now_ms: u64,
    ) -> ProviderGate;

    /// Executes the existing bounded allocation attempt for this immutable
    /// admitted transition under the already-selected normal-write lane.
    async fn execute_attempt(
        &self,
        execution: &WriteExecution,
        attempt: &ExecutableAttempt,
    ) -> AttemptOutcome;

    /// Reconciles an unknown operation by exact operation identity against
    /// its durable receipt. Absence of a receipt is reported as
    /// `StillUnknown`, never as proof of non-application.
    async fn reconcile_unknown(
        &self,
        execution: &WriteExecution,
        operation_id: &OperationId,
    ) -> ReconcileOutcome;
}

/// Per-operation result of one ready batch.
#[derive(Clone, Debug)]
pub enum OpExecution {
    /// Committed through the attempt (`reconciled` set when the commit was
    /// proven by reconciliation rather than observed directly).
    Committed {
        operation_id: OperationId,
        receipt: Box<WriteReceipt>,
        reconciled: bool,
    },
    /// Deterministically rejected with the exact cause; no effect occurred.
    Rejected {
        operation_id: OperationId,
        error: StoreError,
    },
    /// Proven non-application; successors proceed.
    DeadLetter { operation_id: OperationId },
    /// Cancelled or shed before any provider effect; safe to resubmit under
    /// the same admitted identity.
    CancelledBeforeEffect { operation_id: OperationId },
    /// Still unknown after reconciliation was attempted: the operation
    /// keeps its scopes and its explicit reconciliation ownership.
    UnknownRetained { operation_id: OperationId },
    /// The scheduler entry vanished mid-pipeline (drained or resolved
    /// elsewhere): no provider effect was issued from this pipeline.
    DrainedWithoutEffect { operation_id: OperationId },
    /// Defensive scheduler failure after a possible submission: the
    /// operation keeps its reconciliation ownership; the caller reconciles
    /// by identity.
    ExecutionError {
        operation_id: OperationId,
        error: AdapterError,
    },
}

impl OpExecution {
    /// Canonical operation identity of this result.
    #[must_use]
    pub fn operation_id(&self) -> &OperationId {
        match self {
            Self::Committed { operation_id, .. }
            | Self::Rejected { operation_id, .. }
            | Self::DeadLetter { operation_id }
            | Self::CancelledBeforeEffect { operation_id }
            | Self::UnknownRetained { operation_id }
            | Self::DrainedWithoutEffect { operation_id }
            | Self::ExecutionError { operation_id, .. } => operation_id,
        }
    }
}

/// Exclusive operation kinds admitted through the drain gate.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExclusiveOpKind {
    /// Explicit checksummed schema migration.
    Migration,
    /// First-generation genesis where applicable.
    Genesis,
    /// Schema replacement outside the migration entrypoint.
    SchemaReplacement,
    /// Provider/execution generation cutover.
    GenerationCutover,
}

/// Report for one completed exclusive drain.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DrainReport {
    /// Which exclusive kind ran.
    pub kind: ExclusiveOpKind,
    /// Attempts committed (directly or via reconciliation) during the drain.
    pub committed: u64,
    /// Queued-not-started operations safely cancelled without provider
    /// effects during the drain.
    pub cancelled_queued: u64,
    /// Unknown operations resolved through exact reconciliation.
    pub reconciled: u64,
}

/// Durable outcome carried by the recovery denominator for one operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DurableOpOutcome {
    /// Terminal commit; nothing ephemeral to reconstruct.
    Committed,
    /// Terminal deterministic rejection.
    Rejected,
    /// Terminal proven non-application.
    DeadLetter,
    /// Terminal pre-effect cancellation.
    Cancelled,
    /// Unknown or missing: blocks normal readiness until resolved.
    Unknown,
}

/// Trusted durable denominator supplied by the existing owners for restart
/// recovery: admitted reservations plus their durable outcomes. Local
/// memory contributes nothing; an operation missing from `outcomes` counts
/// as unknown and blocks readiness.
#[derive(Clone, Debug)]
pub struct DurableRecoverySet {
    /// Admitted reservations to reconstruct.
    pub reservations: Vec<ReservationProjection>,
    /// Durable outcome per operation identity.
    pub outcomes: Vec<(OperationId, DurableOpOutcome)>,
}

/// Bounded execution metrics with redacted identities (issue #993, case 21).
///
/// Counters plus wait maxima only: no operation identity, digest, scope
/// name, or payload ever enters these values, so they are safe to render
/// into diagnostics and failure output.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ExecutionMetrics {
    /// Reserved submits accepted into the bounded queue.
    pub submitted: u64,
    /// Duplicate submits suppressed onto the already-queued original.
    pub duplicates_suppressed: u64,
    /// Attempts committed (directly observed).
    pub committed: u64,
    /// Commits proven through exact reconciliation after an unknown outcome.
    pub committed_via_reconcile: u64,
    /// Deterministic rejections (reserved sequence closed, no effect).
    pub rejected: u64,
    /// Proven non-applications dispositioned as dead letter.
    pub dead_lettered: u64,
    /// Pre-submit cancellations and capacity sheds without provider effects.
    pub cancelled_before_effect: u64,
    /// Unknown outcomes observed (possible submission, reconciling).
    pub unknown_observed: u64,
    /// Unknowns resolved as proven non-application.
    pub reconciled_absent: u64,
    /// Unknowns still unresolved after a reconcile attempt.
    pub still_unknown_retained: u64,
    /// Submits shed because the bounded queue was full.
    pub queue_full_shed: u64,
    /// Submits refused while draining, fenced, or recovery-blocked.
    pub submit_refused_not_ready: u64,
    /// Completed exclusive drains.
    pub drains_completed: u64,
    /// Failed or incomplete drains (execution stays fenced).
    pub drain_failures: u64,
    /// Drain attempts refused because another drain holds the gate.
    pub drains_refused_busy: u64,
    /// Maximum observed ready age at execution start (`now_ms` deltas).
    pub oldest_ready_wait_max_ms: u64,
    /// Permit acquisitions that queued behind a checked-out session.
    pub permit_waited_events: u64,
}

/// RAII guard for one protected (health/admin/reconciliation) permit.
///
/// Dropping the guard releases the bound permit. Release never implies
/// semantic completion of whatever the holder did: completion is always an
/// explicit scheduler or reconciliation act.
#[derive(Debug)]
pub struct ProtectedPermit {
    _permit: OwnedSemaphorePermit,
}

/// One admitted reserved write held for execution.
#[derive(Clone, Debug)]
struct QueuedReservedWrite {
    request: ReservedWriteRequest,
    submitted_at_ms: u64,
}

/// Drain lifecycle owned by the execution (not a runtime boolean switch:
///
/// transitions run Open -> Draining -> Open on an authorized exclusive
/// completion, or Open -> Draining -> Fenced on failure; Fenced leaves only
/// through [`WriteExecution::reopen_generation`] with accepted evidence).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DrainState {
    Open,
    Draining,
    Fenced,
}

/// Mutable execution state under one short-held lock.
///
/// The lock guards only in-memory scheduling decisions and is never held
/// across an await: every method scopes the guard to a synchronous
/// critical section before any permit, gate, or provider wait.
#[derive(Debug)]
struct Inner {
    scheduler: WriteScheduler,
    queued: BTreeMap<OperationId, QueuedReservedWrite>,
    /// Operations marked in flight by a batch snapshot and not yet
    /// terminally dispositioned. The drain disposition phase never touches
    /// these; their owning pipeline does.
    executing: BTreeSet<OperationId>,
    /// Operations without executable payload reconstructed from the
    /// durable denominator: they order and block scopes but never execute
    /// until reconciled out.
    recovered_pending: BTreeSet<OperationId>,
    cancels: BTreeSet<OperationId>,
    drain: DrainState,
    metrics: ExecutionMetrics,
}

/// Bounded interval between quiescence polls while the drain gate waits for
/// externally held in-flight work.
const DRAIN_POLL_INTERVAL: Duration = Duration::from_millis(1);

/// Liveness bound on drain quiescence waits: each wait round is ~1ms, so
/// this caps the exclusive-gate hold near thirty seconds, well above any
/// single provider attempt bound while still failing closed instead of
/// holding the gate forever.
const DRAIN_MAX_WAIT_ROUNDS: usize = 30_000;

/// Counter for execution generation identities.
static EXECUTION_GENERATION_COUNTER: AtomicU64 = AtomicU64::new(1);

/// One provider/execution generation owning the bounded scheduler and the
/// session-set permit bounds for a single provider generation.
pub struct WriteExecution {
    profile: ExecutionProfile,
    generation_id: u64,
    limits: ClientSetLimits,
    lanes: NonZeroUsize,
    max_pending: NonZeroUsize,
    normal_permits: Arc<Semaphore>,
    protected_permits: Arc<Semaphore>,
    recovery_blocked: AtomicBool,
    state: Mutex<Inner>,
    /// Exclusive migration drain gate: exactly one drain at a time, and the
    /// gate never doubles as a normal writer lane.
    drain_gate: tokio::sync::Mutex<DrainGateOwnership>,
}

/// Ownership token for the exclusive drain gate. A dedicated type rather
/// than `()` so the gate reads as what it is — migration exclusivity —
/// and never as a stand-in for the retired global write lock.
#[derive(Debug)]
struct DrainGateOwnership {
    _sealed: (),
}

/// Redacted debug view: profile, bounds, counts, drain state, and metrics
/// only. Scheduler entries, queued payloads, operation identities, scopes,
/// and digests never render here.
impl fmt::Debug for WriteExecution {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let snapshot = self.state.lock().map(|inner| {
            (
                inner.scheduler.pending_count(),
                inner.scheduler.in_flight_count(),
                inner.drain,
                inner.metrics,
            )
        });
        let (pending, in_flight, drain, metrics) = snapshot.unwrap_or((
            usize::MAX,
            usize::MAX,
            DrainState::Fenced,
            ExecutionMetrics::default(),
        ));
        formatter
            .debug_struct("WriteExecution")
            .field("profile", &self.profile)
            .field("generation_id", &self.generation_id)
            .field("limits", &self.limits)
            .field("lanes", &self.lanes)
            .field("max_pending", &self.max_pending)
            .field("pending", &pending)
            .field("in_flight", &in_flight)
            .field("drain", &drain)
            .field("recovery_blocked", &self.recovery_blocked())
            .field("metrics", &metrics)
            .finish_non_exhaustive()
    }
}

impl WriteExecution {
    /// Installs the concurrent profile over explicit bounds and evidence.
    ///
    /// `lanes` is capped by the validated `limits` write sessions so ready
    /// work can never wait on sessions that cannot free
    /// ([`validate_execution_profile`]); the queue bound is fixed here and
    /// can only shed, never grow, for this generation's lifetime.
    pub fn install_concurrent(
        limits: ClientSetLimits,
        lanes: NonZeroUsize,
        max_pending: NonZeroUsize,
        evidence: &ConcurrentEvidence,
        now_ms: u64,
    ) -> Result<Self, AdapterError> {
        validate_execution_profile(limits, lanes, false)
            .map_err(|error| AdapterError::Config(error.to_string()))?;
        evidence.validate()?;
        let _ = now_ms;
        Ok(Self::build(
            ExecutionProfile::Concurrent,
            limits,
            lanes,
            max_pending,
        ))
    }

    /// Installs the serial compatibility profile: exactly one lane over the
    /// given limits, legacy unreserved path admitted, reserved submits
    /// refused.
    pub fn install_serial(
        limits: ClientSetLimits,
        max_pending: NonZeroUsize,
    ) -> Result<Self, AdapterError> {
        validate_execution_profile(limits, NonZeroUsize::MIN, true)
            .map_err(|error| AdapterError::Config(error.to_string()))?;
        Ok(Self::build(
            ExecutionProfile::Serial,
            limits,
            NonZeroUsize::MIN,
            max_pending,
        ))
    }

    fn build(
        profile: ExecutionProfile,
        limits: ClientSetLimits,
        lanes: NonZeroUsize,
        max_pending: NonZeroUsize,
    ) -> Self {
        Self {
            profile,
            generation_id: EXECUTION_GENERATION_COUNTER.fetch_add(1, Ordering::Relaxed),
            limits,
            lanes,
            max_pending,
            normal_permits: Arc::new(Semaphore::new(usize::from(limits.write_sessions()))),
            protected_permits: Arc::new(Semaphore::new(usize::from(limits.admin_sessions()))),
            recovery_blocked: AtomicBool::new(false),
            state: Mutex::new(Inner {
                scheduler: WriteScheduler::new(lanes, max_pending),
                queued: BTreeMap::new(),
                executing: BTreeSet::new(),
                recovered_pending: BTreeSet::new(),
                cancels: BTreeSet::new(),
                drain: DrainState::Open,
                metrics: ExecutionMetrics::default(),
            }),
            drain_gate: tokio::sync::Mutex::new(DrainGateOwnership { _sealed: () }),
        }
    }

    /// Execution profile of this generation.
    #[must_use]
    pub const fn profile(&self) -> ExecutionProfile {
        self.profile
    }

    /// Whether this generation runs the concurrent reserved profile.
    #[must_use]
    pub const fn is_concurrent(&self) -> bool {
        matches!(self.profile, ExecutionProfile::Concurrent)
    }

    /// Generation identity, unique per installed execution.
    #[must_use]
    pub const fn generation_id(&self) -> u64 {
        self.generation_id
    }

    /// Fixed session-set limits bound at install.
    #[must_use]
    pub const fn limits(&self) -> ClientSetLimits {
        self.limits
    }

    /// Admission of the legacy unreserved `Apply` path: allowed only under
    /// the explicitly admitted serial profile, denied under a concurrent
    /// generation so old callers cannot bypass its scheduler.
    #[must_use]
    pub const fn unreserved_apply_admission(&self) -> UnreservedAdmission {
        match self.profile {
            ExecutionProfile::Serial => UnreservedAdmission::AllowedLegacySerial,
            ExecutionProfile::Concurrent => UnreservedAdmission::DeniedConcurrentGeneration,
        }
    }

    /// Whether restart recovery still blocks normal readiness.
    #[must_use]
    pub fn recovery_blocked(&self) -> bool {
        self.recovery_blocked.load(Ordering::SeqCst)
    }

    /// Currently uncertain operation identities in deterministic order:
    /// the drain/recovery blockers the caller must resolve.
    #[must_use]
    pub fn uncertain_operations(&self) -> Vec<OperationId> {
        self.with_inner(|inner| inner.scheduler.uncertain_operations())
            .unwrap_or_default()
    }

    /// Currently accepted but not completed operations.
    #[must_use]
    pub fn pending_count(&self) -> usize {
        self.with_inner(|inner| inner.scheduler.pending_count())
            .unwrap_or(0)
    }

    /// Currently executing operations.
    #[must_use]
    pub fn in_flight_count(&self) -> usize {
        self.with_inner(|inner| inner.scheduler.in_flight_count())
            .unwrap_or(0)
    }

    /// Free normal-write permits (evidence that waiting work holds none).
    #[must_use]
    pub fn available_normal_permits(&self) -> usize {
        self.normal_permits.available_permits()
    }

    /// Free protected permits (evidence the protected path survives normal
    /// saturation).
    #[must_use]
    pub fn available_protected_permits(&self) -> usize {
        self.protected_permits.available_permits()
    }

    /// Whether the exclusive drain gate is currently draining or fenced.
    #[must_use]
    pub fn is_draining(&self) -> bool {
        self.with_inner(|inner| inner.drain != DrainState::Open)
            .unwrap_or(true)
    }

    /// Whether a failed or incomplete drain fenced this execution.
    #[must_use]
    pub fn is_fenced(&self) -> bool {
        self.with_inner(|inner| inner.drain == DrainState::Fenced)
            .unwrap_or(true)
    }

    /// Oldest accepted operation by reservation order: starvation input.
    #[must_use]
    pub fn oldest_pending(&self) -> Option<(u64, OperationId)> {
        self.with_inner(|inner| inner.scheduler.oldest_pending())
            .ok()
            .flatten()
    }

    /// Snapshot of the redacted execution metrics.
    #[must_use]
    pub fn metrics_snapshot(&self) -> ExecutionMetrics {
        self.with_inner(|inner| inner.metrics).unwrap_or_default()
    }

    /// Acquires one protected permit without touching normal-write
    /// capacity. Returns `None` immediately when the protected lane is
    /// exhausted instead of queueing behind normal work.
    #[must_use]
    pub fn try_acquire_protected_permit(&self) -> Option<ProtectedPermit> {
        self.protected_permits
            .clone()
            .try_acquire_owned()
            .ok()
            .map(|permit| ProtectedPermit { _permit: permit })
    }

    /// Requests cancellation of one queued operation. The flag is honored
    /// at the next pre-submit recheck with a no-effect disposition; work
    /// already possibly submitted reconciles instead of vanishing.
    pub fn cancel_operation(&self, operation_id: &OperationId) -> bool {
        self.with_inner(|inner| {
            let known = inner.queued.contains_key(operation_id)
                || inner.recovered_pending.contains(operation_id);
            if known {
                inner.cancels.insert(operation_id.clone());
            }
            known
        })
        .unwrap_or(false)
    }

    /// Whether a cancellation was requested for this operation.
    #[must_use]
    pub fn is_cancelled(&self, operation_id: &OperationId) -> bool {
        self.with_inner(|inner| inner.cancels.contains(operation_id))
            .unwrap_or(false)
    }

    /// Submits one reserved write into the bounded scheduler.
    ///
    /// Runs the existing admitted receiving boundary first
    /// ([`ReservedWriteRequest::validate`]); a self-consistent caller
    /// fabrication passes shape only and still needs current owner
    /// evidence at execution time. Expired reservations fail closed here.
    /// Queue-full sheds with `Unavailable`; resubmitting the same identity
    /// with the same sealed digest is an idempotent no-op, while a
    /// changed digest under the same identity is an identity conflict.
    pub fn submit_reserved(
        &self,
        request: ReservedWriteRequest,
        now_ms: u64,
    ) -> Result<SubmitDisposition, AdapterError> {
        if !self.is_concurrent() {
            return Err(AdapterError::Store(StoreError::InvalidField {
                field: "store.write_path",
                reason: "reserved writes require the concurrent execution profile",
            }));
        }
        if self.recovery_blocked() {
            self.count_refused();
            return Err(AdapterError::Store(StoreError::Unavailable));
        }
        request.validate().map_err(AdapterError::Store)?;
        if u64::try_from(request.admission.expires_at_ms).is_ok_and(|expires| expires <= now_ms) {
            return Err(AdapterError::Store(StoreError::InvalidField {
                field: "admission.expires_at_ms",
                reason: "reservation expired before execution",
            }));
        }
        let operation_id = request.transition.identity.operation_id.clone();
        let projection = reservation_projection(&request);
        self.with_inner(|inner| {
            if inner.drain != DrainState::Open {
                inner.metrics.submit_refused_not_ready += 1;
                return Err(AdapterError::Store(StoreError::Unavailable));
            }
            if let Some(queued) = inner.queued.get(&operation_id) {
                if queued.request.admission.prepared_transition_digest
                    == request.admission.prepared_transition_digest
                {
                    inner.metrics.duplicates_suppressed += 1;
                    return Ok(SubmitDisposition::AlreadyQueued);
                }
                return Err(AdapterError::Store(StoreError::IdentityConflict));
            }
            match inner.scheduler.submit(projection) {
                Ok(()) => {
                    inner.metrics.submitted += 1;
                    inner.queued.insert(
                        operation_id,
                        QueuedReservedWrite {
                            request,
                            submitted_at_ms: now_ms,
                        },
                    );
                    Ok(SubmitDisposition::Accepted)
                }
                Err(ScheduleReject::QueueFull) => {
                    inner.metrics.queue_full_shed += 1;
                    Err(AdapterError::Store(StoreError::Unavailable))
                }
                Err(ScheduleReject::Draining) => {
                    inner.metrics.submit_refused_not_ready += 1;
                    Err(AdapterError::Store(StoreError::Unavailable))
                }
                Err(ScheduleReject::DuplicateOperation) => {
                    // Unreachable: the queued map above owns the same
                    // identity namespace and returned first.
                    Err(AdapterError::Store(StoreError::Unavailable))
                }
                Err(
                    ScheduleReject::EmptyScopes
                    | ScheduleReject::DuplicateScope
                    | ScheduleReject::UnsortedScopes
                    | ScheduleReject::InconsistentSequences,
                ) => Err(AdapterError::Store(StoreError::InvalidField {
                    field: "admission.scopes",
                    reason: "reservation projection failed scheduler structure",
                })),
                Err(
                    ScheduleReject::UnknownOperation
                    | ScheduleReject::NotReady
                    | ScheduleReject::AlreadyInFlight
                    | ScheduleReject::NotUncertain,
                ) => Err(AdapterError::Store(StoreError::Unavailable)),
            }
        })?
    }

    /// Executes every currently ready operation, bounded by free lanes.
    ///
    /// Ready operations run concurrently through [`join_all`] (bounded by
    /// the lane count the scheduler already enforced), each on its own
    /// normal-write permit acquired only after readiness. Scheduler guards
    /// drop before the first await, so waiting work holds no scheduler
    /// lock and no permit.
    pub async fn run_ready_batch(
        &self,
        now_ms: u64,
        transport: &impl ReservedAttemptTransport,
    ) -> Result<Vec<OpExecution>, AdapterError> {
        let (mut executed, reconciled) = self.run_batch_inner(now_ms, transport, false).await?;
        executed.extend(reconciled);
        Ok(executed)
    }

    /// Drains every possible effect, then runs one existing
    /// migration/genesis operation under actual exclusive ownership.
    ///
    /// Phase order: acquire the exclusive gate (a second concurrent drain
    /// fails closed instead of queueing behind the gate); close normal
    /// admission; disposition queued-not-started work without provider
    /// effects; drive ready work and reconcile in-flight/uncertain work
    /// through the transport; verify quiescence (an incomplete or unknown
    /// drain never grants exclusivity and stays fenced); run the existing
    /// operation; reopen with a fresh scheduler only on its success. A
    /// failed exclusive operation keeps the fenced state and its original
    /// error.
    pub async fn drain_for_migration<F, Fut, O>(
        &self,
        kind: ExclusiveOpKind,
        now_ms: u64,
        transport: &impl ReservedAttemptTransport,
        run_exclusive: F,
    ) -> Result<(DrainReport, O), AdapterError>
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = Result<O, AdapterError>>,
    {
        // Held ownership guard: lives until function end, so exactly one
        // drain runs at a time and the gate never doubles as a normal
        // writer lane. A second concurrent drain fails closed here instead
        // of queueing behind the gate.
        let _ownership = self.drain_gate.try_lock().map_err(|_| {
            self.with_inner(|inner| inner.metrics.drains_refused_busy += 1)
                .unwrap_or(());
            AdapterError::Store(StoreError::Unavailable)
        })?;
        // Recovery-blocked executions refuse the drain without touching
        // state: the owner denominator must resolve first through
        // `resolve_recovered`. Fencing here would punish an honest block.
        if self.recovery_blocked() {
            return Err(AdapterError::Store(StoreError::Unavailable));
        }
        self.with_inner(|inner| {
            if inner.drain != DrainState::Open {
                return Err(AdapterError::Store(StoreError::Unavailable));
            }
            inner.drain = DrainState::Draining;
            inner.scheduler.begin_drain();
            Ok(())
        })??;
        let outcome = self
            .drain_loop(kind, now_ms, transport, run_exclusive)
            .await;
        if outcome.is_err() {
            self.with_inner(|inner| {
                inner.drain = DrainState::Fenced;
                inner.metrics.drain_failures += 1;
            })
            .unwrap_or(());
        }
        outcome
    }

    /// Reopens a fenced execution after an accepted generation/schema
    /// cutover. The evidence bar matches install: only an accepted current
    /// generation with the expected schema and a live fence reopens. Any
    /// other state or evidence stays fenced.
    pub fn reopen_generation(&self, evidence: &ConcurrentEvidence) -> Result<(), AdapterError> {
        if !self.is_concurrent() {
            return Err(AdapterError::Store(StoreError::InvalidField {
                field: "execution.drain",
                reason: "reopen requires the concurrent execution profile",
            }));
        }
        let fenced = self
            .with_inner(|inner| inner.drain == DrainState::Fenced)
            .unwrap_or(false);
        if !fenced {
            return Err(AdapterError::Store(StoreError::InvalidField {
                field: "execution.drain",
                reason: "reopen requires a fenced execution",
            }));
        }
        evidence.validate()?;
        self.with_inner(|inner| {
            inner.scheduler = WriteScheduler::new(self.lanes, self.max_pending);
            inner.queued.clear();
            inner.executing.clear();
            inner.recovered_pending.clear();
            inner.cancels.clear();
            inner.drain = DrainState::Open;
        })?;
        Ok(())
    }

    /// Whether this generation may be uninstalled for a profile change:
    /// quiescent, open, and never recovery-blocked. Profile change is a
    /// drained generation transition, never a live switch.
    pub fn uninstall_readiness(&self) -> Result<(), AdapterError> {
        let ready = self
            .with_inner(|inner| {
                inner.scheduler.pending_count() == 0
                    && inner.drain == DrainState::Open
                    && !self.recovery_blocked()
            })
            .unwrap_or(false);
        if ready {
            Ok(())
        } else {
            Err(AdapterError::Store(StoreError::InvalidField {
                field: "execution.generation",
                reason: "profile change requires a drained quiescent generation",
            }))
        }
    }

    /// Reconstructs ephemeral scheduler state from the trusted durable
    /// denominator. Terminal outcomes need no entry; unknown or missing
    /// outcomes schedule as uncertain and block normal readiness until
    /// [`WriteExecution::resolve_recovered`] dispositions each one. Only
    /// the supplied denominator shapes the result: local memory is never
    /// canonical truth.
    pub fn recover_concurrent(
        limits: ClientSetLimits,
        lanes: NonZeroUsize,
        max_pending: NonZeroUsize,
        evidence: &ConcurrentEvidence,
        recovery: &DurableRecoverySet,
        now_ms: u64,
    ) -> Result<Self, AdapterError> {
        validate_execution_profile(limits, lanes, false)
            .map_err(|error| AdapterError::Config(error.to_string()))?;
        evidence.validate()?;
        let execution = Self::build(ExecutionProfile::Concurrent, limits, lanes, max_pending);
        let outcomes: BTreeMap<&OperationId, DurableOpOutcome> = recovery
            .outcomes
            .iter()
            .map(|(id, outcome)| (id, *outcome))
            .collect();
        execution.with_inner(|inner| {
            for projection in &recovery.reservations {
                let outcome = outcomes.get(&projection.operation_id).copied();
                if matches!(
                    outcome,
                    Some(
                        DurableOpOutcome::Committed
                            | DurableOpOutcome::Rejected
                            | DurableOpOutcome::DeadLetter
                            | DurableOpOutcome::Cancelled
                    )
                ) {
                    continue;
                }
                inner
                    .scheduler
                    .submit(projection.clone())
                    .map_err(map_recovery_reject)?;
                inner
                    .scheduler
                    .mark_in_flight(&projection.operation_id, now_ms)
                    .map_err(map_recovery_reject)?;
                inner
                    .scheduler
                    .complete(
                        &projection.operation_id,
                        CompletionOutcome::Unknown { retry_after_ms: 0 },
                        now_ms,
                    )
                    .map_err(map_recovery_reject)?;
                inner
                    .recovered_pending
                    .insert(projection.operation_id.clone());
            }
            Ok::<(), AdapterError>(())
        })??;
        let blocked = execution
            .with_inner(|inner| !inner.scheduler.uncertain_operations().is_empty())
            .unwrap_or(true);
        execution.recovery_blocked.store(blocked, Ordering::SeqCst);
        Ok(execution)
    }

    /// Dispositions one recovered uncertain operation through its durable
    /// terminal outcome. A terminal outcome frees dependent scopes; an
    /// `Unknown` redisposition keeps the block. The block lifts only when
    /// no uncertain operation remains.
    pub fn resolve_recovered(
        &self,
        operation_id: &OperationId,
        outcome: DurableOpOutcome,
        now_ms: u64,
    ) -> Result<(), AdapterError> {
        let terminal = match outcome {
            DurableOpOutcome::Committed => Some(CompletionOutcome::Committed),
            DurableOpOutcome::Rejected => Some(CompletionOutcome::Rejected),
            DurableOpOutcome::DeadLetter => Some(CompletionOutcome::DeadLetter),
            DurableOpOutcome::Cancelled => Some(CompletionOutcome::Cancelled),
            DurableOpOutcome::Unknown => None,
        };
        self.with_inner(|inner| {
            if !inner.recovered_pending.contains(operation_id) {
                return Err(AdapterError::Store(StoreError::InvalidField {
                    field: "execution.recovery",
                    reason: "operation is not a pending recovered uncertainty",
                }));
            }
            if let Some(terminal) = terminal {
                inner
                    .scheduler
                    .resolve_uncertain(operation_id, terminal, now_ms)
                    .map_err(|_| {
                        AdapterError::Store(StoreError::InvalidField {
                            field: "execution.recovery",
                            reason: "recovered operation cannot resolve",
                        })
                    })?;
                inner.recovered_pending.remove(operation_id);
                inner.cancels.remove(operation_id);
            }
            Ok(())
        })??;
        let blocked = self
            .with_inner(|inner| !inner.scheduler.uncertain_operations().is_empty())
            .unwrap_or(true);
        self.recovery_blocked.store(blocked, Ordering::SeqCst);
        Ok(())
    }

    /// Runs one batch, optionally as the drain loop's driver. Returns the
    /// per-attempt outcomes plus the reconciliation outcomes for every
    /// uncertainty still held at batch end, so an unknown operation is
    /// re-reconciled on later batches until it resolves: dependent scopes
    /// pause, they never wedge until migration.
    async fn run_batch_inner(
        &self,
        now_ms: u64,
        transport: &impl ReservedAttemptTransport,
        during_drain: bool,
    ) -> Result<(Vec<OpExecution>, Vec<OpExecution>), AdapterError> {
        if self.recovery_blocked() {
            return Err(AdapterError::Store(StoreError::Unavailable));
        }
        let marked = self.snapshot_ready(now_ms, during_drain)?;
        let executions = marked
            .into_iter()
            .map(|marked| self.execute_marked(marked, now_ms, transport));
        let executed: Vec<OpExecution> = join_all(executions).await.into_iter().flatten().collect();
        let reconciled = self.reconcile_uncertain(now_ms, transport).await;
        Ok((executed, reconciled))
    }

    /// Snapshots the ready set and marks it in flight under one short
    /// scheduler guard. The guard drops before any await: nothing here
    /// waits on a predecessor, the network, or a permit while holding it.
    fn snapshot_ready(
        &self,
        now_ms: u64,
        during_drain: bool,
    ) -> Result<Vec<MarkedOp>, AdapterError> {
        self.with_inner(|inner| {
            if inner.drain != DrainState::Open && !during_drain {
                return Err(AdapterError::Store(StoreError::Unavailable));
            }
            let mut marked = Vec::new();
            for operation_id in inner.scheduler.ready(now_ms) {
                // Recovered uncertainties carry no executable payload and
                // never execute here: they order and block scopes until
                // reconciliation resolves them.
                if !inner.queued.contains_key(&operation_id) {
                    continue;
                }
                // Readiness is rechecked at execution time by the scheduler
                // itself; a concurrent drain disposition between `ready` and
                // `mark_in_flight` fails closed here instead of executing.
                inner
                    .scheduler
                    .mark_in_flight(&operation_id, now_ms)
                    .map_err(|_| AdapterError::Store(StoreError::Unavailable))?;
                inner.executing.insert(operation_id.clone());
                if let Some(queued) = inner.queued.get(&operation_id) {
                    let wait_ms = now_ms.saturating_sub(queued.submitted_at_ms);
                    inner.metrics.oldest_ready_wait_max_ms =
                        inner.metrics.oldest_ready_wait_max_ms.max(wait_ms);
                    marked.push(MarkedOp {
                        operation_id,
                        queued: queued.clone(),
                    });
                }
            }
            Ok(marked)
        })?
    }

    /// Executes one marked operation through permit, recheck, gate, and
    /// attempt. The normal-write permit is held across the attempt and
    /// releases when this future resolves; release never implies
    /// completion, which stays explicit below. Returns `None` when the
    /// attempt went unknown: the batch-end reconciliation pass owns that
    /// outcome.
    async fn execute_marked(
        &self,
        marked: MarkedOp,
        now_ms: u64,
        transport: &impl ReservedAttemptTransport,
    ) -> Option<OpExecution> {
        let operation_id = marked.operation_id.clone();
        let Some(_permit) = self.acquire_normal_permit().await else {
            return Some(OpExecution::ExecutionError {
                operation_id,
                error: AdapterError::Store(StoreError::Unavailable),
            });
        };
        // Pre-submit recheck under a short guard, still before any
        // provider effect: cancellation, drain onset, or a vanished entry
        // dispositions here with zero transport calls.
        match self.presubmit_recheck(&operation_id) {
            Presubmit::Gone => {
                return Some(OpExecution::DrainedWithoutEffect { operation_id });
            }
            Presubmit::Cancelled => {
                return Some(self.complete_cancelled(&operation_id, now_ms));
            }
            Presubmit::Proceed => {}
        }
        if self.is_cancelled(&operation_id) || self.is_draining() {
            return Some(self.complete_cancelled(&operation_id, now_ms));
        }
        let attempt = executable_attempt(&operation_id, &marked.queued.request);
        let gate = transport.read_submission_gate(self, &attempt, now_ms).await;
        if !gate.submittable() {
            if gate.owner_current && !gate.fence_matches {
                return Some(self.complete_rejected(
                    &operation_id,
                    now_ms,
                    StoreError::FenceMismatch,
                ));
            }
            return Some(self.complete_cancelled(&operation_id, now_ms));
        }
        self.run_attempt(&operation_id, attempt, now_ms, transport)
            .await
    }

    /// Acquires one normal-write permit, counting acquisitions that queued
    /// behind checked-out sessions as wait events.
    async fn acquire_normal_permit(&self) -> Option<OwnedSemaphorePermit> {
        if let Ok(permit) = self.normal_permits.clone().try_acquire_owned() {
            return Some(permit);
        }
        self.with_inner(|inner| inner.metrics.permit_waited_events += 1)
            .unwrap_or(());
        self.normal_permits.clone().acquire_owned().await.ok()
    }

    /// Short-guarded pre-submit recheck with no provider effects.
    fn presubmit_recheck(&self, operation_id: &OperationId) -> Presubmit {
        self.with_inner(|inner| {
            if !inner.queued.contains_key(operation_id) {
                return Presubmit::Gone;
            }
            if inner.cancels.contains(operation_id) || inner.drain != DrainState::Open {
                return Presubmit::Cancelled;
            }
            Presubmit::Proceed
        })
        .unwrap_or(Presubmit::Gone)
    }

    /// Runs the permitted attempt and completes the scheduler entry.
    /// Unknown outcomes only mark uncertainty here (`None`): the
    /// batch-end reconciliation pass owns their outcome.
    async fn run_attempt(
        &self,
        operation_id: &OperationId,
        attempt: ExecutableAttempt,
        now_ms: u64,
        transport: &impl ReservedAttemptTransport,
    ) -> Option<OpExecution> {
        match transport.execute_attempt(self, &attempt).await {
            AttemptOutcome::Committed(receipt) => Some(self.complete_terminal_into(
                operation_id,
                CompletionOutcome::Committed,
                now_ms,
                |metrics| metrics.committed += 1,
                OpExecution::Committed {
                    operation_id: operation_id.clone(),
                    receipt,
                    reconciled: false,
                },
            )),
            AttemptOutcome::Rejected(error) => Some(self.complete_terminal_into(
                operation_id,
                CompletionOutcome::Rejected,
                now_ms,
                |metrics| metrics.rejected += 1,
                OpExecution::Rejected {
                    operation_id: operation_id.clone(),
                    error,
                },
            )),
            AttemptOutcome::DeadLetter => Some(self.complete_terminal_into(
                operation_id,
                CompletionOutcome::DeadLetter,
                now_ms,
                |metrics| metrics.dead_lettered += 1,
                OpExecution::DeadLetter {
                    operation_id: operation_id.clone(),
                },
            )),
            AttemptOutcome::Cancelled => Some(self.complete_cancelled(operation_id, now_ms)),
            AttemptOutcome::Unknown { retry_after_ms } => {
                match self.mark_unknown(operation_id, retry_after_ms, now_ms) {
                    Ok(()) => None,
                    Err(error) => Some(OpExecution::ExecutionError {
                        operation_id: operation_id.clone(),
                        error,
                    }),
                }
            }
        }
    }

    /// Records an unknown outcome on the scheduler entry. Reconciliation
    /// runs separately through [`WriteExecution::reconcile_uncertain`].
    /// Synchronous: marking touches only the short-held scheduler guard.
    fn mark_unknown(
        &self,
        operation_id: &OperationId,
        retry_after_ms: u64,
        now_ms: u64,
    ) -> Result<(), AdapterError> {
        self.with_inner(|inner| {
            inner
                .scheduler
                .complete(
                    operation_id,
                    CompletionOutcome::Unknown { retry_after_ms },
                    now_ms,
                )
                .map(|()| {
                    inner.metrics.unknown_observed += 1;
                })
                .map_err(|_| AdapterError::Store(StoreError::Unavailable))
        })?
    }

    /// Reconciles every currently uncertain operation through the
    /// transport, resolving terminal outcomes and keeping the rest.
    /// Returns one outcome per reconciled operation: resolutions carry
    /// their terminal disposition, retained uncertainties carry
    /// `UnknownRetained` with payload and identity preserved.
    async fn reconcile_uncertain(
        &self,
        now_ms: u64,
        transport: &impl ReservedAttemptTransport,
    ) -> Vec<OpExecution> {
        let mut outcomes = Vec::new();
        for operation_id in self.uncertain_operations() {
            outcomes.push(
                match transport.reconcile_unknown(self, &operation_id).await {
                    ReconcileOutcome::Committed(receipt) => self.complete_terminal_into(
                        &operation_id,
                        CompletionOutcome::Committed,
                        now_ms,
                        |metrics| {
                            metrics.committed += 1;
                            metrics.committed_via_reconcile += 1;
                        },
                        OpExecution::Committed {
                            operation_id: operation_id.clone(),
                            receipt,
                            reconciled: true,
                        },
                    ),
                    ReconcileOutcome::Absent => self.complete_terminal_into(
                        &operation_id,
                        CompletionOutcome::DeadLetter,
                        now_ms,
                        |metrics| {
                            metrics.dead_lettered += 1;
                            metrics.reconciled_absent += 1;
                        },
                        OpExecution::DeadLetter {
                            operation_id: operation_id.clone(),
                        },
                    ),
                    ReconcileOutcome::StillUnknown => {
                        self.with_inner(|inner| {
                            inner.metrics.still_unknown_retained += 1;
                        })
                        .unwrap_or(());
                        // Payload retained: the operation keeps its identity
                        // and its explicit reconciliation ownership.
                        OpExecution::UnknownRetained {
                            operation_id: operation_id.clone(),
                        }
                    }
                },
            );
        }
        outcomes
    }

    /// Completes one entry terminally, drops its payload and executing
    /// mark, counts the metric, and returns the caller-built outcome; a
    /// defensive scheduler failure surfaces as `ExecutionError` with the
    /// operation left in explicit reconciliation ownership.
    ///
    /// Uncertain entries resolve through `resolve_uncertain`: the
    /// scheduler refuses terminal `complete` calls on uncertainties so an
    /// unknown outcome can never be completed without its reconciliation
    /// act.
    fn complete_terminal_into(
        &self,
        operation_id: &OperationId,
        outcome: CompletionOutcome,
        now_ms: u64,
        count: impl FnOnce(&mut ExecutionMetrics),
        success: OpExecution,
    ) -> OpExecution {
        let completed = self.with_inner(|inner| {
            let uncertain = inner
                .scheduler
                .uncertain_operations()
                .contains(operation_id);
            let result = if uncertain {
                inner
                    .scheduler
                    .resolve_uncertain(operation_id, outcome, now_ms)
            } else {
                inner.scheduler.complete(operation_id, outcome, now_ms)
            };
            result
                .map(|()| {
                    count(&mut inner.metrics);
                })
                .map_err(|_| AdapterError::Store(StoreError::Unavailable))
        });
        match completed {
            Ok(Ok(())) => {
                self.with_inner(|inner| {
                    inner.queued.remove(operation_id);
                    inner.executing.remove(operation_id);
                    inner.cancels.remove(operation_id);
                })
                .unwrap_or(());
                success
            }
            Ok(Err(error)) | Err(error) => OpExecution::ExecutionError {
                operation_id: operation_id.clone(),
                error,
            },
        }
    }

    /// Safe pre-effect disposition: completes as cancelled and counts the
    /// shed without any provider effect.
    fn complete_cancelled(&self, operation_id: &OperationId, now_ms: u64) -> OpExecution {
        self.complete_terminal_into(
            operation_id,
            CompletionOutcome::Cancelled,
            now_ms,
            |metrics| metrics.cancelled_before_effect += 1,
            OpExecution::CancelledBeforeEffect {
                operation_id: operation_id.clone(),
            },
        )
    }

    /// Deterministic rejection disposition with the exact cause.
    fn complete_rejected(
        &self,
        operation_id: &OperationId,
        now_ms: u64,
        error: StoreError,
    ) -> OpExecution {
        self.complete_terminal_into(
            operation_id,
            CompletionOutcome::Rejected,
            now_ms,
            |metrics| metrics.rejected += 1,
            OpExecution::Rejected {
                operation_id: operation_id.clone(),
                error,
            },
        )
    }

    /// Counts a submit refused while recovery-blocked.
    fn count_refused(&self) {
        self.with_inner(|inner| inner.metrics.submit_refused_not_ready += 1)
            .unwrap_or(());
    }

    /// Full drain loop: disposition queued work, drive ready work,
    /// reconcile uncertainties, and verify quiescence.
    async fn drain_loop<F, Fut, O>(
        &self,
        kind: ExclusiveOpKind,
        now_ms: u64,
        transport: &impl ReservedAttemptTransport,
        run_exclusive: F,
    ) -> Result<(DrainReport, O), AdapterError>
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = Result<O, AdapterError>>,
    {
        let mut report = DrainReport {
            kind,
            committed: 0,
            cancelled_queued: 0,
            reconciled: 0,
        };
        self.dispose_queued(now_ms, &mut report)?;
        let mut wait_rounds = 0usize;
        let mut last_pending = self.pending_count();
        loop {
            if self.is_quiescent() {
                break;
            }
            // Newly unblocked queued work dispositions every round: an
            // operation freed by a resolved predecessor never executes
            // under a drain.
            self.dispose_queued(now_ms, &mut report)?;
            let (executed, reconciled) = self.run_batch_inner(now_ms, transport, true).await?;
            let mut resolved = 0u64;
            for execution in executed.iter().chain(reconciled.iter()) {
                match execution {
                    OpExecution::Committed { reconciled, .. } => {
                        report.committed += 1;
                        if *reconciled {
                            report.reconciled += 1;
                            resolved += 1;
                        }
                    }
                    OpExecution::DeadLetter { .. } => {
                        // Dead letters observed inside the drain resolve an
                        // ordering position: absent-proofs from the
                        // reconcile pass, or proven non-applications from
                        // the drive phase.
                        report.reconciled += 1;
                        resolved += 1;
                    }
                    OpExecution::Rejected { .. }
                    | OpExecution::CancelledBeforeEffect { .. }
                    | OpExecution::DrainedWithoutEffect { .. }
                    | OpExecution::UnknownRetained { .. }
                    | OpExecution::ExecutionError { .. } => {}
                }
            }
            let pending = self.pending_count();
            if pending < last_pending || resolved > 0 || !executed.is_empty() {
                last_pending = pending;
                wait_rounds = 0;
                continue;
            }
            // No progress: in-flight work held outside this drain (bounded
            // poll) or a quiescence failure (never fake an empty drain).
            // Uncertain work reconciles instead of waiting: it never
            // completes on its own, so only non-uncertain in-flight work
            // justifies another round.
            let waiting = self
                .in_flight_count()
                .saturating_sub(self.uncertain_operations().len());
            if waiting > 0 {
                wait_rounds += 1;
                if wait_rounds > DRAIN_MAX_WAIT_ROUNDS {
                    return Err(AdapterError::Store(StoreError::Unavailable));
                }
                tokio::time::sleep(DRAIN_POLL_INTERVAL).await;
                continue;
            }
            return Err(AdapterError::Store(StoreError::Unavailable));
        }
        let exclusive = run_exclusive().await?;
        self.with_inner(|inner| {
            inner.scheduler = WriteScheduler::new(self.lanes, self.max_pending);
            inner.queued.clear();
            inner.executing.clear();
            inner.recovered_pending.clear();
            inner.cancels.clear();
            inner.drain = DrainState::Open;
            inner.metrics.drains_completed += 1;
            Ok::<(), AdapterError>(())
        })??;
        Ok((report, exclusive))
    }

    /// Dispositions queued-not-started work without provider effects.
    ///
    /// Entries never marked in flight, holding no uncertainty, and carrying
    /// executable payload are marked and immediately completed as
    /// cancelled: marking proves they held no predecessor wait that another
    /// owner still drives, and cancellation precedes any permit, gate, or
    /// attempt, so no provider effect is possible. In-flight, uncertain,
    /// recovered, and not-yet-ready work stays for the drive and reconcile
    /// phases of a later round.
    fn dispose_queued(&self, now_ms: u64, report: &mut DrainReport) -> Result<(), AdapterError> {
        self.with_inner(|inner| {
            for operation_id in inner.queued.keys().cloned().collect::<Vec<_>>() {
                if inner.executing.contains(&operation_id)
                    || inner.recovered_pending.contains(&operation_id)
                    || inner
                        .scheduler
                        .uncertain_operations()
                        .contains(&operation_id)
                {
                    continue;
                }
                // Only entries the scheduler still shows as never started
                // disposition here; anything a concurrent batch marked in
                // flight after the snapshot (or that is not ready yet)
                // stays for the drive phase or a later round.
                if inner
                    .scheduler
                    .mark_in_flight(&operation_id, now_ms)
                    .is_err()
                {
                    continue;
                }
                inner.executing.insert(operation_id.clone());
                match inner
                    .scheduler
                    .complete(&operation_id, CompletionOutcome::Cancelled, now_ms)
                {
                    Ok(()) => {
                        inner.queued.remove(&operation_id);
                        inner.executing.remove(&operation_id);
                        inner.cancels.remove(&operation_id);
                        inner.metrics.cancelled_before_effect += 1;
                        report.cancelled_queued += 1;
                    }
                    Err(_) => {
                        return Err(AdapterError::Store(StoreError::Unavailable));
                    }
                }
            }
            Ok(())
        })?
    }

    /// Whether the scheduler reached quiescence: nothing pending and
    /// nothing in flight. Uncertain work keeps its entry, so an
    /// unresolved drain never observes this.
    fn is_quiescent(&self) -> bool {
        self.with_inner(|inner| {
            inner.scheduler.pending_count() == 0 && inner.scheduler.in_flight_count() == 0
        })
        .unwrap_or(false)
    }

    /// Runs one closure under the state lock.
    fn with_inner<R>(&self, apply: impl FnOnce(&mut Inner) -> R) -> Result<R, AdapterError> {
        match self.state.lock() {
            Ok(mut inner) => Ok(apply(&mut inner)),
            Err(_) => Err(AdapterError::Store(StoreError::Unavailable)),
        }
    }
}

/// Short-guarded pre-submit recheck result.
enum Presubmit {
    Proceed,
    Gone,
    Cancelled,
}

/// One scheduler-marked operation handed to the attempt pipeline.
struct MarkedOp {
    operation_id: OperationId,
    queued: QueuedReservedWrite,
}

/// Derives the conflict-readiness projection from the sealed admission.
///
/// The admission shape already guarantees sorted-unique scopes
/// (`validate_shape`), so this maps fields without renormalizing: a
/// corrupt projection fails in the scheduler, never silently repaired
/// here.
fn reservation_projection(request: &ReservedWriteRequest) -> ReservationProjection {
    ReservationProjection {
        operation_id: request.transition.identity.operation_id.clone(),
        reservation_order: request.admission.reservation_order,
        scopes: request
            .admission
            .scopes
            .iter()
            .map(|scope| ReservedScopeProjection {
                scope: scope.scope.clone(),
                reserved_sequence: scope.reserved_sequence,
            })
            .collect(),
    }
}

/// Builds the executable attempt from the queued admitted request.
fn executable_attempt(
    operation_id: &OperationId,
    request: &ReservedWriteRequest,
) -> ExecutableAttempt {
    ExecutableAttempt {
        operation_id: operation_id.clone(),
        context: request.context.clone(),
        transition: request.transition.clone(),
        expected_revision_heads: request.expected_revision_heads.clone(),
        expected_ordering_heads: request.expected_ordering_heads.clone(),
        reservation_order: request.admission.reservation_order,
        expires_at_ms: request.admission.expires_at_ms,
    }
}

/// Maps a recovery-denominator scheduler rejection to a closed error.
fn map_recovery_reject(reject: ScheduleReject) -> AdapterError {
    match reject {
        ScheduleReject::QueueFull | ScheduleReject::Draining => {
            AdapterError::Store(StoreError::Unavailable)
        }
        _ => AdapterError::Store(StoreError::InvalidField {
            field: "execution.recovery",
            reason: "durable recovery denominator failed scheduler structure",
        }),
    }
}

/// Current wall-clock time in Unix milliseconds for production observation
/// points. Deterministic paths always take explicit `now_ms` instead.
pub(crate) fn current_time_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| {
            u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
        })
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used, clippy::unwrap_used)]

    use super::*;

    #[test]
    fn provider_gate_truth_table() {
        assert!(ProviderGate::open().submittable());
        assert!(!ProviderGate::closed().submittable());
        let fence_shut = ProviderGate {
            owner_current: true,
            fence_matches: false,
            not_expired: true,
        };
        assert!(!fence_shut.submittable());
        let expired = ProviderGate {
            owner_current: true,
            fence_matches: true,
            not_expired: false,
        };
        assert!(!expired.submittable());
    }

    #[test]
    fn unreserved_admission_splits_by_profile() {
        assert!(UnreservedAdmission::AllowedLegacySerial.allowed());
        assert!(!UnreservedAdmission::DeniedConcurrentGeneration.allowed());
    }

    #[test]
    fn recovery_reject_mapping_sheds_capacity_and_fails_structure_closed() {
        assert_eq!(
            map_recovery_reject(ScheduleReject::QueueFull),
            AdapterError::Store(StoreError::Unavailable)
        );
        assert_eq!(
            map_recovery_reject(ScheduleReject::InconsistentSequences),
            AdapterError::Store(StoreError::InvalidField {
                field: "execution.recovery",
                reason: "durable recovery denominator failed scheduler structure",
            })
        );
    }

    #[test]
    fn serial_install_admits_legacy_and_refuses_concurrent_shape() {
        use std::num::NonZeroUsize;

        let execution = WriteExecution::install_serial(
            ClientSetLimits::compatibility(),
            NonZeroUsize::new(4).expect("queue"),
        )
        .expect("serial installs");
        assert_eq!(execution.profile(), ExecutionProfile::Serial);
        assert!(!execution.is_concurrent());
        assert!(execution.unreserved_apply_admission().allowed());
        assert_eq!(execution.available_normal_permits(), 1);
        assert_eq!(execution.available_protected_permits(), 1);
    }
}
