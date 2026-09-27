//! Kernel `WriteCoordinator`: reservations plus per-scope concurrent execution
//! (issue #1926).
//!
//! Architecture traceability: `I5.6` stages the complete immutable operation in
//! ORS and serializes by Ordering Scope; `I5.7` requires the Kernel to
//! atomically reserve all declared Ordering Scopes in ORS, assign one
//! monotonic `reservation_order`, issue a `WriterReservationToken`, serialize
//! one in-flight canonical transition per Ordering Scope, and permit disjoint
//! scopes to execute concurrently. Reservation state is distinct from the
//! canonical `OrderingHead`; recovery reconciles reservations against canonical
//! receipts and heads before allocating new work.
//!
//! ## Owner table
//!
//! ```text
//! Owner                           Evidence
//! ------------------------------- -------------------------------------------
//! ORS (`RedbRecoveryStore`)       uncommitted reservation order, scope
//!                                 sequences, lifecycle states, envelopes,
//!                                 predecessor fairness, canonical-head and
//!                                 recovery-block checks, terminal/gap closure
//! This module (`WriteCoordinator`) one in-flight canonical execution per
//!                                 Ordering Scope (in-memory, across threads),
//!                                 disjoint-scope concurrency, configurable
//!                                 executor lanes, one fair ready-scope
//!                                 scheduler over those lanes, per-scope-head
//!                                 retry delay, starvation metrics, drained
//!                                 generation switch, recovery listing before
//!                                 reallocation
//! Store                           committed heads and `WriteReceipt`s (evidence
//!                                 the caller reconciles through `finalize`)
//! ```
//!
//! This module mints no sequences, orders, digests, or receipts: every durable
//! number comes from the single ORS write transaction in
//! [`OperationalRecoveryStore::stage_and_reserve`]. It grants no authority and
//! interprets no payload: envelopes stay opaque.
//!
//! ## Lifecycle
//!
//! ```text
//! reserve -> mark_eligible -> enqueue_ready (one fair ready-scope queue)
//!   -> dispatch_ready (guard held across the single canonical transaction)
//!   -> drop guard -> finalize(receipt) | release | mark_unknown ->
//!   finalize(receipt)
//! ```
//!
//! `begin_execution` is the same gate without queueing: it admits one already
//! eligible token directly. Both acquire the in-memory per-scope permits
//! first, then perform the durable `Eligible -> Executing` transition under
//! the exact immutable writer epoch. A durable refusal rolls the permits back,
//! so a failed execution never wedges its scopes. The returned
//! [`ScopeExecutionGuard`] releases its scopes on drop: one canonical
//! transaction may be in flight per Ordering Scope, while disjoint scopes stay
//! concurrent. Lane exhaustion and generation-switch discipline are enforced
//! here; predecessor fairness, canonical-head verification, and
//! recovery-blocked scopes are enforced durably inside ORS and surface here as
//! the owner [`OrsError`].
//!
//! ## Fair ready-scope scheduling
//!
//! Every executor lane reads the same in-memory ready queue of Ordering Scope
//! heads. A head enters it exactly once, through
//! [`WriteCoordinator::enqueue_ready`], which first performs the durable
//! `Reserved -> Eligible` transition for that same token: a head with a
//! pending predecessor or a moved canonical head is never queued.
//! [`WriteCoordinator::dispatch_ready`] then hands the longest-waiting
//! dispatchable head to the next free lane, so a burst on one scope can never
//! starve another. A head is dispatchable when none of its declared scopes
//! currently holds a canonical execution permit and no retry delay is pending
//! on it; a head that is not dispatchable is skipped, never a lane-wide stall.
//!
//! [`WriteCoordinator::delay_scope_head`] parks one scope head for a bounded
//! retry: the delay applies to that head alone, so a retrying head never
//! blocks a lane or another scope. Lanes are a concurrency bound, never a
//! global writer gate: disjoint scopes share the pool and commit concurrently.
//!
//! [`WriteCoordinator::metrics`] reports the five I5.7 starvation signals
//! (oldest-ready age, per-scope wait, head retries, reservation conflicts,
//! executor utilization) as plain typed values. It is observation only and
//! gates nothing.
//!
//! ## Recovery rule
//!
//! After a restart the caller lists [`WriteCoordinator::unresolved`] to
//! exhaustion and reconciles every recovered reservation against its
//! `WriteReceipt`/canonical head through [`WriteCoordinator::finalize`]
//! before the scope accepts new execution. ORS refuses reallocation on
//! blocked scopes (`ScopeRecoveryRequired`) and refuses head jumps
//! (`OrderingHeadMismatch`); the coordinator never bypasses either.
//!
//! The ready queue and the retry delays are per-generation in-memory
//! scheduling state, exactly like the scope permits: a restart discards them
//! and the durable `Eligible` reservations they described come back through
//! [`WriteCoordinator::unresolved`] instead, so no head is ever lost or
//! silently re-ordered across a generation.

use std::collections::{BTreeMap, BTreeSet};
use std::num::NonZeroUsize;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use eliot_ors::{
    CanonicalReconciliation, EpochIdentity, OperationalRecoveryStore, OrsError, RedbRecoveryStore,
    ReservationRecord, ReservationRequest, WriterReservationToken,
};

/// Desktop default from I5.7: `writer_executors = min(4, logical_cpu_count)`.
///
/// Runtime composition choice surfaced as an explicit helper so callers name
/// the default instead of hiding a constant inside the coordinator core.
#[must_use]
pub fn default_executor_lanes() -> NonZeroUsize {
    let parallelism = std::thread::available_parallelism().map_or(1, NonZeroUsize::get);
    match NonZeroUsize::new(parallelism.clamp(1, 4)) {
        Some(lanes) => lanes,
        None => NonZeroUsize::MIN,
    }
}

/// Fixed coordinator construction: the executor lane bound for one generation.
///
/// A lane-count change is never a live mutation; it is a drained generation
/// switch through [`WriteCoordinator::reconfigure_lanes`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WriteCoordinatorConfig {
    executor_lanes: NonZeroUsize,
}

impl WriteCoordinatorConfig {
    /// Builds the fixed lane bound for one coordinator generation.
    #[must_use]
    pub const fn new(executor_lanes: NonZeroUsize) -> Self {
        Self { executor_lanes }
    }

    /// Executor lane bound: the maximum concurrent canonical executions.
    #[must_use]
    pub const fn executor_lanes(self) -> NonZeroUsize {
        self.executor_lanes
    }
}

/// Typed failure for coordinator admission and execution gating.
///
/// Every variant fails closed before or without a durable effect the caller is
/// not entitled to: scope conflicts never reach ORS, an exhausted lane pool is
/// an explicit refusal instead of an implicit queue, and a durable refusal
/// rolls the in-memory permits back. ORS lifecycle refusals (predecessor
/// pending, head mismatch, recovery blocked, stale epoch) pass through
/// unchanged as [`CoordinatorError::Ors`].
#[derive(Debug, thiserror::Error)]
pub enum CoordinatorError {
    /// The token declares no ordering scopes; nothing could order it.
    #[error("reservation token carries no ordering scopes")]
    EmptyScopeSet,
    /// The token repeats an ordering scope.
    #[error("reservation token repeats ordering scope {scope}")]
    DuplicateScope {
        /// The repeated scope identity.
        scope: String,
    },
    /// The token scopes are not in stable sorted order. Sorted acquisition is
    /// the contract order (I5.7) and keeps every generation's precedence
    /// identical; the coordinator renormalizes nothing.
    #[error("reservation token scopes are not in stable sorted order")]
    UnsortedScopes,
    /// The scope already holds one in-flight canonical transaction.
    #[error("ordering scope {scope} already has one in-flight canonical transaction")]
    ScopeBusy {
        /// The busy scope identity.
        scope: String,
    },
    /// All executor lanes are in flight; shed or retry instead of queueing.
    #[error("executor lanes exhausted ({lanes} canonical executions in flight)")]
    LanesExhausted {
        /// The fixed lane bound.
        lanes: usize,
    },
    /// The reservation is already a queued ready scope head; one reservation
    /// has exactly one ready head, so a duplicate admission is refused instead
    /// of silently giving the same head two queue positions.
    #[error("reservation {reservation_id} is already a queued ready scope head")]
    AlreadyQueued {
        /// The duplicated reservation identity.
        reservation_id: String,
    },
    /// No ready or executing head declares the named Ordering Scope, so a
    /// retry delay would park nothing. Refused instead of recorded silently.
    #[error("ordering scope {scope} has no ready or executing scope head to delay")]
    NoScopeHead {
        /// The scope identity that holds no head.
        scope: String,
    },
    /// The requested per-scope retry delay leaves the representable clock
    /// range; no head is parked rather than parking it for an unbounded time.
    #[error("retry delay of {delay_ms} ms is outside the representable clock range")]
    RetryDelayOutOfRange {
        /// The refused delay in milliseconds.
        delay_ms: u128,
    },
    /// A lane-count change requires a drained generation switch.
    #[error(
        "coordinator is not drained ({in_flight} canonical executions in flight, {queued} ready scope heads queued)"
    )]
    NotDrained {
        /// Currently in-flight canonical executions.
        in_flight: usize,
        /// Ready scope heads still queued for this generation.
        queued: usize,
    },
    /// Durable ORS lifecycle refusal, preserved verbatim.
    #[error(transparent)]
    Ors(#[from] eliot_ors::OrsError),
}

/// Monotonic admission position of one ready scope head in the single shared
/// ready-scope scheduler.
///
/// `I5.7` line 61: "configurable executor lanes share one fair ready-scope
/// scheduler;". The ticket is the scheduler's only ordering input: it is
/// assigned once, when the reservation becomes a ready scope head, so the
/// longest-waiting (lowest-ticket) dispatchable head is always the next one
/// dispatched. Ties are impossible: positions are strictly increasing per
/// coordinator generation.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct ReadyScopeTicket(u64);

impl ReadyScopeTicket {
    /// Zero-based admission position, strictly increasing per generation.
    #[must_use]
    pub const fn position(self) -> u64 {
        self.0
    }
}

/// One reservation admitted to the fair ready-scope scheduler.
///
/// The caller keeps this value as the acknowledgement that the reservation
/// holds a place in the queue; the coordinator holds the authoritative head,
/// so a dropped or duplicated value can never create a second head.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReadyReservation {
    ticket: ReadyScopeTicket,
    token: WriterReservationToken,
    scopes: Vec<String>,
}

impl ReadyReservation {
    /// Queue position of this ready scope head.
    #[must_use]
    pub const fn ticket(&self) -> ReadyScopeTicket {
        self.ticket
    }

    /// The exact token that is queued; the scheduler never re-derives it.
    #[must_use]
    pub const fn token(&self) -> &WriterReservationToken {
        &self.token
    }

    /// Declared Ordering Scopes held by this head, in stable sorted order.
    #[must_use]
    pub fn scopes(&self) -> &[String] {
        &self.scopes
    }
}

/// Executor lane occupancy at one observation.
///
/// Lanes are a concurrency bound over disjoint scopes, not a global writer
/// gate: `in_flight` counts the canonical transactions currently executing and
/// `queued_reservations` the ready heads still waiting for a lane or a free
/// scope.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ExecutorUtilization {
    /// Canonical executions currently holding a lane.
    pub in_flight: usize,
    /// Fixed lane bound for this generation.
    pub lanes: usize,
    /// Lanes free right now (`lanes - in_flight`).
    pub permits_free: usize,
    /// Ready scope heads queued but not yet dispatched.
    pub queued_reservations: usize,
}

/// Starvation-diagnosis metrics for the fair ready-scope scheduler.
///
/// `I5.7` line 41: "Metrics include oldest-ready age, per-scope wait, head
/// retries, reservation conflicts and executor utilization; they diagnose
/// starvation without replacing per-OrderingScope concurrency by a global
/// writer gate." These five values are the whole surface, they gate nothing,
/// and they carry no operation identity, digest or payload.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct CoordinatorMetrics {
    /// Age of the longest-waiting queued ready scope head; zero when nothing is
    /// queued. A steadily growing value is the starvation signal.
    pub oldest_ready_age: Duration,
    /// Current wait per queued Ordering Scope, in stable scope order. Each
    /// value is the longest wait of the ready heads declaring that scope.
    pub scope_wait: BTreeMap<String, Duration>,
    /// Per-scope-head retry delays applied since this generation started.
    pub head_retries: u64,
    /// Execution attempts refused because a declared Ordering Scope already
    /// held its canonical execution permit. Lane exhaustion is not a
    /// conflict; it is reported through
    /// [`ExecutorUtilization::permits_free`].
    pub reservation_conflicts: u64,
    /// Executor lane occupancy for the same observation.
    pub executor_utilization: ExecutorUtilization,
}

/// In-memory execution state for one coordinator generation.
///
/// Durable truth (orders, sequences, lifecycle states, heads) lives in ORS;
/// this map only tracks which scopes currently hold their single canonical
/// execution permit so disjoint scopes stay concurrent, plus the ready queue
/// and its per-scope-head retry delays that decide which free lane runs next.
#[derive(Debug, Default)]
struct CoordinatorState {
    lanes: Option<NonZeroUsize>,
    in_flight: usize,
    busy: BTreeMap<String, String>,
    ready: ReadyScopeQueue,
    /// Retry-delay expiry per Ordering Scope head: a delayed head stays out of
    /// dispatch while the expiry is in the future, and no other head waits.
    delayed_heads: BTreeMap<String, Instant>,
    head_retries: u64,
    reservation_conflicts: u64,
}

/// One queued ready scope head, held by the shared fair scheduler.
///
/// A head is a complete declared scope set, not a single scope: the canonical
/// transition it stands for commits all of its scopes or none, so they are
/// queued, delayed and dispatched as one unit.
#[derive(Debug)]
struct ReadyReservationEntry {
    token: WriterReservationToken,
    scopes: Vec<String>,
    /// Instant the head became ready; the origin of its wait metric.
    ready_since: Instant,
    /// Earliest instant the head may dispatch: the latest retry-delay expiry
    /// over its declared scopes. A retry delay therefore parks this head
    /// alone, and every other head stays dispatchable.
    not_before: Instant,
}

/// The single fair ready-scope queue shared by every executor lane.
///
/// Fairness is positional, not time-polled: the map is keyed by the admission
/// ticket, so its own iteration order is the fair order and the
/// longest-waiting dispatchable head is always the next one dispatched. A hot
/// scope therefore cannot overtake an older head indefinitely.
#[derive(Debug, Default)]
struct ReadyScopeQueue {
    entries: BTreeMap<ReadyScopeTicket, ReadyReservationEntry>,
    next_ticket: u64,
}

impl ReadyScopeQueue {
    /// Admits one reservation at the next strict position.
    fn insert(&mut self, entry: ReadyReservationEntry) -> ReadyScopeTicket {
        let ticket = ReadyScopeTicket(self.next_ticket);
        self.next_ticket = self.next_ticket.saturating_add(1);
        let _replaced = self.entries.insert(ticket, entry);
        ticket
    }

    /// Whether this exact reservation already holds a ready head.
    fn holds(&self, token: &WriterReservationToken) -> bool {
        self.entries
            .values()
            .any(|entry| entry.token.reservation_id == token.reservation_id)
    }

    /// Whether any queued head declares the named Ordering Scope.
    fn declares_scope(&self, scope: &str) -> bool {
        self.entries
            .values()
            .any(|entry| entry.scopes.iter().any(|declared| declared == scope))
    }

    /// Pushes the dispatch time of every head declaring `scope` to `until`.
    fn delay_scope(&mut self, scope: &str, until: Instant) {
        for entry in self.entries.values_mut() {
            if entry.scopes.iter().any(|declared| declared == scope) && until > entry.not_before {
                entry.not_before = until;
            }
        }
    }

    /// Longest-waiting head that may dispatch now, if any.
    ///
    /// A head is skipped when its retry delay has not elapsed, or when any of
    /// its declared scopes currently holds its canonical execution permit:
    /// skipping keeps the head queued and lets every other head proceed.
    fn dispatchable_ticket(
        &self,
        now: Instant,
        busy: &BTreeMap<String, String>,
    ) -> Option<ReadyScopeTicket> {
        self.entries
            .iter()
            .find(|(_ticket, entry)| {
                entry.not_before <= now
                    && !entry.scopes.iter().any(|scope| busy.contains_key(scope))
            })
            .map(|(ticket, _entry)| *ticket)
    }

    /// Removes one head.
    fn take(&mut self, ticket: ReadyScopeTicket) -> Option<ReadyReservationEntry> {
        self.entries.remove(&ticket)
    }

    /// Removes the head belonging to this exact reservation, if it is queued.
    fn take_reservation(
        &mut self,
        token: &WriterReservationToken,
    ) -> Option<ReadyReservationEntry> {
        let ticket = self
            .entries
            .iter()
            .find(|(_ticket, entry)| entry.token.reservation_id == token.reservation_id)
            .map(|(ticket, _entry)| *ticket)?;
        self.take(ticket)
    }
}

/// Kernel-owned write coordinator around ORS reservations.
///
/// `Send` and `Sync`: share by reference across executor threads; scope
/// permits are enforced through the interior mutex, and every durable number
/// still comes from the single ORS write transaction.
pub struct WriteCoordinator {
    ors: Arc<RedbRecoveryStore>,
    state: Mutex<CoordinatorState>,
}

impl CoordinatorState {
    /// Drops retry delays whose expiry has passed.
    ///
    /// Called from every mutating scheduler entry point, so the delay map
    /// cannot outlive its usefulness between calls. A head is never parked by
    /// an elapsed delay: the expiry is compared against the dispatch instant,
    /// not merely recorded.
    fn prune_elapsed_delays(&mut self, now: Instant) {
        self.delayed_heads
            .retain(|_scope, not_before| *not_before > now);
    }
}

impl std::fmt::Debug for WriteCoordinator {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let state = self.lock_state();
        formatter
            .debug_struct("WriteCoordinator")
            .field("lanes", &state.lanes)
            .field("in_flight", &state.in_flight)
            .field("busy_scopes", &state.busy.keys().collect::<Vec<_>>())
            .field("ready_reservations", &state.ready.entries.len())
            .field("delayed_heads", &state.delayed_heads.len())
            .field("head_retries", &state.head_retries)
            .field("reservation_conflicts", &state.reservation_conflicts)
            .finish()
    }
}

impl WriteCoordinator {
    /// Binds the composition-owned ORS handle with a fixed lane bound.
    ///
    /// The ORS handle keeps its composition-bound evidence provider; the lane
    /// bound stays fixed for this generation and changes only through
    /// [`WriteCoordinator::reconfigure_lanes`] after a drain.
    #[must_use]
    pub fn new(ors: Arc<RedbRecoveryStore>, config: WriteCoordinatorConfig) -> Self {
        Self {
            ors,
            state: Mutex::new(CoordinatorState {
                lanes: Some(config.executor_lanes),
                in_flight: 0,
                busy: BTreeMap::new(),
                ..CoordinatorState::default()
            }),
        }
    }

    /// Returns the composition-owned ORS handle.
    #[must_use]
    pub fn ors(&self) -> &Arc<RedbRecoveryStore> {
        &self.ors
    }

    /// Fixed executor lane bound for this generation.
    #[must_use]
    pub fn lanes(&self) -> NonZeroUsize {
        self.lock_state().lanes.unwrap_or(NonZeroUsize::MIN)
    }

    /// Currently in-flight canonical executions across all scopes.
    #[must_use]
    pub fn in_flight_count(&self) -> usize {
        self.lock_state().in_flight
    }

    /// Scope identities currently holding their canonical execution permit,
    /// in stable sorted order. Observation only.
    #[must_use]
    pub fn busy_scopes(&self) -> Vec<String> {
        self.lock_state().busy.keys().cloned().collect()
    }

    /// Atomically reserves every declared scope or none.
    ///
    /// The single ORS write transaction stable-sorts the scopes, assigns one
    /// monotonic `reservation_order` across all scopes, allocates every scope
    /// sequence, and persists the [`WriterReservationToken`] bound to writer
    /// epoch, operation/admission digest, expected heads, expiry, and recovery
    /// owner. Any failure (duplicate scope, head mismatch, stale epoch,
    /// unbound evidence) commits nothing: no order is consumed and no scope
    /// sequence advances.
    ///
    /// # Errors
    ///
    /// Returns the owner [`OrsError`] when the request is malformed or the
    /// reservation cannot be granted.
    pub fn reserve(&self, request: ReservationRequest) -> Result<WriterReservationToken, OrsError> {
        self.ors.stage_and_reserve(request)
    }

    /// Advances a head reservation to eligibility after all predecessors close.
    ///
    /// Durable ORS predecessor and canonical-head checks run here; a missing
    /// predecessor fails with `PredecessorPending` and dispatches nothing. No
    /// execution permit is taken: eligibility is ordering readiness, not the
    /// single canonical transaction.
    ///
    /// # Errors
    ///
    /// Returns the owner [`OrsError`] when the token is unknown, mismatched,
    /// not at the scope heads, or in the wrong lifecycle state.
    pub fn mark_eligible(
        &self,
        token: &WriterReservationToken,
    ) -> Result<ReservationRecord, OrsError> {
        self.ors.mark_eligible(token)
    }

    /// Begins the single canonical execution for every declared scope.
    ///
    /// The un-queued admission path: the caller already holds eligibility and
    /// dispatches now, taking its head out of the fair ready-scope queue. The
    /// queued path is [`WriteCoordinator::enqueue_ready`] plus
    /// [`WriteCoordinator::dispatch_ready`].
    ///
    /// Fails closed, in order, on: an empty, duplicated, or unsorted token
    /// scope set; exhausted executor lanes; any scope already holding its
    /// canonical execution permit. Only then performs the durable
    /// `Eligible -> Executing` transition under the exact immutable writer
    /// epoch (rechecking predecessor fairness and canonical heads). A durable
    /// refusal rolls the in-memory permits back before returning, so the
    /// scopes stay schedulable.
    ///
    /// The returned guard holds every scope permit until dropped: two
    /// executions sharing one scope can never overlap, while executions with
    /// disjoint scopes proceed concurrently, even under one lane each.
    ///
    /// # Errors
    ///
    /// Returns [`CoordinatorError`] for gate refusals and the owner
    /// [`OrsError`] for durable lifecycle refusals.
    pub fn begin_execution(
        &self,
        token: &WriterReservationToken,
        writer_epoch: &EpochIdentity,
    ) -> Result<ScopeExecutionGuard<'_>, CoordinatorError> {
        let scopes = validated_scope_order(token)?;
        let mut state = self.lock_state();
        if state.in_flight >= state.lanes.unwrap_or(NonZeroUsize::MIN).get() {
            return Err(CoordinatorError::LanesExhausted {
                lanes: state.lanes.unwrap_or(NonZeroUsize::MIN).get(),
            });
        }
        for scope in &scopes {
            if state.busy.contains_key(scope) {
                state.reservation_conflicts = state.reservation_conflicts.saturating_add(1);
                return Err(CoordinatorError::ScopeBusy {
                    scope: scope.clone(),
                });
            }
        }
        // Direct admission owns the head: a queued head for the same
        // reservation leaves the fair queue instead of racing this execution.
        state.prune_elapsed_delays(Instant::now());
        let _dequeued = state.ready.take_reservation(token);
        let operation_id = token.operation_id.as_str().to_owned();
        for scope in &scopes {
            state.busy.insert(scope.clone(), operation_id.clone());
        }
        state.in_flight = state.in_flight.saturating_add(1);
        // The mutex is held across this short local ORS transaction so the
        // permit marks and the durable `Executing` transition stay atomic
        // with respect to every other coordinator caller. A durable refusal
        // rolls the marks back below; the scopes never wedge.
        let durable = self.ors.begin_execute(token, writer_epoch);
        if let Err(error) = durable {
            for scope in &scopes {
                state.busy.remove(scope);
            }
            state.in_flight = state.in_flight.saturating_sub(1);
            return Err(CoordinatorError::Ors(error));
        }
        Ok(ScopeExecutionGuard {
            owner: self,
            operation_id,
            scopes,
        })
    }

    /// Admits one reservation as a ready scope head on the fair queue.
    ///
    /// `I5.7` line 61: "configurable executor lanes share one fair ready-scope
    /// scheduler;". This is the `eligible` step of `reserve -> eligible ->
    /// execute -> finalize/release` for the queued path: the durable
    /// `Reserved -> Eligible` transition runs first against the same token, so
    /// a head with a pending predecessor, a moved canonical head, or a stale
    /// token never enters the queue and never consumes a queue position.
    ///
    /// The head keeps the token it was given; the coordinator mints no order
    /// or sequence. A retry delay already pending on any declared scope is
    /// inherited, so a head parked before admission stays parked. One
    /// reservation holds exactly one head: a duplicate admission is refused.
    ///
    /// # Errors
    ///
    /// Returns [`CoordinatorError::EmptyScopeSet`],
    /// [`CoordinatorError::DuplicateScope`] or
    /// [`CoordinatorError::UnsortedScopes`] for a malformed token,
    /// [`CoordinatorError::AlreadyQueued`] for a duplicate head, and the owner
    /// [`OrsError`] when the durable eligibility check refuses.
    pub fn enqueue_ready(
        &self,
        token: &WriterReservationToken,
    ) -> Result<ReadyReservation, CoordinatorError> {
        let scopes = validated_scope_order(token)?;
        let now = Instant::now();
        let mut state = self.lock_state();
        state.prune_elapsed_delays(now);
        if state.ready.holds(token) {
            return Err(CoordinatorError::AlreadyQueued {
                reservation_id: token.reservation_id.as_str().to_owned(),
            });
        }
        // The mutex is held across this short local ORS transaction for the
        // same reason as `begin_execution`: the duplicate-head refusal, the
        // durable `Reserved -> Eligible` transition and the queue insertion
        // must not be observable apart, or two concurrent admissions could
        // give one reservation two heads.
        self.ors.mark_eligible(token)?;
        let not_before = scopes
            .iter()
            .filter_map(|scope| state.delayed_heads.get(scope))
            .copied()
            .max()
            .unwrap_or(now);
        let ticket = state.ready.insert(ReadyReservationEntry {
            token: token.clone(),
            scopes: scopes.clone(),
            ready_since: now,
            not_before,
        });
        Ok(ReadyReservation {
            ticket,
            token: token.clone(),
            scopes,
        })
    }

    /// Dispatches the longest-waiting dispatchable ready scope head.
    ///
    /// Fairness is positional, not time-polled: the head with the lowest
    /// admission ticket wins, so no scope can be overtaken forever. A head is
    /// skipped, never blocking, when a retry delay is still pending on it or
    /// when any declared scope currently holds its canonical execution permit.
    /// Call repeatedly while this returns a guard and
    /// [`WriteCoordinator::pending_ready`] is non-zero to fill every free lane.
    ///
    /// `Ok(None)` means nothing dispatched: either the queue is empty (check
    /// [`WriteCoordinator::pending_ready`]) or every lane is in flight.
    ///
    /// The durable `Eligible -> Executing` transition runs under the exact
    /// immutable writer epoch, with the same in-memory permits and rollback as
    /// [`WriteCoordinator::begin_execution`]. A durable refusal dequeues the
    /// head and rolls the permits back, so an unexecutable head cannot
    /// monopolize the fair order; the caller then reconciles or releases it
    /// durably.
    ///
    /// # Errors
    ///
    /// Returns the owner [`OrsError`] for durable lifecycle refusals; an empty
    /// queue or a full lane is not an error.
    pub fn dispatch_ready(
        &self,
        writer_epoch: &EpochIdentity,
    ) -> Result<Option<ScopeExecutionGuard<'_>>, CoordinatorError> {
        let now = Instant::now();
        let mut state = self.lock_state();
        state.prune_elapsed_delays(now);
        let lanes = state.lanes.unwrap_or(NonZeroUsize::MIN).get();
        if state.in_flight >= lanes {
            return Ok(None);
        }
        let Some(ticket) = state.ready.dispatchable_ticket(now, &state.busy) else {
            return Ok(None);
        };
        let Some(entry) = state.ready.take(ticket) else {
            return Ok(None);
        };
        let operation_id = entry.token.operation_id.as_str().to_owned();
        let scopes = entry.scopes;
        for scope in &scopes {
            state.busy.insert(scope.clone(), operation_id.clone());
        }
        state.in_flight = state.in_flight.saturating_add(1);
        // Same atomicity argument as `begin_execution`: the permits and the
        // durable `Executing` transition must not be observable apart.
        let durable = self.ors.begin_execute(&entry.token, writer_epoch);
        if let Err(error) = durable {
            for scope in &scopes {
                state.busy.remove(scope);
            }
            state.in_flight = state.in_flight.saturating_sub(1);
            return Err(CoordinatorError::Ors(error));
        }
        Ok(Some(ScopeExecutionGuard {
            owner: self,
            operation_id,
            scopes,
        }))
    }

    /// Ready scope heads queued but not yet dispatched.
    ///
    /// A non-zero value with a full lane pool is normal: the heads are waiting
    /// for a lane or for a scope permit, and the fair order decides which one
    /// runs next.
    #[must_use]
    pub fn pending_ready(&self) -> usize {
        self.lock_state().ready.entries.len()
    }

    /// Parks one Ordering Scope head for a bounded retry.
    ///
    /// `I5.7` line 64: "a retry delay blocks only that scope head, never the
    /// whole lane;". The delay is recorded against the scope identity only:
    /// every other ready head, and every free lane, keeps dispatching, and a
    /// later delay on the same scope extends the existing one rather than
    /// shortening it. A scope that currently holds its execution permit is
    /// accepted too, because the delay then applies to the next head of that
    /// scope.
    ///
    /// # Errors
    ///
    /// Returns [`CoordinatorError::NoScopeHead`] when no ready or executing
    /// head declares the scope, so a mistyped scope cannot park nothing
    /// silently, and [`CoordinatorError::RetryDelayOutOfRange`] when the delay
    /// leaves the representable clock range.
    pub fn delay_scope_head(&self, scope: &str, delay: Duration) -> Result<(), CoordinatorError> {
        let now = Instant::now();
        let until = now
            .checked_add(delay)
            .ok_or(CoordinatorError::RetryDelayOutOfRange {
                delay_ms: delay.as_millis(),
            })?;
        let mut state = self.lock_state();
        state.prune_elapsed_delays(now);
        let known = state.delayed_heads.contains_key(scope)
            || state.busy.contains_key(scope)
            || state.ready.declares_scope(scope);
        if !known {
            return Err(CoordinatorError::NoScopeHead {
                scope: scope.to_owned(),
            });
        }
        state.head_retries = state.head_retries.saturating_add(1);
        state.delayed_heads.insert(scope.to_owned(), until);
        state.ready.delay_scope(scope, until);
        Ok(())
    }

    /// Starvation metrics for the fair ready-scope scheduler.
    ///
    /// A point observation under the coordinator mutex: it reads the ready
    /// queue, the per-scope-head retry delays and the lane occupancy, and it
    /// gates nothing. Per-scope wait is reported for queued heads only, so a
    /// delivered scope leaves the metric instead of freezing a stale value.
    #[must_use]
    pub fn metrics(&self) -> CoordinatorMetrics {
        let now = Instant::now();
        let state = self.lock_state();
        let lanes = state.lanes.unwrap_or(NonZeroUsize::MIN).get();
        let oldest_ready_age = state
            .ready
            .entries
            .values()
            .map(|entry| now.saturating_duration_since(entry.ready_since))
            .max()
            .unwrap_or_default();
        let mut scope_wait: BTreeMap<String, Duration> = BTreeMap::new();
        for entry in state.ready.entries.values() {
            let wait = now.saturating_duration_since(entry.ready_since);
            for scope in &entry.scopes {
                let longest = scope_wait.entry(scope.clone()).or_default();
                *longest = (*longest).max(wait);
            }
        }
        CoordinatorMetrics {
            oldest_ready_age,
            scope_wait,
            head_retries: state.head_retries,
            reservation_conflicts: state.reservation_conflicts,
            executor_utilization: ExecutorUtilization {
                in_flight: state.in_flight,
                lanes,
                permits_free: lanes.saturating_sub(state.in_flight),
                queued_reservations: state.ready.entries.len(),
            },
        }
    }

    /// Closes an executing/unknown reservation from exact receipt evidence.
    ///
    /// `Committed` finalizes; terminally-not-applied (`Rejected`, including
    /// the dead-letter gap) releases with the terminal receipt bound. The
    /// composition-bound evidence provider verifies the reconciliation; all
    /// token scopes advance atomically. Call after the execution guard drops:
    /// the guard frees the in-memory permits, the receipt frees the durable
    /// scope sequences for successors (or explicitly gaps them on rejection).
    ///
    /// # Errors
    ///
    /// Returns the owner [`OrsError`] when the evidence does not verify or the
    /// reservation is in the wrong lifecycle state.
    pub fn finalize(
        &self,
        reconciliation: &CanonicalReconciliation,
    ) -> Result<ReservationRecord, OrsError> {
        self.ors.reconcile(reconciliation)
    }

    /// Releases work that has not executed under the exact writer epoch.
    ///
    /// Valid only from `Reserved`/`Eligible`: before-send cancellation
    /// releases exactly this token and nothing else. From
    /// `Executing`/`Reconciling` the owner rejects, preserving identity until
    /// exact receipt reconciliation.
    ///
    /// # Errors
    ///
    /// Returns the owner [`OrsError`] when the token already executed or is
    /// otherwise unreleasable.
    pub fn release(
        &self,
        token: &WriterReservationToken,
        writer_epoch: &EpochIdentity,
    ) -> Result<ReservationRecord, OrsError> {
        self.ors.release(token, writer_epoch)
    }

    /// Lists every unresolved (non-terminal) reservation by reservation order.
    ///
    /// Pages the bounded recovery cursor to exhaustion, so a restart observes
    /// the complete unresolved set before new eligible work runs. Recovery
    /// pages advance over strictly increasing reservation orders, so the loop
    /// always progresses. Reconcile every returned record against its
    /// `WriteReceipt`/canonical head through [`WriteCoordinator::finalize`]
    /// before the affected scopes accept new execution: ORS refuses
    /// reallocation on blocked scopes until then.
    ///
    /// # Errors
    ///
    /// Returns the owner [`OrsError`] when a recovery page cannot be read.
    pub fn unresolved(&self, limit: u16) -> Result<Vec<ReservationRecord>, OrsError> {
        let mut unresolved = Vec::new();
        let mut after_order = 0_u64;
        loop {
            let cursor = eliot_ors::RecoveryCursor::new(after_order, limit)?;
            let page = self.ors.recover_page(cursor)?;
            unresolved.extend(page.records.into_iter().filter(|record| {
                !matches!(
                    record.state,
                    eliot_ors::ReservationState::Finalized | eliot_ors::ReservationState::Released
                )
            }));
            match page.next_after_order {
                Some(next) => after_order = next,
                None => break,
            }
        }
        Ok(unresolved)
    }

    /// Switches the lane bound after a drained generation.
    ///
    /// `I5.7` line 67: "lane-count change requires drained generation switch."
    /// A generation is drained only when no canonical execution is in flight,
    /// no scope holds its permit and the fair ready-scope queue is empty, so a
    /// new bound never reinterprets a head admitted under the old one. A
    /// refused switch changes nothing; drain first, then switch, then admit new
    /// work on the new generation.
    ///
    /// # Errors
    ///
    /// Returns [`CoordinatorError::NotDrained`] when an execution, a busy scope
    /// or a queued ready head remains.
    pub fn reconfigure_lanes(&self, lanes: NonZeroUsize) -> Result<(), CoordinatorError> {
        let mut state = self.lock_state();
        if state.in_flight != 0 || !state.busy.is_empty() || !state.ready.entries.is_empty() {
            return Err(CoordinatorError::NotDrained {
                in_flight: state.in_flight,
                queued: state.ready.entries.len(),
            });
        }
        state.lanes = Some(lanes);
        Ok(())
    }

    fn lock_state(&self) -> MutexGuard<'_, CoordinatorState> {
        self.state.lock().unwrap_or_else(|poison| {
            // A poisoned mutex means a previous holder panicked mid-gate. The
            // in-memory marks may be stale while ORS durable state is exact:
            // fail-closed recovery is to keep serving from the poisoned state
            // (which still refuses overlaps) rather than inventing permits.
            poison.into_inner()
        })
    }
}

/// In-memory permit for one canonical execution across a token's scopes.
///
/// Holds every declared scope's single-execution permit from
/// [`WriteCoordinator::begin_execution`] until dropped. Dropping releases the
/// permits and the lane; it never touches ORS durable state, which advances
/// only through `finalize`/`release` on receipt evidence. The guard is `Send`
/// so the acquiring thread may hand the execution window to a worker thread.
pub struct ScopeExecutionGuard<'a> {
    owner: &'a WriteCoordinator,
    operation_id: String,
    scopes: Vec<String>,
}

impl std::fmt::Debug for ScopeExecutionGuard<'_> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ScopeExecutionGuard")
            .field("operation_id", &self.operation_id)
            .field("scopes", &self.scopes)
            .finish()
    }
}

impl ScopeExecutionGuard<'_> {
    /// Operation identity holding these scope permits.
    #[must_use]
    pub fn operation_id(&self) -> &str {
        &self.operation_id
    }

    /// Scope identities held, in stable sorted order.
    #[must_use]
    pub fn scopes(&self) -> &[String] {
        &self.scopes
    }
}

impl Drop for ScopeExecutionGuard<'_> {
    fn drop(&mut self) {
        let mut state = self.owner.lock_state();
        for scope in &self.scopes {
            if state
                .busy
                .get(scope)
                .is_some_and(|holder| *holder == self.operation_id)
            {
                state.busy.remove(scope);
            }
        }
        state.in_flight = state.in_flight.saturating_sub(1);
    }
}

/// Requires the token's complete declared scope set in stable sorted order.
///
/// The coordinator renormalizes nothing: an empty, duplicated, or unsorted
/// scope set fails closed before any permit or ORS mutation, so every
/// generation observes the same precedence between overlapping operations.
fn validated_scope_order(token: &WriterReservationToken) -> Result<Vec<String>, CoordinatorError> {
    if token.scopes.is_empty() {
        return Err(CoordinatorError::EmptyScopeSet);
    }
    let mut scopes = Vec::with_capacity(token.scopes.len());
    let mut seen = BTreeSet::new();
    let mut previous: Option<&str> = None;
    for reserved in &token.scopes {
        let scope = reserved.scope.as_str();
        if !seen.insert(scope) {
            return Err(CoordinatorError::DuplicateScope {
                scope: scope.to_owned(),
            });
        }
        if previous.is_some_and(|prior| prior >= scope) {
            return Err(CoordinatorError::UnsortedScopes);
        }
        previous = Some(scope);
        scopes.push(scope.to_owned());
    }
    Ok(scopes)
}

#[cfg(test)]
mod tests;
