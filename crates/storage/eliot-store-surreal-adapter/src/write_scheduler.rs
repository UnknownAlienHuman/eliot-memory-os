//! Bounded pure OrderingScope-ready scheduler and drain model.
//!
//! S-CONC-SCHEDULER (issue #988): #67's bounded pure scheduler as one
//! cohesive module in the existing Surreal adapter — not a new crate, not a
//! durable ordering owner. It consumes projections of already admitted,
//! externally validated reservations and decides conflict readiness; it
//! cannot create ORS reservations, canonical `OrderingHeads`, sequences,
//! receipts, semantic admission, or a real provider permit.
//!
//! Purity contract:
//!
//! - No provider, socket, credential, clock, or mutable canonical state.
//!   Time enters only as an explicit caller-supplied monotonic `now_ms`, so
//!   interleavings stay deterministically simulable (A14.8).
//! - No dependency on the ORS implementation and no copy of its public token
//!   schema: [`ReservationProjection`] carries exactly the precedence fields
//!   the scheduler needs (`reservation_order`, sorted unique scopes with
//!   reserved sequences). Test-created projections prove only the model;
//!   canonical ORS evidence is validated by the separate runtime boundary.
//! - `WriteCoordinator` semantics from I5.7: one canonical transaction in
//!   flight per `OrderingScope`; independent scopes commit concurrently;
//!   `reservation_order` gives the same precedence in every shared scope, so
//!   no cyclic wait graph forms (multi-scope atomicity itself is the ORS
//!   coordinator's job, upstream of this module).
//! - The process-global write mutex stays in place and `apply_prepared` is
//!   untouched here: activating the scheduler in the write path is the
//!   runtime integration's (#993) decision, not this mechanism's.

use std::collections::{BTreeMap, BTreeSet};
use std::num::NonZeroUsize;

use eliot_store_api::{OperationId, OrderingScopeId};

/// Closed projection of one already-admitted ORS reservation, carrying only
/// what conflict readiness needs. `scopes` must arrive sorted by scope with
/// no duplicates — the producer (#990) guarantees sorted-unique; this module
/// validates rather than silently repairing a malformed projection.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReservationProjection {
    /// Canonical operation identity (idempotency key owner upstream).
    pub operation_id: OperationId,
    /// Single-ORS-coordinator precedence; equal orders break by operation id.
    pub reservation_order: u64,
    /// Complete sorted unique scope set with reserved sequences.
    pub scopes: Vec<ReservedScopeProjection>,
}

/// One reserved scope sequence inside a [`ReservationProjection`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReservedScopeProjection {
    /// Ordering scope under test.
    pub scope: OrderingScopeId,
    /// ORS-reserved sequence for this scope.
    pub reserved_sequence: u64,
}

/// Terminal-or-waiting disposition reported by [`WriteScheduler::complete`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CompletionOutcome {
    /// Canonical commit observed; scopes free for successors.
    Committed,
    /// Deterministic rejection; the reserved sequence closes and successors
    /// proceed (never a silent skip: rejection is an explicit disposition).
    Rejected,
    /// Dead letter with proven non-application; the ordering position still
    /// required disposition, which this records — successors proceed.
    DeadLetter,
    /// Cancelled before effect; reserved order safely dispositioned.
    Cancelled,
    /// Commit outcome unknown: dependent scopes pause (not the whole lane)
    /// until [`WriteScheduler::resolve_uncertain`] runs. The optional
    /// retry delay blocks only the affected scope heads, never the lane.
    /// During a drain the operation is reported through
    /// [`WriteScheduler::begin_drain`] / [`WriteScheduler::uncertain_operations`]
    /// until the caller terminally dispositions it: unknown work never
    /// drains silently.
    Unknown {
        /// Milliseconds from `now_ms` before the scope heads reopen.
        retry_after_ms: u64,
    },
}

/// Why a scheduler call refused.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum ScheduleReject {
    /// Projection carries no scopes; nothing could order it.
    #[error("reservation projection carries no ordering scopes")]
    EmptyScopes,
    /// Projection repeats a scope; a self-consistent caller list must not
    /// acquire scheduling authority through duplicates.
    #[error("reservation projection repeats an ordering scope")]
    DuplicateScope,
    /// Projection scopes are not sorted by scope; the producer contract
    /// (#990) requires sorted-unique and this module does not renormalize.
    #[error("reservation projection scopes are not sorted")]
    UnsortedScopes,
    /// Projection contradicts already accepted precedence: on a shared
    /// scope, reservation order and reserved sequence must advance together
    /// (the single ORS coordinator allocates both monotonically). A crossed
    /// pair proves a corrupt projection, never a scheduling decision.
    #[error("reservation projection contradicts accepted sequence precedence")]
    InconsistentSequences,
    /// Operation identity is already scheduled or in flight.
    #[error("operation identity is already scheduled")]
    DuplicateOperation,
    /// Bounded queue is full; shed load instead of queueing unboundedly
    /// (Control Reserve: normal workload cannot consume the pool).
    #[error("scheduler queue is full")]
    QueueFull,
    /// Drain started; no new submissions while a generation switch drains.
    #[error("scheduler is draining")]
    Draining,
    /// Unknown operation identity.
    #[error("unknown scheduled operation")]
    UnknownOperation,
    /// Operation is not eligible now (scope busy, delayed, or uncertain).
    #[error("operation is not eligible for execution")]
    NotReady,
    /// Operation is already in flight.
    #[error("operation is already in flight")]
    AlreadyInFlight,
    /// Operation is not uncertain (nothing to resolve).
    #[error("operation has no uncertain outcome to resolve")]
    NotUncertain,
}

/// Point occupancy snapshot of the bounded scheduler (issue #2030, 994/14).
///
/// Observation for capacity and protected-progress evidence: how many
/// operations are accepted but not completed, how many execute, how many
/// hold their scopes uncertain, and whether the scheduler drains. The
/// snapshot never mutates and never waits; uncertain work keeps its entry,
/// so a drain with an open outcome cannot observe quiescence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SchedulerOccupancy {
    /// Accepted but not completed operations.
    pub pending: usize,
    /// Currently executing operations.
    pub in_flight: usize,
    /// Operations holding their scopes uncertain.
    pub uncertain: usize,
    /// Whether a drain started and new submissions refuse.
    pub draining: bool,
    /// Fixed executor lane bound.
    pub lanes: usize,
    /// Fixed pending-queue bound.
    pub max_pending: usize,
}

/// Non-blocking scheduler admission verdict (issue #2030, 994/14).
///
/// Point observation matching [`WriteScheduler::submit`] without mutating:
/// a full queue sheds with [`ScheduleReject::QueueFull`], a draining
/// scheduler refuses with [`ScheduleReject::Draining`], and only open
/// capacity admits. Callers that must shed load instead of queueing use
/// this entrypoint.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SchedulerAdmission {
    /// Open capacity at observation time.
    Admitted {
        /// Lanes not currently in flight.
        free_lanes: usize,
        /// Queue slots not currently pending.
        free_queue: usize,
    },
    /// The bounded queue is full; shed instead of queueing.
    ShedQueueFull,
    /// A drain started; no new submissions while it runs.
    RefusedDraining,
}

impl SchedulerAdmission {
    /// Whether a submission may proceed without queueing behind the bound.
    #[must_use]
    pub const fn admitted(self) -> bool {
        matches!(self, Self::Admitted { .. })
    }
}

/// Per-scope head state: at most one in-flight operation, one optional
/// retry gate, and one optional uncertainty holder.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
struct ScopeHead {
    in_flight: Option<OperationId>,
    retry_not_before_ms: u64,
    uncertain_holder: Option<OperationId>,
}

/// One accepted projection plus its lifecycle state.
#[derive(Clone, Debug, Eq, PartialEq)]
struct ScheduledOperation {
    order: u64,
    scopes: Vec<ReservedScopeProjection>,
    in_flight: bool,
    uncertain: bool,
}

/// Bounded pure OrderingScope-ready scheduler.
///
/// Clone shares nothing: each scheduler owns its generation of pending and
/// in-flight state. A lane-count change requires a drained generation
/// switch (construct a new scheduler after [`WriteScheduler::is_drained`]),
/// never a runtime mutation of a live one.
#[derive(Clone, Debug)]
pub struct WriteScheduler {
    lanes: NonZeroUsize,
    max_pending: NonZeroUsize,
    draining: bool,
    pending: BTreeMap<OperationId, ScheduledOperation>,
    scope_heads: BTreeMap<OrderingScopeId, ScopeHead>,
}

impl WriteScheduler {
    /// Builds a scheduler with an explicit lane count and pending bound.
    /// Both stay fixed for the scheduler lifetime; I5.7's desktop default
    /// (`writer_executors = min(4, logical_cpu_count)`) is a runtime
    /// composition choice, not a default hidden in this pure core.
    #[must_use]
    pub fn new(lanes: NonZeroUsize, max_pending: NonZeroUsize) -> Self {
        Self {
            lanes,
            max_pending,
            draining: false,
            pending: BTreeMap::new(),
            scope_heads: BTreeMap::new(),
        }
    }

    /// Executor lane bound.
    #[must_use]
    pub const fn lanes(&self) -> NonZeroUsize {
        self.lanes
    }

    /// Pending-queue bound.
    #[must_use]
    pub const fn max_pending(&self) -> NonZeroUsize {
        self.max_pending
    }

    /// Currently accepted but not completed operations.
    #[must_use]
    pub fn pending_count(&self) -> usize {
        self.pending.len()
    }

    /// Currently executing operations.
    #[must_use]
    pub fn in_flight_count(&self) -> usize {
        self.pending.values().filter(|op| op.in_flight).count()
    }

    /// Point occupancy snapshot of this scheduler (issue #2030, 994/14).
    ///
    /// Observation only: counts pending, in-flight, and uncertain
    /// operations plus the drain state and the fixed bounds. Never
    /// mutates, never waits.
    #[must_use]
    pub fn occupancy(&self) -> SchedulerOccupancy {
        SchedulerOccupancy {
            pending: self.pending.len(),
            in_flight: self.in_flight_count(),
            uncertain: self
                .pending
                .values()
                .filter(|operation| operation.uncertain)
                .count(),
            draining: self.draining,
            lanes: self.lanes.get(),
            max_pending: self.max_pending.get(),
        }
    }

    /// Non-blocking admission verdict matching [`WriteScheduler::submit`]
    /// without mutating (issue #2030, 994/14).
    #[must_use]
    pub fn admission(&self) -> SchedulerAdmission {
        if self.draining {
            return SchedulerAdmission::RefusedDraining;
        }
        if self.pending.len() >= self.max_pending.get() {
            return SchedulerAdmission::ShedQueueFull;
        }
        SchedulerAdmission::Admitted {
            free_lanes: self.lanes.get().saturating_sub(self.in_flight_count()),
            free_queue: self.max_pending.get().saturating_sub(self.pending.len()),
        }
    }

    /// Oldest accepted operation by (`reservation_order`, operation id):
    /// starvation-diagnosis input for the caller-owned metrics layer.
    #[must_use]
    pub fn oldest_pending(&self) -> Option<(u64, OperationId)> {
        self.pending
            .iter()
            .map(|(id, op)| (op.order, id.clone()))
            .min()
    }

    /// Accepts one admitted-reservation projection. Structural validation
    /// only: semantic admission happened upstream, and a structurally valid
    /// projection still carries no execution authority by itself.
    pub fn submit(&mut self, projection: ReservationProjection) -> Result<(), ScheduleReject> {
        if self.draining {
            return Err(ScheduleReject::Draining);
        }
        if projection.scopes.is_empty() {
            return Err(ScheduleReject::EmptyScopes);
        }
        if self.pending.contains_key(&projection.operation_id) {
            return Err(ScheduleReject::DuplicateOperation);
        }
        if self.pending.len() >= self.max_pending.get() {
            return Err(ScheduleReject::QueueFull);
        }
        let mut seen = BTreeSet::new();
        let mut previous: Option<&OrderingScopeId> = None;
        for scope in &projection.scopes {
            if !seen.insert(scope.scope.clone()) {
                return Err(ScheduleReject::DuplicateScope);
            }
            if let Some(previous) = previous
                && previous >= &scope.scope
            {
                return Err(ScheduleReject::UnsortedScopes);
            }
            previous = Some(&scope.scope);
        }
        // Orders and reserved sequences advance together on every shared
        // scope: the coordinator allocates both monotonically, so a crossed
        // pair is a corrupt projection, not a scheduling judgment call.
        for scope in &projection.scopes {
            for (id, other) in &self.pending {
                if id == &projection.operation_id {
                    continue;
                }
                if let Some(other_scope) = other
                    .scopes
                    .iter()
                    .find(|candidate| candidate.scope == scope.scope)
                {
                    // Orders are globally unique per coordinator reservation;
                    // sequences are unique per scope. On a shared scope both
                    // must advance together.
                    let order_cmp = projection.reservation_order.cmp(&other.order);
                    let sequence_cmp = scope.reserved_sequence.cmp(&other_scope.reserved_sequence);
                    if order_cmp == std::cmp::Ordering::Equal || sequence_cmp != order_cmp {
                        return Err(ScheduleReject::InconsistentSequences);
                    }
                }
            }
        }
        for scope in &projection.scopes {
            self.scope_heads.entry(scope.scope.clone()).or_default();
        }
        self.pending.insert(
            projection.operation_id,
            ScheduledOperation {
                order: projection.reservation_order,
                scopes: projection.scopes,
                in_flight: false,
                uncertain: false,
            },
        );
        Ok(())
    }

    /// Operations eligible to execute now, in deterministic
    /// (`reservation_order`, operation id) priority order, capped by free
    /// lanes. An operation is eligible when it is the pending head of every
    /// scope it touches (per-scope FIFO over the same precedence that
    /// prevents cyclic waits), no touched scope is in-flight, delayed, or
    /// uncertain under another operation.
    #[must_use]
    pub fn ready(&self, now_ms: u64) -> Vec<OperationId> {
        let free_lanes = self.lanes.get().saturating_sub(self.in_flight_count());
        if free_lanes == 0 {
            return Vec::new();
        }
        let mut ordered: Vec<(&OperationId, &ScheduledOperation)> = self.pending.iter().collect();
        ordered.sort_by(|left, right| {
            left.1
                .order
                .cmp(&right.1.order)
                .then_with(|| left.0.as_str().cmp(right.0.as_str()))
        });
        let mut eligible = Vec::new();
        for (id, operation) in ordered {
            if eligible.len() >= free_lanes {
                break;
            }
            if operation.in_flight {
                continue;
            }
            if self.is_head_of_all_scopes(id, operation) && self.scopes_clear(operation, id, now_ms)
            {
                eligible.push((*id).clone());
            }
        }
        eligible
    }

    /// Marks an eligible operation in flight. Fails closed when the
    /// operation is unknown, already in flight, or not currently eligible:
    /// readiness is rechecked at execution time, never assumed from an
    /// earlier `ready` snapshot.
    pub fn mark_in_flight(
        &mut self,
        operation_id: &OperationId,
        now_ms: u64,
    ) -> Result<(), ScheduleReject> {
        let eligible = self
            .pending
            .get(operation_id)
            .filter(|operation| !operation.in_flight)
            .is_some_and(|_| self.ready(now_ms).iter().any(|ready| ready == operation_id));
        if !eligible {
            return Err(if self.pending.contains_key(operation_id) {
                if self
                    .pending
                    .get(operation_id)
                    .is_some_and(|operation| operation.in_flight)
                {
                    ScheduleReject::AlreadyInFlight
                } else {
                    ScheduleReject::NotReady
                }
            } else {
                ScheduleReject::UnknownOperation
            });
        }
        let operation = self
            .pending
            .get_mut(operation_id)
            .ok_or(ScheduleReject::UnknownOperation)?;
        operation.in_flight = true;
        for scope in &operation.scopes {
            if let Some(head) = self.scope_heads.get_mut(&scope.scope) {
                head.in_flight = Some(operation_id.clone());
            }
        }
        Ok(())
    }

    /// Completes an in-flight operation. Terminal outcomes free every scope
    /// the operation held so successors proceed; `Unknown` pauses only the
    /// operation's own scopes (with an optional per-scope retry delay) until
    /// [`WriteScheduler::resolve_uncertain`] runs. Blind retry is never
    /// implied: unknown stays unknown until resolved.
    pub fn complete(
        &mut self,
        operation_id: &OperationId,
        outcome: CompletionOutcome,
        now_ms: u64,
    ) -> Result<(), ScheduleReject> {
        let operation = self
            .pending
            .get(operation_id)
            .ok_or(ScheduleReject::UnknownOperation)?;
        if !operation.in_flight {
            return Err(ScheduleReject::NotReady);
        }
        if operation.uncertain && !matches!(outcome, CompletionOutcome::Unknown { .. }) {
            return Err(ScheduleReject::NotUncertain);
        }
        match outcome {
            CompletionOutcome::Committed
            | CompletionOutcome::Rejected
            | CompletionOutcome::DeadLetter
            | CompletionOutcome::Cancelled => {
                let operation = self
                    .pending
                    .remove(operation_id)
                    .ok_or(ScheduleReject::UnknownOperation)?;
                for scope in &operation.scopes {
                    if let Some(head) = self.scope_heads.get_mut(&scope.scope) {
                        if head.in_flight.as_ref() == Some(operation_id) {
                            head.in_flight = None;
                        }
                        if head.uncertain_holder.as_ref() == Some(operation_id) {
                            head.uncertain_holder = None;
                        }
                    }
                }
                self.gc_scope_heads();
            }
            CompletionOutcome::Unknown { retry_after_ms } => {
                let not_before = now_ms.saturating_add(retry_after_ms);
                let operation = self
                    .pending
                    .get_mut(operation_id)
                    .ok_or(ScheduleReject::UnknownOperation)?;
                operation.uncertain = true;
                for scope in &operation.scopes {
                    if let Some(head) = self.scope_heads.get_mut(&scope.scope) {
                        head.uncertain_holder = Some(operation_id.clone());
                        head.retry_not_before_ms = head.retry_not_before_ms.max(not_before);
                    }
                }
            }
        }
        Ok(())
    }

    /// Resolves a previously unknown outcome through the terminal outcome
    /// (or a fresh unknown with a new delay). Recovery owns this call after
    /// reconciling the token against the canonical receipt.
    pub fn resolve_uncertain(
        &mut self,
        operation_id: &OperationId,
        outcome: CompletionOutcome,
        now_ms: u64,
    ) -> Result<(), ScheduleReject> {
        let uncertain = self
            .pending
            .get(operation_id)
            .is_some_and(|operation| operation.uncertain);
        if !uncertain {
            return Err(ScheduleReject::NotUncertain);
        }
        if matches!(
            outcome,
            CompletionOutcome::Committed
                | CompletionOutcome::Rejected
                | CompletionOutcome::DeadLetter
                | CompletionOutcome::Cancelled
        ) {
            let operation = self
                .pending
                .remove(operation_id)
                .ok_or(ScheduleReject::UnknownOperation)?;
            for scope in &operation.scopes {
                if let Some(head) = self.scope_heads.get_mut(&scope.scope) {
                    if head.in_flight.as_ref() == Some(operation_id) {
                        head.in_flight = None;
                    }
                    if head.uncertain_holder.as_ref() == Some(operation_id) {
                        head.uncertain_holder = None;
                    }
                    head.retry_not_before_ms = head.retry_not_before_ms.min(now_ms);
                }
            }
            self.gc_scope_heads();
        } else if let CompletionOutcome::Unknown { retry_after_ms } = outcome {
            return self.complete(
                operation_id,
                CompletionOutcome::Unknown { retry_after_ms },
                now_ms,
            );
        }
        Ok(())
    }

    /// Starts the drain: new submissions refuse with
    /// [`ScheduleReject::Draining`]. Returns the currently uncertain
    /// operation IDs — the mandatory resolution set the caller must
    /// terminally disposition through [`WriteScheduler::resolve_uncertain`]
    /// (after reconciling each outcome against its canonical receipt, as
    /// for any unknown outcome) before [`WriteScheduler::is_drained`] can
    /// hold and a new generation may start. Already accepted work with a
    /// known outcome still schedules to completion; accepted work completed
    /// as `Unknown` holds its scopes until the caller resolves it, so an
    /// unresolved drain never reaches quiescence silently. Lane-count
    /// change and exclusive migration handoff are separate owners; this
    /// only models the quiesce half.
    pub fn begin_drain(&mut self) -> Vec<OperationId> {
        self.draining = true;
        self.uncertain_operations()
    }

    /// Currently uncertain operation IDs in deterministic
    /// (`reservation_order`, operation id) order: the drain blockers the
    /// caller must resolve before a generation switch. Reporting only;
    /// resolution stays an explicit caller act through
    /// [`WriteScheduler::resolve_uncertain`].
    #[must_use]
    pub fn uncertain_operations(&self) -> Vec<OperationId> {
        let mut uncertain: Vec<(&OperationId, &ScheduledOperation)> = self
            .pending
            .iter()
            .filter(|(_, operation)| operation.uncertain)
            .collect();
        uncertain.sort_by(|left, right| {
            left.1
                .order
                .cmp(&right.1.order)
                .then_with(|| left.0.as_str().cmp(right.0.as_str()))
        });
        uncertain.into_iter().map(|(id, _)| (*id).clone()).collect()
    }

    /// Whether a drain (or idle start) reached quiescence: nothing pending
    /// and nothing in flight. Uncertain work keeps its pending entry, so a
    /// drain with an unresolved outcome cannot observe this; the caller
    /// first resolves every ID reported by
    /// [`WriteScheduler::begin_drain`]. A new generation may start only
    /// after this holds; the switch itself is the caller's.
    #[must_use]
    pub fn is_drained(&self) -> bool {
        self.pending.is_empty()
    }

    /// The operation is the pending minimum of every scope it touches.
    fn is_head_of_all_scopes(
        &self,
        operation_id: &OperationId,
        operation: &ScheduledOperation,
    ) -> bool {
        operation.scopes.iter().all(|scope| {
            self.pending
                .iter()
                .filter(|(_, other)| {
                    !other.in_flight && other.scopes.iter().any(|s| s.scope == scope.scope)
                })
                .map(|(id, other)| (other.order, id))
                .min()
                .is_some_and(|(order, id)| order == operation.order && id == operation_id)
        })
    }

    /// No touched scope is in-flight under another operation, delayed past
    /// `now_ms`, or uncertain under another operation.
    fn scopes_clear(
        &self,
        operation: &ScheduledOperation,
        operation_id: &OperationId,
        now_ms: u64,
    ) -> bool {
        operation.scopes.iter().all(|scope| {
            self.scope_heads.get(&scope.scope).is_some_and(|head| {
                head.in_flight
                    .as_ref()
                    .is_none_or(|holder| holder == operation_id)
                    && now_ms >= head.retry_not_before_ms
                    && head
                        .uncertain_holder
                        .as_ref()
                        .is_none_or(|holder| holder == operation_id)
            })
        })
    }

    /// Drops scope heads no pending operation references. Heads carry no
    /// durable truth (canonical history lives in the Store); pruning only
    /// bounds memory.
    fn gc_scope_heads(&mut self) {
        let live: BTreeSet<&OrderingScopeId> = self
            .pending
            .values()
            .flat_map(|operation| operation.scopes.iter().map(|scope| &scope.scope))
            .collect();
        self.scope_heads.retain(|scope, _| live.contains(scope));
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used, clippy::unwrap_used)]

    use super::*;
    use serde::Deserialize;

    const LANES: usize = 4;
    const QUEUE: usize = 16;

    fn scheduler() -> WriteScheduler {
        WriteScheduler::new(
            NonZeroUsize::new(LANES).expect("lanes"),
            NonZeroUsize::new(QUEUE).expect("queue"),
        )
    }

    fn scope(name: &str) -> OrderingScopeId {
        OrderingScopeId::new(name).expect("scope")
    }

    fn operation(id: &str) -> OperationId {
        OperationId::new(id).expect("operation")
    }

    fn projection(id: &str, order: u64, scopes: &[(&str, u64)]) -> ReservationProjection {
        ReservationProjection {
            operation_id: operation(id),
            reservation_order: order,
            scopes: scopes
                .iter()
                .map(|(scope, sequence)| ReservedScopeProjection {
                    scope: self::scope(scope),
                    reserved_sequence: *sequence,
                })
                .collect(),
        }
    }

    #[test]
    fn malformed_projections_refuse_fail_closed() {
        let mut scheduler = scheduler();
        assert_eq!(
            scheduler.submit(ReservationProjection {
                operation_id: operation("empty"),
                reservation_order: 1,
                scopes: Vec::new(),
            }),
            Err(ScheduleReject::EmptyScopes)
        );
        assert_eq!(
            scheduler.submit(projection("dup", 1, &[("s", 1), ("s", 2)])),
            Err(ScheduleReject::DuplicateScope)
        );
        assert_eq!(
            scheduler.submit(projection("unsorted", 1, &[("b", 1), ("a", 1)])),
            Err(ScheduleReject::UnsortedScopes)
        );
        scheduler
            .submit(projection("once", 1, &[("s", 1)]))
            .expect("first submit");
        assert_eq!(
            scheduler.submit(projection("once", 2, &[("t", 1)])),
            Err(ScheduleReject::DuplicateOperation)
        );
    }

    #[test]
    fn crossed_order_and_sequence_refuse_as_corrupt() {
        let mut scheduler = scheduler();
        scheduler
            .submit(projection("first", 1, &[("s", 1)]))
            .expect("first");
        // Higher order must carry a higher sequence on the shared scope.
        assert_eq!(
            scheduler.submit(projection("crossed", 2, &[("s", 1)])),
            Err(ScheduleReject::InconsistentSequences)
        );
        // A duplicate coordinator order on a shared scope refuses: orders
        // are globally unique per reservation.
        assert_eq!(
            scheduler.submit(projection("clash", 1, &[("s", 9)])),
            Err(ScheduleReject::InconsistentSequences)
        );
        // Disjoint scopes never compare, so an independent reservation with
        // any order/sequence still validates structurally.
        scheduler
            .submit(projection("parallel", 2, &[("t", 1)]))
            .expect("disjoint scopes do not compare");
    }

    #[test]
    fn bounded_queue_and_drain_refuse_new_work() {
        let mut scheduler = WriteScheduler::new(
            NonZeroUsize::new(1).expect("lanes"),
            NonZeroUsize::new(1).expect("queue"),
        );
        scheduler
            .submit(projection("first", 1, &[("s", 1)]))
            .expect("first");
        assert_eq!(
            scheduler.submit(projection("second", 2, &[("t", 1)])),
            Err(ScheduleReject::QueueFull)
        );
        assert!(!scheduler.is_drained());
        let blockers = scheduler.begin_drain();
        assert!(
            blockers.is_empty(),
            "drain entered over certain work only: {blockers:?}"
        );
        assert_eq!(
            scheduler.submit(projection("third", 3, &[("u", 1)])),
            Err(ScheduleReject::Draining)
        );
    }

    #[test]
    fn disjoint_scopes_proceed_concurrently() {
        let mut scheduler = scheduler();
        scheduler
            .submit(projection("a", 2, &[("scope-a", 1)]))
            .expect("a");
        scheduler
            .submit(projection("b", 1, &[("scope-b", 1)]))
            .expect("b");
        // Priority order follows reservation_order, not submission order.
        assert_eq!(scheduler.ready(0), vec![operation("b"), operation("a")]);
        scheduler
            .mark_in_flight(&operation("b"), 0)
            .expect("b runs");
        scheduler
            .mark_in_flight(&operation("a"), 0)
            .expect("a runs concurrently");
        assert_eq!(scheduler.in_flight_count(), 2);
        scheduler
            .complete(&operation("b"), CompletionOutcome::Committed, 0)
            .expect("b commits");
        scheduler
            .complete(&operation("a"), CompletionOutcome::Committed, 0)
            .expect("a commits");
        assert!(scheduler.is_drained());
    }

    #[test]
    fn shared_scope_serializes_by_reservation_order() {
        let mut scheduler = scheduler();
        scheduler
            .submit(projection("late", 2, &[("shared", 2)]))
            .expect("late");
        scheduler
            .submit(projection("early", 1, &[("shared", 1)]))
            .expect("early");
        assert_eq!(scheduler.ready(0), vec![operation("early")]);
        assert_eq!(
            scheduler.mark_in_flight(&operation("late"), 0),
            Err(ScheduleReject::NotReady)
        );
        scheduler
            .mark_in_flight(&operation("early"), 0)
            .expect("early runs");
        assert!(scheduler.ready(0).is_empty());
        scheduler
            .complete(&operation("early"), CompletionOutcome::Committed, 0)
            .expect("early commits");
        assert_eq!(scheduler.ready(0), vec![operation("late")]);
    }

    #[test]
    fn deterministic_rejection_gaps_the_sequence_for_successors() {
        let mut scheduler = scheduler();
        scheduler
            .submit(projection("doomed", 1, &[("s", 1)]))
            .expect("doomed");
        scheduler
            .submit(projection("next", 2, &[("s", 2)]))
            .expect("next");
        scheduler
            .mark_in_flight(&operation("doomed"), 0)
            .expect("doomed runs");
        scheduler
            .complete(&operation("doomed"), CompletionOutcome::Rejected, 0)
            .expect("doomed rejected");
        // The gap does not wedge the scope: the successor proceeds.
        assert_eq!(scheduler.ready(0), vec![operation("next")]);
        scheduler
            .mark_in_flight(&operation("next"), 0)
            .expect("next runs");
        scheduler
            .complete(&operation("next"), CompletionOutcome::DeadLetter, 0)
            .expect("next dead-letters");
        assert!(scheduler.is_drained());
    }

    #[test]
    fn unknown_pauses_only_dependent_scopes_until_resolved() {
        let mut scheduler = scheduler();
        scheduler
            .submit(projection("risky", 1, &[("shared", 1)]))
            .expect("risky");
        scheduler
            .submit(projection("dependent", 2, &[("shared", 2)]))
            .expect("dependent");
        scheduler
            .submit(projection("free", 1, &[("other", 1)]))
            .expect("free");
        scheduler
            .mark_in_flight(&operation("risky"), 0)
            .expect("risky runs");
        scheduler
            .complete(
                &operation("risky"),
                CompletionOutcome::Unknown { retry_after_ms: 50 },
                10,
            )
            .expect("risky unknown");
        // Dependent scope pauses; the independent scope still schedules.
        assert_eq!(scheduler.ready(10), vec![operation("free")]);
        assert_eq!(
            scheduler.mark_in_flight(&operation("dependent"), 10),
            Err(ScheduleReject::NotReady)
        );
        // Terminal resolution reopens the head: the retry delay guarded
        // the unknown window, and recovery evidence ends it. Both the
        // independent and the dependent scope schedule now.
        assert_eq!(
            scheduler.resolve_uncertain(&operation("risky"), CompletionOutcome::Committed, 20),
            Ok(())
        );
        assert_eq!(
            scheduler.ready(20),
            vec![operation("free"), operation("dependent")]
        );
        assert_eq!(
            scheduler.resolve_uncertain(&operation("risky"), CompletionOutcome::Committed, 60),
            Err(ScheduleReject::NotUncertain)
        );
        for id in ["free", "dependent"] {
            scheduler
                .mark_in_flight(&operation(id), 20)
                .expect("resolved lanes run");
            scheduler
                .complete(&operation(id), CompletionOutcome::Committed, 20)
                .expect("resolved lanes commit");
        }
        assert!(scheduler.is_drained());
    }

    #[test]
    fn drain_reports_uncertain_blockers_until_caller_resolves() {
        let mut scheduler = scheduler();
        scheduler
            .submit(projection("uncertain-a", 1, &[("s", 1)]))
            .expect("a");
        scheduler
            .submit(projection("blocked-b", 2, &[("s", 2)]))
            .expect("b");
        scheduler
            .mark_in_flight(&operation("uncertain-a"), 0)
            .expect("a runs");
        scheduler
            .complete(
                &operation("uncertain-a"),
                CompletionOutcome::Unknown { retry_after_ms: 0 },
                0,
            )
            .expect("a unknown");
        // The drain names its mandatory resolution set instead of starving
        // silently: no quiescence while the uncertain outcome is open, and
        // the successor never becomes ready behind it.
        let blockers = scheduler.begin_drain();
        assert_eq!(blockers, vec![operation("uncertain-a")]);
        assert_eq!(blockers, scheduler.uncertain_operations());
        assert!(!scheduler.is_drained());
        assert!(scheduler.ready(0).is_empty());
        // New submissions still refuse during the drain.
        assert_eq!(
            scheduler.submit(projection("late", 3, &[("t", 1)])),
            Err(ScheduleReject::Draining)
        );
        // The caller resolves through the explicit terminal path (recovery
        // reconciled first, as for any unknown outcome): the successor then
        // becomes ready — no silent loss, no automatic retry.
        scheduler
            .resolve_uncertain(&operation("uncertain-a"), CompletionOutcome::Committed, 10)
            .expect("caller resolves a");
        assert!(scheduler.uncertain_operations().is_empty());
        assert_eq!(scheduler.ready(10), vec![operation("blocked-b")]);
        scheduler
            .mark_in_flight(&operation("blocked-b"), 10)
            .expect("b runs");
        scheduler
            .complete(&operation("blocked-b"), CompletionOutcome::Committed, 10)
            .expect("b commits");
        assert!(scheduler.is_drained());
    }

    #[test]
    fn lanes_cap_concurrent_readiness() {
        let mut scheduler = WriteScheduler::new(
            NonZeroUsize::new(1).expect("lanes"),
            NonZeroUsize::new(QUEUE).expect("queue"),
        );
        scheduler
            .submit(projection("one", 1, &[("a", 1)]))
            .expect("one");
        scheduler
            .submit(projection("two", 2, &[("b", 1)]))
            .expect("two");
        assert_eq!(scheduler.ready(0), vec![operation("one")]);
        scheduler
            .mark_in_flight(&operation("one"), 0)
            .expect("one runs");
        assert!(scheduler.ready(0).is_empty());
    }

    // WORK_UNIT_CASE: 2030/6 — scheduler occupancy snapshot (994/14).
    #[test]
    fn occupancy_snapshot_tracks_pending_in_flight_and_uncertain() {
        let mut scheduler = scheduler();
        let empty = scheduler.occupancy();
        assert_eq!(
            empty,
            SchedulerOccupancy {
                pending: 0,
                in_flight: 0,
                uncertain: 0,
                draining: false,
                lanes: LANES,
                max_pending: QUEUE,
            }
        );
        assert!(scheduler.admission().admitted());
        scheduler
            .submit(projection("risky", 1, &[("shared", 1)]))
            .expect("risky");
        scheduler
            .submit(projection("next", 2, &[("shared", 2)]))
            .expect("next");
        scheduler
            .mark_in_flight(&operation("risky"), 0)
            .expect("risky runs");
        scheduler
            .complete(
                &operation("risky"),
                CompletionOutcome::Unknown { retry_after_ms: 0 },
                0,
            )
            .expect("risky unknown");
        // Uncertain work keeps its entry and its scope hold: the snapshot
        // reports it instead of observing quiescence.
        let snapshot = scheduler.occupancy();
        assert_eq!(snapshot.pending, 2);
        assert_eq!(snapshot.in_flight, 1);
        assert_eq!(snapshot.uncertain, 1);
        assert!(!snapshot.draining);
        scheduler
            .resolve_uncertain(&operation("risky"), CompletionOutcome::Committed, 10)
            .expect("risky resolves");
        let resolved = scheduler.occupancy();
        assert_eq!(resolved.pending, 1);
        assert_eq!(resolved.uncertain, 0);
    }

    // WORK_UNIT_CASE: 2030/7 — scheduler admission sheds and refuses (994/14).
    #[test]
    fn saturated_queue_sheds_while_drain_refuses_new_work() {
        let mut scheduler = WriteScheduler::new(
            NonZeroUsize::new(1).expect("lanes"),
            NonZeroUsize::new(1).expect("queue"),
        );
        assert_eq!(
            scheduler.admission(),
            SchedulerAdmission::Admitted {
                free_lanes: 1,
                free_queue: 1,
            }
        );
        scheduler
            .submit(projection("first", 1, &[("s", 1)]))
            .expect("first");
        // The verdict matches `submit` without mutating: a full queue
        // sheds, and the failed submit leaves the snapshot unchanged.
        assert_eq!(scheduler.admission(), SchedulerAdmission::ShedQueueFull);
        assert_eq!(
            scheduler.submit(projection("second", 2, &[("t", 1)])),
            Err(ScheduleReject::QueueFull)
        );
        assert_eq!(scheduler.occupancy().pending, 1);
        let blockers = scheduler.begin_drain();
        assert!(blockers.is_empty());
        assert_eq!(scheduler.admission(), SchedulerAdmission::RefusedDraining);
        assert!(!scheduler.admission().admitted());
        assert!(scheduler.occupancy().draining);
    }

    /// Corpus-driven replay: finite event/invariant sequences from
    /// `tests/data/write_scheduler_sequences.json`. Each sequence replays
    /// submits, readiness snapshots, completions and drains, then checks the
    /// recorded invariants. The corpus is data, not logic: adding a case
    /// never changes the scheduler.
    #[derive(Debug, Deserialize)]
    struct CorpusStep {
        #[serde(default)]
        submit: Option<CorpusSubmit>,
        #[serde(default)]
        expect_ready: Option<Vec<String>>,
        #[serde(default)]
        begin_drain: Option<bool>,
        #[serde(default)]
        complete: Option<CorpusComplete>,
        #[serde(default)]
        expect_reject: Option<String>,
    }

    #[derive(Debug, Deserialize)]
    struct CorpusSubmit {
        id: String,
        order: u64,
        scopes: Vec<(String, u64)>,
    }

    #[derive(Debug, Deserialize)]
    struct CorpusComplete {
        id: String,
        outcome: String,
        at_ms: u64,
    }

    #[derive(Debug, Deserialize)]
    struct CorpusSequence {
        name: String,
        lanes: usize,
        queue: usize,
        steps: Vec<CorpusStep>,
    }

    fn corpus_outcome(name: &str, at_ms: u64) -> CompletionOutcome {
        match name {
            "committed" => CompletionOutcome::Committed,
            "rejected" => CompletionOutcome::Rejected,
            "dead_letter" => CompletionOutcome::DeadLetter,
            "cancelled" => CompletionOutcome::Cancelled,
            "unknown" => CompletionOutcome::Unknown { retry_after_ms: 0 },
            unknown => panic!("unknown corpus outcome: {unknown} at {at_ms}"),
        }
    }

    fn corpus_reject(name: &str) -> ScheduleReject {
        match name {
            "DuplicateOperation" => ScheduleReject::DuplicateOperation,
            "QueueFull" => ScheduleReject::QueueFull,
            "Draining" => ScheduleReject::Draining,
            "EmptyScopes" => ScheduleReject::EmptyScopes,
            "DuplicateScope" => ScheduleReject::DuplicateScope,
            "UnsortedScopes" => ScheduleReject::UnsortedScopes,
            "InconsistentSequences" => ScheduleReject::InconsistentSequences,
            unexpected => panic!("unknown corpus reject {unexpected}"),
        }
    }

    fn replay_step(scheduler: &mut WriteScheduler, sequence: &str, step: CorpusStep) {
        if let Some(submit) = step.submit {
            let projection = ReservationProjection {
                operation_id: operation(&submit.id),
                reservation_order: submit.order,
                scopes: submit
                    .scopes
                    .iter()
                    .map(|(scope, reserved_sequence)| ReservedScopeProjection {
                        scope: self::scope(scope),
                        reserved_sequence: *reserved_sequence,
                    })
                    .collect(),
            };
            match step.expect_reject.as_deref() {
                Some(expected) => assert_eq!(
                    scheduler.submit(projection),
                    Err(corpus_reject(expected)),
                    "sequence {sequence}"
                ),
                None => scheduler.submit(projection).expect("corpus submit"),
            }
        }
        if let Some(expected) = step.expect_ready {
            let ready: Vec<String> = scheduler
                .ready(0)
                .iter()
                .map(|id| id.as_str().to_owned())
                .collect();
            assert_eq!(ready, expected, "sequence {sequence}");
            for id in ready {
                scheduler
                    .mark_in_flight(&operation(&id), 0)
                    .expect("corpus dispatch");
            }
        }
        if step.begin_drain.unwrap_or(false) {
            // The corpus never drains over uncertain work (no sequence
            // completes as unknown): a future sequence that does must add
            // an explicit resolution step first, not drain silently.
            let blockers = scheduler.begin_drain();
            assert!(
                blockers.is_empty(),
                "sequence {sequence} drains over uncertain work: {blockers:?}"
            );
        }
        if let Some(complete) = step.complete {
            // Corpus completions name explicitly dispatched operations
            // only: every completion target must have left the ready set
            // through a recorded `expect_ready` snapshot first. Implicit
            // dispatch here would let a completion exercise progress while
            // bypassing the corpus's ordered readiness observation.
            let id = operation(&complete.id);
            if scheduler
                .pending
                .get(&id)
                .is_some_and(|operation| !operation.in_flight)
            {
                panic!(
                    "sequence {sequence}: completion target {} was not explicitly dispatched",
                    id.as_str()
                );
            }
            scheduler
                .complete(
                    &id,
                    corpus_outcome(&complete.outcome, complete.at_ms),
                    complete.at_ms,
                )
                .expect("corpus complete");
        }
    }

    #[test]
    fn corpus_sequences_replay_with_recorded_invariants() {
        let text = include_str!("../tests/data/write_scheduler_sequences.json");
        let sequences: Vec<CorpusSequence> =
            serde_json::from_str(text).expect("scheduler corpus parses");
        assert!(!sequences.is_empty(), "empty corpus proves nothing");
        for sequence in sequences {
            let mut scheduler = WriteScheduler::new(
                NonZeroUsize::new(sequence.lanes).expect("corpus lanes"),
                NonZeroUsize::new(sequence.queue).expect("corpus queue"),
            );
            for step in sequence.steps {
                replay_step(&mut scheduler, &sequence.name, step);
            }
            assert!(
                scheduler.is_drained(),
                "sequence {} leaves work behind",
                sequence.name
            );
        }
    }

    #[test]
    #[should_panic(expected = "was not explicitly dispatched")]
    fn corpus_completion_without_explicit_dispatch_is_refused() {
        // Tripwire for the replay harness: a completion whose target never
        // left the ready set through a recorded `expect_ready` snapshot
        // must fail loudly instead of dispatching implicitly.
        let mut scheduler = WriteScheduler::new(
            NonZeroUsize::new(2).expect("lanes"),
            NonZeroUsize::new(8).expect("queue"),
        );
        scheduler
            .submit(projection("op-lonely", 1, &[("s", 1)]))
            .expect("submit");
        replay_step(
            &mut scheduler,
            "proof",
            CorpusStep {
                submit: None,
                expect_ready: None,
                begin_drain: None,
                complete: Some(CorpusComplete {
                    id: "op-lonely".to_owned(),
                    outcome: "committed".to_owned(),
                    at_ms: 0,
                }),
                expect_reject: None,
            },
        );
    }
}
