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
//!                                 executor lanes, drained generation switch,
//!                                 recovery listing before reallocation
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
//! reserve -> mark_eligible -> begin_execution (guard held across the single
//!   canonical transaction) -> drop guard -> finalize(receipt) | release |
//!   mark_unknown -> finalize(receipt)
//! ```
//!
//! `begin_execution` acquires the in-memory per-scope permits first, then
//! performs the durable `Eligible -> Executing` transition under the exact
//! immutable writer epoch. A durable refusal rolls the permits back, so a
//! failed execution never wedges its scopes. The returned
//! [`ScopeExecutionGuard`] releases its scopes on drop: one canonical
//! transaction may be in flight per Ordering Scope, while disjoint scopes stay
//! concurrent. Lane exhaustion and generation-switch discipline are enforced
//! here; predecessor fairness, canonical-head verification, and
//! recovery-blocked scopes are enforced durably inside ORS and surface here as
//! the owner [`OrsError`].
//!
//! ## Recovery rule
//!
//! After a restart the caller lists [`WriteCoordinator::unresolved`] to
//! exhaustion and reconciles every recovered reservation against its
//! `WriteReceipt`/canonical head through [`WriteCoordinator::finalize`]
//! before the scope accepts new execution. ORS refuses reallocation on
//! blocked scopes (`ScopeRecoveryRequired`) and refuses head jumps
//! (`OrderingHeadMismatch`); the coordinator never bypasses either.

use std::collections::{BTreeMap, BTreeSet};
use std::num::NonZeroUsize;
use std::sync::{Arc, Mutex, MutexGuard};

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
/// not entitled to: scope conflicts never reach ORS, lane exhaustion never
/// queues unboundedly, and a durable refusal rolls the in-memory permits back.
/// ORS lifecycle refusals (predecessor pending, head mismatch, recovery
/// blocked, stale epoch) pass through unchanged as [`CoordinatorError::Ors`].
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
    /// A lane-count change requires a drained generation switch.
    #[error("coordinator is not drained ({in_flight} canonical executions in flight)")]
    NotDrained {
        /// Currently in-flight canonical executions.
        in_flight: usize,
    },
    /// Durable ORS lifecycle refusal, preserved verbatim.
    #[error(transparent)]
    Ors(#[from] eliot_ors::OrsError),
}

/// In-memory execution state for one coordinator generation.
///
/// Durable truth (orders, sequences, lifecycle states, heads) lives in ORS;
/// this map only tracks which scopes currently hold their single canonical
/// execution permit so disjoint scopes stay concurrent.
#[derive(Debug, Default)]
struct CoordinatorState {
    lanes: Option<NonZeroUsize>,
    in_flight: usize,
    busy: BTreeMap<String, String>,
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

impl std::fmt::Debug for WriteCoordinator {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let state = self.lock_state();
        formatter
            .debug_struct("WriteCoordinator")
            .field("lanes", &state.lanes)
            .field("in_flight", &state.in_flight)
            .field("busy_scopes", &state.busy.keys().collect::<Vec<_>>())
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
                return Err(CoordinatorError::ScopeBusy {
                    scope: scope.clone(),
                });
            }
        }
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
    /// Requires quiescence: no in-flight canonical execution and no busy
    /// scope. A refused switch changes nothing; drain first, then switch,
    /// then admit new work on the new generation.
    ///
    /// # Errors
    ///
    /// Returns [`CoordinatorError::NotDrained`] when any execution is still in
    /// flight.
    pub fn reconfigure_lanes(&self, lanes: NonZeroUsize) -> Result<(), CoordinatorError> {
        let mut state = self.lock_state();
        if state.in_flight != 0 || !state.busy.is_empty() {
            return Err(CoordinatorError::NotDrained {
                in_flight: state.in_flight,
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
