//! Bounded, release-driven fair-pull progress over the coordinator's own
//! admitted projection (issue #1683 W1, I14.8).
//!
//! I14.8 closes with: "Scheduler is pull-based: terminal/deferred/blocked
//! attempt releases its slot, then the next currently admissible Ready Work
//! Item is selected. Mechanical queue progress never depends on an LLM
//! remembering to start another agent." The selector behind that sentence is
//! `AgentCoordinator::select_ready`; the types here are the *join* around it —
//! what arms it, what one drive is allowed to do, and what the caller is told.
//! The drive itself is [`AgentCoordinator::drive_fair_pull`], which calls that
//! selector through [`AgentCoordinator::pull_next`].
//!
//! It is worth being exact about which entry point the production path uses.
//! `drive_fair_pull` pulls through [`AgentCoordinator::pull_next`] on every pull
//! it performs — the first and the one after each start. That wrapper is the
//! profile-bound *single pull* over [`AgentCoordinator::select_ready`], so
//! there is one profile-bound entry to the selector rather than a bypass and a
//! wrapper that could drift apart. The drive reads the attempt record, the
//! canonical enqueue ordinal and the stored admission receipt between a pull
//! and the start it acts on from the coordinator's own maps, not from the
//! pull's return value. [`AgentCoordinator::next_ready`] is the profile-free
//! single-shot read and is not reached from production; this module's
//! reachability claim below is a claim about `drive_fair_pull` only.
//!
//! # Event-driven *with* bounded recovery polling, and which of the two is
//! # authoritative
//!
//! "Event-driven with bounded recovery polling" is a conjunction of two
//! different things, and only the conjunction is correct:
//!
//! - **Event-driven** is the low-latency arm. A state change that makes more
//!   work eligible should drive the pull at the moment of the change, not on
//!   some later tick. The seam for that is [`FairPullLoop`]: the four
//!   transitions that release a slot — `reconcile_cancellation`,
//!   `mark_worker_lost`, `submit_result` and `reconcile_unknown_outcome` — and
//!   the three that change what is queued — `admit`, `reassign` and
//!   `start_attempt` — each arm the loop through
//!   `AgentCoordinator::note_selection_inputs_changed`, and
//!   `AgentCoordinator::drive_fair_pull` reports the wake it consumed in
//!   [`FairPullOutcome::consumed_wake`].
//! - **Bounded recovery polling** is the safety net. An event-only loop is a
//!   lost-wakeup deadlock: a dropped, coalesced or pre-registered notification
//!   leaves the loop waiting forever for work that is already eligible. So the
//!   poll must be *always armed* — a fallback that runs on every bounded
//!   cadence tick whether or not a wake is pending, never a degraded mode
//!   entered after a failure.
//!
//! **The bounded poll is authoritative; the event is an optimisation.** The
//! deciding property is in [`FairPullOutcome::consumed_wake`]: it is
//! "evidence, not a gate: the drive runs its bounded loop either way", so
//! `drive_fair_pull` performs at least one pull even when
//! `take_wake` returned `None`. Correctness therefore rests on the poll; the
//! event only decides *when* the same work is noticed, and a missed event
//! costs one cadence of latency rather than stranding work. I8.3's
//! deterministic loop is the same shape — `observe` is a step of the loop, not
//! the thing that makes the loop run — and I14.8's "Mechanical queue progress
//! never depends on an LLM remembering to start another agent" is the
//! normative consequence: a reminder that can be forgotten is not a scheduler.
//!
//! Four facts make that a real join rather than a restatement:
//!
//! 1. **The wake is a coordinator transition, not a separate notification.**
//!    The event that releases the slot is the same event that arms the drive,
//!    so there is no second wake channel that could disagree with the
//!    projection. The arm is a latch and an evidence counter, never an
//!    authority: `take_wake` returning `None` does not stop the drive.
//! 2. **The cursor is the durable event log.** The published cursor is
//!    `events.len()` at the newest observed selection-input change, so
//!    `AgentCoordinator::replay_snapshot_events` re-derives it by running the
//!    same seven transitions, and a restart can neither strand eligible work
//!    nor renew anyone's age.
//! 3. **The bound is derived, never invented.** A drive starts at most one
//!    attempt per currently non-terminal admitted attempt, and `admit` /
//!    `reassign` refuse to push the coordinator past the validated
//!    `CoordinatorConfig::max_admitted_attempts`, so the loop is finite with no
//!    constant chosen by this module. The recovery poll's own cadence belongs
//!    to the caller's existing bounded tick; this crate names no interval.
//! 4. **There is one profile-bound entry to the selector.**
//!    `drive_fair_pull` pulls through [`AgentCoordinator::pull_next`], so the
//!    production path and the public single-shot entry run the same wrapper
//!    over [`AgentCoordinator::select_ready`] and cannot diverge. The only
//!    other entry, [`AgentCoordinator::next_ready`], is the profile-free
//!    single-shot read; keeping the drive on the profile-bound wrapper is what
//!    lets it re-pull over the live view after every start, because a profile-
//!    free peek could not apply any per-class ceiling.
//!
//! Selection is not execution. A drive turns a selection into a `Running`
//! attempt through the existing [`AgentCoordinator::start_attempt`] transition,
//! which remains the only transition that starts an attempt and still
//! authorizes nothing: provider execution binding is a later, separately proven
//! step ([`AgentCoordinator::bind_provider_execution`]).
//!
//! That transition is also where the selection is revalidated and its
//! reservation re-checked (issue #1683 W3). It re-presents the item's own
//! stored admission receipt to the sealed provider verifier and re-checks the
//! route's capacity reservation against the live view, both before any state
//! moves, so a drive never spends a selection on the snapshot it was taken from
//! and a selection that went stale between the pull and the start is refused
//! rather than launched. See [`AgentCoordinator::start_attempt`].
//!
//! # Production reachability
//!
//! Reachable in a non-test build, and the two arms are separate callers. Each
//! hop below is a `path.rs::symbol` name that `git grep` confirms, so the claim
//! is checkable rather than a bare file path:
//!
//! - **Event arm.** `agent_fabric.rs::AgentFabric::drive_fair_pull` calls
//!   [`AgentCoordinator::drive_fair_pull`] on the daemon's live coordinator, and
//!   `solo_agent_driver.rs::solo_ingest_result` calls *that* on the production
//!   worker settle path, so released capacity advances work in the same
//!   operation that released it. Neither is `cfg(test)`-gated.
//! - **Recovery-poll arm.** `solo_agent_driver.rs::solo_fair_pull_recovery`
//!   calls the same [`AgentCoordinator::drive_fair_pull`] on the daemon's
//!   existing bounded activation cadence, and
//!   `daemon_runtime.rs::maybe_start_fair_pull_recovery` starts it on **every**
//!   tick of that cadence. It is not gated on a pending wake, on a prior
//!   failure, or on anything else: that is what makes it a fallback rather than
//!   a degraded mode, and it is the arm that survives a lost notification.
//!
//! The recovery poll reuses the same `ACTIVATION_POLL_INTERVAL` tick every
//! other bounded step in `run_loop` already rides. No new timer, no new
//! interval constant, and no second scheme: the recovery arm is the *same*
//! drive over the *same* projection, differing only in that it does not wait
//! to be told there is work.
//!
//! Still blocked, and stated here rather than hidden: nothing in the tree
//! constructs the provider-verified `ProviderAdmissionReceipt` that
//! `AgentCoordinator::admit` requires — the G-11 admission owner, issue #1678.
//! Every struct literal of that receipt is in `src/tests.rs`,
//! `src/core/admission_normalization_tests.rs` or `tests/coordinator.rs`, and
//! this crate is forbidden from minting one, because it is provider evidence.
//! So a drive over a coordinator built by the plan/define path sees an empty
//! `attempts` map, performs one pull, selects nothing, and stops — the correct
//! bounded behaviour of an empty projection.
//!
//! The claim is deliberately narrower than "`admit` is unreachable".
//! `AgentCoordinator::admit` *does* have a production path: its single non-test
//! caller is `core.rs::replay_snapshot_events`, reached from three `bins/eliotd`
//! restore sites via `AgentCoordinator::restore_with_admitted_provider`. A drive
//! over a coordinator restored from an event log containing
//! `CoordinatorEvent::PlanAdmitted` really does select and start. No such
//! snapshot exists yet, because producing one needs the same absent issuer.
//! Nothing here waits for that owner and nothing here forges an admission to
//! make it look live.
//!
//! Proof ceiling: [`FAIR_PULL_LOOP_PROOF_CEILING`]. This loop starts
//! coordinator attempts and nothing else: no process, no provider/admission/
//! lease/route evidence, no canonical Task write, no Finish authority.

use eliot_agent_api::AttemptId;
use serde::Serialize;

use crate::model::{AdmissionId, ReadySelectionOutcome, WorkClass};

/// Proof ceiling of [`AgentCoordinator::drive_fair_pull`](crate::AgentCoordinator::drive_fair_pull):
/// it starts coordinator attempts under their own admission and nothing else.
pub const FAIR_PULL_LOOP_PROOF_CEILING: &str = "FAIR_PULL_LOOP_CANDIDATE_ONLY";

/// Wake and coalescing state of the pull-based scheduler.
///
/// In-memory scheduler state, exactly like the fair virtual times it drives: it
/// is not a snapshot field and not canonical work state, and the durable part it
/// points at (the coordinator's event log) is what a restore replays.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct FairPullLoop {
    /// `events.len()` at the newest observed selection-input change.
    cursor: u64,
    /// A selection input changed since the last drive consumed a wake.
    pending: bool,
    /// Wakes observed since the last drive consumed one.
    coalesced: u64,
}

impl FairPullLoop {
    /// Records that a selection input changed at `event_sequence`, coalescing
    /// with any wake already pending.
    pub(crate) fn arm(&mut self, event_sequence: u64) {
        self.cursor = event_sequence;
        self.coalesced = self.coalesced.saturating_add(1);
        self.pending = true;
    }

    /// Consumes the pending wake as `(cursor, coalesced_wakes)`, or `None` when
    /// no selection input has changed since the last drive.
    pub(crate) fn take_wake(&mut self) -> Option<(u64, u64)> {
        if !self.pending {
            return None;
        }
        self.pending = false;
        let coalesced = self.coalesced;
        self.coalesced = 0;
        Some((self.cursor, coalesced))
    }

    /// The durable cursor: `events.len()` at the newest armed transition, or
    /// zero while nothing has changed yet.
    pub(crate) const fn cursor(&self) -> u64 {
        self.cursor
    }
}

/// One attempt a single drive selected and started.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct FairPullStart {
    pub attempt_id: AttemptId,
    /// The admission this attempt was started under, read from the attempt's
    /// own stored record and never synthesized.
    pub admission_id: AdmissionId,
    pub work_class: WorkClass,
    /// Canonical enqueue ordinal of the started item, under the age rule named
    /// in [`crate::FAIR_PULL_ALGORITHM`]. It is the age that won the pull, published
    /// so a caller sees the ordering decision instead of re-deriving it.
    pub enqueue_sequence: u64,
}

/// Exact outcome of one bounded fair-pull drive (issue #1683 W1, I14.8).
///
/// The real effects of the drive plus its exact decision record. `started` is
/// not a claim: each entry names an attempt the coordinator actually
/// transitioned to `Running` through its own admission, and `last_selection` is
/// the complete selector record of the pull that ended the drive — including
/// the limiting dimension of every class it could not serve, so an empty drive
/// is an explained refusal rather than a silent `None`.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct FairPullOutcome {
    /// Always [`crate::FAIR_PULL_ALGORITHM`], which also names the frozen within-class
    /// age rule and its clock domain.
    pub algorithm: &'static str,
    /// Always [`FAIR_PULL_LOOP_PROOF_CEILING`].
    pub proof_ceiling: &'static str,
    /// Profile revision every per-class ceiling in `last_selection` was taken
    /// from. Not optional: this drive is profile-bound and refuses rather than
    /// running without per-class partitions.
    pub profile_revision: String,
    pub capacity_identity: String,
    pub capacity_revision: eliot_agent_contracts::RevisionId,
    /// Durable cursor this drive read: the coordinator's event-log length at
    /// the newest observed selection-input change. A restore replays that log
    /// and re-derives the same value.
    pub cursor_event_sequence: u64,
    /// `Some((cursor, coalesced_wakes))` when a selection input had changed
    /// since the last drive, `None` when the caller re-polled unchanged state.
    ///
    /// This is evidence, not a gate: the drive runs its bounded loop either
    /// way, which is what makes a missed wake unable to strand eligible work.
    pub consumed_wake: Option<(u64, u64)>,
    /// Whether this drive ran as the always-armed bounded recovery poll
    /// (issue #1683 W5) rather than as the response to an observed event.
    ///
    /// `Some(true)` is the arm that survives a lost notification: the caller
    /// invoked the drive because its bounded cadence fired, not because a wake
    /// was pending, so `consumed_wake` is legitimately `None` on a drive that
    /// still performed a real pull. `Some(false)` is the event arm.
    /// `None` when the caller did not classify the drive, which keeps the
    /// field additive for an existing caller rather than forcing every caller
    /// to take a position it has no evidence for.
    pub recovery_poll: Option<bool>,
    /// Upper bound this drive enforced: the number of non-terminal admitted
    /// attempts it could have started. Derived from the projection, never a
    /// constant chosen here.
    pub poll_bound: usize,
    /// Pulls actually performed. At most `poll_bound + 1`: one per started
    /// attempt plus the pull that observed the state which ended the drive.
    pub pulls_performed: usize,
    /// Attempts started, in selection order.
    pub started: Vec<FairPullStart>,
    /// The pull that ended this drive, in full. Its `deferrals` name the exact
    /// limiting dimension, observed value, limit and profile revision for every
    /// class that held ready work and was closed.
    pub last_selection: ReadySelectionOutcome,
}
