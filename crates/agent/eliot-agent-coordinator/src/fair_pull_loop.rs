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
//! selector directly.
//!
//! It is worth being exact about which entry point the production path uses,
//! because two sibling selectors sit next to it and neither is on that path.
//! `drive_fair_pull` calls `AgentCoordinator::select_ready` twice per drive
//! (once before the loop and once after every start), **not**
//! [`AgentCoordinator::pull_next`], which is a thin profile-bound wrapper over
//! the same selector and has no caller anywhere in the tree. Selecting over
//! `select_ready` rather than over `pull_next` is not a stylistic choice: the
//! drive needs the attempt record, the canonical enqueue ordinal and the stored
//! admission receipt between the pull and the start, so an extra wrapper that
//! returned only a `ReadySelectionOutcome` would be a hop it cannot use.
//! [`AgentCoordinator::pull_next`] and [`AgentCoordinator::next_ready`] are
//! single-shot reads for callers that want one decision and no drive; neither is
//! reached from production, and this module's reachability claim below is a
//! claim about `drive_fair_pull` only.
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
//! 3. **The bound is derived, never invented.** A drive spends each currently
//!    non-terminal admitted attempt at most once — it either starts it or
//!    re-reads once over a stale refusal — and `admit` /
//!    `reassign` refuse to push the coordinator past the validated
//!    `CoordinatorConfig::max_admitted_attempts`, so the loop is finite with no
//!    constant chosen by this module. The recovery poll's own cadence belongs
//!    to the caller's existing bounded tick; this crate names no interval.
//! 4. **The selector is one function, and the drive is its only production
//!    entry.** `drive_fair_pull` calls `AgentCoordinator::select_ready`
//!    directly. The two sibling selectors named above, `pull_next` and
//!    `next_ready`, are single-shot reads and neither is on the production path;
//!    keeping the drive on the selector itself is what lets it re-pull over the
//!    live view after every start, which a wrapper returning one decision could
//!    not do.
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
//! A refusal there is not the end of the drive. I14.8's "no unbounded
//! retries" is the limit; a refusal that means the evidence moved under the
//! read is the other side of it, because I14.8 also says "the next currently
//! admissible Ready Work Item is selected" and "mechanical queue progress
//! never depends on an LLM remembering to start another agent". So the drive
//! takes **one fresh bounded read** over a staleness refusal
//! ([`stale_selection_disposition`]) and spends whatever that read offers,
//! which is released capacity advancing work with no further command — the
//! event that abandoned the read is not being papered over, because the read
//! is the same selector, just later.
//!
//! Two things keep that from being a retry loop, and neither is a constant:
//! an attempt is **spent** at most once per drive, so the re-reads are charged
//! against the same `poll_bound` the starts are; and only staleness re-reads.
//! A refusal that means "nothing more is eligible" — a route at its effective
//! limit, or this coordinator's own records disagreeing with each other — ends
//! the drive by propagating the owner's own error, unchanged. And the
//! refusals that did re-read are published in [`FairPullOutcome::stale_refusals`]
//! as typed dispositions, so A8's exact-disposition requirement survives the
//! retry: a refusal is never swallowed into a generic "nothing to do".
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

use crate::model::{AdmissionId, CoordinatorError, ReadySelectionOutcome, WorkClass};

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

/// The typed owner refusal that made one selection stale, and therefore worth
/// a fresh bounded read (issue #1683 A8/W7).
///
/// One variant per [`CoordinatorError`] the drive classifies as staleness, so
/// the published disposition is the owner's own refusal identity rather than a
/// re-derivation of it. None of these is flattened into a boolean, and none is
/// merged: `StaleCapacity` and `StaleProviderBinding` are different owners
/// moving under the coordinator, and a reader that is told which one fired can
/// tell a capacity-view change from a provider-binding change without parsing
/// a message string.
///
/// Exhaustion is deliberately **not** here. `CoordinatorError::Backpressure`
/// names a route already at its effective limit, which is not staleness, and it
/// is carried to the caller as itself — with its exact `active`, `requested`
/// and `limit` — rather than becoming a re-read.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum FairPullStaleDisposition {
    /// [`CoordinatorError::StaleCapacity`]: the live capacity identity or
    /// revision this item's stored claim was taken against has moved.
    StaleCapacity,
    /// [`CoordinatorError::StaleProviderBinding`]: the persisted provider
    /// binding no longer matches current live provider evidence.
    StaleProviderBinding,
    /// [`CoordinatorError::StaleFence`]: the presented attempt state fence is
    /// no longer the current one.
    StaleFence,
    /// [`CoordinatorError::StaleController`]: the presented controller epoch
    /// or coordinator lease is no longer current, or names another admission.
    StaleController,
    /// [`CoordinatorError::RouteEvidence`]: the route revision the sealed
    /// verifier checked against is stale.
    RouteEvidence,
}

/// One stale-selection refusal a bounded drive spent, and what its fresh
/// bounded read then found (issue #1683 A8/W7, I14.8).
///
/// This is the record that keeps A8's exact-disposition requirement true once
/// the drive retries instead of propagating: the refusal is not swallowed into
/// a generic "nothing to do", it is published. It names the item, the
/// admission whose owner-issued receipt refused it, the typed refusal, and
/// whether the fresh read could offer anything else.
///
/// It is not a second reporting scheme. `last_selection.deferrals` reports
/// refusals the **selector** made (per-class capacity dimensions); this reports
/// refusals the **start boundary** made against owner evidence, and the two
/// vocabularies do not overlap because the two owners do not. Neither record
/// mints the #1679 pull-versus-retry directive vocabulary, which stays with the
/// admission owner.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct FairPullStaleRefusal {
    /// The item whose selection was stale. It is still `Admitted`: a start that
    /// is refused changes nothing, so the item keeps its slot and its age.
    pub attempt_id: AttemptId,
    /// The admission whose own stored `ProviderAdmissionReceipt` refused the
    /// start, read from the record — never re-derived.
    pub admission_id: AdmissionId,
    pub work_class: WorkClass,
    /// Canonical enqueue ordinal, under the age rule named in
    /// [`crate::FAIR_PULL_ALGORITHM`].
    pub enqueue_sequence: u64,
    /// The exact typed owner refusal, unflattened.
    pub disposition: FairPullStaleDisposition,
    /// `true` when the fresh bounded read offered this **same** item again, so
    /// the drive stopped because the read found nothing else to spend.
    ///
    /// It is exact about why the drive ended, which is the difference between
    /// "the re-read helped" and "there was nothing else admissible". `false`
    /// means the fresh read either offered a different item — which the drive
    /// then spends, so this refusal was not the drive's last decision — or
    /// selected nothing at all, which `last_selection` reports in full.
    pub repull_reselected_same_item: bool,
}

/// Classifies one start-boundary refusal as staleness or as exhaustion.
///
/// Exhaustive, and the asymmetry is the point: `Some` means "the evidence this
/// coordinator read moved under it, so a fresh bounded read is worth one", and
/// `None` means "re-read it again and it answers identically", which must
/// terminate the drive rather than spin it.
///
/// Every arm is a decision about the owner that produced the refusal, not
/// about its severity:
///
/// - **Staleness — re-read.** [`CoordinatorError::StaleCapacity`] (the live
///   capacity view moved, produced by `core.rs::validate_route_capacity` and by
///   the sealed verifier's stale-capacity mapping),
///   [`CoordinatorError::StaleProviderBinding`] (live provider evidence no
///   longer matches the persisted binding),
///   [`CoordinatorError::StaleFence`] and [`CoordinatorError::StaleController`]
///   (the presented fence / epoch / lease is no longer current), and
///   [`CoordinatorError::RouteEvidence`] (the sealed verifier's stale-route leg;
///   that mapping is the only producer of this variant reachable from
///   [`AgentCoordinator::start_attempt`](crate::AgentCoordinator::start_attempt)
///   — the crate's other producers are `AgentCoordinator::plan`,
///   `AgentCoordinator::admit`, `validate_recipe_references` /
///   `validate_manifest_references` and the swarm definition admission path,
///   none of which a start runs).
/// - **Exhaustion — terminate.**
///   [`CoordinatorError::Backpressure`] is a route already at its effective
///   limit, which no read inside this drive can change: the drive itself
///   released nothing, so the active count a second read would observe is the
///   same one this refusal already reported. It propagates as itself, carrying
///   its exact `active`/`requested`/`limit`, which is what A8 asks for.
/// - **Inconsistency — terminate.** [`CoordinatorError::IdentityConflict`]
///   (from `core.rs::validate_reservation_admission` /
///   `core.rs::validate_reserved_lane` / `core.rs::reassignment_for`),
///   [`CoordinatorError::ProviderVerification`],
///   [`CoordinatorError::InvalidAttemptState`], [`CoordinatorError::UnknownAttempt`],
///   [`CoordinatorError::UnknownAdmission`], [`CoordinatorError::InvalidField`],
///   [`CoordinatorError::PlanGap`] and [`CoordinatorError::Serialization`]:
///   these say this coordinator's own records do not agree with each other,
///   which a re-read cannot repair and which re-spending would only obscure.
/// - **The other `Stale*` variants — terminate, on purpose.**
///   [`CoordinatorError::StaleTaskRevision`] and
///   [`CoordinatorError::StalePlanRevision`] are produced on this path only by
///   `core.rs::validate_context`, which compares the presented
///   `ExecutionContext` against the very stored receipt the drive derives that
///   context from — a self-comparison, so they cannot fire here at all.
///   [`CoordinatorError::StaleWorker`], [`CoordinatorError::StaleLease`],
///   [`CoordinatorError::StaleResult`] and
///   [`CoordinatorError::StaleAdmission`] have no producer anywhere in
///   `start_attempt`'s call graph either (their producers are `mark_worker_lost`,
///   `reassign`, the result/reconciliation paths, `validate_admitted_lane` and
///   `swarm_execution_ownership.rs`). Listing them here as terminating is the
///   honest placement: they are not staleness *this boundary can observe*, so a
///   re-read would be a claim the code cannot support.
///
/// **Exhaustive, and that is deliberate.** Every [`CoordinatorError`] variant
/// is classified here, so a variant added later is a *compile error at this
/// match* rather than a refusal that quietly becomes a retry loop or, worse, a
/// refusal that quietly vanishes. There is no catch-all arm and no
/// `#[allow]`; the terminating side is written out.
pub(crate) fn stale_selection_disposition(
    refusal: &CoordinatorError,
) -> Option<FairPullStaleDisposition> {
    match refusal {
        CoordinatorError::StaleCapacity => Some(FairPullStaleDisposition::StaleCapacity),
        CoordinatorError::StaleProviderBinding => {
            Some(FairPullStaleDisposition::StaleProviderBinding)
        }
        CoordinatorError::StaleFence => Some(FairPullStaleDisposition::StaleFence),
        CoordinatorError::StaleController => Some(FairPullStaleDisposition::StaleController),
        CoordinatorError::RouteEvidence => Some(FairPullStaleDisposition::RouteEvidence),
        // Exhaustion and inconsistency, every one of them terminating. Listed
        // exhaustively so the match above stays exhaustive without a wildcard.
        CoordinatorError::Backpressure { .. }
        | CoordinatorError::IdentityConflict(_)
        | CoordinatorError::ProviderVerification(_)
        | CoordinatorError::ProviderContract(_)
        | CoordinatorError::InvalidAttemptState(_)
        | CoordinatorError::UnknownAttempt
        | CoordinatorError::UnknownAdmission
        | CoordinatorError::UnknownCandidate
        | CoordinatorError::UnknownMessage
        | CoordinatorError::UnknownWorkClass(_)
        | CoordinatorError::InvalidField(_)
        | CoordinatorError::Serialization(_)
        | CoordinatorError::PlanGap(_)
        | CoordinatorError::RuntimeProfileRejected(_)
        | CoordinatorError::DuplicateIdentity(_)
        | CoordinatorError::DuplicateResult
        | CoordinatorError::IdempotencyConflict
        | CoordinatorError::HostEventQuarantine(_)
        | CoordinatorError::UnknownOutcomeRequiresReconciliation
        | CoordinatorError::IncompleteDescendantClosure
        | CoordinatorError::DeliveryUnavailable
        | CoordinatorError::UnsupportedSnapshot
        | CoordinatorError::SnapshotRollback
        | CoordinatorError::SnapshotDigest
        | CoordinatorError::MissingExecutionBinding
        | CoordinatorError::LegacyResultWire(_)
        | CoordinatorError::MutatingWriterConflict(_)
        | CoordinatorError::BudgetExceeded { .. }
        | CoordinatorError::SemanticDrift(_)
        | CoordinatorError::StaleTaskRevision
        | CoordinatorError::StalePlanRevision
        | CoordinatorError::StaleWorker
        | CoordinatorError::StaleLease
        | CoordinatorError::StaleAdmission
        | CoordinatorError::StaleResult
        | CoordinatorError::RouteMismatch => None,
    }
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
    /// attempts it could have spent — started, or found stale and re-read over.
    /// Derived from the projection, never a constant chosen here.
    pub poll_bound: usize,
    /// Pulls actually performed. Exactly `1 + started.len() +
    /// stale_refusals.len()`, so at most `poll_bound + 1`: one pull before the
    /// first spend, and one fresh pull after each attempt this drive spent —
    /// started or refused stale. The stale re-read is charged against the same
    /// `poll_bound` the starts are rather than added on top, because an attempt
    /// is spent at most once per drive, which is the bound this drive already
    /// documented for starts alone.
    pub pulls_performed: usize,
    /// Attempts started, in selection order.
    pub started: Vec<FairPullStart>,
    /// Stale-selection refusals this drive spent and re-read over, in the order
    /// they occurred.
    ///
    /// It cannot be a partial record: a **non-staleness** refusal returns the
    /// owner's own error instead of this outcome, so a caller holding an
    /// outcome is holding every staleness refusal that drive spent.
    /// [`FairPullStaleRefusal::repull_reselected_same_item`] is `true` on the
    /// last entry exactly when the fresh read found nothing else to spend,
    /// which is the only way a stale refusal is what ends this drive.
    pub stale_refusals: Vec<FairPullStaleRefusal>,
    /// The pull that ended this drive, in full. Its `deferrals` name the exact
    /// limiting dimension, observed value, limit and profile revision for every
    /// class that held ready work and was closed.
    pub last_selection: ReadySelectionOutcome,
}
