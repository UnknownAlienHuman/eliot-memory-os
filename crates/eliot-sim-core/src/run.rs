//! Deterministic run harness: schedule, apply, check, fold into artifact.
//!
//! [`run`] executes one [`ScenarioId`] with one seed: it validates the fault
//! plan fail-closed, submits the scenario commands, drains the scheduler to
//! quiescence or the deterministic horizons, applies every delivery to the
//! [`SimState`], evaluates the invariant suite and the scenario acceptance
//! predicate, and folds everything into a [`SimulationSeedArtifact`]. Lost
//! acknowledgements for committed operations surface as
//! [`SimOutcome::AckLostAfterCommit`] at the drop point, because a lost
//! envelope never reaches the state machine.

use crate::command::{OpId, SimCommand};
use crate::digest::{Canonical, SimDigest};
use crate::event::{SimOutcome, TracedEvent};
use crate::fault::FaultPlanError;
use crate::scenario::{ScenarioDefinition, ScenarioId, SimError, define};
use crate::scheduler::Scheduler;
use crate::seed::{SimConfig, SimulationSeedArtifact};
use crate::state::{OpStatus, SimState};

/// One invariant verdict.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InvariantVerdict {
    /// Stable invariant identifier.
    pub id: &'static str,
    /// Whether the invariant held.
    pub passed: bool,
    /// Human-readable detail naming the witness or the violation.
    pub detail: String,
}

impl Canonical for InvariantVerdict {
    fn feed(&self, digest: &mut SimDigest) {
        digest.feed_tag("invariant-verdict");
        digest.feed_str(self.id);
        digest.feed_bool(self.passed);
        digest.feed_str(&self.detail);
    }
}

/// Full deterministic result of one scenario plus seed.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SimulationReport {
    /// Seed artifact with every digest.
    pub artifact: SimulationSeedArtifact,
    /// Schedule log in delivery order, drops included.
    pub schedule: Vec<crate::scheduler::DeliveryRecord>,
    /// Terminal state.
    pub terminal: SimState,
    /// Invariant verdicts in stable order.
    pub invariants: Vec<InvariantVerdict>,
    /// Full trace in delivery order.
    pub trace: Vec<TracedEvent>,
    /// True when the run drained within its horizons.
    pub drained: bool,
    /// Fail-closed plan diagnosis when the fault plan did not validate.
    /// `None` for every validated run; `Some` exactly when the run skipped
    /// its drain because validation refused the plan.
    pub plan_error: Option<FaultPlanError>,
}

impl SimulationReport {
    /// Returns the minimal failure trace: the full trace when accepted is
    /// empty by construction; otherwise a head prefix plus the trailing
    /// window around the failure, deterministically sliced.
    #[must_use]
    pub fn minimal_failure_trace(&self) -> Vec<TracedEvent> {
        if self.artifact.accepted {
            return Vec::new();
        }
        let window =
            usize::try_from(SimConfig::default_config().failure_trace_window).unwrap_or(usize::MAX);
        minimal_window(&self.trace, window)
    }
}

/// Deterministically slices a head prefix plus trailing window.
fn minimal_window(trace: &[TracedEvent], window: usize) -> Vec<TracedEvent> {
    if trace.len() <= window {
        return trace.to_vec();
    }
    let head = 8_usize.min(trace.len());
    let mut out = trace[..head].to_vec();
    let tail_start = trace.len().saturating_sub(window);
    let tail_from = tail_start.max(head);
    out.extend_from_slice(&trace[tail_from..]);
    out
}

/// Runs one scenario with one seed to a deterministic report.
#[must_use]
pub fn run(id: ScenarioId, seed: u64) -> SimulationReport {
    run_with_config(id, seed, SimConfig::default_config())
}

/// Runs one scenario with one seed and an explicit deterministic config.
///
/// A scenario whose fault plan fails closed validation still returns a
/// report, but the report carries the [`FaultPlanError`] in `plan_error`,
/// never drains, and never accepts. Use [`try_run_with_config`] when the
/// caller prefers the failure as a [`SimError`].
#[must_use]
pub fn run_with_config(id: ScenarioId, seed: u64, config: SimConfig) -> SimulationReport {
    match try_run_with_config(id, seed, config) {
        Ok(report) => report,
        Err(SimError::InvalidPlan(error)) => degraded_report(id, seed, config, error),
        Err(SimError::UnsupportedScenario { .. }) => {
            unreachable!("mandatory scenario ids always resolve")
        }
    }
}

/// Fallible run of one scenario: fails closed with [`SimError::InvalidPlan`]
/// before submitting anything when the scenario's fault plan does not
/// validate.
pub fn try_run(id: ScenarioId, seed: u64) -> Result<SimulationReport, SimError> {
    try_run_with_config(id, seed, SimConfig::default_config())
}

/// Fallible run of one scenario with an explicit deterministic config.
pub fn try_run_with_config(
    id: ScenarioId,
    seed: u64,
    config: SimConfig,
) -> Result<SimulationReport, SimError> {
    try_run_definition(&define(id), seed, config)
}

/// Fallible run of one executable definition. This is the entrypoint that
/// makes fail-closed validation reachable: any definition whose fault plan
/// does not validate returns [`SimError::InvalidPlan`] without submitting a
/// single command.
pub fn try_run_definition(
    definition: &ScenarioDefinition,
    seed: u64,
    config: SimConfig,
) -> Result<SimulationReport, SimError> {
    definition.plan.validate().map_err(SimError::InvalidPlan)?;
    Ok(run_validated(definition, seed, config, None))
}

/// Builds the degraded report for a refused plan: empty state, empty trace,
/// no drain, no acceptance, and the diagnosis carried in `plan_error`.
fn degraded_report(
    id: ScenarioId,
    seed: u64,
    config: SimConfig,
    error: FaultPlanError,
) -> SimulationReport {
    run_validated(&define(id), seed, config, Some(error))
}

fn run_validated(
    definition: &ScenarioDefinition,
    seed: u64,
    config: SimConfig,
    plan_error: Option<FaultPlanError>,
) -> SimulationReport {
    let mut scheduler = Scheduler::new(seed, definition.plan.clone());
    let mut state = SimState::new(definition.mailbox_capacity);
    let mut trace: Vec<TracedEvent> = Vec::new();
    let mut drained = false;
    if plan_error.is_none() {
        for command in &definition.initial {
            scheduler.submit(command.clone());
        }
        drained = drain(&mut scheduler, &mut state, &mut trace, config);
    }
    append_drops(&scheduler, &state, &mut trace);
    trace.sort_by_key(|event| (event.tick.0, event.seq));

    let invariants = check_invariants(&state, &trace);
    let (predicate_holds, _) = acceptance(definition.id, &state, &trace);
    let accepted = plan_error.is_none()
        && drained
        && invariants.iter().all(|item| item.passed)
        && predicate_holds;
    let artifact = fold_artifact(
        definition,
        &scheduler,
        &state,
        &invariants,
        &trace,
        seed,
        config,
        accepted,
    );
    SimulationReport {
        artifact,
        schedule: scheduler.log().to_vec(),
        terminal: state,
        invariants,
        trace,
        drained,
        plan_error,
    }
}

/// Drains the scheduler into the state machine within the deterministic
/// horizons. Returns true only when the queue fully drained.
fn drain(
    scheduler: &mut Scheduler,
    state: &mut SimState,
    trace: &mut Vec<TracedEvent>,
    config: SimConfig,
) -> bool {
    let mut deliveries = 0_u64;
    while let Some(delivery) = scheduler.pop() {
        deliveries = deliveries.saturating_add(1);
        if delivery.envelope.deliver_at.0 > config.max_ticks || deliveries > config.max_deliveries {
            return false;
        }
        let tick = scheduler.now();
        let outcomes = state.apply(&delivery.envelope.command, tick);
        for outcome in outcomes {
            trace.push(TracedEvent {
                tick,
                seq: delivery.envelope.seq,
                fault: delivery.fault,
                outcome,
            });
        }
    }
    scheduler.is_empty()
}

/// Appends drop outcomes after the drain so they observe the terminal
/// commit state.
fn append_drops(scheduler: &Scheduler, state: &SimState, trace: &mut Vec<TracedEvent>) {
    for record in scheduler.log() {
        if record.dropped {
            trace.push(TracedEvent {
                tick: record.tick,
                seq: record.seq,
                fault: record.fault,
                outcome: ack_or_dropped(state, record.seq, &record.command),
            });
        }
    }
}

/// Folds the definition, schedule, terminal state, verdicts, and trace
/// window into the seed artifact.
#[allow(clippy::too_many_arguments)]
fn fold_artifact(
    definition: &crate::scenario::ScenarioDefinition,
    scheduler: &Scheduler,
    state: &SimState,
    invariants: &[InvariantVerdict],
    trace: &[TracedEvent],
    seed: u64,
    config: SimConfig,
    accepted: bool,
) -> SimulationSeedArtifact {
    let mut schedule_digest = SimDigest::new();
    scheduler.feed_schedule(&mut schedule_digest);
    let terminal_digest = SimDigest::of(state);
    let invariant_digest = digest_verdicts(invariants);
    let window = usize::try_from(config.failure_trace_window).unwrap_or(usize::MAX);
    let minimal = minimal_window_or_empty(trace, accepted, window);
    let failure_trace_digest = digest_events(&minimal);
    let code_digest = code_digest_of(definition);
    let profile_digest = SimDigest::of(&config);
    let failure_capsule = if accepted {
        None
    } else {
        Some(SimulationSeedArtifact::capsule_ref(
            schedule_digest,
            terminal_digest,
        ))
    };
    SimulationSeedArtifact {
        scenario: definition.id,
        code_digest,
        profile_digest,
        seed,
        schedule_digest,
        terminal_digest,
        invariant_digest,
        failure_trace_digest,
        trace_len: u64::try_from(trace.len()).unwrap_or(u64::MAX),
        failure_capsule,
        disposition: scenario_disposition(definition.id),
        accepted,
    }
}

/// Folds invariant verdicts in stable order.
fn digest_verdicts(invariants: &[InvariantVerdict]) -> SimDigest {
    let mut digest = SimDigest::new();
    digest.feed_tag("invariant-verdicts");
    digest.feed_u64(u64::try_from(invariants.len()).unwrap_or(u64::MAX));
    for item in invariants {
        item.feed(&mut digest);
    }
    digest
}

/// Folds one trace window with its length prefix.
fn digest_events(events: &[TracedEvent]) -> SimDigest {
    let mut digest = SimDigest::new();
    digest.feed_tag("failure-trace");
    digest.feed_u64(u64::try_from(events.len()).unwrap_or(u64::MAX));
    for event in events {
        event.feed(&mut digest);
    }
    digest
}

/// Binds the pure-core code identity plus scenario definition.
fn code_digest_of(definition: &crate::scenario::ScenarioDefinition) -> SimDigest {
    let mut digest = SimDigest::new();
    digest.feed_tag("code-version");
    digest.feed_str(crate::seed::CODE_VERSION);
    definition.feed(&mut digest);
    digest
}

/// Returns the minimal failure window, or an empty trace for accepted runs.
fn minimal_window_or_empty(
    trace: &[TracedEvent],
    accepted: bool,
    window: usize,
) -> Vec<TracedEvent> {
    if accepted {
        Vec::new()
    } else {
        minimal_window(trace, window)
    }
}

/// Emits the drop outcome for one lost envelope: a lost ack for a committed
/// operation is an [`SimOutcome::AckLostAfterCommit`], any other loss is
/// [`SimOutcome::Dropped`]. Drop outcomes append after the drain so they
/// observe the terminal commit state.
fn ack_or_dropped(state: &SimState, seq: u64, command: &SimCommand) -> SimOutcome {
    if let SimCommand::Ack { op } = command {
        let committed = state
            .ops
            .get(&op.0)
            .is_some_and(|record| record.status == OpStatus::Committed);
        if committed {
            return SimOutcome::AckLostAfterCommit { op: *op };
        }
    }
    SimOutcome::Dropped { seq }
}

fn scenario_disposition(id: ScenarioId) -> crate::scenario::ScenarioDisposition {
    crate::scenario::MANDATORY_SCENARIOS
        .iter()
        .find(|scenario| scenario.id == id)
        .map_or(
            crate::scenario::ScenarioDisposition::Unsupported {
                reason: "no mandatory scenario entry; refusing to claim coverage",
            },
            |scenario| scenario.disposition,
        )
}

/// Evaluates the invariant suite over the terminal state and full trace.
#[must_use]
pub fn check_invariants(state: &SimState, trace: &[TracedEvent]) -> Vec<InvariantVerdict> {
    vec![
        no_double_apply(state),
        stale_never_commits(state),
        ack_loss_consistent(state, trace),
        unknown_never_completes(state),
        cancel_complete_exclusive(trace),
        commit_survives_cancel(state),
        shed_bounded(state),
        old_generation_rejected(state),
        supervision_explicit(state, trace),
        restart_durable(state, trace),
        depth_consistent(state),
    ]
}

fn verdict(id: &'static str, passed: bool, detail: String) -> InvariantVerdict {
    InvariantVerdict { id, passed, detail }
}

fn no_double_apply(state: &SimState) -> InvariantVerdict {
    let worst = state
        .ops
        .iter()
        .map(|(id, record)| (*id, record.applied))
        .max_by(|left, right| left.1.cmp(&right.1));
    match worst {
        Some((id, applied)) if applied > 1 => verdict(
            "no-double-apply",
            false,
            format!("op {id} applied {applied} times"),
        ),
        Some((id, applied)) => verdict(
            "no-double-apply",
            true,
            format!("max applications {applied} at op {id}"),
        ),
        None => verdict("no-double-apply", true, "no operations".to_owned()),
    }
}

fn stale_never_commits(state: &SimState) -> InvariantVerdict {
    let violator = state.ops.iter().find(|(_, record)| {
        record.status == OpStatus::Fenced
            && (record.applied > 0 || record.store == Some(crate::command::StoreOutcome::Committed))
    });
    if let Some((id, _)) = violator {
        verdict(
            "stale-never-commits",
            false,
            format!("fenced op {id} committed"),
        )
    } else {
        let fenced = state
            .ops
            .values()
            .filter(|record| record.status == OpStatus::Fenced)
            .count();
        verdict(
            "stale-never-commits",
            true,
            format!("{fenced} fenced operations, none committed"),
        )
    }
}

fn ack_loss_consistent(state: &SimState, trace: &[TracedEvent]) -> InvariantVerdict {
    for event in trace {
        if let SimOutcome::AckLostAfterCommit { op } = &event.outcome {
            let ok = state.ops.get(&op.0).is_some_and(|record| {
                record.status == OpStatus::Committed && record.applied <= 1 && !record.acked
            });
            if !ok {
                return verdict(
                    "ack-loss-consistent",
                    false,
                    format!("op {} lost its ack but is not a clean commit", op.0),
                );
            }
        }
    }
    verdict(
        "ack-loss-consistent",
        true,
        "every ack loss left exactly one unacked commit".to_owned(),
    )
}

fn unknown_never_completes(state: &SimState) -> InvariantVerdict {
    let violator = state.ops.iter().find(|(_, record)| {
        record.status == OpStatus::Completed
            && record.store == Some(crate::command::StoreOutcome::Unknown)
    });
    if let Some((id, _)) = violator {
        verdict(
            "unknown-never-completes",
            false,
            format!("op {id} completed from an unknown store outcome"),
        )
    } else {
        verdict(
            "unknown-never-completes",
            true,
            "no completion without a committed store record".to_owned(),
        )
    }
}

fn cancel_complete_exclusive(trace: &[TracedEvent]) -> InvariantVerdict {
    use std::collections::BTreeMap;
    let mut terminals: BTreeMap<u32, Vec<&'static str>> = BTreeMap::new();
    for event in trace {
        match &event.outcome {
            SimOutcome::Completed { op } => {
                terminals.entry(op.0).or_default().push("completed");
            }
            SimOutcome::Cancelled { op } => {
                terminals.entry(op.0).or_default().push("cancelled");
            }
            _ => {}
        }
    }
    let violator = terminals
        .iter()
        .find(|(_, ends)| ends.len() > 1)
        .map(|(id, _)| *id);
    if let Some(id) = violator {
        verdict(
            "cancel-complete-exclusive",
            false,
            format!("op {id} reached two terminals"),
        )
    } else {
        verdict(
            "cancel-complete-exclusive",
            true,
            format!("{} operations with single terminals", terminals.len()),
        )
    }
}

/// A durable commit is never voided by a late cancel: no cancelled
/// operation may carry a committed store record. Cancellation wins only
/// before the store commits; afterwards the commit stands and completion
/// wins (see `SimState` cancel rules).
fn commit_survives_cancel(state: &SimState) -> InvariantVerdict {
    let violator = state.ops.iter().find(|(_, record)| {
        record.status == OpStatus::Cancelled
            && record.store == Some(crate::command::StoreOutcome::Committed)
    });
    if let Some((id, _)) = violator {
        verdict(
            "commit-survives-cancel",
            false,
            format!("cancelled op {id} voids a durable commit"),
        )
    } else {
        verdict(
            "commit-survives-cancel",
            true,
            "no cancellation voided a durable commit".to_owned(),
        )
    }
}

fn shed_bounded(state: &SimState) -> InvariantVerdict {
    let depth_ok = state.mailbox_depth <= state.mailbox_capacity;
    let detail = format!(
        "depth {} within capacity {}, shed total {}",
        state.mailbox_depth, state.mailbox_capacity, state.shed_total
    );
    verdict("shed-bounded", depth_ok, detail)
}

fn old_generation_rejected(state: &SimState) -> InvariantVerdict {
    let parked = state.ops.iter().find(|(_, record)| {
        record.status == OpStatus::OldGeneration && (record.applied > 0 || record.store.is_some())
    });
    if let Some((id, _)) = parked {
        return verdict(
            "old-generation-rejected",
            false,
            format!("op {id} parked as old generation carries effects"),
        );
    }
    let ungrounded = state.ops.iter().find(|(_, record)| {
        record.status == OpStatus::Completed
            && (record.store != Some(crate::command::StoreOutcome::Committed)
                || record.applied == 0)
    });
    if let Some((id, _)) = ungrounded {
        verdict(
            "old-generation-rejected",
            false,
            format!("op {id} completed without an applied durable commit"),
        )
    } else {
        verdict(
            "old-generation-rejected",
            true,
            format!("active generation {}", state.generation),
        )
    }
}

fn supervision_explicit(state: &SimState, trace: &[TracedEvent]) -> InvariantVerdict {
    for source in [
        crate::command::SupervisionSource::Watchdog,
        crate::command::SupervisionSource::Testd,
    ] {
        let mut lost = false;
        for event in trace {
            match &event.outcome {
                SimOutcome::SupervisionLost { source: found } if *found == source => {
                    lost = true;
                }
                SimOutcome::SupervisionRestored { source: found } if *found == source => {
                    lost = false;
                }
                _ => {}
            }
        }
        if lost {
            let coverage = match source {
                crate::command::SupervisionSource::Watchdog => state.watchdog,
                crate::command::SupervisionSource::Testd => state.testd,
            };
            if coverage == crate::state::Coverage::Full {
                return verdict(
                    "supervision-explicit",
                    false,
                    "lost supervision still claims full coverage".to_owned(),
                );
            }
        }
    }
    verdict(
        "supervision-explicit",
        true,
        "coverage downgrades recorded, no silent success".to_owned(),
    )
}

fn restart_durable(state: &SimState, trace: &[TracedEvent]) -> InvariantVerdict {
    let restarted = trace
        .iter()
        .any(|event| event.outcome == SimOutcome::WriterRestarted);
    if !restarted {
        return verdict("restart-durable", true, "no restart in trace".to_owned());
    }
    let pending = state
        .ops
        .values()
        .filter(|record| record.status == OpStatus::Pending)
        .count();
    if pending > 0 {
        return verdict(
            "restart-durable",
            false,
            format!("{pending} volatile pending operations survived a restart"),
        );
    }
    verdict(
        "restart-durable",
        true,
        format!("restart applied, {} writer restarts", state.writer_restarts),
    )
}

fn depth_consistent(state: &SimState) -> InvariantVerdict {
    let recomputed = state.depth_check();
    verdict(
        "depth-consistent",
        recomputed == state.mailbox_depth,
        format!(
            "tracked depth {} recomputed {recomputed}",
            state.mailbox_depth
        ),
    )
}

/// Scenario acceptance predicate: the assertions each scenario must hold
/// at its terminal state and trace. Returns whether the scenario held plus
/// a short witness description.
#[must_use]
pub fn acceptance(id: ScenarioId, state: &SimState, trace: &[TracedEvent]) -> (bool, &'static str) {
    match id {
        ScenarioId::StaleFencing => accept_stale_fencing(state),
        ScenarioId::DuplicateDelivery => accept_duplicate(state, trace),
        ScenarioId::AckLossAfterCommit => accept_ack_loss(state, trace),
        ScenarioId::WriterRestart => accept_restart(state),
        ScenarioId::UnknownStoreOutcome => accept_unknown(state, trace),
        ScenarioId::CancelCompleteRace => accept_race(trace),
        ScenarioId::PromotionCutoverRollbackRace => accept_epoch_race(state, trace),
        ScenarioId::OverloadShedding => accept_shedding(state),
        ScenarioId::OldGenerationRejection => accept_old_generation(state),
        ScenarioId::WatchdogLoss => {
            accept_supervision_loss(state, trace, crate::command::SupervisionSource::Watchdog)
        }
        ScenarioId::TestdLoss => {
            accept_supervision_loss(state, trace, crate::command::SupervisionSource::Testd)
        }
    }
}

fn completed_once(state: &SimState, id: u32) -> bool {
    state
        .ops
        .get(&id)
        .is_some_and(|record| record.status == OpStatus::Completed && record.applied == 1)
}

fn accept_stale_fencing(state: &SimState) -> (bool, &'static str) {
    let fresh = completed_once(state, 1);
    let fenced = state
        .ops
        .get(&2)
        .is_some_and(|record| record.status == OpStatus::Fenced && record.applied == 0);
    (fresh && fenced, "fresh commits, stale fenced")
}

fn accept_duplicate(state: &SimState, trace: &[TracedEvent]) -> (bool, &'static str) {
    let once = state.ops.get(&1).is_some_and(|record| {
        record.status == OpStatus::Completed && record.applied == 1 && record.acked
    });
    let ignored = trace
        .iter()
        .any(|event| event.outcome == SimOutcome::DuplicateIgnored { op: OpId(1) });
    (once && ignored, "exactly once under redelivery")
}

fn accept_ack_loss(state: &SimState, trace: &[TracedEvent]) -> (bool, &'static str) {
    let committed = state.ops.get(&1).is_some_and(|record| {
        record.status == OpStatus::Committed && record.applied == 1 && !record.acked
    });
    let traced = trace
        .iter()
        .any(|event| event.outcome == SimOutcome::AckLostAfterCommit { op: OpId(1) });
    (committed && traced, "commit stands, completion unconfirmed")
}

fn accept_restart(state: &SimState) -> (bool, &'static str) {
    let kept = completed_once(state, 1);
    let dropped = state
        .ops
        .get(&2)
        .is_some_and(|record| record.status == OpStatus::Unknown);
    (kept && dropped, "commits survive, volatile pending lost")
}

fn accept_unknown(state: &SimState, trace: &[TracedEvent]) -> (bool, &'static str) {
    let unknown = state
        .ops
        .get(&1)
        .is_some_and(|record| record.status == OpStatus::Unknown);
    let never_completed = !trace
        .iter()
        .any(|event| event.outcome == SimOutcome::Completed { op: OpId(1) });
    (unknown && never_completed, "unknown never completes")
}

fn accept_race(trace: &[TracedEvent]) -> (bool, &'static str) {
    // Both race directions are scripted in one run: op 1 cancels while
    // pending so cancellation wins, op 2's cancel arrives after a durable
    // commit so completion wins with the commit standing.
    let cancel_wins = trace.iter().any(|event| {
        event.outcome
            == SimOutcome::CancelCompleteResolved {
                op: OpId(1),
                winner_is_complete: false,
            }
    });
    let complete_wins = trace.iter().any(|event| {
        event.outcome
            == SimOutcome::CancelCompleteResolved {
                op: OpId(2),
                winner_is_complete: true,
            }
    });
    let cancelled = trace
        .iter()
        .any(|event| event.outcome == SimOutcome::Cancelled { op: OpId(1) });
    let completed = trace
        .iter()
        .any(|event| event.outcome == SimOutcome::Completed { op: OpId(2) });
    (
        cancel_wins && complete_wins && cancelled && completed,
        "cancel wins pre-commit, complete wins post-commit",
    )
}

fn accept_epoch_race(state: &SimState, trace: &[TracedEvent]) -> (bool, &'static str) {
    let mut moves = Vec::new();
    for event in trace {
        if let SimOutcome::EpochMoved { epoch } = &event.outcome {
            moves.push(*epoch);
        }
    }
    let last_wins = moves.last().is_some_and(|epoch| *epoch == state.epoch);
    (moves.len() == 3 && last_wins, "last delivered move wins")
}

fn accept_shedding(state: &SimState) -> (bool, &'static str) {
    let bounded = state.mailbox_depth <= state.mailbox_capacity;
    (
        bounded && state.shed_total == 3,
        "shed counted, mailbox bounded",
    )
}

fn accept_old_generation(state: &SimState) -> (bool, &'static str) {
    let kept = state
        .ops
        .get(&1)
        .is_some_and(|record| record.status == OpStatus::Committed && record.applied == 1);
    let refused = state
        .ops
        .get(&2)
        .is_some_and(|record| record.status == OpStatus::OldGeneration);
    (kept && refused, "old generation refused, prior commit kept")
}

fn accept_supervision_loss(
    state: &SimState,
    trace: &[TracedEvent],
    source: crate::command::SupervisionSource,
) -> (bool, &'static str) {
    let (lost_coverage, kept_coverage) = match source {
        crate::command::SupervisionSource::Watchdog => (state.watchdog, state.testd),
        crate::command::SupervisionSource::Testd => (state.testd, state.watchdog),
    };
    let coverage = lost_coverage == crate::state::Coverage::Unknown
        && kept_coverage == crate::state::Coverage::Full;
    let completed = completed_once(state, 1);
    let lost = trace
        .iter()
        .any(|event| event.outcome == SimOutcome::SupervisionLost { source });
    let witness = match source {
        crate::command::SupervisionSource::Watchdog => "watchdog unknown, work honest",
        crate::command::SupervisionSource::Testd => "testd unknown, work honest",
    };
    (coverage && completed && lost, witness)
}

/// Resolves an unsupported slug fail-closed. Convenience wrapper over
/// [`ScenarioId::from_slug`] for adapter authors.
pub fn resolve_slug(slug: &str) -> Result<ScenarioId, SimError> {
    ScenarioId::from_slug(slug)
}
