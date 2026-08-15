//! Deterministic, side-effect-free supervision decisions for the runtime watchdog.
//!
//! The watchdog owns no process handles and performs no persistence itself.  It
//! consumes durable operation observations and returns an ordered action list;
//! the kernel adapter is responsible for executing those actions and recording
//! the resulting receipt.  Keeping the decision engine this small makes a
//! missed tick harmless and prevents a stale watchdog from acquiring authority.

use std::collections::{BTreeMap, VecDeque};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

pub use eliot_runtime_contracts::{LeaseState, SupervisionLease};

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct Epoch(pub u64);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OperationPhase {
    Prepared,
    Dispatching,
    Running,
    Cancelling,
    Reaping,
    Reconciling,
    Completed,
    Failed,
    Abandoned,
}

impl OperationPhase {
    #[must_use]
    pub const fn terminal(self) -> bool {
        matches!(self, Self::Completed | Self::Failed | Self::Abandoned)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DispatchState {
    NotStarted,
    Starting,
    Proven,
    AckUnknown,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CancellationState {
    NotRequested,
    Requested,
    Graceful,
    Forced,
    Reaped,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CircuitState {
    Closed,
    Open,
    HalfOpen,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RestartDecision {
    FreshGeneration,
    ReconcileBeforeRetry,
    AcceptCapturedTerminal,
    OpenCircuit,
    TerminalFailure,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WatchdogActionKind {
    RequestCancellation,
    ForceReap,
    Reconcile,
    Quarantine,
    OpenCircuit,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WatchdogAction {
    pub operation_id: String,
    pub generation: u64,
    pub kind: WatchdogActionKind,
    pub reason: &'static str,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReapReceipt {
    pub operation_id: String,
    pub generation: u64,
    pub process_count_before: u32,
    pub process_count_after: u32,
    pub stdout_closed: bool,
    pub stderr_closed: bool,
    pub all_tasks_joined: bool,
    pub forced_termination: bool,
    pub terminal_error_codes: Vec<u32>,
}

impl ReapReceipt {
    #[must_use]
    pub fn proves_complete(&self) -> bool {
        self.process_count_after == 0
            && self.stdout_closed
            && self.stderr_closed
            && self.all_tasks_joined
            && (self.forced_termination || self.terminal_error_codes.is_empty())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OperationObservation {
    pub operation_id: String,
    pub generation: u64,
    pub phase: OperationPhase,
    pub dispatch: DispatchState,
    pub cancellation: CancellationState,
    pub phase_deadline: SystemTime,
    pub absolute_deadline: SystemTime,
    pub last_progress: SystemTime,
    pub active_processes: u32,
    pub restart_count: u32,
    pub restart_window_started: Option<SystemTime>,
    pub circuit: CircuitState,
    pub terminal_result_exists: bool,
}

impl OperationObservation {
    fn validate(&self) -> Result<(), WatchdogError> {
        if self.operation_id.is_empty() {
            return Err(WatchdogError::InvalidObservation("empty operation id"));
        }
        if self.generation == 0 {
            return Err(WatchdogError::InvalidObservation("zero generation"));
        }
        if self.phase_deadline < self.last_progress || self.absolute_deadline < self.phase_deadline
        {
            return Err(WatchdogError::InvalidObservation("deadline ordering"));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WatchdogConfig {
    pub restart_window: Duration,
    pub cancellation_grace: Duration,
    pub stale_progress_after: Duration,
    pub max_restarts: u32,
}

impl Default for WatchdogConfig {
    fn default() -> Self {
        Self {
            restart_window: Duration::from_secs(300),
            cancellation_grace: Duration::from_secs(10),
            stale_progress_after: Duration::from_secs(30),
            max_restarts: 3,
        }
    }
}

impl WatchdogConfig {
    fn validate(&self) -> Result<(), WatchdogError> {
        if self.restart_window.is_zero()
            || self.cancellation_grace.is_zero()
            || self.stale_progress_after.is_zero()
        {
            return Err(WatchdogError::InvalidConfig(
                "watchdog durations must be non-zero",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum WatchdogError {
    InvalidConfig(&'static str),
    InvalidObservation(&'static str),
    UnknownOperation(String),
    StaleGeneration { expected: u64, observed: u64 },
    InvalidReceipt(&'static str),
}

#[derive(Clone, Debug)]
struct TrackedOperation {
    observation: OperationObservation,
    cancellation_requested_at: Option<SystemTime>,
    action_generation: u64,
    force_action_generation: u64,
}

/// The authoritative in-memory decision state for one watchdog instance.
///
/// Calls are synchronous and deterministic.  The caller may invoke `tick`
/// repeatedly with the same timestamp; each operation/action pair is emitted
/// at most once for a generation until a new observation advances the state.
pub struct Watchdog {
    config: WatchdogConfig,
    epoch: Epoch,
    operations: BTreeMap<String, TrackedOperation>,
    actions: VecDeque<WatchdogAction>,
}

impl Watchdog {
    pub fn new(config: WatchdogConfig, epoch: Epoch) -> Result<Self, WatchdogError> {
        config.validate()?;
        Ok(Self {
            config,
            epoch,
            operations: BTreeMap::new(),
            actions: VecDeque::new(),
        })
    }

    #[must_use]
    pub const fn epoch(&self) -> Epoch {
        self.epoch
    }

    pub fn observe(&mut self, observation: OperationObservation) -> Result<(), WatchdogError> {
        observation.validate()?;
        match self.operations.get_mut(&observation.operation_id) {
            Some(tracked) if tracked.observation.generation > observation.generation => {
                Err(WatchdogError::StaleGeneration {
                    expected: tracked.observation.generation,
                    observed: observation.generation,
                })
            }
            Some(tracked) => {
                if tracked.observation.generation < observation.generation {
                    tracked.cancellation_requested_at = None;
                    tracked.action_generation = 0;
                    tracked.force_action_generation = 0;
                }
                if observation.cancellation == CancellationState::Requested
                    && tracked.cancellation_requested_at.is_none()
                {
                    tracked.cancellation_requested_at = Some(observation.last_progress);
                }
                tracked.observation = observation;
                Ok(())
            }
            None => {
                let cancellation_requested_at =
                    if observation.cancellation == CancellationState::Requested {
                        Some(observation.last_progress)
                    } else {
                        None
                    };
                self.operations.insert(
                    observation.operation_id.clone(),
                    TrackedOperation {
                        observation,
                        cancellation_requested_at,
                        action_generation: 0,
                        force_action_generation: 0,
                    },
                );
                Ok(())
            }
        }
    }

    pub fn remove(&mut self, operation_id: &str) -> Result<(), WatchdogError> {
        if self.operations.remove(operation_id).is_none() {
            return Err(WatchdogError::UnknownOperation(operation_id.to_owned()));
        }
        Ok(())
    }

    pub fn tick(&mut self, now: SystemTime) -> Vec<WatchdogAction> {
        let config = &self.config;
        let mut emitted = Vec::new();
        for tracked in self.operations.values_mut() {
            let op = &mut tracked.observation;
            if op.phase.terminal() {
                continue;
            }
            if op.cancellation == CancellationState::Requested {
                if tracked.cancellation_requested_at.is_some_and(|at| {
                    now.duration_since(at).unwrap_or_default() >= config.cancellation_grace
                }) && tracked.force_action_generation != op.generation
                {
                    tracked.force_action_generation = op.generation;
                    emitted.push(WatchdogAction {
                        operation_id: op.operation_id.clone(),
                        generation: op.generation,
                        kind: WatchdogActionKind::ForceReap,
                        reason: "cancellation_grace_exceeded",
                    });
                }
                continue;
            }
            let deadline = now >= op.phase_deadline || now >= op.absolute_deadline;
            let stale = now.duration_since(op.last_progress).unwrap_or_default()
                >= config.stale_progress_after;
            if (deadline || stale) && tracked.action_generation != op.generation {
                tracked.action_generation = op.generation;
                op.cancellation = CancellationState::Requested;
                op.phase = OperationPhase::Cancelling;
                tracked.cancellation_requested_at = Some(now);
                emitted.push(WatchdogAction {
                    operation_id: op.operation_id.clone(),
                    generation: op.generation,
                    kind: WatchdogActionKind::RequestCancellation,
                    reason: if deadline {
                        "deadline_exceeded"
                    } else {
                        "progress_stale"
                    },
                });
            }
        }
        self.actions.extend(emitted);
        self.actions.drain(..).collect()
    }

    pub fn record_reap(&mut self, receipt: &ReapReceipt) -> Result<(), WatchdogError> {
        if !receipt.proves_complete() {
            return Err(WatchdogError::InvalidReceipt(
                "receipt does not prove complete reap",
            ));
        }
        let tracked = self
            .operations
            .get_mut(&receipt.operation_id)
            .ok_or_else(|| WatchdogError::UnknownOperation(receipt.operation_id.clone()))?;
        if tracked.observation.generation != receipt.generation {
            return Err(WatchdogError::StaleGeneration {
                expected: tracked.observation.generation,
                observed: receipt.generation,
            });
        }
        tracked.observation.active_processes = 0;
        tracked.observation.cancellation = CancellationState::Reaped;
        tracked.observation.phase = OperationPhase::Reaping;
        Ok(())
    }

    #[must_use]
    pub fn restart_decision(
        &self,
        observation: &OperationObservation,
        now: SystemTime,
    ) -> RestartDecision {
        if observation.terminal_result_exists {
            return RestartDecision::AcceptCapturedTerminal;
        }
        if observation.circuit == CircuitState::Open {
            return RestartDecision::OpenCircuit;
        }
        if self.config.max_restarts == 0
            || observation.restart_count >= self.config.max_restarts
                && observation.restart_window_started.is_some_and(|started| {
                    now.duration_since(started).unwrap_or_default() <= self.config.restart_window
                })
        {
            return RestartDecision::OpenCircuit;
        }
        if observation.dispatch == DispatchState::NotStarted {
            RestartDecision::FreshGeneration
        } else if matches!(
            observation.dispatch,
            DispatchState::Starting | DispatchState::Proven | DispatchState::AckUnknown
        ) {
            RestartDecision::ReconcileBeforeRetry
        } else {
            RestartDecision::TerminalFailure
        }
    }
}

#[must_use]
pub fn unix_timestamp(now: SystemTime) -> u64 {
    now.duration_since(UNIX_EPOCH).unwrap_or_default().as_secs()
}
