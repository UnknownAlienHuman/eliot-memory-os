//! Pure deterministic simulation boundary for ELIOT control semantics.
//!
//! This crate drives pure command/event/state transitions without `Tokio`,
//! databases, model SDKs, `Wasmtime`, process spawning, or file/network I/O.
//! Those frameworks stay outside the boundary and attach through the adapter
//! traits in [`adapters`]; the adapter traits are declarations only and this
//! crate never calls into a runtime.
//!
//! A run is fully determined by its [`ScenarioId`] and seed: the [`Scheduler`]
//! delivers every [`SimCommand`] through scripted duplicate, reorder, delay,
//! and loss faults plus a seeded [`SimRng`] stream, the [`SimState`] machine
//! applies each delivered command, and [`run`] folds the delivery schedule,
//! terminal state, invariant verdicts, and failure trace into a
//! [`SimulationSeedArtifact`]. Running the same scenario with the same seed
//! twice yields identical digests, schedule, terminal state, invariants, and
//! failure trace.
//!
//! A simulation `PASS` proves only the modeled contracts. Every scenario
//! names the real-edge or live fault proof that remains required; see
//! [`MandatoryScenario::live_proof_required`] and `I18.41`.

pub mod adapters;
pub mod command;
pub mod digest;
pub mod event;
pub mod fault;
pub mod rng;
pub mod run;
pub mod scenario;
pub mod scheduler;
pub mod seed;
pub mod state;

pub use adapters::{
    ADAPTER_BOUNDARY_NOTE, EXCLUDED_FRAMEWORKS, IoPort, ModelCassette, ModelPort, ProcessPort,
    StorePort, TimerPort, WasmPort,
};
pub use command::{
    CommandKind, EffectClass, FencingToken, OpId, PromotionAction, SimCommand, StoreOutcome,
    SupervisionSource,
};
pub use digest::{Canonical, SimDigest};
pub use event::{DeliveryFault, SimOutcome, Tick, TracedEvent};
pub use fault::{Failpoint, FaultPlan, FaultPlanError, ScriptedFault};
pub use rng::SimRng;
pub use run::{
    InvariantVerdict, SimulationReport, acceptance, check_invariants, resolve_slug, run,
    run_with_config,
};
pub use scenario::{
    MANDATORY_SCENARIOS, MandatoryScenario, ScenarioDefinition, ScenarioDisposition, ScenarioId,
    SimError, define,
};
pub use scheduler::{Delivery, DeliveryRecord, Envelope, Scheduler};
pub use seed::{
    CODE_VERSION, FAILURE_TRACE_WINDOW, MAX_DELIVERIES, MAX_TICKS, SimConfig,
    SimulationSeedArtifact,
};
pub use state::{Coverage, OpRecord, OpStatus, SimState};
