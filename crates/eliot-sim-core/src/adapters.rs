//! Adapter boundary: everything outside the pure simulation core.
//!
//! `Tokio`, databases, model SDKs, `Wasmtime`, process spawning, and
//! file/network I/O stay outside this crate via the ports below. The ports
//! are declarations only: this crate never calls into a runtime, never
//! opens a store, never invokes a model, and never spawns anything. An
//! implementation may replay a [`SimulationReport`](crate::run::SimulationReport)
//! against real frameworks — deterministic `Tokio` scenarios through
//! `Turmoil`, exhaustive small primitives through `Loom`, larger randomized
//! spaces through `Shuttle`, broad async coverage through `MadSim` — but the
//! implementation always lives outside this crate.
//!
//! ```text
//! pure core ............. eliot-sim-core (this crate, no runtime)
//! timer ................. TimerPort      (Tokio or Turmoil adapter outside)
//! durable store ......... StorePort      (database adapter outside)
//! models and tools ...... ModelPort      (cassettes inside, live calls outside)
//! sandboxed modules ..... WasmPort       (Wasmtime adapter outside)
//! native processes ...... ProcessPort    (process adapter outside)
//! files and network ..... IoPort         (filesystem/network adapter outside)
//! ```

use crate::command::StoreOutcome;
use crate::digest::SimDigest;
use crate::event::Tick;

/// Human-readable statement of the boundary for reports and diagnostics.
pub const ADAPTER_BOUNDARY_NOTE: &str =
    "Tokio, DB, model SDK, Wasmtime, process, and IO stay outside via adapters";

/// Framework families that must never appear as dependencies of this crate.
pub const EXCLUDED_FRAMEWORKS: &[&str] = &[
    "tokio",
    "database clients",
    "model SDKs",
    "wasmtime",
    "process spawning",
    "file I/O",
    "network I/O",
];

/// Logical clock port for adapters replaying a simulation trace.
pub trait TimerPort {
    /// Returns the adapter clock as a logical tick.
    fn logical_now(&self) -> Tick;
    /// Advances the adapter clock to `tick`.
    fn advance_to(&mut self, tick: Tick);
}

/// Durable store port. Unknown outcomes stay unknown; the adapter must
/// reconcile them through an explicit readback, never a blind retry.
pub trait StorePort {
    /// Records a commit decision for `op`, returning the previous outcome.
    fn commit(&mut self, op: u32, outcome: StoreOutcome) -> Option<StoreOutcome>;
    /// Returns the recorded outcome for `op`, if any.
    fn lookup(&self, op: u32) -> Option<StoreOutcome>;
}

/// Pure decision of a recorded model or tool cassette.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum ModelDecision {
    /// The recorded response allowed the action.
    Allow,
    /// The recorded response denied the action.
    Deny,
    /// The recorded response required escalation.
    Escalate,
}

/// Pure cassette for one provider, tool, or model interaction. Digests
/// stand in for content: the bytes live outside the boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct ModelCassette {
    /// Digest of the recorded prompt.
    pub prompt_digest: SimDigest,
    /// Digest of the recorded response.
    pub response_digest: SimDigest,
    /// Recorded decision.
    pub decision: ModelDecision,
}

/// Model and tool port. Cassettes replay inside; live calls stay outside.
pub trait ModelPort {
    /// Replays one cassette and returns its recorded decision.
    fn play(&mut self, cassette: &ModelCassette) -> ModelDecision;
}

/// Sandboxed module port. Execution stays in the `Wasmtime` adapter outside.
pub trait WasmPort {
    /// Invokes `function` of the module identified by `module_digest`.
    /// Returns an adapter-local handle.
    fn invoke(&mut self, module_digest: &str, function: &str) -> u32;
}

/// Native process port. Lifecycle stays in the process adapter outside.
pub trait ProcessPort {
    /// Launches the spec identified by `spec_digest`.
    /// Returns an adapter-local handle.
    fn spawn(&mut self, spec_digest: &str) -> u32;
    /// Terminates `handle`.
    fn kill(&mut self, handle: u32);
}

/// File and network port. Only content-addressed digests cross the boundary.
pub trait IoPort {
    /// Reads the bytes addressed by `path_digest`.
    fn read_bytes(&mut self, path_digest: &str) -> Vec<u8>;
    /// Writes `bytes` at `path_digest`.
    fn write_bytes(&mut self, path_digest: &str, bytes: &[u8]);
}
