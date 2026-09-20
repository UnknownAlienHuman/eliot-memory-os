//! Deterministic run configuration and the [`SimulationSeedArtifact`].
//!
//! Each run creates one artifact binding scenario and code digests, the seed
//! and deterministic config, the schedule, the terminal state, invariant
//! results, and the minimal failure trace plus a failure-capsule reference.
//! The pure core binds the scenario definition digest as its code identity;
//! the host adapter binds the real binary and profile digests outside this
//! crate (see [`adapters`](crate::adapters)).

use crate::digest::{Canonical, SimDigest};
use crate::scenario::{ScenarioDisposition, ScenarioId};

/// Pure-core code identity bound into every artifact.
pub const CODE_VERSION: &str = "eliot-sim-core/1";

/// Logical-tick horizon: a run that has not drained by this tick truncates
/// deterministically instead of running forever.
pub const MAX_TICKS: u64 = 4096;

/// Delivery horizon: a run that has not drained after this many deliveries
/// truncates deterministically instead of running forever.
pub const MAX_DELIVERIES: u64 = 4096;

/// Number of trailing trace events kept in a minimal failure trace, plus a
/// short head prefix so the run opening is never lost.
pub const FAILURE_TRACE_WINDOW: u64 = 64;

/// Deterministic run configuration. Every field is digest-bound.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SimConfig {
    /// Logical-tick horizon.
    pub max_ticks: u64,
    /// Delivery horizon.
    pub max_deliveries: u64,
    /// Minimal failure-trace window.
    pub failure_trace_window: u64,
}

impl SimConfig {
    /// Returns the default deterministic configuration.
    #[must_use]
    pub const fn default_config() -> Self {
        Self {
            max_ticks: MAX_TICKS,
            max_deliveries: MAX_DELIVERIES,
            failure_trace_window: FAILURE_TRACE_WINDOW,
        }
    }
}

impl Canonical for SimConfig {
    fn feed(&self, digest: &mut SimDigest) {
        digest.feed_tag("sim-config");
        digest.feed_str(CODE_VERSION);
        digest.feed_u64(self.max_ticks);
        digest.feed_u64(self.max_deliveries);
        digest.feed_u64(self.failure_trace_window);
    }
}

/// Per-run artifact for one scenario plus seed.
///
/// The same scenario plus seed run twice yields identical digests. A
/// simulation `PASS` proves only the modeled contracts; the disposition and
/// the scenario's live proof name the remainder.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SimulationSeedArtifact {
    /// Scenario that ran.
    pub scenario: ScenarioId,
    /// Digest of the pure-core code identity plus scenario definition.
    pub code_digest: SimDigest,
    /// Digest of the deterministic configuration.
    pub profile_digest: SimDigest,
    /// Seed driving the scheduler stream.
    pub seed: u64,
    /// Digest of the delivery schedule, drops included.
    pub schedule_digest: SimDigest,
    /// Digest of the terminal state.
    pub terminal_digest: SimDigest,
    /// Digest of the invariant verdicts.
    pub invariant_digest: SimDigest,
    /// Digest of the minimal failure trace.
    pub failure_trace_digest: SimDigest,
    /// Total trace events; the minimal failure trace is a window of these.
    pub trace_len: u64,
    /// Failure-capsule reference when the run did not accept, else `None`.
    /// Pure content addressing: `simcapsule:<schedule>:<terminal>`.
    pub failure_capsule: Option<String>,
    /// Boundary disposition of the scenario.
    pub disposition: ScenarioDisposition,
    /// True when every invariant passed, the scenario predicate held, and
    /// the run drained within its horizons.
    pub accepted: bool,
}

impl SimulationSeedArtifact {
    /// Builds the failure-capsule reference from schedule and terminal digests.
    #[must_use]
    pub fn capsule_ref(schedule: SimDigest, terminal: SimDigest) -> String {
        format!("simcapsule:{schedule}:{terminal}")
    }
}

impl Canonical for SimulationSeedArtifact {
    fn feed(&self, digest: &mut SimDigest) {
        digest.feed_tag("simulation-seed-artifact");
        digest.feed_str(self.scenario.slug());
        self.code_digest.feed(digest);
        self.profile_digest.feed(digest);
        digest.feed_u64(self.seed);
        self.schedule_digest.feed(digest);
        self.terminal_digest.feed(digest);
        self.invariant_digest.feed(digest);
        self.failure_trace_digest.feed(digest);
        digest.feed_u64(self.trace_len);
        digest.feed_bool(self.accepted);
    }
}
