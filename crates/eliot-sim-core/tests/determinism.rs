//! Determinism acceptance: the same scenario plus seed run twice yields
//! identical digests, schedule, terminal state, invariants, and failure
//! trace. Different seeds must still diverge in the schedule digest.

use eliot_sim_core::{ScenarioId, run};

const SEEDS: [u64; 3] = [1916, 7, 0x9e37_79b9_7f4a_7c15];

#[test]
fn same_scenario_plus_seed_is_bit_identical() {
    for id in ScenarioId::ALL {
        for seed in SEEDS {
            let first = run(id, seed);
            let second = run(id, seed);
            assert_eq!(
                first.artifact,
                second.artifact,
                "artifact diverged for {} seed {seed}",
                id.slug()
            );
            assert_eq!(
                first.schedule,
                second.schedule,
                "schedule diverged for {} seed {seed}",
                id.slug()
            );
            assert_eq!(
                first.terminal,
                second.terminal,
                "terminal state diverged for {} seed {seed}",
                id.slug()
            );
            assert_eq!(
                first.invariants,
                second.invariants,
                "invariants diverged for {} seed {seed}",
                id.slug()
            );
            assert_eq!(
                first.trace,
                second.trace,
                "trace diverged for {} seed {seed}",
                id.slug()
            );
            assert_eq!(
                first.artifact.schedule_digest,
                second.artifact.schedule_digest,
                "schedule digest diverged for {} seed {seed}",
                id.slug()
            );
            assert_eq!(
                first.artifact.terminal_digest,
                second.artifact.terminal_digest,
                "terminal digest diverged for {} seed {seed}",
                id.slug()
            );
            assert_eq!(
                first.artifact.invariant_digest,
                second.artifact.invariant_digest,
                "invariant digest diverged for {} seed {seed}",
                id.slug()
            );
            assert_eq!(
                first.artifact.failure_trace_digest,
                second.artifact.failure_trace_digest,
                "failure trace digest diverged for {} seed {seed}",
                id.slug()
            );
            assert_eq!(
                first.minimal_failure_trace(),
                second.minimal_failure_trace(),
                "minimal failure trace diverged for {} seed {seed}",
                id.slug()
            );
        }
    }
}

#[test]
fn different_seeds_diverge_in_schedule_digest() {
    for id in ScenarioId::ALL {
        let first = run(id, SEEDS[0]);
        let second = run(id, SEEDS[1]);
        assert_ne!(
            first.artifact.schedule_digest,
            second.artifact.schedule_digest,
            "seeds did not diverge for {}",
            id.slug()
        );
    }
}
