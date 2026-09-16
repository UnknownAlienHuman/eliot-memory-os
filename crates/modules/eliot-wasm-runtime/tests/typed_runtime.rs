//! Deterministic Slice-B integration proof (issue #760, cases 16 and 34).
//!
//! These tests exercise the neutral generation-replacement coordinator through
//! its public API only, against deterministic injected providers: a scripted
//! [`ReadinessOracle`] (never a live engine) and finite JSON fixtures under
//! `tests/data/typed-runtime/`. No guest component, no Wasmtime provider, no
//! network, and no full-workspace build is required; final real-capsule
//! execution belongs to #758 with #762 consuming both.
//!
//! Synchronization is barrier-controlled only; no sleeps.

use std::collections::BTreeSet;
use std::path::PathBuf;
use std::sync::{Arc, Barrier};

use eliot_runtime_contracts::ModuleGeneration;
use eliot_wasm_runtime::replacement::{
    CallCompletion, CallOutcome, CallTerminal, CandidateDescriptor, GenerationCoordinator,
    GenerationParams, GenerationRecord, PrepareRequest, ReadinessEvidence, ReadinessOracle,
    ReplacementError, StateMigration, SwitchRequest,
};
use eliot_wasm_runtime::{
    ArtifactAccessLimits, CancellationPolicy, CapabilityId, EngineBinding, EpochPolicy,
    InvocationLimits, Sha256Digest,
};
use serde::Deserialize;
use serde_json::json;

#[derive(Deserialize)]
struct FixtureShape {
    module_id: String,
    generation: u64,
    predecessor: Option<u64>,
    artifact_digest: String,
    artifact_len: u64,
    world: String,
    component_version: String,
    abi_digest: String,
    kit_digest: String,
    scope: String,
}

fn must<T, E: std::fmt::Debug>(result: Result<T, E>) -> T {
    match result {
        Ok(value) => value,
        Err(error) => panic!("typed-runtime fixture failed: {error:?}"),
    }
}

fn fixture_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/data/typed-runtime")
}

fn load_fixture(name: &str) -> FixtureShape {
    let path = fixture_dir().join(name);
    let text = match std::fs::read_to_string(&path) {
        Ok(text) => text,
        Err(error) => panic!("cannot read fixture {name}: {error:?}"),
    };
    match serde_json::from_str(&text) {
        Ok(shape) => shape,
        Err(error) => panic!("cannot parse fixture {name}: {error:?}"),
    }
}

fn fixture_digest(value: &str) -> Sha256Digest {
    must(Sha256Digest::new(value))
}

fn fixture_generation(shape: &FixtureShape, artifact: &Sha256Digest) -> ModuleGeneration {
    must(serde_json::from_value(json!({
        "module_id": shape.module_id,
        "generation": shape.generation,
        "artifact_id": artifact.as_str(),
        "state": "READY",
        "health": {
            "liveness": "HEALTHY", "readiness": "HEALTHY",
            "freshness": "HEALTHY", "compatibility": "HEALTHY",
            "integrity": "HEALTHY", "capacity": "HEALTHY"
        },
        "state_fence": {
            "authority_epoch": {"lineage_id": "550e8400-e29b-41d4-a716-446655440000", "sequence": 1}, "resource_generation": 1,
            "task_revision": 1, "policy_revision": 1,
            "integration_revision": null
        }
    })))
}

fn fixture_engine() -> EngineBinding {
    EngineBinding {
        implementation_id: "engine.test.v1".to_owned(),
        exact_version: "1.2.3".to_owned(),
        engine_artifact_digest: fixture_digest(&"8".repeat(64)),
        engine_configuration_digest: fixture_digest(&"9".repeat(64)),
        wit_interface_digest: fixture_digest(&"b".repeat(64)),
    }
}

fn fixture_limits(artifact: &Sha256Digest) -> InvocationLimits {
    InvocationLimits {
        max_input_bytes: 128,
        max_output_bytes: 128,
        max_host_calls: 4,
        max_fuel: 1_000,
        max_memory_bytes: 65_536,
        max_table_elements: 64,
        max_instances: 2,
        max_stack_bytes: 8_192,
        wall_deadline_ms: 500,
        epoch: EpochPolicy {
            deadline_ticks: 50,
            cancellation: CancellationPolicy::EpochAndFuel,
        },
        artifact_access: ArtifactAccessLimits {
            allowed_digests: BTreeSet::from([artifact.clone()]),
            max_reads: 2,
            max_bytes: 1_024,
        },
    }
}

fn fixture_record(shape: &FixtureShape) -> GenerationRecord {
    let artifact = fixture_digest(&shape.artifact_digest);
    must(GenerationRecord::new(GenerationParams {
        generation: fixture_generation(shape, &artifact),
        predecessor: shape.predecessor,
        artifact_len: shape.artifact_len,
        artifact_digest: artifact.clone(),
        world: shape.world.clone(),
        component_version: shape.component_version.clone(),
        abi_digest: fixture_digest(&shape.abi_digest),
        kit_digest: fixture_digest(&shape.kit_digest),
        engine: fixture_engine(),
        observed_imports: BTreeSet::from([must(CapabilityId::new("log"))]),
        state_migration: StateMigration::Stateless,
        scope: shape.scope.clone(),
        limits: fixture_limits(&artifact),
    }))
}

fn fixture_candidate(record: GenerationRecord) -> CandidateDescriptor {
    CandidateDescriptor {
        record,
        probe_input_digest: fixture_digest(&"1".repeat(64)),
        probe_deadline_ms: 500,
        max_probe_output_bytes: 1024,
    }
}

struct ScriptedReadiness {
    pass: bool,
}

impl ReadinessOracle for ScriptedReadiness {
    fn probe(
        &mut self,
        candidate: &CandidateDescriptor,
    ) -> Result<ReadinessEvidence, ReplacementError> {
        Ok(ReadinessEvidence {
            generation: candidate.record.generation_number(),
            probe_output_digest: fixture_digest(&"1".repeat(64)),
            success: self.pass,
        })
    }
}

fn completed_outcome(call_id: &str, generation: u64) -> CallOutcome {
    CallOutcome {
        call_id: call_id.to_owned(),
        generation,
        terminal: CallTerminal::Completed,
    }
}

// WORK_UNIT_CASE: 760/16
#[test]
fn unresolved_drain_deadline_cannot_make_dual_active() {
    let initial = load_fixture("generation-initial.json");
    let candidate = load_fixture("generation-candidate.json");
    let coordinator = GenerationCoordinator::new();
    must(coordinator.admit_initial(&fixture_record(&initial)));
    let mut oracle = ScriptedReadiness { pass: true };
    must(coordinator.prepare(
        &PrepareRequest {
            operation_id: "op-16".to_owned(),
            expected_active: initial.generation,
            candidate: fixture_candidate(fixture_record(&candidate)),
        },
        &mut oracle,
    ));
    must(coordinator.acquire_call("call-16-old"));
    let snapshot = must(coordinator.begin_drain("op-16", 200));
    assert_eq!(snapshot.draining_generation, initial.generation);
    assert_eq!(snapshot.unresolved, vec!["call-16-old".to_owned()]);
    let status = must(coordinator.note_drain_deadline("op-16"));
    assert!(status.draining);
    assert!(status.blocked);
    assert_eq!(status.unresolved, vec!["call-16-old".to_owned()]);
    assert_eq!(
        coordinator.switch(&SwitchRequest {
            operation_id: "op-16".to_owned(),
            expected_active: initial.generation,
        }),
        Err(ReplacementError::DrainUnresolved)
    );
    assert_eq!(
        coordinator.active_generation_number(),
        Some(initial.generation)
    );
    assert_eq!(must(coordinator.receipt_count()), 0);
    assert_eq!(
        coordinator.acquire_call("call-16-new"),
        Err(ReplacementError::AdmissionBlockedDraining)
    );
    must(coordinator.verify_call_invariants());
    assert_eq!(
        must(coordinator.complete_call(&completed_outcome("call-16-old", initial.generation))),
        CallCompletion::RecordedTerminal
    );
    let receipt = must(coordinator.switch(&SwitchRequest {
        operation_id: "op-16".to_owned(),
        expected_active: initial.generation,
    }));
    assert_eq!(receipt.old_generation, initial.generation);
    assert_eq!(receipt.new_generation, candidate.generation);
    assert_eq!(
        coordinator.active_generation_number(),
        Some(candidate.generation)
    );
    must(coordinator.verify_switch_uniqueness("op-16"));
}

// WORK_UNIT_CASE: 760/34
#[test]
fn barrier_controlled_concurrent_acquisition_and_single_switch() {
    const ACQUIRERS: usize = 4;
    let initial = load_fixture("generation-initial.json");
    let candidate = load_fixture("generation-candidate.json");
    let coordinator = Arc::new(GenerationCoordinator::new());
    must(coordinator.admit_initial(&fixture_record(&initial)));
    let mut oracle = ScriptedReadiness { pass: true };
    must(coordinator.prepare(
        &PrepareRequest {
            operation_id: "op-34".to_owned(),
            expected_active: initial.generation,
            candidate: fixture_candidate(fixture_record(&candidate)),
        },
        &mut oracle,
    ));
    let start = Arc::new(Barrier::new(ACQUIRERS + 1));
    let acquired = Arc::new(Barrier::new(ACQUIRERS + 1));
    let draining = Arc::new(Barrier::new(ACQUIRERS + 1));
    let initial_generation = initial.generation;
    let mut handles = Vec::with_capacity(ACQUIRERS);
    for index in 0..ACQUIRERS {
        let coordinator = Arc::clone(&coordinator);
        let start = Arc::clone(&start);
        let acquired = Arc::clone(&acquired);
        let draining = Arc::clone(&draining);
        handles.push(std::thread::spawn(move || {
            start.wait();
            let call_id = format!("mt-call-{index}");
            let lease = must(coordinator.acquire_call(&call_id));
            assert_eq!(lease.accepted_generation, initial_generation);
            acquired.wait();
            draining.wait();
            assert!(matches!(
                coordinator.acquire_call("mt-call-retry"),
                Err(ReplacementError::AdmissionBlockedDraining)
            ));
        }));
    }
    start.wait();
    acquired.wait();
    must(coordinator.begin_drain("op-34", 500));
    draining.wait();
    for index in 0..ACQUIRERS {
        let call_id = format!("mt-call-{index}");
        assert_eq!(
            must(coordinator.complete_call(&completed_outcome(&call_id, initial.generation))),
            CallCompletion::RecordedTerminal
        );
    }
    let receipt = must(coordinator.switch(&SwitchRequest {
        operation_id: "op-34".to_owned(),
        expected_active: initial.generation,
    }));
    assert_eq!(receipt.old_generation, initial.generation);
    assert_eq!(receipt.new_generation, candidate.generation);
    assert_eq!(
        coordinator.switch(&SwitchRequest {
            operation_id: "op-34".to_owned(),
            expected_active: initial.generation,
        }),
        Err(ReplacementError::UnknownOperation)
    );
    for (index, handle) in handles.into_iter().enumerate() {
        match handle.join() {
            Ok(()) => {}
            Err(_) => panic!("acquirer {index} failed"),
        }
    }
    assert_eq!(
        coordinator.active_generation_number(),
        Some(candidate.generation)
    );
    assert_eq!(must(coordinator.history_len()), ACQUIRERS);
    must(coordinator.verify_call_invariants());
    must(coordinator.verify_switch_uniqueness("op-34"));
}
