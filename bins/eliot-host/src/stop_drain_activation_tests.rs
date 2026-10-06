//! Owner-path lifecycle contour proofs for #891 A6/A8.
//!
//! Norm: `docs/architecture/I02-06-error-and-crash-model.md:20` (operation
//! identity) plus the issue's stop/drain distinction: request, pending,
//! drained and stopped are separate durable records sharing one drain
//! generation, with exactly one terminal per failed operation.
//!
//! The integration suite (cases 6/8) drives the durable journal reducer with
//! hand-built records. These in-crate tests drive the real
//! `HostComposition::stop` contour, which builds every drain record itself
//! from the held activation fence: the only hand-built record is the seed
//! `Active` activation every durable owner requires before it admits drain
//! appends under its fence. The contour then commits request, draining,
//! commit and stopped-clean through the journal owner, terminates the (absent
//! test) children through the job owner, releases the owner lease, and
//! disarms its terminal guard.

use super::*;
use eliot_host_state::{
    EliotActivationRecord, HostKernelStoreLineage, LifecycleTimestamps, ReadinessEvidence,
};
use std::sync::atomic::{AtomicU64, Ordering};

/// Case disambiguator so parallel tests never share an owner mutex name or
/// a case root. The mutex is process-global per installation identity.
static CONTOUR_CASE_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Test contour owner: a production-shaped composition with no live effect
/// surface (empty registry, temp journal, test lease, inert job branches).
struct ContourFixture {
    composition: HostComposition,
}

fn contour_handle(value: String) -> PlatformHandle {
    PlatformHandle::new(value)
        .unwrap_or_else(|error| panic!("the 891 contour handle must be valid: {error}"))
}

fn contour_fixture(case: &str) -> ContourFixture {
    let slot = CONTOUR_CASE_COUNTER.fetch_add(1, Ordering::SeqCst);
    let unique = format!("{case}-{}-{slot}", std::process::id());
    let installation = contour_handle(format!("installation:891-contour-{unique}"));
    let case_root = std::env::temp_dir().join(format!("eliot-891-contour-{unique}"));
    let host_state_root = case_root.join("host-state");
    std::fs::create_dir_all(&host_state_root).expect("the 891 case root must exist");
    // The stop contour sweeps completed store-recovery evidence under the
    // Host root; the sweep syncs the store dir, so the contour owns it.
    std::fs::create_dir_all(host_state_root.join("store-recoveries"))
        .expect("the 891 store-recovery store must exist");
    let (journal, host, activation_generation, activation_id, _) =
        host_epoch_reopen::open_test_support_epoch(
            &case_root.join("host-state-journal.redb"),
            installation.clone(),
            None,
            None,
        )
        .expect("the 891 test-support epoch must open");
    let owner_lease =
        HostOwnerLease::acquire(&installation).expect("the 891 case owner lease must acquire");
    let launch_options = HostLaunchOptions {
        config_descriptor_path: case_root.join("config.json"),
        config_descriptor_digest: contour_handle("0".repeat(64)),
        installation,
        transaction_plan_generation: 1,
        host_state_root: host_state_root.clone(),
        registration_nonce: None,
    };
    let jobs =
        HostJobBranches::new_test_support(&host).expect("the 891 inert job branches must build");
    let composition = HostComposition {
        store_rebind_boundary: HostStoreRebindProductionBoundary,
        runtime_control_boundary: HostRuntimeControlProductionBoundary,
        journal,
        registry_host_root: host_state_root,
        test_registry_file: None,
        registry: ApprovedGenerationRegistry::default(),
        launch_options,
        host,
        activation_generation,
        activation_id,
        running: true,
        jobs,
        readiness_gate: HostReadinessGate::with_cadence(ReadinessCadence::default()),
        phase_b: None,
        watchdog_start_recovery: None,
        runtime_restarts: std::collections::HashMap::new(),
        runtime_control_queue: std::sync::Arc::new(std::sync::Mutex::new(
            std::collections::VecDeque::new(),
        )),
        user_automation_execution_queue: std::sync::Arc::new(std::sync::Mutex::new(
            std::collections::VecDeque::new(),
        )),
        backup_dispatch_queue: HostBackupDispatchQueue::bounded(),
        store_recovery_startup_fence: StoreRecoveryStartupFence::Clear,
        active_phase_b_rebind_recovery: ActivePhaseBRebindRecoveryKind::None,
        owner_lease,
        pending_record: None,
        durable_finalized: false,
        owner_released: false,
        shutdown_failed: false,
    };
    ContourFixture { composition }
}

/// Scoped tracing capture: the contour observations travel through the
/// tracing facade, so driving the contour inside this closure captures
/// exactly the records the owner emitted alongside its returned outcome.
fn capture_contour<T>(emit: impl FnOnce() -> T) -> (String, T) {
    struct Sink {
        bytes: std::sync::Mutex<Vec<u8>>,
    }
    struct CloneWriter {
        sink: std::sync::Arc<Sink>,
    }
    impl std::io::Write for CloneWriter {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.sink
                .bytes
                .lock()
                .map_err(|_| std::io::Error::other("891 capture lock poisoned"))?
                .extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let sink = std::sync::Arc::new(Sink {
        bytes: std::sync::Mutex::new(Vec::new()),
    });
    let writer_sink = std::sync::Arc::clone(&sink);
    let value = {
        let subscriber = tracing_subscriber::fmt()
            .with_ansi(false)
            .with_writer(move || CloneWriter {
                sink: writer_sink.clone(),
            })
            .finish();
        tracing::subscriber::with_default(subscriber, emit)
    };
    let captured = sink.bytes.lock().expect("891 capture must read back");
    (String::from_utf8_lossy(&captured).into_owned(), value)
}

fn count_occurrences(haystack: &str, needle: &str) -> usize {
    haystack.matches(needle).count()
}

/// The seed every durable owner requires: a committed `Active` activation
/// whose fence the contour's drain appends must name. The durable reducer
/// admits only the legal `Stopped -> Starting -> ControlReady -> Active`
/// chain, so the seed walks exactly those edges; every later record is
/// built by the contour under test, never by hand.
/// Builds one activation record under the fixture's own fence. Seeds use
/// it for the legal chain; tests reuse it for governed rollbacks.
fn seed_record(fixture: &ContourFixture, state: ActivationState) -> HostStateRecord {
    let composition = &fixture.composition;
    let host = composition.host.clone();
    let generation = composition.activation_generation.clone();
    let activation_id = composition.activation_id.clone();
    let handle = |slot: &str| contour_handle(format!("891-stop-seed-{slot}"));
    let epoch = |lineage: &str, sequence: u64| {
        EpochIdentity::new(
            EpochLineageId::new(lineage).unwrap_or_else(|_| unreachable!()),
            std::num::NonZeroU64::new(sequence).unwrap_or_else(|| unreachable!()),
        )
        .unwrap_or_else(|_| unreachable!())
    };
    HostStateRecord::Activation(EliotActivationRecord {
        fence: RecordFence {
            host: host.clone(),
            activation_id: activation_id.clone(),
            activation_generation: generation.clone(),
        },
        operation: IdempotencyIdentity {
            operation_id: handle("operation"),
            idempotency_key: handle("key-operation"),
        },
        activation_id: activation_id.clone(),
        trigger_class: handle("observable-use"),
        trigger_evidence: vec![handle("trigger-evidence")],
        requester_principal_session_or_scheduler: handle("principal-session"),
        requested_capabilities: vec![handle("kernel-control")],
        candidate_scope: handle("installation-scope"),
        state,
        drain_generation: None,
        lineage: HostKernelStoreLineage {
            host_epoch: host.epoch.current.clone(),
            kernel_epoch: epoch("550e8400-e29b-41d4-a716-446655440001", 1),
            watchdog_epoch: epoch("550e8400-e29b-41d4-a716-446655440002", 1),
            store_generation: epoch("550e8400-e29b-41d4-a716-446655440003", 1),
        },
        readiness: ReadinessEvidence {
            supervision_ready: true,
            control_ready: true,
            evidence_refs: vec![handle("readiness-evidence")],
        },
        governance_profile: handle("governance-profile"),
        runtime_lease_refs: vec![],
        supervision_lease_refs: vec![],
        wake_intent_refs: vec![],
        drain_commit_ref: None,
        wake_during_drain_disposition: None,
        boot_session_evidence: vec![handle("boot-session-evidence")],
        power_transition_evidence: vec![],
        timestamps: LifecycleTimestamps {
            started_at: Some(handle("t-started")),
            ready_at: Some(handle("t-ready")),
            draining_at: None,
            stopped_at: None,
        },
        failure_and_recovery_directive: None,
    })
}

fn seed_active_activation(fixture: &mut ContourFixture) {
    // Each link carries its own operation identity: replaying the same
    // operation would be an idempotent replay, never a forward transition.
    for (operation, state) in [
        ("seed-starting", ActivationState::Starting),
        ("seed-control-ready", ActivationState::ControlReady),
        ("seed-active", ActivationState::Active),
    ] {
        let mut chained = seed_record(fixture, state);
        let HostStateRecord::Activation(ref mut activation) = chained else {
            unreachable!("the seed builder yields activation records")
        };
        activation.operation = IdempotencyIdentity {
            operation_id: contour_handle(operation.to_owned()),
            idempotency_key: contour_handle(format!("key-{operation}")),
        };
        append_reconciled(&fixture.composition.journal, chained)
            .expect("the seed activation chain must commit");
    }
}

// WORK_UNIT_CASE: 891/A6
#[test]
fn stop_contour_commits_request_pending_drained_stopped_through_owner() {
    let mut fixture = contour_fixture("a6-stop");
    seed_active_activation(&mut fixture);
    let (captured, outcome) = capture_contour(|| fixture.composition.stop());
    outcome.expect("the clean stop contour must succeed");
    // The contour's own phase records, each exactly once, in one capture
    // of one owner operation. Needles match the full `detail="..."` cell:
    // `host.stop stopped` is a strict prefix of the stopped-clean event, so
    // a bare substring count would conflate the two phases the issue keeps
    // distinct.
    for boundary in [
        BOUNDARY_STOP_REQUESTED,
        BOUNDARY_STOP_CANCELLATION_REQUESTED,
        BOUNDARY_DRAIN_REQUESTED,
        BOUNDARY_DRAIN_DRAINING,
        BOUNDARY_DRAIN_COMMIT,
        BOUNDARY_KERNEL_TERMINATE_REQUESTED,
        BOUNDARY_KERNEL_TERMINATE_STOPPED,
        BOUNDARY_STORE_TERMINATE_REQUESTED,
        BOUNDARY_STORE_TERMINATE_STOPPED,
        BOUNDARY_STOP_STOPPED_CLEAN_DRAINED,
        BOUNDARY_STOP_STOPPED,
    ] {
        let needle = format!("detail=\"{}\"", boundary.event);
        assert_eq!(
            count_occurrences(&captured, &needle),
            1,
            "the stop contour must emit {:?} exactly once: {captured}",
            boundary.event
        );
    }
    // The terminal travels as the frozen code cell, not a detail cell: a
    // clean stop must emit no `code="host-stop-failed"` record at all.
    assert_eq!(
        count_occurrences(
            &captured,
            &format!("code=\"{}\"", BOUNDARY_STOP_TERMINAL.event)
        ),
        0,
        "a clean stop disarms its guard and emits no terminal: {captured}"
    );
    assert!(
        !fixture.composition.running,
        "a clean stop leaves the composition stopped"
    );
    assert!(
        fixture
            .composition
            .owner_lease
            .activation_capability()
            .live_guard()
            .is_err(),
        "a clean stop releases the owner lease"
    );
    let snapshot = fixture
        .composition
        .journal
        .snapshot()
        .expect("the stopped journal must project");
    assert_eq!(
        snapshot.activation.as_ref().map(|record| record.state),
        Some(ActivationState::StoppedClean),
        "the contour must leave the durable StoppedClean activation"
    );
    assert!(
        snapshot.drain_commit.is_some(),
        "the contour must leave the durable drain commit"
    );
    assert_eq!(
        snapshot.drain.as_ref().map(|drain| drain.state),
        Some(DrainState::Draining),
        "the durable drain record stays at the Draining state the reducer committed"
    );
    // A second stop is refused: the contour owns exactly one shutdown.
    assert!(
        fixture.composition.stop().is_err(),
        "a stopped composition must refuse a second stop"
    );
}

/// Readiness observations enter the journal only through the readiness
/// contour's approved-contour admission (`append_readiness_observation`):
/// a direct append is refused by design, so no test seeds one. The
/// promotion half of the ready rule therefore stays environment-gated
/// (live Watchdog heartbeat plus kernel artifacts, which this contour
/// owns); the owner proofs below cover the admission projection, the
/// evidence refusal, and the degraded arm.

// WORK_UNIT_CASE: 891/A7-admission
#[test]
fn activation_admission_projects_durable_record_through_owner() {
    let mut fixture = contour_fixture("a7-admission");
    seed_active_activation(&mut fixture);
    let (captured, admission) = capture_contour(|| fixture.composition.activation_admission());
    let admission = admission.expect("the seeded admission must project");
    assert_eq!(
        admission.state,
        ActivationState::Active,
        "the admission must project the durable activation state"
    );
    assert_eq!(
        admission.activation_generation, fixture.composition.activation_generation,
        "the admission must bind the durable activation generation"
    );
    assert!(
        admission.control_ready && admission.supervision_ready,
        "the admission must carry the proven readiness the record holds"
    );
    assert!(
        admission
            .requested_capabilities
            .iter()
            .any(|capability| capability.as_str().contains("kernel-control")),
        "the admission must carry the requested capabilities the record holds"
    );
    assert_eq!(
        count_occurrences(
            &captured,
            &format!(
                "detail=\"{}\"",
                BOUNDARY_ACTIVATION_ADMISSION_REQUESTED.event
            )
        ),
        1,
        "the admission owner must observe its request exactly once: {captured}"
    );
    // The fresh epoch carries its own durable Stopped record: the
    // projection reads it instead of refusing or fabricating liveness.
    let bare = contour_fixture("a7-admission-stopped");
    let (bare_captured, bare_outcome) = capture_contour(|| bare.composition.activation_admission());
    let bare_admission = bare_outcome.expect("the epoch Stopped record must project");
    assert_eq!(
        bare_admission.state,
        ActivationState::Stopped,
        "the admission must project the epoch's own Stopped state, never liveness"
    );
    assert!(
        !bare_admission.control_ready && !bare_admission.supervision_ready,
        "a Stopped admission must carry no readiness claim"
    );
    assert_eq!(
        count_occurrences(
            &bare_captured,
            &format!(
                "detail=\"{}\"",
                BOUNDARY_ACTIVATION_ADMISSION_REQUESTED.event
            )
        ),
        1,
        "even the Stopped projection observes the admission request: {bare_captured}"
    );
}

// WORK_UNIT_CASE: 891/A7-ready-degraded
#[test]
fn readiness_contour_keeps_degraded_degraded_through_owner() {
    let mut fixture = contour_fixture("a7-ready-degraded");
    seed_active_activation(&mut fixture);
    let generation = contour_handle("generation-891-a7-degraded".to_owned());
    let kernel_artifact = contour_handle("c".repeat(64));
    let store_artifact = contour_handle("d".repeat(64));
    let config = contour_handle("e".repeat(64));
    let (captured, outcome) = capture_contour(|| {
        fixture.composition.reconcile_branch_readiness_at(
            &generation,
            &kernel_artifact,
            &store_artifact,
            &config,
            HostBranchDisposition::ReadinessDegraded,
            std::time::Instant::now(),
        )
    });
    assert_eq!(
        outcome,
        HostBranchDisposition::ReadinessDegraded,
        "a degraded branch must stay degraded through the contour"
    );
    assert_eq!(
        count_occurrences(
            &captured,
            &format!("detail=\"{}\"", BOUNDARY_READINESS_DEGRADED.event)
        ),
        1,
        "the contour must observe the degraded exactly once: {captured}"
    );
    assert_eq!(
        count_occurrences(
            &captured,
            &format!("detail=\"{}\"", BOUNDARY_READINESS_READY_PROOF.event)
        ),
        0,
        "a degraded branch must never observe the ready proof: {captured}"
    );
    let snapshot = fixture
        .composition
        .journal
        .snapshot()
        .expect("the journal must project");
    assert_eq!(
        snapshot.activation.as_ref().map(|record| record.state),
        Some(ActivationState::Active),
        "the degraded arm must neither promote nor demote the durable activation"
    );
}

// WORK_UNIT_CASE: 891/A9
#[test]
fn managed_launch_admits_through_job_owner_without_readiness() {
    let fixture = contour_fixture("a9-launch");
    // The managed-launch owner only creates the two Job branches and
    // observes the current process binding: no child is launched or
    // adopted, no readiness row is selected, no terminal is armed.
    let (captured, branches) = capture_contour(|| HostJobBranches::new(&fixture.composition.host));
    let branches = branches.expect("the inert job branches must build");
    assert!(
        branches.kernel.is_none() && branches.store.is_none(),
        "a managed launch admits branches but launches no child"
    );
    for boundary in [BOUNDARY_JOBS_REQUESTED, BOUNDARY_JOBS_ADMITTED] {
        assert_eq!(
            count_occurrences(&captured, &format!("detail=\"{}\"", boundary.event)),
            1,
            "the launch owner must emit {:?} exactly once: {captured}",
            boundary.event
        );
    }
    assert!(
        !captured.contains("readiness"),
        "a managed launch record must never carry readiness wording: {captured}"
    );
    assert_eq!(
        count_occurrences(&captured, "code="),
        0,
        "a managed launch arms no terminal: {captured}"
    );
}

// WORK_UNIT_CASE: 891/A10
#[test]
fn liveness_tick_observes_without_readiness_through_owner() {
    let mut fixture = contour_fixture("a10-liveness");
    seed_active_activation(&mut fixture);
    let (captured, tick) = capture_contour(|| fixture.composition.liveness_tick());
    tick.expect("the liveness tick must answer");
    for boundary in [BOUNDARY_LIVENESS_REQUESTED, BOUNDARY_LIVENESS_OBSERVED] {
        assert_eq!(
            count_occurrences(&captured, &format!("detail=\"{}\"", boundary.event)),
            1,
            "the liveness tick must emit {:?} exactly once: {captured}",
            boundary.event
        );
    }
    // With no live branches the gate records branch-degraded instead of
    // claiming ready: the only readiness-named record is the degradation,
    // never a readiness proof.
    assert_eq!(
        count_occurrences(
            &captured,
            "boundary=\"host.readiness branch degraded observed\""
        ),
        1,
        "the tick must record the degraded branch exactly once: {captured}"
    );
    for proof in [
        "host.readiness requested proof",
        "host.readiness ready proof",
    ] {
        assert!(
            !captured.contains(&format!("detail=\"{proof}\"")),
            "a liveness tick must never claim a readiness proof {proof:?}: {captured}"
        );
    }
    assert_eq!(
        count_occurrences(
            &captured,
            &format!("code=\"{}\"", BOUNDARY_LIVENESS_TERMINAL.event)
        ),
        0,
        "a live liveness tick disarms its guard and emits no terminal: {captured}"
    );
    let snapshot = fixture
        .composition
        .journal
        .snapshot()
        .expect("the journal must project");
    assert_eq!(
        snapshot.activation.as_ref().map(|record| record.state),
        Some(ActivationState::Active),
        "a liveness observation must never advance the activation"
    );
}

// WORK_UNIT_CASE: 891/A7-ready-refused
#[test]
fn ready_transition_without_evidence_is_refused_through_owner() {
    let mut fixture = contour_fixture("a7-ready-refused");
    // The fresh epoch opens Stopped; walk the single legal edge to Starting
    // so the ready transition has a live source and no evidence anywhere.
    // (There is no Active -> Starting edge: a rollback that skips the drain
    // contour would erase the durable shutdown the reducer owns.)
    let mut chained = seed_record(&fixture, ActivationState::Starting);
    let HostStateRecord::Activation(ref mut activation) = chained else {
        unreachable!("the seed builder yields activation records")
    };
    activation.operation = IdempotencyIdentity {
        operation_id: contour_handle("891-a7-starting".to_owned()),
        idempotency_key: contour_handle("891-a7-key-starting".to_owned()),
    };
    append_reconciled(&fixture.composition.journal, chained)
        .expect("the Starting seed must commit");
    let outcome = fixture
        .composition
        .transition_activation_with_readiness_evidence(ActivationState::ControlReady, "host-ready");
    assert!(
        outcome.is_err(),
        "a ready transition with no readiness observation must be refused"
    );
    let snapshot = fixture
        .composition
        .journal
        .snapshot()
        .expect("the journal must project");
    assert_eq!(
        snapshot.activation.as_ref().map(|record| record.state),
        Some(ActivationState::Starting),
        "a refused ready transition must leave the durable state untouched"
    );
}
