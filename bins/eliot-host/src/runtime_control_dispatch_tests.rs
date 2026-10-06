//! Owner-path runtime-control dispatch proofs for #891 A4/A5.
//!
//! Norm: `docs/architecture/I02-06-error-and-crash-model.md:20` (operation
//! identity: every admitted operation carries its exact identity from the
//! owner that admitted it; a receipt answers only the operation that asked).
//!
//! The integration suite (`tests/host_lifecycle_diagnostics.rs` case 4/5)
//! proves the receipt answer through the owner's own constructors
//! (`restarted_for`, `response_matches_request`, `validate`). What it cannot
//! do from the integration binary is drive the dispatch itself:
//! `HostComposition` fields are private, so no out-of-crate test can hold
//! one. These in-crate tests drive the real
//! `HostComposition::handle_kernel_restart_request` on the production type
//! built with the production field layout (mirroring the `open_for_profile`
//! initializer), over a fenced test contour that admits no live effect: an
//! empty registry (every execute gate fails before any effect), a temp
//! journal, and a test owner lease. Seeded `runtime_restarts` rows stand in
//! for previously committed restarts, which is exactly the durable replay
//! the reconcile arm is specified to read back.
//!
//! A4 (receipt through the runtime-control owner):
//! - fenced owner answers typed Unknown that retains the request identity;
//! - a committed receipt replays through the owner as the typed receipt
//!   answer with the receipt completion observation;
//! - the reconcile operation delegates to the readback replay, re-bound to
//!   the reconcile request, without committing a second receipt.
//! A5 (unsupported control through the runtime-control owner):
//! - a non-restart operation answers typed Unknown, never a receipt, with
//!   the unknown observation and the single terminal.

use super::*;
use std::sync::atomic::{AtomicU64, Ordering};

/// Case disambiguator so parallel tests never share an owner mutex name or
/// a case root. The mutex is process-global per installation identity.
static DISPATCH_CASE_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Test contour owner: a production-shaped composition with no live effect
/// surface (empty registry, temp journal, test lease).
struct DispatchFixture {
    composition: HostComposition,
    installation: PlatformHandle,
}

fn dispatch_handle(value: String) -> PlatformHandle {
    PlatformHandle::new(value)
        .unwrap_or_else(|error| panic!("the 891 dispatch handle must be valid: {error}"))
}

fn dispatch_fixture(case: &str) -> DispatchFixture {
    let slot = DISPATCH_CASE_COUNTER.fetch_add(1, Ordering::SeqCst);
    let unique = format!("{}-{}-{}", case, std::process::id(), slot);
    let installation = dispatch_handle(format!("installation:891-dispatch-{unique}"));
    let case_root = std::env::temp_dir().join(format!("eliot-891-dispatch-{unique}"));
    let host_state_root = case_root.join("host-state");
    std::fs::create_dir_all(&host_state_root).expect("the 891 case root must exist");
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
        config_descriptor_digest: dispatch_handle("0".repeat(64)),
        installation: installation.clone(),
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
    DispatchFixture {
        composition,
        installation,
    }
}

/// Scoped tracing capture: the owner observations travel through the
/// tracing facade, so driving the dispatch inside this closure captures
/// exactly the records the owner emitted alongside its returned response.
fn capture_dispatch<T>(emit: impl FnOnce() -> T) -> (String, T) {
    struct Sink {
        bytes: std::sync::Mutex<Vec<u8>>,
    }
    impl std::io::Write for Sink {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.bytes
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
            .with_writer(move || {
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
                CloneWriter {
                    sink: writer_sink.clone(),
                }
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

/// Counts the exact `detail="..."` cell: several frozen events are strict
/// prefixes of sibling events (e.g. the unknown vs the owner-fenced
/// unknown), so a bare substring count would conflate phases the issue
/// keeps distinct.
fn exact_detail(event: &str) -> String {
    format!("detail=\"{event}\"")
}

/// Terminal records carry the frozen code, not a detail cell (the
/// `code="host-open-failed"` pattern the frozen table pins): a terminal
/// code is a strict substring risk the other way, so it gets its own cell.
fn exact_code(event: &str) -> String {
    format!("code=\"{event}\"")
}

fn restart_request(case: &str, id: &str) -> HostRuntimeControlRequest {
    HostRuntimeControlRequest::new(
        HostRuntimeControlOperation::RestartKernel,
        dispatch_handle(format!("891-{case}-{id}")),
    )
    .expect("the 891 restart request must validate on the wire")
}

/// Builds the committed receipt exactly as the owner builds it: every
/// identity slot derives from the requesting operation, and the receipt
/// digest covers them, so any drift fails the owner's own validation.
fn committed_receipt(request: &HostRuntimeControlRequest) -> HostKernelRestartReceipt {
    let identity = |slot: &str| {
        dispatch_handle(eliot_platform_windows::sha256_hex(
            format!(
                "891-dispatch-receipt:{slot}:{}",
                request.mutation_digest.as_str()
            )
            .as_bytes(),
        ))
    };
    let mut receipt = HostKernelRestartReceipt {
        mutation_digest: request.mutation_digest.clone(),
        request_digest: request.request_digest.clone(),
        old_kernel_generation: identity("old-kernel-generation"),
        new_kernel_generation: identity("new-kernel-generation"),
        store_fence: identity("store-fence"),
        activation_receipt_digest: identity("activation-receipt"),
        ready_receipt_digest: identity("ready-receipt"),
        receipt_digest: dispatch_handle("0".repeat(64)),
    };
    receipt.receipt_digest = receipt
        .computed_digest()
        .expect("the 891 committed receipt digest must compute");
    receipt
        .validate()
        .expect("the 891 committed receipt must validate");
    receipt
}

// WORK_UNIT_CASE: 891/A4-fenced
#[test]
fn dispatch_fenced_owner_answers_unknown_with_identity() {
    let mut fixture = dispatch_fixture("a4-fenced");
    // Fence the owner lease the way a released Host leaves it: the
    // capability survives inside the composition, but its live guard is
    // gone, so the dispatch must refuse before any effect.
    fixture
        .composition
        .owner_lease
        .release()
        .expect("the 891 fenced lease must release");
    assert!(
        !fixture.installation.as_str().is_empty(),
        "the installation identity stays available for the correlation asserts"
    );
    let request = restart_request("a4-fenced", "restart");
    let (captured, response) =
        capture_dispatch(|| fixture.composition.handle_kernel_restart_request(&request));
    let HostRuntimeControlResponse::Unknown { .. } = response else {
        panic!("the fenced owner must answer typed Unknown, never a receipt");
    };
    assert!(
        eliot_host_service::runtime_control::response_matches_request(&request, &response),
        "the fenced refusal must retain the exact control request identity"
    );
    for boundary in [
        BOUNDARY_KERNEL_RESTART_REQUESTED,
        BOUNDARY_KERNEL_RESTART_UNKNOWN_OWNER_FENCED,
    ] {
        assert_eq!(
            count_occurrences(&captured, &exact_detail(boundary.event)),
            1,
            "the fenced dispatch must emit {:?} exactly once: {captured}",
            boundary.event
        );
    }
    // The terminal travels as the frozen code cell, not a detail cell.
    assert_eq!(
        count_occurrences(
            &captured,
            &exact_code(BOUNDARY_KERNEL_RESTART_TERMINAL.event)
        ),
        1,
        "the fenced dispatch owns exactly one terminal: {captured}"
    );
    assert_eq!(
        count_occurrences(
            &captured,
            &exact_detail(BOUNDARY_KERNEL_RESTART_RECEIPT_COMPLETION.event)
        ),
        0,
        "the fenced dispatch must never emit the receipt completion: {captured}"
    );
}

// WORK_UNIT_CASE: 891/A4-receipt
#[test]
fn dispatch_committed_receipt_replays_through_owner() {
    let mut fixture = dispatch_fixture("a4-receipt");
    let request = restart_request("a4-receipt", "restart");
    // The row stands in for a previously committed restart with the exact
    // mutation identity this request carries; the owner replays it instead
    // of committing a second receipt.
    fixture.composition.runtime_restarts.insert(
        request.mutation_digest.as_str().to_owned(),
        committed_receipt(&request),
    );
    let (captured, response) =
        capture_dispatch(|| fixture.composition.handle_kernel_restart_request(&request));
    let HostRuntimeControlResponse::Restarted { receipt } = &response else {
        panic!("the committed receipt must replay as the typed receipt answer");
    };
    assert!(
        eliot_host_service::runtime_control::response_matches_request(&request, &response),
        "the replayed receipt must retain the exact control request identity"
    );
    assert_eq!(
        receipt.mutation_digest, request.mutation_digest,
        "the replayed receipt must retain the exact mutation identity"
    );
    assert_eq!(
        receipt.request_digest, request.request_digest,
        "the replayed receipt must retain the exact request digest"
    );
    for boundary in [
        BOUNDARY_KERNEL_RESTART_REQUESTED,
        BOUNDARY_KERNEL_RESTART_EXECUTE_REQUESTED,
        BOUNDARY_KERNEL_RESTART_RECEIPT_COMPLETION,
    ] {
        assert_eq!(
            count_occurrences(&captured, &exact_detail(boundary.event)),
            1,
            "the receipt dispatch must emit {:?} exactly once: {captured}",
            boundary.event
        );
    }
}

// WORK_UNIT_CASE: 891/A4-reconcile
#[test]
fn dispatch_reconcile_replays_committed_receipt_without_recommit() {
    let mut fixture = dispatch_fixture("a4-reconcile");
    let committed = restart_request("a4-reconcile", "restart");
    fixture.composition.runtime_restarts.insert(
        committed.mutation_digest.as_str().to_owned(),
        committed_receipt(&committed),
    );
    // The reconcile carries a fresh request id but the exact mutation
    // identity of the committed operation; anything else is a conflict.
    let reconcile = HostRuntimeControlRequest::new_reconcile(
        dispatch_handle("891-a4-reconcile-readback".to_owned()),
        committed.mutation_digest.clone(),
    )
    .expect("the 891 reconcile request must validate on the wire");
    assert_eq!(
        reconcile.operation,
        HostRuntimeControlOperation::ReconcileKernelRestart,
        "the readback path requires the reconcile operation"
    );
    let (captured, response) = capture_dispatch(|| {
        fixture
            .composition
            .handle_kernel_restart_request(&reconcile)
    });
    let HostRuntimeControlResponse::Restarted { receipt } = &response else {
        panic!("the committed receipt must read back as the typed receipt answer");
    };
    assert!(
        eliot_host_service::runtime_control::response_matches_request(&reconcile, &response),
        "the readback must answer the reconcile request, never the original restart"
    );
    assert_eq!(
        receipt.mutation_digest, committed.mutation_digest,
        "the readback keeps the committed mutation identity"
    );
    assert_eq!(
        receipt.request_digest, reconcile.request_digest,
        "the readback re-binds to the reconcile request digest"
    );
    assert_eq!(
        count_occurrences(
            &captured,
            &exact_detail(BOUNDARY_KERNEL_RESTART_RECONCILE_RECEIPT_READBACK_REPLAY.event)
        ),
        1,
        "the reconcile must observe the readback replay exactly once: {captured}"
    );
    assert_eq!(
        fixture.composition.runtime_restarts.len(),
        1,
        "the readback publishes nothing: no second receipt row may exist"
    );
}

// WORK_UNIT_CASE: 891/A13-pending
#[test]
fn reconcile_pending_intent_stays_unknown_through_owner() {
    let mut fixture = dispatch_fixture("a13-pending");
    let restart = restart_request("a13-pending", "restart");
    // The pending intent is published through the owner's own writer: a
    // possible effect whose outcome no one has observed.
    let publication = persist_runtime_restart_pending(
        fixture.composition.launch_options.host_state_root(),
        &restart,
        &fixture.composition.host,
    )
    .expect("the owner must publish the pending intent");
    assert!(
        matches!(publication, RuntimeRestartPendingPublication::Created),
        "the first publication must create, never replay"
    );
    // The reconcile carries a fresh request id but the exact mutation
    // identity of the pending operation.
    let reconcile = HostRuntimeControlRequest::new_reconcile(
        dispatch_handle("891-a13-pending-readback".to_owned()),
        restart.mutation_digest.clone(),
    )
    .expect("the 891 reconcile request must validate on the wire");
    let (captured, response) = capture_dispatch(|| {
        fixture
            .composition
            .handle_kernel_restart_request(&reconcile)
    });
    let HostRuntimeControlResponse::Unknown { .. } = response else {
        panic!("a pending intent must stay Unknown: a timeout proves nothing");
    };
    assert!(
        eliot_host_service::runtime_control::response_matches_request(&reconcile, &response),
        "the Unknown must still answer the reconcile request identity"
    );
    assert_eq!(
        count_occurrences(
            &captured,
            &exact_detail(BOUNDARY_KERNEL_RESTART_RECONCILE_UNKNOWN_PENDING.event)
        ),
        1,
        "the pending arm must observe the unknown-pending exactly once: {captured}"
    );
    assert_eq!(
        count_occurrences(
            &captured,
            &exact_code(BOUNDARY_KERNEL_RESTART_RECONCILE_TERMINAL.event)
        ),
        1,
        "the pending arm owns exactly one terminal: {captured}"
    );
    assert_eq!(
        count_occurrences(
            &captured,
            &exact_detail(BOUNDARY_KERNEL_RESTART_RECONCILE_RECEIPT_READBACK_REPLAY.event)
        ),
        0,
        "a pending timeout is never the committed-receipt readback: {captured}"
    );
}

// WORK_UNIT_CASE: 891/A13-unknown
#[test]
fn reconcile_without_commit_stays_unknown_through_owner() {
    let mut fixture = dispatch_fixture("a13-unknown");
    let restart = restart_request("a13-unknown", "restart");
    let reconcile = HostRuntimeControlRequest::new_reconcile(
        dispatch_handle("891-a13-unknown-readback".to_owned()),
        restart.mutation_digest.clone(),
    )
    .expect("the 891 reconcile request must validate on the wire");
    let (captured, response) = capture_dispatch(|| {
        fixture
            .composition
            .handle_kernel_restart_request(&reconcile)
    });
    let HostRuntimeControlResponse::Unknown { .. } = response else {
        panic!("an uncommitted reconcile must stay Unknown");
    };
    assert!(
        eliot_host_service::runtime_control::response_matches_request(&reconcile, &response),
        "the Unknown must still answer the reconcile request identity"
    );
    assert_eq!(
        count_occurrences(
            &captured,
            &exact_detail(BOUNDARY_KERNEL_RESTART_RECONCILE_UNKNOWN.event)
        ),
        1,
        "the unknown arm must observe the reconcile-unknown exactly once: {captured}"
    );
    assert_eq!(
        count_occurrences(
            &captured,
            &exact_code(BOUNDARY_KERNEL_RESTART_RECONCILE_TERMINAL.event)
        ),
        1,
        "the unknown arm owns exactly one terminal: {captured}"
    );
}

// WORK_UNIT_CASE: 891/A5
#[test]
fn dispatch_unsupported_operation_stays_unknown_without_receipt() {
    let mut fixture = dispatch_fixture("a5-unsupported");
    let request = HostRuntimeControlRequest::new(
        HostRuntimeControlOperation::RecoverStore,
        dispatch_handle("891-a5-unsupported-recover".to_owned()),
    )
    .expect("the 891 unsupported request must validate on the wire");
    let (captured, response) =
        capture_dispatch(|| fixture.composition.handle_kernel_restart_request(&request));
    let HostRuntimeControlResponse::Unknown { .. } = response else {
        panic!("an unsupported control operation must stay typed Unknown, never a receipt");
    };
    assert!(
        eliot_host_service::runtime_control::response_matches_request(&request, &response),
        "the typed refusal must still retain the exact control request identity"
    );
    assert_eq!(
        count_occurrences(
            &captured,
            &exact_detail(BOUNDARY_KERNEL_RESTART_UNKNOWN.event)
        ),
        1,
        "the unsupported operation must observe the unknown exactly once: {captured}"
    );
    assert_eq!(
        count_occurrences(
            &captured,
            &exact_code(BOUNDARY_KERNEL_RESTART_TERMINAL.event)
        ),
        1,
        "the unsupported operation owns exactly one terminal: {captured}"
    );
    assert_eq!(
        count_occurrences(
            &captured,
            &exact_detail(BOUNDARY_KERNEL_RESTART_RECEIPT_COMPLETION.event)
        ),
        0,
        "an unsupported operation must never emit the receipt completion: {captured}"
    );
    assert!(
        fixture.composition.runtime_restarts.is_empty(),
        "an unsupported operation must record no receipt row"
    );
}
