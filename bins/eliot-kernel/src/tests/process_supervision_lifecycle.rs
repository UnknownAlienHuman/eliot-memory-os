#![allow(clippy::expect_used, clippy::unwrap_used)]
#![cfg(windows)]
#![allow(
    clippy::too_many_lines,
    reason = "each case drives several real boundaries of one frozen #901 checklist item"
)]

//! Kernel process-supervision LIFECYCLE observation proof — issue #901
//! (F-LOG-KERNEL-3), checklist items W11, W30, W31, W24 and W21.
//!
//! The #901-owned Kernel modules are private `mod`s of the crate root and the
//! functions below are `pub(crate)`, so an integration test under
//! `bins/eliot-kernel/tests/` cannot reach them. This suite is therefore
//! registered as a crate-internal `#[cfg(test)]` module and reaches them through
//! `use super::*`, exactly as `src/tests/local_read_claim.rs` and
//! `src/tests/process_execution.rs` do. Every case drives a REAL production
//! callsite of `process_execution.rs`, `activation_lifecycle.rs` or
//! `daemon_live_receipt.rs` on a REAL `ProcessExecutionGateway` /
//! `KernelComposition`, captures the emitted bytes through the #895
//! `tracing_subscriber` seam, and asserts the DISTINCTION its item names.
//!
//! * W11 — a parent exit does not establish descendant cleanup.
//! * W30 — a cleanup/reap failure retains the owner and the reconciliation
//!   requirement.
//! * W31 — a restart/reattach observation binds the exact operation, process
//!   and lease.
//! * W24 — a late receipt or exit cannot revive revoked or old-generation
//!   authority.
//! * W21 — a cancellation acknowledgement is not a terminal cancellation.
//!
//! Test-oracle only. It owns no process, authority, Store or daemon authority,
//! clones no production logic, and induces no fault by poisoning a lock: every
//! refusal asserted below is the owner's own decision on data the fixture really
//! produced.
//!
//! Architecture: A8.1, A13.2, A13.3, ARCH-WDG-01, ARCH-RES-01, ARCH-RES-04;
//! implementation I1.4, I1.5, I13.11, I14.20, I14.21, I15.4, and I02.20
//! (Module Test Capsule).

use super::*;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use eliot_contracts::{EpochId, EpochLineageId};
use eliot_kernel_core::{
    KernelAuthorityReplaySnapshot, KernelError, KernelResult, SealedAuthoritySnapshot,
};
use eliot_ors::{
    EpochIdentity, EpochLineage, OpaqueLabel, ProcessStartReplayRecord, ProcessStartReplayState,
    RecoveryPayload, StateFenceSnapshot,
};
use eliot_platform::SecretReference;
use eliot_process::{
    DescendantEvidence, OperationId, ProcessExecutionBinding, ProcessExecutionView, ProcessId,
};

use crate::activation_lifecycle::{DescendantClosureReceipt, RegisteredDescendant};

// ---------------------------------------------------------------------------
// Capture seam. Per-file duplication is this crate's house pattern; this file
// owns no shared helper module and creates none.
// ---------------------------------------------------------------------------

#[derive(Clone, Default)]
struct CaptureSink {
    bytes: Arc<Mutex<Vec<u8>>>,
}

impl Write for CaptureSink {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.bytes
            .lock()
            .map_err(|_| std::io::Error::other("capture lock poisoned"))?
            .extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Thread-local capture: `with_default` never installs a process-global
/// subscriber, so these cases stay parallel-safe with every sibling suite.
fn capture_with<F, R>(run: F) -> (String, R)
where
    F: FnOnce() -> R,
{
    let sink = CaptureSink::default();
    let writer_sink = sink.clone();
    let result = {
        let subscriber = tracing_subscriber::fmt()
            .with_ansi(false)
            .with_writer(move || writer_sink.clone())
            .finish();
        tracing::subscriber::with_default(subscriber, run)
    };
    let bytes = sink.bytes.lock().expect("capture lock").clone();
    (String::from_utf8_lossy(&bytes).into_owned(), result)
}

fn capture(run: impl FnOnce()) -> String {
    capture_with(run).0
}

/// Reads the RECORDED value of one `kernel.operation` span slot out of one
/// captured line, if that line carries it at all.
///
/// Two properties of the real renderer (tracing-subscriber 0.3.23) force this
/// shape, and both were read from that crate rather than assumed:
///
/// * `fmt::format::Format::format_event` writes exactly one opening brace
///   around the whole space-separated `FormattedFields` run, so `{slot="` never
///   occurs for any slot but the first declared one, and the needle must be the
///   bare `slot="`.
/// * `FmtLayer::on_record` APPENDS through `add_fields`; it never rewrites the
///   declared slot. A recorded value therefore appears AFTER its declared
///   default, so the LAST occurrence on the line is the recorded value and the
///   first is the default.
///
/// A slot the owner never recorded occurs exactly once and resolves to its
/// declared `"unavailable"` default, which is the honest answer for it.
fn span_field<'a>(line: &'a str, slot: &str) -> Option<&'a str> {
    let needle = format!("{slot}=\"");
    let last = line.rfind(&needle)?;
    let rest = &line[last + needle.len()..];
    let end = rest.find('"')?;
    Some(&rest[..end])
}

/// Reads the value after the FIRST occurrence of `key="` on one line.
fn quoted<'a>(line: &'a str, key: &str) -> &'a str {
    let needle = format!("{key}=\"");
    let start = line
        .find(&needle)
        .unwrap_or_else(|| panic!("field {key} absent from captured line: {line}"))
        + needle.len();
    let rest = &line[start..];
    let end = rest
        .find('"')
        .unwrap_or_else(|| panic!("unterminated field {key} in captured line: {line}"));
    &rest[..end]
}

/// The captured line carrying `event="<event>"`.
fn event_line<'a>(logs: &'a str, event: &str) -> &'a str {
    logs.lines()
        .find(|line| line.contains(&format!("event=\"{event}\"")))
        .unwrap_or_else(|| panic!("no captured line carries event={event}; captured: {logs}"))
}

/// The captured line carrying BOTH `event="<event>"` and `needle`, for cases
/// that emit the same event once per operation and must read each occurrence
/// separately instead of relying on line order.
fn event_line_with<'a>(logs: &'a str, event: &str, needle: &str) -> &'a str {
    logs.lines()
        .find(|line| line.contains(&format!("event=\"{event}\"")) && line.contains(needle))
        .unwrap_or_else(|| {
            panic!("no captured line carries event={event} and {needle}; captured: {logs}")
        })
}

/// The recorded value of one span slot on an already selected line.
fn recorded_on(line: &str, slot: &str) -> String {
    span_field(line, slot)
        .unwrap_or_else(|| panic!("span slot {slot} absent from captured line: {line}"))
        .to_owned()
}

/// The recorded value of one span slot under the given event.
fn recorded(logs: &str, event: &str, slot: &str) -> String {
    recorded_on(event_line(logs, event), slot)
}

/// The `outcome` field of the given event.
fn event_outcome(logs: &str, event: &str) -> String {
    quoted(event_line(logs, event), "outcome").to_owned()
}

fn event_count(logs: &str, event: &str) -> usize {
    logs.matches(&format!("event=\"{event}\"")).count()
}

/// Every `kernel.terminal_error` code, in captured order.
fn terminal_codes(logs: &str) -> Vec<String> {
    logs.lines()
        .filter(|line| line.contains("event=\"kernel.terminal_error\""))
        .map(|line| quoted(line, "code").to_owned())
        .collect()
}

// ---------------------------------------------------------------------------
// Fixture builders. Each one constructs real contract values through their own
// constructors, so the production validators — not this file — decide validity.
// ---------------------------------------------------------------------------

const EPOCH_LINEAGE: &str = "550e8400-e29b-41d4-a716-446655440000";

/// Opaque, secret-free codec standing in for the production DPAPI authority
/// snapshot codec. It exists only so
/// `ProcessDispatchAuthorityController::activate` has a codec to bind; it grants
/// no authority, seals no real secret, and is not production behaviour. No case
/// below exercises an authority-snapshot round trip.
struct FixtureAuthorityCodec;

impl DispatchSnapshotCodec for FixtureAuthorityCodec {
    fn seal(
        &self,
        snapshot: &KernelAuthorityReplaySnapshot,
        _binding: &AuthoritySnapshotBinding,
    ) -> KernelResult<SealedAuthoritySnapshot> {
        let ciphertext = serde_json::to_vec(snapshot)
            .map_err(|error| KernelError::DependencyUnavailable(error.to_string()))?;
        let key = SecretReference::new("fixture-provider", "eliot-901-lifecycle-authority")
            .map_err(|error| KernelError::DependencyUnavailable(error.to_string()))?;
        SealedAuthoritySnapshot::new(key, ciphertext)
    }

    fn open(
        &self,
        payload: &RecoveryPayload,
        _binding: &AuthoritySnapshotBinding,
    ) -> KernelResult<KernelAuthorityReplaySnapshot> {
        let RecoveryPayload::Encrypted { ciphertext, .. } = payload else {
            return Err(KernelError::RecoveryUnavailable(
                "901 lifecycle fixture payload is not encrypted".to_owned(),
            ));
        };
        serde_json::from_slice(ciphertext)
            .map_err(|error| KernelError::RecoveryUnavailable(error.to_string()))
    }
}

struct TempRoot(PathBuf);

impl TempRoot {
    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempRoot {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn test_root(tag: &str) -> TempRoot {
    let root = std::env::temp_dir().join(format!(
        "eliot-901-lifecycle-{tag}-{}-{}",
        std::process::id(),
        unix_ms()
    ));
    std::fs::create_dir_all(&root).expect("fixture work root");
    TempRoot(root)
}

fn test_epoch(sequence: u64) -> EpochId {
    EpochId::new(
        EpochLineageId::new(EPOCH_LINEAGE).expect("epoch lineage"),
        std::num::NonZeroU64::new(sequence).expect("epoch sequence"),
    )
    .expect("epoch")
}

fn authority_binding(authority_id: &DispatchAuthorityId) -> AuthoritySnapshotBinding {
    let epoch = EpochLineage {
        current: EpochIdentity {
            lineage_id: OpaqueLabel::new("eliot-901-lifecycle-lineage").expect("lineage"),
            epoch: 1,
        },
        predecessor: None,
    };
    let state_fence =
        StateFenceSnapshot::capture(&serde_json::json!({"authority": "eliot-901-lifecycle"}), 1)
            .expect("state fence snapshot");
    AuthoritySnapshotBinding::new(
        authority_id.clone(),
        OperationIdentity::new("eliot-901-lifecycle-authority-record").expect("record id"),
        epoch,
        state_fence,
        1,
        None,
    )
    .expect("authority snapshot binding")
}

/// The one owner identity these cases record. `generation` is a parameter so a
/// case can present an old-generation owner against the same retained record.
fn test_owner(generation: u64) -> ProcessOwnerBinding {
    ProcessOwnerBinding::new(
        "eliotd",
        "a".repeat(64),
        test_epoch(1),
        Generation::new(generation).expect("generation"),
    )
    .expect("owner")
}

fn ors_path(root: &Path) -> PathBuf {
    root.join(".eliot").join("kernel-ors.redb")
}

/// A real `ProcessExecutionGateway` over a real redb ORS, with the durable
/// process-start replay records named by `seeds` already persisted through the
/// store's own `begin_process_start`.
///
/// `gateway` is declared BEFORE `_root` on purpose: struct fields drop in
/// declaration order, so the gateway releases its open redb file before the
/// fixture removes the work root.
struct GatewayFixture {
    gateway: ProcessExecutionGateway,
    _root: TempRoot,
}

fn gateway_fixture(tag: &str, seeds: &[(&str, ProcessOwnerBinding)]) -> GatewayFixture {
    let root = test_root(tag);
    let path = ors_path(root.path());
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).expect("ors parent");
    }
    {
        let store = RedbRecoveryStore::open(&path).expect("seed ORS store");
        for (operation_id, owner) in seeds {
            let record = ProcessStartReplayRecord {
                operation_id: OperationIdentity::new(*operation_id).expect("replay operation"),
                admission_digest: "b".repeat(64),
                owner: owner.clone(),
                state: ProcessStartReplayState::Reserved,
                receipt: None,
            };
            record.validate().expect("seeded replay record is coherent");
            store
                .begin_process_start(&record)
                .expect("seed durable process-start replay record");
        }
    }
    let ors = Arc::new(RedbRecoveryStore::open(&path).expect("gateway ORS store"));
    let authority_id =
        DispatchAuthorityId::new("eliot-901-lifecycle-authority").expect("authority id");
    let binding = authority_binding(&authority_id);
    let platform =
        Arc::new(WindowsPlatform::new(root.path().to_path_buf()).expect("fixture platform root"));
    let path_admission = Arc::new(KernelPathAdmission::new(Arc::clone(&platform)));
    let authority_store: Arc<dyn OperationalRecoveryStore> = ors.clone();
    let controller = Arc::new(Mutex::new(ProcessDispatchAuthorityController::activate(
        authority_id,
        KernelDispatchKey::from_secret_bytes([0x6c; 32]).expect("dispatch key"),
        authority_store,
        Arc::new(FixtureAuthorityCodec),
    )));
    let gateway = ProcessExecutionGateway::new(controller, ors, binding, path_admission);
    GatewayFixture {
        gateway,
        _root: root,
    }
}

/// Registers one descendant through the production registry constructor, so the
/// registration carries the real owner coordinates its own contract validates.
fn register_descendant(
    gateway: &ProcessExecutionGateway,
    operation_id: &str,
    owner: &ProcessOwnerBinding,
) {
    let registration = RegisteredDescendant::new(
        OperationId::new(operation_id).expect("descendant operation id"),
        owner.module_id().to_owned(),
        owner.authority_epoch().clone(),
        owner.generation(),
    )
    .expect("registered descendant");
    gateway
        .descendants
        .lock()
        .expect("descendant registry")
        .register(registration)
        .expect("descendant registration");
}

fn registered_operation_ids(gateway: &ProcessExecutionGateway) -> Vec<String> {
    gateway
        .descendants
        .lock()
        .expect("descendant registry")
        .registered_operation_ids()
        .iter()
        .map(|id| id.as_str().to_owned())
        .collect()
}

/// A real `ProcessExecutionBinding` for the given operation. Built through the
/// contract's own `Deserialize`, the only public construction path for a binding
/// this Kernel did not itself mint from a permit.
fn test_binding(operation_id: &str, generation: u64) -> ProcessExecutionBinding {
    serde_json::from_value(serde_json::json!({
        "operation_id": operation_id,
        "process_tree_id": format!("{operation_id}-tree"),
        "job_id": format!("{operation_id}-job"),
        "image_id": format!("{operation_id}-image"),
        "session_id": format!("{operation_id}-session"),
        "generation": generation,
        "action_lease_ref": format!("{operation_id}-lease"),
        "authority_id": "eliot-901-lifecycle-authority",
        "authority_epoch": {
            "lineage_id": EPOCH_LINEAGE,
            "sequence": 1
        },
        "state_fence": {
            "authority_epoch": {
                "lineage_id": EPOCH_LINEAGE,
                "sequence": 1
            },
            "generation": generation,
            "nonce": format!("{operation_id}-fence")
        },
        "request_digest": "a".repeat(64),
        "permit_digest": "b".repeat(64),
        "effect_digest": "c".repeat(64),
        "validation_revision": 1
    }))
    .expect("process execution binding")
}

/// One real execution view carrying exactly the root lifecycle and the
/// descendant-tree observation the case needs. The production
/// `DescendantClosureReceipt::close` reads only those two.
fn test_view(
    operation_id: &str,
    generation: u64,
    lifecycle: &str,
    descendants: Option<&DescendantEvidence>,
) -> ProcessExecutionView {
    let binding = test_binding(operation_id, generation);
    serde_json::from_value(serde_json::json!({
        "binding": serde_json::to_value(&binding).expect("binding JSON"),
        "lifecycle": lifecycle,
        "health": {
            "status": "healthy",
            "ready": false,
            "observed_at_unix_ms": 10,
            "detail": null
        },
        "cancellation": "not_requested",
        "identity": null,
        "exit": null,
        "descendants": descendants
            .map(serde_json::to_value)
            .transpose()
            .expect("descendant evidence JSON"),
    }))
    .expect("process execution view")
}

/// A real `DescendantEvidence` tree observation built through the contract's own
/// constructor, so the coherence of `complete`, `tree_terminated` and
/// `evidence_ref` is the contract's decision and not this file's.
fn test_descendants(
    binding: &ProcessExecutionBinding,
    complete: bool,
    tree_terminated: bool,
    evidence_ref: Option<&str>,
    members: &[&str],
) -> DescendantEvidence {
    let ids = members
        .iter()
        .map(|member| ProcessId::new(*member).expect("descendant process id"))
        .collect();
    DescendantEvidence::new(
        binding.clone(),
        ProcessId::new("eliot-901-lifecycle-root").expect("root process id"),
        ids,
        complete,
        tree_terminated,
        evidence_ref.map(str::to_owned),
    )
    .expect("descendant evidence")
}

/// One real `ProcessStartReceipt` for the given operation identity. The binding,
/// its state fence and the identity all carry the same generation, so the
/// contract's own `matches_identity` accepts it; nothing here decides validity.
fn test_process_receipt(
    operation_id: &str,
    generation: u64,
    lifecycle: &str,
) -> ProcessStartReceipt {
    serde_json::from_value(serde_json::json!({
        "binding": {
            "operation_id": operation_id,
            "process_tree_id": format!("{operation_id}-tree"),
            "job_id": format!("{operation_id}-job"),
            "image_id": format!("{operation_id}-image"),
            "session_id": format!("{operation_id}-session"),
            "generation": generation,
            "action_lease_ref": format!("{operation_id}-lease"),
            "authority_id": "eliot-901-lifecycle-authority",
            "authority_epoch": {
                "lineage_id": EPOCH_LINEAGE,
                "sequence": 1
            },
            "state_fence": {
                "authority_epoch": {
                    "lineage_id": EPOCH_LINEAGE,
                    "sequence": 1
                },
                "generation": generation,
                "nonce": format!("{operation_id}-fence")
            },
            "request_digest": "a".repeat(64),
            "permit_digest": "b".repeat(64),
            "effect_digest": "c".repeat(64),
            "validation_revision": 1
        },
        "identity": {
            "suspended": {
                "process_id": format!("{operation_id}-process"),
                "process_tree_id": format!("{operation_id}-tree"),
                "job_id": format!("{operation_id}-job"),
                "image_id": format!("{operation_id}-image"),
                "session_id": format!("{operation_id}-session"),
                "generation": generation,
                "physical": {
                    "process_id": 4401,
                    "start_time_100ns": 1,
                    "image_path": "C:\\ProgramData\\Eliot\\bin\\eliotd.exe",
                    "executor_job_name": "Local\\Eliot-P04-901"
                },
                "created_suspended_at_unix_ms": 1,
                "executable_sha256": "a".repeat(64)
            },
            "resumed_at_unix_ms": 2
        },
        "lifecycle": lifecycle
    }))
    .expect("process start receipt")
}

fn test_launch(root: &Path) -> EliotdLaunchDescriptor {
    let executable =
        PlatformHandle::new(root.join("eliotd.exe").to_string_lossy()).expect("eliotd path");
    let config = PlatformHandle::new(root.join("eliotd-governor.json").to_string_lossy())
        .expect("eliotd config path");
    let working_directory = PlatformHandle::new(root.to_string_lossy()).expect("working directory");
    let executable_sha256 = "a".repeat(64);
    let config_sha256 = "b".repeat(64);
    let nonce =
        PlatformHandle::new("eliotd:9010123456789abcdef0123456789ab").expect("launch nonce");
    EliotdLaunchDescriptor {
        wire_id: "eliot.kernel.eliotd-launch".to_owned(),
        wire_version: EliotdLaunchDescriptor::CONTRACT_VERSION,
        executable,
        executable_sha256: executable_sha256.clone(),
        arguments: vec![
            PlatformHandle::new("--config-descriptor").expect("argument"),
            config.clone(),
            PlatformHandle::new("--config-descriptor-sha256").expect("argument"),
            PlatformHandle::new(&config_sha256).expect("argument"),
            PlatformHandle::new("--launch-nonce").expect("argument"),
            nonce.clone(),
            PlatformHandle::new("--executable-sha256").expect("argument"),
            PlatformHandle::new(&executable_sha256).expect("argument"),
        ],
        working_directory,
        config_descriptor: config,
        config_descriptor_sha256: config_sha256,
        protected_snapshot_digest: "c".repeat(64),
        launch_nonce: nonce,
        authority_epoch: test_epoch(1),
        generation: ResourceGeneration::genesis(),
        restart_policy: None,
        job_object_limits: None,
        health_readiness_contract_ref: None,
        descriptor_sha256: String::new(),
    }
    .with_computed_digest()
    .expect("descriptor digest")
}

/// Returns the GUARD first so `let (root_guard, kernel) = ...` declares the
/// guard first, and reverse declaration order then drops the composition -
/// which holds the fixture's open ORS file under this root - BEFORE the guard
/// removes the work root. Windows refuses `remove_dir_all` on a still-open
/// redb file, and the guard's `let _ =` would swallow that failure silently,
/// leaking one work root per run.
fn test_kernel(tag: &str) -> (TempRoot, KernelComposition) {
    let root = test_root(tag);
    let kernel = KernelComposition::new(KernelConfig::new(root.path())).expect("composition");
    (root, kernel)
}

fn current_thread_runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("tokio runtime")
}

// ---------------------------------------------------------------------------
// W11 — a parent exit does not establish descendant cleanup.
//
// The aggregation boundary the Kernel shutdown contour calls
// (`process_execution.rs::close_all_registered_descendants`) walks the registry
// and delegates every closure claim to
// `activation_lifecycle.rs::DescendantClosureReceipt::close`. That function is
// where the guarantee lives: `all_closed` is the conjunction of a TERMINAL root
// lifecycle AND a COMPLETE, TERMINATED tree observation
// (`activation_lifecycle.rs:173-177`), and `validate` (`:196-220`) refuses any
// receipt whose flag disagrees with that conjunction.
//
// The aggregation's own loop (`process_execution.rs:3461-3501`) is exercised on
// BOTH an empty and a one-entry registry, so "an empty registry yields nothing"
// is read as a measurement against a sweep that demonstrably yields something.
// ---------------------------------------------------------------------------

// WORK_UNIT_CASE: 901/22
#[test]
fn parent_exit_alone_never_establishes_descendant_cleanup() {
    let operation_id = "eliot-901-lifecycle-parent-exit";
    let registered_operation = "eliot-901-lifecycle-parent-exit-child";
    let owner = test_owner(1);

    // (1) The shutdown aggregation over an EMPTY registry. This is the state a
    // parent exit leaves when nothing is registered: the loop body never runs,
    // so no closure outcome and no closure observation exist at all.
    //
    // An empty sweep is only evidence because the SAME gateway is driven a
    // second time below with ONE registration the production writer really
    // created, and answers differently on the identical code path. Without that
    // contrast the two assertions here would be satisfied by a registry that is
    // empty no matter what, and deleting the whole loop body
    // (`process_execution.rs:3461-3501`) would redden nothing.
    let fixture = gateway_fixture("case12-sweep", &[(registered_operation, owner.clone())]);
    let runtime = current_thread_runtime();
    let (empty_logs, empty_outcomes) =
        capture_with(|| runtime.block_on(fixture.gateway.close_all_registered_descendants()));
    assert!(
        registered_operation_ids(&fixture.gateway).is_empty(),
        "the first sweep really runs over an empty registry: the durable replay record seeded for {registered_operation} is a retained RECORD, not a registration, and only the registry makes a sweep iterate"
    );
    assert!(
        empty_outcomes.is_empty(),
        "an empty registry produces no closure outcome: {empty_outcomes:?}"
    );
    assert!(
        !empty_logs.contains("kernel.process.descendant_close_"),
        "REGRESSION GUARD (absence): a parent exit with nothing registered observes no descendant closure at all. Non-vacuous because the SAME gateway is driven again below with one real registration and DOES emit these events, so the absence is a contrast, not a constant: {empty_logs}"
    );

    // (2) The SAME aggregation over the SAME gateway with ONE registration. The
    // loop at `process_execution.rs:3461` now runs exactly once and delegates to
    // the per-operation close boundary (`:3496-3500` ->
    // `close_registered_descendant_in_context`), so the outcome count and the
    // closure observations below are produced by the code the empty arm above
    // skipped. Deleting that loop body reddens every assertion in this block and
    // leaves the empty arm above untouched — which is what makes the empty arm
    // an observation rather than a constant.
    register_descendant(&fixture.gateway, registered_operation, &owner);
    assert_eq!(
        registered_operation_ids(&fixture.gateway),
        vec![registered_operation.to_owned()],
        "the second sweep really runs over a populated registry"
    );
    let (populated_logs, populated_outcomes) =
        capture_with(|| runtime.block_on(fixture.gateway.close_all_registered_descendants()));
    assert_eq!(
        populated_outcomes.len(),
        1,
        "one registered operation yields exactly one closure outcome where the empty registry yielded none: {populated_outcomes:?}"
    );
    let (populated_operation, populated_result) = &populated_outcomes[0];
    assert_eq!(
        populated_operation.as_str(),
        registered_operation,
        "the outcome is keyed by the exact registered operation: {populated_outcomes:?}"
    );
    assert!(
        matches!(populated_result, Err(ProcessExecutionError::NotFound)),
        "the aggregation really ran the close and that close was NOT a closure receipt, which is the W11 distinction itself: {populated_outcomes:?}"
    );
    assert!(
        event_count(&populated_logs, "kernel.process.descendant_close_requested") == 1
            && event_count(&populated_logs, "kernel.process.descendant_close_failed") == 1,
        "the populated sweep observes the close exactly once each where the empty sweep observed none at all: {populated_logs}"
    );
    assert!(
        !populated_logs.contains("event=\"kernel.process.descendant_close_observed\"")
            && !populated_logs.contains("outcome=\"closed\""),
        "REGRESSION GUARD (absence): a parent exit alone is still not a closure even when a descendant IS registered. `descendant_close_observed` is the SUCCESS arm at process_execution.rs:3406-:3416 and carries outcome closed/open, so this reddens if that arm is reached: {populated_logs}"
    );
    drop(fixture);
    drop(runtime);

    // (3) The closure decision itself, on five real views. Only a terminal root
    // together with a complete, terminated tree may read as closed.
    let registration = RegisteredDescendant::new(
        OperationId::new(operation_id).expect("descendant operation id"),
        owner.module_id().to_owned(),
        owner.authority_epoch().clone(),
        owner.generation(),
    )
    .expect("registered descendant");
    let binding = test_binding(operation_id, 1);

    // A: the parent exited and no tree observation exists at all.
    let receipt_a =
        DescendantClosureReceipt::close(&registration, &test_view(operation_id, 1, "exited", None));
    receipt_a.validate().expect("an open receipt is coherent");
    assert!(
        !receipt_a.all_closed(),
        "a parent exit with no descendant observation is not a closure"
    );
    assert_eq!(receipt_a.lifecycle(), ProcessLifecycle::Exited);
    assert!(
        receipt_a.evidence_ref().is_none(),
        "an unproven closure carries no evidence handle"
    );

    // B: the parent exited and the tree observation is explicitly INCOMPLETE.
    let incomplete = test_descendants(&binding, false, false, None, &[]);
    let receipt_b = DescendantClosureReceipt::close(
        &registration,
        &test_view(operation_id, 1, "exited", Some(&incomplete)),
    );
    receipt_b.validate().expect("an open receipt is coherent");
    assert!(
        !receipt_b.all_closed(),
        "an incomplete tree observation is not a closure"
    );

    // C: the parent exited and the observation is complete, but one Job member
    // was never proven terminated.
    let live_member = test_descendants(
        &binding,
        true,
        false,
        Some("eliot://blob/901-tree"),
        &["child-a"],
    );
    let receipt_c = DescendantClosureReceipt::close(
        &registration,
        &test_view(operation_id, 1, "exited", Some(&live_member)),
    );
    receipt_c.validate().expect("an open receipt is coherent");
    assert!(
        !receipt_c.all_closed(),
        "a complete observation with an unterminated tree member is not a closure"
    );

    // D: the whole tree IS proven terminated, but the root is still RUNNING, so
    // the parent has not exited at all.
    let terminated = test_descendants(
        &binding,
        true,
        true,
        Some("eliot://blob/901-tree"),
        &["child-a"],
    );
    let receipt_d = DescendantClosureReceipt::close(
        &registration,
        &test_view(operation_id, 1, "running", Some(&terminated)),
    );
    receipt_d.validate().expect("an open receipt is coherent");
    assert!(
        !receipt_d.all_closed(),
        "a terminated tree under a running parent is not a closure"
    );

    // The accepted arm: a terminal root AND a complete, terminated tree.
    let receipt_e = DescendantClosureReceipt::close(
        &registration,
        &test_view(operation_id, 1, "exited", Some(&terminated)),
    );
    receipt_e.validate().expect("a closed receipt is coherent");
    assert!(
        receipt_e.all_closed(),
        "only a terminal root with a complete, terminated tree closes"
    );

    // Every receipt is bound to THIS registration's operation and owner, and the
    // two receipts that share one tree observation differ ONLY because the root
    // lifecycle differs — that is the whole distinction, on the owner's own
    // inputs.
    for receipt in [&receipt_a, &receipt_b, &receipt_c, &receipt_d, &receipt_e] {
        assert_eq!(receipt.operation_id().as_str(), operation_id);
        assert_eq!(receipt.owner_module(), owner.module_id());
    }
    assert_eq!(receipt_d.evidence_ref(), Some("eliot://blob/901-tree"));
    assert_eq!(receipt_e.evidence_ref(), Some("eliot://blob/901-tree"));
    assert!(
        receipt_e.all_closed() && !receipt_d.all_closed(),
        "the same tree observation reads differently under a running and an exited root"
    );
    assert!(
        !receipt_a.all_closed() && !receipt_b.all_closed() && !receipt_c.all_closed(),
        "a parent exit alone, an incomplete tree and an unterminated member all stay open"
    );
}

// ---------------------------------------------------------------------------
// W30 — a cleanup/reap failure retains the owner and the reconciliation
// requirement.
//
// `close_all_registered_descendants` has two per-operation failure arms: a
// missing replay record (`process_execution.rs:3464-3478`) and an unprovable
// physical close (`:3419-3429`). Neither removes the registration, and the
// Kernel shutdown contour turns every `Err` into a retained
// `descendant-closure-unproven:<operation>` instead of a clean terminal
// (`lib.rs:4736-4742`).
// ---------------------------------------------------------------------------

// WORK_UNIT_CASE: 901/23
#[test]
fn cleanup_and_reap_failure_retain_owner_and_reconciliation_requirement() {
    // `orphan` is registered with NO durable replay record; `unproven` has one
    // whose owner matches, so its close is authorized and then fails at the
    // physical inspect. Two operations, two different failure owners, one
    // aggregation.
    let orphan_operation = "eliot-901-lifecycle-orphan";
    let unproven_operation = "eliot-901-lifecycle-unproven";
    let owner = test_owner(1);
    let fixture = gateway_fixture("case13", &[(unproven_operation, owner.clone())]);
    register_descendant(&fixture.gateway, orphan_operation, &owner);
    register_descendant(&fixture.gateway, unproven_operation, &owner);
    assert_eq!(
        registered_operation_ids(&fixture.gateway),
        vec![orphan_operation.to_owned(), unproven_operation.to_owned()],
        "both registrations are owned by this case before the aggregation runs"
    );

    let runtime = current_thread_runtime();
    let (logs, outcomes) =
        capture_with(|| runtime.block_on(fixture.gateway.close_all_registered_descendants()));

    assert_eq!(
        outcomes.len(),
        2,
        "one outcome per registered operation: {outcomes:?}"
    );
    for (operation, outcome) in &outcomes {
        assert!(
            matches!(outcome, Err(ProcessExecutionError::NotFound)),
            "a failed cleanup is never a closure receipt: {operation:?} -> {outcome:?}"
        );
    }

    // Neither failure released its registration: the owner evidence and the
    // reconciliation requirement both survive the failed close.
    assert_eq!(
        registered_operation_ids(&fixture.gateway),
        vec![orphan_operation.to_owned(), unproven_operation.to_owned()],
        "a failed cleanup retains every registration: {logs}"
    );
    assert!(
        fixture
            .gateway
            .descendants
            .lock()
            .expect("descendant registry")
            .get(&OperationId::new(unproven_operation).expect("operation id"))
            .is_some(),
        "the unproven closure keeps its owner module, epoch and generation"
    );

    // Each failed operation reports exactly one terminal, and the two records are
    // bound to their OWN operation rather than distinguished by line order.
    assert_eq!(
        terminal_codes(&logs),
        vec![
            "process_not_found".to_owned(),
            "process_not_found".to_owned()
        ],
        "one terminal per failed close, and the missing record and the unprovable close are the same typed code: {logs}"
    );
    assert_eq!(
        event_count(&logs, "kernel.process.descendant_close_failed"),
        2,
        "each failed close is observed once: {logs}"
    );
    assert!(
        !logs.contains("event=\"kernel.process.descendant_close_observed\"")
            && !logs.contains("outcome=\"closed\"")
            && !logs.contains("outcome=\"open\""),
        "REGRESSION GUARD (absence): a failed cleanup never reads as a closure, open or closed. `descendant_close_observed` is the Ok-only arm at process_execution.rs:3406-:3416 and is the only emitter of outcome closed/open on this boundary, so reaching it reddens this: {logs}"
    );

    let orphan_line = event_line_with(
        &logs,
        "kernel.process.descendant_close_failed",
        &format!("operation=\"{orphan_operation}\""),
    );
    let unproven_line = event_line_with(
        &logs,
        "kernel.process.descendant_close_failed",
        &format!("operation=\"{unproven_operation}\""),
    );
    // The flat terminal vector above proves the COUNT but not the ATTRIBUTION:
    // both codes are identical, so a mutation that emitted BOTH terminals under
    // the other operation's span would satisfy it. Each terminal is therefore
    // bound to the operation whose `descendant_close_failed` record names it,
    // read off the rendered span slot rather than off line order. The `orphan`
    // arm's terminal is the aggregate's own no-record arm
    // (process_execution.rs:3464-:3476, whose context is built by
    // `process_operation_context(Some(&op), None, None, None)` and therefore
    // carries the operation but no owner generation); the `unproven` arm's is
    // the composed close's terminal (process_execution.rs:3424-:3427).
    // `terminal_op` rather than `operation`: this scope already binds
    // `operation_id`, `registered_operation`, `orphan_operation` and
    // `unproven_operation`, and a fifth near-identical name trips
    // clippy::similar_names.
    for (terminal_op, failed_line) in [
        (orphan_operation, orphan_line),
        (unproven_operation, unproven_line),
    ] {
        // `terminal_lines`, not `owned`: this scope binds `owner` at :822, and
        // `owned` is close enough in name to trip clippy::similar_names.
        let terminal_lines: Vec<&str> = {
            let terminal_event = "event=\"kernel.terminal_error\"";
            let needle = format!("operation=\"{terminal_op}\"");
            logs.lines()
                .filter(|line| line.contains(terminal_event) && line.contains(&needle))
                .collect()
        };
        assert_eq!(
            terminal_lines.len(),
            1,
            "the failed close of {terminal_op} owns exactly one terminal, bound to ITS OWN operation and not to its neighbour's: {logs}"
        );
        assert_eq!(
            span_field(terminal_lines[0], "operation").unwrap_or_else(|| {
                panic!(
                    "the terminal of {terminal_op} carries no operation slot: {}",
                    terminal_lines[0]
                )
            }),
            terminal_op,
            "the terminal of {terminal_op} names the same operation its failure record does, so the single terminal cannot belong to the other close: {logs}"
        );
        assert!(
            failed_line.contains(&format!("operation=\"{terminal_op}\"")),
            "the failure record of {terminal_op} really carries its own operation slot, so the terminal binding above is compared against a per-operation record and not against line order: {failed_line}"
        );
    }
    assert_eq!(
        quoted(orphan_line, "outcome"),
        "unknown",
        "the missing-record arm stays unknown: {orphan_line}"
    );
    assert_eq!(
        quoted(unproven_line, "outcome"),
        "unknown",
        "the unprovable-close arm stays unknown: {unproven_line}"
    );
    // The missing-record arm could read NO owner at all, so its generation stays
    // unavailable; the authorized arm carries the RETAINED owner's generation,
    // because `close_all_registered_descendants` derives the owner from the
    // record and never from a caller.
    assert_eq!(
        recorded_on(orphan_line, "generation"),
        "unavailable",
        "an operation with no retained record has no owner generation to report: {orphan_line}"
    );
    assert_eq!(
        recorded_on(unproven_line, "generation"),
        owner.generation().get().to_string(),
        "the unprovable close still names the retained owner's generation: {unproven_line}"
    );
    assert!(
        event_count(&logs, "kernel.process.owner_admitted") >= 1
            && !logs.contains("event=\"kernel.process.owner_rejected\""),
        "REGRESSION GUARD (absence): the close authorized the RETAINED owner before inspecting. `owner_admitted` is process_execution.rs:4528 and `owner_rejected` its :4523 sibling; they are mutually exclusive, so the presence and the absence pin the same authorization: {logs}"
    );
}

// ---------------------------------------------------------------------------
// W31 — a restart/reattach observation binds the exact operation, process and
// lease.
//
// `daemon_live_receipt.rs::record_process_receipt_context` (:61-88) is the
// reattach correlation seam: it records the receipt's own operation, generation,
// fence, epoch digest, PID, start marker and image digest, and it records
// NOTHING when `process.validate()` fails. Production reaches it from
// `validate_daemon_process_readiness_in_context` (:574), whose
// `readiness_requested` record is rendered under that same span.
// ---------------------------------------------------------------------------

// WORK_UNIT_CASE: 901/24
#[test]
fn restart_reattach_observation_binds_exact_operation_process_and_lease() {
    // Declared guard-FIRST, so reverse declaration order drops the composition
    // before the guard: `KernelComposition` holds the fixture's open ORS file
    // under this root, and Windows refuses `remove_dir_all` on a still-open
    // redb file, which the guard's `let _ =` would then silently swallow.
    let (root_guard, kernel) = test_kernel("case14");
    let launch = test_launch(root_guard.path());
    let runtime = current_thread_runtime();

    // The reattached receipt of THIS restart: its own operation, generation and
    // physical identity, all validated by the contract before any recording.
    let receipt = test_process_receipt("eliot-901-lifecycle-reattach", 3, "running");
    receipt
        .validate()
        .expect("the reattached receipt is coherent");

    let (attach_logs, attach_result) = capture_with(|| {
        let context = crate::kernel_diagnostics::operation_context(None, None, None, None);
        runtime.block_on(
            kernel.validate_daemon_process_readiness_in_context(&launch, &receipt, &context, true),
        )
    });
    assert!(
        attach_result.is_err(),
        "a composition with no physical process authority cannot prove readiness: {attach_result:?}"
    );

    let physical = receipt.identity().physical();
    let epoch_digest = receipt
        .binding()
        .state_fence()
        .canonical_epoch_digest()
        .expect("canonical epoch digest")
        .as_str()
        .to_owned();
    for (slot, expected) in [
        ("operation", receipt.operation_id().as_str().to_owned()),
        (
            "generation",
            receipt.accepted_generation().get().to_string(),
        ),
        ("process_id", physical.process_id().to_string()),
        (
            "process_start_100ns",
            physical.start_time_100ns().to_string(),
        ),
        (
            "image_sha256",
            receipt.identity().executable_sha256().to_owned(),
        ),
        ("state_fence", epoch_digest.clone()),
        ("authority_epoch", epoch_digest.clone()),
    ] {
        assert_eq!(
            recorded(
                &attach_logs,
                "kernel.live_receipt.readiness_requested",
                slot
            ),
            expected,
            "the reattach record binds THIS receipt's {slot}: {attach_logs}"
        );
    }
    // REGRESSION GUARD (absence). These three slots keep their declared
    // `"unavailable"` default (`kernel_diagnostics.rs:674-676`) on THIS capture,
    // and each one CAN redden — but for two DIFFERENT reasons, so they are not
    // asserted as one claim.
    //
    // `lease` and `receipt`: honest guards. The only writer of either slot on a
    // readiness span is `record_live_receipt_context_field` at
    // `daemon_live_receipt.rs:293`/`:484` (lease) and `:294`/`:485` (receipt),
    // all four inside the live-receipt PUBLISH/VERIFY owners, which this
    // readiness boundary never enters. A mutation recording either slot here
    // reddens both asserts.
    //
    // `process_tree` is NOT the same claim, and is asserted separately because
    // production DOES record this receipt's tree onto this very span:
    // `process_execution.rs:3106`-`:3111` inside `inspect_exact_running_receipt_in_context`,
    // which `validate_daemon_process_readiness_inner` calls at
    // `daemon_live_receipt.rs:616`. It reads unavailable here ONLY because THIS
    // composition carries no physical process authority: `KernelComposition::new`
    // passes `None` for the gateway (`composition_bootstrap.rs:579` ->
    // `Self::assemble(config, ors, ors_path, None, platform)`), so the inner
    // validator refuses at `daemon_live_receipt.rs:610`-`:614` before reaching
    // that readback. The assertion therefore pins the ABSENCE OF THE GATEWAY,
    // not a limit on what a reattach record may carry.
    for slot in ["lease", "receipt"] {
        assert_eq!(
            recorded(
                &attach_logs,
                "kernel.live_receipt.readiness_requested",
                slot
            ),
            "unavailable",
            "REGRESSION GUARD (absence): no live-receipt publish/verify owner writes {slot} on this boundary, so the declared default stands: {attach_logs}"
        );
    }
    assert_eq!(
        recorded(
            &attach_logs,
            "kernel.live_receipt.readiness_requested",
            "process_tree"
        ),
        "unavailable",
        "REGRESSION GUARD (absence): this composition has no physical process authority, so the readback at daemon_live_receipt.rs:616 that records the receipt's own tree is never entered: {attach_logs}"
    );

    // A LATE receipt for a DIFFERENT operation and generation, driven through
    // the same boundary: the values are that receipt's own, so the binding is to
    // content and is neither sticky nor shared.
    let late = test_process_receipt("eliot-901-lifecycle-late-reattach", 5, "running");
    late.validate().expect("the late receipt is coherent");
    let late_logs = capture(|| {
        let context = crate::kernel_diagnostics::operation_context(None, None, None, None);
        let late_result = runtime.block_on(
            kernel.validate_daemon_process_readiness_in_context(&launch, &late, &context, true),
        );
        assert!(
            late_result.is_err(),
            "a late reattach for another operation and generation is refused by the same absence of physical process authority: {late_result:?}"
        );
    });
    assert_eq!(
        recorded(
            &late_logs,
            "kernel.live_receipt.readiness_requested",
            "operation"
        ),
        late.operation_id().as_str(),
        "the late reattach binds its own operation: {late_logs}"
    );
    assert_eq!(
        recorded(
            &late_logs,
            "kernel.live_receipt.readiness_requested",
            "generation"
        ),
        "5",
        "the late reattach binds its own generation: {late_logs}"
    );

    // The REFUSAL arm: a receipt the contract itself rejects contributes no
    // identity at all. `record_process_receipt_context` returns before its first
    // `record` (`daemon_live_receipt.rs:65`-`:67`), so every slot keeps its
    // declared `"unavailable"` default — a malformed identity remains
    // unavailable, never guessed.
    let invalid = test_process_receipt("eliot-901-lifecycle-invalid-reattach", 3, "exited");
    assert!(
        invalid.validate().is_err(),
        "a non-running receipt cannot pass the contract validator"
    );
    let (invalid_logs, invalid_result) = capture_with(|| {
        let context = crate::kernel_diagnostics::operation_context(None, None, None, None);
        runtime.block_on(
            kernel.validate_daemon_process_readiness_in_context(&launch, &invalid, &context, true),
        )
    });
    assert!(
        invalid_result.is_err(),
        "an invalid reattach receipt cannot prove readiness: {invalid_result:?}"
    );
    // The five identity slots are the REAL discriminator for this arm: they are
    // exactly the ones `record_process_receipt_context` would have written at
    // `:70`-`:87` had the `validate()` early return not fired, so deleting that
    // guard reddens every one of them.
    for slot in [
        "operation",
        "generation",
        "process_id",
        "process_start_100ns",
        "image_sha256",
    ] {
        assert_eq!(
            recorded(
                &invalid_logs,
                "kernel.live_receipt.readiness_requested",
                slot
            ),
            "unavailable",
            "an invalid reattach receipt contributes no {slot}: the record never ran: {invalid_logs}"
        );
    }
    // REGRESSION GUARD (absence) — `lease` and `receipt` are pure declared
    // defaults here: no writer of either slot exists on this boundary at all (see
    // the attach arm above for the census), so these two assert the default and
    // not the early return.
    for slot in ["lease", "receipt"] {
        assert_eq!(
            recorded(
                &invalid_logs,
                "kernel.live_receipt.readiness_requested",
                slot
            ),
            "unavailable",
            "REGRESSION GUARD (absence): no writer of {slot} exists on this boundary: {invalid_logs}"
        );
    }
    assert!(
        !invalid_logs.contains("event=\"kernel.live_receipt.readiness_proven\""),
        "REGRESSION GUARD (absence): an invalid reattach receipt never reads as proven readiness: {invalid_logs}"
    );
}

// ---------------------------------------------------------------------------
// W24 — a late receipt or exit cannot revive revoked or old-generation
// authority.
//
// `process_execution.rs::reconcile_origin_grant_effect` (:2331-2411) is the
// post-crash / lost-response reconciliation query. It authorizes the presented
// owner against the RETAINED operation record FIRST (:2352), so only an
// authorized owner ever reaches the durable effect journal. Its vocabulary is
// four distinct records, selected at :2396-2403 from two flags:
// `grant_reconcile_rejected`/`fenced` when `rejected` (:2399),
// `grant_reconcile_unknown`/`unknown` when `unknown` (:2397),
// `grant_reconcile_failed`/`unknown` for every other admitted failure (:2401),
// and `grant_reconcile_replayed` — reachable ONLY for a proven effect — for a
// replay.
//
// `unknown` is set in exactly ONE place, :2380-2383, and only AFTER the source
// lookup at :2354-2361 has returned a journaled entry for the presented nonce.
// That arm therefore requires a RECORDED, DECIDED OriginControl grant whose
// `effect_outcome()` is `Unknown` (`origin_challenge.rs:827`), with the same
// operation (:2362), a journaled installation equal to the live Kernel
// installation (:2368) and a `Kill` operation class (:2374). This fixture
// cannot mint one: gateway issuance (:2183) and gateway decision (:2208) each
// refuse unless the process-global `DISPATCH_CONTOUR` (`dispatch_launch.rs:846`,
// set once by `compose_dispatch_contour` at `dispatch_launch.rs:951`, and
// already composed by sibling in-crate cases with their own principal at
// `dispatch_launch.rs:6208`/`:6729`) is composed with the very installation
// identity the journaled entry must equal at :2368 — a composition this
// observation-only file neither owns nor can make deterministic under parallel
// tests. Leg 3 below therefore pins the arm an UNRECORDED nonce really takes,
// and pins `grant_reconcile_unknown` as ABSENT.
//
// WHY THIS TEST CARRIES NO `// WORK_UNIT_CASE` MARKER, stated rather than left
// to be inferred: the issue's matrix is exactly 30 cases numbered 1..30 and every
// one of those numbers is already owned and recorded in the fixture's
// `case_owners[].test_file`. Case 17's carrier is the receipt capsule and case
// 11's is the identity capsule, so claiming a number here would either collide
// with that mapping or silently renumber an existing case. This test is
// supplementary: it pins real production lines (the reconciliation boundary
// :2331-2411 and the fence/generation refusals at :2362, :2368 and :2374), but it
// is not the test the matrix names for any of its claims.
// ---------------------------------------------------------------------------

#[test]
fn late_receipt_or_exit_cannot_revive_revoked_or_old_generation_authority() {
    let exit_operation = "eliot-901-lifecycle-late-exit";
    let retained_owner = test_owner(1);
    let fixture = gateway_fixture("case17", &[(exit_operation, retained_owner.clone())]);
    let exit = OperationId::new(exit_operation).expect("exit operation id");
    // `reconcile_origin_grant_effect` is the SYNCHRONOUS reconciliation boundary
    // (process_execution.rs:2331), so this case drives it directly and needs no
    // runtime.
    let nonce = "eliot-901-lifecycle-one-shot-nonce";

    // (1) REFUSED: a late exit presented by an OLD-GENERATION owner. The
    // retained record names generation 1; the presented owner is generation 2,
    // so `authorize_process_owner_in_context` refuses and the boundary reports
    // `rejected`/`fenced` WITHOUT reading the effect journal.
    let old_generation_owner = test_owner(2);
    let (refused_logs, refused) = capture_with(|| {
        fixture
            .gateway
            .reconcile_origin_grant_effect(&old_generation_owner, &exit, nonce)
    });
    assert!(
        refused.is_err(),
        "an old-generation exit cannot reconcile a retained operation: {refused:?}"
    );
    assert_eq!(
        event_outcome(&refused_logs, "kernel.process.grant_reconcile_requested"),
        "attempt"
    );
    assert_eq!(
        event_outcome(&refused_logs, "kernel.process.owner_rejected"),
        "fenced"
    );
    assert_eq!(
        event_outcome(&refused_logs, "kernel.process.grant_reconcile_rejected"),
        "fenced"
    );
    assert!(
        !refused_logs.contains("event=\"kernel.process.grant_reconcile_replayed\""),
        "REGRESSION GUARD (absence): a refused reconcile never replays a preserved receipt, because the replay arm is the Ok-only arm at process_execution.rs:2387-:2393: {refused_logs}"
    );
    assert_eq!(
        terminal_codes(&refused_logs),
        vec!["process_contract".to_owned()],
        "the refused reconcile owns exactly one terminal: {refused_logs}"
    );
    // The refusal still names the operation it was asked about, and it names the
    // PRESENTED generation, so the record cannot be mistaken for the retained
    // owner's own lineage.
    let refused_request = event_line(&refused_logs, "kernel.process.grant_reconcile_requested");
    assert_eq!(
        recorded_on(refused_request, "operation"),
        exit_operation,
        "the refused attempt names the exact operation: {refused_request}"
    );
    assert_eq!(
        recorded_on(refused_request, "generation"),
        "2",
        "the refused attempt records the PRESENTED old generation: {refused_request}"
    );

    // (2) REFUSED: the exact retained owner, but for an operation this Kernel
    // never retained. There is no record to authorize against, so the boundary
    // fences before any journal read and never reports a replay.
    let foreign_operation =
        OperationId::new("eliot-901-lifecycle-unknown-exit").expect("foreign operation id");
    let (foreign_logs, foreign) = capture_with(|| {
        fixture
            .gateway
            .reconcile_origin_grant_effect(&retained_owner, &foreign_operation, nonce)
    });
    assert!(
        foreign.is_err(),
        "an exit for an unrecorded operation cannot reconcile: {foreign:?}"
    );
    assert_eq!(
        event_outcome(&foreign_logs, "kernel.process.grant_reconcile_rejected"),
        "fenced"
    );
    assert!(
        !foreign_logs.contains("event=\"kernel.process.grant_reconcile_replayed\""),
        "REGRESSION GUARD (absence): an unrecorded operation never replays a receipt, because the replay arm is the Ok-only arm at process_execution.rs:2387-:2393: {foreign_logs}"
    );
    assert_eq!(
        terminal_codes(&foreign_logs),
        vec!["process_not_found".to_owned()],
        "the unrecorded operation is refused by its own single terminal: {foreign_logs}"
    );

    // (3) ACCEPTED AUTHORIZATION, NO DECIDED GRANT: the exact retained owner is
    // admitted past `authorize_operation` (:2352) and reaches the durable source
    // lookup (:2354-2361), where the journal holds no decided grant for this
    // nonce: `grant_reconciliation_source` refuses it with the typed
    // `request_nonce` contract failure (`origin_challenge.rs:1415-1427`) that
    // `origin_contract_error` (:2250-2257) preserves as `Contract`. At that
    // moment `rejected` is already false again (:2353) and `unknown` was never
    // set, so the selection at :2396-2403 takes the `grant_reconcile_failed`
    // arm (:2401) with outcome `unknown` — NOT `grant_reconcile_unknown`
    // (:2397), which is unreachable for an unrecorded nonce because `unknown` is
    // only ever set at :2380-2383, after this lookup has succeeded. Nothing is
    // replayed and nothing is revived: the answer stays `unknown`, by name.
    let (admitted_logs, admitted) = capture_with(|| {
        fixture
            .gateway
            .reconcile_origin_grant_effect(&retained_owner, &exit, nonce)
    });
    assert!(
        admitted.is_err(),
        "no decided grant exists for this nonce, so nothing is replayed: {admitted:?}"
    );
    assert_eq!(
        event_outcome(&admitted_logs, "kernel.process.owner_admitted"),
        "success"
    );
    assert_eq!(
        event_outcome(&admitted_logs, "kernel.process.grant_reconcile_failed"),
        "unknown",
        "an admitted reconcile refused at the source lookup for an unrecorded nonce is reported as grant_reconcile_failed with outcome unknown: {admitted_logs}"
    );
    assert!(
        !admitted_logs.contains("event=\"kernel.process.grant_reconcile_unknown\""),
        "REGRESSION GUARD (absence): the unproven-effect arm is unreachable while the source lookup fails, because `unknown` is assigned in exactly ONE place (process_execution.rs:2380-:2383) and only AFTER the :2354-:2361 lookup has returned a journaled entry. Moving or duplicating that assignment reddens this: {admitted_logs}"
    );
    assert!(
        !admitted_logs.contains("event=\"kernel.process.grant_reconcile_replayed\""),
        "REGRESSION GUARD (absence): an unproven effect never replays a preserved receipt, because the replay arm is the Ok-only arm at process_execution.rs:2387-:2393: {admitted_logs}"
    );
    assert_eq!(
        terminal_codes(&admitted_logs).len(),
        1,
        "the admitted reconcile owns exactly one terminal: {admitted_logs}"
    );
    let admitted_request = event_line(&admitted_logs, "kernel.process.grant_reconcile_requested");
    assert_eq!(
        recorded_on(admitted_request, "generation"),
        retained_owner.generation().get().to_string(),
        "the admitted attempt records the RETAINED generation: {admitted_request}"
    );
    assert_ne!(
        recorded_on(refused_request, "generation"),
        recorded_on(admitted_request, "generation"),
        "an old-generation exit and a retained-generation exit are distinguishable without relying on line order"
    );

    // The one-shot nonce is never projected onto any record, and none of the
    // three attempts ever reaches the `replayed` name. REGRESSION GUARD
    // (absence): `reconcile_origin_grant_effect` builds its span from
    // `process_operation_context(Some(operation_id), Some(owner.generation()),
    // None, Some(owner.authority_epoch()))` (process_execution.rs:2337-:2342),
    // which never names `request_nonce`; a mutation projecting the consumed
    // one-shot onto any of these spans reddens all three.
    for logs in [&refused_logs, &foreign_logs, &admitted_logs] {
        assert!(
            !logs.contains(nonce),
            "REGRESSION GUARD (absence): the one-shot nonce never reaches the sink: {logs}"
        );
    }
}

// ---------------------------------------------------------------------------
// W21 — a cancellation acknowledgement is not a terminal cancellation.
//
// `process_execution.rs::cancel_with_origin_grant_inner` (:3196-3323) emits
// `cancel_acknowledged` only after the executor OBSERVED a receipt (:3321), or
// after a proven grant effect replayed its preserved receipt (:3274). Both of
// those arms need a live physical operation this process launched, so what is
// provable in-crate is the boundary's own refusal vocabulary: an unauthorized
// operation is `rejected`/`fenced`, and an authorized operation whose delivery
// cannot be proven is `failed`/`unknown` with exactly one terminal. In neither
// arm is anything acknowledged, de-registered, or reported as terminal.
// ---------------------------------------------------------------------------

// WORK_UNIT_CASE: 901/19
#[test]
fn cancellation_acknowledgement_is_not_terminal_cancellation() {
    let authorized_operation = "eliot-901-lifecycle-cancel-authorized";
    let unknown_operation = "eliot-901-lifecycle-cancel-unknown";
    let owner = test_owner(1);
    let fixture = gateway_fixture("case19", &[(authorized_operation, owner.clone())]);
    // The authorized operation is also a registered descendant, so the case can
    // show that a cancellation request is not a cleanup.
    register_descendant(&fixture.gateway, authorized_operation, &owner);
    let runtime = current_thread_runtime();

    // (1) AUTHORIZED OWNER, UNPROVEN DELIVERY. The retained record's owner IS
    // the presented owner, so the boundary is admitted and reaches the executor.
    // No physical operation exists for this identity, so delivery cannot be
    // proven: the outcome stays `unknown` and the error is `UnknownOutcome` —
    // never a terminal cancellation claim.
    let authorized = OperationId::new(authorized_operation).expect("operation id");
    let (authorized_logs, authorized_result) = capture_with(|| {
        let context = ProcessExecutionGateway::operation_context_for(&owner, &authorized);
        runtime.block_on(
            fixture
                .gateway
                .cancel_in_context(&owner, authorized.clone(), &context),
        )
    });
    assert!(
        matches!(
            authorized_result,
            Err(ProcessExecutionError::UnknownOutcome)
        ),
        "an unproven cancellation delivery stays an unknown outcome: {authorized_result:?}"
    );
    assert_eq!(
        event_outcome(&authorized_logs, "kernel.process.cancel_requested"),
        "attempt"
    );
    assert_eq!(
        event_outcome(&authorized_logs, "kernel.process.owner_admitted"),
        "success"
    );
    assert_eq!(
        event_outcome(&authorized_logs, "kernel.process.cancel_failed"),
        "unknown"
    );
    assert!(
        !authorized_logs.contains("event=\"kernel.process.cancel_acknowledged\""),
        "REGRESSION GUARD (absence): an unproven delivery is never acknowledged. `cancel_acknowledged` is emitted only at process_execution.rs:3321 (executor-observed receipt) or :3274 (proven grant-effect replay), neither of which this arm reaches, so reaching either reddens this: {authorized_logs}"
    );
    assert!(
        !authorized_logs.contains("event=\"kernel.process.descendant_close_observed\"")
            && !authorized_logs.contains("outcome=\"closed\"")
            && !authorized_logs.contains("outcome=\"open\""),
        "REGRESSION GUARD (absence): an unproven cancellation is never a descendant closure. `cancel_in_context` reaches no descendant-close callsite at all, and `descendant_close_observed` (process_execution.rs:3406-:3416) is the sole emitter of outcome closed/open on this boundary: {authorized_logs}"
    );
    assert_eq!(
        terminal_codes(&authorized_logs),
        vec!["process_unknown_outcome".to_owned()],
        "the failed cancel owns exactly one terminal: {authorized_logs}"
    );
    let cancel_request = event_line(&authorized_logs, "kernel.process.cancel_requested");
    assert_eq!(
        recorded_on(cancel_request, "operation"),
        authorized_operation,
        "the cancel record binds THIS operation: {cancel_request}"
    );
    assert_eq!(
        recorded_on(cancel_request, "generation"),
        owner.generation().get().to_string(),
        "the cancel record binds THIS owner generation: {cancel_request}"
    );
    // The registration survives: a cancellation request is not a cleanup. This
    // claim is INERT for the boundary under test — `cancel_in_context`
    // (process_execution.rs:3160) reaches `authorize_effect_with_grant` (:3218)
    // and `executor.cancel` (:3292) and nothing that owns `self.descendants` — so
    // it is stated as a MEASURED count against a registry this case then proves
    // is live, not as a constant that no deletion could contradict. The
    // registry's actual writer is asserted by the companion below.
    assert_eq!(
        registered_operation_ids(&fixture.gateway),
        vec![authorized_operation.to_owned()],
        "an unproven cancellation retains the registration: {authorized_logs}"
    );
    // The count above is a measurement, not a constant: the SAME registry,
    // driven through the production writer `DescendantRegistry::register`
    // (activation_lifecycle.rs:108), reports the newly registered child AND
    // still reports the entry the cancel boundary left behind. Deleting that
    // insert reddens this assertion; so does any future cancel-boundary write to
    // `self.descendants` that removed or renamed the retained entry.
    let later_child = "eliot-901-lifecycle-cancel-later-child";
    register_descendant(&fixture.gateway, later_child, &owner);
    assert_eq!(
        registered_operation_ids(&fixture.gateway),
        vec![authorized_operation.to_owned(), later_child.to_owned()],
        "the retained registration is still there after a later REAL registration, so a cancellation request is not a cleanup: {authorized_logs}"
    );

    // (2) REFUSED: an operation this Kernel never retained. There is no record to
    // authorize against, so the boundary fences before touching the executor.
    let unknown = OperationId::new(unknown_operation).expect("operation id");
    let (unknown_logs, unknown_result) = capture_with(|| {
        let context = ProcessExecutionGateway::operation_context_for(&owner, &unknown);
        runtime.block_on(
            fixture
                .gateway
                .cancel_in_context(&owner, unknown.clone(), &context),
        )
    });
    assert!(
        matches!(unknown_result, Err(ProcessExecutionError::NotFound)),
        "an unauthorized cancellation is refused by the retained-record lookup: {unknown_result:?}"
    );
    assert_eq!(
        event_outcome(&unknown_logs, "kernel.process.cancel_rejected"),
        "fenced"
    );
    assert!(
        !unknown_logs.contains("event=\"kernel.process.cancel_acknowledged\""),
        "REGRESSION GUARD (absence): a refused cancellation is never acknowledged. The refusal returns at process_execution.rs:3230, which is upstream of both acknowledgement arms (:3274 and :3321), so reaching either reddens this: {unknown_logs}"
    );
    assert_eq!(
        terminal_codes(&unknown_logs),
        vec!["process_not_found".to_owned()],
        "the refused cancel owns exactly one terminal: {unknown_logs}"
    );
    assert!(
        !unknown_logs.contains("event=\"kernel.process.cancel_failed\""),
        "REGRESSION GUARD (absence): a refused cancellation never reaches the executor at all. `cancel_failed` is emitted only from process_execution.rs:3300 (after `executor.cancel` at :3292) and :3262, both downstream of the :3230 refusal, so reaching either reddens this: {unknown_logs}"
    );

    // The two arms are different facts rather than one fact relabelled: an
    // unproven DELIVERY and an unauthorized REQUEST are different records with
    // different typed codes. Neither reaches `cancel_acknowledged` — which is
    // precisely why an acknowledgement could not be read as a terminal
    // cancellation in the first place.
    assert_ne!(
        terminal_codes(&authorized_logs),
        terminal_codes(&unknown_logs),
        "an unproven delivery and an unauthorized request are distinct failures"
    );
}

// ---------------------------------------------------------------------------
// AUD3 + AUD4 (audit comment 5917649683) — every `close_registered_descendant`
// error path emits exactly one terminal, INCLUDING registry/readback failures,
// and the nested `inspect` double-terminal path is gone.
//
// AUD3, quoted: "make every `close_registered_descendant` error path emit
// exactly one terminal, including registry/readback failures". Unrepaired, the
// descendant read sat BEHIND `?` ahead of the function's own result wrapper: a
// poisoned registry lock (`process_execution.rs:3362-3367`) and a missing
// registration (`:3368-3370`) returned from the function before
// `descendant_close_failed` (`:3419-3423`) and before the terminal
// (`:3424-3427`), so those arms emitted NEITHER record. The arm that
// discriminates AUD3 is therefore the descendant READ itself — an authorized
// owner whose operation has no registration — never the
// `authorize_operation` refusal at `:3347-3357`, which already emitted one of
// each.
//
// AUD4, quoted: "remove the nested `inspect` double-terminal path". Unrepaired,
// the readback at `:3371-3373` called the PUBLIC `inspect` wrapper
// (`:3026-3033`), whose `inspect_in_context` failure arm (`:3060-3064`) assigns
// its own `kernel.terminal_error`; the outer close then assigned a SECOND one
// for the same propagated error. `inspect_inner` (`:3073-3094`, "Reads one
// operation without assigning a terminal") is the nonterminal read, so this arm
// reaches the readback and yields exactly one terminal.
//
// Two operations share ONE capture, so every count below is per operation
// IDENTITY and never line order: `readback` clears the registry read and fails
// AT the readback (`:3372`); `registry_gap` fails AT the missing registration
// (`:3370`). This is a SUPPLEMENTARY case: AUD3/AUD4 own no
// work-unit case number, so no case marker is attached here and no existing
// marker, test name or assertion is renumbered or moved.
// ---------------------------------------------------------------------------

#[test]
fn descendant_close_read_failure_emits_exactly_one_terminal_per_operation() {
    // `readback` has a retained replay record AND a registration, so it clears
    // `authorize_operation` (`:3347`), the registry lookup (`:3368`) and fails
    // inside the readback (`:3372`). `registry_gap` carries the SAME retained
    // record and owner but no registration, so it is the missing-registration
    // `NotFound` of `:3370` itself — both refusals are the owner's own decision
    // on data this fixture really produced, and no lock is poisoned.
    let readback_operation = "eliot-901-lifecycle-audit-readback";
    let registry_gap_operation = "eliot-901-lifecycle-audit-registry-gap";
    let owner = test_owner(1);
    let fixture = gateway_fixture(
        "case-aud34",
        &[
            (readback_operation, owner.clone()),
            (registry_gap_operation, owner.clone()),
        ],
    );
    register_descendant(&fixture.gateway, readback_operation, &owner);
    assert_eq!(
        registered_operation_ids(&fixture.gateway),
        vec![readback_operation.to_owned()],
        "exactly one operation is registered, so the registry-gap arm below is the missing-registration read at :3370 and not a fenced authorization"
    );
    let runtime = current_thread_runtime();

    // ONE capture for BOTH operations. `capture_with` installs the subscriber
    // around a synchronous `block_on`, and a span binds its dispatcher at
    // CONSTRUCTION, so both contexts are built inside the capture region.
    let (logs, results) = capture_with(|| {
        let readback = OperationId::new(readback_operation).expect("readback operation id");
        let readback_context = ProcessExecutionGateway::operation_context_for(&owner, &readback);
        let readback_result =
            runtime.block_on(fixture.gateway.close_registered_descendant_in_context(
                &owner,
                readback,
                &readback_context,
            ));
        let registry_gap =
            OperationId::new(registry_gap_operation).expect("registry gap operation id");
        let registry_gap_context =
            ProcessExecutionGateway::operation_context_for(&owner, &registry_gap);
        let registry_gap_result =
            runtime.block_on(fixture.gateway.close_registered_descendant_in_context(
                &owner,
                registry_gap,
                &registry_gap_context,
            ));
        (readback_result, registry_gap_result)
    });

    // Neither close produced a receipt: both failures are typed `NotFound`, the
    // projection `process_terminal_code` (:236-244) maps to `process_not_found`.
    for (operation, result) in [
        (readback_operation, &results.0),
        (registry_gap_operation, &results.1),
    ] {
        assert!(
            matches!(result, Err(ProcessExecutionError::NotFound)),
            "a close that cannot read its descendant is never a closure receipt: {operation} -> {result:?}"
        );
    }

    // Which arm each operation really entered, read off the capture rather than
    // assumed: only the readback operation reaches the readback at `:3372`.
    let count_for = |event: &str, operation: &str| -> usize {
        let event = format!("event=\"{event}\"");
        let operation = format!("operation=\"{operation}\"");
        logs.lines()
            .filter(|line| line.contains(&event) && line.contains(&operation))
            .count()
    };
    assert_eq!(
        count_for(
            "kernel.process.descendant_close_requested",
            readback_operation
        ),
        1,
        "the readback operation entered the close boundary exactly once: {logs}"
    );
    assert_eq!(
        count_for("kernel.process.inspect_failed", readback_operation),
        1,
        "the readback operation passed the registry read at :3368 and failed inside the readback at :3372: {logs}"
    );
    assert_eq!(
        count_for("kernel.process.inspect_failed", registry_gap_operation),
        0,
        "the registry-gap operation failed AT the missing registration (:3370) and never reached the readback, which is what makes it the AUD3 arm: {logs}"
    );
    assert!(
        !logs.contains("event=\"kernel.process.descendant_close_rejected\""),
        "REGRESSION GUARD (absence): neither arm was fenced at authorize_operation (process_execution.rs:3347-:3358); both presented the owner their own retained record names, so both passed. Reaching that arm reddens this: {logs}"
    );

    // AUD3 — every error path, including the registry and readback failures,
    // observes its failure and assigns exactly one terminal. Unrepaired, these
    // two arms returned through `?` before `:3405-3430` and emitted neither.
    for operation in [readback_operation, registry_gap_operation] {
        assert_eq!(
            count_for("kernel.process.descendant_close_failed", operation),
            1,
            "a failed descendant close is observed exactly once for {operation}, which the unrepaired `?` shortcut never emitted: {logs}"
        );
        let observation = event_line_with(
            &logs,
            "kernel.process.descendant_close_failed",
            &format!("operation=\"{operation}\""),
        );
        assert_eq!(
            quoted(observation, "outcome"),
            "unknown",
            "the failure of {operation} is observed as unknown, never as a closure: {observation}"
        );
        assert!(
            !logs.contains("event=\"kernel.process.descendant_close_observed\""),
            "REGRESSION GUARD (absence): a failed descendant close never reads as a closure, open or closed. `descendant_close_observed` is the Ok-only arm at process_execution.rs:3406-:3416, unreachable while `result` is Err: {logs}"
        );
    }

    // AUD4 — one nested failure, one terminal. With the public `inspect`
    // wrapper restored at `:3372`, the READBACK operation alone emits a second
    // `kernel.terminal_error` and both of these counts go red.
    for operation in [readback_operation, registry_gap_operation] {
        let terminals: Vec<&str> = {
            let event = "event=\"kernel.terminal_error\"";
            let operation = format!("operation=\"{operation}\"");
            logs.lines()
                .filter(|line| line.contains(event) && line.contains(&operation))
                .collect()
        };
        assert_eq!(
            terminals.len(),
            1,
            "the close of {operation} owns exactly one terminal; the nested public `inspect` wrapper assigns a second one for the same propagated error: {logs}"
        );
        assert_eq!(
            quoted(terminals[0], "code"),
            crate::process_execution::process_terminal_code(&ProcessExecutionError::NotFound),
            "the single terminal carries the projection of the error this close actually returned: {logs}"
        );
    }
    assert_eq!(
        event_count(&logs, "kernel.terminal_error"),
        2,
        "the capture holds one terminal per failed close and no extra terminal for either identity: {logs}"
    );

    // The observation and the terminal of one close share the identity the call
    // entered with, read off the rendered span slots, and the two closes are
    // distinguishable without relying on line order.
    let observation_line = |operation: &str| -> String {
        event_line_with(
            &logs,
            "kernel.process.descendant_close_failed",
            &format!("operation=\"{operation}\""),
        )
        .to_owned()
    };
    let terminal_line = |operation: &str| -> String {
        event_line_with(
            &logs,
            "kernel.terminal_error",
            &format!("operation=\"{operation}\""),
        )
        .to_owned()
    };
    let terminal_identity = |operation: &str| -> String {
        let line = terminal_line(operation);
        span_field(&line, "operation")
            .unwrap_or_else(|| {
                panic!("the terminal of {operation} carries no operation slot: {line}")
            })
            .to_owned()
    };
    for operation in [readback_operation, registry_gap_operation] {
        let observation = observation_line(operation);
        assert_eq!(
            recorded_on(&observation, "operation"),
            operation,
            "the failure observation binds the exact operation the call entered with: {logs}"
        );
        assert_eq!(
            terminal_identity(operation),
            recorded_on(&observation, "operation"),
            "the terminal and its observation share ONE operation identity for {operation}, so the single terminal cannot belong to the other close: {logs}"
        );
        assert_eq!(
            recorded_on(&observation, "generation"),
            owner.generation().get().to_string(),
            "the close of {operation} runs under the RETAINED owner's generation, which the no-record aggregate arms (:3464-3478) cannot report: {logs}"
        );
    }
    assert_ne!(
        terminal_identity(readback_operation),
        terminal_identity(registry_gap_operation),
        "the two closes are distinguishable by identity rather than by line order: {logs}"
    );

    // The readback failure retained its registration: proof that this arm
    // cleared the registry read at `:3368` and failed at the readback instead,
    // and that a failed close releases nothing.
    assert_eq!(
        registered_operation_ids(&fixture.gateway),
        vec![readback_operation.to_owned()],
        "the readback failure retains its registration: {logs}"
    );
    drop(fixture);
    drop(runtime);
}
