#![allow(clippy::expect_used, clippy::unwrap_used)]

//! Kernel process-execution and supervision diagnostics (F-LOG-KERNEL-3, issue #901).
//!
//! Every case drives a real production callsite through an existing public
//! seam and asserts against the bytes that run actually emitted. The five
//! owned modules stay read-only here: this suite adds no production
//! behaviour, no inline test inside them, and no expected-log vector in
//! place of executing a callsite.

use std::collections::BTreeMap;
use std::io::Write;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use eliot_contracts::{ArtifactId, ContractId, EpochId, EpochLineageId, ResourceGeneration};
use eliot_ipc::{PeerIdentity, Session};
use eliot_kernel::kernel_diagnostics::{
    KERNEL_DIAGNOSTICS_TARGET, MAX_DIAGNOSTIC_FIELD_BYTES, bound_field,
};
use eliot_kernel::{KernelComposition, KernelConfig};
use eliot_kernel_core::{
    AuthoritySnapshotBinding, DispatchSnapshotCodec, KernelAuthorityReplaySnapshot, KernelError,
    KernelResult, ProcessDispatchAuthorityController, SealedAuthoritySnapshot,
};
use eliot_kernel_service::{
    ProcessExecutionClient, ProcessExecutionRejection, ProcessExecutionRequest,
    ProcessExecutionResponse,
};
use eliot_ors::{
    EpochIdentity, EpochLineage, OpaqueLabel, OperationIdentity, ProcessStartReplayRecord,
    ProcessStartReplayState, RecoveryPayload, RedbRecoveryStore, StateFenceSnapshot,
};
use eliot_platform::SecretReference;
use eliot_process::{
    ActionLeaseRef, DispatchAuthorityId, EnvironmentInheritance, EnvironmentProjection,
    FencingToken, Generation, ImageId, JobId, KernelDispatchKey, OperationId, PermitIssuance,
    ProcessExecutionAdmissionRequest, ProcessIntent, ProcessOwnerBinding, ProcessSessionBinding,
    ProcessTreeId, ResourceLimits, SecretRef, SessionId,
};
use eliot_runtime_contracts::{HealthVector, ModuleGeneration, ModuleGenerationState};
use serde_json::Value;
use sha2::{Digest, Sha256};

/// The exact five source files this leaf owns, in the fixture's spelling.
const OWNED_FILES: [&str; 5] = [
    "bins/eliot-kernel/src/process_execution.rs",
    "bins/eliot-kernel/src/daemon_process_launch.rs",
    "bins/eliot-kernel/src/daemon_live_receipt.rs",
    "bins/eliot-kernel/src/daemon_supervision.rs",
    "bins/eliot-kernel/src/supervision_lease_authority.rs",
];

/// The crate-relative owned paths this suite reads for case 30's diff.
const OWNED_PATHS: [&str; 5] = [
    "src/process_execution.rs",
    "src/daemon_process_launch.rs",
    "src/daemon_live_receipt.rs",
    "src/daemon_supervision.rs",
    "src/supervision_lease_authority.rs",
];

/// Vocabulary no owned module may gain: a second subscriber owner, a new
/// public observation surface, or a facade installer.
const FORBIDDEN_IN_OWNED: [&str; 5] = [
    "try_init",
    "set_global_default",
    "install_kernel_diagnostics",
    "pub fn observe_",
    "tracing::subscriber::set_global",
];

/// Event families the five owned modules alone emit; neither the crate root
/// nor the shared facade may learn them.
const OWNED_EVENT_FAMILIES: [&str; 4] = [
    "kernel.process.",
    "kernel.live_receipt.",
    "kernel.daemon.launch",
    "kernel.supervision.commit_",
];

/// Slot defaults declared by the shared operation span.
const SPAN_SLOT_DEFAULTS: [&str; 8] = [
    "process_tree = \"unavailable\"",
    "process_id = \"unavailable\"",
    "process_start_100ns = \"unavailable\"",
    "image_sha256 = \"unavailable\"",
    "lease = \"unavailable\"",
    "lease_operation = \"unavailable\"",
    "receipt = \"unavailable\"",
    "request_id = \"unavailable\"",
];

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

/// A sink whose every `write` fails, as a dropped/full target would.
///
/// `offered` records what production handed the writer *before* the `Err` is
/// returned, so a failing arm can still be observed; nothing is ever delivered
/// through this sink. The failure is not a flag: `write` unconditionally
/// returns `Err`, and the `tracing-subscriber` fmt layer ignores writer errors
/// because `log_internal_errors` is off by default
/// (tracing-subscriber-0.3.23 `src/fmt/fmt_layer.rs:1049-1055`), which is
/// exactly the failed/dropped-sink condition under test.
#[derive(Clone, Default)]
struct FailingSink {
    offered: Arc<Mutex<Vec<u8>>>,
    attempts: Arc<AtomicU64>,
}

impl Write for FailingSink {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.offered
            .lock()
            .map_err(|_| std::io::Error::other("failing sink lock poisoned"))?
            .extend_from_slice(buf);
        self.attempts.fetch_add(1, Ordering::SeqCst);
        Err(std::io::Error::other("capture sink write failed"))
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Err(std::io::Error::other("capture sink flush failed"))
    }
}

fn fixture() -> Value {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/data/kernel_process_supervision_diagnostics.json");
    let bytes = std::fs::read(&path).expect("process/supervision fixture must be readable");
    serde_json::from_slice(&bytes).expect("process/supervision fixture must be valid JSON")
}

/// Thread-local capture: `with_default` never installs a process-global
/// subscriber, so these tests stay parallel-safe with every sibling suite.
fn capture_with<F, R>(f: F) -> (String, R)
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
        tracing::subscriber::with_default(subscriber, f)
    };
    let bytes = sink.bytes.lock().expect("capture lock").clone();
    (String::from_utf8_lossy(&bytes).into_owned(), result)
}

/// Thread-local capture through a sink whose every write fails: returns the
/// bytes production offered the writer, the driven result, and the number of
/// real (failed) write attempts.
fn capture_with_failing_sink<F, R>(f: F) -> (String, R, u64)
where
    F: FnOnce() -> R,
{
    let sink = FailingSink::default();
    let writer_sink = sink.clone();
    let result = {
        let subscriber = tracing_subscriber::fmt()
            .with_ansi(false)
            .with_writer(move || writer_sink.clone())
            .finish();
        tracing::subscriber::with_default(subscriber, f)
    };
    let offered = sink.offered.lock().expect("offered lock").clone();
    let attempts = sink.attempts.load(Ordering::SeqCst);
    (
        String::from_utf8_lossy(&offered).into_owned(),
        result,
        attempts,
    )
}

struct TempGuard {
    root: PathBuf,
}

impl Drop for TempGuard {
    fn drop(&mut self) {
        // The composition must already be released when this runs, or Windows
        // refuses `remove_dir_all` on the still-open redb file and `let _ =`
        // swallows the failure, leaking one `eliot-901-*` root per run. Both
        // carriers in this file order the drop that way on purpose:
        // `process_authority_kernel` returns the guard FIRST, so a test's
        // `let (_guard, kernel) = ...` drops `kernel` before `_guard`; and
        // `SupervisionFixture` declares `kernel` before `_guard`, so struct
        // field drop order releases the composition first too.
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

static ROOT_COUNTER: AtomicU64 = AtomicU64::new(0);

fn unique_root(suffix: &str) -> PathBuf {
    let n = ROOT_COUNTER.fetch_add(1, Ordering::SeqCst);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(u128::from(n), |d| d.as_nanos());
    let unique = format!("{suffix}-{n}-{nanos}-{}", std::process::id());
    let root = std::env::temp_dir().join(format!("eliot-901-{unique}"));
    std::fs::create_dir_all(&root).expect("test work root");
    root
}

// ---------------------------------------------------------------------------
// Captured-byte readers
// ---------------------------------------------------------------------------

fn captured_line<'a>(logs: &'a str, needle: &str) -> &'a str {
    logs.lines()
        .find(|line| line.contains(needle))
        .unwrap_or_else(|| panic!("no captured line carries {needle}; captured: {logs}"))
}

fn quoted_value<'a>(line: &'a str, key: &str) -> &'a str {
    let prefix = format!("{key}=\"");
    let start = line
        .find(&prefix)
        .unwrap_or_else(|| panic!("field {key} absent from captured line: {line}"))
        + prefix.len();
    let rest = &line[start..];
    let end = rest
        .find('"')
        .unwrap_or_else(|| panic!("unterminated field {key} in captured line: {line}"));
    &rest[..end]
}

/// Reads one slot of the `kernel.operation` span the given event is printed
/// under, returning the RECORDED value where the owner recorded one.
///
/// Two properties of the real renderer force this shape, both read from
/// tracing-subscriber 0.3.23 rather than assumed:
///
/// * `fmt::format::Format::format_event` writes exactly one opening brace
///   around the whole `FormattedFields` run
///   (`src/fmt/format/mod.rs:997`), and `FormattedFields` renders as a single
///   space-separated `key=value` sequence. A needle of `{slot="` therefore
///   only ever matches the FIRST declared field (`request_id`), and every
///   other slot would panic as absent.
/// * `FmtLayer::on_record` appends through `add_fields`
///   (`src/fmt/fmt_layer.rs`, `src/fmt/format/mod.rs:244-253`), which pushes a
///   space and formats; it never rewrites the declared slot. A recorded slot
///   therefore appears AFTER its declared default, so the last occurrence on
///   the line is the recorded value and the first is the declared default.
///
/// A slot the owner never recorded occurs exactly once and resolves to its
/// declared `"unavailable"` default, which is the honest answer for it. The
/// `*_redaction` twins cannot false-match, because the needle requires `="`
/// immediately after the slot name.
fn span_field(logs: &str, event: &str, slot: &str) -> String {
    let line = captured_line(logs, &format!("event=\"{event}\""));
    let key = format!("{slot}=\"");
    let last = line
        .rfind(&key)
        .unwrap_or_else(|| panic!("span slot {slot} absent from captured line: {line}"));
    let rest = &line[last + key.len()..];
    let end = rest
        .find('"')
        .unwrap_or_else(|| panic!("unterminated span slot {slot} in captured line: {line}"));
    rest[..end].to_owned()
}

fn event_outcome(logs: &str, event: &str) -> String {
    quoted_value(
        captured_line(logs, &format!("event=\"{event}\"")),
        "outcome",
    )
    .to_owned()
}

fn event_count(logs: &str, event: &str) -> usize {
    logs.matches(&format!("event=\"{event}\"")).count()
}

fn terminal_codes(logs: &str) -> Vec<String> {
    logs.lines()
        .filter(|line| line.contains("event=\"kernel.terminal_error\""))
        .map(|line| quoted_value(line, "code").to_owned())
        .collect()
}

fn byte_offset(logs: &str, needle: &str) -> usize {
    logs.find(needle)
        .unwrap_or_else(|| panic!("{needle} absent from captured run: {logs}"))
}

// ---------------------------------------------------------------------------
// Fixture accessors: every read is a hard expectation, so the fixture cannot
// drift away from this suite silently.
// ---------------------------------------------------------------------------

fn fixture_event(key: &str) -> String {
    fixture()["events"][key]
        .as_str()
        .unwrap_or_else(|| panic!("fixture must name events.{key}"))
        .to_owned()
}

fn fixture_canary(key: &str) -> String {
    fixture()["canaries"][key]
        .as_str()
        .unwrap_or_else(|| panic!("fixture must name canaries.{key}"))
        .to_owned()
}

fn fixture_terminal_codes() -> Vec<String> {
    fixture()["terminal_codes"]["process"]
        .as_array()
        .expect("fixture must pin terminal_codes.process")
        .iter()
        .map(|value| value.as_str().expect("terminal code string").to_owned())
        .collect()
}

// ---------------------------------------------------------------------------
// Authenticated session fixtures
// ---------------------------------------------------------------------------

const MODULE_ID: &str = "eliot-901-module";
const PEER_SID: &str = "S-1-5-21-1000";
const PEER_SESSION: &str = "4";
const CONNECTION_ID: &str = "conn-901-process";

fn test_epoch(sequence: u64) -> EpochId {
    EpochId::new(
        EpochLineageId::new("550e8400-e29b-41d4-a716-446655440000").expect("lineage"),
        std::num::NonZeroU64::new(sequence).expect("sequence"),
    )
    .expect("epoch")
}

fn test_generation() -> Generation {
    Generation::new(1).expect("generation")
}

fn authenticated_peer() -> PeerIdentity {
    let binding = eliot_ipc::ProcessBinding::from_observation(4242, 99_001, r"C:\Eliot\bridge.exe")
        .expect("fake process binding");
    PeerIdentity::authenticated_for_test(binding, PEER_SID.to_owned(), PEER_SESSION.to_owned())
        .expect("fake authenticated peer")
}

fn process_session() -> Session {
    let resource_gen = ResourceGeneration::new(1).expect("resource generation");
    let fence = eliot_contracts::StateFence::new(test_epoch(1), resource_gen);
    Session {
        connection_id: CONNECTION_ID.to_owned(),
        protocol_version: eliot_protocol::ProtocolVersion::CURRENT,
        peer: authenticated_peer(),
        authority_epoch: test_epoch(1),
        module_generation: ModuleGeneration {
            module_id: ContractId::new(MODULE_ID).expect("module id"),
            generation: resource_gen,
            artifact_id: ArtifactId::new("a".repeat(64)).expect("artifact id"),
            state: ModuleGenerationState::Starting,
            health: HealthVector::healthy(),
            state_fence: fence,
        },
        launch_nonce: "eliot-901-launch-nonce".to_owned(),
        capabilities: vec![],
        privacy_classes: vec!["PUBLIC".to_owned()],
        effects: vec![],
        session_epoch: 1,
        state: eliot_ipc::SessionState::Open,
    }
}

fn session_binding() -> ProcessSessionBinding {
    ProcessSessionBinding::new(CONNECTION_ID, 1).expect("process session binding")
}

/// Fixture-only reproduction of the crate-internal stable owner digest
/// (`src/runtime_identity.rs:176`) so a durable replay record can be seeded
/// with the exact owner this authenticated session derives. No observation
/// behaviour, no event name and no terminal code is reproduced here.
fn session_owner(session: &Session) -> ProcessOwnerBinding {
    let PeerIdentity::Authenticated { user_identity, .. } = &session.peer else {
        panic!("process fixture requires an authenticated peer");
    };
    let generation = test_generation();
    let mut principal = Sha256::new();
    principal.update(user_identity.as_str().as_bytes());
    principal.update(session.module_generation.module_id.as_str().as_bytes());
    principal.update(session.authority_epoch.lineage_id.as_str().as_bytes());
    principal.update(session.authority_epoch.sequence.get().to_le_bytes());
    principal.update(generation.get().to_le_bytes());
    ProcessOwnerBinding::new(
        session.module_generation.module_id.as_str(),
        format!("{:x}", Sha256::digest(principal.finalize())),
        session.authority_epoch.clone(),
        generation,
    )
    .expect("derived process owner")
}

// ---------------------------------------------------------------------------
// Admission fixtures
// ---------------------------------------------------------------------------

struct IntentShape {
    operation_id: String,
    process_tree_id: String,
    executable: String,
    executable_sha256: String,
    argv: Vec<String>,
    working_directory: String,
    environment: BTreeMap<String, String>,
    secret_refs: Vec<SecretRef>,
}

fn default_shape(operation_id: &str) -> IntentShape {
    IntentShape {
        operation_id: operation_id.to_owned(),
        process_tree_id: format!("{operation_id}-tree"),
        executable: r"C:\Eliot\worker.exe".to_owned(),
        executable_sha256: "c".repeat(64),
        argv: vec!["--serve".to_owned()],
        working_directory: r"C:\Eliot".to_owned(),
        environment: BTreeMap::from([("ELIOT_MODE".to_owned(), "kernel".to_owned())]),
        secret_refs: Vec::new(),
    }
}

fn shape_intent(shape: &IntentShape) -> ProcessIntent {
    ProcessIntent::new(
        OperationId::new(shape.operation_id.clone()).expect("operation id"),
        ProcessTreeId::new(shape.process_tree_id.clone()).expect("process tree id"),
        JobId::new(format!("{}-job", shape.operation_id)).expect("job id"),
        ImageId::new(format!("{}-image", shape.operation_id)).expect("image id"),
        SessionId::new(format!("{}-session", shape.operation_id)).expect("session id"),
        test_generation(),
        shape.executable.clone(),
        shape.executable_sha256.clone(),
        shape.argv.clone(),
        shape.working_directory.clone(),
        EnvironmentProjection::new(
            shape.environment.clone(),
            shape.secret_refs.clone(),
            EnvironmentInheritance::None,
        )
        .expect("environment projection"),
        ResourceLimits::new(10_000, Some(5_000), Some(1_048_576), 4096, 4096, 4)
            .expect("resource limits"),
    )
    .expect("process intent")
}

fn shape_admission(shape: &IntentShape) -> ProcessExecutionAdmissionRequest {
    ProcessExecutionAdmissionRequest::new(
        MODULE_ID,
        shape_intent(shape),
        ActionLeaseRef::new(format!("{}-lease", shape.operation_id)).expect("action lease"),
        FencingToken::new(
            test_epoch(1),
            test_generation(),
            format!("{}-fence", shape.operation_id),
        )
        .expect("fencing token"),
        4_102_444_800_000,
    )
    .expect("process execution admission")
}

/// Seed intent used only to persist the process-authority replay snapshot the
/// public `new_with_process_authority` constructor restores from.
fn authority_seed_intent() -> ProcessIntent {
    ProcessIntent::new(
        OperationId::new("eliot-901-authority-seed-operation").expect("operation id"),
        ProcessTreeId::new("eliot-901-authority-seed-tree").expect("tree"),
        JobId::new("eliot-901-authority-seed-job").expect("job"),
        ImageId::new("eliot-901-authority-seed-image").expect("image"),
        SessionId::new("eliot-901-authority-seed-session").expect("session"),
        test_generation(),
        r"C:\Eliot\seed-worker.exe",
        "d".repeat(64),
        vec!["--seed".to_owned()],
        r"C:\Eliot",
        EnvironmentProjection::new(BTreeMap::new(), Vec::new(), EnvironmentInheritance::None)
            .expect("environment"),
        ResourceLimits::new(10_000, Some(5_000), Some(1_048_576), 4096, 4096, 4)
            .expect("resource limits"),
    )
    .expect("authority seed intent")
}

// ---------------------------------------------------------------------------
// Public composition construction
// ---------------------------------------------------------------------------

/// Opaque, secret-free test codec standing in for the production DPAPI
/// authority snapshot codec. It exists only so the public
/// `new_with_process_authority` constructor has a codec to restore through;
/// it grants no authority and is not production behaviour.
struct FixtureAuthorityCodec;

impl DispatchSnapshotCodec for FixtureAuthorityCodec {
    fn seal(
        &self,
        snapshot: &KernelAuthorityReplaySnapshot,
        _binding: &AuthoritySnapshotBinding,
    ) -> KernelResult<SealedAuthoritySnapshot> {
        let ciphertext = serde_json::to_vec(snapshot)
            .map_err(|e| KernelError::DependencyUnavailable(e.to_string()))?;
        let key = SecretReference::new("fixture-provider", "eliot-901-authority")
            .map_err(|e| KernelError::DependencyUnavailable(e.to_string()))?;
        SealedAuthoritySnapshot::new(key, ciphertext)
    }

    fn open(
        &self,
        payload: &RecoveryPayload,
        _binding: &AuthoritySnapshotBinding,
    ) -> KernelResult<KernelAuthorityReplaySnapshot> {
        let RecoveryPayload::Encrypted { ciphertext, .. } = payload else {
            return Err(KernelError::RecoveryUnavailable(
                "901 authority fixture payload is not encrypted".to_owned(),
            ));
        };
        serde_json::from_slice(ciphertext)
            .map_err(|e| KernelError::RecoveryUnavailable(e.to_string()))
    }
}

fn authority_binding(authority_id: &DispatchAuthorityId) -> AuthoritySnapshotBinding {
    let epoch = EpochLineage {
        current: EpochIdentity {
            lineage_id: OpaqueLabel::new("eliot-901-lineage").expect("lineage"),
            epoch: 1,
        },
        predecessor: None,
    };
    let state_fence =
        StateFenceSnapshot::capture(&serde_json::json!({"authority": "eliot-901"}), 1)
            .expect("state fence snapshot");
    AuthoritySnapshotBinding::new(
        authority_id.clone(),
        OperationIdentity::new("eliot-901-authority-record").expect("record id"),
        epoch,
        state_fence,
        1,
        None,
    )
    .expect("authority snapshot binding")
}

fn ors_path(root: &std::path::Path) -> PathBuf {
    root.join(".eliot").join("kernel-ors.redb")
}

fn open_ors(root: &std::path::Path) -> RedbRecoveryStore {
    let path = ors_path(root);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).expect("ors parent");
    }
    RedbRecoveryStore::open(&path).expect("real ORS store")
}

/// Persists one durable process-start replay record through the same public
/// ORS seam the gateway's own replay store reads.
fn seed_replay_record(store: &RedbRecoveryStore, operation_id: &str, owner: ProcessOwnerBinding) {
    let record = ProcessStartReplayRecord {
        operation_id: OperationIdentity::new(operation_id).expect("replay operation identity"),
        admission_digest: "a".repeat(64),
        owner,
        state: ProcessStartReplayState::Reserved,
        receipt: None,
    };
    store
        .begin_process_start(&record)
        .expect("seed durable process-start replay record");
}

/// Builds one process-authority composition, seeding the durable replay
/// records the named operations will later be read back under.
///
/// The guard is returned FIRST on purpose: it is bound first and therefore
/// dropped last, after the `Arc<KernelComposition>` has released its open
/// redb file.
fn process_authority_kernel(
    suffix: &str,
    seeds: &[(&str, ProcessOwnerBinding)],
) -> (TempGuard, Arc<KernelComposition>) {
    let root = unique_root(suffix);
    let authority_id =
        DispatchAuthorityId::new("eliot-901-kernel-authority").expect("authority id");
    let binding = authority_binding(&authority_id);
    let codec: Arc<dyn DispatchSnapshotCodec> = Arc::new(FixtureAuthorityCodec);
    let key = KernelDispatchKey::from_secret_bytes([0x4a; 32]).expect("dispatch key");

    {
        let store = Arc::new(open_ors(&root));
        let store_port: Arc<dyn eliot_ors::OperationalRecoveryStore> = store.clone();
        let mut controller = ProcessDispatchAuthorityController::activate(
            authority_id.clone(),
            KernelDispatchKey::from_secret_bytes([0x4a; 32]).expect("seed dispatch key"),
            store_port,
            Arc::clone(&codec),
        );
        let seed_fence =
            FencingToken::new(test_epoch(1), test_generation(), "eliot-901-seed-fence")
                .expect("seed fence");
        controller
            .issue(
                &authority_seed_intent(),
                PermitIssuance::new(
                    ActionLeaseRef::new("eliot-901-seed-lease").expect("seed lease"),
                    seed_fence,
                    BTreeMap::from([("authority".to_owned(), "a".repeat(64))]),
                    1,
                    2,
                    "eliot-901-seed-nonce",
                )
                .expect("seed issuance"),
                &binding,
            )
            .expect("seed the authority replay snapshot");
        drop(controller);
        for (operation_id, owner) in seeds {
            seed_replay_record(store.as_ref(), operation_id, owner.clone());
        }
    }

    let mut config = KernelConfig::new(&root);
    config.pipe_name = format!(r"\\.\pipe\eliot\kernel-901-{suffix}-{}", std::process::id());
    let kernel = KernelComposition::new_with_process_authority(
        config,
        eliot_kernel::ProcessExecutionAuthorityConfig {
            authority_id,
            key,
            snapshot_binding: binding,
            snapshot_codec: codec,
        },
    )
    .expect("process-authority composition");
    assert!(kernel.process_execution_configured());
    (TempGuard { root }, Arc::new(kernel))
}

// ---------------------------------------------------------------------------
// Callsite drivers
// ---------------------------------------------------------------------------

fn current_thread_runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("tokio runtime")
}

fn drive_request<'a>(
    kernel: &'a KernelComposition,
    session: &'a Session,
    binding: &'a ProcessSessionBinding,
    request: ProcessExecutionRequest,
) -> (String, ProcessExecutionResponse) {
    let rt = current_thread_runtime();
    capture_with(move || {
        rt.block_on(kernel.execute_process_request(session, binding.clone(), request))
    })
}

fn drive_client_start(
    kernel: &Arc<KernelComposition>,
    session: &Session,
    binding: &ProcessSessionBinding,
    admission: ProcessExecutionAdmissionRequest,
) -> (String, ProcessExecutionResponse) {
    let rt = current_thread_runtime();
    capture_with(move || {
        let client = eliot_kernel::process_execution_client(kernel, session, binding)
            .expect("front-door process-execution client");
        rt.block_on(client.execute(ProcessExecutionRequest::Start(admission)))
    })
}

fn operation_request(operation_id: &str) -> ProcessExecutionRequest {
    let id = OperationId::new(operation_id).expect("operation id");
    ProcessExecutionRequest::Cancel { operation_id: id }
}

fn inspect_request(operation_id: &str) -> ProcessExecutionRequest {
    let id = OperationId::new(operation_id).expect("operation id");
    ProcessExecutionRequest::Inspect { operation_id: id }
}

fn reconcile_request(operation_id: &str) -> ProcessExecutionRequest {
    let id = OperationId::new(operation_id).expect("operation id");
    ProcessExecutionRequest::Reconcile { operation_id: id }
}

fn rejection_code(response: &ProcessExecutionResponse) -> String {
    let ProcessExecutionResponse::Rejected(rejection) = response else {
        panic!("expected a typed rejection, got {response:?}");
    };
    rejection.code.clone()
}

fn rejection_detail(response: &ProcessExecutionResponse) -> String {
    let ProcessExecutionResponse::Rejected(rejection) = response else {
        panic!("expected a typed rejection, got {response:?}");
    };
    rejection.detail.clone()
}

// WORK_UNIT_CASE: 901/1
#[test]
fn process_supervision_denominator_is_exact() {
    let f = fixture();
    assert_eq!(f["issue"].as_u64(), Some(901), "fixture pins this issue");
    let files = f["files"].as_array().expect("fixture files array");
    assert_eq!(files.len(), 5, "exactly five owned source files");
    for expected in OWNED_FILES {
        assert!(
            files.iter().any(|v| v.as_str() == Some(expected)),
            "fixture must list {expected}"
        );
    }
    let boundaries = f["boundaries"].as_array().expect("fixture boundaries");
    assert!(!boundaries.is_empty(), "boundary table is non-empty");
    for boundary in boundaries {
        let file = boundary["file"]
            .as_str()
            .expect("boundary file is a string");
        assert!(
            files.iter().any(|v| v.as_str() == Some(file)),
            "boundary file {file} is inside the denominator"
        );
        assert!(
            boundary["covering_case"]
                .as_u64()
                .is_some_and(|case| (1..=30).contains(&case)),
            "every boundary names a case in 1..30"
        );
    }
    assert_eq!(
        f["test_file"].as_str(),
        Some("bins/eliot-kernel/tests/kernel_process_supervision_diagnostics.rs"),
        "the fixture names this suite"
    );
    assert_eq!(
        f["target"].as_str(),
        Some(KERNEL_DIAGNOSTICS_TARGET),
        "fixture targets the shared facade"
    );
    assert_eq!(
        f["terminal_event"].as_str(),
        Some("kernel.terminal_error"),
        "fixture pins the one terminal event"
    );

    let facade = std::fs::read_to_string(
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src/kernel_diagnostics.rs"),
    )
    .expect("shared facade source");
    for slot in SPAN_SLOT_DEFAULTS {
        assert!(facade.contains(slot), "facade declares {slot}");
    }
    assert_eq!(
        f["max_field_bytes"].as_u64(),
        Some(u64::try_from(MAX_DIAGNOSTIC_FIELD_BYTES).expect("field bound")),
        "fixture pins the shared field bound"
    );

    let (_guard, kernel) = process_authority_kernel("case01", &[]);
    let session = process_session();
    let binding = session_binding();
    let (logs, response) = drive_request(
        &kernel,
        &session,
        &binding,
        operation_request("op-901-case01-unknown"),
    );
    assert!(
        logs.contains(KERNEL_DIAGNOSTICS_TARGET),
        "a real callsite ran under the facade target: {logs}"
    );
    assert_eq!(rejection_code(&response), "NOT_FOUND");
}

// WORK_UNIT_CASE: 901/2
#[test]
fn admitted_owner_and_rejected_owner_are_distinct_sites() {
    let session = process_session();
    let binding = session_binding();
    let owner = session_owner(&session);
    let foreign = ProcessOwnerBinding::new(
        MODULE_ID,
        "b".repeat(64),
        session.authority_epoch.clone(),
        test_generation(),
    )
    .expect("foreign principal owner");
    let (_guard, kernel) = process_authority_kernel(
        "case02",
        &[
            ("op-901-case02-admitted", owner),
            ("op-901-case02-rejected", foreign),
        ],
    );

    let (admitted_logs, admitted) = drive_request(
        &kernel,
        &session,
        &binding,
        inspect_request("op-901-case02-admitted"),
    );
    assert!(
        matches!(admitted, ProcessExecutionResponse::Rejected(_)),
        "the admitted owner's inspect still returns a typed result: {admitted:?}"
    );
    assert!(
        admitted_logs.contains(&format!(
            "event=\"{}\"",
            fixture_event("process.request_received")
        )),
        "admitted run observed the request: {admitted_logs}"
    );
    assert!(
        admitted_logs.contains(&format!(
            "event=\"{}\"",
            fixture_event("process.request_admitted")
        )),
        "admitted run passed the process-authority gate: {admitted_logs}"
    );
    assert!(
        admitted_logs.contains(&format!(
            "event=\"{}\"",
            fixture_event("process.owner_admitted")
        )),
        "admitted run recorded the authorized owner: {admitted_logs}"
    );
    assert!(
        !admitted_logs.contains(&format!(
            "event=\"{}\"",
            fixture_event("process.owner_rejected")
        )),
        "the admitted owner was never rejected: {admitted_logs}"
    );
    assert_eq!(
        terminal_codes(&admitted_logs).len(),
        1,
        "one terminal for the one failed underlying operation: {admitted_logs}"
    );

    let (rejected_logs, rejected) = drive_request(
        &kernel,
        &session,
        &binding,
        inspect_request("op-901-case02-rejected"),
    );
    assert!(
        rejection_code(&rejected) == "CONTRACT_REJECTED",
        "a foreign principal is refused with the contract code: {:?}",
        rejection_code(&rejected)
    );
    let owner_rejected = fixture_event("process.owner_rejected");
    assert_eq!(
        event_outcome(&rejected_logs, &owner_rejected),
        "fenced",
        "the foreign owner is fenced: {rejected_logs}"
    );
    assert_eq!(
        terminal_codes(&rejected_logs).len(),
        1,
        "the subordinate owner site still emits no terminal of its own: {rejected_logs}"
    );
    assert!(
        byte_offset(&rejected_logs, &format!("event=\"{owner_rejected}\""))
            < byte_offset(&rejected_logs, "event=\"kernel.terminal_error\""),
        "the single terminal is emitted after the subordinate rejection, not at it: {rejected_logs}"
    );
}

// WORK_UNIT_CASE: 901/3
#[test]
fn operation_tree_and_lease_bind_the_validated_admission() {
    let (_guard, kernel) = process_authority_kernel("case03", &[]);
    let session = process_session();
    let binding = session_binding();
    let shape = default_shape("op-901-case03");
    let admission = shape_admission(&shape);
    let (logs, response) = drive_client_start(&kernel, &session, &binding, admission);

    let rejection = fixture_event("process.request_rejected");
    let operation = span_field(&logs, &rejection, "operation");
    let process_tree = span_field(&logs, &rejection, "process_tree");
    let lease = span_field(&logs, &rejection, "lease");
    let generation = span_field(&logs, &rejection, "generation");
    assert_eq!(
        operation, shape.operation_id,
        "operation is the admitted one: {logs}"
    );
    assert_ne!(
        operation, "unavailable",
        "an absent identity stays unavailable"
    );
    assert_eq!(
        process_tree, shape.process_tree_id,
        "process tree is the admitted one: {logs}"
    );
    assert_ne!(
        process_tree, "unavailable",
        "an absent tree stays unavailable"
    );
    assert_eq!(
        lease,
        format!("{}-lease", shape.operation_id),
        "lease is the admitted one: {logs}"
    );
    assert_ne!(lease, "unavailable", "an absent lease stays unavailable");
    assert_eq!(
        generation,
        test_generation().get().to_string(),
        "generation is the admitted one: {logs}"
    );
    assert_eq!(
        rejection_code(&response),
        ProcessExecutionRejection::WATCHDOG_COVERAGE_UNAVAILABLE,
        "the start was refused before any launch attempt"
    );
}

// WORK_UNIT_CASE: 901/4
#[test]
fn pre_launch_refusal_stays_not_attempted() {
    let (_guard, kernel) = process_authority_kernel("case04", &[]);
    let session = process_session();
    let binding = session_binding();
    let admission = shape_admission(&default_shape("op-901-case04"));
    let (logs, response) = drive_client_start(&kernel, &session, &binding, admission);

    let request_rejected = fixture_event("process.request_rejected");
    assert_eq!(
        event_count(&logs, &request_rejected),
        1,
        "exactly one pre-launch refusal: {logs}"
    );
    assert_eq!(
        event_outcome(&logs, &request_rejected),
        "watchdog_coverage",
        "the pre-launch admission refusal is the observed outcome: {logs}"
    );
    let codes = terminal_codes(&logs);
    assert_eq!(
        codes,
        vec![ProcessExecutionRejection::WATCHDOG_COVERAGE_UNAVAILABLE.to_owned()],
        "exactly one typed terminal: {logs}"
    );
    for never in [
        "process.start_requested",
        "process.start_registration",
        "process.start_handoff",
        "process.start_committed",
    ] {
        let event = fixture_event(never);
        assert!(
            !logs.contains(&format!("event=\"{event}\"")),
            "{event} must never run after the refusal: {logs}"
        );
    }
    let launch = fixture_event("daemon.launch_requested");
    assert!(
        !logs.contains(&launch),
        "no daemon launch was requested either: {logs}"
    );
    assert_eq!(
        rejection_code(&response),
        ProcessExecutionRejection::WATCHDOG_COVERAGE_UNAVAILABLE,
        "the typed refusal is projected unchanged"
    );
}

// WORK_UNIT_CASE: 901/7
#[test]
fn possible_effect_outcome_stays_unknown_under_its_operation() {
    let session = process_session();
    let binding = session_binding();
    let owner = session_owner(&session);
    let (_guard, kernel) = process_authority_kernel("case07", &[("op-901-case07", owner)]);
    let (logs, response) = drive_request(
        &kernel,
        &session,
        &binding,
        operation_request("op-901-case07"),
    );

    let cancel_failed = fixture_event("process.cancel_failed");
    assert!(
        logs.contains(&format!("event=\"{cancel_failed}\"")),
        "the unproven effect was observed: {logs}"
    );
    assert_eq!(
        event_outcome(&logs, &cancel_failed),
        "unknown",
        "a possible effect never reports a decided outcome: {logs}"
    );
    let codes = terminal_codes(&logs);
    assert_eq!(codes.len(), 1, "exactly one terminal: {logs}");
    assert_eq!(
        codes[0], "process_unknown_outcome",
        "static unknown code: {logs}"
    );
    assert_eq!(
        span_field(&logs, &cancel_failed, "operation"),
        "op-901-case07",
        "the original operation identity is retained: {logs}"
    );
    assert_eq!(rejection_code(&response), "UNKNOWN_OUTCOME");
}

// WORK_UNIT_CASE: 901/11
#[test]
fn stale_generation_owner_stays_fenced_and_current_generation_is_admitted() {
    let session = process_session();
    let binding = session_binding();
    let current = session_owner(&session);
    // F-LOG-KERNEL-3 (#901 T11). The durable record is seeded with the SAME
    // principal, module and authority epoch this authenticated session derives,
    // and only the GENERATION differs. `ProcessOwnerBinding` derives `PartialEq`
    // over {module_id, principal_digest, authority_epoch, generation}
    // (crates/kernel/eliot-process/src/lib.rs:675-682) and
    // `authorize_process_owner_in_context` compares that whole binding
    // (process_execution.rs:4520), so generation is genuinely part of the
    // compared authorization tuple. The two-arm pair below is what discriminates:
    // a mutation that ignored the generation would let the stale arm go
    // green-admitted and turn the first assertion red.
    let stale = ProcessOwnerBinding::new(
        current.module_id(),
        current.principal_digest(),
        current.authority_epoch().clone(),
        Generation::new(7).expect("stale generation"),
    )
    .expect("same-principal stale-generation owner");
    // Premise guard on the fixture itself, not production evidence: the two
    // durable owners must differ in exactly the generation.
    assert_eq!(
        stale.module_id(),
        current.module_id(),
        "module is not varied"
    );
    assert_eq!(
        stale.principal_digest(),
        current.principal_digest(),
        "principal is not varied"
    );
    assert_eq!(
        stale.authority_epoch(),
        current.authority_epoch(),
        "authority epoch is not varied"
    );
    assert_ne!(
        stale.generation(),
        current.generation(),
        "generation is the only varied leg of the authorization binding"
    );

    let (_guard, kernel) = process_authority_kernel(
        "case11",
        &[
            ("op-901-case11-stale-generation", stale),
            ("op-901-case11-current-generation", current),
        ],
    );
    let owner_rejected = fixture_event("process.owner_rejected");
    let owner_admitted = fixture_event("process.owner_admitted");

    let (stale_logs, stale_response) = drive_request(
        &kernel,
        &session,
        &binding,
        inspect_request("op-901-case11-stale-generation"),
    );
    assert_eq!(
        event_outcome(&stale_logs, &owner_rejected),
        "fenced",
        "the same principal under a stale generation is fenced, never admitted: {stale_logs}"
    );
    assert!(
        !stale_logs.contains(&format!("event=\"{owner_admitted}\"")),
        "no stale owner is ever admitted: {stale_logs}"
    );
    assert_eq!(
        terminal_codes(&stale_logs).len(),
        1,
        "exactly one terminal, owned by the gateway boundary: {stale_logs}"
    );
    assert!(
        byte_offset(&stale_logs, &format!("event=\"{owner_rejected}\""))
            < byte_offset(&stale_logs, "event=\"kernel.terminal_error\""),
        "the subordinate owner site emits no terminal: {stale_logs}"
    );
    assert_eq!(rejection_code(&stale_response), "CONTRACT_REJECTED");

    let (current_logs, _) = drive_request(
        &kernel,
        &session,
        &binding,
        inspect_request("op-901-case11-current-generation"),
    );
    assert_eq!(
        event_outcome(&current_logs, &owner_admitted),
        "success",
        "the identical principal under its own generation IS admitted: {current_logs}"
    );
    assert!(
        !current_logs.contains(&format!("event=\"{owner_rejected}\"")),
        "the generation, not the principal, is what the gate reads: {current_logs}"
    );
    assert_eq!(
        terminal_codes(&current_logs).len(),
        1,
        "the admitted arm still fails later in the operation, with its own single terminal: {current_logs}"
    );
    assert!(
        byte_offset(&current_logs, &format!("event=\"{owner_admitted}\""))
            < byte_offset(&current_logs, "event=\"kernel.terminal_error\""),
        "the admitted owner site is still subordinate to the one terminal: {current_logs}"
    );

    // Honest scope note: PID reuse itself has no representation in these five
    // modules. No `pid_reused` or `foreign` outcome literal exists anywhere in
    // them, and `process_id`/`process_start_100ns` are recorded only from a
    // validated start receipt (process_execution.rs:187-204), never reopened by
    // number. So case 11 is proven in its generation/identity half only; the
    // PID-reuse half is unreachable from these public seams.
}

// WORK_UNIT_CASE: 901/18
#[test]
fn cancellation_request_differs_from_acknowledgement() {
    let (_guard, kernel) = process_authority_kernel("case18", &[]);
    let session = process_session();
    let binding = session_binding();
    let (logs, response) = drive_request(
        &kernel,
        &session,
        &binding,
        operation_request("op-901-case18-unknown"),
    );

    let requested = fixture_event("process.cancel_requested");
    let acknowledged = fixture_event("process.cancel_acknowledged");
    assert!(
        logs.contains(&format!("event=\"{requested}\"")),
        "the cancellation request is observed: {logs}"
    );
    assert_ne!(
        requested, acknowledged,
        "request and acknowledgement differ"
    );
    assert!(
        !logs.contains(&format!("event=\"{acknowledged}\"")),
        "a request is never an acknowledgement: {logs}"
    );
    assert_eq!(
        terminal_codes(&logs).len(),
        1,
        "the refused acknowledgement carries exactly one terminal: {logs}"
    );
    assert!(
        byte_offset(&logs, &format!("event=\"{requested}\""))
            < byte_offset(&logs, "event=\"kernel.terminal_error\""),
        "the request precedes the refusal of the acknowledgement: {logs}"
    );
    assert_eq!(rejection_code(&response), "NOT_FOUND");
}

// WORK_UNIT_CASE: 901/20
#[test]
fn unknown_reconcile_outcome_emits_exactly_one_terminal() {
    let session = process_session();
    let binding = session_binding();
    let owner = session_owner(&session);
    let (_guard, kernel) = process_authority_kernel("case20", &[("op-901-case20", owner)]);
    let (logs, response) = drive_request(
        &kernel,
        &session,
        &binding,
        reconcile_request("op-901-case20"),
    );

    let requested = fixture_event("process.reconcile_requested");
    let unknown = fixture_event("process.reconcile_unknown");
    assert!(
        logs.contains(&format!("event=\"{requested}\"")),
        "the exit/evidence boundary was entered: {logs}"
    );
    assert!(
        logs.contains(&format!("event=\"{unknown}\"")),
        "the unprovable exit was observed: {logs}"
    );
    assert_eq!(
        event_outcome(&logs, &unknown),
        "unknown",
        "the outcome literal stays unknown: {logs}"
    );
    let codes = terminal_codes(&logs);
    assert_eq!(
        codes.len(),
        1,
        "exactly one terminal for one operation: {logs}"
    );
    assert!(
        codes
            .iter()
            .all(|code| fixture_terminal_codes().contains(code)),
        "the terminal code is a stable mapper projection: {codes:?}"
    );
    assert_eq!(
        span_field(&logs, &unknown, "operation"),
        "op-901-case20",
        "the original operation identity is retained: {logs}"
    );
    assert!(matches!(response, ProcessExecutionResponse::Rejected(_)));
}

// WORK_UNIT_CASE: 901/21
#[test]
fn exit_observation_never_claims_completed_work() {
    let session = process_session();
    let binding = session_binding();
    let owner = session_owner(&session);
    let (_guard, kernel) = process_authority_kernel(
        "case21",
        &[
            ("op-901-case21-inspect", owner.clone()),
            ("op-901-case21-reconcile", owner),
        ],
    );

    let (logs, response) = drive_request(
        &kernel,
        &session,
        &binding,
        inspect_request("op-901-case21-inspect"),
    );

    let requested = fixture_event("process.inspect_requested");
    let failed = fixture_event("process.inspect_failed");
    let reported = fixture_event("process.inspect_reported");
    assert!(
        logs.contains(&format!("event=\"{requested}\"")),
        "the exit observation boundary was entered: {logs}"
    );
    assert!(
        logs.contains(&format!("event=\"{failed}\"")),
        "the exit observation was read and stayed unproven: {logs}"
    );
    assert!(
        !logs.contains(&format!("event=\"{reported}\"")),
        "an exit observation never becomes a reported success: {logs}"
    );
    assert!(
        matches!(response, ProcessExecutionResponse::Rejected(_)),
        "an exit observation never becomes a status projection: {response:?}"
    );

    // The exit direction. `reconcile_in_context` (process_execution.rs:3517) is
    // the projection that owns an exit observation: it requests, and an exit the
    // owner cannot prove takes the :3560 arm, `reconcile_unknown`/"unknown"
    // (:3561), never the `reconcile_reported`/"success" arm at :3557. Reaching
    // `reconcile_reported` would require the executor to hand back proven
    // evidence, which no fake-free path here can fabricate.
    let (exit_logs, exit_response) = drive_request(
        &kernel,
        &session,
        &binding,
        reconcile_request("op-901-case21-reconcile"),
    );
    let reconcile_requested = fixture_event("process.reconcile_requested");
    let reconcile_unknown = fixture_event("process.reconcile_unknown");
    let reconcile_reported = fixture_event("process.reconcile_reported");
    assert_eq!(
        event_count(&exit_logs, &reconcile_requested),
        1,
        "the exit/evidence boundary was entered exactly once: {exit_logs}"
    );
    assert_eq!(
        event_count(&exit_logs, &reconcile_unknown),
        1,
        "the unprovable exit is observed as unknown exactly once: {exit_logs}"
    );
    assert_eq!(
        event_outcome(&exit_logs, &reconcile_unknown),
        "unknown",
        "exit zero never promotes an exit observation to a decided outcome: {exit_logs}"
    );
    assert_eq!(
        event_count(&exit_logs, &reconcile_reported),
        0,
        "an unprovable exit is never reported as decided evidence: {exit_logs}"
    );
    assert_eq!(
        terminal_codes(&exit_logs).len(),
        1,
        "the unprovable exit still carries exactly one designated terminal: {exit_logs}"
    );
    assert!(
        matches!(exit_response, ProcessExecutionResponse::Rejected(_)),
        "an unprovable exit never becomes an evidence projection: {exit_response:?}"
    );
    // No exit status and no completion-shaped field is ever formatted on this
    // path. This is a negative vocabulary guard, not the primary discrimination
    // above: it turns red the moment the projection grows an `exit_code`,
    // `exit_status`, `completion` or `completed` field, none of which the five
    // owned modules emit today.
    for forbidden in ["exit_code", "exit_status", "completion", "completed"] {
        assert!(
            !exit_logs.contains(forbidden),
            "no {forbidden} field may be formatted by the exit projection: {exit_logs}"
        );
    }
}

// WORK_UNIT_CASE: 901/25
#[test]
fn one_designated_terminal_per_failed_operation() {
    let session = process_session();
    let binding = session_binding();
    let owner = session_owner(&session);
    // ONE operation, seeded so the owner gate passes and the failure happens
    // downstream, observed by THREE owners that all see the same failure:
    // `execute_process_request` (request boundary, :4603),
    // `inspect_in_context` (the gateway boundary that OWNS the terminal, :3037)
    // and `inspect_inner` (the subordinate exit observation, :3073). That is
    // the propagation case: several correlated subordinate observations, one
    // designated terminal. Two independent operations would prove nothing
    // about propagation, so there is only one here.
    let (_guard, kernel) = process_authority_kernel("case25", &[("op-901-case25-inspect", owner)]);
    let (logs, response) = drive_request(
        &kernel,
        &session,
        &binding,
        inspect_request("op-901-case25-inspect"),
    );

    let inspect_requested = fixture_event("process.inspect_requested");
    let inspect_failed = fixture_event("process.inspect_failed");
    let request_failed = fixture_event("process.request_failed");
    assert_eq!(
        event_count(&logs, &inspect_requested),
        1,
        "the subordinate exit observation ran exactly once: {logs}"
    );
    assert_eq!(
        event_count(&logs, &inspect_failed),
        1,
        "the failure is observed by the subordinate owner exactly once: {logs}"
    );
    assert_eq!(
        event_count(&logs, &request_failed),
        1,
        "the same failure is projected by the outer request owner exactly once: {logs}"
    );
    assert_eq!(
        terminal_codes(&logs).len(),
        1,
        "three owners of one failed operation, exactly one designated terminal: {logs}"
    );
    assert_eq!(
        span_field(&logs, &inspect_failed, "operation"),
        "op-901-case25-inspect",
        "the subordinate owner is correlated to the same underlying operation: {logs}"
    );
    assert_eq!(
        span_field(&logs, &request_failed, "operation"),
        "op-901-case25-inspect",
        "the propagated refusal carries the same underlying operation: {logs}"
    );
    assert!(
        byte_offset(&logs, &format!("event=\"{inspect_failed}\""))
            < byte_offset(&logs, "event=\"kernel.terminal_error\""),
        "the owning gateway boundary emits the terminal right after the failure it owns: {logs}"
    );
    assert!(
        byte_offset(&logs, "event=\"kernel.terminal_error\"")
            < byte_offset(&logs, &format!("event=\"{request_failed}\"")),
        "the outer request owner projects the failure after the terminal and adds none of its own: {logs}"
    );
    assert_eq!(rejection_code(&response), "NOT_FOUND");
}

// WORK_UNIT_CASE: 901/26
#[test]
fn terminal_code_is_a_static_projection_not_error_prose() {
    let (_guard, kernel) = process_authority_kernel("case26", &[]);
    let session = process_session();
    let binding = session_binding();
    let (logs, response) = drive_request(
        &kernel,
        &session,
        &binding,
        operation_request("op-901-case26"),
    );

    let codes = terminal_codes(&logs);
    assert_eq!(codes.len(), 1, "exactly one terminal: {logs}");
    let code = codes[0].clone();
    assert!(
        fixture_terminal_codes().contains(&code),
        "the code is a pinned mapper projection, got {code}"
    );
    let detail = rejection_detail(&response);
    assert!(
        !detail.is_empty(),
        "the caller still receives its typed detail"
    );
    assert_ne!(code, detail, "the code is never the error's rendered prose");
    assert!(
        !logs.contains(&detail),
        "no rendered error prose reaches the captured bytes: {logs}"
    );
}

// WORK_UNIT_CASE: 901/27
// HONEST LIMIT, stated here rather than left for a reader to assume away: on
// this path no production line ever dereferences the payload. The start is
// refused by `admit_material_process_start` (`src/lib.rs:3308`), which reads
// only `admission.state_fence()` plus the Kernel's own service and activation
// state, and the composition path returns at `process_execution.rs:4708` before
// `retain_process_path_proof` (`:4756`) - the only reader of `executable` and
// `working_directory` - can run. So these loops prove the REFUSAL BOUNDARY
// DOES NOT LEAK the payload, which is the property issue-901-body.md:45 asks
// for ("Redact before formatting ... Fixed-field tests include nested and
// oversized canaries"). They are reddened by ADDING a leak on this path, not
// by deleting a callsite, and they do not prove reader-side redaction on a path
// that does read the payload. No canary can travel into a record as payload
// either: every span field is fed from a typed identity through
// `record_process_context_field`, never from free text.
//
// The captured-byte loop below is therefore not the only leak channel this case
// checks. The other one is the returned `ProcessExecutionRejection.detail`,
// which production builds from the typed error at `process_execution.rs:4591`
// (`error.to_string()`), so it is inspected for every canary too. And the
// redaction owner itself is driven directly through
// `eliot_kernel::kernel_diagnostics::bound_field`, the single emission boundary
// every one of these five modules reaches (`kernel_diagnostics.rs:347-349`),
// which is what puts the oversized/nested screening under test rather than only
// the refusal path.
#[test]
fn command_argument_environment_path_credential_canaries_are_absent() {
    let mut shape = default_shape("op-901-case27");
    let command = fixture_canary("command");
    let argument = fixture_canary("argument");
    let environment = fixture_canary("environment");
    let working_path = fixture_canary("working_path");
    let data_path = fixture_canary("data_path");
    let credential = fixture_canary("credential");
    let token = fixture_canary("token");
    let nested = fixture_canary("nested");
    let oversized = fixture_canary("oversized");
    assert!(
        oversized.len() > MAX_DIAGNOSTIC_FIELD_BYTES,
        "the oversized canary exceeds the shared field bound"
    );
    shape.executable = format!(r"C:\Eliot\{command}.exe");
    shape.argv = vec![
        format!("--flag={argument}"),
        format!("--nested={nested}"),
        oversized.clone(),
    ];
    shape.working_directory = format!(r"C:\Eliot\{working_path}");
    shape.environment.insert(
        "ELIOT_901_ENV".to_owned(),
        format!("{environment}/{data_path}"),
    );
    shape
        .environment
        .insert("ELIOT_901_NESTED".to_owned(), nested.clone());
    shape.secret_refs = vec![
        SecretRef::new("eliot-901", credential.clone()).expect("opaque secret reference"),
        SecretRef::new("eliot-901", token.clone()).expect("opaque secret reference"),
    ];

    let (_guard, kernel) = process_authority_kernel("case27", &[]);
    let session = process_session();
    let binding = session_binding();
    let (logs, response) = drive_client_start(&kernel, &session, &binding, shape_admission(&shape));

    assert_eq!(
        rejection_code(&response),
        ProcessExecutionRejection::WATCHDOG_COVERAGE_UNAVAILABLE,
        "the canary admission still ran the real refusal"
    );
    for canary in [
        &command,
        &argument,
        &environment,
        &working_path,
        &data_path,
        &credential,
        &token,
        &nested,
        &oversized,
    ] {
        assert!(
            !logs.contains(canary.as_str()),
            "canary {canary} must never reach the captured bytes: {logs}"
        );
        assert!(
            !rejection_detail(&response).contains(canary.as_str()),
            "canary {canary} must never reach the returned rejection detail, which production renders from the typed error: {}",
            rejection_detail(&response)
        );
    }

    // The redaction owner itself, driven through its public API. Honest
    // disposition for this input, read off the code rather than guessed:
    // `bounded_value` (kernel_diagnostics.rs:453-500) screens FIRST through
    // `requires_evidence_handle`, whose length threshold is 256 CHARACTERS
    // (field_policy.rs:299-301); this canary is 320 characters, so it is
    // replaced whole by an immutable evidence handle and `truncated` stays
    // `false`. Asserting `truncated() == true` here would be asserting a lie:
    // a prefix of an over-long value is exactly what the policy forbids.
    let bounded = bound_field(&oversized);
    assert!(
        bounded.text().len() <= MAX_DIAGNOSTIC_FIELD_BYTES,
        "the emitted value stays inside the shared field bound, got {} bytes",
        bounded.text().len()
    );
    assert_eq!(
        bounded.original_bytes(),
        oversized.len(),
        "the boundary records the length of the input it refused to emit"
    );
    assert!(
        !bounded.truncated(),
        "a screened value is replaced whole, never truncated to a prefix"
    );
    assert_eq!(
        bounded.redaction_status(),
        Some("redacted:content"),
        "an over-long value is screened as content before bounding, not silently truncated"
    );
    assert_eq!(
        bounded.evidence_handle(),
        Some(bounded.text()),
        "the emitted value IS the immutable evidence handle"
    );
    for fragment in ["CANARY_OVERSIZED_901", "oversized-field-filler", "CANARY"] {
        assert!(
            !bounded.text().contains(fragment),
            "no fragment {fragment} of the screened input survives: {}",
            bounded.text()
        );
    }
    assert_ne!(
        bounded.text(),
        oversized,
        "the emitted value is never the input itself"
    );
}

// WORK_UNIT_CASE: 901/28
// The same honest limit as case 27 applies to this canary sweep: the refusal
// path never reads argv, environment or secret_refs, so these loops prove the
// boundary does not leak them rather than proving reader-side redaction. The
// returned rejection detail (built by production from the typed error at
// `process_execution.rs:4591`) is the second channel and is checked for every
// canary too; the oversized value's screening disposition itself is pinned in
// case 27 through the public `bound_field` boundary.
#[test]
fn stream_provider_model_user_canaries_stay_unavailable_not_guessed() {
    let mut shape = default_shape("op-901-case28");
    let stream = fixture_canary("stream");
    let provider = fixture_canary("provider");
    let model = fixture_canary("model");
    let user = fixture_canary("user");
    let lease_signature = fixture_canary("lease_signature");
    let process_memory = fixture_canary("process_memory");
    let error_debug = fixture_canary("error_debug");
    let nested = fixture_canary("nested");
    let oversized = fixture_canary("oversized");
    shape.argv = vec![
        format!("--stdout={stream}"),
        format!("--stderr={oversized}"),
        format!("--memory={process_memory}"),
        format!("--lease={lease_signature}"),
        format!("--error={error_debug}"),
        format!("--nested={nested}"),
    ];
    shape
        .environment
        .insert("ELIOT_901_USER".to_owned(), user.clone());
    shape.secret_refs = vec![
        SecretRef::new("eliot-901", provider.clone()).expect("opaque secret reference"),
        SecretRef::new("eliot-901", model.clone()).expect("opaque secret reference"),
    ];

    let (_guard, kernel) = process_authority_kernel("case28", &[]);
    let session = process_session();
    let binding = session_binding();
    let (logs, response) = drive_client_start(&kernel, &session, &binding, shape_admission(&shape));

    assert_eq!(
        rejection_code(&response),
        ProcessExecutionRejection::WATCHDOG_COVERAGE_UNAVAILABLE,
        "the canary admission still ran the real refusal"
    );
    let detail = rejection_detail(&response);
    for canary in [
        &stream,
        &provider,
        &model,
        &user,
        &lease_signature,
        &process_memory,
        &error_debug,
        &nested,
        &oversized,
    ] {
        assert!(
            !logs.contains(canary.as_str()),
            "payload canary {canary} must never reach the captured bytes: {logs}"
        );
        assert!(
            !detail.contains(canary.as_str()),
            "payload canary {canary} must never reach the returned rejection detail, which production renders from the typed error: {detail}"
        );
    }
    // The span is fed only from typed identities. No start receipt identity was
    // recorded here, so those slots stay exactly "unavailable" and are never
    // guessed from the payload material.
    let rejection = fixture_event("process.request_rejected");
    for slot in ["process_id", "process_start_100ns", "image_sha256"] {
        assert_eq!(
            span_field(&logs, &rejection, slot),
            "unavailable",
            "{slot} stays unavailable without a validated receipt: {logs}"
        );
    }
}

// WORK_UNIT_CASE: 901/29
#[test]
fn sink_presence_leaves_results_unchanged() {
    let (_guard, kernel) = process_authority_kernel("case29", &[]);
    let session = process_session();
    let binding = session_binding();
    let (logs, enabled) = drive_request(
        &kernel,
        &session,
        &binding,
        operation_request("op-901-case29"),
    );
    let rt = current_thread_runtime();
    let disabled = rt.block_on(kernel.execute_process_request(
        &session,
        session_binding(),
        operation_request("op-901-case29"),
    ));

    assert_eq!(
        format!("{enabled:?}"),
        format!("{disabled:?}"),
        "a capture subscriber leaves the exact result unchanged"
    );
    assert!(
        matches!(enabled, ProcessExecutionResponse::Rejected(_))
            && matches!(disabled, ProcessExecutionResponse::Rejected(_)),
        "both arms return the same typed refusal"
    );
    assert!(
        logs.contains(KERNEL_DIAGNOSTICS_TARGET),
        "the enabled arm really had a live sink: {logs}"
    );
    assert!(
        logs.contains(&format!(
            "event=\"{}\"",
            fixture_event("process.request_received")
        )),
        "the enabled arm really executed the callsite: {logs}"
    );
    assert_eq!(
        terminal_codes(&logs).len(),
        1,
        "the sink did not add or remove a terminal: {logs}"
    );

    // The FAILED sink arm. issue-901-body.md:43 requires that a
    // "Failed/disabled/dropped sink leaves calls, results, primary and cleanup
    // errors, receipts, deadlines and ordering unchanged". The comparison above
    // covers `disabled`; this covers `failed`. The sink's `write` returns `Err`
    // unconditionally while still counting what production offered it.
    let (offered, failing, refused_writes) = capture_with_failing_sink(|| {
        current_thread_runtime().block_on(kernel.execute_process_request(
            &session,
            session_binding(),
            operation_request("op-901-case29"),
        ))
    });
    assert!(
        refused_writes > 0,
        "the failing sink really was written to, so this arm is not vacuous"
    );
    assert_eq!(
        format!("{failing:?}"),
        format!("{enabled:?}"),
        "a FAILED sink leaves the exact result unchanged; {refused_writes} writes were refused"
    );
    assert!(
        matches!(failing, ProcessExecutionResponse::Rejected(_)),
        "the failed-sink arm still returns the same typed refusal"
    );
    // The one terminal is emitted whether the sink delivers it or refuses it:
    // `offered` is what production handed the writer, so the emission itself is
    // still observable through a sink that accepted none of it.
    assert_eq!(
        offered
            .matches(&format!(
                "event=\"{}\"",
                fixture_event("process.request_received")
            ))
            .count(),
        1,
        "the failed-sink arm really executed the callsite: {offered}"
    );
    assert_eq!(
        terminal_codes(&offered),
        terminal_codes(&logs),
        "a failed sink emits the identical single terminal; it neither adds, drops nor reorders one"
    );
}

// WORK_UNIT_CASE: 901/30
#[test]
fn captured_causal_order_and_diagnostic_only_diff() {
    let (_guard, kernel) = process_authority_kernel("case30", &[]);
    let session = process_session();
    let binding = session_binding();
    let (logs, response) = drive_request(
        &kernel,
        &session,
        &binding,
        operation_request("op-901-case30"),
    );

    let received = format!("event=\"{}\"", fixture_event("process.request_received"));
    let admitted = format!("event=\"{}\"", fixture_event("process.request_admitted"));
    let requested = format!("event=\"{}\"", fixture_event("process.cancel_requested"));
    let terminal = "event=\"kernel.terminal_error\"".to_owned();
    assert!(byte_offset(&logs, &received) < byte_offset(&logs, &admitted));
    assert!(byte_offset(&logs, &admitted) < byte_offset(&logs, &requested));
    assert!(byte_offset(&logs, &requested) < byte_offset(&logs, &terminal));
    assert_eq!(rejection_code(&response), "NOT_FOUND");

    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    for owned in OWNED_PATHS {
        let src = std::fs::read_to_string(manifest_dir.join(owned))
            .unwrap_or_else(|_| panic!("owned module {owned} must be readable"));
        for needle in FORBIDDEN_IN_OWNED {
            assert!(!src.contains(needle), "{owned} must not contain {needle}");
        }
    }
    // F-LOG-KERNEL-3 (#901 T30): the guard against a new PUBLIC observation
    // surface is `pub fn observe_` (not `fn observe_`: the five owned modules
    // legitimately carry `process_execution.rs:73 observe_process_in_context`,
    // which is `pub(crate)`), and it is already asserted per file above because
    // `pub fn observe_` is one of the `FORBIDDEN_IN_OWNED` needles. A separate
    // zero-count over the concatenated sources would be implied by that
    // assertion, so it is deliberately absent rather than duplicated.

    for unowned in ["src/lib.rs", "src/kernel_diagnostics.rs"] {
        let src = std::fs::read_to_string(manifest_dir.join(unowned))
            .unwrap_or_else(|_| panic!("{unowned} must be readable"));
        for family in OWNED_EVENT_FAMILIES {
            assert!(
                !src.contains(family),
                "{unowned} must not gain the owned vocabulary {family}"
            );
        }
        for mapper in [
            "process_terminal_code",
            "live_receipt_terminal_code",
            "daemon_launch_terminal_code",
            "supervision_authority_terminal_code",
        ] {
            assert!(
                !src.contains(mapper),
                "{unowned} must not gain the owned mapper {mapper}"
            );
        }
    }

    let cargo_toml =
        std::fs::read_to_string(manifest_dir.join("Cargo.toml")).expect("manifest readable");
    for family in OWNED_EVENT_FAMILIES {
        assert!(
            !cargo_toml.contains(family),
            "the manifest must not gain the owned vocabulary {family}"
        );
    }
    for forbidden in [
        "[dependencies.kernel]",
        "serial_test",
        "kernel_process_supervision",
    ] {
        assert!(
            !cargo_toml.contains(forbidden),
            "the manifest must not gain {forbidden}"
        );
    }
}

// ---------------------------------------------------------------------------
// Supervision-lease authority fixtures
//
// Cases 15 and 16 drive `KernelSupervisionLeaseAuthority` through its existing
// public seam. The composition only carries an authority when the configuration
// supplies one, so the fixture provisions the installer-owned disposable
// `PortableDev` signing key with the same public key provider the production
// installer uses and hands the resulting `SupervisionLeaseAuthorityConfig` to
// `KernelConfig`. No production code, `pub`, or helper is added here.
// ---------------------------------------------------------------------------

#[cfg(windows)]
use eliot_contracts::{AuthorityEpoch, StateFence};
#[cfg(windows)]
use eliot_installation::InstallationProfile;
#[cfg(windows)]
use eliot_kernel::{KernelSupervisionLeaseAuthority, SupervisionLeaseAuthorityConfig};
#[cfg(windows)]
use eliot_ors::{
    SupervisionLeaseBinding, SupervisionLeaseOperation, SupervisionLeasePrepareRequest,
    SupervisionLeaseProjection, SupervisionLeaseSnapshot, SupervisionLeaseStageReceipt,
};
#[cfg(windows)]
use eliot_platform_windows::{
    PortableDevSupervisionAuthorityKeyRequest, PortableDevSupervisionAuthorityKeyWriteOutcome,
    UserOwnedRootLease, WindowsPortableDevSupervisionAuthorityKeyProvider,
};
#[cfg(windows)]
use eliot_runtime_contracts::{
    LeaseState, ProvisionedSupervisionAuthority, RegisteredActivityWakePolicy,
    SupervisionAuthorityKeyReference, SupervisionGenerationBinding,
    SupervisionLeaseTerminalDisposition, SupervisionObservationScope,
};

/// Installation identity pinned into both the provisioned trust anchor and the
/// observation scope of every lease this fixture stages.
#[cfg(windows)]
const SUPERVISION_INSTALLATION_ID: &str = "eliot-901-installation";
#[cfg(windows)]
const SUPERVISION_SCOPE_ID: &str = "eliot-901-supervision-scope";
#[cfg(windows)]
const SUPERVISION_CANDIDATE_GENERATION: &str = "eliot-901-candidate-generation";
#[cfg(windows)]
const SUPERVISION_SIGNER_ID: &str = "eliot-901-kernel-signer";
#[cfg(windows)]
const SUPERVISION_KEY_ID: &str = "eliot-901-supervision-key";
#[cfg(windows)]
const SUPERVISION_KEY_RELATIVE_PATH: &str =
    ".eliot-dev/state/supervision/eliot-901-supervision-authority.key";

/// One composition that really carries a `KernelSupervisionLeaseAuthority`,
/// plus the non-secret contour values a lease binding must reproduce.
#[cfg(windows)]
struct SupervisionFixture {
    kernel: Arc<KernelComposition>,
    _guard: TempGuard,
    observation_scope: SupervisionObservationScope,
    wake_policy: RegisteredActivityWakePolicy,
    fence: StateFence,
    now_ms: u64,
}

#[cfg(windows)]
fn unix_now_ms() -> u64 {
    u64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system clock after the unix epoch")
            .as_millis(),
    )
    .expect("unix millisecond timestamp fits an unsigned 64-bit counter")
}

#[cfg(windows)]
fn supervision_generation() -> ResourceGeneration {
    ResourceGeneration::new(1).expect("supervision resource generation")
}

/// Provisions the disposable repository-local signing key and builds one
/// composition whose `supervision_lease_authority` accessor is therefore live.
#[cfg(windows)]
fn supervision_fixture(suffix: &str) -> SupervisionFixture {
    let root = unique_root(suffix);
    // The disposable provider keeps its seed below the exact repository-local
    // contour, so both contour ancestors must already exist before a key is
    // prepared.
    let contour = root.join(".eliot-dev").join("state");
    std::fs::create_dir_all(&contour).expect("portable-dev state contour");
    let repository_identity = UserOwnedRootLease::open_existing(&root)
        .expect("portable-dev repository root lease")
        .identity();

    let provider = WindowsPortableDevSupervisionAuthorityKeyProvider::new();
    let prepared = provider
        .prepare(PortableDevSupervisionAuthorityKeyRequest {
            transaction_id: format!("eliot-901-{suffix}-transaction"),
            effect_id: format!("eliot-901-{suffix}-effect"),
            installation_id: SUPERVISION_INSTALLATION_ID.to_owned(),
            candidate_generation: SUPERVISION_CANDIDATE_GENERATION.to_owned(),
            authority_generation: supervision_generation(),
            supervision_lease_scope_id: SUPERVISION_SCOPE_ID.to_owned(),
            signer_id: SUPERVISION_SIGNER_ID.to_owned(),
            key_id: SUPERVISION_KEY_ID.to_owned(),
            repository_root: root.clone(),
            repository_root_identity: repository_identity,
            relative_path: SUPERVISION_KEY_RELATIVE_PATH.to_owned(),
        })
        .expect("prepared portable-dev supervision authority key");
    let trust_anchor = prepared.receipt().trust_anchor.clone();
    let written = provider
        .write_prepared(prepared)
        .expect("written portable-dev supervision authority key");
    assert!(
        matches!(
            &written,
            PortableDevSupervisionAuthorityKeyWriteOutcome::Created { .. }
        ),
        "the disposable repository-local key must be created, got {written:?}"
    );

    let authority = ProvisionedSupervisionAuthority::new(
        SUPERVISION_SCOPE_ID,
        SUPERVISION_CANDIDATE_GENERATION,
        supervision_generation(),
        SupervisionAuthorityKeyReference::portable_dev(SUPERVISION_KEY_RELATIVE_PATH)
            .expect("portable-dev supervision key reference"),
        trust_anchor,
    )
    .expect("provisioned supervision authority");
    // The canonical observation scope and wake policy are read back from the
    // provisioned receipt itself, so a lease binding can never invent them.
    let observation_scope = authority.observation_scope.clone();
    let wake_policy = authority.wake_policy.clone();

    let mut config = KernelConfig::new(&root);
    config.pipe_name = format!(
        r"\\.\pipe\eliot\kernel-901-supervision-{suffix}-{}",
        std::process::id()
    );
    let config = config
        .with_supervision_installation_profile(
            InstallationProfile::PortableDev,
            Some((root.clone(), repository_identity)),
        )
        .with_supervision_lease_authority(SupervisionLeaseAuthorityConfig { authority });
    let kernel = KernelComposition::new(config).expect("supervision-authority composition");
    assert!(
        kernel.supervision_lease_authority().is_some(),
        "the composition really carries the supervision lease authority"
    );

    SupervisionFixture {
        kernel: Arc::new(kernel),
        _guard: TempGuard { root },
        observation_scope,
        wake_policy,
        fence: StateFence::new(test_epoch(1), supervision_generation()),
        now_ms: unix_now_ms(),
    }
}

/// One `ACTIVE` binding over the fixture's exact lineage. `expires_at_ms` is the
/// only field a renewal is allowed to move.
#[cfg(windows)]
fn active_lease_binding(
    fixture: &SupervisionFixture,
    expires_at_ms: u64,
) -> SupervisionLeaseBinding {
    let issued_at_ms = fixture.now_ms - 60_000;
    SupervisionLeaseBinding {
        scope_ref: OpaqueLabel::new(SUPERVISION_SCOPE_ID).expect("lease scope label"),
        observation_scope: fixture.observation_scope.clone(),
        installation_id: OpaqueLabel::new(SUPERVISION_INSTALLATION_ID)
            .expect("installation identity label"),
        host_epoch: AuthorityEpoch::new(11).expect("host authority epoch"),
        activation_id: OpaqueLabel::new("eliot-901-activation").expect("activation label"),
        activation_generation: supervision_generation(),
        kernel_epoch: test_epoch(1),
        kernel_front_door_server_sid: PEER_SID.to_owned(),
        kernel_front_door_session_id: 4,
        kernel_front_door_artifact_sha256: "b".repeat(64),
        watchdog_epoch: AuthorityEpoch::new(12).expect("watchdog authority epoch"),
        generation_binding: SupervisionGenerationBinding {
            target_id: "a".repeat(64),
            module_id: MODULE_ID.to_owned(),
            process_id: "pid:4242:start:99001".to_owned(),
            target_generation: supervision_generation(),
            module_generation: supervision_generation(),
            process_generation: supervision_generation(),
        },
        state_fence: fixture.fence.clone(),
        issued_at_ms,
        expires_at_ms,
        renew_before_ms: issued_at_ms + (expires_at_ms - issued_at_ms) / 2,
        wake_policy: fixture.wake_policy.clone(),
        state: LeaseState::Active,
        terminal_disposition: None,
        revocation_reason: None,
        revocation_id: None,
        revocation_epoch: None,
    }
}

#[cfg(windows)]
fn lease_prepare_request(
    lease_id: &str,
    tag: &str,
    operation: SupervisionLeaseOperation,
    expected_revision: Option<u64>,
    binding: SupervisionLeaseBinding,
) -> SupervisionLeasePrepareRequest {
    SupervisionLeasePrepareRequest {
        ticket_id: OperationIdentity::new(format!("{tag}-ticket")).expect("ticket identity"),
        operation_id: OperationIdentity::new(format!("{tag}-operation"))
            .expect("lease operation identity"),
        lease_id: OperationIdentity::new(lease_id.to_owned()).expect("lease identity"),
        expected_revision,
        operation,
        binding,
    }
}

/// Clones the exact active head into its `REVOKED` successor shape. Only the
/// revocation fields move, so the lineage the predecessor proof requires is
/// preserved exactly.
#[cfg(windows)]
fn revocation_binding(head: &SupervisionLeaseSnapshot, reason: &str) -> SupervisionLeaseBinding {
    let mut binding = head.record.binding.clone();
    binding.state = LeaseState::Revoked;
    binding.terminal_disposition = Some(SupervisionLeaseTerminalDisposition::Revoked);
    binding.revocation_reason = Some(reason.to_owned());
    binding.revocation_id = Some("eliot-901-revocation-identity".to_owned());
    binding.revocation_epoch = Some(AuthorityEpoch::new(13).expect("revocation authority epoch"));
    binding
}

/// Stages one ticket and drives the public active-commit boundary, returning
/// the captured bytes and the committed revision.
#[cfg(windows)]
fn drive_commit_active(
    authority: &KernelSupervisionLeaseAuthority,
    lease_id: &str,
    tag: &str,
    operation: SupervisionLeaseOperation,
    expected_revision: Option<u64>,
    binding: SupervisionLeaseBinding,
) -> (String, SupervisionLeaseSnapshot) {
    let stage = authority
        .prepare(lease_prepare_request(
            lease_id,
            tag,
            operation,
            expected_revision,
            binding,
        ))
        .expect("staged supervision lease ticket");
    let (logs, committed) = capture_with(|| authority.commit_active(stage.ticket()));
    (
        logs,
        committed.expect("committed active supervision lease revision"),
    )
}

#[cfg(windows)]
fn stage_terminal_ticket(
    authority: &KernelSupervisionLeaseAuthority,
    lease_id: &str,
    tag: &str,
    operation: SupervisionLeaseOperation,
    expected_revision: Option<u64>,
    binding: SupervisionLeaseBinding,
) -> SupervisionLeaseStageReceipt {
    authority
        .prepare(lease_prepare_request(
            lease_id,
            tag,
            operation,
            expected_revision,
            binding,
        ))
        .expect("staged terminal supervision lease ticket")
}

/// Captured bytes and committed revision of each distinct phase of case 16.
#[cfg(windows)]
struct DistinctLeasePhases {
    acquired: SupervisionLeaseSnapshot,
    renewed: SupervisionLeaseSnapshot,
    renew_logs: String,
    revoked: SupervisionLeaseSnapshot,
    revoke_logs: String,
    expired: SupervisionLeaseSnapshot,
    expire_logs: String,
    conflict_logs: String,
    conflict_is_error: bool,
}

/// Drives renewal, revocation, expiry and one conflicting terminal commit over
/// four independent lease identities of one real supervision authority.
#[cfg(windows)]
fn drive_distinct_lease_phases(fixture: &SupervisionFixture) -> DistinctLeasePhases {
    let authority = fixture
        .kernel
        .supervision_lease_authority()
        .expect("composition carries the supervision lease authority");
    let first_expiry_ms = fixture.now_ms + 3_600_000;

    let (_acquire_logs, acquired) = drive_commit_active(
        authority,
        "eliot-901-case16-renew",
        "eliot-901-case16-renew-acquire",
        SupervisionLeaseOperation::Commit,
        None,
        active_lease_binding(fixture, first_expiry_ms),
    );
    let (renew_logs, renewed) = drive_commit_active(
        authority,
        "eliot-901-case16-renew",
        "eliot-901-case16-renew-renewal",
        SupervisionLeaseOperation::Renew,
        Some(acquired.record.revision),
        active_lease_binding(fixture, fixture.now_ms + 7_200_000),
    );

    let (_revoke_acquire_logs, revoke_head) = drive_commit_active(
        authority,
        "eliot-901-case16-revoke",
        "eliot-901-case16-revoke-acquire",
        SupervisionLeaseOperation::Commit,
        None,
        active_lease_binding(fixture, first_expiry_ms),
    );
    let revoke_stage = stage_terminal_ticket(
        authority,
        "eliot-901-case16-revoke",
        "eliot-901-case16-revoke-terminal",
        SupervisionLeaseOperation::Revoke,
        Some(revoke_head.record.revision),
        revocation_binding(&revoke_head, "eliot-901-case16-revocation"),
    );
    let (revoke_logs, revoked) = capture_with(|| authority.commit_terminal(revoke_stage.ticket()));
    let revoked = revoked.expect("committed revoked supervision lease revision");

    let (_expire_acquire_logs, expire_head) = drive_commit_active(
        authority,
        "eliot-901-case16-expire",
        "eliot-901-case16-expire-acquire",
        SupervisionLeaseOperation::Commit,
        None,
        active_lease_binding(fixture, first_expiry_ms),
    );
    let past_due_ms = expire_head.record.binding.expires_at_ms + 1;
    let (expire_logs, expired) = capture_with(|| {
        authority.expire_past_due_lease("eliot-901-case16-expire", &fixture.fence, past_due_ms)
    });
    let expired = expired
        .expect("past-due lease expiry read")
        .expect("a past-due active lease is expired");

    let conflict_stage = stage_terminal_ticket(
        authority,
        "eliot-901-case16-renew",
        "eliot-901-case16-conflict",
        SupervisionLeaseOperation::Revoke,
        Some(renewed.record.revision),
        revocation_binding(&renewed, "eliot-901-case16-conflict"),
    );
    let mut conflicting = conflict_stage.ticket().clone();
    conflicting.binding.revocation_reason = Some("eliot-901-case16-conflict-altered".to_owned());
    let (conflict_logs, conflict) = capture_with(|| authority.commit_terminal(&conflicting));

    DistinctLeasePhases {
        acquired,
        renewed,
        renew_logs,
        revoked,
        revoke_logs,
        expired,
        expire_logs,
        conflict_logs,
        conflict_is_error: conflict.is_err(),
    }
}

// WORK_UNIT_CASE: 901/15
#[cfg(windows)]
#[test]
fn lease_acquisition_is_not_yet_active_ownership() {
    let fixture = supervision_fixture("case15");
    let authority = fixture
        .kernel
        .supervision_lease_authority()
        .expect("composition carries the supervision lease authority");
    let lease_id = "eliot-901-case15-lease";

    let stage = authority
        .prepare(lease_prepare_request(
            lease_id,
            "eliot-901-case15-acquire",
            SupervisionLeaseOperation::Commit,
            None,
            active_lease_binding(&fixture, fixture.now_ms + 3_600_000),
        ))
        .expect("staged lease acquisition");
    assert_eq!(
        stage.projection,
        SupervisionLeaseProjection::Staged,
        "an acquired ticket is staged, never an active lease: {stage:?}"
    );
    let acquired_only = authority
        .current_snapshot(lease_id)
        .expect("durable lease head read");
    assert!(
        acquired_only.is_none(),
        "a staged acquisition is not active ownership yet"
    );

    let (logs, committed) = capture_with(|| authority.commit_active(stage.ticket()));
    let committed = committed.expect("committed active supervision lease revision");

    let requested = "kernel.supervision.commit_requested";
    let committed_event = "kernel.supervision.commit_committed";
    assert_eq!(event_count(&logs, requested), 1, "one acquisition: {logs}");
    assert_eq!(
        event_outcome(&logs, requested),
        "attempt",
        "acquisition is requested before it is ownership: {logs}"
    );
    assert_ne!(
        event_outcome(&logs, requested),
        event_outcome(&logs, committed_event),
        "a requested acquisition is never the committed outcome: {logs}"
    );
    assert_eq!(
        span_field(&logs, requested, "lease_operation"),
        "commit",
        "the acquisition phase is recorded on the shared operation span: {logs}"
    );
    assert_eq!(
        span_field(&logs, requested, "lease"),
        lease_id,
        "the acquisition keeps its exact lease identity: {logs}"
    );
    assert!(
        byte_offset(&logs, &format!("event=\"{requested}\""))
            < byte_offset(&logs, &format!("event=\"{committed_event}\"")),
        "the requested acquisition precedes the committed ownership: {logs}"
    );
    assert!(
        terminal_codes(&logs).is_empty(),
        "an acquisition that commits emits no terminal: {logs}"
    );

    assert_eq!(
        committed.record.state,
        LeaseState::Active,
        "committed ownership reaches the ACTIVE lease state: {logs}"
    );
    assert_eq!(
        format!("{}", committed.record.state),
        "ACTIVE",
        "the production state literal is the lifecycle vocabulary value: {logs}"
    );
    assert_eq!(
        committed.record.projection,
        SupervisionLeaseProjection::Active,
        "only a committed revision becomes the active projection: {logs}"
    );
    let owned = authority
        .current_snapshot(lease_id)
        .expect("durable lease head read after the commit")
        .expect("the committed revision is the durable head");
    assert_eq!(
        owned.record.state,
        LeaseState::Active,
        "the durable head is active only after the commit evidence: {logs}"
    );
}

// WORK_UNIT_CASE: 901/16
#[cfg(windows)]
#[test]
fn renewal_revocation_expiry_and_conflict_are_distinct_observations() {
    let fixture = supervision_fixture("case16");
    let phases = drive_distinct_lease_phases(&fixture);

    let renew_operation = assert_renewal_phase(&phases);
    let revoke_operation = assert_revocation_phase(&phases);
    let expire_operation = assert_expiry_phase(&phases);
    assert_conflict_phase(&phases);

    // Distinctness: the three committed phases are three different production
    // phase discriminators, and the conflict is a fourth observation with its
    // own refusal outcome and its own terminal code.
    assert_ne!(
        renew_operation,
        revoke_operation,
        "renewal and revocation stay distinct: {logs}",
        logs = phases.renew_logs
    );
    assert_ne!(
        revoke_operation,
        expire_operation,
        "revocation and expiry stay distinct: {logs}",
        logs = phases.revoke_logs
    );
    assert_ne!(
        renew_operation,
        expire_operation,
        "renewal and expiry stay distinct: {logs}",
        logs = phases.expire_logs
    );
    for logs in [&phases.renew_logs, &phases.revoke_logs, &phases.expire_logs] {
        assert!(
            !logs.contains("event=\"kernel.supervision.terminal_failed\""),
            "no committed phase emits the refusal event: {logs}"
        );
        assert!(
            terminal_codes(logs).is_empty(),
            "no committed phase emits a terminal: {logs}"
        );
    }
}

/// A renewal is a new revision and a new expiry over the same lineage; the
/// returned phase discriminator is what makes it distinct from the others.
#[cfg(windows)]
fn assert_renewal_phase(phases: &DistinctLeasePhases) -> String {
    let operation = span_field(
        &phases.renew_logs,
        "kernel.supervision.commit_requested",
        "lease_operation",
    );
    assert_eq!(
        operation,
        "renew",
        "the renewal phase discriminator is observed: {logs}",
        logs = phases.renew_logs
    );
    assert_eq!(
        event_outcome(&phases.renew_logs, "kernel.supervision.commit_committed"),
        "success",
        "the renewal commits: {logs}",
        logs = phases.renew_logs
    );
    assert_eq!(
        phases.renewed.record.state,
        LeaseState::Active,
        "a renewal stays ACTIVE: {logs}",
        logs = phases.renew_logs
    );
    assert_eq!(
        phases.renewed.record.revision,
        phases.acquired.record.revision + 1,
        "a renewal is a new revision: {logs}",
        logs = phases.renew_logs
    );
    assert_ne!(
        phases.renewed.record.binding.expires_at_ms,
        phases.acquired.record.binding.expires_at_ms,
        "a renewal carries a new expiry: {logs}",
        logs = phases.renew_logs
    );
    operation
}

/// A revocation crosses the terminal commit boundary into the REVOKED state and
/// is fenced by its terminal projection.
#[cfg(windows)]
fn assert_revocation_phase(phases: &DistinctLeasePhases) -> String {
    let operation = span_field(
        &phases.revoke_logs,
        "kernel.supervision.terminal_requested",
        "lease_operation",
    );
    assert_eq!(
        operation,
        "revoke",
        "the revocation phase discriminator is observed: {logs}",
        logs = phases.revoke_logs
    );
    assert_eq!(
        event_outcome(&phases.revoke_logs, "kernel.supervision.terminal_committed"),
        "success",
        "the revocation commits: {logs}",
        logs = phases.revoke_logs
    );
    assert_eq!(
        format!("{}", phases.revoked.record.state),
        "REVOKED",
        "revocation reaches the REVOKED lifecycle state: {logs}",
        logs = phases.revoke_logs
    );
    assert_eq!(
        phases.revoked.record.projection,
        SupervisionLeaseProjection::Terminal,
        "a revoked revision is fenced, not active: {logs}",
        logs = phases.revoke_logs
    );
    operation
}

/// An expiry past the validity boundary reaches the EXPIRED state through the
/// expiry boundary rather than the terminal boundary alone.
#[cfg(windows)]
fn assert_expiry_phase(phases: &DistinctLeasePhases) -> String {
    let operation = span_field(
        &phases.expire_logs,
        "kernel.supervision.expire_committed",
        "lease_operation",
    );
    assert_eq!(
        operation,
        "expire",
        "the expiry phase discriminator is observed: {logs}",
        logs = phases.expire_logs
    );
    assert_eq!(
        event_outcome(&phases.expire_logs, "kernel.supervision.expire_committed"),
        "success",
        "the expiry commits: {logs}",
        logs = phases.expire_logs
    );
    assert_eq!(
        format!("{}", phases.expired.record.state),
        "EXPIRED",
        "expiry reaches the EXPIRED lifecycle state: {logs}",
        logs = phases.expire_logs
    );
    operation
}

/// A changed same-ticket payload keeps the actual conflict: a refusal outcome
/// plus exactly one typed identity-conflict terminal, never a commit.
#[cfg(windows)]
fn assert_conflict_phase(phases: &DistinctLeasePhases) {
    assert!(
        phases.conflict_is_error,
        "a changed same-ticket payload retains the conflict: {logs}",
        logs = phases.conflict_logs
    );
    assert_eq!(
        event_outcome(&phases.conflict_logs, "kernel.supervision.terminal_failed"),
        "rejected",
        "the conflict is a refusal, never a commit: {logs}",
        logs = phases.conflict_logs
    );
    assert_eq!(
        terminal_codes(&phases.conflict_logs),
        vec!["SUPERVISION_IDENTITY_CONFLICT".to_owned()],
        "the conflict carries exactly one typed terminal: {logs}",
        logs = phases.conflict_logs
    );
}
