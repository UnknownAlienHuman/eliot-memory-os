#![allow(clippy::expect_used, clippy::unwrap_used)]
// Every fixture and helper in this file exists only to serve the six
// `#[cfg(windows)]` cases below, so the whole file is Windows-gated rather than
// gating each test and leaving ~15 ungated helpers to read as dead code on any
// other target. This is the crate's house shape, matching
// `tests/process_supervision_lifecycle.rs` and
// `tests/process_supervision_daemon_receipt.rs`; the per-test attributes are
// kept because they document each case's platform requirement at the case.
#![cfg(windows)]

//! Issue #901 `W5`, `W9`, `W13`, `W23`, `W25`, `W29` — process supervision and
//! launch evidence, proved in-crate against the production `eliot-kernel`
//! callsites.
//!
//! This suite owns no runtime authority, no process ownership and no Store
//! ownership. It drives the real production entry points only:
//!
//! * `process_execution.rs::ProcessExecutionGateway::start_in_context` and
//!   `process_execution.rs::run_process_start`, with the real
//!   `ProcessStartPorts` implementation, so registration, the effect-operation
//!   gates, the replay ledger, the executor handoff and the commit claim are
//!   all decided by production code;
//! * `process_execution.rs::ProcessExecutionGateway::{begin, persist_completed,
//!   abort, completed_receipt}` over a real `RedbRecoveryStore`;
//! * `ProcessExecutionGateway::execute` over the real `WindowsProcessExecutor`,
//!   which performs a real suspended Windows child launch and leaves a real
//!   live handle behind. That handle is RETAINED, not re-read: `ProcessExecutor::
//!   inspect` observes only Job liveness and returns the executor's retained
//!   state, so no assertion in this file claims to re-verify a pid or a creation
//!   marker against the OS;
//! * `eliot_ors::RedbRecoveryStore::{begin_process_start, load_process_start,
//!   abort_process_start, persist_process_start}` and
//!   `eliot_ors::ProcessStartReplayRecord::validate` for the exact-identity and
//!   physical-identity facts.
//!
//! Nothing in this file re-implements a production decision, and no test
//! substitutes an in-memory stand-in for the executor: the one OS launch each
//! launch test needs is performed by the production executor.

use super::*;

use eliot_kernel_core::{
    AuthoritySnapshotBinding, DispatchSnapshotCodec, KernelAuthorityReplaySnapshot, KernelError,
    KernelResult, SealedAuthoritySnapshot,
};
use eliot_ors::{
    EpochIdentity, EpochLineage, OpaqueLabel, OperationIdentity, ProcessStartReplayRecord,
    ProcessStartReplayState, RecoveryPayload, StateFenceSnapshot,
};
use eliot_platform::{PlatformHandle, SecretReference};
use eliot_process::{
    ActionLeaseRef, DispatchPermitAuthority, EnvironmentInheritance, EnvironmentProjection,
    FencingToken, Generation, ImageId, JobId, OperationId, PermitIssuance, ProcessExecutionView,
    ProcessExecutor, ProcessIntent, ProcessLifecycle, ProcessOwnerBinding, ProcessRequest,
    ProcessStartReceipt, ProcessTreeId, ResourceLimits, SessionId,
};
use eliot_runtime_contracts::{
    RegisteredActivityWakePolicy, SupervisionJournalEpoch, SupervisionLeaseIncarnationBinding,
    SupervisionObservationScope,
};
use std::collections::BTreeMap;
use std::io::Write;
use std::sync::{Arc, Mutex};

// ---------------------------------------------------------------------------
// Tracing capture seam.
//
// Two measured properties of the real capture boundary shape this seam:
//
// * `tracing::subscriber::with_default` is SYNCHRONOUS (tracing-core 0.1.36
//   `dispatcher.rs`: `pub fn with_default<T>(dispatcher: &Dispatch, f:
//   impl FnOnce() -> T) -> T { let _guard = set_default(dispatcher); f() }`),
//   so with an async body it drops the thread-local default BEFORE the future
//   is ever polled and every `info_span!`/`info!` below is disabled against
//   `Dispatch::none()`. The seam therefore holds the `DefaultGuard` its own
//   `set_default` returns across the await. Installing a subscriber
//   process-wide is never done here: it is set-once, so concurrent tests would
//   interfere.
// * A span's `is_disabled()` is decided when it is CREATED. A span built before
//   the subscriber is installed stays inert for its whole life: its declared
//   fields never reach the registry and every later `Span::record` on it is a
//   no-op. Every captured call site therefore builds its operation span INSIDE
//   the closure passed to `capture_with`, not before it.
//
// The renderer writes exactly one `{` before the whole space-separated
// `FormattedFields` run, so `{slot="` never occurs; and a recorded value is
// appended after the declared default, so `span_field` must take the value
// after the LAST occurrence of `slot="` on the line.
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

async fn capture_with<F, Fut, T>(run: F) -> (T, String)
where
    F: FnOnce() -> Fut,
    Fut: std::future::Future<Output = T>,
{
    let sink = CaptureSink::default();
    let writer_sink = sink.clone();
    let subscriber = tracing_subscriber::fmt()
        .with_ansi(false)
        .with_writer(move || writer_sink.clone())
        .finish();
    // The guard is a NAMED binding: `let _ = ...` would drop it immediately and
    // reproduce the `with_default`-over-an-async-body defect exactly. The
    // `#[tokio::test]` runtime here is the current-thread default, which
    // `block_on`s this future without a `Send` bound, so holding the guard
    // across the await needs no attribute and no allow.
    // `set_default` takes the subscriber BY VALUE (tracing-0.1.44/src/subscriber.rs:57),
    // so the `fmt::Subscriber` is consumed directly - no `Dispatch` wrapper, and
    // certainly no `&Dispatch`, which is not a `Subscriber` at all.
    let _guard = tracing::subscriber::set_default(subscriber);
    let value = run().await;
    let bytes = String::from_utf8_lossy(&sink.bytes.lock().expect("capture lock")).into_owned();
    (value, bytes)
}

/// Reads the value of one recorded span slot from a captured line.
///
/// Two properties of the real renderer (tracing-subscriber 0.3.23) force this
/// shape, both measured rather than assumed:
///
/// * `Format::format_event` writes exactly one `{` before the whole
///   space-separated `FormattedFields` run, so the needle `{slot="` never
///   occurs and must not be used;
/// * `FmtLayer::on_record` appends through `add_fields`, which pushes a space
///   and formats without rewriting the declared slot, so a recorded value
///   appears AFTER its declared default and the LAST occurrence is the recorded
///   value.
///
/// A slot the owner never recorded occurs exactly once and resolves to its
/// declared `"unavailable"` default, which is the honest answer for it.
fn span_field<'a>(line: &'a str, slot: &str) -> Option<&'a str> {
    let needle = format!("{slot}=\"");
    let start = line.rfind(&needle)? + needle.len();
    let rest = &line[start..];
    let end = rest.find('"')?;
    Some(&rest[..end])
}

fn captured_line<'a>(logs: &'a str, needle: &str) -> &'a str {
    logs.lines()
        .find(|line| line.contains(needle))
        .unwrap_or_else(|| panic!("no captured line carries {needle}; captured: {logs}"))
}

/// The captured line carrying one `kernel_diagnostics` observation. Each
/// observation is emitted as the `event` field of its own record, so the event
/// name is read from that field and never from a message position.
fn event_line<'a>(logs: &'a str, event: &str) -> &'a str {
    captured_line(logs, &format!("event=\"{event}\""))
}

fn event_present(logs: &str, event: &str) -> bool {
    logs.contains(&format!("event=\"{event}\""))
}

fn event_count(logs: &str, event: &str) -> usize {
    logs.matches(&format!("event=\"{event}\"")).count()
}

fn event_outcome(logs: &str, event: &str) -> String {
    let line = event_line(logs, event);
    line.split_once("outcome=\"")
        .and_then(|(_, rest)| rest.split_once('"'))
        .map_or_else(
            || panic!("no outcome on the {event} line: {line}"),
            |(value, _)| value.to_owned(),
        )
}

fn terminal_code(logs: &str) -> String {
    let line = event_line(logs, "kernel.terminal_error");
    line.split_once("code=\"")
        .and_then(|(_, rest)| rest.split_once('"'))
        .map_or_else(
            || panic!("no terminal code on: {line}"),
            |(value, _)| value.to_owned(),
        )
}

/// Byte offset of one observation in the captured run, for ordering proofs.
fn event_offset(logs: &str, event: &str) -> usize {
    let needle = format!("event=\"{event}\"");
    logs.find(&needle)
        .unwrap_or_else(|| panic!("{needle} absent from captured run: {logs}"))
}

// ---------------------------------------------------------------------------
// Local fixtures. Duplicated per file by the crate's house pattern; no
// existing in-crate module is edited and no shared helper module is created.
// ---------------------------------------------------------------------------

fn test_epoch(sequence: u64) -> eliot_contracts::EpochId {
    eliot_contracts::EpochId::new(
        eliot_contracts::EpochLineageId::new("550e8400-e29b-41d4-a716-446655440000")
            .expect("lineage"),
        std::num::NonZeroU64::new(sequence).expect("sequence"),
    )
    .expect("epoch")
}

fn test_owner(generation: u64) -> ProcessOwnerBinding {
    ProcessOwnerBinding::new(
        "eliotd",
        "a".repeat(64),
        test_epoch(1),
        Generation::new(generation).expect("generation"),
    )
    .expect("owner")
}

/// The production authority snapshot binding the real gateway's dispatch
/// controller and admission validator both read.
fn authority_binding(authority_id: &DispatchAuthorityId) -> AuthoritySnapshotBinding {
    let epoch = EpochLineage {
        current: EpochIdentity {
            lineage_id: OpaqueLabel::new("kernel-901-launch-lineage").expect("lineage"),
            epoch: 1,
        },
        predecessor: None,
    };
    let state_fence =
        StateFenceSnapshot::capture(&serde_json::json!({"authority": "kernel-901"}), 1)
            .expect("state fence");
    AuthoritySnapshotBinding::new(
        authority_id.clone(),
        OperationIdentity::new("kernel-901-launch-authority-record").expect("record id"),
        epoch,
        state_fence,
        1,
        None,
    )
    .expect("authority binding")
}

struct LaunchSnapshotCodec;

impl DispatchSnapshotCodec for LaunchSnapshotCodec {
    fn seal(
        &self,
        snapshot: &KernelAuthorityReplaySnapshot,
        _binding: &AuthoritySnapshotBinding,
    ) -> KernelResult<SealedAuthoritySnapshot> {
        let ciphertext = serde_json::to_vec(snapshot)
            .map_err(|error| KernelError::DependencyUnavailable(error.to_string()))?;
        let key = SecretReference::new("test-provider", "kernel-901-authority")
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
                "authority fixture payload is not encrypted".to_owned(),
            ));
        };
        serde_json::from_slice(ciphertext)
            .map_err(|error| KernelError::RecoveryUnavailable(error.to_string()))
    }
}

/// The dispatch validation port the production `WindowsProcessExecutor` calls
/// before it resumes a suspended child. It owns the dispatch permit authority
/// that issued the permit for the launch this suite performs; it decides
/// nothing about registration, replay, identity or evidence.
struct LaunchValidationAuthority {
    authority: Mutex<DispatchPermitAuthority>,
    context: DispatchValidationContext,
    fence: FencingToken,
    revision_heads: BTreeMap<String, String>,
    /// The ONE wall-clock reading this authority's validation clock and every
    /// permit it issues are stamped from.
    ///
    /// `DispatchPermitAuthority::validate_and_consume` reads `now` from
    /// `DispatchValidationContext::now_unix_ms`, which is the FROZEN
    /// `valid_time_ms` of `context` and nothing else
    /// (`crates/kernel/eliot-process/src/lib.rs:1498-1510`), and refuses when
    /// `now < permit.issued_at_unix_ms`
    /// (`crates/kernel/eliot-process/src/dispatch_permit.rs:386-389`). A permit
    /// stamped from a SECOND, later `unix_ms()` reading is therefore born already
    /// stale however short the gap is — and the gap is not short, because
    /// building this fixture reads the ORS twice and SHA-256s `ping.exe` — so the
    /// launch would be refused as `ExpiredDispatchPermit` before any OS process
    /// existed. Reading the clock once and using that single value for both the
    /// frozen context and the permit stamp makes `now == issued_at_unix_ms` by
    /// construction, so the freshness gate is satisfied by arithmetic rather than
    /// by timing luck.
    ///
    /// The gate is NOT weakened or bypassed: the stamp is still the real clock,
    /// and the expiry is still the admission's own deadline. Only the spurious
    /// difference between two readings of the same clock is removed.
    issued_at_ms: u64,
}

impl LaunchValidationAuthority {
    fn new() -> Self {
        // Read the wall clock ONCE. This one value is both the frozen validation
        // clock below and the issue stamp in `issue`, which is what makes the
        // production permit-freshness gate pass by construction.
        let issued_at_ms = unix_ms();
        let generation = Generation::new(1).expect("generation");
        let fence = FencingToken::new(test_epoch(1), generation, "kernel-901-launch-fence")
            .expect("test fence");
        let revision_heads = BTreeMap::from([("kernel-901".to_owned(), "a".repeat(64))]);
        let context = DispatchValidationContext::new(
            ClockObservation {
                valid_time_ms: Some(i64::try_from(issued_at_ms).expect("clock range")),
                known_time_ms: Some(i64::try_from(issued_at_ms).expect("clock range")),
                transaction_sequence: None,
                monotonic_ns: None,
            },
            fence.clone(),
            test_epoch(1),
            revision_heads.clone(),
            1,
        )
        .expect("test validation context");
        Self {
            authority: Mutex::new(DispatchPermitAuthority::activate(
                DispatchAuthorityId::new("kernel-901-launch-permit").expect("permit authority"),
                KernelDispatchKey::from_secret_bytes([0x31; 32]).expect("launch dispatch key"),
            )),
            context,
            fence,
            revision_heads,
            issued_at_ms,
        }
    }

    /// Issues one permit from the SAME clock reading the validation context
    /// carries, so `validate_and_consume` compares a permit against the instant
    /// it was stamped rather than against a later reading of the same clock.
    fn issue(&self, admission: &ProcessExecutionAdmissionRequest) -> ProcessRequest {
        let issuance = PermitIssuance::new_with_validation_revision(
            admission.action_lease_ref().clone(),
            self.fence.clone(),
            self.revision_heads.clone(),
            self.issued_at_ms,
            admission.deadline_unix_ms(),
            format!("kernel-901:{}", admission.intent().operation_id().as_str()),
            1,
        )
        .expect("permit issuance");
        let permit = self
            .authority
            .lock()
            .expect("launch permit authority lock")
            .issue(admission.intent(), issuance)
            .expect("launch dispatch permit");
        ProcessRequest::new(admission.intent().clone(), permit).expect("launch process request")
    }
}

impl DispatchValidationPort for LaunchValidationAuthority {
    fn validate_and_consume(
        &self,
        request: ProcessRequest,
        observed: SuspendedProcessIdentity,
    ) -> Result<ValidatedDispatch, ProcessExecutionError> {
        self.authority
            .lock()
            .map_err(|_| {
                ProcessExecutionError::Unavailable(
                    "launch permit authority lock poisoned".to_owned(),
                )
            })?
            .validate_and_consume(request, observed, &self.context)
            .map_err(ProcessExecutionError::Contract)
    }
}

/// Real-executor cases run inside one process-owned outer Job. Retain its
/// handle for the test process lifetime: dropping a kill-on-close Job while its
/// root is still running would terminate the test harness itself. This confines
/// only this test process and its children, never Cargo or the runner.
fn launch_outer_binding(owner: &ProcessOwnerBinding) -> HostKernelCandidateBinding {
    use eliot_platform_windows::{JobObject, JobObjectIdentity, JobObjectLimits, OuterKillDomain};
    static JOB: std::sync::OnceLock<Mutex<JobObject>> = std::sync::OnceLock::new();
    static BINDING: std::sync::OnceLock<eliot_kernel_service::HostJobBinding> =
        std::sync::OnceLock::new();
    let binding = BINDING
        .get_or_init(|| {
            let executable = std::env::current_exe().expect("test executable");
            let identity = eliot_platform_windows::file_identity_for_path(&executable)
                .expect("root file identity");
            let job = JOB.get_or_init(|| {
                let name = format!(
                    "{}kernel-901-launch-{}",
                    OuterKillDomain::Kernel.host_job_name_prefix(),
                    std::process::id()
                );
                Mutex::new(
                    JobObject::new_named_outer_kill_on_close_with_limits(
                        OuterKillDomain::Kernel,
                        JobObjectIdentity::new(name).expect("Job name"),
                        JobObjectLimits::default(),
                    )
                    .expect("test outer Job"),
                )
            });
            let job = job.lock().expect("test outer Job lock");
            let process = job
                .assign_process(std::process::id())
                .expect("assign exact test root");
            eliot_kernel_service::HostJobBinding {
                job: eliot_kernel_service::HostJobIdentity {
                    name: job.identity().name().to_owned(),
                },
                root: eliot_kernel_service::HostJobRoot {
                    process: eliot_kernel_service::HostProcessBinding {
                        process_id: process.process_id,
                        start_time_100ns: process.start_time_100ns,
                        image_path: process.image_path,
                    },
                    executable: eliot_kernel_service::HostFileIdentity {
                        volume_serial_number: identity.volume_serial_number,
                        file_index: identity.file_index,
                    },
                },
            }
        })
        .clone();
    let candidate = HostKernelCandidateBinding {
        installation_id: PlatformHandle::new("installation-1").expect("installation"),
        host_epoch: eliot_contracts::AuthorityEpoch::new(1).expect("host epoch"),
        kernel_epoch: owner.authority_epoch().clone(),
        activation_id: PlatformHandle::new("activation-1").expect("activation"),
        artifact_hash: PlatformHandle::new("kernel-901-launch-artifact").expect("artifact"),
        config_hash: PlatformHandle::new("kernel-901-launch-config").expect("config"),
        job_object_id: PlatformHandle::new(binding.job.name.clone()).expect("Job identity"),
        pipe_identity: PlatformHandle::new(KERNEL_CONTROL_PIPE).expect("pipe identity"),
        host_process: binding.root.process.clone(),
        job_binding: binding,
        supervision_incarnation: SupervisionLeaseIncarnationBinding {
            supervision_lease_scope_id: "eliot-kernel-901-supervision-scope".to_owned(),
            supervision_lease_id: String::new(),
            scope_ref_digest: String::new(),
            installation_id: "installation-1".to_owned(),
            host_epoch: SupervisionJournalEpoch {
                lineage_id: "kernel-901-host-lineage".to_owned(),
                sequence: 1,
            },
            activation_id: "activation-1".to_owned(),
            activation_generation: SupervisionJournalEpoch {
                lineage_id: "kernel-901-activation-lineage".to_owned(),
                sequence: 1,
            },
            kernel_generation: SupervisionJournalEpoch {
                lineage_id: "kernel-901-kernel-lineage".to_owned(),
                sequence: 1,
            },
            watchdog_epoch: SupervisionJournalEpoch {
                lineage_id: "kernel-901-watchdog-lineage".to_owned(),
                sequence: 1,
            },
            observation_scope: SupervisionObservationScope {
                targets: vec!["eliot-kernel".to_owned()],
                sensor_profile: "eliot-runtime-live-v3".to_owned(),
                claimed_coverage: vec!["process".to_owned(), "job".to_owned()],
                governance_axis: "runtime-live-v3".to_owned(),
            },
            wake_policy: RegisteredActivityWakePolicy::Disabled,
            predecessor: None,
        }
        .with_derived_ids()
        .expect("sealed supervision incarnation"),
        restart_budget: eliot_kernel_service::RestartBudget::new(1, 1).expect("restart budget"),
        agent_bridge_admission: None,
        containment_action: None,
    };
    candidate.validate().expect("valid physical test binding");
    candidate
}

/// One real composition: a real durable ORS, the real production
/// `ProcessExecutionGateway`, and the real production `WindowsProcessExecutor`.
struct LaunchFixture {
    gateway: ProcessExecutionGateway,
    store: Arc<RedbRecoveryStore>,
    platform: Arc<WindowsPlatform>,
    validation: Arc<LaunchValidationAuthority>,
    root: std::path::PathBuf,
    owner: ProcessOwnerBinding,
    /// One deadline for every admission this fixture builds.
    ///
    /// `deadline_unix_ms` is part of the serialized admission, so it is part of
    /// `process_admission_digest`, and `RedbRecoveryStore::begin_process_start`
    /// refuses a second registration whose digest differs from the recorded one.
    /// A per-call `unix_ms()` would therefore make two structurally identical
    /// admissions of the same operation DIFFERENT operations to the store, which
    /// turns every replay into a registration conflict decided long before the
    /// replay gate. One value, read once per fixture, keeps the whole fixture on
    /// a single admission identity.
    ///
    /// The production deadline gate at `process_execution.rs:3938-3943` — `let
    /// now = ports.now(); if admission.deadline_unix_ms() <= now` — IS REACHABLE
    /// from this capsule, unlike the permit-freshness gate on
    /// `LaunchValidationAuthority`: `ProcessExecutionGateway::execute`
    /// (`:4374-4442`) does not call `run_process_start`, so `launch_and_commit`
    /// never reaches it, but `start_in_context` calls `run_process_start` at
    /// `:2924`, so every `start_in_context` this file issues (cases 5, 8 and 6)
    /// runs that real-clock comparison before `ports.begin`.
    ///
    /// It cannot redden because of TEST EXECUTION ORDER. The 120 s budget is
    /// measured from this fixture's OWN construction, inside the test body that
    /// then spends it: it is neither a process-global nor shared with a sibling
    /// test, no `OnceLock`/`static` in this file holds a deadline, and the only
    /// wall-clock reads here are this one and `LaunchValidationAuthority`'s own
    /// single frozen reading. Running the whole capsule in parallel, in any
    /// order, or on its own therefore cannot move this gate. The only way it
    /// fires is one test spending more than two minutes of real wall clock
    /// between `launch_fixture` and its own `start_in_context`, and it then
    /// fails loudly rather than silently: `event_outcome`/`event_offset` panic
    /// on an absent `kernel.process.start_registration`, so a tripped deadline
    /// reports as a missing registration observation rather than as a pass.
    deadline_unix_ms: u64,
}

fn launch_root(tag: &str) -> std::path::PathBuf {
    std::env::temp_dir().join(format!(
        "eliot-kernel-901-launch-{tag}-{}-{}",
        std::process::id(),
        unix_ms()
    ))
}

fn live_child_executable() -> std::path::PathBuf {
    std::path::PathBuf::from(std::env::var("SystemRoot").expect("SystemRoot"))
        .join("System32")
        .join("ping.exe")
}

fn launch_fixture(tag: &str) -> LaunchFixture {
    let root = launch_root(tag);
    std::fs::create_dir_all(&root).expect("launch fixture root");
    let store = Arc::new(
        RedbRecoveryStore::open(root.join("kernel-ors.redb")).expect("launch fixture ORS"),
    );
    let authority_id = DispatchAuthorityId::new("kernel-901-launch-authority").expect("authority");
    let snapshot_binding = authority_binding(&authority_id);
    let authority_store: Arc<dyn OperationalRecoveryStore> = store.clone();
    let codec: Arc<dyn DispatchSnapshotCodec> = Arc::new(LaunchSnapshotCodec);
    let controller = Arc::new(Mutex::new(ProcessDispatchAuthorityController::activate(
        authority_id,
        KernelDispatchKey::from_secret_bytes([0x29; 32]).expect("dispatch key"),
        authority_store,
        codec,
    )));
    let platform = Arc::new(
        WindowsPlatform::new(root.join("containment")).expect("launch fixture platform root"),
    );
    let path_admission = Arc::new(KernelPathAdmission::new(Arc::clone(&platform)));
    let validation = Arc::new(LaunchValidationAuthority::new());
    let validation_port: Arc<dyn DispatchValidationPort> = validation.clone();
    let launch_admission: Arc<dyn ProcessLaunchAdmission> = path_admission.clone();
    let mut gateway = ProcessExecutionGateway::new(
        controller,
        Arc::clone(&store),
        snapshot_binding,
        path_admission,
    );
    gateway.executor =
        WindowsProcessExecutor::new_with_launch_admission(validation_port, launch_admission);
    LaunchFixture {
        gateway,
        store,
        platform,
        validation,
        root,
        owner: test_owner(1),
        deadline_unix_ms: unix_ms().saturating_add(120_000),
    }
}

impl LaunchFixture {
    /// One admitted start whose executable and working directory are the real
    /// files this fixture retains. `executable_sha256` is the only field a
    /// caller may change, so a payload change is exactly a digest change over
    /// the same operation identity.
    ///
    /// Every field here is a pure function of the arguments and of
    /// `self.deadline_unix_ms`, so two calls with the same arguments are the
    /// SAME admission to the canonical replay identity and not merely a similar
    /// one. `assert_same_admission_identity` proves that at each replay site.
    fn admission(
        &self,
        operation: &str,
        executable_sha256: &str,
    ) -> ProcessExecutionAdmissionRequest {
        let generation = Generation::new(1).expect("generation");
        let executable = live_child_executable();
        let working_directory = self.root.clone();
        let intent = ProcessIntent::new(
            OperationId::new(operation).expect("operation id"),
            ProcessTreeId::new(format!("kernel-901-tree-{operation}")).expect("process tree"),
            JobId::new(format!("kernel-901-logical-job-{operation}")).expect("logical Job id"),
            ImageId::new(format!("kernel-901-image-{operation}")).expect("image id"),
            SessionId::new(format!("kernel-901-session-{operation}")).expect("session id"),
            generation,
            executable.to_string_lossy(),
            executable_sha256,
            vec!["-n".to_owned(), "45".to_owned(), "127.0.0.1".to_owned()],
            working_directory.to_string_lossy(),
            EnvironmentProjection::new(BTreeMap::new(), Vec::new(), EnvironmentInheritance::None)
                .expect("closed child environment"),
            ResourceLimits::new(60_000, Some(45_000), None, 64 * 1024, 64 * 1024, 4)
                .expect("resource limits"),
        )
        .expect("launch intent");
        ProcessExecutionAdmissionRequest::new(
            ACTIVE_DAEMON_CALLER,
            intent,
            ActionLeaseRef::new(format!("kernel-901-lease-{operation}")).expect("action lease"),
            FencingToken::new(test_epoch(1), generation, "kernel-901-launch-fence")
                .expect("state fence"),
            self.deadline_unix_ms,
        )
        .expect("launch admission")
    }

    fn executable_sha256() -> String {
        sha256_hex(&std::fs::read(live_child_executable()).expect("child image bytes"))
    }

    /// The canonical replay identity production itself computes for one
    /// admission. Production reads this, never a value derived here.
    ///
    /// This is an associated function on purpose, exactly like
    /// [`LaunchFixture::executable_sha256`]: `process_admission_digest` is a free
    /// function over the serialized admission alone, so it reads nothing off a
    /// fixture and there is no receiver field that would honestly belong here.
    fn digest(admission: &ProcessExecutionAdmissionRequest) -> String {
        process_admission_digest(admission).expect("production admission digest")
    }

    /// HONEST GUARD (no production pin) — proves only that
    /// `LaunchFixture::admission` is REPRODUCIBLE, and returns the canonical
    /// replay identity so the caller can pin it to the committed row.
    ///
    /// Read the first bullet under "what this does and does not prove" before
    /// citing this as evidence about production: this comparison CANNOT redden
    /// on any production change. Both sides are the same pure function over two
    /// independently constructed but structurally identical admissions, so
    /// deleting or weakening `process_admission_digest` — or any other
    /// production line — leaves it green. What it does pin is the fixture's own
    /// builder.
    ///
    /// Why reproducibility is load-bearing: a replay must present the SAME
    /// admitted bytes as the committed start, because the durable store refuses a
    /// second registration of one operation identity whose `admission_digest`
    /// differs, reports it at the registration seam as `Unavailable`, and returns
    /// before the effect-replay gate is reached. A non-reproducible `admission()`
    /// would silently convert "the replay gate refused" into "the store refused a
    /// different admission". `deadline_unix_ms` is the field that made this
    /// reproducible: it is read once per fixture and is part of the serialized
    /// admission, so it is part of the digest.
    ///
    /// Precisely what this does and does not prove, because the honest boundary
    /// matters here:
    ///
    /// * DOES prove: two INDEPENDENT constructions of the same operation serialize
    ///   to the same `process_admission_digest`. Both sides go through the same
    ///   pure function with the same arguments, so this is a reproducibility
    ///   check on the builder and NOT a comparison of two different inputs. It
    ///   fires the moment `admission()` grows any field that is not a function of
    ///   its arguments and `self.deadline_unix_ms` — a fresh `unix_ms()`, a
    ///   counter, anything else.
    /// * DOES NOT prove: that the replayed admission equals the admission
    ///   PRODUCTION COMMITTED. Nothing here reads the store. That premise is
    ///   established separately, and only there, by the caller comparing the
    ///   returned digest against `durable.admission_digest` on the row
    ///   production actually wrote. Keep that assertion at every call site; this
    ///   helper does not replace it.
    fn assert_same_admission_identity(
        &self,
        operation: &str,
        admission: &ProcessExecutionAdmissionRequest,
    ) -> String {
        let rebuilt = self.admission(operation, &LaunchFixture::executable_sha256());
        let original = Self::digest(admission);
        let rebuilt_digest = Self::digest(&rebuilt);
        assert_eq!(
            original, rebuilt_digest,
            "LaunchFixture::admission must be reproducible: a replay built from a different \
             serialized admission would be refused by the durable store as a digest conflict \
             before the replay gate is ever reached"
        );
        original
    }

    /// One admitted start of the SAME operation identity whose payload differs
    /// only in its process-tree coordinate. The executable, its digest and the
    /// working directory are byte-identical to `admission`, so the retained
    /// path proof still validates and the ONLY thing that changed is the
    /// admitted payload the admission digest is computed over.
    fn admission_with_tree(
        &self,
        operation: &str,
        executable_sha256: &str,
        tree: &str,
    ) -> ProcessExecutionAdmissionRequest {
        let admission = self.admission(operation, executable_sha256);
        let generation = Generation::new(1).expect("generation");
        let intent = ProcessIntent::new(
            OperationId::new(operation).expect("operation id"),
            ProcessTreeId::new(tree).expect("changed process tree"),
            JobId::new(format!("kernel-901-logical-job-{operation}")).expect("logical Job id"),
            ImageId::new(format!("kernel-901-image-{operation}")).expect("image id"),
            SessionId::new(format!("kernel-901-session-{operation}")).expect("session id"),
            generation,
            admission.intent().executable(),
            executable_sha256,
            admission.intent().argv().to_vec(),
            admission.intent().working_directory(),
            EnvironmentProjection::new(BTreeMap::new(), Vec::new(), EnvironmentInheritance::None)
                .expect("closed child environment"),
            ResourceLimits::new(60_000, Some(45_000), None, 64 * 1024, 64 * 1024, 4)
                .expect("resource limits"),
        )
        .expect("changed launch intent");
        ProcessExecutionAdmissionRequest::new(
            ACTIVE_DAEMON_CALLER,
            intent,
            admission.action_lease_ref().clone(),
            admission.state_fence().clone(),
            admission.deadline_unix_ms(),
        )
        .expect("changed launch admission")
    }

    /// The real retained path proof the production admission validator and the
    /// production path admission both read.
    fn path_proof(&self, admission: &ProcessExecutionAdmissionRequest) -> ProcessPathProof {
        let executable = std::path::PathBuf::from(admission.intent().executable());
        let working_directory = std::path::PathBuf::from(admission.intent().working_directory());
        let lease = self
            .platform
            .retain_process_path_lease(
                &executable,
                &working_directory,
                admission.intent().executable_sha256(),
            )
            .expect("retained launch path proof");
        ProcessPathProof {
            executable,
            working_directory,
            lease: Arc::new(lease),
        }
    }

    /// Performs ONE real suspended Windows child launch through the production
    /// gateway and executor, then commits the start through the production
    /// `ProcessStartPorts::persist_completed` seam into the real ORS. The child
    /// stays alive, so the executor retains a real live handle for it.
    ///
    /// This path builds the `ProcessRequest` itself, through
    /// `LaunchValidationAuthority::issue`, and hands it straight to
    /// `ProcessExecutionGateway::execute`. It therefore does NOT insert a gateway
    /// validation context: the only reader of that slot is `ports.issue` inside
    /// `run_process_start` (`src/process_execution.rs:4108`), and `execute`
    /// (`:4374-4442`) never touches it. Inserting one here and dropping it unread
    /// asserted nothing and cost a second `unix_ms()` reading, so it is gone
    /// rather than kept as decoration. The retained path proof IS inserted,
    /// because the production launch admission reads it.
    async fn launch_and_commit(
        &self,
        admission: &ProcessExecutionAdmissionRequest,
    ) -> ProcessStartReceipt {
        let operation_id = admission.intent().operation_id().clone();
        let path_guard = self
            .gateway
            .insert_path(operation_id.clone(), self.path_proof(admission))
            .expect("retained launch path proof");
        let request = self.validation.issue(admission);
        let receipt = self
            .gateway
            .execute(
                &self.owner,
                request,
                Some(&launch_outer_binding(&self.owner)),
            )
            .await
            .expect("production Windows child launch");
        drop(path_guard);
        let digest = Self::digest(admission);
        ProcessStartPorts::persist_completed(
            &self.gateway,
            &operation_id,
            &digest,
            &self.owner,
            receipt.clone(),
        )
        .expect("production completed-start commit");
        receipt
    }

    fn durable_record(&self, operation: &str) -> Option<ProcessStartReplayRecord> {
        self.store
            .load_process_start(&OperationIdentity::new(operation).expect("operation identity"))
            .expect("durable replay read")
    }

    /// The executor's RETAINED view of this operation, via the production
    /// `ProcessExecutor::inspect`.
    ///
    /// This is NOT an OS re-read of the launched process.
    /// `WindowsProcessExecutor::inspect_inner` returns `guard.state.view()`
    /// (`crates/instrument/eliot-process-executor/src/lib.rs:2768`), and the only
    /// fresh fact it adds is `refresh_operation`'s `child.observe()`, whose
    /// `RunningJobObservation::Running` carries just `active_processes: u32`
    /// (`crates/kernel/eliot-platform-windows/src/process_job.rs:2739-2742`).
    /// The executor really does hold a live OS handle; nothing on this path
    /// reads the pid or the creation marker back out of it. So the identity in
    /// the returned view is the identity the executor RETAINED, and comparing it
    /// to the receipt is a self-consistency check between two clones of one
    /// `ProcessIdentity` (`ProcessState::view` clones `self.identity`;
    /// `ProcessStartReceipt::new` cloned the same value out of that state). It
    /// proves the receipt and the retained state agree, and it proves liveness
    /// only in the weak sense that the Job still reports a live member.
    async fn live_handle(
        &self,
        operation: &str,
    ) -> Result<ProcessExecutionView, ProcessExecutionError> {
        self.gateway
            .executor
            .inspect(OperationId::new(operation).expect("operation id"))
            .await
    }
}

fn cleanup_launch_root(tag: &str) {
    let _ = std::fs::remove_dir_all(launch_root(tag));
}

// ---------------------------------------------------------------------------
// W13 — registration-before-launch ordering.
//
// Drives the real `ProcessExecutionGateway::start_in_context` on the real
// production gateway. Nothing about registration is added here: the ordering is
// read back from the captured byte order of the observations production emits.
// ---------------------------------------------------------------------------

// WORK_UNIT_CASE: 901/5
#[cfg(windows)]
#[tokio::test]
async fn registration_is_recorded_before_any_launch_handoff() {
    let fixture = launch_fixture("w13");
    let admission = fixture.admission("kernel-901-w13", &LaunchFixture::executable_sha256());
    let (result, logs) = capture_with(|| {
        let fixture = &fixture;
        let admission = admission.clone();
        async move {
            let context = ProcessExecutionGateway::start_context_for(&fixture.owner, &admission);
            let proof = fixture.path_proof(&admission);
            let outer = launch_outer_binding(&fixture.owner);
            fixture
                .gateway
                .start_in_context(&fixture.owner, admission, proof, outer, &context)
                .await
        }
    })
    .await;

    assert!(
        result.is_err(),
        "an operation with no recorded admitted manifest is refused: {result:?}"
    );
    // The registration observation is the first thing the pipeline records, and
    // the byte order of the captured run is the order production emitted them.
    assert_eq!(
        event_outcome(&logs, "kernel.process.start_requested"),
        "attempt"
    );
    assert_eq!(
        event_outcome(&logs, "kernel.process.start_registration"),
        "acquired"
    );
    assert!(
        event_offset(&logs, "kernel.process.start_requested")
            < event_offset(&logs, "kernel.process.start_registration"),
        "the admitted request precedes its registration: {logs}"
    );
    assert!(
        event_offset(&logs, "kernel.process.start_registration")
            < event_offset(&logs, "kernel.process.effect_operation_lease_refused"),
        "registration precedes the new-operation authority gate: {logs}"
    );
    // The launch handoff observation and the committed-start claim come AFTER
    // registration in production order, and neither byte exists here: the
    // registration is strictly earlier evidence than an OS launch.
    //
    // REGRESSION GUARD (absence) — both CAN redden, and the same mutation
    // reaches both: moving `ports.require_new_effect_operation_authority`
    // (`src/process_execution.rs:3985`) to after the handoff observation
    // (`:4141-4145`) emits `start_handoff` here and fails both assertions. The
    // `start_committed` guard is independently reachable: emitting that event
    // from the `Err` arm of `start_in_context` (`:2951-2962`) rather than only
    // from the `Ok` arm under `!replayed` (`:2942-2948`) fails it while leaving
    // `start_handoff` untouched. Neither is vacuous merely because its emitter
    // is otherwise unreached from this fixture: an unreached emitter is exactly
    // the state these guards exist to detect changing.
    assert!(
        !event_present(&logs, "kernel.process.start_handoff"),
        "no executor handoff may be observed for a refused start: {logs}"
    );
    assert!(
        !event_present(&logs, "kernel.process.start_committed"),
        "a refused start may never claim a committed start: {logs}"
    );
    assert_eq!(
        event_outcome(&logs, "kernel.process.start_failed"),
        "rejected"
    );
    assert_eq!(
        terminal_code(&logs),
        "process_unavailable",
        "the new-operation authority gate's own refusal is the terminal: {logs}"
    );
    // The registration really was durable and was then released by the
    // production reservation abort, and no OS process exists for it.
    //
    // REGRESSION GUARD (absence) — both CAN redden. Deleting the
    // `reservation.release()` arm of the new-operation gate
    // (`src/process_execution.rs:3992-3995`), or making
    // `ProcessStartReservation::release` (`:2003-2015`) a no-op, leaves the
    // Reserved row on disk and fails the first; the same gate-after-handoff
    // mutation named above hands the operation to the executor and leaves a
    // retained operation, so `ProcessExecutor::inspect` answers and the second
    // fails. A positive verdict is not reachable by accident here: the only
    // producer of a durable row on this path is `ports.begin`, and the only
    // producer of a retained view is `ports.execute`.
    assert!(
        fixture.durable_record("kernel-901-w13").is_none(),
        "the refused reservation must be released, not left registered"
    );
    assert!(
        fixture.live_handle("kernel-901-w13").await.is_err(),
        "a registration is not an OS launch: the executor retains no handle"
    );
    drop(fixture);
    cleanup_launch_root("w13");
}

// ---------------------------------------------------------------------------
// W5 / W23 — an exact replay of an already committed start.
//
// Both tests first perform ONE real suspended Windows child launch through the
// production gateway and executor and commit it through the production
// `persist_completed` seam, so the durable replay record the replay then meets
// is produced by production, never by the test.
// ---------------------------------------------------------------------------

/// One real launch, committed through the production seam, plus the executor's
/// retained view and the durable record the replay must find unchanged.
///
/// The caller passes the admission it will later replay, so the committed bytes
/// and the replayed bytes are the same value by construction rather than by two
/// constructions that happen to agree.
///
/// The returned view is the executor's RETAINED state, not an OS re-read; see
/// [`LaunchFixture::live_handle`].
async fn committed_launch(
    fixture: &LaunchFixture,
    operation: &str,
    admission: &ProcessExecutionAdmissionRequest,
) -> (
    ProcessStartReceipt,
    ProcessStartReplayRecord,
    ProcessExecutionView,
) {
    let receipt = fixture.launch_and_commit(admission).await;
    let durable = fixture
        .durable_record(operation)
        .expect("committed start record");
    assert_eq!(durable.state, ProcessStartReplayState::Completed);
    assert_eq!(
        durable.receipt.as_ref(),
        Some(&receipt),
        "the durable record holds exactly the receipt production returned"
    );
    let view = fixture
        .live_handle(operation)
        .await
        .expect("the production executor retains the launched handle");
    assert_eq!(view.lifecycle(), ProcessLifecycle::Running);
    assert_eq!(view.identity(), Some(receipt.identity()));
    (receipt, durable, view)
}

#[cfg(windows)]
#[tokio::test]
async fn an_exact_replay_meets_the_recorded_outcome_and_never_a_second_launch() {
    let fixture = launch_fixture("w5");
    let operation = "kernel-901-w5";
    let admission = fixture.admission(operation, &LaunchFixture::executable_sha256());
    // The replay below replays THESE bytes. If they were not the committed
    // identity, the durable store would refuse the registration and this case
    // would be measuring the wrong refusal entirely, so the premise is asserted
    // before anything is committed.
    let admission_identity = fixture.assert_same_admission_identity(operation, &admission);
    let (first, durable, view_before) = committed_launch(&fixture, operation, &admission).await;
    assert_eq!(
        durable.admission_digest, admission_identity,
        "the committed start was recorded under exactly the admission the replay presents"
    );

    let (result, logs) = capture_with(|| {
        let fixture = &fixture;
        let admission = admission.clone();
        async move {
            let context = ProcessExecutionGateway::start_context_for(&fixture.owner, &admission);
            let proof = fixture.path_proof(&admission);
            let outer = launch_outer_binding(&fixture.owner);
            fixture
                .gateway
                .start_in_context(&fixture.owner, admission, proof, outer, &context)
                .await
        }
    })
    .await;

    // The replay is answered from the durable record, so it reaches the
    // `Existing` arm and never takes a fresh registration.
    assert_eq!(
        event_outcome(&logs, "kernel.process.start_registration"),
        "existing",
        "an exact replay must be answered from the recorded registration: {logs}"
    );
    assert_eq!(event_count(&logs, "kernel.process.start_registration"), 1);
    // The effect-replay gate is the owner that answers the replay, and it
    // refuses: this generation records no effect operation lease for the
    // operation, so there is no already-authorized effect to resume.
    assert_eq!(event_count(&logs, "kernel.process.effect_replay_denied"), 1);
    assert_eq!(
        event_outcome(&logs, "kernel.process.effect_replay_denied"),
        "shadow_only"
    );
    assert!(
        matches!(
            result,
            Err(ProcessExecutionError::Contract(
                eliot_process::ContractError::DispatchBindingMismatch
            ))
        ),
        "the replay gate's own conflict must be the returned one: {result:?}"
    );
    // No second launch: the handoff observation and the committed-start claim
    // are both strictly later production steps and neither byte exists.
    //
    // REGRESSION GUARD (absence) — both CAN redden, by moving
    // `ports.require_effect_replay_authority` (`src/process_execution.rs:4021`)
    // to AFTER the executor handoff (`:4141-4146`) so a replay resumes the
    // effect instead of being refused, and by emitting `start_committed` from
    // the `Err` arm of `start_in_context` (`:2951-2962`) rather than only from
    // the `Ok` arm under `!replayed` (`:2942-2948`). The retained-identity
    // comparison below is the independent, non-absence witness of the same
    // fact, and it reddens on the first mutation because `ports.execute` would
    // then overwrite the executor's retained state for this operation.
    assert!(
        !event_present(&logs, "kernel.process.start_handoff"),
        "a replay may never hand the operation to the executor again: {logs}"
    );
    assert!(
        !event_present(&logs, "kernel.process.start_committed"),
        "a replay may never claim a committed start: {logs}"
    );
    // The executor still retains the FIRST launch's state, and the Job it is
    // attached to still reports a live member. This pins that no second launch
    // replaced it: the retained identity is unchanged across the replay. It is a
    // comparison of retained state, not an OS re-read.
    let view_after = fixture
        .live_handle(operation)
        .await
        .expect("the first launch's retained operation is still present");
    assert_eq!(view_after.lifecycle(), ProcessLifecycle::Running);
    assert_eq!(
        view_after.identity(),
        view_before.identity(),
        "the executor's retained identity is unchanged across the replay, so the replay did not \
         replace the first launch's state with a second one"
    );
    assert_eq!(view_after.identity(), Some(first.identity()));
    assert_eq!(fixture.durable_record(operation), Some(durable));
    drop(fixture);
    cleanup_launch_root("w5");
}

// WORK_UNIT_CASE: 901/8
#[cfg(windows)]
#[tokio::test]
async fn an_exact_replay_neither_launches_again_nor_commits_a_start_again() {
    let fixture = launch_fixture("w23");
    let operation = "kernel-901-w23";
    let admission = fixture.admission(operation, &LaunchFixture::executable_sha256());
    let admission_identity = fixture.assert_same_admission_identity(operation, &admission);
    let (first, durable, view_before) = committed_launch(&fixture, operation, &admission).await;
    assert_eq!(durable.admission_digest, admission_identity);

    let (result, logs) = capture_with(|| {
        let fixture = &fixture;
        let admission = admission.clone();
        async move {
            let context = ProcessExecutionGateway::start_context_for(&fixture.owner, &admission);
            let proof = fixture.path_proof(&admission);
            let outer = launch_outer_binding(&fixture.owner);
            fixture
                .gateway
                .start_in_context(&fixture.owner, admission, proof, outer, &context)
                .await
        }
    })
    .await;

    // The refusal must be the REPLAY gate's own, and this case is only
    // discriminating because it says so. `is_err()` plus the two zero counts
    // below hold identically when the store refuses a DIFFERENT admission
    // (`Unavailable` at the registration seam, `start_registration` observed as
    // `unavailable`) — the denial observations and the returned variant are what
    // separate the two, and they can only be produced from the `Existing` arm
    // that this digest identity is what reaches.
    assert_eq!(
        event_count(&logs, "kernel.process.start_registration"),
        1,
        "the replay is answered from the recorded registration exactly once: {logs}"
    );
    assert_eq!(
        event_outcome(&logs, "kernel.process.start_registration"),
        "existing",
        "a registration conflict would be observed as `unavailable`, not `existing`: {logs}"
    );
    assert_eq!(
        event_outcome(&logs, "kernel.process.effect_replay_denied"),
        "shadow_only",
        "the replay gate refuses a start this generation never authorized: {logs}"
    );
    assert!(
        matches!(
            result,
            Err(ProcessExecutionError::Contract(
                eliot_process::ContractError::DispatchBindingMismatch
            ))
        ),
        "the replay gate's own conflict must be the returned one: {result:?}"
    );

    // No launch handoff and no committed-start claim: those are the two
    // production steps that would make the replay a second start.
    //
    // REGRESSION GUARD (absence) — both CAN redden, by the two mutations named
    // in the sibling exact-replay case above: replay-gate-after-handoff
    // (`src/process_execution.rs:4021` moved past `:4141-4146`) emits
    // `start_handoff`, and a `start_committed` emitted from the `Err` arm of
    // `start_in_context` (`:2951-2962`) emits the claim. The durable-row
    // comparison further down is the non-absence witness and fails on the first
    // mutation too, because a second `persist_completed` would rewrite the row
    // this case then compares byte-for-byte.
    assert_eq!(event_count(&logs, "kernel.process.start_handoff"), 0);
    assert_eq!(event_count(&logs, "kernel.process.start_committed"), 0);
    assert_eq!(
        event_outcome(&logs, "kernel.process.start_failed"),
        "rejected"
    );

    // The committed-start claim is one durable row, and the replay left it
    // byte-identical: same admission digest, same owner, same single receipt.
    let after = fixture
        .durable_record(operation)
        .expect("the committed start record survives the replay");
    assert_eq!(after, durable);
    assert_eq!(after.admission_digest, durable.admission_digest);
    assert_eq!(after.owner, fixture.owner);
    assert_eq!(after.receipt.as_ref(), Some(&first));

    // No second start: the executor's retained state for this operation is the
    // first launch's and is unchanged, and the Job it is attached to still
    // reports a live member. Retained-state comparison, not an OS re-read.
    let view_after = fixture
        .live_handle(operation)
        .await
        .expect("the first launch's retained operation is still present");
    assert_eq!(view_after.lifecycle(), view_before.lifecycle());
    assert_eq!(view_after.identity(), view_before.identity());
    drop(fixture);
    cleanup_launch_root("w23");
}

// ---------------------------------------------------------------------------
// W25 — a changed same-operation payload retains the ACTUAL conflict.
// ---------------------------------------------------------------------------

// WORK_UNIT_CASE: 901/9
#[cfg(windows)]
#[tokio::test]
async fn a_changed_same_operation_payload_retains_the_actual_store_conflict() {
    let fixture = launch_fixture("w25");
    let operation = "kernel-901-w25";
    let original = fixture.admission(operation, &LaunchFixture::executable_sha256());
    let (_first, durable, _view) = committed_launch(&fixture, operation, &original).await;

    let changed = fixture.admission_with_tree(
        operation,
        &LaunchFixture::executable_sha256(),
        "kernel-901-changed-tree",
    );
    let original_digest = LaunchFixture::digest(&original);
    let changed_digest = LaunchFixture::digest(&changed);
    assert_eq!(
        durable.admission_digest, original_digest,
        "the committed start was recorded under exactly the admission this case changes"
    );
    assert_ne!(
        original_digest, changed_digest,
        "only the admitted payload may differ for the same operation identity"
    );

    let (result, logs) = capture_with(|| {
        let fixture = &fixture;
        let changed = changed.clone();
        async move {
            let context = ProcessExecutionGateway::start_context_for(&fixture.owner, &changed);
            let proof = fixture.path_proof(&changed);
            let outer = launch_outer_binding(&fixture.owner);
            fixture
                .gateway
                .start_in_context(&fixture.owner, changed, proof, outer, &context)
                .await
        }
    })
    .await;

    // The conflict is the DURABLE store's own typed conflict about this exact
    // operation identity, retained verbatim — not a summarised start refusal and
    // not the effect-replay gate's binding mismatch.
    let Err(ProcessExecutionError::Unavailable(detail)) = result else {
        panic!("a changed same-operation payload must be refused: {result:?}");
    };
    assert!(
        detail.contains("existing operation identity, digest, or owner conflicts"),
        "the store's own conflict reason must be retained, got: {detail}"
    );
    assert_eq!(
        event_outcome(&logs, "kernel.process.start_registration"),
        "unavailable",
        "the conflict is decided by the registration seam itself: {logs}"
    );
    //
    // REGRESSION GUARD (absence) — all three CAN redden, and none of them is
    // satisfied merely because its emitter is unreachable from this fixture.
    // Moving `ports.require_effect_replay_authority`
    // (`src/process_execution.rs:4021`) ABOVE the `record.admission_digest !=
    // digest || record.owner != *owner` conflict check (`:4005-4009`) makes this
    // conflicting payload emit `effect_replay_denied`; doing the same to the
    // handoff (`:4141-4146`) emits `start_handoff`; and emitting
    // `start_committed` from the `Err` arm of `start_in_context` (`:2951-2962`)
    // emits the claim. Each is a reordering of production steps, not a new
    // owner, so each is a legitimate mutation this guard must catch.
    assert!(
        !event_present(&logs, "kernel.process.effect_replay_denied"),
        "a payload conflict must not be reported as an effect-replay denial: {logs}"
    );
    assert!(!event_present(&logs, "kernel.process.start_handoff"));
    assert!(
        !event_present(&logs, "kernel.process.start_committed"),
        "a conflicting payload may never claim a committed start: {logs}"
    );
    assert_eq!(
        terminal_code(&logs),
        "process_unavailable",
        "the conflict projects its own stable terminal code: {logs}"
    );
    // The recorded outcome is untouched by the conflicting attempt.
    assert_eq!(fixture.durable_record(operation), Some(durable));
    drop(fixture);
    cleanup_launch_root("w25");
}

// ---------------------------------------------------------------------------
// W29 — owner generation and physical start identity are exact.
//
// `ProcessOwnerBinding` derives `PartialEq` over exactly four coordinates, so
// generation alone is the discriminator here; the physical leg is the EXISTING
// `ProcessStartReplayRecord::validate`, never a recomputed value.
//
// The two legs the item names are separate claims about separate owners, so each
// is a named step: the owner leg is decided by the durable registration seam,
// the physical leg by the durable record's own validator.
// ---------------------------------------------------------------------------

/// Owner-generation leg: generation alone is the discriminator, and the
/// production registration seam — not a comparison recomputed here — refuses a
/// substituted generation under the SAME operation identity and the SAME
/// admission digest.
///
/// The operation identity is read back off the committed record rather than
/// passed in, so the conflict below is provably about this record's own row.
fn owner_generation_leg_is_exact(fixture: &LaunchFixture, durable: &ProcessStartReplayRecord) {
    let operation = durable.operation_id.as_str();
    // Generation alone is the discriminator: every other owner coordinate is
    // byte-identical between the two bindings, so a refusal below can only be
    // about generation.
    let recorded_owner = fixture.owner.clone();
    let substituted_owner = test_owner(2);
    assert_ne!(recorded_owner, substituted_owner);
    assert_eq!(recorded_owner.module_id(), substituted_owner.module_id());
    assert_eq!(
        recorded_owner.principal_digest(),
        substituted_owner.principal_digest()
    );
    assert_eq!(
        recorded_owner.authority_epoch(),
        substituted_owner.authority_epoch()
    );
    assert_eq!(recorded_owner.generation().get(), 1);
    assert_eq!(substituted_owner.generation().get(), 2);

    // The durable registration seam refuses the substituted generation under the
    // SAME operation identity and the SAME admission digest, because the
    // recorded owner differs.
    assert_eq!(
        fixture
            .store
            .begin_process_start(durable)
            .expect("an exact replay is answered from the recorded row"),
        Some(durable.clone()),
        "the exact owner and digest resume the recorded outcome"
    );
    let substituted = ProcessStartReplayRecord {
        owner: substituted_owner.clone(),
        ..durable.clone()
    };
    assert!(
        matches!(
            fixture.store.begin_process_start(&substituted),
            Err(eliot_ors::OrsError::IntegrityProblem { .. })
        ),
        "a PID-reused generation may not present itself as the recorded owner"
    );
    // The same refusal, read back through the production registration seam. The
    // digest is asserted equal to the recorded one first, so the conflict below
    // can only be about the owner and not about a different admission.
    let replayed_admission = fixture.admission(operation, &LaunchFixture::executable_sha256());
    let digest = LaunchFixture::digest(&replayed_admission);
    assert_eq!(
        digest, durable.admission_digest,
        "the replayed admission digest is exactly the recorded one"
    );
    let seam_error = ProcessStartPorts::begin(
        &fixture.gateway,
        &OperationId::new(operation).expect("operation id"),
        &digest,
        &substituted_owner,
    )
    .expect_err("the production registration seam must refuse a substituted owner");
    assert!(
        matches!(&seam_error, ProcessExecutionError::Unavailable(detail) if detail.contains("existing operation identity, digest, or owner conflicts")),
        "the production seam must retain the store's own conflict: {seam_error:?}"
    );
    assert_eq!(fixture.durable_record(operation), Some(durable.clone()));
}

/// Physical leg, refusals only: the EXISTING validator accepts the real record
/// and refuses exactly the substitutions production compares. The set is read
/// off production, not invented:
///
/// * `PhysicalProcessBinding::validate` rejects `process_id == 0 ||
///   start_time_100ns == 0` and nothing else about the physical tuple;
/// * `ProcessStartReceipt::validate` rejects a receipt whose `binding` no
///   longer matches its observed `identity` (tree/job/image/session/generation);
/// * `ProcessStartReplayRecord::validate` rejects a completed receipt that
///   does not bind the record's own reserved operation.
fn durable_record_refuses_foreign_physical_identity(durable: &ProcessStartReplayRecord) {
    durable
        .validate()
        .expect("the real committed record validates");
    let mut zero_start = serde_json::to_value(durable).expect("durable wire");
    zero_start["receipt"]["identity"]["suspended"]["physical"]["start_time_100ns"] =
        serde_json::json!(0);
    let zero_start: ProcessStartReplayRecord =
        serde_json::from_value(zero_start).expect("zero-start record");
    assert!(
        matches!(
            zero_start.validate(),
            Err(eliot_ors::OrsError::IntegrityProblem { .. })
        ),
        "a zero observed start time is not an exact physical identity"
    );
    // A foreign identity coordinate IS refused, and this is the check production
    // really performs: the receipt's binding must still match the identity the
    // receipt claims to have observed.
    let mut foreign_binding = serde_json::to_value(durable).expect("durable wire");
    foreign_binding["receipt"]["binding"]["process_tree_id"] =
        serde_json::json!("kernel-901-foreign-tree");
    let foreign_binding: ProcessStartReplayRecord =
        serde_json::from_value(foreign_binding).expect("foreign-binding record");
    assert!(
        matches!(
            foreign_binding.validate(),
            Err(eliot_ors::OrsError::IntegrityProblem { .. })
        ),
        "a receipt whose binding no longer matches its observed identity is not the recorded identity"
    );
    // A completed receipt for a DIFFERENT operation is refused by the record
    // validator, which is the one place a receipt is tied back to the operation
    // it was reserved for.
    let mut foreign_operation = serde_json::to_value(durable).expect("durable wire");
    foreign_operation["receipt"]["binding"]["operation_id"] =
        serde_json::json!("kernel-901-w29-foreign-operation");
    let foreign_operation: ProcessStartReplayRecord =
        serde_json::from_value(foreign_operation).expect("foreign-operation record");
    assert!(
        matches!(
            foreign_operation.validate(),
            Err(eliot_ors::OrsError::IntegrityProblem { .. })
        ),
        "a completion receipt that does not bind the reserved operation is not this record's receipt"
    );
}

/// Physical leg, the boundary production does NOT draw. These two assertions
/// exist so the refusal set above is never read as more than it is.
///
/// Production does not tie `receipt.binding.permit_digest` to the record's
/// `admission_digest`, and it does not compare a well-formed non-zero creation
/// marker against any external truth: `validate_hex_digest` accepts any
/// 64-character lowercase hex string and `PhysicalProcessBinding::validate`
/// accepts any non-zero pair. Both are asserted HERE as accepted, because each
/// assertion first proves the substitution really changed the value, so a
/// green result is a recorded limit and not a silent gap.
///
/// What that leaves genuinely unproven, stated without hedging: NOTHING in this
/// file proves a recorded permit digest is the permit that authorized the start,
/// and NOTHING in this file proves a recorded creation marker is the marker of
/// the process that is running. The permit digest is authenticated only where it
/// is issued, which this capsule does not reach. A creation marker is compared
/// only against another stored value — production's own comparison lives in
/// `ProcessExecutionGateway::inspect_exact_running_receipt_in_context`
/// (`src/process_execution.rs:3120-3145`), which compares a PRESENTED receipt
/// against the executor's retained state and the durable row. Neither of those is
/// an OS handle re-read: `WindowsProcessExecutor::inspect_inner` returns
/// `guard.state.view()` (`crates/instrument/eliot-process-executor/src/lib.rs:2768`)
/// after `refresh_operation` has observed only the Job's ACTIVE PROCESS COUNT
/// (`RunningJobObservation::Running { active_processes }`,
/// `crates/kernel/eliot-platform-windows/src/process_job.rs:2739-2742`), which
/// carries no pid and no creation marker. So the pid-and-marker tuple in a
/// durable record is never re-verified against the OS anywhere reachable from
/// here, and a fabricated non-zero marker is indistinguishable from an observed
/// one to every check in this file.
fn durable_record_does_not_verify_permit_or_creation_markers(durable: &ProcessStartReplayRecord) {
    let mut forged_permit = serde_json::to_value(durable).expect("durable wire");
    forged_permit["receipt"]["binding"]["permit_digest"] = serde_json::json!("f".repeat(64));
    let forged_permit: ProcessStartReplayRecord =
        serde_json::from_value(forged_permit).expect("forged-permit record");
    assert_ne!(
        forged_permit
            .receipt
            .as_ref()
            .map(ProcessStartReceipt::permit_digest),
        durable
            .receipt
            .as_ref()
            .map(ProcessStartReceipt::permit_digest),
        "the substitution really changed the recorded permit digest, so the acceptance below is \
         about a genuinely foreign one"
    );
    assert!(
        forged_permit.validate().is_ok(),
        "the durable validator is NOT an integrity oracle over permit digests: it accepts a \
         well-formed foreign one, so this case proves nothing about permit binding"
    );
    let mut unmade_creation_marker = serde_json::to_value(durable).expect("durable wire");
    unmade_creation_marker["receipt"]["identity"]["suspended"]["physical"]["start_time_100ns"] =
        serde_json::json!(1);
    let unmade_creation_marker: ProcessStartReplayRecord =
        serde_json::from_value(unmade_creation_marker).expect("unmade-creation-marker record");
    assert_ne!(
        unmade_creation_marker
            .receipt
            .as_ref()
            .map(|receipt| receipt.identity().physical().start_time_100ns()),
        durable
            .receipt
            .as_ref()
            .map(|receipt| receipt.identity().physical().start_time_100ns()),
        "the fabricated creation marker really differs from the observed one"
    );
    assert!(
        unmade_creation_marker.validate().is_ok(),
        "a fabricated but non-zero creation marker is ACCEPTED by the durable validator, unlike \
         the zero case the refusal step pins; nothing reachable from here re-reads the OS to \
         tell this apart from an observed marker, so this case does not prove the durable record \
         detects PID reuse"
    );
}

// WORK_UNIT_CASE: 901/10
#[cfg(windows)]
#[tokio::test]
async fn owner_generation_and_physical_start_identity_are_exact() {
    let fixture = launch_fixture("w29");
    let operation = "kernel-901-w29";
    let admission = fixture.admission(operation, &LaunchFixture::executable_sha256());
    let admission_identity = fixture.assert_same_admission_identity(operation, &admission);
    let (first, durable, _view) = committed_launch(&fixture, operation, &admission).await;
    assert_eq!(durable.admission_digest, admission_identity);

    owner_generation_leg_is_exact(&fixture, &durable);
    durable_record_refuses_foreign_physical_identity(&durable);
    durable_record_does_not_verify_permit_or_creation_markers(&durable);

    // The real receipt is untouched by every substitution above.
    assert_eq!(durable.receipt.as_ref(), Some(&first));
    assert_eq!(fixture.durable_record(operation), Some(durable));
    drop(fixture);
    cleanup_launch_root("w29");
}

// ---------------------------------------------------------------------------
// W9 — a registered intent, an OS launch, a live handle and a committed receipt
// are different evidence.
//
// "Live handle" here means the executor's RETAINED view plus a Job liveness
// count, NOT an OS re-read: `inspect_inner` returns `guard.state.view()`
// (`crates/instrument/eliot-process-executor/src/lib.rs:2768`) after observing
// only `active_processes: u32`. So the executor genuinely holds a live handle,
// but nothing on this path reads the pid or creation marker back out of it, and
// the identity comparison below is agreement between the executor's retained
// state and the receipt minted from that same state — not PID-reuse detection.
//
// The two steps that are separable claims about an owner other than the case
// itself are named helpers rather than inline: a registered intent as a durable
// reservation, and what the committed record's own validator decides and cannot.
// Keeping them out of the test body keeps the four evidence kinds the item
// compares legible.
// ---------------------------------------------------------------------------

/// Step one: a REGISTERED INTENT is a durable reservation and nothing more.
///
/// The row is created and read back through the real store, shown to carry no
/// receipt at all, and then released by the production abort. Releasing it is
/// what makes the launch that follows the FIRST start of this operation rather
/// than a replay of the reservation.
fn a_registered_intent_is_a_reservation_without_a_receipt(
    fixture: &LaunchFixture,
    operation: &str,
    digest: &str,
) {
    // (1) A REGISTERED INTENT is a durable reservation: a row whose state says
    // the operation is registered and which carries no receipt at all, so it
    // names no pid, no start time and no image.
    let operation_identity = OperationIdentity::new(operation).expect("operation identity");
    assert_eq!(
        fixture
            .store
            .begin_process_start(&ProcessStartReplayRecord {
                operation_id: operation_identity.clone(),
                admission_digest: digest.to_owned(),
                owner: fixture.owner.clone(),
                state: ProcessStartReplayState::Reserved,
                receipt: None,
            })
            .expect("durable reservation"),
        None,
        "the first reservation of this operation acquires it"
    );
    let reserved = fixture
        .durable_record(operation)
        .expect("durable reservation read back");
    assert_eq!(reserved.state, ProcessStartReplayState::Reserved);
    assert!(reserved.receipt.is_none());
    let reserved_wire = serde_json::to_value(&reserved).expect("reserved wire");
    assert!(
        reserved_wire["receipt"].is_null(),
        "a registered intent carries no receipt and therefore no physical identity: {reserved_wire}"
    );
    assert!(reserved.validate().is_ok());

    // The registration is released by the production abort, which is what makes
    // the launch below the FIRST start of this operation rather than a replay.
    assert!(matches!(
        fixture
            .store
            .abort_process_start(&operation_identity, digest, &fixture.owner)
            .expect("durable abort"),
        eliot_ors::ProcessStartReplayAbort::Released
    ));
    assert!(fixture.durable_record(operation).is_none());
}

/// Durable-record leg: the exact substitutions the EXISTING
/// `ProcessStartReplayRecord::validate` refuses on the committed row, and the one
/// fabricated physical coordinate it accepts.
///
/// Refused, because production compares them:
///
/// * a physical coordinate of zero is not an identity
///   (`PhysicalProcessBinding::validate`);
/// * a receipt whose binding no longer matches its observed identity is refused
///   (`ProcessStartReceipt::validate` via `matches_identity`).
///
/// NOT refused, and asserted here as accepted so it is a recorded limit rather
/// than a gap: production does not compare a well-formed NON-ZERO creation marker
/// to anything external, so a fabricated `start_time_100ns` of 1 validates. That
/// is precisely why the live-handle agreement asserted in the case body, and not
/// this validator, is the evidence that the recorded creation marker is real.
fn durable_record_refusals_and_limits_are_pinned(durable: &ProcessStartReplayRecord) {
    let mut zero_pid = serde_json::to_value(durable).expect("durable wire");
    zero_pid["receipt"]["identity"]["suspended"]["physical"]["process_id"] = serde_json::json!(0);
    let zero_pid: ProcessStartReplayRecord =
        serde_json::from_value(zero_pid).expect("zero-pid record");
    assert!(
        matches!(
            zero_pid.validate(),
            Err(eliot_ors::OrsError::IntegrityProblem { .. })
        ),
        "the durable claim rejects an absent physical process id"
    );
    let mut foreign_binding = serde_json::to_value(durable).expect("durable wire");
    foreign_binding["receipt"]["binding"]["image_id"] =
        serde_json::json!("kernel-901-foreign-image");
    let foreign_binding: ProcessStartReplayRecord =
        serde_json::from_value(foreign_binding).expect("foreign-binding record");
    assert!(
        matches!(
            foreign_binding.validate(),
            Err(eliot_ors::OrsError::IntegrityProblem { .. })
        ),
        "the durable claim rejects a receipt bound to an identity it did not observe"
    );
    let mut unmade_creation_marker = serde_json::to_value(durable).expect("durable wire");
    unmade_creation_marker["receipt"]["identity"]["suspended"]["physical"]["start_time_100ns"] =
        serde_json::json!(1);
    let unmade_creation_marker: ProcessStartReplayRecord =
        serde_json::from_value(unmade_creation_marker).expect("unmade-creation-marker record");
    assert_ne!(
        unmade_creation_marker
            .receipt
            .as_ref()
            .map(|recorded| recorded.identity().physical().start_time_100ns()),
        durable
            .receipt
            .as_ref()
            .map(|recorded| recorded.identity().physical().start_time_100ns()),
        "the fabricated creation marker really differs from the observed one"
    );
    assert!(
        unmade_creation_marker.validate().is_ok(),
        "a fabricated but non-zero creation marker is ACCEPTED by the durable validator, so this \
         case does NOT prove the durable record detects PID reuse"
    );
}

// WORK_UNIT_CASE: 901/6
#[cfg(windows)]
#[tokio::test]
async fn registered_intent_os_launch_live_handle_and_receipt_are_different_evidence() {
    let fixture = launch_fixture("w9");
    let operation = "kernel-901-w9";
    let admission = fixture.admission(operation, &LaunchFixture::executable_sha256());
    // The reservation aborted here, the start committed below and the replay at
    // the end must all be ONE admission identity, or the replay is refused by the
    // durable store as a conflicting digest instead of by the replay gate.
    let digest = fixture.assert_same_admission_identity(operation, &admission);

    // (1) A REGISTERED INTENT is a durable reservation that names no process.
    a_registered_intent_is_a_reservation_without_a_receipt(&fixture, operation, &digest);

    // (2) An OS LAUNCH and its (3) RETAINED EXECUTOR VIEW come from the production
    // executor, and (4) a COMMITTED RECEIPT is the durable row it produced.
    let (receipt, durable, view) = committed_launch(&fixture, operation, &admission).await;
    assert_eq!(
        durable.admission_digest, digest,
        "the committed start carries the same admission identity the reservation and the replay use"
    );
    let receipt_wire = serde_json::to_value(&receipt).expect("receipt wire");
    let physical = &receipt_wire["identity"]["suspended"]["physical"];
    // `PhysicalProcessBinding` serializes `process_id` and `start_time_100ns`
    // unconditionally, so neither slot can be absent and a null check would be
    // vacuous. What production actually requires is that both be NON-ZERO
    // (`PhysicalProcessBinding::validate`), and that is what is pinned here.
    assert!(
        physical["process_id"]
            .as_u64()
            .is_some_and(|process_id| process_id > 0),
        "a launch receipt records a non-zero observed process id, which production requires: \
         {receipt_wire}"
    );
    assert_ne!(physical["start_time_100ns"], serde_json::json!(0));
    assert_eq!(durable.state, ProcessStartReplayState::Completed);

    // The durable receipt and the executor's retained view are SEPARATE facts that
    // must agree. What the record alone decides, and what it cannot decide, is one
    // named step.
    durable_record_refusals_and_limits_are_pinned(&durable);

    // Lifecycle is the ONE fact `inspect` freshly observes, because
    // `refresh_operation` queries the Job. The identity is NOT re-read: this
    // compares the executor's retained `ProcessIdentity` against the receipt minted
    // from that same state, so it proves the two agree and nothing about the OS.
    assert_eq!(view.lifecycle(), ProcessLifecycle::Running);
    assert_eq!(
        view.identity(),
        Some(receipt.identity()),
        "the executor's retained state and the receipt it issued carry the same ProcessIdentity; \
         this is agreement between two values derived from one retained state, NOT a re-read of \
         the OS process and NOT PID-reuse detection"
    );

    // (5) The operation span never projects a physical identity this run did
    // not observe. The replay below builds its OWN operation span from the
    // admitted request alone, observes no receipt, and so leaves the declared
    // `"unavailable"` defaults in place — a fresh span, not the launch span of
    // step (2), which is why the two facts are separate evidence.
    //
    // REGRESSION GUARD (absence) — both CAN redden, in two independent ways.
    // Deleting the declared `process_id` / `image_sha256` slots from
    // `kernel_diagnostics::operation_context` (`src/kernel_diagnostics.rs:671`
    // and `:673`) makes `span_field` resolve to `None` and fails both; and
    // calling `record_process_start_receipt_identity`
    // (`src/process_execution.rs:187`, today reachable only from the `Ok` arm
    // at `:2936`) on the replay path — for example from the `Existing` arm
    // before `require_effect_replay_authority` — writes a real value over each
    // declared default and fails both. The third assertion below is a POSITIVE
    // binding, not an absence, and fails if `record_process_start_request_context`
    // (`:145-183`) stops recording the operation.
    let (_result, logs) = capture_with(|| {
        let fixture = &fixture;
        let admission = admission.clone();
        async move {
            let context = ProcessExecutionGateway::start_context_for(&fixture.owner, &admission);
            let proof = fixture.path_proof(&admission);
            let outer = launch_outer_binding(&fixture.owner);
            fixture
                .gateway
                .start_in_context(&fixture.owner, admission, proof, outer, &context)
                .await
        }
    })
    .await;
    let replay_line = event_line(&logs, "kernel.process.effect_replay_denied");
    assert_eq!(
        span_field(replay_line, "process_id"),
        Some("unavailable"),
        "a replay that observed no receipt projects no process id: {replay_line}"
    );
    assert_eq!(
        span_field(replay_line, "image_sha256"),
        Some("unavailable"),
        "a replay that observed no receipt projects no image digest: {replay_line}"
    );
    assert_eq!(
        span_field(replay_line, "operation"),
        Some(operation),
        "the observation is still bound to THIS operation: {replay_line}"
    );
    drop(fixture);
    cleanup_launch_root("w9");
}
