#![allow(clippy::expect_used, clippy::unwrap_used)]
#![cfg(windows)]
#![allow(
    clippy::too_many_lines,
    reason = "each case drives several real boundaries of one frozen #901 checklist item"
)]

//! Kernel unknown-outcome boundary proof — issue #901 (F-LOG-KERNEL-3),
//! checklist items W22 and W26.
//!
//! * W22 — "Possible launch or response loss after a timeout or disconnect
//!   remains unknown under its original operation."
//! * W26 — "A timeout or disconnect after possible execution remains unknown."
//!
//! The #901-owned boundary lives in the private `mod process_execution` with
//! `pub(crate)` entry points, so this suite is registered as a crate-internal
//! `#[cfg(test)]` module (see `src/lib.rs`) and reaches it through
//! `use super::*`, exactly as `src/tests/local_read_claim.rs` and the sibling
//! #901 capsules do. Every case drives a REAL `ProcessExecutionGateway` over a
//! REAL durable `RedbRecoveryStore` and the REAL production
//! `WindowsProcessExecutor` `ProcessExecutionGateway::new` installs.
//!
//! * W22 drives `ProcessExecutionGateway::cancel` (`:3149`) ->
//!   `cancel_in_context` (`:3160`) -> `cancel_with_origin_grant_in_context`
//!   (`:3172`; its grant-fence arm at `:3185` is skipped by `grant = None`) ->
//!   `cancel_with_origin_grant_inner` (`:3196`). It pins that the span is built
//!   from THIS call's `OperationId` (`:3154`), that
//!   `cancel_requested`/`attempt` (`:3206`) is followed by
//!   `cancel_failed`/the literal `unknown` (`:3300`), that EXACTLY ONE terminal
//!   is emitted and its code is `process_terminal_code(&UnknownOutcome)`
//!   (`:3301`-`:3304` through `:236`-`:244`), that the caller receives the
//!   typed `Err(UnknownOutcome)` (`:3305`), and that `owner_admitted`/`success`
//!   (`:4528`) is the subordinate read which authorized the attempt. Two
//!   distinct operations and a retry of the first prove each capture reads its
//!   OWN identity and never the other's.
//!
//! * W26 drives the same `cancel` and `reconcile` (`:3505`) boundaries, so
//!   `authorize_process_owner_in_context` (`:4520`) -> `owner_admitted`/
//!   `success` (`:4528`) really is on the path. Its positive arm is the
//!   possible-effect cancel; its two refusal arms isolate the two mutable
//!   coordinates of the derived `PartialEq` on `ProcessOwnerBinding` — the
//!   first presents a foreign PRINCIPAL holding `module_id` fixed, the second a
//!   foreign MODULE identity holding the principal, epoch and generation fixed —
//!   and production refuses both at `:3225` with `cancel_rejected`/`fenced` and
//!   the typed `Contract(DispatchBindingMismatch)` from `:4524`.
//!
//! THE ACCEPTANCE LIMITS THIS SUITE STATES INSTEAD OF FAKING
//!
//! 1. `outcome="unknown"` is NOT an oracle for an unknown outcome.
//!    `reconcile_in_context` emits `kernel.process.reconcile_unknown` with the
//!    literal `unknown` UNCONDITIONALLY (`:3561`) and then resolves the terminal
//!    code from the error the executor ACTUALLY returned (`:3563`). The real
//!    executor's `operation()` returns `NotFound` for an unregistered identity
//!    (`eliot-process-executor/src/lib.rs:1690`-`:1696`), and the mapper sends
//!    `NotFound` to `process_not_found` (`:239`). The third leg of W26 drives
//!    exactly that shape and asserts `unknown` TOGETHER WITH
//!    `process_not_found`, which is what forces a reader to read `code` and
//!    never `outcome`.
//!    The same fact holds for the CANCEL legs and is stated here instead of
//!    being left implied: `cancel_inner` resolves its operation first
//!    (`eliot-process-executor/src/lib.rs:2785` into `operation()` `:1690`-`:1696`),
//!    so in THIS composition the executor's typed refusal really is `NotFound`
//!    and no live child ever existed to kill. What the cancel legs therefore
//!    prove is the stronger gateway contract: `:3292` DISCARDS whatever the
//!    executor returned and projects the typed `UnknownOutcome` either way, so
//!    an effect that could have been possible can never be read back as
//!    decided. No case here claims that a kill was attempted.
//! 2. W22's LAUNCH half carries NO `unknown` literal at all.
//!    `start_in_context` passes the literal `"rejected"` to
//!    `kernel.process.start_failed` UNCONDITIONALLY (`:2956`) while `:2958`
//!    maps the very same error through the same `process_terminal_code`. There
//!    is therefore nothing truthful to assert about `unknown` on the launch
//!    path, and this suite asserts nothing about it. Reaching that boundary at
//!    all also requires a real `HostKernelCandidateBinding` outer Job that
//!    `start_in_context` takes by value, which no case here has a reason to
//!    build. Stated as a limit, not as a passing assertion.
//! 3. `reconcile_origin_grant_effect`'s unknown arm (`:2380`-`:2397`) is
//!    UNREACHABLE from a test: `:2368` gates on `live_origin_installation_id()`
//!    -> `dispatch_contour()` -> the process-wide
//!    `static DISPATCH_CONTOUR: OnceLock<..>` in `dispatch_launch.rs`, and
//!    composing that global from one case would poison every concurrent case.
//!    This suite never touches it: every call passes `grant = None`, which
//!    returns at `authorize_effect_with_grant` `:3622`-`:3624`, before the
//!    installation check at `:3645`.
//! 4. The declared `receipt` slot is NOT evidence on either boundary below, and
//!    this suite asserts nothing about it. `"unavailable"` is that slot's
//!    DECLARED default (`kernel_diagnostics.rs:676`), and the only writer of that
//!    slot in the whole Kernel is
//!    `record_process_context_field(context, "receipt", ..)` at
//!    `process_execution.rs:3391`, in the descendant-close SUCCESS arm, after
//!    that boundary's own first record (`:3342`) and after it holds a live view
//!    and a built `DescendantClosureReceipt` (`:3374`-`:3390`). The cancel path
//!    returns at `:3305` and can reach neither. What is asserted instead is the
//!    sequence of `kernel.process.*` records each path really emits
//!    (`process_event_sequence`), which CAN fail and which contains no
//!    descendant-close record at all, so a default rendering could never have
//!    been a receipt on these captures.
//!
//! Test-oracle only. It owns no process, authority, Store or daemon authority,
//! clones no production logic, induces no fault by poisoning a lock, and
//! launches no child: every refusal asserted below is production's own decision
//! on rows production itself persisted through `ProcessStartPorts::begin`.
//!
//! Architecture: A8.1, A13.2, A13.3, ARCH-WDG-01; implementation I1.4, I1.5,
//! I13.11, I14.20, I14.21, I15.4, and I02.20 (Module Test Capsule).

use super::*;

use std::collections::BTreeMap;
use std::io::Write;
use std::sync::{Arc, Mutex};

use eliot_kernel_core::{
    AuthoritySnapshotBinding, DispatchSnapshotCodec, KernelAuthorityReplaySnapshot, KernelError,
    KernelResult, SealedAuthoritySnapshot,
};
use eliot_ors::{
    EpochIdentity, EpochLineage, OpaqueLabel, OperationIdentity, RecoveryPayload,
    StateFenceSnapshot,
};
use eliot_platform::SecretReference;
use eliot_process::OperationId;

// ---------------------------------------------------------------------------
// Capture seam.
//
// `Format::format_event` (tracing-subscriber 0.3.23) writes exactly ONE opening
// brace before the whole space-separated `FormattedFields` run, so the needle is
// the bare `slot="` and never `{slot="`. `FmtLayer::on_record` appends through
// `add_fields`, which pushes a space and formats WITHOUT rewriting the declared
// slot, so a RECORDED value appears AFTER its declared default and the LAST
// occurrence of `slot="` on the line is the recorded one.
//
// `set_default` takes the subscriber BY VALUE and returns a thread-local
// `DefaultGuard`; it is deliberately NOT `with_default(subscriber, run).await`,
// because `with_default` is `fn with_default<T>(d: &Dispatch, f: impl FnOnce() ->
// T) -> T` (tracing-core `src/dispatcher.rs:254`): with an async `run` the `T`
// is the UN-POLLED future, so the guard would die before `.await` ever polls
// the body and every captured string would come back empty. No process-wide,
// set-once global installer is used anywhere in this file.
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

/// Captures one async production call.
///
/// The guard is bound for the whole awaited body, so the thread-local default
/// stays current across every poll. It is sound only because this is the
/// current-thread runtime `#[tokio::test]` builds and nothing here spawns.
///
/// EVERY span the driven boundary builds must be created INSIDE this closure:
/// a `tracing::Span` binds its dispatcher at creation and decides
/// `is_disabled()` there, so a span built before the subscriber is installed is
/// permanently inert, `record(..)` is a no-op on it and `span_field` reads
/// `None`. Each case therefore calls `ProcessExecutionGateway::cancel` /
/// `::reconcile` (which build their own span) from inside.
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
    // Named, not `_`-prefixed: the guard IS used - `drop` below orders the
    // unregistration before the sink is read.
    let guard = tracing::subscriber::set_default(subscriber);
    let value = run().await;
    drop(guard);
    let bytes = String::from_utf8_lossy(&sink.bytes.lock().expect("capture lock")).into_owned();
    (value, bytes)
}

/// Reads the RECORDED value of one `kernel.operation` span slot.
///
/// A slot the owner never recorded occurs exactly once and resolves to its
/// declared `"unavailable"` default from `kernel_diagnostics.rs:657`-`:677`,
/// which is the honest answer for it. This suite NEVER asserts that a declared
/// slot name is absent: those defaults render verbatim on every line, so such an
/// assertion would be true by construction and could not fail.
fn span_field<'a>(logs: &'a str, slot: &str) -> Option<&'a str> {
    let needle = format!("{slot}=\"");
    let start = logs.rfind(&needle)? + needle.len();
    let rest = &logs[start..];
    let end = rest.find('"')?;
    Some(&rest[..end])
}

/// The single captured line carrying one `event="..."` field. Each
/// observation is emitted as the `event` field of its own record.
fn event_line<'a>(logs: &'a str, event: &str) -> &'a str {
    logs.lines()
        .find(|line| line.contains(&format!("event=\"{event}\"")))
        .unwrap_or_else(|| panic!("no captured line carries event={event}; captured: {logs}"))
}

fn event_present(logs: &str, event: &str) -> bool {
    logs.contains(&format!("event=\"{event}\""))
}

fn event_count(logs: &str, event: &str) -> usize {
    logs.matches(&format!("event=\"{event}\"")).count()
}

/// Reads the value after the LAST occurrence of `key="` on one line.
fn quoted<'a>(line: &'a str, key: &str) -> &'a str {
    let needle = format!("{key}=\"");
    let start = line
        .rfind(&needle)
        .unwrap_or_else(|| panic!("field {key} absent from captured line: {line}"))
        + needle.len();
    let rest = &line[start..];
    let end = rest
        .find('"')
        .unwrap_or_else(|| panic!("unterminated field {key} in captured line: {line}"));
    &rest[..end]
}

fn event_outcome(logs: &str, event: &str) -> String {
    quoted(event_line(logs, event), "outcome").to_owned()
}

/// Every `kernel.terminal_error` code the run emitted, in observed order.
fn terminal_codes(logs: &str) -> Vec<String> {
    logs.lines()
        .filter(|line| line.contains("event=\"kernel.terminal_error\""))
        .map(|line| quoted(line, "code").to_owned())
        .collect()
}

/// Every `kernel.process.*` record in one capture, in EMISSION order.
///
/// That prefix is the Kernel's own reserved observation vocabulary and only
/// `observe_process_in_context` (`process_execution.rs:73`-`:88`) and its unscoped
/// wrapper `observe_process` (`:65`-`:68`) emit it in this crate, so an exact
/// comparison of the whole sequence is the boundary's own vocabulary with its own
/// counts and its own order. A record of ANY additional name shows up, including
/// a `descendant_close_*` record, which is what precedes the single writer of the
/// `receipt` slot (`:3342` before `:3391`). Unlike reading one declared default,
/// this can fail.
fn process_event_sequence(logs: &str) -> Vec<String> {
    logs.lines()
        .filter(|line| line.contains("event=\"kernel.process."))
        .map(|line| quoted(line, "event").to_owned())
        .collect()
}

/// The bounded transport refusal a caller of the front door receives for one
/// error. `execute_process_request` applies exactly this projection to every
/// failed cancel/reconcile at `process_execution.rs:4741`-`:4748`, so the
/// assertions below are about the wire the caller actually gets.
fn caller_refusal(
    error: &ProcessExecutionError,
) -> eliot_kernel_service::ProcessExecutionRejection {
    eliot_kernel_service::ProcessExecutionRejection::from_error(error)
}

// ---------------------------------------------------------------------------
// Local fixtures. Per-file duplication is this crate's house pattern: this file
// edits no existing in-crate module and creates no shared helper module.
// ---------------------------------------------------------------------------

fn unknown_outcome_epoch() -> eliot_contracts::EpochId {
    eliot_contracts::EpochId::new(
        eliot_contracts::EpochLineageId::new("550e8400-e29b-41d4-a716-446655440901")
            .expect("unknown-outcome lineage"),
        std::num::NonZeroU64::new(1).expect("unknown-outcome sequence"),
    )
    .expect("unknown-outcome epoch")
}

fn unknown_outcome_owner(module_id: &str, principal: &str) -> ProcessOwnerBinding {
    ProcessOwnerBinding::new(
        module_id,
        principal.repeat(64),
        unknown_outcome_epoch(),
        Generation::new(1).expect("generation"),
    )
    .expect("owner binding")
}

/// The `StateFence::canonical_epoch_digest` of THIS owner's authority epoch.
///
/// `record_process_owner_operation_context` (`process_execution.rs:133`) and
/// `process_operation_context` (`:103`-`:107`) both project the span's
/// `authority_epoch` slot from exactly this value, so a case that reads it back
/// is reading production's own projection and not a re-derived shape.
fn owner_epoch_digest(owner: &ProcessOwnerBinding) -> String {
    eliot_contracts::StateFence::canonical_epoch_digest(owner.authority_epoch())
        .expect("canonical owner epoch digest")
        .as_str()
        .to_owned()
}

/// The authority snapshot binding the real gateway's dispatch controller reads.
fn unknown_outcome_authority_binding(
    authority_id: &eliot_process::DispatchAuthorityId,
) -> AuthoritySnapshotBinding {
    let epoch = EpochLineage {
        current: EpochIdentity {
            lineage_id: OpaqueLabel::new("kernel-901-unknown-outcome-lineage").expect("lineage"),
            epoch: 1,
        },
        predecessor: None,
    };
    let state_fence =
        StateFenceSnapshot::capture(&serde_json::json!({"authority": "kernel-901"}), 1)
            .expect("state fence");
    AuthoritySnapshotBinding::new(
        authority_id.clone(),
        OperationIdentity::new("kernel-901-unknown-outcome-authority-record").expect("record id"),
        epoch,
        state_fence,
        1,
        None,
    )
    .expect("authority binding")
}

struct UnknownOutcomeSnapshotCodec;

impl DispatchSnapshotCodec for UnknownOutcomeSnapshotCodec {
    fn seal(
        &self,
        snapshot: &KernelAuthorityReplaySnapshot,
        _binding: &AuthoritySnapshotBinding,
    ) -> KernelResult<SealedAuthoritySnapshot> {
        let ciphertext = serde_json::to_vec(snapshot)
            .map_err(|error| KernelError::DependencyUnavailable(error.to_string()))?;
        let key = SecretReference::new("test-provider", "kernel-901-unknown-outcome-authority")
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
                "unknown-outcome fixture payload is not encrypted".to_owned(),
            ));
        };
        serde_json::from_slice(ciphertext)
            .map_err(|error| KernelError::RecoveryUnavailable(error.to_string()))
    }
}

/// Owns one case's work root and removes it on drop.
///
/// It is bound BEFORE the composition it holds, so Rust's reverse declaration
/// order drops the composition FIRST and the directory goes with its handles
/// closed.
struct UnknownOutcomeTempRoot(std::path::PathBuf);

impl Drop for UnknownOutcomeTempRoot {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// One real composition: a real durable ORS, the real production
/// `ProcessExecutionGateway`, and the real production `WindowsProcessExecutor`
/// that `ProcessExecutionGateway::new` installs.
///
/// The fixture also KEEPS the ORS handle, because the value both authorization
/// paths compare is the owner loaded back out of this store, not one of the
/// owner objects this file constructed: `authorize_effect_with_grant` reads the
/// row at `process_execution.rs:3616`-`:3620` and `authorize_operation` at
/// `:3577`-`:3581`, and both hand that RECORDED owner to
/// `authorize_process_owner_in_context` (`:4520`). `recorded_owner` below reads
/// that same row back through the store's own public seam.
struct UnknownOutcomeFixture {
    gateway: ProcessExecutionGateway,
    owner: ProcessOwnerBinding,
    foreign_owner: ProcessOwnerBinding,
    store: Arc<RedbRecoveryStore>,
}

fn unknown_outcome_root(tag: &str) -> std::path::PathBuf {
    std::env::temp_dir().join(format!(
        "eliot-kernel-901-unknown-outcome-{tag}-{}-{}",
        std::process::id(),
        unix_ms()
    ))
}

/// A real admitted start request. Nothing here is launched: the reservation is
/// the production `ProcessStartPorts::begin` row the cancel/reconcile boundaries
/// read back, and its `admission_digest` is production's own projection of the
/// admitted request rather than a test-chosen string.
fn unknown_outcome_admission(operation: &str) -> ProcessExecutionAdmissionRequest {
    let generation = Generation::new(1).expect("generation");
    let executable = std::path::PathBuf::from(std::env::var("SystemRoot").expect("SystemRoot"))
        .join("System32")
        .join("ping.exe");
    let working_directory = executable
        .parent()
        .expect("child image directory")
        .to_path_buf();
    let intent = ProcessIntent::new(
        OperationId::new(operation).expect("operation id"),
        ProcessTreeId::new(format!("kernel-901-unknown-outcome-tree-{operation}"))
            .expect("process tree"),
        JobId::new(format!("kernel-901-unknown-outcome-job-{operation}")).expect("logical Job id"),
        ImageId::new(format!("kernel-901-unknown-outcome-image-{operation}")).expect("image id"),
        SessionId::new(format!("kernel-901-unknown-outcome-session-{operation}"))
            .expect("session id"),
        generation,
        executable.to_string_lossy(),
        sha256_hex(&std::fs::read(&executable).expect("child image bytes")),
        vec!["-n".to_owned(), "1".to_owned(), "127.0.0.1".to_owned()],
        working_directory.to_string_lossy(),
        EnvironmentProjection::new(BTreeMap::new(), Vec::new(), EnvironmentInheritance::None)
            .expect("closed child environment"),
        ResourceLimits::new(60_000, Some(45_000), None, 64 * 1024, 64 * 1024, 4)
            .expect("resource limits"),
    )
    .expect("unknown-outcome intent");
    ProcessExecutionAdmissionRequest::new(
        ACTIVE_DAEMON_CALLER,
        intent,
        ActionLeaseRef::new(format!("kernel-901-unknown-outcome-lease-{operation}"))
            .expect("action lease"),
        FencingToken::new(
            unknown_outcome_epoch(),
            generation,
            "kernel-901-unknown-outcome-fence",
        )
        .expect("state fence"),
        unix_ms().saturating_add(120_000),
    )
    .expect("unknown-outcome admission")
}

fn unknown_outcome_fixture(tag: &str) -> (UnknownOutcomeTempRoot, UnknownOutcomeFixture) {
    let root = unknown_outcome_root(tag);
    std::fs::create_dir_all(&root).expect("unknown-outcome fixture root");
    let store = Arc::new(
        RedbRecoveryStore::open(root.join("kernel-ors.redb")).expect("unknown-outcome fixture ORS"),
    );
    let authority_id =
        eliot_process::DispatchAuthorityId::new("kernel-901-unknown-outcome-authority")
            .expect("authority id");
    let snapshot_binding = unknown_outcome_authority_binding(&authority_id);
    let authority_store: Arc<dyn OperationalRecoveryStore> = Arc::clone(&store) as Arc<_>;
    let codec: Arc<dyn DispatchSnapshotCodec> = Arc::new(UnknownOutcomeSnapshotCodec);
    let controller = Arc::new(Mutex::new(ProcessDispatchAuthorityController::activate(
        authority_id,
        eliot_process::KernelDispatchKey::from_secret_bytes([0x2f; 32]).expect("dispatch key"),
        authority_store,
        codec,
    )));
    let platform =
        Arc::new(WindowsPlatform::new(root.join("containment")).expect("fixture containment root"));
    let path_admission = Arc::new(KernelPathAdmission::new(Arc::clone(&platform)));
    (
        UnknownOutcomeTempRoot(root),
        UnknownOutcomeFixture {
            gateway: ProcessExecutionGateway::new(
                controller,
                Arc::clone(&store),
                snapshot_binding,
                path_admission,
            ),
            owner: unknown_outcome_owner(ACTIVE_DAEMON_CALLER, "a"),
            foreign_owner: unknown_outcome_owner(ACTIVE_DAEMON_CALLER, "b"),
            store,
        },
    )
}

impl UnknownOutcomeFixture {
    /// Reserves one operation durably through the PRODUCTION seam, with no OS
    /// launch behind it. The cancel/reconcile boundaries read this row back
    /// through `authorize_effect_with_grant` / `authorize_operation`, so the
    /// owner authorization they perform is against real owner evidence
    /// production itself persisted.
    fn reserve_without_launch(&self, operation: &str) -> OperationId {
        let admission = unknown_outcome_admission(operation);
        let operation_id = admission.intent().operation_id().clone();
        let digest = process_admission_digest(&admission).expect("admission digest");
        let begun = ProcessStartPorts::begin(&self.gateway, &operation_id, &digest, &self.owner)
            .expect("production start reservation");
        assert_eq!(
            begun,
            ProcessExecutionReplayBegin::Acquired,
            "a fresh operation identity owns its only reservation"
        );
        operation_id
    }

    /// The owner PRODUCTION persisted for one reserved operation, read back
    /// through `RedbRecoveryStore::load_process_start`
    /// (`eliot-ors/src/store.rs:5651`-`:5673`).
    ///
    /// This is the left operand of the comparison both boundaries actually
    /// make: `authorize_effect_with_grant` (`:3616`-`:3621`) and
    /// `authorize_operation` (`:3577`-`:3582`) pass `record.owner` — never the
    /// caller's own copy — to `authorize_process_owner_in_context` (`:4520`).
    /// Reading it back here is what keeps the admitted/refused premises below
    /// bound to production's own durable row instead of to a second reference to
    /// the fixture's own owner objects: a reservation that stored, or a readback
    /// that returned, a different owner would move production's operand while
    /// every premise written against the fixture stayed green.
    fn recorded_owner(&self, operation: &str) -> ProcessOwnerBinding {
        let identity = OperationIdentity::new(operation).expect("recorded operation identity");
        self.store
            .load_process_start(&identity)
            .expect("recorded process start readback")
            .unwrap_or_else(|| panic!("production persisted no process-start row for {operation}"))
            .owner
    }
}

/// The two operation identities W22 correlates. Neither is a prefix or a
/// substring of the other, so "this capture never mentions the other's
/// identity" is a real assertion and not a coincidence of naming.
const W22_ALPHA: &str = "kernel-901-w22-alpha";
const W22_BETA: &str = "kernel-901-w22-beta";

/// Every `kernel.process.cancel_*` record in one capture.
fn cancel_record_lines(logs: &str) -> Vec<&str> {
    logs.lines()
        .filter(|line| line.contains("event=\"kernel.process.cancel"))
        .collect()
}

// ---------------------------------------------------------------------------
// W22 — possible launch or response loss after a timeout or disconnect remains
// unknown under its ORIGINAL operation.
//
// The response-loss arm is the whole of what production enforces on this
// boundary, and it is deterministic: `cancel_with_origin_grant_inner` guards the
// executor call with `let Ok(receipt) = self.executor.cancel(operation_id)
// .await else` (`:3292`), so whatever the executor actually returned — and in
// this composition that is a typed `NotFound` for an identity the executor never
// registered, see header limit 1 — the possible kill effect is projected as the
// typed unknown outcome (`:3300`-`:3305`). The LAUNCH half carries no `unknown`
// literal at all - see the limit note in the module header.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn possible_launch_or_response_loss_stays_unknown_under_its_original_operation() {
    let (root_guard, fixture) = unknown_outcome_fixture("w22");
    let owner = fixture.owner.clone();
    let epoch_digest = owner_epoch_digest(&owner);
    let generation_text = owner.generation().get().to_string();

    // Two real durable reservations under this owner, written by production.
    let alpha = fixture.reserve_without_launch(W22_ALPHA);
    let beta = fixture.reserve_without_launch(W22_BETA);
    assert_eq!(
        alpha.as_str(),
        W22_ALPHA,
        "ALPHA keeps the identity it was admitted with"
    );
    assert_eq!(
        beta.as_str(),
        W22_BETA,
        "BETA keeps the identity it was admitted with"
    );
    // PREMISE against production's OWN comparison operand, not a second copy of
    // this fixture's owner: the row `authorize_effect_with_grant` loads at
    // :3616-:3620 and hands to :4520 carries exactly the owner that reserved
    // both identities, so the admitted legs below compare equal objects and the
    // `owner_admitted` reading is a real admission rather than an accident of
    // two equal fixture values.
    assert_eq!(
        fixture.recorded_owner(W22_ALPHA),
        owner,
        "the durable ALPHA row production compares against IS this owner: \
         authorize_effect_with_grant reads the row, not the caller's copy"
    );
    assert_eq!(
        fixture.recorded_owner(W22_BETA),
        owner,
        "the durable BETA row is under the same owner, so BETA's leg is the \
         same admission and not a second identity read"
    );

    // ---- ALPHA, first attempt ---------------------------------------------
    let (alpha_result, alpha_logs) =
        capture_with(|| fixture.gateway.cancel(&owner, alpha.clone())).await;
    let alpha_error = alpha_result.expect_err("a cancel with no observable receipt has no receipt");
    assert!(
        matches!(alpha_error, ProcessExecutionError::UnknownOutcome),
        "an executor effect nobody observed is the typed unknown outcome, and \
         :3292 discards whatever the executor actually returned: \
         {alpha_error:?}\n{alpha_logs}"
    );
    assert_eq!(
        caller_refusal(&alpha_error).code,
        "UNKNOWN_OUTCOME",
        "the caller receives the unknown-outcome refusal"
    );

    // `cancel_requested`/`attempt` at :3206, then the literal `unknown` at
    // :3300: a possible-but-unproven effect is never projected as decided.
    assert_eq!(
        event_count(&alpha_logs, "kernel.process.cancel_requested"),
        1,
        "the cancellation boundary is entered exactly once: {alpha_logs}"
    );
    assert_eq!(
        event_outcome(&alpha_logs, "kernel.process.cancel_requested"),
        "attempt",
        "the boundary records the attempt before it knows the effect: {alpha_logs}"
    );
    assert_eq!(
        event_count(&alpha_logs, "kernel.process.cancel_failed"),
        1,
        "the possible-but-unproven effect is observed exactly once: {alpha_logs}"
    );
    assert_eq!(
        event_outcome(&alpha_logs, "kernel.process.cancel_failed"),
        "unknown",
        "the literal `unknown` is production's own, at :3300: {alpha_logs}"
    );

    // EXACTLY ONE terminal for the one failed operation, and its code is the
    // static mapper projection of the unknown variant - never the prose.
    assert_eq!(
        terminal_codes(&alpha_logs),
        vec!["process_unknown_outcome".to_owned()],
        "exactly one terminal, and it is the unknown outcome's own code: {alpha_logs}"
    );
    assert_eq!(
        crate::process_execution::process_terminal_code(&ProcessExecutionError::UnknownOutcome),
        "process_unknown_outcome",
        "the emitted code is the static mapper projection at :242"
    );
    assert_ne!(
        terminal_codes(&alpha_logs),
        vec![alpha_error.to_string()],
        "the terminal code is never the error's rendered prose: {alpha_logs}"
    );

    // The ORIGINAL operation identity is on the span of every record this call
    // produced, and BETA's identity appears nowhere in ALPHA's capture.
    assert_eq!(
        span_field(
            event_line(&alpha_logs, "kernel.process.cancel_requested"),
            "operation"
        ),
        Some(W22_ALPHA),
        "the request record stays under the operation THIS call passed: {alpha_logs}"
    );
    assert_eq!(
        span_field(
            event_line(&alpha_logs, "kernel.process.cancel_failed"),
            "operation"
        ),
        Some(W22_ALPHA),
        "the possible-effect record stays under the same original operation: {alpha_logs}"
    );
    assert_eq!(
        span_field(
            event_line(&alpha_logs, "kernel.terminal_error"),
            "operation"
        ),
        Some(W22_ALPHA),
        "the single terminal stays under the same original operation: {alpha_logs}"
    );
    // REGRESSION GUARD (absence), not the proof: it is an ABSENCE of one string.
    // It keeps the correlation honest if the span's `operation` projection is
    // ever rebuilt from a wider context, but it discriminates nothing on its own
    // — the positive role is carried by the three `operation` readings above.
    assert!(
        !alpha_logs.contains(W22_BETA),
        "a cancel never records another operation's identity: {alpha_logs}"
    );

    // The owner legs of the SAME span: production's own projection of THIS
    // owner's generation and authority epoch, not a shape.
    for event in [
        "kernel.process.cancel_requested",
        "kernel.process.cancel_failed",
        "kernel.terminal_error",
    ] {
        let line = event_line(&alpha_logs, event);
        assert_eq!(
            span_field(line, "generation"),
            Some(generation_text.as_str()),
            "the {event} record carries this owner's generation: {alpha_logs}"
        );
        assert_eq!(
            span_field(line, "authority_epoch"),
            Some(epoch_digest.as_str()),
            "the {event} record carries this owner's own StateFence epoch digest: {alpha_logs}"
        );
    }
    // `owner_admitted`/`success` at :4528 is the subordinate read that
    // authorized this attempt; it owns no terminal of its own.
    assert_eq!(
        event_outcome(&alpha_logs, "kernel.process.owner_admitted"),
        "success",
        "the durable row's owner matched this owner, so the attempt was authorized: {alpha_logs}"
    );
    // REGRESSION GUARD (absence): its producer, `owner_rejected`/`fenced` at
    // :4523, is on the REFUSED arm of :4520 and this call took the admitted arm.
    // The positive role is the `owner_admitted`/`success` reading above.
    assert_eq!(
        event_count(&alpha_logs, "kernel.process.owner_rejected"),
        0,
        "an authorized attempt has no owner refusal: {alpha_logs}"
    );

    // ---- BETA, a DIFFERENT operation on the same composition ---------------
    let (beta_result, beta_logs) =
        capture_with(|| fixture.gateway.cancel(&owner, beta.clone())).await;
    let beta_error = beta_result.expect_err("a cancel with no observable receipt has no receipt");
    assert!(
        matches!(beta_error, ProcessExecutionError::UnknownOutcome),
        "BETA is refused the same way: {beta_error:?}\n{beta_logs}"
    );
    assert_eq!(
        event_outcome(&beta_logs, "kernel.process.cancel_failed"),
        "unknown",
        "the literal `unknown` is production's own for BETA too: {beta_logs}"
    );
    // POSITIVE, and the reason BETA's capture is a second OBSERVATION rather
    // than a repeat of ALPHA's: each capture owns its own attempt (:3206) and its
    // own single possible-effect record (:3300), both counted.
    assert_eq!(
        event_count(&beta_logs, "kernel.process.cancel_requested"),
        1,
        "BETA enters the cancellation boundary exactly once, at :3206: {beta_logs}"
    );
    assert_eq!(
        event_count(&beta_logs, "kernel.process.cancel_failed"),
        1,
        "BETA observes its own possible effect exactly once, at :3300: {beta_logs}"
    );
    assert_eq!(
        terminal_codes(&beta_logs),
        vec!["process_unknown_outcome".to_owned()],
        "exactly one terminal for BETA alone: {beta_logs}"
    );
    for event in [
        "kernel.process.cancel_requested",
        "kernel.process.cancel_failed",
        "kernel.terminal_error",
    ] {
        assert_eq!(
            span_field(event_line(&beta_logs, event), "operation"),
            Some(W22_BETA),
            "BETA's capture reads BETA, on its {event} record: {beta_logs}"
        );
    }
    // REGRESSION GUARD (absence), like the ALPHA twin above: the positive role is
    // the three `operation` readings just above it.
    assert!(
        !beta_logs.contains(W22_ALPHA),
        "the two captures are separate observations, never merged: {beta_logs}"
    );

    // ---- ALPHA again: a retry stays under the ORIGINAL operation ----------
    let (retry_result, retry_logs) =
        capture_with(|| fixture.gateway.cancel(&owner, alpha.clone())).await;
    let retry_error = retry_result.expect_err("a retry with no observable receipt has no receipt");
    assert!(
        matches!(retry_error, ProcessExecutionError::UnknownOutcome),
        "the retry is refused exactly as the first attempt was: {retry_error:?}\n{retry_logs}"
    );
    assert_eq!(
        event_outcome(&retry_logs, "kernel.process.cancel_failed"),
        "unknown",
        "a retry of a possible effect is still unknown: {retry_logs}"
    );
    // POSITIVE: the retry is a SECOND, separately counted entry into the same
    // boundary, so "still unknown" is a new observation and not the first one
    // re-read. It is NOT a replay-and-observe proof and claims nothing about
    // launch replay: `cancel_with_origin_grant_inner` consults no replay store
    // on this path (the journal arm at :3240 is `grant`-gated and this call
    // passes `grant = None`), and the start-side "an exact replay observes the
    // existing outcome instead of launching again" contract belongs to the
    // `ProcessStartReplayBegin::Existing` arm at :3999, which no case here
    // reaches. Two terminals for two ALPHA attempts is the honest count: the
    // single-terminal rule is per failed invocation, and no dedup ledger may
    // collapse them.
    assert_eq!(
        event_count(&retry_logs, "kernel.process.cancel_requested"),
        1,
        "the retry enters the cancellation boundary exactly once, at :3206: {retry_logs}"
    );
    assert_eq!(
        event_count(&retry_logs, "kernel.process.cancel_failed"),
        1,
        "the retry observes the possible effect exactly once, at :3300: {retry_logs}"
    );
    assert_eq!(
        span_field(
            event_line(&retry_logs, "kernel.process.cancel_failed"),
            "operation"
        ),
        Some(W22_ALPHA),
        "the retry stays under the operation it retried, not under a fresh one: {retry_logs}"
    );
    // REGRESSION GUARD (absence): the positive role is the `operation` reading
    // above plus the two counted records.
    assert!(
        !retry_logs.contains(W22_BETA),
        "the retry never borrows another operation's identity: {retry_logs}"
    );

    // Across the three attempts production emitted EXACTLY THREE terminals and
    // every one of them is the unknown outcome's code.
    let all_terminals: Vec<String> = [alpha_logs.as_str(), beta_logs.as_str(), retry_logs.as_str()]
        .into_iter()
        .flat_map(terminal_codes)
        .collect();
    assert_eq!(
        all_terminals,
        vec!["process_unknown_outcome".to_owned(); 3],
        "three failed cancels own three terminals, all unknown-outcome codes"
    );

    // REGRESSION GUARDS (absences), worth keeping and worth naming as such: the
    // three decided producers are `:3321` (acknowledged, after an OBSERVED
    // receipt), `:3254` (replayed, grant-only) and `:3314` (unrecorded,
    // grant-only), and none of them is on the `Err` arm at `:3300`. They cannot
    // discriminate a correct implementation from a broken one on their own; the
    // POSITIVE role of this test is carried by the `unknown` literals at `:3300`,
    // the exactly-one-terminal counts, the `operation` readings and the record
    // sequences asserted above and below.
    for decided in [
        "kernel.process.cancel_acknowledged",
        "kernel.process.cancel_replayed",
        "kernel.process.cancel_unrecorded",
    ] {
        for (label, logs) in [
            ("ALPHA", &alpha_logs),
            ("BETA", &beta_logs),
            ("ALPHA retry", &retry_logs),
        ] {
            assert!(
                !event_present(logs, decided),
                "{label} never reads as {decided} for an unproven kill effect: {logs}"
            );
        }
    }
    // REGRESSION GUARD (absence): `cancel_rejected`/`fenced` is a DECIDED refusal
    // produced at `:3185`/`:3211`/`:3225`/`:3245`/`:3283`, none of which is on the
    // `Err` arm at `:3300`; production reached the possible-effect arm on all
    // three attempts, so no cancel record anywhere may carry it.
    for (label, logs) in [
        ("ALPHA", &alpha_logs),
        ("BETA", &beta_logs),
        ("ALPHA retry", &retry_logs),
    ] {
        for line in cancel_record_lines(logs) {
            assert!(
                !line.contains("outcome=\"fenced\""),
                "{label} has no decided fence on any cancel record: {line}"
            );
        }
    }

    // ---- NO CANCELLATION RECEIPT IS CLAIMED --------------------------------
    //
    // REMOVED as vacuous, and documented here rather than left to look like
    // proof: this block used to assert
    // `span_field(<cancel_failed line>, "receipt") == Some("unavailable")`.
    // That literal is the slot's DECLARED DEFAULT (`kernel_diagnostics.rs:676`),
    // and the ONLY writer of that slot in the whole Kernel is
    // `record_process_context_field(context, "receipt", ..)` at
    // `process_execution.rs:3391`, inside the DESCENDANT-CLOSE success arm,
    // after that boundary's own first record (`:3342`) and after it holds a live
    // view and a built `DescendantClosureReceipt` (`:3374`-`:3390`).
    // `cancel_with_origin_grant_inner` returns at `:3305` and reaches neither, so
    // the reading could never fail and observed nothing about this boundary.
    //
    // What replaces it CAN fail, and it is the same shape the identity capsule
    // uses for a refused read: prove the recording boundary was never entered,
    // by pinning the WHOLE record sequence this path emits. Each capture owns
    // exactly three `kernel.process.*` records - `cancel_requested`/`attempt`
    // (`:3206`), `owner_admitted`/`success` (`:4528` through `:3621`) and
    // `cancel_failed`/`unknown` (`:3300`) - in that order, and nothing else. A
    // fourth record of any name reddens this, and the descendant-close records
    // that precede the only `receipt` writer (`:3342`/`:3350`/`:3409`/`:3421`)
    // are among them.
    for (label, logs) in [
        ("ALPHA", &alpha_logs),
        ("BETA", &beta_logs),
        ("ALPHA retry", &retry_logs),
    ] {
        assert_eq!(
            process_event_sequence(logs),
            vec![
                "kernel.process.cancel_requested".to_owned(),
                "kernel.process.owner_admitted".to_owned(),
                "kernel.process.cancel_failed".to_owned(),
            ],
            "{label} emits exactly the three records this possible-effect path owns, \
             so the cancel boundary never enters the descendant-close boundary \
             that writes the `receipt` slot: {logs}"
        );
    }

    drop(fixture);
    drop(root_guard);
}

// ---------------------------------------------------------------------------
// W26 — a timeout or disconnect after possible execution remains unknown.
//
// `owner_admitted`/`success` is the point of this item: the owner authorization
// at `authorize_process_owner_in_context` (`:4520`-`:4528`) really was reached
// on both legs below, and it really was reached with the owner PRODUCTION loaded
// out of the durable row (`authorize_effect_with_grant` `:3616`-`:3621`,
// `authorize_operation` `:3577`-`:3582`) — `recorded_owner` reads that row back
// through the store's own seam so no leg here is proved by comparing two copies
// of one fixture value. The refusal legs then show the boundary DECIDES a
// foreign owner instead of reading it as unknown — one leg per mutable
// coordinate of the `PartialEq` at `:4520`, so neither a dropped
// `principal_digest` nor a dropped `module_id` can pass this file. The
// acceptance-limit leg shows that the `unknown` literal is not an oracle: it
// ships with a DECIDED `process_not_found` terminal (:3561 emits the literal
// unconditionally, :3563 resolves the code from the error actually returned).
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_timeout_or_disconnect_after_possible_execution_remains_unknown() {
    let (root_guard, fixture) = unknown_outcome_fixture("w26");
    let owner = fixture.owner.clone();

    // ---- POSSIBLE EXECUTION: the authorized, unproven effect --------------
    let possible = fixture.reserve_without_launch("kernel-901-w26-possible-execution");
    // PREMISE on production's own operand: the row `authorize_effect_with_grant`
    // loads at :3616-:3620 and hands to :4520 carries this owner, so the
    // `owner_admitted` reading below is the authorization of a durable row and
    // not a comparison of two copies of the same fixture value.
    assert_eq!(
        fixture.recorded_owner("kernel-901-w26-possible-execution"),
        owner,
        "the durable row production compares against IS this owner, so the \
         possible effect belonged to an operation this owner really reserved"
    );
    let (possible_result, possible_logs) =
        capture_with(|| fixture.gateway.cancel(&owner, possible.clone())).await;
    let possible_error = possible_result.expect_err("no observable receipt means no receipt");
    assert!(
        matches!(possible_error, ProcessExecutionError::UnknownOutcome),
        "an authorized but unproven effect stays the typed unknown outcome: \
         {possible_error:?}\n{possible_logs}"
    );
    assert_eq!(
        caller_refusal(&possible_error).code,
        "UNKNOWN_OUTCOME",
        "the caller receives the unknown-outcome refusal"
    );
    assert_eq!(
        event_outcome(&possible_logs, "kernel.process.owner_admitted"),
        "success",
        "the execution WAS possible: the real durable row's owner matched this \
         owner, so the effect boundary was authorized: {possible_logs}"
    );
    // REGRESSION GUARD (absence): `owner_rejected`/`fenced` is produced at :4523,
    // the refused arm of the same comparison this leg took the admitted arm of;
    // the positive role is the `owner_admitted`/`success` reading above.
    assert_eq!(
        event_count(&possible_logs, "kernel.process.owner_rejected"),
        0,
        "the authorized leg has no owner refusal: {possible_logs}"
    );
    // POSITIVE: the literal `unknown` at :3300.
    assert_eq!(
        event_outcome(&possible_logs, "kernel.process.cancel_failed"),
        "unknown",
        "an authorized possible effect is never projected as decided: {possible_logs}"
    );
    // POSITIVE: exactly one terminal, carrying the unknown outcome's own code.
    assert_eq!(
        terminal_codes(&possible_logs),
        vec!["process_unknown_outcome".to_owned()],
        "exactly one terminal, and it is the unknown outcome's own code: {possible_logs}"
    );
    // POSITIVE: the span identity of the record that carries the literal.
    assert_eq!(
        span_field(
            event_line(&possible_logs, "kernel.process.cancel_failed"),
            "operation"
        ),
        Some(possible.as_str()),
        "the possible effect stays under its own operation: {possible_logs}"
    );
    // POSITIVE: the boundary's whole record sequence, so "authorized, unproven,
    // decided nowhere else" is one measured shape rather than a list of absences.
    assert_eq!(
        process_event_sequence(&possible_logs),
        vec![
            "kernel.process.cancel_requested".to_owned(),
            "kernel.process.owner_admitted".to_owned(),
            "kernel.process.cancel_failed".to_owned(),
        ],
        "the authorized possible-effect path owns exactly these three records \
         (:3206, :4528 through :3621, :3300) and no descendant-close record: \
         {possible_logs}"
    );
    // REGRESSION GUARD (absence): `cancel_acknowledged`/`success` at :3321 is
    // emitted only after an OBSERVED receipt, which this leg never received. The
    // sequence assertion above is what carries the positive role.
    assert!(
        !event_present(&possible_logs, "kernel.process.cancel_acknowledged"),
        "delivery acknowledgement is never minted for an unproven effect: {possible_logs}"
    );

    // ---- DECIDED REFUSAL: a foreign owner on the same boundary ------------
    let foreign = fixture.reserve_without_launch("kernel-901-w26-foreign-owner");
    let foreign_owner = fixture.foreign_owner.clone();
    assert_eq!(
        foreign_owner.authority_epoch(),
        owner.authority_epoch(),
        "fixture premise: the refused owner differs only in its principal digest"
    );
    assert_eq!(
        foreign_owner.generation(),
        owner.generation(),
        "fixture premise: the refused owner is not stale, it is simply not the owner"
    );
    // PREMISE on production's OWN operand: `authorize_effect_with_grant` loads
    // `record.owner` from the durable row (:3616-:3621) and compares THAT with
    // the presented binding, so the refusal is proved on the value production
    // really compared. Read from the store, it also pins that the refused
    // operation is a real reservation under this owner - a stale/unknown owner
    // cannot reach :4523 at all, it fails the row load.
    let foreign_recorded_owner = fixture.recorded_owner("kernel-901-w26-foreign-owner");
    assert_eq!(
        foreign_recorded_owner, owner,
        "the refused operation is a real durable row under THIS owner, so the \
         refusal is decided against the recorded owner and not against a \
         missing identity"
    );
    assert_ne!(
        foreign_recorded_owner, foreign_owner,
        "the recorded owner and the refused owner are the two operands of the \
         :4520 comparison, and they really differ"
    );
    let (foreign_result, foreign_logs) =
        capture_with(|| fixture.gateway.cancel(&foreign_owner, foreign.clone())).await;
    let foreign_error = foreign_result.expect_err("a foreign owner is refused");
    assert!(
        matches!(
            foreign_error,
            ProcessExecutionError::Contract(eliot_process::ContractError::DispatchBindingMismatch)
        ),
        "a foreign owner is refused by the owner comparison itself (:4524): {foreign_error:?}\n{foreign_logs}"
    );
    assert_eq!(
        caller_refusal(&foreign_error).code,
        "CONTRACT_REJECTED",
        "the caller receives the decided contract refusal"
    );
    assert_eq!(
        event_outcome(&foreign_logs, "kernel.process.owner_rejected"),
        "fenced",
        "the subordinate owner comparison reads as fenced (:4523): {foreign_logs}"
    );
    assert_eq!(
        event_outcome(&foreign_logs, "kernel.process.cancel_rejected"),
        "fenced",
        "and the composed boundary reads the same decision (:3225): {foreign_logs}"
    );
    // REGRESSION GUARD (absence): the positive role of this leg is the `fenced`
    // readings above and the sequence assertion below.
    assert_eq!(
        event_count(&foreign_logs, "kernel.process.owner_admitted"),
        0,
        "a refused owner is never admitted: {foreign_logs}"
    );
    assert_eq!(
        terminal_codes(&foreign_logs),
        vec!["process_contract".to_owned()],
        "exactly one terminal, carrying the DECIDED contract code (:238): {foreign_logs}"
    );
    assert_eq!(
        crate::process_execution::process_terminal_code(&foreign_error),
        "process_contract",
        "the emitted code is the static mapper projection of the contract variant"
    );
    for event in [
        "kernel.process.owner_rejected",
        "kernel.process.cancel_rejected",
        "kernel.terminal_error",
    ] {
        assert_eq!(
            span_field(event_line(&foreign_logs, event), "operation"),
            Some(foreign.as_str()),
            "the refusal is recorded under the refused operation, on its {event}: {foreign_logs}"
        );
    }
    // POSITIVE: the refused leg's whole record sequence. It is three records in
    // production order - the attempt (`:3206`), the subordinate owner refusal
    // (`:4523`) and the composed refusal (`:3225`) - so the boundary DECIDED after
    // entering, rather than failing to observe anything.
    assert_eq!(
        process_event_sequence(&foreign_logs),
        vec![
            "kernel.process.cancel_requested".to_owned(),
            "kernel.process.owner_rejected".to_owned(),
            "kernel.process.cancel_rejected".to_owned(),
        ],
        "a refused owner owns exactly the attempt and the two refusal records \
         (:3206, :4523, :3225) and no possible-effect record: {foreign_logs}"
    );
    // REGRESSION GUARDS (absences): `unknown` and the possible-effect vocabulary
    // are what a decided refusal must never report. Their producers (`:3300`,
    // `:3321`) are not on this arm, and the positive role is the `fenced`
    // readings plus the sequence above.
    assert!(
        !foreign_logs.contains("outcome=\"unknown\""),
        "a decided owner refusal is never reported as an unknown effect: {foreign_logs}"
    );
    assert!(
        !event_present(&foreign_logs, "kernel.process.cancel_failed")
            && !event_present(&foreign_logs, "kernel.process.cancel_acknowledged"),
        "the possible-effect arm never ran for a decided refusal: {foreign_logs}"
    );

    // ---- DECIDED REFUSAL, THE OTHER COORDINATE: a foreign MODULE identity ---
    //
    // The arm above holds `module_id` fixed and varies `principal_digest`, so it
    // pins ONE coordinate of the derived `PartialEq` on `ProcessOwnerBinding`
    // (`crates/kernel/eliot-process/src/lib.rs:675`-`:682`: `module_id` `:678`,
    // `principal_digest` `:679`, `authority_epoch` `:680`, `generation` `:681`;
    // the operation id is only the load key of `:3618`, never a compared
    // member). This arm isolates the OTHER one. The presented owner is built by
    // this file's own `unknown_outcome_owner` helper from the SAME principal
    // (`"a"`), the same `unknown_outcome_epoch()` and the same
    // `Generation::new(1)` as `fixture.owner`, and differs from it ONLY in
    // `module_id`, which is why each premise below is a separate coordinate
    // reading and `assert_ne!(module_id)` alone would not be enough: a second
    // difference could otherwise ride along and this arm would still pass
    // against a comparison that had dropped `module_id`.
    let foreign_module = fixture.reserve_without_launch("kernel-901-w26-foreign-module");
    let foreign_module_owner = unknown_outcome_owner("other-module", "a");
    // PREMISE on production's OWN operand, through the file's existing
    // `recorded_owner` readback (`:524`-`:531`), which goes through
    // `RedbRecoveryStore::load_process_start` — the same seam
    // `authorize_effect_with_grant` reads at `:3616`-`:3620`. Every premise
    // below is therefore stated against the durable row production hands to
    // `:4520`, not against a second copy of the fixture's own object.
    let foreign_module_recorded_owner = fixture.recorded_owner("kernel-901-w26-foreign-module");
    assert_eq!(
        foreign_module_recorded_owner, owner,
        "the refused operation is a real durable row under THIS owner, so this \
         refusal is decided against the recorded owner and not against a \
         missing identity"
    );
    assert_eq!(
        foreign_module_owner.principal_digest(),
        foreign_module_recorded_owner.principal_digest(),
        "coordinate 1 held equal: the refused owner presents the SAME principal \
         digest production recorded, so the principal comparison at :4520 is \
         satisfied and cannot be the reason for this refusal"
    );
    assert_eq!(
        foreign_module_owner.authority_epoch(),
        foreign_module_recorded_owner.authority_epoch(),
        "coordinate 2 held equal: the refused owner is on the same authority \
         epoch, so it is not stale and epoch cannot be the reason either"
    );
    assert_eq!(
        foreign_module_owner.generation(),
        foreign_module_recorded_owner.generation(),
        "coordinate 3 held equal: the refused owner is on the same generation, \
         so generation cannot be the reason either"
    );
    assert_ne!(
        foreign_module_owner.module_id(),
        foreign_module_recorded_owner.module_id(),
        "coordinate 4, and the ONLY one: the refused owner presents a foreign \
         module identity, which is what :4520 must decide on"
    );
    assert_ne!(
        foreign_module_recorded_owner, foreign_module_owner,
        "the recorded owner and the refused owner are the two operands of the \
         :4520 comparison, and they really differ"
    );
    // The SAME production path the arm above drives: `cancel` (:3149) ->
    // `cancel_in_context` (:3160) -> `cancel_with_origin_grant_in_context`
    // (:3172; `grant = None` skips `:3179`-`:3191`) ->
    // `cancel_with_origin_grant_inner` (:3196, `cancel_requested` at `:3206`) ->
    // `authorize_effect_with_grant` (:3621) -> `:4520`.
    let (foreign_module_result, foreign_module_logs) = capture_with(|| {
        fixture
            .gateway
            .cancel(&foreign_module_owner, foreign_module.clone())
    })
    .await;
    let foreign_module_error =
        foreign_module_result.expect_err("a foreign module identity is refused");
    assert!(
        matches!(
            foreign_module_error,
            ProcessExecutionError::Contract(eliot_process::ContractError::DispatchBindingMismatch)
        ),
        "a foreign module identity alone is refused by the owner comparison \
         itself (:4524), with the same typed contract refusal the principal-only \
         arm asserts: {foreign_module_error:?}\n{foreign_module_logs}"
    );
    assert_eq!(
        caller_refusal(&foreign_module_error).code,
        "CONTRACT_REJECTED",
        "the caller receives the decided contract refusal"
    );
    assert_eq!(
        event_outcome(&foreign_module_logs, "kernel.process.owner_rejected"),
        "fenced",
        "the subordinate owner comparison reads as fenced (:4523) on the \
         module_id difference alone: {foreign_module_logs}"
    );
    assert_eq!(
        event_outcome(&foreign_module_logs, "kernel.process.cancel_rejected"),
        "fenced",
        "and the composed boundary reads the same decision (:3225): \
         {foreign_module_logs}"
    );
    // POSITIVE: the refusal is produced exactly once, on the subordinate record
    // :4523 writes and nothing else.
    assert_eq!(
        event_count(&foreign_module_logs, "kernel.process.owner_rejected"),
        1,
        "the decided owner comparison is observed exactly once (:4523): \
         {foreign_module_logs}"
    );
    // REGRESSION GUARD (absence): `owner_admitted`/`success` (:4528) is the
    // ADMITTED arm of the very comparison at `:4520`. What reddens this
    // absence is mutating `:4520` to drop `module_id` from the derived
    // `PartialEq` — production would then admit this owner. The positive role
    // is the `fenced` readings above.
    assert_eq!(
        event_count(&foreign_module_logs, "kernel.process.owner_admitted"),
        0,
        "a refused module identity is never admitted (:4528): {foreign_module_logs}"
    );
    assert_eq!(
        terminal_codes(&foreign_module_logs),
        vec!["process_contract".to_owned()],
        "exactly one terminal, carrying the DECIDED contract code (:238): \
         {foreign_module_logs}"
    );
    // POSITIVE: this arm's whole record sequence — the attempt (`:3206`), the
    // subordinate owner refusal (`:4523`) and the composed refusal (`:3225`).
    // What reddens it is the same `:4520` mutation: production would take the
    // admitted arm (`:4528`) and then reach the possible-effect arm
    // (`:3292`-`:3305`), so both the third element and the length change.
    assert_eq!(
        process_event_sequence(&foreign_module_logs),
        vec![
            "kernel.process.cancel_requested".to_owned(),
            "kernel.process.owner_rejected".to_owned(),
            "kernel.process.cancel_rejected".to_owned(),
        ],
        "a refused module identity owns exactly the attempt and the two refusal \
         records (:3206, :4523, :3225) and no possible-effect record: \
         {foreign_module_logs}"
    );
    // REGRESSION GUARDS (absences): `unknown` (`:3300`) and the delivery
    // acknowledgement (`:3321`) are what a decided refusal must never report.
    // What reddens their absence is the same `:4520` mutation, which reaches
    // the possible-effect arm once the owner is admitted; the positive role is
    // the `fenced` readings plus the sequence above.
    assert!(
        !foreign_module_logs.contains("outcome=\"unknown\""),
        "a decided module-identity refusal is never reported as an unknown \
         effect: {foreign_module_logs}"
    );
    assert!(
        !event_present(&foreign_module_logs, "kernel.process.cancel_failed")
            && !event_present(&foreign_module_logs, "kernel.process.cancel_acknowledged"),
        "the possible-effect arm never ran for a decided refusal: \
         {foreign_module_logs}"
    );

    // ---- ACCEPTANCE LIMIT: `unknown` is NOT an oracle ----------------------
    // `reconcile_in_context` reaches the real executor for an operation this
    // composition really reserved. The executor has no live operation under
    // that identity, so `operation()` returns `NotFound`
    // (`eliot-process-executor/src/lib.rs:1690`-`:1696`), :3561 still emits the
    // literal `unknown`, and :3563 resolves the terminal from THAT error. So the
    // `unknown` literal and a DECIDED `process_not_found` code ship together:
    // a reader must read `code`, never `outcome`.
    let unproven = fixture.reserve_without_launch("kernel-901-w26-unproven-execution");
    // The same premise on the OTHER authorization path: `authorize_operation`
    // loads `record.owner` at :3577-:3581 and hands it to :4520, so this leg's
    // authorization is against the durable row, not against a fixture copy.
    assert_eq!(
        fixture.recorded_owner("kernel-901-w26-unproven-execution"),
        owner,
        "the reconcile leg compares the owner production loaded from the row"
    );
    let (unproven_result, unproven_logs) =
        capture_with(|| fixture.gateway.reconcile(&owner, unproven.clone())).await;
    let unproven_error = unproven_result.expect_err("no live operation to reconcile");
    assert!(
        matches!(unproven_error, ProcessExecutionError::NotFound),
        "the executor's typed refusal is surfaced verbatim: {unproven_error:?}\n{unproven_logs}"
    );
    assert_eq!(
        caller_refusal(&unproven_error).code,
        "NOT_FOUND",
        "the caller receives the decided not-found refusal"
    );
    assert_eq!(
        event_count(&unproven_logs, "kernel.process.reconcile_requested"),
        1,
        "the exit/evidence boundary is entered exactly once (:3527): {unproven_logs}"
    );
    assert_eq!(
        event_outcome(&unproven_logs, "kernel.process.reconcile_requested"),
        "attempt",
        "the boundary records the attempt: {unproven_logs}"
    );
    assert_eq!(
        event_outcome(&unproven_logs, "kernel.process.owner_admitted"),
        "success",
        "the reconcile authorization really ran through :4528: {unproven_logs}"
    );
    assert_eq!(
        event_outcome(&unproven_logs, "kernel.process.reconcile_unknown"),
        "unknown",
        "the literal `unknown` is production's own, at :3561: {unproven_logs}"
    );
    assert_eq!(
        terminal_codes(&unproven_logs),
        vec!["process_not_found".to_owned()],
        "and yet the terminal is the DECIDED not-found code (:3563 -> :239): {unproven_logs}"
    );
    assert_eq!(
        crate::process_execution::process_terminal_code(&unproven_error),
        "process_not_found",
        "the terminal code is resolved from the error actually returned, not \
         from the emitted outcome literal"
    );
    assert_ne!(
        terminal_codes(&unproven_logs),
        vec!["process_unknown_outcome".to_owned()],
        "this is the whole limit: `outcome=\"unknown\"` here accompanies a \
         decided NOT-unknown-outcome terminal code: {unproven_logs}"
    );
    assert_ne!(
        terminal_codes(&unproven_logs),
        vec![unproven_error.to_string()],
        "the terminal code is never the error's rendered prose: {unproven_logs}"
    );
    assert_eq!(
        span_field(
            event_line(&unproven_logs, "kernel.process.reconcile_unknown"),
            "operation"
        ),
        Some(unproven.as_str()),
        "even the literal that is not an oracle stays under its own operation: {unproven_logs}"
    );
    // POSITIVE: the leg's whole record sequence - the attempt (`:3527`), the
    // authorized owner (`:4528` through `:3582`) and the literal `unknown`
    // (`:3561`) - so the `unknown` leg is entered and authorized, not skipped.
    assert_eq!(
        process_event_sequence(&unproven_logs),
        vec![
            "kernel.process.reconcile_requested".to_owned(),
            "kernel.process.owner_admitted".to_owned(),
            "kernel.process.reconcile_unknown".to_owned(),
        ],
        "the unknown reconcile leg owns exactly these three records (:3527, \
         :4528 through :3582, :3561) and no decided reading: {unproven_logs}"
    );
    // REGRESSION GUARD (absence): `:3557` (reported) and `:3529` (rejected) are
    // the two decided reconcile readings and neither is on the `Err` arm at
    // `:3560`; the positive role is the sequence assertion just above.
    assert!(
        !event_present(&unproven_logs, "kernel.process.reconcile_reported")
            && !event_present(&unproven_logs, "kernel.process.reconcile_rejected"),
        "an executor that cannot answer neither reports nor fences: {unproven_logs}"
    );

    drop(fixture);
    drop(root_guard);
}
