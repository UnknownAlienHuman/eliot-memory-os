//! Bounded ordinary request loop for the admitted Kernel grant
//! (issue #2568, #1955, I14.19).
//!
//! This is the runtime composition the grant path was missing: the closed
//! authenticated authorization message the owner publisher stages beside
//! the installation-approved image is bound, admitted, and then served by a
//! bounded request loop whose control surface stays processable while guest
//! work is pending.
//!
//! ```text
//! main (ordinary branch)
//!   → run_ordinary_request_loop
//!     → read_dispatch_material: owner envelope + colocated bytes, bound
//!     → build_admitted_runtime: installation binding, one-shot P-03
//!       permit, local owner proxies, one admitted engine mode
//!     → run_request_loop
//!         control phase   (authority refresh, drain, containment)
//!         request phase   (typed invoke / cancel / reconcile / shutdown)
//!         completion phase(correlated owner-backed receipt)
//! ```
//!
//! Two structures keep the loop honest:
//!
//! - **The engine worker owns the runner.** Synchronous guest work never
//!   runs on the control loop, and no untracked timer or detached thread is
//!   introduced: exactly one worker is spawned, it is joined, and the
//!   control loop talks to it over a bounded command channel.
//! - **Authority is re-checked, never inherited.** The admitted grant is a
//!   window ([`LiveAuthority`]); the control loop refreshes the observed
//!   clock on every tick and the local owner proxies inside the worker
//!   consult the same cell before resolving anything, so a successful start
//!   never authorizes later work forever.
//!
//! The experimental describe path and the one-shot guest-child protocol are
//! separate modes reachable only through their own CLI branches; the
//! governed loop never falls back to either, and neither falls back here.

use std::collections::BTreeMap;
use std::fmt;
use std::fmt::Write as _;
use std::io::Write;
use std::path::Path;
use std::sync::Arc;
use std::sync::mpsc::{Receiver, RecvTimeoutError, SyncSender, sync_channel};
use std::time::Duration;

use eliot_wasm_runtime::lifecycle::{DIVERGENCE_REASON_CODE, DivergenceReport};
use eliot_wasm_runtime::{
    EngineBinding, InvocationRequest, InvocationResult, Sha256Digest, VerificationVerdict,
};

use crate::WasmHostRunner;
use crate::admission::LiveAuthority;
use crate::dispatch_drive::{
    DriveError, LifecycleVerdicts, SeatedVerdicts, evaluate_lifecycle_verdicts,
    evaluate_seated_verdicts,
};
use crate::dispatch_material::{MaterialError, ValidatedDispatchMaterial, read_dispatch_material};
use crate::parent_authority::edge_now_ms;
use crate::parent_runtime::{AdmittedRuntime, build_admitted_runtime};

/// Request-frame wire identity, matched exactly by the loop's parser.
pub const WASM_HOST_REQUEST_WIRE_ID: &str = "eliot.wasm.host-request";
/// Request-frame wire version, matched exactly by the loop's parser.
pub const WASM_HOST_REQUEST_WIRE_VERSION: u16 = 1;
/// Closed operation: execute the one admitted invocation.
pub const OP_INVOKE: &str = "wasm_guest_invoke";
/// Closed operation: contain an uncertain in-flight outcome.
pub const OP_CANCEL: &str = "wasm_guest_cancel";
/// Closed operation: reconcile an uncertain outcome through its owners.
pub const OP_RECONCILE: &str = "wasm_guest_reconcile";
/// Closed operation: close admission and drain.
pub const OP_SHUTDOWN: &str = "wasm_host_shutdown";

/// Result-frame wire identity, matched exactly with the request wire so one
/// correlated receipt answers one request.
pub const WASM_HOST_RESULT_WIRE_ID: &str = "eliot.wasm.host-result";

/// Bounded result-byte budget: the largest result frame the loop publishes.
pub const MAX_RESULT_FRAME_BYTES: usize = 64 * 1024;

/// Control-loop poll cadence while a command is outstanding. It bounds how
/// long the loop can go without re-checking the authority window; it starts
/// no worker and decides no timeout policy of its own.
const CONTROL_POLL: Duration = Duration::from_millis(25);

/// Fail-closed loop errors. Stable codes plus one stable field name; no
/// digests, paths, or payloads are echoed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LoopError {
    /// A request frame failed its wire, binding, size, or authority check.
    RequestDenied {
        /// Stable field name.
        field: &'static str,
    },
    /// The request source or the result sink could not be read or written.
    ChannelUnavailable,
    /// The result frame exceeded the admitted result-byte budget.
    ResultTooLarge,
}

impl LoopError {
    /// Stable code for this rejection.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::RequestDenied { .. } => "REQUEST_LOOP_DENIED",
            Self::ChannelUnavailable => "REQUEST_LOOP_CHANNEL_UNAVAILABLE",
            Self::ResultTooLarge => "REQUEST_LOOP_RESULT_TOO_LARGE",
        }
    }
}

impl fmt::Display for LoopError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RequestDenied { field } => write!(formatter, "{}:{field}", self.code()),
            other => formatter.write_str(other.code()),
        }
    }
}

impl std::error::Error for LoopError {}

fn denied(field: &'static str) -> LoopError {
    LoopError::RequestDenied { field }
}

/// Exact binding one admitted grant fixes for every request it may serve.
///
/// Derived once from validated owner material and re-checked on every
/// request, so a caller-known digest stays a claim until it matches the
/// authorized material the owner actually published.
#[derive(Clone, Debug)]
pub struct AdmittedBinding {
    claim_id: String,
    operation_id: String,
    invocation_id: String,
    request_digest: String,
    grant_digest: String,
    component_id: String,
    artifact_digest: String,
    input_digest: String,
    input_bytes: Vec<u8>,
    fence_nonce: String,
    deterministic_seed: u64,
    max_output_bytes: u64,
}

impl AdmittedBinding {
    /// Binds the exact admitted identities, digests, payload, and window.
    #[must_use]
    pub fn from_material(
        material: &ValidatedDispatchMaterial,
        request: &InvocationRequest,
    ) -> Self {
        let ceilings = &material.ceilings;
        Self {
            claim_id: material.claim_id.clone(),
            operation_id: material.operation_id.clone(),
            invocation_id: request.invocation_id.as_str().to_owned(),
            request_digest: request.request_digest().as_str().to_owned(),
            grant_digest: material.grant.grant_digest.as_str().to_owned(),
            component_id: ceilings.component_id.clone(),
            artifact_digest: ceilings.artifact_digest.as_str().to_owned(),
            input_digest: ceilings.input_digest.as_str().to_owned(),
            input_bytes: request.input.clone(),
            fence_nonce: material.grant.fence_nonce.clone(),
            deterministic_seed: material.work.deterministic_seed,
            max_output_bytes: ceilings.max_output_bytes,
        }
    }
}

/// The admitted invoke request: exact claim, grant, target, input, and
/// request identity. No field here is a fresh claim; every one is compared
/// against the binding the owner published.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WasmHostInvoke {
    claim_id: String,
    operation_id: String,
    invocation_id: String,
    request_digest: String,
    grant_digest: String,
    grant_fence_nonce: String,
    component_id: String,
    artifact_digest: String,
    input_digest: String,
    deterministic_seed: u64,
    input_bytes: Vec<u8>,
}

/// The admitted control request naming the operation it acts on.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WasmHostControl {
    operation_id: String,
    invocation_id: String,
    request_digest: String,
}

/// One request in the loop's closed vocabulary.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum WasmHostRequest {
    /// Execute the one admitted invocation.
    Invoke(WasmHostInvoke),
    /// Contain an uncertain outcome through the runtime owner.
    Cancel(WasmHostControl),
    /// Reconcile an uncertain outcome through its owners.
    Reconcile(WasmHostControl),
    /// Close admission and drain.
    Shutdown,
}

/// Strict wire shape of one request frame. Parsed with
/// `deny_unknown_fields`, so a mixed or extended frame fails closed before
/// any authority, permit, or child exists.
#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub struct WasmHostRequestFrame {
    wire_id: String,
    wire_version: u16,
    operation: String,
    claim_id: String,
    operation_id: String,
    invocation_id: String,
    request_digest: String,
    grant_digest: String,
    grant_fence_nonce: String,
    component_id: String,
    artifact_digest: String,
    input_digest: String,
    deterministic_seed: u64,
    input_bytes: Vec<u8>,
}

impl WasmHostRequestFrame {
    /// Builds the frame the owner delivery set yields for the admitted
    /// operation. Every value is admitted material, a sealed request field,
    /// or a digest recomputed from the real bytes.
    fn admitted_invoke(binding: &AdmittedBinding) -> Self {
        Self {
            wire_id: WASM_HOST_REQUEST_WIRE_ID.to_owned(),
            wire_version: WASM_HOST_REQUEST_WIRE_VERSION,
            operation: OP_INVOKE.to_owned(),
            claim_id: binding.claim_id.clone(),
            operation_id: binding.operation_id.clone(),
            invocation_id: binding.invocation_id.clone(),
            request_digest: binding.request_digest.clone(),
            grant_digest: binding.grant_digest.clone(),
            grant_fence_nonce: binding.fence_nonce.clone(),
            component_id: binding.component_id.clone(),
            artifact_digest: binding.artifact_digest.clone(),
            input_digest: binding.input_digest.clone(),
            deterministic_seed: binding.deterministic_seed,
            input_bytes: binding.input_bytes.clone(),
        }
    }

    /// Builds the control frame the loop derives for an uncertain outcome.
    fn control(operation: &str, binding: &AdmittedBinding) -> Self {
        Self {
            wire_id: WASM_HOST_REQUEST_WIRE_ID.to_owned(),
            wire_version: WASM_HOST_REQUEST_WIRE_VERSION,
            operation: operation.to_owned(),
            claim_id: binding.claim_id.clone(),
            operation_id: binding.operation_id.clone(),
            invocation_id: binding.invocation_id.clone(),
            request_digest: binding.request_digest.clone(),
            grant_digest: binding.grant_digest.clone(),
            grant_fence_nonce: binding.fence_nonce.clone(),
            component_id: binding.component_id.clone(),
            artifact_digest: binding.artifact_digest.clone(),
            input_digest: binding.input_digest.clone(),
            deterministic_seed: binding.deterministic_seed,
            input_bytes: Vec::new(),
        }
    }

    /// Parses one bounded request frame into the typed vocabulary.
    fn parse(frame: &WasmHostRequestFrame) -> Result<WasmHostRequest, LoopError> {
        if frame.wire_id != WASM_HOST_REQUEST_WIRE_ID
            || frame.wire_version != WASM_HOST_REQUEST_WIRE_VERSION
        {
            return Err(denied("wire"));
        }
        match frame.operation.as_str() {
            OP_INVOKE => Ok(WasmHostRequest::Invoke(WasmHostInvoke {
                claim_id: frame.claim_id.clone(),
                operation_id: frame.operation_id.clone(),
                invocation_id: frame.invocation_id.clone(),
                request_digest: frame.request_digest.clone(),
                grant_digest: frame.grant_digest.clone(),
                grant_fence_nonce: frame.grant_fence_nonce.clone(),
                component_id: frame.component_id.clone(),
                artifact_digest: frame.artifact_digest.clone(),
                input_digest: frame.input_digest.clone(),
                deterministic_seed: frame.deterministic_seed,
                input_bytes: frame.input_bytes.clone(),
            })),
            OP_CANCEL | OP_RECONCILE => {
                if !frame.input_bytes.is_empty() {
                    return Err(denied("control-payload"));
                }
                let control = WasmHostControl {
                    operation_id: frame.operation_id.clone(),
                    invocation_id: frame.invocation_id.clone(),
                    request_digest: frame.request_digest.clone(),
                };
                if frame.operation == OP_CANCEL {
                    Ok(WasmHostRequest::Cancel(control))
                } else {
                    Ok(WasmHostRequest::Reconcile(control))
                }
            }
            OP_SHUTDOWN => {
                if !frame.input_bytes.is_empty() {
                    return Err(denied("control-payload"));
                }
                Ok(WasmHostRequest::Shutdown)
            }
            _ => Err(denied("operation")),
        }
    }
}

/// Validates one invoke request against the admitted binding before any
/// authority, permit, or child exists: exact claim, grant, target, input,
/// and request identity, the request's own bytes re-hashed, the request
/// size, and the live authority window.
fn check_invoke(
    binding: &AdmittedBinding,
    live: &Arc<LiveAuthority>,
    request: &WasmHostInvoke,
) -> Result<(), LoopError> {
    if !live.is_live() {
        return Err(denied("authority-window"));
    }
    if request.claim_id != binding.claim_id || request.operation_id != binding.operation_id {
        return Err(denied("admission-identity"));
    }
    if request.grant_digest != binding.grant_digest
        || request.grant_fence_nonce != binding.fence_nonce
    {
        return Err(denied("grant-binding"));
    }
    if request.component_id != binding.component_id
        || request.artifact_digest != binding.artifact_digest
    {
        return Err(denied("target-binding"));
    }
    if request.input_digest != binding.input_digest
        || request.input_bytes != binding.input_bytes
        || Sha256Digest::of_bytes(&request.input_bytes).as_str() != binding.input_digest
    {
        return Err(denied("input-binding"));
    }
    if u64::try_from(request.input_bytes.len()).unwrap_or(u64::MAX)
        > u64::try_from(binding.input_bytes.len()).unwrap_or(0)
    {
        return Err(denied("input-size"));
    }
    if request.deterministic_seed != binding.deterministic_seed {
        return Err(denied("determinism-seed"));
    }
    if request.invocation_id != binding.invocation_id
        || request.request_digest != binding.request_digest
    {
        return Err(denied("request-identity"));
    }
    Ok(())
}

/// Validates one control request against the admitted operation identity.
fn check_control(binding: &AdmittedBinding, control: &WasmHostControl) -> Result<(), LoopError> {
    if control.operation_id != binding.operation_id
        || control.invocation_id != binding.invocation_id
        || control.request_digest != binding.request_digest
    {
        return Err(denied("request-identity"));
    }
    Ok(())
}

/// Correlated owner-backed result frame. Bounded serialization only: the
/// guest output travels as lowercase hex under the admitted output
/// ceiling, and a frame that would exceed the result budget is published
/// with the payload omitted and its digest retained.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub struct WasmHostResultFrame {
    /// Result wire identity.
    pub wire_id: &'static str,
    /// Result wire version.
    pub wire_version: u16,
    /// Operation this frame answers.
    pub operation: String,
    /// Admitted claim identity.
    pub claim_id: String,
    /// Admitted operation identity.
    pub operation_id: String,
    /// Sealed invocation identity.
    pub invocation_id: String,
    /// Sealed request digest.
    pub request_digest: String,
    /// Grant digest the execution was authorized under.
    pub grant_digest: String,
    /// Admitted component identity.
    pub component_id: String,
    /// Proven artifact digest.
    pub artifact_digest: String,
    /// Proven input digest.
    pub input_digest: String,
    /// Seated engine mode identity.
    pub engine_implementation_id: String,
    /// Seated engine exact version.
    pub engine_version: String,
    /// Classified disposition.
    pub disposition: String,
    /// Typed error code, when the invocation did not succeed.
    pub error: Option<String>,
    /// SHA-256 of the guest output bytes.
    pub output_digest: Option<String>,
    /// Guest output byte count actually observed.
    pub output_bytes: Option<u64>,
    /// Lowercase-hex guest output, omitted when the frame budget is spent.
    pub output_hex: Option<String>,
    /// True when the output payload was omitted under the frame budget.
    pub output_omitted: bool,
    /// Child-observed fuel consumed.
    pub fuel_consumed: Option<u64>,
    /// Child-observed peak memory bytes.
    pub peak_memory_bytes: Option<u64>,
    /// Child-observed table elements.
    pub table_elements: Option<u64>,
    /// Child-observed epoch ticks.
    pub epoch_ticks: Option<u64>,
    /// Lifecycle verdicts evaluated from the retained result.
    pub verdict_shadow: String,
    pub verdict_canary: String,
    pub verdict_rollback: String,
    pub verdict_cutover: String,
    /// Seated trap / cancel / drain / rollback verdicts for the same run.
    pub trap: Option<String>,
    pub cancelled: bool,
    pub drain: Option<String>,
    pub rollback_candidate: bool,
    /// Canonical explicit-divergence reason code, present exactly when the
    /// sealed execution disagreed with its declared reference.
    pub divergence_code: Option<String>,
    /// Explicit leg-level divergence report, present exactly when the
    /// sealed execution disagreed with its declared reference.
    pub divergence: Option<DivergenceReport>,
}

fn disposition_text(disposition: eliot_wasm_runtime::InvocationDisposition) -> String {
    format!("{disposition:?}")
}

fn verdict_text(verdict: VerificationVerdict) -> String {
    match verdict {
        VerificationVerdict::Verified => "verified".to_owned(),
        VerificationVerdict::Rejected => "rejected".to_owned(),
    }
}

fn lifecycle_frame(verdicts: LifecycleVerdicts) -> (String, String, String, String) {
    (
        verdict_text(verdicts.shadow),
        verdict_text(verdicts.canary),
        verdict_text(verdicts.rollback),
        verdict_text(verdicts.cutover),
    )
}

fn seated_frame(verdicts: SeatedVerdicts) -> (Option<String>, bool, Option<String>, bool) {
    (
        verdicts.trap.map(|trap| format!("{trap:?}")),
        verdicts.cancelled,
        verdicts.drain.map(|drain| format!("{drain:?}")),
        verdicts.rollback_candidate,
    )
}

fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(out, "{byte:02x}");
    }
    out
}

fn usage_frames(result: &InvocationResult) -> (Option<u64>, Option<u64>, Option<u64>, Option<u64>) {
    let usage = result.receipt.usage.as_ref();
    (
        usage.map(|usage| usage.fuel_consumed),
        usage.and_then(|usage| usage.peak_memory_bytes),
        usage.and_then(|usage| usage.table_elements).map(u64::from),
        usage.and_then(|usage| usage.epoch_ticks),
    )
}

/// Projects one classified invocation result onto the correlated frame.
///
/// The explicit divergence report travels separately from the typed error:
/// the error keeps its stable classification while the report carries the
/// leg-level evidence and the canonical divergence reason code.
fn project_result(
    binding: &AdmittedBinding,
    engine: &EngineBinding,
    result: &InvocationResult,
    divergence: Option<DivergenceReport>,
) -> WasmHostResultFrame {
    let (shadow, canary, rollback, cutover) = lifecycle_frame(evaluate_lifecycle_verdicts(result));
    let (trap, cancelled, drain, rollback_candidate) =
        seated_frame(evaluate_seated_verdicts(result));
    let (fuel_consumed, peak_memory_bytes, table_elements, epoch_ticks) = usage_frames(result);
    let divergence_code = divergence
        .as_ref()
        .map(|_| DIVERGENCE_REASON_CODE.to_owned());
    WasmHostResultFrame {
        wire_id: WASM_HOST_RESULT_WIRE_ID,
        wire_version: WASM_HOST_REQUEST_WIRE_VERSION,
        operation: OP_INVOKE.to_owned(),
        claim_id: binding.claim_id.clone(),
        operation_id: binding.operation_id.clone(),
        invocation_id: binding.invocation_id.clone(),
        request_digest: binding.request_digest.clone(),
        grant_digest: binding.grant_digest.clone(),
        component_id: binding.component_id.clone(),
        artifact_digest: binding.artifact_digest.clone(),
        input_digest: binding.input_digest.clone(),
        engine_implementation_id: engine.implementation_id.clone(),
        engine_version: engine.exact_version.clone(),
        disposition: disposition_text(result.receipt.disposition),
        error: result
            .receipt
            .error
            .as_ref()
            .map(|error| format!("{error:?}")),
        output_digest: result
            .output
            .as_ref()
            .map(|bytes| Sha256Digest::of_bytes(bytes).as_str().to_owned()),
        output_bytes: result.output.as_ref().map(|bytes| bytes.len() as u64),
        output_hex: Some(hex(&result.output.clone().unwrap_or_default())),
        output_omitted: false,
        fuel_consumed,
        peak_memory_bytes,
        table_elements,
        epoch_ticks,
        verdict_shadow: shadow,
        verdict_canary: canary,
        verdict_rollback: rollback,
        verdict_cutover: cutover,
        trap,
        cancelled,
        drain,
        rollback_candidate,
        divergence_code,
        divergence,
    }
}

/// Bounds the result payload by the admitted output ceiling and the
/// loop's result-frame budget, keeping the digest so a readback stays exact
/// even when the payload is omitted.
fn enforce_frame_budget(
    mut frame: WasmHostResultFrame,
    max_output_bytes: u64,
) -> WasmHostResultFrame {
    let over_ceiling = frame
        .output_bytes
        .is_some_and(|observed| observed > max_output_bytes);
    let within =
        serde_json::to_vec(&frame).is_ok_and(|bytes| bytes.len() <= MAX_RESULT_FRAME_BYTES);
    if over_ceiling || !within {
        frame.output_hex = None;
        frame.output_omitted = true;
    }
    frame
}

/// Terminal frame for a request that never reached execution.
fn denial_frame(
    binding: &AdmittedBinding,
    operation: &str,
    error: LoopError,
) -> WasmHostResultFrame {
    WasmHostResultFrame {
        wire_id: WASM_HOST_RESULT_WIRE_ID,
        wire_version: WASM_HOST_REQUEST_WIRE_VERSION,
        operation: operation.to_owned(),
        claim_id: binding.claim_id.clone(),
        operation_id: binding.operation_id.clone(),
        invocation_id: binding.invocation_id.clone(),
        request_digest: binding.request_digest.clone(),
        grant_digest: binding.grant_digest.clone(),
        component_id: binding.component_id.clone(),
        artifact_digest: binding.artifact_digest.clone(),
        input_digest: binding.input_digest.clone(),
        engine_implementation_id: String::new(),
        engine_version: String::new(),
        disposition: "Rejected".to_owned(),
        error: Some(error.code().to_owned()),
        output_digest: None,
        output_bytes: None,
        output_hex: None,
        output_omitted: false,
        fuel_consumed: None,
        peak_memory_bytes: None,
        table_elements: None,
        epoch_ticks: None,
        verdict_shadow: verdict_text(VerificationVerdict::Rejected),
        verdict_canary: verdict_text(VerificationVerdict::Rejected),
        verdict_rollback: verdict_text(VerificationVerdict::Rejected),
        verdict_cutover: verdict_text(VerificationVerdict::Rejected),
        trap: None,
        cancelled: false,
        drain: None,
        rollback_candidate: false,
        divergence_code: None,
        divergence: None,
    }
}

/// Bounded typed request source and result sink for the ordinary loop.
pub trait WasmHostRequestChannel {
    /// Returns the next request frame, or `None` when the delivery set is
    /// exhausted and the loop must drain.
    ///
    /// # Errors
    ///
    /// Returns [`LoopError::ChannelUnavailable`] when the source cannot be
    /// read.
    fn next_frame(&mut self) -> Result<Option<WasmHostRequestFrame>, LoopError>;

    /// Publishes one correlated result frame.
    ///
    /// # Errors
    ///
    /// Returns [`LoopError::ChannelUnavailable`] or
    /// [`LoopError::ResultTooLarge`] when the frame cannot be written.
    fn publish(&mut self, frame: &WasmHostResultFrame) -> Result<(), LoopError>;
}

/// Production channel over the owner delivery set and the canonical receipt
/// stream. One delivery set carries exactly one admitted operation, so the
/// channel issues that request once and then reports exhaustion, which is
/// what closes admission and starts the drain.
pub struct DeliverySetChannel {
    admitted: Option<WasmHostRequestFrame>,
    delivered: bool,
    stdout: std::io::Stdout,
}

impl DeliverySetChannel {
    /// Binds the channel to the one admitted request frame of this
    /// delivery set.
    #[must_use]
    pub fn new(admitted: WasmHostRequestFrame) -> Self {
        Self {
            admitted: Some(admitted),
            delivered: false,
            stdout: std::io::stdout(),
        }
    }
}

impl WasmHostRequestChannel for DeliverySetChannel {
    fn next_frame(&mut self) -> Result<Option<WasmHostRequestFrame>, LoopError> {
        if self.delivered {
            return Ok(None);
        }
        self.delivered = true;
        Ok(self.admitted.take())
    }

    fn publish(&mut self, frame: &WasmHostResultFrame) -> Result<(), LoopError> {
        let bytes = serde_json::to_vec(frame).map_err(|_| LoopError::ResultTooLarge)?;
        if bytes.len() > MAX_RESULT_FRAME_BYTES {
            return Err(LoopError::ResultTooLarge);
        }
        let mut stdout = self.stdout.lock();
        stdout
            .write_all(&bytes)
            .and_then(|()| stdout.write_all(b"\n"))
            .and_then(|()| stdout.flush())
            .map_err(|_| LoopError::ChannelUnavailable)
    }
}

/// One command sent to the tracked engine worker.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum WorkerCommand {
    Execute,
    Cancel,
    Reconcile,
    Shutdown,
}

/// One reply from the tracked engine worker.
#[derive(Debug)]
struct WorkerOutcome {
    command: WorkerCommand,
    result: Result<InvocationResult, String>,
    /// Explicit divergence report, present exactly when the executed
    /// outcome was a sealed differential mismatch.
    divergence: Option<DivergenceReport>,
}

/// The tracked engine worker's channels and join handle.
struct EngineWorker {
    /// Bounded command channel into the worker.
    commands: SyncSender<WorkerCommand>,
    /// Bounded reply channel out of the worker.
    outcomes: Receiver<WorkerOutcome>,
    /// The single worker handle the control loop joins.
    handle: std::thread::JoinHandle<()>,
}

/// Spawns the single tracked engine worker that owns the runner.
///
/// The worker holds the only mutable handle to the runner, so synchronous
/// guest work never runs on the control loop. The caller joins it; no timer
/// or detached thread exists.
fn spawn_worker(runtime: AdmittedRuntime, bound: usize) -> EngineWorker {
    let (command_tx, command_rx) = sync_channel::<WorkerCommand>(bound);
    let (outcome_tx, outcome_rx) = sync_channel::<WorkerOutcome>(bound);
    let handle = std::thread::spawn(move || {
        let AdmittedRuntime {
            runner,
            invocation,
            admitted,
            live: _,
            engine_binding: _,
        } = runtime;
        let mut runner: WasmHostRunner = runner;
        let mut attempt: Option<InvocationRequest> = None;
        let mut shutdown = false;
        while let Ok(command) = command_rx.recv() {
            let result = match command {
                WorkerCommand::Execute => {
                    attempt = Some(invocation.clone());
                    runner
                        .execute_admitted(&admitted, invocation.clone())
                        .map_err(|error| format!("{error}"))
                }
                WorkerCommand::Cancel | WorkerCommand::Reconcile => match attempt.as_ref() {
                    Some(pending) => {
                        let outcome = if command == WorkerCommand::Cancel {
                            runner.cancel(&pending.invocation_id, pending.request_digest())
                        } else {
                            runner.reconcile(&pending.invocation_id, pending.request_digest())
                        };
                        outcome.map_err(|error| format!("{error:?}"))
                    }
                    None => Err("NO_ATTEMPT".to_owned()),
                },
                WorkerCommand::Shutdown => {
                    let _ = runner.request_shutdown();
                    shutdown = true;
                    Err("SHUTDOWN".to_owned())
                }
            };
            // Pure readback over the retained outcome: the report exists
            // exactly when the executed outcome was a sealed differential
            // mismatch, and costs one cache lookup otherwise.
            let divergence = match (&result, attempt.as_ref()) {
                (Ok(_), Some(pending)) => runner.divergence_report(&pending.invocation_id),
                _ => None,
            };
            if outcome_tx
                .send(WorkerOutcome {
                    command,
                    result,
                    divergence,
                })
                .is_err()
            {
                break;
            }
            if shutdown {
                break;
            }
        }
    });
    EngineWorker {
        commands: command_tx,
        outcomes: outcome_rx,
        handle,
    }
}

/// Uncertain disposition token the loop reads back from its own frame.
const UNCERTAIN_DISPOSITION: &str = "Unknown";

/// Which bounded follow-up an uncertain outcome already spent.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum FollowUp {
    /// Nothing spent yet.
    None,
    /// Containment was delivered to the runtime owner.
    Contained,
    /// One reconciliation pass was delivered to the owners.
    Reconciled,
}

/// Bounded lifecycle flags of the loop. Grouped so no single struct carries
/// an unbounded set of independent booleans.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct LifecycleFlags {
    /// A command is outstanding on the tracked worker.
    in_flight: bool,
    /// Admission is closed (delivery exhausted, drained, or revoked).
    closed: bool,
    /// The one-shot grant authority already funded an executed effect.
    one_shot_spent: bool,
    /// Which uncertain-outcome follow-up was already spent.
    follow_up: FollowUp,
}

/// Bounded state of the ordinary request loop.
///
/// Every transition is explicit: the control loop decides, the tracked
/// worker executes, and nothing here constructs a second runner, a second
/// engine, or a second effect for the same admitted operation.
pub struct BoundedRequestLoop {
    binding: AdmittedBinding,
    engine: EngineBinding,
    live: Arc<LiveAuthority>,
    max_in_flight: usize,
    /// Exact retained results keyed by the sealed request digest, so an
    /// exact replay is a readback and performs no new execution.
    retained: BTreeMap<String, WasmHostResultFrame>,
    /// Command queued by the last transition, not yet handed to the worker.
    queued: Option<WorkerCommand>,
    /// Retained frame to republish when a request is an exact replay.
    replay: Option<WasmHostResultFrame>,
    lifecycle: LifecycleFlags,
    published: Option<WasmHostResultFrame>,
    denial: Option<LoopError>,
}

impl BoundedRequestLoop {
    /// Creates the loop state from the granted binding, engine mode, and
    /// live authority cell.
    #[must_use]
    pub fn new(binding: AdmittedBinding, engine: EngineBinding, live: Arc<LiveAuthority>) -> Self {
        Self {
            binding,
            engine,
            live,
            max_in_flight: 1,
            retained: BTreeMap::new(),
            queued: None,
            replay: None,
            lifecycle: LifecycleFlags {
                in_flight: false,
                closed: false,
                one_shot_spent: false,
                follow_up: FollowUp::None,
            },
            published: None,
            denial: None,
        }
    }

    /// Returns the terminal frame the loop published, if any.
    #[must_use]
    pub fn published(&self) -> Option<&WasmHostResultFrame> {
        self.published.as_ref()
    }

    /// Returns the terminal denial, when the loop refused before executing.
    #[must_use]
    pub const fn denial(&self) -> Option<LoopError> {
        self.denial
    }

    /// Returns whether ordinary admission is still open.
    fn admission_open(&self) -> bool {
        self.published.is_none() && self.denial.is_none() && !self.lifecycle.closed
    }

    /// Control phase: refresh the observed clock and close admission on a
    /// revoked or expired binding. A trap in one bounded instance never
    /// reaches this state; it is classified and the loop keeps its contract.
    fn tick(&mut self) {
        self.live.observe(edge_now_ms());
        if !self.live.is_live() {
            self.lifecycle.closed = true;
        }
    }

    /// Admit phase for one request frame: wire, operation, identity, size,
    /// and live authority checks, then the replay and one-shot consumption
    /// rules. The control operations the loop derives for its own lifecycle
    /// travel through this same frame shape, parse, and validation, so the
    /// loop has one admission path rather than two.
    fn admit(&mut self, frame: &WasmHostRequestFrame) -> Result<(), LoopError> {
        let request = WasmHostRequestFrame::parse(frame)?;
        self.queued = None;
        self.replay = None;
        match &request {
            WasmHostRequest::Invoke(invoke) => {
                check_invoke(&self.binding, &self.live, invoke)?;
                if let Some(retained) = self.retained.get(&invoke.request_digest) {
                    // Exact retained-result replay: legitimate result
                    // readback, never a new execution and never a new effect.
                    self.replay = Some(retained.clone());
                    return Ok(());
                }
                if self.lifecycle.one_shot_spent {
                    // The one-shot authority already funded an effect. A
                    // grant intentionally valid for several requests still
                    // needs a distinct admitted request identity; this
                    // delivery set carries exactly one.
                    return Err(denied("one-shot-authority"));
                }
                self.queued = Some(WorkerCommand::Execute);
            }
            WasmHostRequest::Cancel(control) => {
                check_control(&self.binding, control)?;
                self.lifecycle.follow_up = FollowUp::Contained;
                self.queued = Some(WorkerCommand::Cancel);
            }
            WasmHostRequest::Reconcile(control) => {
                check_control(&self.binding, control)?;
                self.lifecycle.follow_up = FollowUp::Reconciled;
                self.queued = Some(WorkerCommand::Reconcile);
            }
            WasmHostRequest::Shutdown => self.lifecycle.closed = true,
        }
        Ok(())
    }

    /// Queues one owner-admitted control operation through the same frame
    /// shape and validation the request path uses.
    fn queue_control(&mut self, operation: &str) -> Result<(), LoopError> {
        let frame = WasmHostRequestFrame::control(operation, &self.binding);
        self.admit(&frame)
    }

    /// Completion phase: classify the worker's reply and decide the next
    /// bounded step.
    ///
    /// A trap or a guest cancellation reports the actual classified outcome
    /// and never implies rollback of an effect already issued through an
    /// imported port. An uncertain outcome is neither collapsed into success
    /// nor into failure: while authority is live it is reconciled once
    /// through its owners, after authority closed it is contained once, and
    /// either way the original operation identity is retained for the
    /// owner-side reconciliation record rather than reissued.
    fn on_outcome(&mut self, outcome: WorkerOutcome) -> Option<WasmHostResultFrame> {
        if outcome.command == WorkerCommand::Shutdown {
            return None;
        }
        let WorkerOutcome {
            command: _,
            result,
            divergence,
        } = outcome;
        let frame = match result {
            Ok(result) => {
                let projected = project_result(&self.binding, &self.engine, &result, divergence);
                enforce_frame_budget(projected, self.binding.max_output_bytes)
            }
            Err(code) => {
                let field = if code == "NO_ATTEMPT" {
                    "attempt-identity"
                } else {
                    "execution-refused"
                };
                let denial = denial_frame(&self.binding, OP_INVOKE, denied(field));
                enforce_frame_budget(denial, self.binding.max_output_bytes)
            }
        };
        self.retained
            .insert(frame.request_digest.clone(), frame.clone());
        self.lifecycle.one_shot_spent = true;
        if frame.disposition == UNCERTAIN_DISPOSITION {
            self.settle_uncertain(frame.clone());
        } else {
            self.queued = None;
            self.published = Some(frame.clone());
        }
        Some(frame)
    }

    /// Chooses the single bounded next step for an uncertain outcome:
    /// containment once authority closed, one reconciliation pass while it
    /// is live, and terminal retention once either has been spent. The
    /// uncertain frame is published either way, so the outcome is never
    /// hidden behind the follow-up step.
    fn settle_uncertain(&mut self, frame: WasmHostResultFrame) {
        match self.lifecycle.follow_up {
            FollowUp::None if !self.live.is_live() => {
                let _ = self.queue_control(OP_CANCEL);
            }
            FollowUp::None => {
                let _ = self.queue_control(OP_RECONCILE);
            }
            FollowUp::Contained | FollowUp::Reconciled => {
                self.queued = None;
                self.published = Some(frame);
            }
        }
    }

    /// Control phase while a command is outstanding: contain the attempt if
    /// its authority window closed while the guest was still running. The
    /// bounded Store epoch and fuel policy is what actually interrupts the
    /// guest; this delivers the owner's containment to the runtime owner at
    /// the first point it can accept it.
    fn containment_step(&mut self) -> Result<(), LoopError> {
        if self.lifecycle.follow_up != FollowUp::None || self.live.is_live() {
            return Ok(());
        }
        self.queue_control(OP_CANCEL)
    }

    /// Hands the queued command to the tracked worker.
    fn send(
        &mut self,
        command: WorkerCommand,
        sender: &SyncSender<WorkerCommand>,
    ) -> Result<(), LoopError> {
        sender
            .try_send(command)
            .map_err(|_| LoopError::ChannelUnavailable)?;
        self.queued = None;
        self.lifecycle.in_flight = true;
        Ok(())
    }
}

/// Runs the bounded ordinary request loop over one granted execution.
///
/// The control phase always runs (authority refresh, drain, revocation,
/// containment), the request phase admits at most `max_in_flight` queued
/// commands, and each reply is projected onto a correlated owner-backed
/// frame. The worker is always joined before the loop returns, so no guest
/// work outlives the process.
pub fn run_request_loop(
    runtime: AdmittedRuntime,
    material: &ValidatedDispatchMaterial,
) -> Result<WasmHostResultFrame, LoopError> {
    let binding = AdmittedBinding::from_material(material, &runtime.invocation);
    let request_frame = WasmHostRequestFrame::admitted_invoke(&binding);
    let mut state = BoundedRequestLoop::new(
        binding,
        runtime.engine_binding.clone(),
        Arc::clone(&runtime.live),
    );
    let mut channel = DeliverySetChannel::new(request_frame);
    let worker = spawn_worker(runtime, state.max_in_flight);
    let outcome = drive_loop(&mut state, &mut channel, &worker.commands, &worker.outcomes);
    // Typed shutdown: close admission, ask the worker to stop, and join it so
    // no guest work is left untracked.
    state.live.revoke();
    let _ = worker.commands.try_send(WorkerCommand::Shutdown);
    drop(worker.commands);
    let _ = worker.handle.join();
    if let Some(error) = state.denial() {
        // The loop recorded the exact admission denial; report that stable
        // field rather than the transport symptom that surfaced it.
        return Err(error);
    }
    outcome?;
    state.published().cloned().ok_or(denied("no-request"))
}

/// The control / request / completion cycle. Split out so each phase stays a
/// single bounded step.
fn drive_loop(
    state: &mut BoundedRequestLoop,
    channel: &mut DeliverySetChannel,
    commands: &SyncSender<WorkerCommand>,
    outcomes: &Receiver<WorkerOutcome>,
) -> Result<(), LoopError> {
    while state.admission_open() {
        state.tick();
        if state.lifecycle.in_flight {
            poll_pending(state, channel, commands, outcomes)?;
            continue;
        }
        let Some(frame) = channel.next_frame()? else {
            break;
        };
        if let Err(error) = state.admit(&frame) {
            // Record the exact admission denial before it surfaces as a
            // transport-level refusal, so the receipt names the field that
            // actually broke the binding.
            state.denial = Some(error);
            return Err(error);
        }
        if let Some(replay) = state.replay.clone() {
            state.replay = None;
            state.published = Some(replay.clone());
            channel.publish(&replay)?;
            break;
        }
        if let Some(command) = state.queued {
            state.send(command, commands)?;
        }
    }
    Ok(())
}

/// Waits for the outstanding command, publishing its correlated frame and
/// containing an uncertain attempt whose authority window closed while it
/// was pending.
fn poll_pending(
    state: &mut BoundedRequestLoop,
    channel: &mut DeliverySetChannel,
    commands: &SyncSender<WorkerCommand>,
    outcomes: &Receiver<WorkerOutcome>,
) -> Result<(), LoopError> {
    match outcomes.recv_timeout(CONTROL_POLL) {
        Ok(outcome) => {
            state.lifecycle.in_flight = false;
            if let Some(frame) = state.on_outcome(outcome) {
                channel.publish(&frame)?;
            }
            if let Some(command) = state.queued {
                state.send(command, commands)?;
            }
            Ok(())
        }
        Err(RecvTimeoutError::Timeout) => {
            state.containment_step()?;
            if let Some(command) = state.queued {
                state.send(command, commands)?;
            }
            Ok(())
        }
        Err(RecvTimeoutError::Disconnected) => Err(LoopError::ChannelUnavailable),
    }
}

/// Outcome of the ordinary governed path: the canonical correlated frame.
pub type OrdinaryOutcome = WasmHostResultFrame;

/// Typed refusal of the ordinary governed path.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum OrdinaryDriveError {
    /// No owner delivery set is staged beside this installation.
    NoDeliverySet,
    /// The delivery set, installation binding, permit, or admitted world
    /// failed closed before the loop could start.
    Drive(DriveError),
    /// The bounded request loop failed closed.
    Loop(LoopError),
}

impl fmt::Display for OrdinaryDriveError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoDeliverySet => formatter.write_str("ORDINARY_NO_ADMITTED_DELIVERY_SET"),
            Self::Drive(error) => write!(formatter, "{error}"),
            Self::Loop(error) => write!(formatter, "{error}"),
        }
    }
}

impl std::error::Error for OrdinaryDriveError {}

/// Runs the ordinary governed path for this process: binds the owner
/// delivery set, resolves the authenticated grant into a local admitted port
/// set, and serves the bounded request loop to its correlated terminal
/// frame.
///
/// Generation replacement closes here. After the current set is consumed,
/// the staged path is re-read through the same validated loader: a
/// replacement set — one naming a grant this process has not served — is
/// revalidated through the identical full admission path with fresh
/// authority, while the previous generation's binding, permit, and
/// authority cell are dropped, never reused. A re-staged copy of the grant
/// this process already served ends the chain without a second execution:
/// spent one-shot authority is never revived, and the completed outcome —
/// whose terminal frame was already published — stands.
///
/// # Errors
///
/// Returns [`OrdinaryDriveError`] when the delivery set, the installation
/// binding, the one-shot permit, the admitted world, the request source,
/// the result sink, or a request binding fails closed.
pub fn run_ordinary_request_loop() -> Result<OrdinaryOutcome, OrdinaryDriveError> {
    let mut served_grant: Option<String> = None;
    let mut outcome: Option<OrdinaryOutcome> = None;
    // The staged path is the owner's only route into this process, and the
    // previous set was consumed, so any set observed here is either a
    // replacement generation or a same-grant re-stage. Nothing is carried
    // across iterations except the served grant digest below, so no
    // accumulation is possible.
    while let Some(material) = read_admitted_material().map_err(OrdinaryDriveError::Drive)? {
        if served_grant.as_deref() == Some(material.grant.grant_digest.as_str()) {
            // Same grant this process already served to its published
            // terminal frame. Serving it again would revive spent one-shot
            // authority for a new effect, so the chain ends here.
            break;
        }
        let runtime =
            build_admitted_runtime(&material, edge_now_ms()).map_err(OrdinaryDriveError::Drive)?;
        let frame = run_request_loop(runtime, &material);
        // The delivery set is one-shot: it is consumed exactly once, so a
        // leftover is a fresh-drive signal rather than a silent reuse. The
        // in-memory retention of the terminal frame above is the readback
        // path, not a second execution.
        consume_delivery_set();
        let frame = frame.map_err(OrdinaryDriveError::Loop)?;
        served_grant = Some(material.grant.grant_digest.as_str().to_owned());
        outcome = Some(frame);
    }
    outcome.ok_or(OrdinaryDriveError::NoDeliverySet)
}

/// Consumes the staged delivery set beside this installation. Best effort by
/// contract, and derived from the loader path only — never from argv, stdin,
/// or environment.
fn consume_delivery_set() {
    use crate::dispatch_material::{
        WASM_HOST_GUEST_ARTIFACT_FILE_NAME, WASM_HOST_GUEST_INPUT_FILE_NAME,
        WASM_HOST_MATERIAL_FILE_NAME, admitted_material_path, consume_staged,
    };
    let Some(directory) =
        admitted_material_path().and_then(|path| path.parent().map(Path::to_path_buf))
    else {
        return;
    };
    consume_staged(&directory.join(WASM_HOST_MATERIAL_FILE_NAME));
    consume_staged(&directory.join(WASM_HOST_GUEST_ARTIFACT_FILE_NAME));
    consume_staged(&directory.join(WASM_HOST_GUEST_INPUT_FILE_NAME));
}

/// Reads the owner-staged delivery set beside this installation.
fn read_admitted_material() -> Result<Option<ValidatedDispatchMaterial>, DriveError> {
    read_dispatch_material().map_err(|error| match error {
        MaterialError::Missing => DriveError::NoMaterial,
        other => DriveError::Material(other),
    })
}
