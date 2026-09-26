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
//! Two more disciplines close the loop's edges:
//!
//! - **External control is real intake, not self-talk.** An installed
//!   [`KernelControlReader`] polls the owner-staged control-request file on
//!   every tick — including while guest work is pending — and admits what
//!   it yields through the same frame shape, parse, and binding validation
//!   the delivery-set path uses, so one admission path serves both sources.
//!   Only an identity-matching Cancel/Reconcile/Shutdown is consumed;
//!   anything else is left for its own delivery.
//! - **Emission and cleanup are bounded.** Each result event is validated
//!   and gets a bounded caller wait on stdout; a caller timeout retains
//!   the helper for tracked termination and never reuses the contended
//!   stream while it runs, and the staged set is consumed only while it
//!   still names the served generation, so a replacement staged mid-run is
//!   never deleted.
//!
//! The experimental describe path and the one-shot guest-child protocol are
//! separate modes reachable only through their own CLI branches; the
//! governed loop never falls back to either, and neither falls back here.

use std::collections::BTreeMap;
use std::fmt;
use std::fmt::Write as _;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::mpsc::{
    Receiver, RecvTimeoutError, SyncSender, TrySendError, channel, sync_channel,
};
use std::time::Duration;

use eliot_wasm_runtime::{
    EngineBinding, InvocationRequest, InvocationResult, Sha256Digest, VerificationVerdict,
};

use crate::WasmHostRunner;
use crate::admission::LiveAuthority;
use crate::dispatch_drive::{
    DriveError, LifecycleVerdicts, SeatedVerdicts, evaluate_lifecycle_verdicts,
    evaluate_seated_verdicts,
};
use crate::dispatch_material::{
    MaterialError, ValidatedDispatchMaterial, WASM_HOST_CONTROL_FILE_NAME, admitted_material_path,
    consume_staged, read_staged_bytes,
};
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
/// Result-event wire version (#2787). Independent of the request constant:
/// the result family is its own versioned contract, so a request-shape
/// revision never silently re-versions emitted results and a result-shape
/// revision never admits foreign requests. Version 2 adds the required
/// bounded `observation_predecessors` field; this producer no longer emits
/// version 1. Consumers must reject every other version. (Prior emissions
/// carried the request constant by defect.)
pub const WASM_HOST_RESULT_WIRE_VERSION: u16 = 2;
/// Closed observation phase: the frame observes guest execution.
pub const RESULT_PHASE_EXECUTE: &str = "execute";
/// Closed observation phase: the frame observes containment of an uncertain
/// attempt through the runtime owner.
pub const RESULT_PHASE_CONTAIN: &str = "contain";
/// Closed observation phase: the frame observes reconciliation of an
/// uncertain attempt through its owners.
pub const RESULT_PHASE_RECONCILE: &str = "reconcile";
/// Closed observation phase: the frame refuses before execution. Admission
/// denials currently surface as the process exit path (stderr plus exit
/// status), not as stdout frames, so no producer emits this phase today; it
/// stays in the closed vocabulary so a future pre-execution denial frame
/// cannot masquerade as an execution observation.
pub const RESULT_PHASE_DENY: &str = "deny";
/// Bound on the retained/emitted result-event sequence per operation
/// (#2787). The follow-up taxonomy admits at most one initial observation
/// plus one follow-up observation per operation, so two events is the
/// structural maximum; the bound leaves headroom for future bounded phases
/// without permitting unbounded growth, and emission fails closed past it.
pub const MAX_RESULT_SEQUENCE: u64 = 8;

/// Bounded result-byte budget: the largest result frame the loop publishes.
pub const MAX_RESULT_FRAME_BYTES: usize = 64 * 1024;

/// Control-loop poll cadence while a command is outstanding. It bounds how
/// long the loop can go without re-checking the authority window; it starts
/// no worker and decides no timeout policy of its own.
const CONTROL_POLL: Duration = Duration::from_millis(25);

/// Output deadline for one result-frame emission. A size budget is not a
/// time budget: when the reader stops consuming, the synchronous stdout
/// write plus flush would wedge the control thread forever, so one frame
/// gets this bounded wait and then fails closed. Same value and discipline
/// as the agent-bridge `STDOUT_WRITE_TIMEOUT` precedent: at most one
/// outstanding frame, a bounded wait on the slow consumer, and no reuse of
/// the contended stream after a timeout.
const OUTPUT_DEADLINE: Duration = Duration::from_secs(5);

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
    /// A result frame failed its own consistency validation before
    /// emission (#2787: digest/length/hex agreement, omission semantics,
    /// engine/claim/operation bindings, phase versus command, sequence
    /// bound). A frame that cannot prove itself is never emitted.
    ResultInvalid {
        /// Stable field name.
        field: &'static str,
    },
    /// A command was not accepted because the bounded command queue was full.
    CommandQueueFull {
        /// Exact command whose enqueue remains pending.
        command: &'static str,
    },
    /// A command was not accepted because the worker command receiver closed.
    CommandChannelDisconnected {
        /// Exact command whose enqueue was refused.
        command: &'static str,
    },
    /// The worker exited before returning the accepted command's outcome.
    WorkerTerminatedWithoutOutcome {
        /// Exact accepted command whose outcome remains unknown.
        command: &'static str,
    },
    /// The worker outcome channel disconnected before the accepted command replied.
    OutcomeChannelDisconnected {
        /// Exact accepted command whose outcome remains unknown.
        command: &'static str,
    },
}

impl LoopError {
    /// Stable code for this rejection.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::RequestDenied { .. } => "REQUEST_LOOP_DENIED",
            Self::ChannelUnavailable => "REQUEST_LOOP_CHANNEL_UNAVAILABLE",
            Self::ResultTooLarge => "REQUEST_LOOP_RESULT_TOO_LARGE",
            Self::ResultInvalid { .. } => "REQUEST_LOOP_RESULT_INVALID",
            Self::CommandQueueFull { .. } => "REQUEST_LOOP_COMMAND_QUEUE_FULL",
            Self::CommandChannelDisconnected { .. } => "REQUEST_LOOP_COMMAND_CHANNEL_DISCONNECTED",
            Self::WorkerTerminatedWithoutOutcome { .. } => {
                "REQUEST_LOOP_WORKER_TERMINATED_WITHOUT_OUTCOME"
            }
            Self::OutcomeChannelDisconnected { .. } => "REQUEST_LOOP_OUTCOME_CHANNEL_DISCONNECTED",
        }
    }
}

impl fmt::Display for LoopError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RequestDenied { field } => write!(formatter, "{}:{field}", self.code()),
            Self::CommandQueueFull { command }
            | Self::CommandChannelDisconnected { command }
            | Self::WorkerTerminatedWithoutOutcome { command }
            | Self::OutcomeChannelDisconnected { command } => {
                write!(formatter, "{}:{command}", self.code())
            }
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

/// Correlated owner-backed result event (#2787: the one versioned result
/// contract). Bounded serialization only: the guest output travels as
/// lowercase hex under the admitted output ceiling, and a frame that would
/// exceed the result budget is published with the payload omitted and its
/// digest retained.
///
/// This is the only schema ever emitted under [`WASM_HOST_RESULT_WIRE_ID`]:
/// there is no second parallel result DTO. Allowed stream sequences per
/// operation, all under [`WASM_HOST_RESULT_WIRE_VERSION`] with gapless
/// `sequence` values from 0 and exactly one `terminal: true` event closing
/// the stream:
/// - one terminal success/refusal event (healthy execution, worker
///   refusal);
/// - one nonterminal `Unknown` execution event followed by one terminal
///   containment/reconciliation event carrying its own command/phase
///   identity and an ordered reference to the prior observation, with the
///   original uncertainty preserved, never rewritten;
/// - a publication failure surfaces through the loop error and the retained
///   observation, never as an ad hoc fallback object.
///
/// Consumers must reject mixed versions, duplicate terminal events, sequence
/// gaps, and contradictory identities. Absence stays absence per I5.16:
/// `None` serializes absent, measured zero stays numeric zero, Booleans stay
/// Booleans, and no formatting helper feeds stringified values back into
/// this contract.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
#[serde(deny_unknown_fields)]
// Four JSON Booleans are the versioned wire shape (#2787 step 4: Booleans
// stay Booleans); an enum would break the Boolean contract.
#[allow(clippy::struct_excessive_bools)]
pub struct WasmHostResultFrame {
    /// Result wire identity.
    pub wire_id: &'static str,
    /// Result wire version ([`WASM_HOST_RESULT_WIRE_VERSION`]).
    pub wire_version: u16,
    /// Closed observation phase (`execute`, `contain`, `reconcile`, `deny`):
    /// what this event observes. A Cancel/Reconcile outcome carries its own
    /// phase and never masquerades as a new Invoke result.
    pub phase: String,
    /// Worker command this event observes (`execute`, `cancel`,
    /// `reconcile`); `None` when the frame refuses before any worker
    /// command ran.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub worker_command: Option<String>,
    /// Bounded event sequence number within the operation, from 0, gapless.
    pub sequence: u64,
    /// Complete ordered prefix of prior observation sequence numbers used by
    /// this event. The first event has no predecessors; each follow-up names
    /// every retained event before it, bounded by `sequence`.
    pub observation_predecessors: Vec<u64>,
    /// Whether this event closes the operation's result stream.
    pub terminal: bool,
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
    /// Opaque #2786 delivery identity passthrough. `None` until the
    /// delivery/acknowledgement lane binds it; carried as an opaque string,
    /// never interpreted here.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub delivery_id: Option<String>,
    /// Seated engine mode identity; `None` when no engine observation
    /// exists (a refusal invents no engine evidence).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub engine_implementation_id: Option<String>,
    /// Seated engine exact version; `None` when no engine observation
    /// exists.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub engine_version: Option<String>,
    /// Classified disposition.
    pub disposition: String,
    /// Typed error code, when the invocation did not succeed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    /// SHA-256 of the guest output bytes; present only when output bytes
    /// were actually observed (or retained under omission).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub output_digest: Option<String>,
    /// Guest output byte count actually observed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub output_bytes: Option<u64>,
    /// Lowercase-hex guest output, present only when output bytes were
    /// actually observed: absent output stays absent (never empty hex), an
    /// observed empty vector serializes as `""`, and a budget-omitted
    /// payload is `None` with `output_omitted` set.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub output_hex: Option<String>,
    /// True when the output payload was omitted under the frame budget.
    pub output_omitted: bool,
    /// Child-observed fuel consumed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fuel_consumed: Option<u64>,
    /// Child-observed peak memory bytes.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub peak_memory_bytes: Option<u64>,
    /// Child-observed table elements.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub table_elements: Option<u64>,
    /// Child-observed epoch ticks.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub epoch_ticks: Option<u64>,
    /// Lifecycle verdicts evaluated from the retained result.
    pub verdict_shadow: String,
    pub verdict_canary: String,
    pub verdict_rollback: String,
    pub verdict_cutover: String,
    /// Seated trap / cancel / drain / rollback verdicts for the same run.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub trap: Option<String>,
    pub cancelled: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub drain: Option<String>,
    pub rollback_candidate: bool,
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
/// The observed worker command fixes the frame's operation, phase, and
/// worker-command identities: a Cancel outcome answers [`OP_CANCEL`] in the
/// `contain` phase, a Reconcile outcome answers [`OP_RECONCILE`] in the
/// `reconcile` phase, and neither ever masquerades as a new Invoke result.
/// Absent output stays absent: `output_hex` is present only when output
/// bytes were actually observed, so no-output, observed-empty, and
/// budget-omitted stay distinct. Sequence and terminal disposition are
/// assigned by the loop when the frame joins the retained sequence, not
/// here.
fn project_result(
    binding: &AdmittedBinding,
    engine: &EngineBinding,
    command: WorkerCommand,
    result: &InvocationResult,
) -> WasmHostResultFrame {
    let (shadow, canary, rollback, cutover) = lifecycle_frame(evaluate_lifecycle_verdicts(result));
    let (trap, cancelled, drain, rollback_candidate) =
        seated_frame(evaluate_seated_verdicts(result));
    let (fuel_consumed, peak_memory_bytes, table_elements, epoch_ticks) = usage_frames(result);
    WasmHostResultFrame {
        wire_id: WASM_HOST_RESULT_WIRE_ID,
        wire_version: WASM_HOST_RESULT_WIRE_VERSION,
        phase: command_phase(command).to_owned(),
        worker_command: Some(command_name(command).to_owned()),
        sequence: 0,
        observation_predecessors: Vec::new(),
        terminal: false,
        operation: command_operation(command).to_owned(),
        claim_id: binding.claim_id.clone(),
        operation_id: binding.operation_id.clone(),
        invocation_id: binding.invocation_id.clone(),
        request_digest: binding.request_digest.clone(),
        grant_digest: binding.grant_digest.clone(),
        component_id: binding.component_id.clone(),
        artifact_digest: binding.artifact_digest.clone(),
        input_digest: binding.input_digest.clone(),
        delivery_id: None,
        engine_implementation_id: Some(engine.implementation_id.clone()),
        engine_version: Some(engine.exact_version.clone()),
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
        output_hex: result.output.as_ref().map(|bytes| hex(bytes)),
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
    // Omission drops a payload that exists: a frame with no observed output
    // has nothing to omit, so `output_omitted` stays false and the size
    // refusal (if any) surfaces at publish instead of inventing evidence.
    if (over_ceiling || !within) && frame.output_hex.is_some() {
        frame.output_hex = None;
        frame.output_omitted = true;
    }
    frame
}

/// Decodes the lowercase hex the loop emits. `None` on any shape or digit
/// fault; used only to check a frame's own digest/length agreement.
fn unhex(text: &str) -> Option<Vec<u8>> {
    if !text.len().is_multiple_of(2) {
        return None;
    }
    let mut out = Vec::with_capacity(text.len() / 2);
    let bytes = text.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        let high = hex_value(bytes[index])?;
        let low = hex_value(bytes[index + 1])?;
        out.push(high * 16 + low);
        index += 2;
    }
    Some(out)
}

fn hex_value(digit: u8) -> Option<u8> {
    match digit {
        b'0'..=b'9' => Some(digit - b'0'),
        b'a'..=b'f' => Some(digit - b'a' + 10),
        _ => None,
    }
}

/// Stable invalid-frame fault constructor.
fn invalid(field: &'static str) -> LoopError {
    LoopError::ResultInvalid { field }
}

fn validate_observation_predecessors(frame: &WasmHostResultFrame) -> Result<(), LoopError> {
    let predecessor_count = u64::try_from(frame.observation_predecessors.len())
        .map_err(|_| invalid("observation-predecessors"))?;
    if predecessor_count != frame.sequence {
        return Err(invalid("observation-predecessors"));
    }
    for (index, predecessor) in frame.observation_predecessors.iter().enumerate() {
        let expected = u64::try_from(index).map_err(|_| invalid("observation-predecessors"))?;
        if *predecessor != expected {
            return Err(invalid("observation-predecessors"));
        }
    }
    Ok(())
}

/// Validates one result frame's internal consistency before emission
/// (#2787 step 5): wire identity/version, closed operation/phase/command
/// vocabulary and their agreement, sequence bound and complete ordered
/// predecessor prefix, output
/// digest/length/hex agreement and omission semantics, and engine-evidence
/// bindings. A frame that cannot prove itself is never emitted; a refusal
/// carries its exact phase with no invented engine, usage, or output
/// evidence, and an unknown outcome stays unknown — local serialization
/// success upgrades nothing.
fn validate_frame(frame: &WasmHostResultFrame) -> Result<(), LoopError> {
    if frame.wire_id != WASM_HOST_RESULT_WIRE_ID {
        return Err(invalid("wire-id"));
    }
    if frame.wire_version != WASM_HOST_RESULT_WIRE_VERSION {
        return Err(invalid("wire-version"));
    }
    if frame.sequence >= MAX_RESULT_SEQUENCE {
        return Err(invalid("sequence-bound"));
    }
    validate_observation_predecessors(frame)?;
    let operation_known = matches!(
        frame.operation.as_str(),
        OP_INVOKE | OP_CANCEL | OP_RECONCILE | OP_SHUTDOWN
    );
    if !operation_known {
        return Err(invalid("operation"));
    }
    let phase_known = matches!(
        frame.phase.as_str(),
        RESULT_PHASE_EXECUTE | RESULT_PHASE_CONTAIN | RESULT_PHASE_RECONCILE | RESULT_PHASE_DENY
    );
    if !phase_known {
        return Err(invalid("phase"));
    }
    // Phase versus command: the observed command fixes the phase, and each
    // operation answers in its own phase, so a Cancel/Reconcile outcome can
    // never masquerade as a new Invoke result.
    let phase_matches_command = match frame.worker_command.as_deref() {
        Some("execute") => frame.phase == RESULT_PHASE_EXECUTE && frame.operation == OP_INVOKE,
        Some("cancel") => frame.phase == RESULT_PHASE_CONTAIN && frame.operation == OP_CANCEL,
        Some("reconcile") => {
            frame.phase == RESULT_PHASE_RECONCILE && frame.operation == OP_RECONCILE
        }
        Some(_) => false,
        None => frame.phase == RESULT_PHASE_DENY,
    };
    if !phase_matches_command {
        return Err(invalid("phase-command"));
    }
    if frame.claim_id.is_empty()
        || frame.operation_id.is_empty()
        || frame.invocation_id.is_empty()
        || frame.request_digest.is_empty()
        || frame.grant_digest.is_empty()
        || frame.component_id.is_empty()
        || frame.artifact_digest.is_empty()
        || frame.input_digest.is_empty()
    {
        return Err(invalid("claim-binding"));
    }
    // Output agreement: hex present ⟹ digest and length agree with the
    // decoded bytes; omitted ⟹ hex absent with digest and length retained;
    // neither ⟹ no output evidence at all. Each state is distinct.
    match (
        frame.output_hex.as_deref(),
        frame.output_digest.as_deref(),
        frame.output_bytes,
        frame.output_omitted,
    ) {
        (Some(text), Some(digest), Some(length), false) => {
            let Some(bytes) = unhex(text) else {
                return Err(invalid("output-hex"));
            };
            let observed = u64::try_from(bytes.len()).map_err(|_| invalid("output-length"))?;
            if observed != length {
                return Err(invalid("output-length"));
            }
            if Sha256Digest::of_bytes(&bytes).as_str() != digest {
                return Err(invalid("output-digest"));
            }
        }
        (None, Some(_), Some(_), true) | (None, None, None, false) => {}
        _ => return Err(invalid("output-omitted")),
    }
    // Engine-evidence binding: an executed observation names its seated
    // engine; a worker refusal or a pre-execution denial carries none and
    // invents none. Mixed or empty engine halves are never valid.
    match (
        frame.worker_command.as_deref(),
        frame.engine_implementation_id.as_deref(),
        frame.engine_version.as_deref(),
    ) {
        (Some(_), Some(engine), Some(version)) if !engine.is_empty() && !version.is_empty() => {}
        (_, None, None) => {}
        _ => return Err(invalid("engine-binding")),
    }
    // A frame with no engine observation is a refusal, so it names its
    // refusal code; an error-free frame always names its engine.
    if frame.engine_implementation_id.is_none() && frame.error.is_none() {
        return Err(invalid("refusal-code"));
    }
    // Refusals carry no invented usage or output evidence — both
    // pre-execution denials (no worker command) and worker refusals (a
    // command with no engine binding): no engine observation means no
    // usage or output was measured. Executed observations keep whatever
    // the child actually reported, including absence.
    if frame.engine_implementation_id.is_none()
        && (frame.fuel_consumed.is_some()
            || frame.peak_memory_bytes.is_some()
            || frame.table_elements.is_some()
            || frame.epoch_ticks.is_some()
            || frame.output_digest.is_some()
            || frame.output_bytes.is_some()
            || frame.output_hex.is_some()
            || frame.output_omitted)
    {
        return Err(invalid("denial-evidence"));
    }
    validate_lifecycle_vocabulary(frame)
}

/// Lifecycle verdict applicability: verdicts are the closed
/// `verified`/`rejected` vocabulary from the owning dispatch-drive
/// evaluator, never lifecycle strings manufacturing success; the
/// classified disposition is the closed `InvocationDisposition`
/// vocabulary. Both producers emit only these spellings.
fn validate_lifecycle_vocabulary(frame: &WasmHostResultFrame) -> Result<(), LoopError> {
    for verdict in [
        frame.verdict_shadow.as_str(),
        frame.verdict_canary.as_str(),
        frame.verdict_rollback.as_str(),
        frame.verdict_cutover.as_str(),
    ] {
        if verdict != "verified" && verdict != "rejected" {
            return Err(invalid("lifecycle-verdict"));
        }
    }
    match frame.disposition.as_str() {
        "Succeeded" | "Rejected" | "Unavailable" | "Unknown" => {}
        _ => return Err(invalid("disposition-vocabulary")),
    }
    Ok(())
}

/// Terminal frame for a worker command the runtime refused, or for a
/// request refused before execution. The frame carries the exact operation
/// and phase of what was attempted — never a hardcoded Invoke — the stable
/// refusal code, and no invented engine, usage, or output evidence.
/// Sequence and terminal disposition are assigned by the loop when the
/// frame joins the retained sequence, not here.
fn denial_frame(
    binding: &AdmittedBinding,
    operation: &str,
    phase: &str,
    worker_command: Option<WorkerCommand>,
    error_code: &str,
) -> WasmHostResultFrame {
    WasmHostResultFrame {
        wire_id: WASM_HOST_RESULT_WIRE_ID,
        wire_version: WASM_HOST_RESULT_WIRE_VERSION,
        phase: phase.to_owned(),
        worker_command: worker_command.map(|command| command_name(command).to_owned()),
        sequence: 0,
        observation_predecessors: Vec::new(),
        terminal: false,
        operation: operation.to_owned(),
        claim_id: binding.claim_id.clone(),
        operation_id: binding.operation_id.clone(),
        invocation_id: binding.invocation_id.clone(),
        request_digest: binding.request_digest.clone(),
        grant_digest: binding.grant_digest.clone(),
        component_id: binding.component_id.clone(),
        artifact_digest: binding.artifact_digest.clone(),
        input_digest: binding.input_digest.clone(),
        delivery_id: None,
        engine_implementation_id: None,
        engine_version: None,
        disposition: "Rejected".to_owned(),
        error: Some(error_code.to_owned()),
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

    /// Non-blocking poll for one externally staged Kernel control frame
    /// naming this operation. `None` means nothing is pending right now —
    /// never exhaustion: the loop keeps serving the delivery set and polls
    /// again on its next tick, including while guest work is pending. The
    /// default has no external source and always reports nothing pending.
    ///
    /// # Errors
    ///
    /// Returns [`LoopError::ChannelUnavailable`] when the control source
    /// fails in a way the loop must not ignore.
    fn poll_control(&mut self) -> Result<Option<WasmHostRequestFrame>, LoopError> {
        Ok(None)
    }

    /// Publishes one correlated result frame: the one stdout emission
    /// owner for the ordinary result stream (#2787 step 2).
    ///
    /// # Errors
    ///
    /// Returns [`LoopError::ResultInvalid`] when the frame fails its own
    /// consistency validation, [`LoopError::ChannelUnavailable`] when the
    /// stream cannot be written (or stays contended past a caller timeout),
    /// or [`LoopError::ResultTooLarge`] when the frame exceeds the budget.
    /// Success is an observed local write plus flush, not owner
    /// acceptance; failure retains the observed result in the loop for
    /// drain accounting, never an ad hoc fallback.
    fn publish(&mut self, frame: &WasmHostResultFrame) -> Result<(), LoopError>;
}

/// Installed Kernel control reader: the external control intake of the
/// ordinary loop.
///
/// The owner stages the delivery set as files beside the installation; a
/// Kernel Cancel/Reconcile/Shutdown for the running operation stages the
/// same way, as one [`WasmHostRequestFrame`] JSON document at the
/// loader-derived control path. The loop polls this reader on every tick —
/// including while guest work is pending — and admits what it yields
/// through the same frame shape, parse, and binding validation the
/// delivery-set path uses, so one admission path serves both sources.
///
/// Fail-closed per frame: an absent, unreadable, oversize, malformed, or
/// foreign control file yields nothing and is left in place — ownership of
/// an unidentifiable file can never be established, and unauthenticated
/// input must neither act nor abort the admitted operation. Only a
/// well-formed frame naming this exact operation is consumed and returned.
/// `Invoke` is never admitted externally: the one admitted invoke comes
/// from the delivery set only, so a second execution path cannot open
/// through the control file.
pub struct KernelControlReader {
    path: PathBuf,
    identity: WasmHostControl,
}

impl KernelControlReader {
    /// Pins the reader to the loader-derived control path and the exact
    /// admitted operation identity it may consume control for.
    #[must_use]
    pub fn new(binding: &AdmittedBinding, path: PathBuf) -> Self {
        Self {
            path,
            identity: WasmHostControl {
                operation_id: binding.operation_id.clone(),
                invocation_id: binding.invocation_id.clone(),
                request_digest: binding.request_digest.clone(),
            },
        }
    }

    /// Returns one staged control frame naming this operation, consuming
    /// it, or `None` when nothing admittable is staged. Never fails the
    /// loop: every control-file fault degrades to nothing pending.
    fn poll(&self) -> Option<WasmHostRequestFrame> {
        let Ok(bytes) = read_staged_bytes(&self.path) else {
            return None;
        };
        let Ok(frame) = serde_json::from_slice::<WasmHostRequestFrame>(&bytes) else {
            return None;
        };
        match WasmHostRequestFrame::parse(&frame) {
            Ok(WasmHostRequest::Cancel(control) | WasmHostRequest::Reconcile(control))
                if control == self.identity =>
            {
                consume_staged(&self.path);
                Some(frame)
            }
            Ok(WasmHostRequest::Shutdown) if self.controls_this_operation(&frame) => {
                consume_staged(&self.path);
                Some(frame)
            }
            Ok(WasmHostRequest::Invoke(_)) if self.controls_this_operation(&frame) => {
                // Names this operation but is never externally admittable:
                // consume so it cannot spin the poll, and yield nothing.
                consume_staged(&self.path);
                None
            }
            Ok(_) | Err(_) => None,
        }
    }

    /// Pins a Shutdown or Invoke frame to this operation. Those parses
    /// carry their identity as plain fields, so the external path checks
    /// them here: parse alone authenticates nothing.
    fn controls_this_operation(&self, frame: &WasmHostRequestFrame) -> bool {
        frame.operation_id == self.identity.operation_id
            && frame.invocation_id == self.identity.invocation_id
            && frame.request_digest == self.identity.request_digest
    }
}

/// Outcome of one bounded stdout emission (#2787 owner comment on #2895).
/// A missed caller wait is reported as what it is — the caller gave up
/// waiting — never as bounded termination of the writer: the helper may
/// still be blocked holding the stdout lock, so its handle is retained for
/// tracked termination instead of dropped.
enum BoundedEmission {
    /// The helper confirmed `write_all` plus `flush` inside the wait.
    Written,
    /// The helper confirmed the write plus flush failed.
    WriteFailed,
    /// The caller wait elapsed first. The retained helper handle is still
    /// owned here: the caller must reap it once finished and must never
    /// claim the writer stopped.
    CallerTimedOut { helper: std::thread::JoinHandle<()> },
}

/// Emits one serialized frame on stdout with the bounded caller wait.
///
/// The write plus flush runs on a single named helper thread so a stalled
/// reader cannot wedge the control thread past [`OUTPUT_DEADLINE`]. At most
/// one frame is ever outstanding — the synchronous loop never pipelines a
/// second. The deadline is a caller-side observation window, not a bound on
/// the writer: on timeout the helper handle is returned (never dropped),
/// and the contended stream stays untouched until the helper is reaped
/// finished.
fn emit_frame_bounded(framed: Vec<u8>) -> Result<BoundedEmission, LoopError> {
    let (done_tx, done_rx) = channel::<bool>();
    let helper = std::thread::Builder::new()
        .name("eliot-wasm-host-stdout-write".to_owned())
        .spawn(move || {
            let stdout = std::io::stdout();
            let mut output = stdout.lock();
            let ok = output
                .write_all(&framed)
                .and_then(|()| output.write_all(b"\n"))
                .and_then(|()| output.flush())
                .is_ok();
            let _ = done_tx.send(ok);
        })
        .map_err(|_| LoopError::ChannelUnavailable)?;
    match done_rx.recv_timeout(OUTPUT_DEADLINE) {
        Ok(true) => {
            let _ = helper.join();
            Ok(BoundedEmission::Written)
        }
        Ok(false) => {
            let _ = helper.join();
            Ok(BoundedEmission::WriteFailed)
        }
        Err(_) => Ok(BoundedEmission::CallerTimedOut { helper }),
    }
}

/// Production channel over the owner delivery set and the canonical receipt
/// stream. One delivery set carries exactly one admitted operation, so the
/// channel issues that request once and then reports exhaustion, which is
/// what closes admission and starts the drain.
///
/// An installed [`KernelControlReader`] additionally feeds externally staged
/// Kernel control while the loop runs; without one the channel behaves
/// exactly as before.
pub struct DeliverySetChannel {
    admitted: Option<WasmHostRequestFrame>,
    delivered: bool,
    control: Option<KernelControlReader>,
    emission_broken: bool,
    /// stdout helper retained past a caller timeout (#2787). The handle is
    /// reaped once finished — tracked termination — and while it runs the
    /// contended stream is never reused, so at most one frame is ever
    /// outstanding and wire order is preserved.
    pending_helper: Option<std::thread::JoinHandle<()>>,
}

impl DeliverySetChannel {
    /// Binds the channel to the one admitted request frame of this
    /// delivery set.
    #[must_use]
    pub fn new(admitted: WasmHostRequestFrame) -> Self {
        Self {
            admitted: Some(admitted),
            delivered: false,
            control: None,
            emission_broken: false,
            pending_helper: None,
        }
    }

    /// Installs the Kernel control reader feeding external
    /// Cancel/Reconcile/Shutdown for this operation.
    #[must_use]
    pub fn with_kernel_control(mut self, reader: KernelControlReader) -> Self {
        self.control = Some(reader);
        self
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

    fn poll_control(&mut self) -> Result<Option<WasmHostRequestFrame>, LoopError> {
        match self.control.as_ref() {
            Some(reader) => Ok(reader.poll()),
            None => Ok(None),
        }
    }

    fn publish(&mut self, frame: &WasmHostResultFrame) -> Result<(), LoopError> {
        // Internal consistency first: a frame that cannot prove itself is
        // never emitted, and a publication failure retains the observed
        // result through the loop's drain accounting, never an ad hoc
        // fallback. A successful write plus flush below is an observed
        // local stream write, not proof the owner durably accepted the
        // result.
        validate_frame(frame)?;
        if self.emission_broken {
            // A previous emission confirmed its write failed; the stream
            // state is unusable, so every later frame fails closed here.
            return Err(LoopError::ChannelUnavailable);
        }
        // Tracked helper termination: reap a retained helper only once it
        // actually finished — a reaped handle is joined, never dropped
        // running. While it still runs, the contended stream is never
        // reused: the caller timeout is reported as a timeout, never as
        // bounded writer termination.
        if self
            .pending_helper
            .as_ref()
            .is_some_and(std::thread::JoinHandle::is_finished)
            && let Some(helper) = self.pending_helper.take()
        {
            let _ = helper.join();
        }
        if self.pending_helper.is_some() {
            return Err(LoopError::ChannelUnavailable);
        }
        let bytes = serde_json::to_vec(frame).map_err(|_| LoopError::ResultTooLarge)?;
        if bytes.len() > MAX_RESULT_FRAME_BYTES {
            return Err(LoopError::ResultTooLarge);
        }
        match emit_frame_bounded(bytes)? {
            BoundedEmission::Written => Ok(()),
            BoundedEmission::WriteFailed => {
                self.emission_broken = true;
                Err(LoopError::ChannelUnavailable)
            }
            BoundedEmission::CallerTimedOut { helper } => {
                self.pending_helper = Some(helper);
                Err(LoopError::ChannelUnavailable)
            }
        }
    }
}

impl Drop for DeliverySetChannel {
    /// Reaps the retained stdout helper when — and only when — it already
    /// finished. A still-blocked helper is never joined here: joining it
    /// could wedge teardown forever, and the drop must not claim a
    /// termination it did not observe.
    fn drop(&mut self) {
        if self
            .pending_helper
            .as_ref()
            .is_some_and(std::thread::JoinHandle::is_finished)
            && let Some(helper) = self.pending_helper.take()
        {
            let _ = helper.join();
        }
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

/// Closed `worker_command` name the result event records for one observed
/// worker command.
fn command_name(command: WorkerCommand) -> &'static str {
    match command {
        WorkerCommand::Execute => "execute",
        WorkerCommand::Cancel => "cancel",
        WorkerCommand::Reconcile => "reconcile",
        WorkerCommand::Shutdown => "shutdown",
    }
}

/// Operation a result event answers for one observed worker command. A
/// Shutdown outcome never projects a frame (the loop returns `None` for
/// it); the arm exists so the mapping stays total.
fn command_operation(command: WorkerCommand) -> &'static str {
    match command {
        WorkerCommand::Execute => OP_INVOKE,
        WorkerCommand::Cancel => OP_CANCEL,
        WorkerCommand::Reconcile => OP_RECONCILE,
        WorkerCommand::Shutdown => OP_SHUTDOWN,
    }
}

/// Observation phase a result event carries for one observed worker
/// command. Shutdown never projects a frame; see [`command_operation`].
fn command_phase(command: WorkerCommand) -> &'static str {
    match command {
        WorkerCommand::Execute => RESULT_PHASE_EXECUTE,
        WorkerCommand::Cancel => RESULT_PHASE_CONTAIN,
        WorkerCommand::Reconcile => RESULT_PHASE_RECONCILE,
        WorkerCommand::Shutdown => RESULT_PHASE_DENY,
    }
}

/// One reply from the tracked engine worker.
#[derive(Debug)]
struct WorkerOutcome {
    command: WorkerCommand,
    result: Result<InvocationResult, String>,
    /// Whether this Shutdown request won the runner's P-11 request race.
    shutdown_request_won: Option<bool>,
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
            let mut shutdown_request_won = None;
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
                    shutdown_request_won = Some(runner.request_shutdown());
                    shutdown = true;
                    Err("SHUTDOWN".to_owned())
                }
            };
            if outcome_tx
                .send(WorkerOutcome {
                    command,
                    result,
                    shutdown_request_won,
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

/// Explicit loop phase (#2785): intake runs only while `Running`; close or
/// exhaustion moves to `Draining`, an idled worker to `Drained`, and the
/// joined worker to `ShutDown`. Admission open/closed stays the existing
/// `LifecycleFlags.closed` bit plus the published/denial terms.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum LoopPhase {
    Running,
    Draining,
    Drained,
    ShutDown,
}

/// Bounded lifecycle flags of the loop. Grouped so no single struct carries
/// an unbounded set of independent booleans.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct LifecycleFlags {
    /// The exact command outstanding on the tracked worker, if any. This is
    /// the accepted-command half of the drain accounting: a command stays
    /// here until its own outcome is consumed and correlated.
    outstanding: Option<WorkerCommand>,
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
///
/// Drain wedge (#2785), fixed by drain-before-join: trigger 1 joins the
/// worker while a command is outstanding — the `Timeout` arm keeps the
/// `outstanding` command, the intake loop returns on exhaustion, and the join then
/// wedges behind the unconsumed outcome on the bound-1 channel; trigger 2
/// admits after close — `tick` closes admission after the loop-top check
/// yet intake still runs, and the `Timeout` arm stacks a second command
/// behind the outstanding one against `max_in_flight = 1`.
pub struct BoundedRequestLoop {
    binding: AdmittedBinding,
    engine: EngineBinding,
    live: Arc<LiveAuthority>,
    max_in_flight: usize,
    /// Exact retained result-event sequences keyed by the sealed request
    /// digest (#2787 step 3). Each observation appends; history is never
    /// rewritten, so an initial `Unknown` and its later control outcome
    /// both survive, and an exact replay republishes the same bounded
    /// sequence without executing again. Bounded by [`MAX_RESULT_SEQUENCE`].
    retained: BTreeMap<String, Vec<WasmHostResultFrame>>,
    /// Command queued by the last transition, not yet handed to the worker.
    queued: Option<WorkerCommand>,
    /// Retained sequence to republish when a request is an exact replay.
    replay: Option<Vec<WasmHostResultFrame>>,
    /// Next event sequence number for this operation, from 0, gapless.
    next_sequence: u64,
    phase: LoopPhase,
    lifecycle: LifecycleFlags,
    published: Option<WasmHostResultFrame>,
    denial: Option<LoopError>,
    /// Exact observed P-11 request disposition, distinct from join/exit.
    shutdown_request_won: Option<bool>,
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
            next_sequence: 0,
            phase: LoopPhase::Running,
            lifecycle: LifecycleFlags {
                outstanding: None,
                closed: false,
                one_shot_spent: false,
                follow_up: FollowUp::None,
            },
            published: None,
            denial: None,
            shutdown_request_won: None,
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

    /// Moves `Running` to `Draining`. Idempotent: every close path calls it,
    /// so a second close is a no-op rather than a second transition.
    fn begin_drain(&mut self) {
        if self.phase == LoopPhase::Running {
            self.phase = LoopPhase::Draining;
        }
    }

    /// Moves `Draining` to `Drained` once every accepted command's outcome
    /// was consumed with nothing queued. The caller gates this on a
    /// successful drain; idempotent over already-terminal phases.
    fn mark_drained(&mut self) {
        if self.phase == LoopPhase::Draining {
            self.phase = LoopPhase::Drained;
        }
    }

    /// Moves `Drained` to `ShutDown` once the worker handle joined.
    /// Idempotent over already-terminal phases.
    fn mark_shutdown(&mut self) {
        if self.phase == LoopPhase::Drained {
            self.phase = LoopPhase::ShutDown;
        }
    }

    /// Single-gate intake (#2785): new demand is taken only while `Running`
    /// with admission open, nothing outstanding, and nothing already queued.
    /// The bound-1 command channel admits exactly one outstanding command,
    /// so `outstanding` is the capacity signal — sending while a command is
    /// outstanding would stack a second command behind it.
    fn intake_open(&self) -> bool {
        self.phase == LoopPhase::Running
            && self.lifecycle.outstanding.is_none()
            && self.queued.is_none()
            && self.admission_open()
    }

    /// Drain-complete predicate: every accepted command's outcome was
    /// consumed (nothing outstanding) and none is queued.
    fn drain_complete(&self) -> bool {
        self.lifecycle.outstanding.is_none() && self.queued.is_none()
    }

    /// Control phase: refresh the observed clock and close admission on a
    /// revoked or expired binding. A trap in one bounded instance never
    /// reaches this state; it is classified and the loop keeps its contract.
    fn tick(&mut self) {
        self.live.observe(edge_now_ms());
        if !self.live.is_live() {
            self.lifecycle.closed = true;
            self.begin_drain();
        }
    }

    /// Admit phase for one request frame: wire, operation, identity, size,
    /// and live authority checks, then the replay and one-shot consumption
    /// rules. The control operations the loop derives for its own lifecycle
    /// travel through this same frame shape, parse, and validation, so the
    /// loop has one admission path rather than two.
    fn admit(&mut self, frame: &WasmHostRequestFrame) -> Result<(), LoopError> {
        let request = WasmHostRequestFrame::parse(frame)?;
        // Drain gate (#2785): once draining, new invoke demand is refused
        // with the typed drain-closed denial; pre-drain admitted demand —
        // the control follow-ups settling the admitted attempt — keeps its
        // exact scope through the unchanged arms below.
        if self.phase != LoopPhase::Running && matches!(request, WasmHostRequest::Invoke(_)) {
            return Err(denied("drain-closed"));
        }
        self.queued = None;
        self.replay = None;
        match &request {
            WasmHostRequest::Invoke(invoke) => {
                check_invoke(&self.binding, &self.live, invoke)?;
                if let Some(retained) = self.retained.get(&invoke.request_digest) {
                    // Exact retained-sequence replay: legitimate result
                    // readback of the same bounded event sequence, never a
                    // new execution and never a new effect.
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
                self.queued = Some(WorkerCommand::Cancel);
            }
            WasmHostRequest::Reconcile(control) => {
                check_control(&self.binding, control)?;
                self.queued = Some(WorkerCommand::Reconcile);
            }
            WasmHostRequest::Shutdown => {
                self.lifecycle.closed = true;
                self.begin_drain();
            }
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
            self.shutdown_request_won = outcome.shutdown_request_won;
            return None;
        }
        // The observed command fixes the frame's operation/phase identity:
        // a Cancel outcome answers `OP_CANCEL` in the `contain` phase, a
        // Reconcile outcome answers `OP_RECONCILE` in the `reconcile` phase.
        // Control outcomes never masquerade as Invoke results.
        let command = outcome.command;
        let mut frame = match outcome.result {
            Ok(result) => project_result(&self.binding, &self.engine, command, &result),
            Err(code) => denial_frame(
                &self.binding,
                command_operation(command),
                command_phase(command),
                Some(command),
                code.as_str(),
            ),
        };
        frame.sequence = self.next_sequence;
        frame.observation_predecessors = self
            .retained
            .get(&frame.request_digest)
            .into_iter()
            .flatten()
            .map(|previous| previous.sequence)
            .collect();
        frame = enforce_frame_budget(frame, self.binding.max_output_bytes);
        self.next_sequence = self.next_sequence.saturating_add(1);
        self.lifecycle.one_shot_spent = true;
        if frame.disposition == UNCERTAIN_DISPOSITION {
            self.settle_uncertain(&mut frame);
        } else {
            self.queued = None;
            frame.terminal = true;
            self.published = Some(frame.clone());
        }
        self.retained
            .entry(frame.request_digest.clone())
            .or_default()
            .push(frame.clone());
        Some(frame)
    }

    /// Chooses the single bounded next step for an uncertain outcome:
    /// containment once authority closed, one reconciliation pass while it
    /// is live, and terminal retention once either has been spent. The
    /// uncertain frame is nonterminal while its follow-up is queued and
    /// terminal once the follow-up is spent, and it is published either
    /// way, so the outcome is never hidden behind the follow-up step and
    /// the original uncertainty is never rewritten.
    fn settle_uncertain(&mut self, frame: &mut WasmHostResultFrame) {
        match self.lifecycle.follow_up {
            FollowUp::None if !self.live.is_live() => {
                let _ = self.queue_control(OP_CANCEL);
                frame.terminal = false;
            }
            FollowUp::None => {
                let _ = self.queue_control(OP_RECONCILE);
                frame.terminal = false;
            }
            FollowUp::Contained | FollowUp::Reconciled => {
                self.queued = None;
                frame.terminal = true;
                self.published = Some(frame.clone());
            }
        }
    }

    /// Control phase while a command is outstanding: contain the attempt if
    /// its authority window closed while the guest was still running. The
    /// bounded Store epoch and fuel policy is what actually interrupts the
    /// guest; this delivers the owner's containment to the runtime owner at
    /// the first point it can accept it.
    fn containment_step(&mut self) -> Result<(), LoopError> {
        // Never queue containment behind an outstanding command: the bound-1
        // channel admits exactly one, so the uncertain attempt settles after
        // its own outcome arrives, through the follow-up taxonomy.
        if self.lifecycle.outstanding.is_some()
            || self.lifecycle.follow_up != FollowUp::None
            || self.live.is_live()
        {
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
        match sender.try_send(command) {
            Ok(()) => {}
            Err(TrySendError::Full(_)) => {
                return Err(LoopError::CommandQueueFull {
                    command: command_name(command),
                });
            }
            Err(TrySendError::Disconnected(_)) => {
                return Err(LoopError::CommandChannelDisconnected {
                    command: command_name(command),
                });
            }
        }
        self.queued = None;
        self.lifecycle.outstanding = Some(command);
        match command {
            WorkerCommand::Cancel => self.lifecycle.follow_up = FollowUp::Contained,
            WorkerCommand::Reconcile => self.lifecycle.follow_up = FollowUp::Reconciled,
            WorkerCommand::Execute | WorkerCommand::Shutdown => {}
        }
        Ok(())
    }
}

/// Runs the bounded ordinary request loop over one granted execution.
///
/// The control phase always runs (authority refresh, drain, revocation,
/// containment, external control intake), the request phase admits at most
/// `max_in_flight` queued commands, and each reply is projected onto a
/// correlated owner-backed frame. The worker is always joined before the
/// loop returns, so no guest work outlives the process.
pub fn run_request_loop(
    runtime: AdmittedRuntime,
    material: &ValidatedDispatchMaterial,
) -> Result<WasmHostResultFrame, LoopError> {
    let binding = AdmittedBinding::from_material(material, &runtime.invocation);
    let request_frame = WasmHostRequestFrame::admitted_invoke(&binding);
    let mut channel = DeliverySetChannel::new(request_frame);
    if let Some(path) = kernel_control_path() {
        channel = channel.with_kernel_control(KernelControlReader::new(&binding, path));
    }
    let mut state = BoundedRequestLoop::new(
        binding,
        runtime.engine_binding.clone(),
        Arc::clone(&runtime.live),
    );
    let worker = spawn_worker(runtime, state.max_in_flight);
    let outcome = drive_loop(
        &mut state,
        &mut channel,
        &worker.commands,
        &worker.outcomes,
        &worker.handle,
    );
    // Join-after-drain (#2785 trigger 1): intake returns on close or
    // exhaustion with a command possibly outstanding, so keep polling
    // outcomes until the worker idles and only then shut down and join.
    // Joining with a command outstanding or an outcome unconsumed wedges the
    // worker's Shutdown reply behind the unread outcome on the bound-1
    // channel and the join never returns.
    state.begin_drain();
    let drained = drain_outstanding(
        &mut state,
        &mut channel,
        &worker.commands,
        &worker.outcomes,
        &worker.handle,
    );
    // Typed shutdown: only enqueue after accepted work and its outcomes have
    // settled. The accepted Shutdown remains outstanding until its exact
    // worker reply is consumed below.
    state.live.revoke();
    let mut shutdown_error = None;
    let shutdown_sent = if state.drain_complete() {
        state.queued = Some(WorkerCommand::Shutdown);
        match state.send(WorkerCommand::Shutdown, &worker.commands) {
            Ok(()) => true,
            Err(error) => {
                shutdown_error = Some(error);
                false
            }
        }
    } else {
        false
    };
    let shutdown_drained = if shutdown_sent {
        drain_outstanding(
            &mut state,
            &mut channel,
            &worker.commands,
            &worker.outcomes,
            &worker.handle,
        )
    } else {
        Ok(())
    };
    // If Shutdown was not accepted, select sender closure as the termination
    // protocol. If it was accepted, keep the sender alive and require the
    // tracked reply; the two protocols are never combined for an accepted
    // Shutdown.
    if !shutdown_sent {
        drop(worker.commands);
    }
    let termination_drain =
        drain_until_worker_exit(&mut state, &mut channel, &worker.outcomes, &worker.handle);
    let shutdown_observed = shutdown_sent
        && state.lifecycle.outstanding != Some(WorkerCommand::Shutdown)
        && state.shutdown_request_won.is_some();
    if state.drain_complete()
        && drained.is_ok()
        && shutdown_drained.is_ok()
        && termination_drain.is_ok()
        && shutdown_observed
    {
        state.mark_drained();
    }
    // `JoinHandle::join` is called only after the worker owner confirms
    // termination. The wait also drains any late bounded outcome before the
    // handle can be joined.
    while !worker.handle.is_finished() {
        std::thread::yield_now();
    }
    let joined = worker.handle.join().is_ok();
    if joined {
        state.mark_shutdown();
    }
    if let Some(error) = shutdown_error {
        return Err(error);
    }
    shutdown_drained?;
    termination_drain?;
    if let Some(error) = state.denial() {
        // The loop recorded the exact admission denial; report that stable
        // field rather than the transport symptom that surfaced it.
        return Err(error);
    }
    outcome?;
    drained?;
    // Explicit termination accounting (#2785): a worker that never took
    // `Shutdown` or never joined left guest work untracked; that is a
    // failed loop, never a silent success.
    if !shutdown_sent {
        return Err(LoopError::CommandChannelDisconnected {
            command: "shutdown",
        });
    }
    if !shutdown_observed {
        return Err(LoopError::WorkerTerminatedWithoutOutcome {
            command: "shutdown",
        });
    }
    if !joined {
        return Err(LoopError::ChannelUnavailable);
    }
    state.published().cloned().ok_or(denied("no-request"))
}

/// Derives the Kernel control-request path from the loader path only —
/// never from argv, stdin, or environment. `None` when the loader path is
/// unavailable, in which case the loop serves the delivery set with no
/// external control source.
fn kernel_control_path() -> Option<PathBuf> {
    admitted_material_path().and_then(|path| {
        path.parent()
            .map(|directory| directory.join(WASM_HOST_CONTROL_FILE_NAME))
    })
}

/// Admits one externally staged Kernel control frame through the same
/// admission path internal control uses. Returns whether a frame was
/// admitted; the caller then applies the loop's normal send/close handling
/// and continues its tick without pulling a new delivery request.
fn admit_external_control(
    state: &mut BoundedRequestLoop,
    channel: &mut dyn WasmHostRequestChannel,
) -> Result<bool, LoopError> {
    let Some(frame) = channel.poll_control()? else {
        return Ok(false);
    };
    if let Err(error) = state.admit(&frame) {
        state.denial = Some(error);
        return Err(error);
    }
    Ok(true)
}

/// The control / request / completion cycle. Split out so each phase stays a
/// single bounded step.
fn drive_loop(
    state: &mut BoundedRequestLoop,
    channel: &mut dyn WasmHostRequestChannel,
    commands: &SyncSender<WorkerCommand>,
    outcomes: &Receiver<WorkerOutcome>,
    handle: &std::thread::JoinHandle<()>,
) -> Result<(), LoopError> {
    while state.admission_open() {
        state.tick();
        if state.lifecycle.outstanding.is_some() {
            poll_pending(state, channel, commands, outcomes, handle)?;
            continue;
        }
        // Single-gate intake (#2785 trigger 2): `tick` may have closed
        // admission after the loop-top check, so recheck before touching
        // the delivery set — no Execute lands after close.
        if !state.intake_open() {
            state.begin_drain();
            break;
        }
        // External control stays processable while the loop is idle too: a
        // Kernel Cancel racing the delivery set is admitted before the
        // invoke is pulled, never after it executed. Intake is provably
        // open here (nothing outstanding or queued), so no second command
        // stacks behind an outstanding one.
        if admit_external_control(state, channel)? {
            if let Some(command) = state.queued {
                state.send(command, commands)?;
            }
            continue;
        }
        let Some(frame) = channel.next_frame()? else {
            state.begin_drain();
            break;
        };
        if let Err(error) = state.admit(&frame) {
            // Record the exact admission denial before it surfaces as a
            // transport-level refusal, so the receipt names the field that
            // actually broke the binding.
            state.denial = Some(error);
            state.begin_drain();
            return Err(error);
        }
        if let Some(replay) = state.replay.clone() {
            state.replay = None;
            // Exact replay republishes the retained bounded sequence in
            // order — same events, same sequence numbers, same terminal —
            // without executing again. The terminal projection is the last
            // retained event.
            for event in &replay {
                channel.publish(event)?;
            }
            state.published = replay.last().cloned();
            state.begin_drain();
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
    channel: &mut dyn WasmHostRequestChannel,
    commands: &SyncSender<WorkerCommand>,
    outcomes: &Receiver<WorkerOutcome>,
    handle: &std::thread::JoinHandle<()>,
) -> Result<(), LoopError> {
    match outcomes.recv_timeout(CONTROL_POLL) {
        Ok(outcome) => consume_worker_outcome(state, channel, commands, outcome),
        Err(RecvTimeoutError::Timeout) => {
            if handle.is_finished()
                && let Some(command) = state.lifecycle.outstanding
            {
                // A reply can arrive between the timeout and the termination
                // observation. Consume that last reply before calling it lost.
                if let Ok(outcome) = outcomes.try_recv() {
                    return consume_worker_outcome(state, channel, commands, outcome);
                }
                return Err(LoopError::WorkerTerminatedWithoutOutcome {
                    command: command_name(command),
                });
            }
            // Single-gate intake (#2785 trigger 2): while a command is
            // outstanding on the bound-1 channel — or admission has
            // closed — never queue a second command behind it. An
            // uncertain attempt settles after its own outcome arrives,
            // through the existing follow-up taxonomy.
            if !state.intake_open() {
                return Ok(());
            }
            state.containment_step()?;
            // External control intake while the worker is idle (past the
            // single-gate check above, nothing is outstanding): the control
            // poll never blocks, so a Kernel Cancel/Reconcile/Shutdown
            // staged beside the delivery set is admitted through the same
            // path. Owner intent wins the single command slot over the
            // clock-derived containment above. While a command is
            // outstanding this whole block is deferred until its outcome
            // arrives — never stacked behind it.
            admit_external_control(state, channel)?;
            if let Some(command) = state.queued {
                state.send(command, commands)?;
            }
            Ok(())
        }
        Err(RecvTimeoutError::Disconnected) => {
            let command = state
                .lifecycle
                .outstanding
                .map_or("untracked", command_name);
            Err(LoopError::OutcomeChannelDisconnected { command })
        }
    }
}

fn consume_worker_outcome(
    state: &mut BoundedRequestLoop,
    channel: &mut dyn WasmHostRequestChannel,
    commands: &SyncSender<WorkerCommand>,
    outcome: WorkerOutcome,
) -> Result<(), LoopError> {
    // An uncorrelated reply cannot settle an accepted command.
    if state.lifecycle.outstanding != Some(outcome.command) {
        return Err(denied("uncorrelated-outcome"));
    }
    state.lifecycle.outstanding = None;
    if let Some(frame) = state.on_outcome(outcome) {
        channel.publish(&frame)?;
    }
    if let Some(command) = state.queued {
        state.send(command, commands)?;
    }
    Ok(())
}

/// Join-after-drain (#2785): after intake closes, keep polling worker
/// outcomes until the worker idles, so the join never meets an outstanding
/// command or an unconsumed outcome. Pre-drain admitted demand keeps its
/// exact scope — a queued follow-up is handed over once the worker is idle
/// — and control outcomes settle through the existing taxonomy. A
/// publication failure is recorded but never stops the drain: outcomes keep
/// flowing until the worker idles, and the failure surfaces afterwards.
fn drain_outstanding(
    state: &mut BoundedRequestLoop,
    channel: &mut dyn WasmHostRequestChannel,
    commands: &SyncSender<WorkerCommand>,
    outcomes: &Receiver<WorkerOutcome>,
    handle: &std::thread::JoinHandle<()>,
) -> Result<(), LoopError> {
    let mut first_error: Option<LoopError> = None;
    while !state.drain_complete() {
        if state.lifecycle.outstanding.is_some() {
            match poll_pending(state, channel, commands, outcomes, handle) {
                // The outcome was consumed but its delivery failed: keep
                // draining — a publication failure must not stop outcome
                // draining — and report the first such failure once idle.
                Err(error) if state.lifecycle.outstanding.is_none() => {
                    if first_error.is_none() {
                        first_error = Some(error);
                    }
                }
                result => result?,
            }
        } else if let Some(command) = state.queued {
            state.send(command, commands)?;
        }
        state.tick();
    }
    if let Some(error) = first_error {
        return Err(error);
    }
    Ok(())
}

/// Supervises the worker to termination while retaining every outcome still
/// available on the bounded channel. Used after drain/termination errors so
/// no return path drops a live `JoinHandle`. An unresolved command or enqueue
/// remains an explicit error after the worker exits.
fn drain_until_worker_exit(
    state: &mut BoundedRequestLoop,
    channel: &mut dyn WasmHostRequestChannel,
    outcomes: &Receiver<WorkerOutcome>,
    handle: &std::thread::JoinHandle<()>,
) -> Result<(), LoopError> {
    let mut first_error: Option<LoopError> = None;
    let mut observe = |outcome: WorkerOutcome| {
        if state.lifecycle.outstanding != Some(outcome.command) {
            first_error.get_or_insert(denied("uncorrelated-outcome"));
            return;
        }
        state.lifecycle.outstanding = None;
        if let Some(frame) = state.on_outcome(outcome)
            && let Err(error) = channel.publish(&frame)
        {
            first_error.get_or_insert(error);
        }
        if let Some(command) = state.queued {
            first_error.get_or_insert(LoopError::CommandChannelDisconnected {
                command: command_name(command),
            });
        }
    };

    while !handle.is_finished() {
        match outcomes.recv_timeout(CONTROL_POLL) {
            Ok(outcome) => observe(outcome),
            Err(RecvTimeoutError::Timeout | RecvTimeoutError::Disconnected) => {
                std::thread::yield_now();
            }
        }
    }
    while let Ok(outcome) = outcomes.try_recv() {
        observe(outcome);
    }
    if let Some(command) = state.lifecycle.outstanding {
        first_error.get_or_insert(LoopError::WorkerTerminatedWithoutOutcome {
            command: command_name(command),
        });
    }
    if let Some(command) = state.queued {
        first_error.get_or_insert(LoopError::CommandChannelDisconnected {
            command: command_name(command),
        });
    }
    first_error.map_or(Ok(()), Err)
}

/// Outcome of the ordinary governed path: the canonical correlated frame.
pub type OrdinaryOutcome = WasmHostResultFrame;

/// Typed refusal of the ordinary governed path.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum OrdinaryDriveError {
    /// No owner delivery set is staged beside this installation.
    NoDeliverySet,
    /// A staged delivery this drive already served — or its spent grant
    /// re-staged — is still present: terminal-unacknowledged across
    /// restart, with no retained result in this process. Explicit
    /// in-progress, never mistaken for absence.
    DeliveryInProgress {
        /// Served operation identity.
        operation_id: String,
        /// Served generation.
        generation: u64,
        /// Served claim identity.
        claim_id: String,
    },
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
            Self::DeliveryInProgress { .. } => formatter.write_str("ORDINARY_DELIVERY_IN_PROGRESS"),
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
    let mut served: Option<crate::dispatch_material::StagedDeliveryIdentity> = None;
    let mut outcome: Option<OrdinaryOutcome> = None;
    let mut replayed: Option<crate::dispatch_material::StagedDeliveryIdentity> = None;
    // The staged path is the owner's only route into this process, and the
    // previous set was consumed, so any set observed here is either a
    // replacement generation or a same-grant re-stage. Nothing is carried
    // across iterations except the served delivery identity below, so no
    // accumulation is possible.
    while let Some((claim, material)) =
        read_admitted_material().map_err(OrdinaryDriveError::Drive)?
    {
        // The claim arrives with the material from one claim-first read:
        // the pre-read envelope identity selected this operation before
        // the payload files were trusted, so the claim below is that
        // selection — never a copy derived after the fact. Durable served
        // state extends in-memory retention across restart: a staged set
        // the marker names is terminal-unacknowledged (a crash between
        // publish and reclaim), so it replays below instead of
        // re-executing.
        let served_marker = crate::dispatch_material::admitted_material_path()
            .and_then(|path| path.parent().map(std::path::Path::to_path_buf))
            .and_then(|directory| crate::dispatch_material::read_served_marker(&directory));
        match crate::dispatch_material::classify_staged_delivery(
            &material,
            served.as_ref(),
            served_marker.as_ref(),
        ) {
            crate::dispatch_material::StagedDeliveryState::Replay { identity } => {
                // Same delivery this process already served to its published
                // terminal frame — or the same grant under spent one-shot
                // authority, or a durable-marker terminal-unacknowledged set
                // after a crash between publish and reclaim. Serving it again
                // would revive spent authority for a new effect, so the chain
                // ends here with the retained result and the exact replayed
                // identity preserved.
                if outcome.is_none() {
                    // Cross-restart replay with nothing retained in this
                    // process: drain the exact-identity staged set plus its
                    // marker so the residue does not repeat every drive.
                    // Grant-only matches (another operation under the spent
                    // grant) are not ours to delete — a bounded fixed-name
                    // residual the owner must retire, still reported
                    // explicitly below, never as absence.
                    let exact = served.as_ref() == Some(&identity)
                        || served_marker
                            .as_ref()
                            .is_some_and(|mark| mark.names(&identity));
                    if exact
                        && let Some(directory) = crate::dispatch_material::admitted_material_path()
                            .and_then(|path| path.parent().map(std::path::Path::to_path_buf))
                    {
                        let _ =
                            crate::dispatch_material::reclaim_claimed_delivery(&claim, &directory);
                    }
                }
                replayed = Some(identity);
                break;
            }
            crate::dispatch_material::StagedDeliveryState::LegacyV1FixedName { identity } => {
                // Explicit v1 compatibility: full admission under the staged
                // identity verbatim, never reinterpreted as a fresh
                // generation with new identity.
                let _admitted_operation = identity.operation_id.len();
            }
        }
        let runtime =
            build_admitted_runtime(&material, edge_now_ms()).map_err(OrdinaryDriveError::Drive)?;
        let frame = run_request_loop(runtime, &material);
        // The delivery set is one-shot: a published terminal outcome reclaims
        // exactly the claimed generation, so a leftover is a fresh-drive
        // signal rather than a silent reuse. Unknown execution, failed
        // publication, lost response, or failed drain retains the exact
        // operation/generation evidence for recovery and never reclaims. The
        // in-memory retention of the terminal frame below is the readback
        // path, not a second execution.
        match frame {
            Ok(ok_frame) => {
                // Durable served marker (#2786 step 7): after the terminal
                // outcome published, before reclaim. A crash between the two
                // leaves staged bytes plus this marker, so restart replays
                // instead of re-executing. Best-effort: the serve already
                // happened exactly once.
                if let Some(directory) = crate::dispatch_material::admitted_material_path()
                    .and_then(|path| path.parent().map(std::path::Path::to_path_buf))
                {
                    let _ = crate::dispatch_material::write_served_marker(
                        &directory,
                        claim.identity(),
                        edge_now_ms(),
                    );
                }
                let reclamation = consume_delivery_set(&material, &claim);
                // Bounded residual only: a partial reclamation never
                // overwrites the primary result; retained files stay for
                // maintenance under the exact claimed identity.
                let _residual_complete = match &reclamation {
                    crate::dispatch_material::ClaimedReclamation::Reclaimed(detail) => {
                        let _reclaimed_operation = detail.identity.operation_id.len();
                        detail.fully_reclaimed()
                    }
                    crate::dispatch_material::ClaimedReclamation::ReplacementPreserved {
                        claimed,
                    }
                    | crate::dispatch_material::ClaimedReclamation::AlreadyGone { claimed }
                    | crate::dispatch_material::ClaimedReclamation::RetainedForRecovery {
                        claimed,
                    } => {
                        let _preserved_operation = claimed.operation_id.len();
                        false
                    }
                };
                served = Some(claim.into_identity());
                outcome = Some(ok_frame);
            }
            Err(loop_error) => {
                return Err(OrdinaryDriveError::Loop(loop_error));
            }
        }
    }
    // A replay with a retained frame returns that result; a replay with
    // nothing retained (cross-restart terminal-unacknowledged, or a
    // same-grant re-stage under spent authority) is explicit in-progress
    // — the marker carries identity, not a result payload, so no result
    // is fabricated. Only a drive that observed nothing staged reports
    // absence.
    match (outcome, replayed) {
        (Some(frame), _) => Ok(frame),
        (None, Some(identity)) => Err(OrdinaryDriveError::DeliveryInProgress {
            operation_id: identity.operation_id,
            generation: identity.generation,
            claim_id: identity.claim_id,
        }),
        (None, None) => Err(OrdinaryDriveError::NoDeliverySet),
    }
}

/// Consumes the staged delivery set beside this installation — but only
/// while it still names the exact claimed generation this loop served.
///
/// The publisher stages replacements under the same fixed filenames, so a
/// replacement published while this loop ran now owns those paths: the
/// claimed identity (claim, operation, generation, nonce, grant/fence,
/// digests, window, epoch) is re-read and compared, preserving the #2895
/// grant/artifact/input digest comparison as a subset, and each removal
/// re-verifies after a claim-by-rename move. Anything else — a
/// replacement, an unreadable envelope, or an already-consumed set — is
/// left untouched; a leftover is a fresh-drive signal, never silent reuse.
/// Derived from the loader path only — never from argv, stdin, or
/// environment. Returns the typed claimed reclamation; a partial outcome is
/// a bounded residual, never a primary-result overwrite.
fn consume_delivery_set(
    material: &ValidatedDispatchMaterial,
    claim: &crate::dispatch_material::DeliveryClaim,
) -> crate::dispatch_material::ClaimedReclamation {
    use crate::dispatch_material::admitted_material_path;
    let Some(directory) =
        admitted_material_path().and_then(|path| path.parent().map(Path::to_path_buf))
    else {
        return crate::dispatch_material::ClaimedReclamation::RetainedForRecovery {
            claimed: claim.identity().clone(),
        };
    };
    let reclamation = crate::dispatch_material::reclaim_claimed_delivery(claim, &directory);
    // Control retire is claim-pinned, not a fixed-name delete: the fixed
    // control name is only a locator — it is renamed aside under the exact
    // claimed operation identity and only aside bytes that prove they name
    // this operation are deleted. A foreign or malformed control is
    // restored (or left when a successor owns the name) for its own
    // delivery. Control ownership is (operation, grant) by protocol, so a
    // late same-operation control retires with its operation; the live
    // poll read-then-consume path above is unchanged and out of scope here.
    let _control = crate::dispatch_material::reclaim_claimed_file(
        &directory,
        WASM_HOST_CONTROL_FILE_NAME,
        claim.identity(),
        |bytes| control_bytes_name_operation(bytes, material),
    );
    reclamation
}

/// Returns whether staged control bytes name the served operation. Any
/// shape or identity mismatch answers no: ownership of an unidentifiable
/// file can never be established.
fn control_bytes_name_operation(bytes: &[u8], material: &ValidatedDispatchMaterial) -> bool {
    let Ok(frame) = serde_json::from_slice::<WasmHostRequestFrame>(bytes) else {
        return false;
    };
    frame.operation_id == material.operation_id
        && frame.grant_digest == material.grant.grant_digest.as_str()
}

/// Reads the owner-staged delivery set beside this installation,
/// claim-first: the pre-read claim arrives with its bound material from
/// one snapshot, so the fixed names never select the operation twice.
fn read_admitted_material() -> Result<
    Option<(
        crate::dispatch_material::DeliveryClaim,
        ValidatedDispatchMaterial,
    )>,
    DriveError,
> {
    crate::dispatch_material::read_claimed_dispatch_material().map_err(|error| match error {
        MaterialError::Missing => DriveError::NoMaterial,
        other => DriveError::Material(other),
    })
}
