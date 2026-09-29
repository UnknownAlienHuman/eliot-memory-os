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
//!   [`KernelControlReader`] polls the owner-published replayable control
//!   spool on every tick — including while guest work is pending — and admits
//!   what it yields through the same frame shape, parse, and binding
//!   validation the delivery-set path uses, so one admission path serves both
//!   sources. Typed acknowledgements record admission refusal, successful
//!   worker enqueue, and the observed command outcome against the exact
//!   generation/sequence; deliveries are never deleted by the child, and
//!   anything unadmittable stays in place as typed evidence for the owner.
//!   An admitted Cancel/Shutdown interrupts pending guest work without
//!   consuming its owner delivery; Reconcile waits for the idle path.
//! - **Emission and cleanup are bounded.** Each result event is validated
//!   and gets a bounded caller wait on stdout; a caller timeout retains
//!   the helper for tracked termination and never reuses the contended
//!   stream while it runs, and the staged set is consumed only while it
//!   still names the served generation, so a replacement staged mid-run is
//!   never deleted. Control spool files and acks are owner-reclaimed;
//!   cleanup deletes none of them, so a stale operation can never remove
//!   a newer control.
//!
//! Three terminal dispositions are kept apart, because collapsing any two
//! of them is how an uncertain effect gets reported as a clean stop
//! (issue #2785):
//!
//! - **Execution evidence** is the projected result event sequence; the
//!   uncertain `Unknown` event and the later containment/reconciliation
//!   event are separate retained observations, never one rewritten record.
//! - **Cleanup evidence** is this loop's own termination record: whether
//!   the tracked worker was asked to stop, whether its Shutdown reply
//!   arrived, and whether the thread was actually joined. A clean stop is
//!   claimed only when all three were observed.
//! - **Operation-level containment evidence** is what the outer
//!   process-containment owner (P-04, the Kernel that launched this
//!   process) observed about the P-03 guest child this operation still
//!   owns. A clean stop of this loop never upgrades it: a guest child
//!   without an observed exit stays unresolved for its owner.
//!
//! The execution deadline, the drain deadline, and the shutdown grace all
//! come from one owner: the admitted guest ceilings
//! ([`ceilings`](crate::dispatch_material::ValidatedGuestCeilings)), which
//! are the same numbers [`parent_runtime`](crate::parent_runtime) already
//! gives the composed runtime as its shutdown grace and
//! [`parent_runtime::derive_parent_intent`] gives the admitted child's
//! wall limit. The loop invents no timing policy of its own: drain bounds
//! are the granted ceilings plus the bounded control-poll cadence this
//! file already uses, because a drain can only make progress on a poll.
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
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{
    Receiver, RecvTimeoutError, SyncSender, TrySendError, channel, sync_channel,
};
use std::time::{Duration, Instant};

use eliot_contracts::sha256_hex;
use eliot_wasm_runtime::lifecycle::{
    DIVERGENCE_REASON_CODE, DivergenceReport, InFlightDisposition,
};
use eliot_wasm_runtime::{
    EngineBinding, GuestInterruptHandle, InvocationRequest, InvocationResult, Sha256Digest,
    VerificationVerdict,
};

use crate::WasmHostRunner;
use crate::admission::LiveAuthority;
use crate::dispatch_drive::{
    DriveError, LifecycleVerdicts, SeatedVerdicts, evaluate_lifecycle_verdicts,
    evaluate_seated_verdicts,
};
use crate::dispatch_material::{
    ControlAckPhase, ControlFileClass, ExpectedControlBinding, MaterialError,
    ValidatedDispatchMaterial, WASM_CONTROL_ACK_WIRE_ID, WASM_CONTROL_ACK_WIRE_VERSION,
    WASM_CONTROL_MAX_DETAIL_BYTES, WASM_CONTROL_SPOOL_MAX_DELIVERIES, WASM_CONTROL_SPOOL_SCAN_CAP,
    WASM_HOST_CONTROL_FILE_NAME, SERVED_RESULT_MAX_BYTES, StagedDeliveryIdentity, WasmControlAck,
    WasmControlDelivery, WasmControlKind, admitted_material_path, control_ack_name,
    control_delivery_name, control_replay_key, join_control_delivery, parse_control_delivery,
    parse_control_name, read_control_bytes, retire_legacy_control, stage_control_bytes,
};
use crate::parent_authority::edge_now_ms;
use crate::parent_runtime::{
    AdmittedRuntime, ProcessTermination, ProcessTerminationObservation, build_admitted_runtime,
};

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

/// Process-local monotonic correlation token (#2785 I1). Command
/// correlation already comes from the bound-1 single-slot worker: exactly
/// one command can be outstanding, so the token below can only ever match
/// itself. It exists so the accepted-command entry names the command that
/// was handed over rather than only its kind, and so a stale token from
/// another operation in this process can never settle this one. It is
/// bookkeeping, not an operation authority.
static COMMAND_SEQUENCE: AtomicU64 = AtomicU64::new(1);

/// Fixed field name for the loop's own Execute command, used by the
/// delivery residual that reports which accepted command lost its sink.
const EXECUTE_COMMAND: &str = "execute";
/// Fixed field name reported when the outer containment owner left this
/// operation's effect unresolved. The operation identity itself is the
/// owner's own record, so the refusal stays a stable field name and never
/// echoes an identifier.
const UNATTESTED_OPERATION: &str = "unattested";

/// How far the loop's own termination protocol has progressed. The worker
/// thread stays joinable in every one of these states; the caller only
/// joins once this is `Terminated`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum WorkerState {
    /// The worker owns the runner and no termination step has been taken.
    Alive,
    /// The tracked `Shutdown` command was accepted by the command channel
    /// and its reply is still owed. This is the only termination protocol
    /// the loop uses while the worker is alive.
    TerminationRequested,
    /// The worker thread was observed finished and joined.
    Terminated,
    /// A bound expired with the worker still alive: the thread is
    /// contained, not terminated, and this process is about to end. No
    /// clean shutdown may be claimed.
    Contained,
}

/// Accepted-command lifecycle of one command handed to the worker. Distinct
/// from the drain phase: this is the per-command accounting, and it is how
/// "requested" and "accepted by the command channel" stay separate facts
/// (issue #2785 I1).
///
/// This is the bound-1 channel's capacity slot, so it carries at most one
/// command and is never used as a history record: an observed outcome
/// retires the accepted slot before the observation runs, so the follow-up
/// that observation requests can take it. The outcome-observed fact itself
/// is retained as history by the result-event sequence
/// ([`BoundedRequestLoop::retained`]), not here (issue #2785 audit,
/// defect 1).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CommandDelivery {
    /// Admission produced the command; it has not been handed to the
    /// worker yet. The bounded command channel admits exactly one, so this
    /// slot can hold one pending command and never a queue. `owner` is true
    /// only for a command admitted from an owner-staged control delivery,
    /// and it is what lets a real enqueue be confirmed against that exact
    /// delivery while a loop-derived follow-up confirms nothing (issue #2896
    /// A2).
    Requested {
        /// Command the command channel is about to be asked to take.
        command: WorkerCommand,
        /// Whether an owner-staged control delivery produced this command.
        owner: bool,
    },
    /// `try_send` succeeded: the worker received the command and exactly
    /// this correlated reply is owed.
    Accepted {
        /// Command the worker received.
        command: WorkerCommand,
        /// Process-local correlation token for this handover.
        token: u64,
        /// Whether an owner-staged control delivery produced this command.
        owner: bool,
    },
}

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
    /// A result frame was observed and retained but its publication failed.
    /// The observation itself stays available through the loop's retained
    /// sequence; only the delivery failed, and it never reopens admission.
    ResultPublicationFailed {
        /// Exact observation whose delivery failed.
        observation: &'static str,
    },
    /// An accepted control frame was delivered to the worker but no reply
    /// arrived within the admitted bounds. The request is not reissued: the
    /// operation's uncertain effect is handed to the owner that may still
    /// contain it, and the loop reports an unresolved operation rather than
    /// a clean stop.
    ContainmentUnresolved {
        /// Exact control frame whose completion was never observed.
        command: &'static str,
    },
    /// The operation's P-03 guest child was never observed settled by the
    /// outer process-containment owner. A clean stop of this loop never
    /// claims this effect: the child stays unresolved for the owner that may
    /// still terminate it.
    OperationContainmentUnresolved {
        /// Exact admitted operation the unresolved child belongs to.
        operation_id: &'static str,
    },
    /// The bounded drain for an accepted command did not settle inside the
    /// admitted bounds. Distinct from
    /// [`Self::ContainmentUnresolved`]: no control frame was ever issued
    /// for this command, and its outcome is simply still owed.
    DrainUnsettled {
        /// Exact accepted command that never returned.
        command: &'static str,
    },
    /// The tracked worker was still alive when the process-level containment
    /// path took over. The thread is not a detached worker: the process that
    /// owns it is ending, and the owner is told the operation stayed
    /// unresolved instead of being told a clean shutdown happened.
    WorkerContained {
        /// Exact command that was still executing inside the worker.
        command: &'static str,
    },
    /// A staged stdout helper was still holding the contended output stream
    /// when the process-level containment path took over. The helper was
    /// never joined (it was not finished), and the result whose emission it
    /// held remains unconfirmed for the owner's recovery path.
    OutputHelperContained,
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
            Self::ResultPublicationFailed { .. } => "REQUEST_LOOP_RESULT_PUBLICATION_FAILED",
            Self::ContainmentUnresolved { .. } => "REQUEST_LOOP_CONTAINMENT_UNRESOLVED",
            Self::OperationContainmentUnresolved { .. } => {
                "REQUEST_LOOP_OPERATION_CONTAINMENT_UNRESOLVED"
            }
            Self::DrainUnsettled { .. } => "REQUEST_LOOP_DRAIN_UNSETTLED",
            Self::WorkerContained { .. } => "REQUEST_LOOP_WORKER_CONTAINED",
            Self::OutputHelperContained => "REQUEST_LOOP_OUTPUT_HELPER_CONTAINED",
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
            | Self::OutcomeChannelDisconnected { command }
            | Self::ContainmentUnresolved { command }
            | Self::DrainUnsettled { command }
            | Self::WorkerContained { command } => {
                write!(formatter, "{}:{command}", self.code())
            }
            Self::ResultPublicationFailed { observation }
            | Self::OperationContainmentUnresolved {
                operation_id: observation,
            } => write!(formatter, "{}:{observation}", self.code()),
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
    generation: u64,
    work_scope: String,
    authority_epoch_json: String,
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
            generation: material.generation,
            work_scope: material.work.work_scope.clone(),
            authority_epoch_json: material.authority_epoch_json.clone(),
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
/// gaps, and contradictory identities; `validate_result_stream` enforces
/// exactly that where the loop consumes a retained sequence for replay
/// republish. Absence stays absence per I5.16: `None` serializes absent,
/// measured zero stays numeric zero, Booleans stay Booleans, and no
/// formatting helper feeds stringified values back into this contract.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
// Four JSON Booleans are the versioned wire shape (#2787 step 4: Booleans
// stay Booleans); an enum would break the Boolean contract.
#[allow(clippy::struct_excessive_bools)]
pub struct WasmHostResultFrame {
    /// Result wire identity.
    pub wire_id: String,
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
/// The observed worker command fixes the frame's operation, phase, and
/// worker-command identities: a Cancel outcome answers [`OP_CANCEL`] in the
/// `contain` phase, a Reconcile outcome answers [`OP_RECONCILE`] in the
/// `reconcile` phase, and neither ever masquerades as a new Invoke result.
/// Absent output stays absent: `output_hex` is present only when output
/// bytes were actually observed, so no-output, observed-empty, and
/// budget-omitted stay distinct. Sequence and terminal disposition are
/// assigned by the loop when the frame joins the retained sequence, not
/// here.
///
/// The explicit divergence report travels separately from the typed error:
/// the error keeps its stable classification while the report carries the
/// leg-level evidence and the canonical divergence reason code.
fn project_result(
    binding: &AdmittedBinding,
    engine: &EngineBinding,
    command: WorkerCommand,
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
        wire_id: WASM_HOST_RESULT_WIRE_ID.to_owned(),
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

/// Validates one consumed result-event sequence (#2787 step 7): every event
/// proves itself through `validate_frame`, and the sequence proves its
/// stream shape — one wire identity/version, gapless `sequence` values from
/// 0, exactly one `terminal: true` event closing the stream, and one
/// consistent parent identity across every event. Mixed versions, duplicate
/// terminal events, sequence gaps, and contradictory identities fail closed
/// here, before any event is acted on or republished.
fn validate_result_stream(events: &[WasmHostResultFrame]) -> Result<(), LoopError> {
    let Some(first) = events.first() else {
        return Err(invalid("result-stream"));
    };
    for event in events {
        validate_frame(event)?;
    }
    let mut terminal_seen = false;
    for (index, event) in events.iter().enumerate() {
        if event.wire_id != WASM_HOST_RESULT_WIRE_ID {
            return Err(invalid("wire-id"));
        }
        if event.wire_version != WASM_HOST_RESULT_WIRE_VERSION {
            return Err(invalid("wire-version"));
        }
        let expected = u64::try_from(index).map_err(|_| invalid("sequence-gap"))?;
        if event.sequence != expected {
            return Err(invalid("sequence-gap"));
        }
        if event.request_digest != first.request_digest
            || event.operation_id != first.operation_id
            || event.claim_id != first.claim_id
            || event.invocation_id != first.invocation_id
            || event.grant_digest != first.grant_digest
            || event.component_id != first.component_id
            || event.artifact_digest != first.artifact_digest
            || event.input_digest != first.input_digest
        {
            return Err(invalid("result-identity"));
        }
        if event.terminal {
            if terminal_seen || index + 1 != events.len() {
                return Err(invalid("terminal"));
            }
            terminal_seen = true;
        }
    }
    if terminal_seen {
        Ok(())
    } else {
        Err(invalid("terminal"))
    }
}

/// Versioned payload stored inside the existing #2786 served-result record.
/// Each observed event is persisted before its stdout write; `complete` only
/// becomes true when the terminal event itself has been observed.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct RetainedResultStream {
    wire_id: String,
    wire_version: u16,
    complete: bool,
    terminal_sequence: Option<u64>,
    events: Vec<WasmHostResultFrame>,
    events_digest: String,
}

const RETAINED_RESULT_STREAM_WIRE_ID: &str = "eliot.wasm.retained-result-stream";
const RETAINED_RESULT_STREAM_WIRE_VERSION: u16 = 1;

/// Validates a bounded, gapless event prefix before it is retained. An
/// incomplete prefix may not contain a terminal frame; a terminal prefix is
/// delegated to the full stream validator.
fn validate_result_prefix(events: &[WasmHostResultFrame]) -> Result<(), LoopError> {
    let Some(first) = events.first() else {
        return Err(invalid("result-stream"));
    };
    if events.len() > MAX_RESULT_SEQUENCE as usize {
        return Err(invalid("sequence"));
    }
    for (index, event) in events.iter().enumerate() {
        validate_frame(event)?;
        if event.sequence != u64::try_from(index).map_err(|_| invalid("sequence-gap"))?
            || event.request_digest != first.request_digest
            || event.operation_id != first.operation_id
            || event.claim_id != first.claim_id
            || event.invocation_id != first.invocation_id
            || event.grant_digest != first.grant_digest
            || event.component_id != first.component_id
            || event.artifact_digest != first.artifact_digest
            || event.input_digest != first.input_digest
            || (event.terminal && index + 1 != events.len())
        {
            return Err(invalid("result-stream"));
        }
    }
    if events.last().is_some_and(|event| event.terminal) {
        validate_result_stream(events)
    } else {
        Ok(())
    }
}

fn retained_result_stream(
    events: &[WasmHostResultFrame],
) -> Result<RetainedResultStream, LoopError> {
    validate_result_prefix(events)?;
    let events_json = serde_json::to_vec(events).map_err(|_| LoopError::ResultTooLarge)?;
    let complete = events.last().is_some_and(|event| event.terminal);
    Ok(RetainedResultStream {
        wire_id: RETAINED_RESULT_STREAM_WIRE_ID.to_owned(),
        wire_version: RETAINED_RESULT_STREAM_WIRE_VERSION,
        complete,
        terminal_sequence: complete.then_some(events.last().map(|event| event.sequence)).flatten(),
        events: events.to_vec(),
        events_digest: sha256_hex(&events_json),
    })
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
        wire_id: WASM_HOST_RESULT_WIRE_ID.to_owned(),
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
        divergence_code: None,
        divergence: None,
    }
}

/// Terminal Unknown observation for accepted work whose outcome never
/// resolved: a failed follow-up or a lost worker reply (#2568 A4). The frame
/// carries the exact operation and phase of what was attempted, the stable
/// failure code, no invented engine, usage, or output evidence — and the
/// uncertainty is preserved, never rewritten into success or denial: the
/// scope stays blocked ([`InFlightDisposition::BlockScopeUnknownOutcome`])
/// until receipt/probe/reconciliation resolves it, and the generation stays
/// a rollback candidate. Sequence and terminal disposition are assigned by
/// the loop when the frame joins the retained sequence, not here.
fn unknown_frame(
    binding: &AdmittedBinding,
    operation: &str,
    phase: &str,
    worker_command: Option<WorkerCommand>,
    error_code: &str,
) -> WasmHostResultFrame {
    WasmHostResultFrame {
        wire_id: WASM_HOST_RESULT_WIRE_ID.to_owned(),
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
        disposition: UNCERTAIN_DISPOSITION.to_owned(),
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
        drain: Some(format!(
            "{:?}",
            InFlightDisposition::BlockScopeUnknownOutcome
        )),
        rollback_candidate: true,
        divergence_code: None,
        divergence: None,
    }
}

/// Exact owner-delivery identity carried from poll through admission, enqueue,
/// and completion. Spool identities bind every owner key; legacy identities
/// bind the exact bytes admitted from the fixed file.
#[derive(Clone, Debug, Eq, PartialEq)]
enum ControlDeliveryIdentity {
    Spool {
        generation: u64,
        sequence: u64,
        replay_key: String,
        delivery_digest: String,
    },
    Legacy {
        delivery_digest: String,
    },
}

/// Opaque capability for one polled owner delivery. The loop returns this
/// same value to the channel at each acknowledgement edge; operation names
/// alone can never select or settle a different delivery.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ControlDeliveryToken {
    operation_id: String,
    kind: WasmControlKind,
    identity: ControlDeliveryIdentity,
}

/// One validated control frame and the identity that must accompany every
/// later admission and acknowledgement call.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PolledControl {
    /// Validated request frame.
    pub frame: WasmHostRequestFrame,
    /// Exact owner-delivery identity for the frame.
    pub token: ControlDeliveryToken,
}

impl ControlDeliveryToken {
    fn operation(&self) -> &'static str {
        control_operation(self.kind)
    }

    fn spool_slot(&self) -> Option<(u64, u64)> {
        match &self.identity {
            ControlDeliveryIdentity::Spool {
                generation,
                sequence,
                ..
            } => Some((*generation, *sequence)),
            ControlDeliveryIdentity::Legacy { .. } => None,
        }
    }

    fn delivery_digest(&self) -> &str {
        match &self.identity {
            ControlDeliveryIdentity::Spool {
                delivery_digest, ..
            }
            | ControlDeliveryIdentity::Legacy { delivery_digest } => delivery_digest,
        }
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
    /// never exhaustion: the loop keeps servicing this lane during drain
    /// and polls again on its next tick, including while guest work is
    /// pending. The default has no external source and always reports
    /// nothing pending. Polling never acknowledges or retires anything:
    /// the staged delivery stays replayable until it is confirmed after
    /// worker enqueue.
    ///
    /// # Errors
    ///
    /// Returns [`LoopError::ChannelUnavailable`] when the control source
    /// fails in a way the loop must not ignore.
    fn poll_control(&mut self) -> Result<Option<PolledControl>, LoopError> {
        Ok(None)
    }

    /// Non-blocking poll for one staged Cancel/Shutdown naming this
    /// operation (#2568 A3). Unlike [`Self::poll_control`], this runs before
    /// the single-gate intake check, so an admitted Cancel/Shutdown
    /// interrupts accepted guest work instead of queueing behind the
    /// bound-1 slot. Reconcile is never urgent: it stays staged for the idle
    /// path exactly as before. Polling leaves the owner delivery
    /// unacknowledged and replayable. The default has no external source.
    ///
    /// # Errors
    ///
    /// Returns [`LoopError::ChannelUnavailable`] when the control source
    /// fails in a way the loop must not ignore.
    fn poll_control_urgent(&mut self) -> Result<Option<PolledControl>, LoopError> {
        Ok(None)
    }

    /// Records the actual admission refusal against this exact delivery.
    /// The default has no external source and confirms nothing.
    ///
    /// # Errors
    ///
    /// Returns [`LoopError::ChannelUnavailable`] when the refusal cannot be
    /// staged; in that case the delivery remains in custody for retry.
    fn reject_delivery(
        &mut self,
        _token: &ControlDeliveryToken,
        _reason: &str,
    ) -> Result<(), LoopError> {
        Ok(())
    }

    /// Confirms admission and successful command-channel enqueue for this
    /// exact delivery. The default has no external source.
    ///
    /// # Errors
    ///
    /// Returns [`LoopError::ChannelUnavailable`] when the acknowledgement
    /// cannot be staged; accepted custody is preserved for retry.
    fn confirm_control_enqueued(
        &mut self,
        _token: &ControlDeliveryToken,
    ) -> Result<(), LoopError> {
        Ok(())
    }

    /// Confirms the exact observed worker outcome for this accepted delivery,
    /// carrying its digest when one exists. The default has no external
    /// source.
    ///
    /// # Errors
    ///
    /// Returns [`LoopError::ChannelUnavailable`] when the acknowledgement
    /// cannot be staged; accepted custody is preserved for retry.
    fn confirm_control_completed(
        &mut self,
        _token: &ControlDeliveryToken,
        _outcome_digest: Option<&str>,
    ) -> Result<(), LoopError> {
        Ok(())
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

/// Maps an owner control kind onto the loop's closed operation vocabulary.
fn control_operation(kind: WasmControlKind) -> &'static str {
    match kind {
        WasmControlKind::Cancel => OP_CANCEL,
        WasmControlKind::Reconcile => OP_RECONCILE,
        WasmControlKind::Shutdown => OP_SHUTDOWN,
    }
}

fn is_lower_digest(digest: &str) -> bool {
    digest.len() == 64
        && digest
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

fn valid_ack_shape(ack: &WasmControlAck) -> bool {
    ack.wire_id == WASM_CONTROL_ACK_WIRE_ID
        && ack.wire_version == WASM_CONTROL_ACK_WIRE_VERSION
        && !ack.operation_id.trim().is_empty()
        && ack.generation != 0
        && is_lower_digest(&ack.replay_key)
        && is_lower_digest(&ack.delivery_digest)
        && !ack.detail.as_ref().is_some_and(|detail| {
            detail.trim().is_empty() || detail.len() > WASM_CONTROL_MAX_DETAIL_BYTES
        })
        && !ack
            .outcome_digest
            .as_ref()
            .is_some_and(|digest| !is_lower_digest(digest))
        && match ack.phase {
            ControlAckPhase::Enqueued => ack.detail.is_none() && ack.outcome_digest.is_none(),
            ControlAckPhase::Completed => ack.detail.is_none(),
            ControlAckPhase::Refused => {
                ack.detail.as_ref().is_some_and(|detail| !detail.trim().is_empty())
                    && ack.outcome_digest.is_none()
            }
        }
}

fn ack_matches_delivery(ack: &WasmControlAck, delivery: &WasmControlDelivery) -> bool {
    valid_ack_shape(ack)
        && ack.operation_id == delivery.identity.operation_id
        && ack.generation == delivery.identity.generation
        && ack.owner_sequence == delivery.identity.owner_sequence
        && ack.replay_key == delivery.identity.replay_key
        && ack.delivery_digest == delivery.delivery_digest
}

fn predecessor_replay_key_matches(ack: &WasmControlAck) -> bool {
    [
        WasmControlKind::Cancel,
        WasmControlKind::Reconcile,
        WasmControlKind::Shutdown,
    ]
    .into_iter()
    .any(|kind| {
        control_replay_key(
            &ack.operation_id,
            ack.generation,
            kind,
            ack.owner_sequence,
        ) == ack.replay_key
    })
}

/// One polled-but-unconfirmed control delivery: validated and yielded to the
/// loop, but not yet admitted and enqueued, so still unacknowledged and
/// fully replayable. Every identity field it carries is the delivery's own,
/// read from its validated bytes, so an acknowledgement written from it is
/// bound to that delivery's content and not to an operation name two
/// controls can share (issue #2896 A2).
#[derive(Clone, Debug)]
struct PendingControl {
    frame: WasmHostRequestFrame,
    token: ControlDeliveryToken,
    refusal: Option<String>,
}

impl PendingControl {
    fn kind(&self) -> WasmControlKind {
        self.token.kind
    }
}

/// One enqueue-confirmed spool delivery whose exact worker outcome is still
/// open. At most one exists: the single-gate intake admits nothing new while
/// a command is outstanding. It is the child's custody of a command the
/// worker has already taken, so it is recorded the moment that send succeeds
/// — before the owner-visible ack is staged — and a failed ack write is
/// retried rather than dropping it (issue #2896 W5/A2).
#[derive(Clone, Debug)]
struct AcceptedControl {
    token: ControlDeliveryToken,
}

/// A worker outcome whose exact control-completion ack still needs a durable
/// write. The observed digest is retained so retries cannot change evidence.
#[derive(Clone, Debug)]
struct PendingControlCompletion {
    token: ControlDeliveryToken,
    outcome_digest: Option<String>,
}

/// Bounded control-file reads per poll: at most one spool row of deliveries
/// plus their acks and predecessor links. The walk stops when the budget is
/// spent and resumes on the next tick, so a foreign-filled directory degrades
/// admission instead of growing work without bound.
const CONTROL_POLL_READ_BUDGET: usize = WASM_CONTROL_SPOOL_MAX_DELIVERIES * 3;

/// Resolution of one delivery's ack slot before its identity is known.
#[derive(Clone, Debug)]
enum AckSlot {
    /// No ack occupies the exact slot.
    Free,
    /// The bounded read budget was spent before the slot could be checked.
    BudgetDeferred,
    /// Bytes exist but cannot establish a trustworthy ack identity.
    Conflict,
    /// A valid matching terminal ack already owns this exact delivery.
    Terminal,
    /// An ack value that must be joined against the parsed delivery identity.
    Existing(WasmControlAck),
}

/// Truthful state of a control delivery's predecessor link.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PreviousDisposition {
    /// Exact predecessor terminal ack proves this edge.
    Verified,
    /// The predecessor has no terminal ack yet; keep this delivery staged.
    AwaitingEvidence,
    /// The per-poll read budget is exhausted; retry on a later tick.
    BudgetDeferred,
    /// Present predecessor evidence contradicts the linked identity.
    Conflict,
}

/// Installed Kernel control reader: the external control intake of the
/// ordinary loop.
///
/// One spool slot address: (generation, sequence).
type ControlSlot = (u64, u64);
/// Bounded spool slot listing collected by one directory scan.
type ControlSlotList = Vec<ControlSlot>;

/// The owner publishes Cancel/Reconcile/Shutdown for the running operation
/// as versioned deliveries in a generation-specific immutable spool colocated
/// with the delivery set, one exact `generation-sequence` name per delivery
/// plus the child-staged ack beside it. The loop polls this reader on every
/// tick — including while guest work is pending — and admits what it yields
/// through the same frame shape, parse, and binding validation the
/// delivery-set path uses, so one admission path serves both sources.
///
/// Validate-then-admit-then-enqueue-then-ack: polling validates and stages
/// terminal refusals, but a delivery is acknowledged only after the loop
/// confirms admission plus successful worker enqueue. Queue-full,
/// disconnected, admission failure, and crash leave the original staged
/// delivery replayable with its typed disposition — never falsely accepted.
/// The `enqueued` phase therefore means the command channel took the
/// command, never that a demand was recorded: an owner `Shutdown` is
/// admitted on the tick that closes admission and is confirmed later, from
/// the delivery retained in [`Self::shutdown`], by the drain that actually
/// sends it (issue #2896 W5/A2). Deliveries are never deleted by the child;
/// the owner reclaims its own stream. In-memory state is bounded (one
/// pending slot, one retained shutdown slot, one accepted slot, capped scan
/// buffers), and every poll does bounded directory/file work, so intake
/// holds no unbounded queue and a poisoned file cannot wedge it.
///
/// The legacy fixed file joins only while the versioned spool holds no
/// delivery or ack for this generation — the sequenced stream always wins —
/// and retires only after admission plus successful worker enqueue, by
/// exact-name byte-verified delete.
///
/// Fail-closed per delivery: an absent, unreadable, oversize, malformed, or
/// foreign delivery yields nothing and is left in place, and `Invoke` is
/// never admitted externally: the one admitted invoke comes from the
/// delivery set only, so a second execution path cannot open through the
/// control lane. A versioned delivery stays owner-owned in its spool; typed
/// acknowledgements are written only after the corresponding refusal,
/// successful enqueue, or observed command outcome. `follow_up` advances
/// only when the command was really handed to the worker (issue #2785 P1/I2),
/// so a delivery the command channel refuses stays staged and replayable
/// instead of being acknowledged for a control step that never ran. A step
/// admission refusal carries its exact typed reason; a step that only waits
/// for the occupied command slot stays staged and is re-offered.
pub struct KernelControlReader {
    /// Loader-derived install directory holding the delivery set and spool.
    directory: PathBuf,
    /// Exact legacy fixed-file path inside `directory`.
    legacy_path: PathBuf,
    /// Full admitted binding: derived control frames reuse it.
    admitted: AdmittedBinding,
    /// Exact operation binding every delivery must join.
    binding: ExpectedControlBinding,
    /// One polled-but-unconfirmed delivery, if the loop holds a yield.
    pending: Option<PendingControl>,
    /// The admitted owner `Shutdown` delivery whose worker enqueue is not
    /// yet confirmed. A `Shutdown` demand is recorded while a command may
    /// still be accepted, and its command is only handed to the worker by
    /// the drain, long after the transient [`Self::pending`] slot has been
    /// reused by the control lane — so the delivery identity is retained
    /// here until that real enqueue is proven (issue #2896 W5/A2).
    shutdown: Option<PendingControl>,
    /// One enqueue-confirmed delivery with its outcome still open, if any.
    accepted: Option<AcceptedControl>,
    /// Whether the legacy file was consumed this run.
    legacy_consumed: bool,
    /// Whether any same-generation spool delivery or ack was observed this
    /// run: the versioned stream permanently closes the legacy join, even if
    /// the owner reclaims its terminal files mid-run.
    versioned_seen: bool,
    /// Directory cursor retained across polls so unrelated names cannot
    /// consume every scan budget before this operation's control slots.
    scan_entries: Option<std::fs::ReadDir>,
    scan_deliveries: ControlSlotList,
    scan_acks: ControlSlotList,
}

impl KernelControlReader {
    /// Pins the reader to the loader-derived install directory and the exact
    /// admitted operation binding every delivery must join. A generation of
    /// zero or an unparseable authority epoch fails closed inside the join:
    /// every delivery refuses or skips, and the loop still serves the
    /// delivery set.
    #[must_use]
    pub fn new(binding: &AdmittedBinding, directory: PathBuf) -> Self {
        let authority_epoch =
            serde_json::from_str(&binding.authority_epoch_json).unwrap_or(serde_json::Value::Null);
        Self {
            legacy_path: directory.join(WASM_HOST_CONTROL_FILE_NAME),
            directory,
            admitted: binding.clone(),
            binding: ExpectedControlBinding {
                operation_id: binding.operation_id.clone(),
                invocation_id: binding.invocation_id.clone(),
                claim_id: binding.claim_id.clone(),
                generation: binding.generation,
                grant_digest: binding.grant_digest.clone(),
                work_scope: binding.work_scope.clone(),
                authority_epoch,
            },
            pending: None,
            shutdown: None,
            accepted: None,
            legacy_consumed: false,
            versioned_seen: false,
            scan_entries: None,
            scan_deliveries: Vec::new(),
            scan_acks: Vec::new(),
        }
    }

    /// Whether the transient yielded frame is already held in accepted
    /// custody. Its poll slot may be released, but the accepted identity
    /// remains available to prevent a duplicate enqueue.
    fn pending_is_accepted(&self) -> bool {
        self.pending
            .as_ref()
            .zip(self.accepted.as_ref())
            .is_some_and(|(pending, accepted)| pending.token == accepted.token)
    }

    /// Returns one staged control frame with its exact owner identity.
    /// Repeated polls return the same token until rejection or successful
    /// enqueue; queue pressure never drops accepted custody.
    fn poll(&mut self) -> Option<PolledControl> {
        if self.pending_is_accepted() {
            self.pending = None;
        }
        if let Some(pending) = &self.pending {
            if pending.refusal.is_some() {
                let _ = self.retry_refusal();
                return None;
            }
            return Some(PolledControl {
                frame: pending.frame.clone(),
                token: pending.token.clone(),
            });
        }
        let (deliveries, acks) = self.scan_spool()?;
        if deliveries
            .iter()
            .chain(acks.iter())
            .any(|(generation, _)| *generation == self.binding.generation)
        {
            self.versioned_seen = true;
        }
        if let Some(control) = self.poll_spool(&deliveries, &acks, false) {
            return Some(control);
        }
        self.poll_legacy(&deliveries, &acks, false)
    }

    /// Lists this generation's delivery and ack slots in bounded steps over
    /// the loader-derived directory. A cursor survives between polls, so
    /// unrelated names cannot permanently hide a later control delivery.
    /// No file is read during enumeration.
    fn scan_spool(&mut self) -> Option<(ControlSlotList, ControlSlotList)> {
        if self.scan_entries.is_none() {
            self.scan_entries = std::fs::read_dir(&self.directory).ok();
            if self.scan_entries.is_none() {
                return Some((Vec::new(), Vec::new()));
            }
        }
        for _ in 0..WASM_CONTROL_SPOOL_SCAN_CAP {
            let Some(entry) = self.scan_entries.as_mut().and_then(Iterator::next) else {
                self.scan_entries = None;
                let mut deliveries = std::mem::take(&mut self.scan_deliveries);
                let acks = std::mem::take(&mut self.scan_acks);
                deliveries.sort_by_key(|(_, sequence)| *sequence);
                return Some((deliveries, acks));
            };
            let Ok(entry) = entry else {
                continue;
            };
            let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
                continue;
            };
            let Some((generation, sequence, class)) = parse_control_name(&name) else {
                continue;
            };
            if generation != self.binding.generation {
                continue;
            }
            match class {
                ControlFileClass::Delivery => {
                    if self.scan_deliveries.len() < WASM_CONTROL_SPOOL_SCAN_CAP {
                        self.scan_deliveries.push((generation, sequence));
                    }
                }
                ControlFileClass::Ack => {
                    if self.scan_acks.len() < WASM_CONTROL_SPOOL_SCAN_CAP {
                        self.scan_acks.push((generation, sequence));
                    }
                }
            }
        }
        None
    }

    /// Walks staged deliveries in sequence order and yields the first
    /// identity-verified delivery. Urgent polling skips Reconcile without
    /// modifying its files so a later Cancel or Shutdown can preempt it.
    fn poll_spool(
        &mut self,
        deliveries: &[ControlSlot],
        acks: &[ControlSlot],
        urgent_only: bool,
    ) -> Option<PolledControl> {
        let mut reads = 0usize;
        for &(generation, sequence) in deliveries {
            let slot = self.open_ack(generation, sequence, acks, &mut reads);
            if matches!(&slot, AckSlot::BudgetDeferred) {
                return None;
            }
            let slot_taken = !matches!(&slot, AckSlot::Free);
            if reads >= CONTROL_POLL_READ_BUDGET {
                return None;
            }
            reads += 1;
            let path = self
                .directory
                .join(control_delivery_name(generation, sequence));
            let Ok(bytes) = read_control_bytes(&path) else {
                continue;
            };
            let Ok(delivery) = parse_control_delivery(&bytes) else {
                // Malformed: no identity to bind an ack to, so the file
                // itself stays as the bounded evidence and the walk moves
                // on — a poisoned file cannot wedge intake.
                continue;
            };
            if matches!(&slot, AckSlot::Conflict) {
                continue;
            }
            let token = ControlDeliveryToken {
                operation_id: delivery.identity.operation_id.clone(),
                kind: delivery.identity.control_kind,
                identity: ControlDeliveryIdentity::Spool {
                    generation,
                    sequence,
                    replay_key: delivery.identity.replay_key.clone(),
                    delivery_digest: delivery.delivery_digest.clone(),
                },
            };
            if self
                .accepted
                .as_ref()
                .is_some_and(|accepted| accepted.token == token)
            {
                continue;
            }
            let slot = match slot.clone() {
                AckSlot::Free => AckSlot::Free,
                AckSlot::Existing(ack) if !ack_matches_delivery(&ack, &delivery) => {
                    AckSlot::Conflict
                }
                AckSlot::Existing(ack) => match ack.phase {
                    ControlAckPhase::Completed | ControlAckPhase::Refused => AckSlot::Terminal,
                    ControlAckPhase::Enqueued => {
                        if self
                            .accepted
                            .as_ref()
                            .is_some_and(|accepted| accepted.token == token)
                        {
                            AckSlot::Terminal
                        } else {
                            AckSlot::Existing(ack)
                        }
                    }
                },
                AckSlot::BudgetDeferred | AckSlot::Conflict | AckSlot::Terminal => {
                    AckSlot::Conflict
                }
            };
            if matches!(&slot, AckSlot::Conflict | AckSlot::Terminal) {
                continue;
            }
            // A re-offered open delivery must still carry its accepted
            // bytes: changed same-sequence content is an identity conflict,
            // left as the two mismatching files for the owner, never
            // re-acknowledged over the taken slot.
            let identity = &delivery.identity;
            if identity.generation != generation || identity.owner_sequence != sequence {
                // A filename/content mismatch is an identity conflict, not a
                // refusal that can safely own this ack slot.
                continue;
            }
            if identity.generation != self.binding.generation {
                // Foreign generation: never admit, never act, and never
                // stage into its slot — a concurrent replacement stream owns it.
                continue;
            }
            if let Err(refusal) = join_control_delivery(&delivery, &self.binding, edge_now_ms()) {
                self.refuse_slot(generation, sequence, &delivery, refusal.field, slot_taken);
                continue;
            }
            let kind = identity.control_kind;
            let previous = self.check_previous(generation, sequence, &delivery, acks, &mut reads);
            match previous {
                PreviousDisposition::Verified => {}
                PreviousDisposition::BudgetDeferred => return None,
                PreviousDisposition::AwaitingEvidence
                    if urgent_only
                        && matches!(kind, WasmControlKind::Cancel | WasmControlKind::Shutdown) =>
                {
                    match self.verify_reconcile_preemption(
                        generation,
                        sequence,
                        &delivery,
                        &mut reads,
                    ) {
                        Ok(()) => {}
                        Err(PreviousDisposition::BudgetDeferred) => return None,
                        Err(_) => continue,
                    }
                }
                PreviousDisposition::AwaitingEvidence | PreviousDisposition::Conflict => continue,
            }
            if urgent_only && kind == WasmControlKind::Reconcile {
                // Explicit urgent preemption: leave this predecessor in its
                // original slot and continue scanning for Cancel/Shutdown.
                continue;
            }
            let frame = WasmHostRequestFrame::control(control_operation(kind), &self.admitted);
            self.pending = Some(PendingControl {
                frame: frame.clone(),
                token: token.clone(),
                refusal: None,
            });
            return Some(PolledControl { frame, token });
        }
        None
    }

    /// Reads the ack slot without trusting its embedded identity. The exact
    /// identity join happens only after the paired delivery bytes are parsed.
    fn open_ack(
        &self,
        generation: u64,
        sequence: u64,
        acks: &[(u64, u64)],
        reads: &mut usize,
    ) -> AckSlot {
        if !acks.contains(&(generation, sequence)) {
            return AckSlot::Free;
        }
        if *reads >= CONTROL_POLL_READ_BUDGET {
            return AckSlot::BudgetDeferred;
        }
        *reads += 1;
        let path = self.directory.join(control_ack_name(generation, sequence));
        let Ok(bytes) = read_control_bytes(&path) else {
            return AckSlot::Conflict;
        };
        let Ok(ack) = serde_json::from_slice::<WasmControlAck>(&bytes) else {
            return AckSlot::Conflict;
        };
        if !valid_ack_shape(&ack) {
            return AckSlot::Conflict;
        }
        AckSlot::Existing(ack)
    }

    /// Checks the predecessor's exact generation, sequence, replay key, and
    /// delivery digest. Missing or merely enqueued evidence defers admission;
    /// malformed or contradictory evidence stays visible as a conflict.
    fn check_previous(
        &self,
        generation: u64,
        sequence: u64,
        delivery: &WasmControlDelivery,
        acks: &[(u64, u64)],
        reads: &mut usize,
    ) -> PreviousDisposition {
        let previous = delivery.identity.previous_delivery_digest.as_deref();
        if sequence == 0 {
            return if previous.is_none() {
                PreviousDisposition::Verified
            } else {
                PreviousDisposition::Conflict
            };
        }
        let Some(previous) = previous else {
            return PreviousDisposition::Conflict;
        };
        if !acks.contains(&(generation, sequence - 1)) {
            return PreviousDisposition::AwaitingEvidence;
        }
        if *reads >= CONTROL_POLL_READ_BUDGET {
            return PreviousDisposition::BudgetDeferred;
        }
        *reads += 1;
        let path = self
            .directory
            .join(control_ack_name(generation, sequence - 1));
        let Ok(bytes) = read_control_bytes(&path) else {
            return PreviousDisposition::Conflict;
        };
        let Ok(ack) = serde_json::from_slice::<WasmControlAck>(&bytes) else {
            return PreviousDisposition::Conflict;
        };
        if !valid_ack_shape(&ack)
            || ack.operation_id != self.binding.operation_id
            || ack.generation != generation
            || ack.owner_sequence != sequence - 1
            || ack.delivery_digest != previous
            || !predecessor_replay_key_matches(&ack)
        {
            return PreviousDisposition::Conflict;
        }
        match ack.phase {
            ControlAckPhase::Completed | ControlAckPhase::Refused => {
                PreviousDisposition::Verified
            }
            ControlAckPhase::Enqueued => PreviousDisposition::AwaitingEvidence,
        }
    }

    /// Verifies the exact pending Reconcile immediately before an urgent
    /// Cancel/Shutdown. This is the explicit preemption edge: it admits the
    /// urgent control while leaving both owner files and sequence numbers in
    /// their original order; the deferred Reconcile remains retryable.
    fn verify_reconcile_preemption(
        &self,
        generation: u64,
        sequence: u64,
        delivery: &WasmControlDelivery,
        reads: &mut usize,
    ) -> Result<(), PreviousDisposition> {
        if sequence == 0 {
            return Err(PreviousDisposition::Conflict);
        }
        if *reads >= CONTROL_POLL_READ_BUDGET {
            return Err(PreviousDisposition::BudgetDeferred);
        }
        *reads += 1;
        let path = self
            .directory
            .join(control_delivery_name(generation, sequence - 1));
        let Ok(bytes) = read_control_bytes(&path) else {
            return Err(PreviousDisposition::Conflict);
        };
        let Ok(previous) = parse_control_delivery(&bytes) else {
            return Err(PreviousDisposition::Conflict);
        };
        let identity = &previous.identity;
        if previous.delivery_digest != delivery.identity.previous_delivery_digest.as_deref().unwrap_or_default()
            || identity.operation_id != self.binding.operation_id
            || identity.invocation_id != self.binding.invocation_id
            || identity.claim_id != self.binding.claim_id
            || identity.generation != generation
            || identity.owner_sequence != sequence - 1
            || identity.dispatch_grant_digest != self.binding.grant_digest
            || identity.control_kind != WasmControlKind::Reconcile
        {
            return Err(PreviousDisposition::Conflict);
        }
        Ok(())
    }

    /// Stages one typed refused ack at an exact free slot. Best-effort: a
    /// staging failure leaves the delivery unacknowledged for the next poll,
    /// and a taken slot is never overwritten.
    fn refuse_slot(
        &self,
        generation: u64,
        sequence: u64,
        delivery: &WasmControlDelivery,
        field: &'static str,
        slot_taken: bool,
    ) {
        if slot_taken {
            return;
        }
        let ack = refused_ack(
            &delivery.identity.operation_id,
            &delivery.identity.replay_key,
            &delivery.delivery_digest,
            generation,
            sequence,
            field,
        );
        let _ = self.stage_ack(generation, sequence, &ack);
    }

    /// Stages the typed refused ack for the delivery the loop last yielded,
    /// naming `detail` as the exact admission failure. This is the loop's own
    /// admission refusal — the one case where the child knows the delivery
    /// cannot run — and it is dispositioned, not acknowledged as enqueued:
    /// the delivery file itself is left in place, so the same owner operation
    /// stays retained and the owner sees a terminal `refused` rather than a
    /// false `enqueued` (issue #2896 W5). The refusal drops every enqueue
    /// claim this reader holds for that delivery, so no later send can
    /// confirm it. A legacy delivery carries no ack slot, so its file stays
    /// as the owner's evidence and nothing is staged.
    fn refuse_pending(&mut self, detail: &'static str) {
        let Some(pending) = self.pending.take() else {
            return;
        };
        if pending.kind() == WasmControlKind::Shutdown {
            // Terminal evidence wins over a retained enqueue claim: a Shutdown
            // the loop refused must not be confirmed later by the drain's own
            // internal shutdown enqueue.
            self.shutdown = None;
        }
        let PendingControl::Spool {
            operation_id,
            generation,
            sequence,
            replay_key,
            delivery_digest,
            ..
        } = pending
        else {
            // A legacy delivery carries no ack slot: its file stays in place
            // as the owner's evidence and nothing is staged.
            return;
        };
        let ack = refused_ack(
            &operation_id,
            &replay_key,
            &delivery_digest,
            generation,
            sequence,
            detail,
        );
        let _ = self.stage_ack(generation, sequence, &ack);
    }

    /// Polls the legacy fixed file under the serialized owner rule.
    fn poll_legacy(
        &mut self,
        deliveries: &[(u64, u64)],
        acks: &[(u64, u64)],
        urgent_only: bool,
    ) -> Option<PolledControl> {
        if self.legacy_consumed || self.versioned_seen {
            return None;
        }
        let versioned_staged = deliveries
            .iter()
            .chain(acks.iter())
            .any(|(generation, _)| *generation == self.binding.generation);
        if versioned_staged {
            self.versioned_seen = true;
            return None;
        }
        let Ok(bytes) = read_control_bytes(&self.legacy_path) else {
            return None;
        };
        let Ok(frame) = serde_json::from_slice::<WasmHostRequestFrame>(&bytes) else {
            return None;
        };
        if frame.grant_digest != self.admitted.grant_digest {
            return None;
        }
        let expected = WasmHostControl {
            operation_id: self.admitted.operation_id.clone(),
            invocation_id: self.admitted.invocation_id.clone(),
            request_digest: self.admitted.request_digest.clone(),
        };
        let kind = match WasmHostRequestFrame::parse(&frame) {
            Ok(WasmHostRequest::Cancel(control)) if control == expected => WasmControlKind::Cancel,
            Ok(WasmHostRequest::Reconcile(control)) if control == expected => {
                WasmControlKind::Reconcile
            }
            Ok(WasmHostRequest::Shutdown) if self.controls_this_operation(&frame) => {
                WasmControlKind::Shutdown
            }
            Ok(_) | Err(_) => return None,
        };
        if urgent_only && kind == WasmControlKind::Reconcile {
            return None;
        }
        let token = ControlDeliveryToken {
            operation_id: self.admitted.operation_id.clone(),
            kind,
            identity: ControlDeliveryIdentity::Legacy {
                delivery_digest: sha256_hex(&bytes),
            },
        };
        self.pending = Some(PendingControl {
            frame: frame.clone(),
            token: token.clone(),
            refusal: None,
        });
        Some(PolledControl { frame, token })
    }

    /// Offers an urgent delivery, scanning past staged Reconcile records
    /// without changing their sequence or acknowledgement state.
    fn poll_urgent(&mut self) -> Option<PolledControl> {
        if self.pending_is_accepted() {
            self.pending = None;
        }
        if let Some(pending) = &self.pending {
            if pending.refusal.is_some() {
                let _ = self.retry_refusal();
                return None;
            }
            if matches!(pending.kind(), WasmControlKind::Cancel | WasmControlKind::Shutdown) {
                return Some(PolledControl {
                    frame: pending.frame.clone(),
                    token: pending.token.clone(),
                });
            }
            // This Reconcile was polled while the command slot was free but
            // has not been admitted. Release only the local cursor; its owner
            // files and predecessor position remain untouched for idle intake.
            self.pending = None;
        }
        let (deliveries, acks) = self.scan_spool()?;
        if deliveries
            .iter()
            .chain(acks.iter())
            .any(|(generation, _)| *generation == self.binding.generation)
        {
            self.versioned_seen = true;
        }
        if let Some(control) = self.poll_spool(&deliveries, &acks, true) {
            return Some(control);
        }
        self.poll_legacy(&deliveries, &acks, true)
    }

    /// Stages one typed refusal for the exact pending token. A failed write
    /// leaves the token and refusal in custody so the next poll retries the
    /// same outcome without re-admitting it as a command.
    fn reject_delivery(
        &mut self,
        token: &ControlDeliveryToken,
        reason: &str,
    ) -> Result<(), LoopError> {
        if self
            .accepted
            .as_ref()
            .is_some_and(|accepted| accepted.token == *token)
        {
            return Err(LoopError::ChannelUnavailable);
        }
        let Some(pending) = self.pending.as_mut() else {
            return Err(LoopError::ChannelUnavailable);
        };
        if pending.token != *token {
            return Err(LoopError::ChannelUnavailable);
        }
        let detail = reason
            .chars()
            .take(WASM_CONTROL_MAX_DETAIL_BYTES)
            .collect::<String>();
        pending.refusal = Some(detail);
        self.retry_refusal()
    }

    fn retry_refusal(&mut self) -> Result<(), LoopError> {
        let Some(pending) = self.pending.as_ref() else {
            return Ok(());
        };
        let Some(detail) = pending.refusal.clone() else {
            return Ok(());
        };
        if let Some((generation, sequence)) = pending.token.spool_slot() {
            let ControlDeliveryIdentity::Spool { replay_key, .. } = &pending.token.identity else {
                return Err(LoopError::ChannelUnavailable);
            };
            let ack = WasmControlAck {
                wire_id: WASM_CONTROL_ACK_WIRE_ID.to_owned(),
                wire_version: WASM_CONTROL_ACK_WIRE_VERSION,
                replay_key: replay_key.clone(),
                operation_id: pending.token.operation_id.clone(),
                generation,
                owner_sequence: sequence,
                delivery_digest: pending.token.delivery_digest().to_owned(),
                phase: ControlAckPhase::Refused,
                detail: Some(detail),
                outcome_digest: None,
            };
            self.stage_ack(generation, sequence, &ack)?;
        } else {
            self.legacy_consumed = true;
        }
        self.pending = None;
        Ok(())
    }

    /// Confirms admission plus successful worker enqueue for one exact
    /// pending token. Spool custody is recorded before the ack write so a
    /// write failure can be retried without forgetting the accepted action.
    fn confirm_enqueued(&mut self, token: &ControlDeliveryToken) -> Result<(), LoopError> {
        if let Some(accepted) = self.accepted.as_ref() {
            if accepted.token != *token {
                return Err(LoopError::ChannelUnavailable);
            }
        } else {
            let Some(pending) = self.pending.as_ref() else {
                return Err(LoopError::ChannelUnavailable);
            };
            if pending.token != *token || pending.refusal.is_some() {
                return Err(LoopError::ChannelUnavailable);
            }
            if token.spool_slot().is_some() {
                self.accepted = Some(AcceptedControl {
                    token: token.clone(),
                });
            }
        }
        match &token.identity {
            ControlDeliveryIdentity::Spool { .. } => {
                let (generation, sequence) = token
                    .spool_slot()
                    .ok_or(LoopError::ChannelUnavailable)?;
                let ControlDeliveryIdentity::Spool { replay_key, .. } = &token.identity else {
                    return Err(LoopError::ChannelUnavailable);
                };
                let ack = WasmControlAck {
                    wire_id: WASM_CONTROL_ACK_WIRE_ID.to_owned(),
                    wire_version: WASM_CONTROL_ACK_WIRE_VERSION,
                    replay_key: replay_key.clone(),
                    operation_id: token.operation_id.clone(),
                    generation,
                    owner_sequence: sequence,
                    delivery_digest: token.delivery_digest().to_owned(),
                    phase: ControlAckPhase::Enqueued,
                    detail: None,
                    outcome_digest: None,
                };
                self.stage_ack(generation, sequence, &ack)?;
            }
            ControlDeliveryIdentity::Legacy { delivery_digest } => {
                let is_pending = self
                    .pending
                    .as_ref()
                    .is_some_and(|pending| pending.token == *token);
                if is_pending {
                    let _ = retire_legacy_control(&self.legacy_path, delivery_digest);
                    self.legacy_consumed = true;
                    self.pending = None;
                }
            }
        }
        if self.pending.as_ref().is_some_and(|pending| pending.token == *token) {
            self.pending = None;
        }
        Ok(())
    }

    /// Confirms the exact observed worker outcome of an accepted spool
    /// delivery. Failed writes leave Accepted custody intact for a later retry.
    fn confirm_completed(
        &mut self,
        token: &ControlDeliveryToken,
        outcome_digest: Option<&str>,
    ) -> Result<(), LoopError> {
        let Some(accepted) = self.accepted.as_ref() else {
            return if token.spool_slot().is_none() {
                Ok(())
            } else {
                Err(LoopError::ChannelUnavailable)
            };
        };
        if accepted.token != *token {
            return Err(LoopError::ChannelUnavailable);
        }
        // A `completed` ack supersedes any still-unstaged `enqueued` ack for
        // the same slot, so the completion path clears the pending write
        // rather than leaving it to overwrite a terminal phase.
        let outcome_digest = outcome_digest
            .filter(|digest| is_lower_digest(digest))
            .map(str::to_owned);
        if token.spool_slot().is_none() {
            self.accepted = None;
            return Ok(());
        }
        let (generation, sequence) = token
            .spool_slot()
            .ok_or(LoopError::ChannelUnavailable)?;
        let ControlDeliveryIdentity::Spool { replay_key, .. } = &token.identity else {
            return Err(LoopError::ChannelUnavailable);
        };
        let ack = WasmControlAck {
            wire_id: WASM_CONTROL_ACK_WIRE_ID.to_owned(),
            wire_version: WASM_CONTROL_ACK_WIRE_VERSION,
            replay_key: replay_key.clone(),
            operation_id: token.operation_id.clone(),
            generation,
            owner_sequence: sequence,
            delivery_digest: token.delivery_digest().to_owned(),
            phase: ControlAckPhase::Completed,
            detail: None,
            outcome_digest,
        };
        self.stage_ack(generation, sequence, &ack)?;
        self.accepted = None;
        if self.pending.as_ref().is_some_and(|pending| pending.token == *token) {
            self.pending = None;
        }
        Ok(())
    }

    /// Stages one ack at its exact generation/sequence name.
    fn stage_ack(
        &self,
        generation: u64,
        sequence: u64,
        ack: &WasmControlAck,
    ) -> Result<(), LoopError> {
        let bytes = serde_json::to_vec(ack).map_err(|_| LoopError::ChannelUnavailable)?;
        stage_control_bytes(
            &self.directory.join(control_ack_name(generation, sequence)),
            &bytes,
        )
        .map_err(|_| LoopError::ChannelUnavailable)
    }

    /// Pins a legacy Shutdown frame to this operation. The parse carries its
    /// identity as plain fields, so the external path checks them here: parse
    /// alone authenticates nothing.
    fn controls_this_operation(&self, frame: &WasmHostRequestFrame) -> bool {
        frame.operation_id == self.admitted.operation_id
            && frame.invocation_id == self.admitted.invocation_id
            && frame.request_digest == self.admitted.request_digest
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

#[derive(Default)]
struct BoundedResultEmitter {
    emission_broken: bool,
    pending_helper: Option<std::thread::JoinHandle<()>>,
}

impl BoundedResultEmitter {
    fn reap_output_helper(&mut self) -> bool {
        if self
            .pending_helper
            .as_ref()
            .is_some_and(std::thread::JoinHandle::is_finished)
            && let Some(helper) = self.pending_helper.take()
        {
            let _ = helper.join();
        }
        self.pending_helper.is_some()
    }

    fn publish(&mut self, frame: &WasmHostResultFrame) -> Result<(), LoopError> {
        validate_frame(frame)?;
        if self.emission_broken || self.reap_output_helper() {
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

    fn cleanup_output_helper(&mut self) -> Result<(), LoopError> {
        if self.emission_broken {
            return Ok(());
        }
        if self.reap_output_helper() {
            return Err(LoopError::ChannelUnavailable);
        }
        if self.reap_output_helper() {
            return Err(LoopError::OutputHelperContained);
        }
        Ok(())
    }
}

impl Drop for BoundedResultEmitter {
    fn drop(&mut self) {
        self.reap_output_helper();
    }
}

fn emit_retained_result_stream(events: &[WasmHostResultFrame]) -> Result<(), LoopError> {
    validate_result_stream(events)?;
    let mut emitter = BoundedResultEmitter::default();
    let mut delivery_error = None;
    for event in events {
        if let Err(error) = emitter.publish(event) {
            delivery_error = Some(error);
            break;
        }
    }
    let cleanup_error = emitter.cleanup_output_helper().err();
    match (delivery_error, cleanup_error) {
        (Some(error), _) | (None, Some(error)) => Err(error),
        (None, None) => Ok(()),
    }
}

/// Writer for one exact claimed identity's bounded event sequence. Every
/// event is durably appended to the existing served-result record before its
/// ordinary stdout emission; no parallel result ledger is introduced.
struct ResultRetention {
    directory: PathBuf,
    identity: StagedDeliveryIdentity,
    events: Vec<WasmHostResultFrame>,
    encoded_event_bytes: usize,
}

impl ResultRetention {
    fn new(directory: &Path, identity: &StagedDeliveryIdentity) -> Self {
        Self {
            directory: directory.to_path_buf(),
            identity: identity.clone(),
            events: Vec::new(),
            encoded_event_bytes: 0,
        }
    }

    fn retain_before_emit(&mut self, frame: &WasmHostResultFrame) -> Result<(), LoopError> {
        validate_frame(frame)?;
        let event_bytes = serde_json::to_vec(frame).map_err(|_| LoopError::ResultTooLarge)?;
        if event_bytes.len() > MAX_RESULT_FRAME_BYTES {
            return Err(LoopError::ResultTooLarge);
        }
        let sequence = u64::try_from(self.events.len()).map_err(|_| invalid("sequence"))?;
        if frame.sequence != sequence
            || self.events.last().is_some_and(|previous| previous.terminal)
            || self
                .encoded_event_bytes
                .saturating_add(event_bytes.len())
                > SERVED_RESULT_MAX_BYTES.saturating_sub(8 * 1024)
        {
            return Err(LoopError::ResultTooLarge);
        }
        let mut events = self.events.clone();
        events.push(frame.clone());
        let stream = retained_result_stream(&events)?;
        let value = serde_json::to_value(stream).map_err(|_| LoopError::ResultTooLarge)?;
        let record = crate::dispatch_material::ServedResultRecord::from_identity(
            &self.identity,
            &value,
            edge_now_ms(),
        );
        let record_bytes = serde_json::to_vec(&record).map_err(|_| LoopError::ResultTooLarge)?;
        if record_bytes.len() > SERVED_RESULT_MAX_BYTES {
            return Err(LoopError::ResultTooLarge);
        }
        crate::dispatch_material::write_served_result(
            &self.directory,
            &self.identity,
            &value,
            edge_now_ms(),
        )
        .map_err(|_| LoopError::ChannelUnavailable)?;
        self.events = events;
        self.encoded_event_bytes = self.encoded_event_bytes.saturating_add(event_bytes.len());
        Ok(())
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
    emitter: BoundedResultEmitter,
    result_retention: Option<ResultRetention>,
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
            emitter: BoundedResultEmitter::default(),
            result_retention: None,
        }
    }

    /// Installs the Kernel control reader feeding external
    /// Cancel/Reconcile/Shutdown for this operation.
    #[must_use]
    pub fn with_kernel_control(mut self, reader: KernelControlReader) -> Self {
        self.control = Some(reader);
        self
    }

    fn with_result_retention(mut self, retention: ResultRetention) -> Self {
        self.result_retention = Some(retention);
        self
    }

    /// Runs the loop's own tracked cleanup of the stdout helper at a real
    /// terminal edge: reap a finished helper, and fail closed when one is
    /// still blocked. The second, deliberate call is the
    /// process-level containment edge (issue #2785 A6) — the helper is not
    /// reaped while running, and its unconfirmed frame is reported to the
    /// process owner instead of being dropped as a clean stop.
    pub(crate) fn cleanup_output_helper(&mut self) -> Result<(), LoopError> {
        self.emitter.cleanup_output_helper()
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

    fn poll_control(&mut self) -> Result<Option<PolledControl>, LoopError> {
        match self.control.as_mut() {
            Some(reader) => Ok(reader.poll(ControlPollClass::Any)),
            None => Ok(None),
        }
    }

    fn poll_control_urgent(&mut self) -> Result<Option<PolledControl>, LoopError> {
        match self.control.as_mut() {
            Some(reader) => Ok(reader.poll_urgent()),
            None => Ok(None),
        }
    }

    fn reject_delivery(
        &mut self,
        token: &ControlDeliveryToken,
        reason: &str,
    ) -> Result<(), LoopError> {
        match self.control.as_mut() {
            Some(reader) => reader.reject_delivery(token, reason),
            None => Ok(()),
        }
    }

    fn confirm_control_enqueued(
        &mut self,
        token: &ControlDeliveryToken,
    ) -> Result<(), LoopError> {
        match self.control.as_mut() {
            Some(reader) => reader.confirm_enqueued(token),
            None => Ok(()),
        }
    }

    fn confirm_control_completed(
        &mut self,
        token: &ControlDeliveryToken,
        outcome_digest: Option<&str>,
    ) -> Result<(), LoopError> {
        match self.control.as_mut() {
            Some(reader) => reader.confirm_completed(token, outcome_digest),
            None => Ok(()),
        }
    }

    fn publish(&mut self, frame: &WasmHostResultFrame) -> Result<(), LoopError> {
        // Internal consistency first: a frame that cannot prove itself is
        // never emitted, and a publication failure retains the observed
        // result through the loop's drain accounting, never an ad hoc
        // fallback. A successful write plus flush below is an observed
        // local stream write, not proof the owner durably accepted the
        // result.
        if let Some(retention) = self.result_retention.as_mut() {
            retention.retain_before_emit(frame)?;
        }
        self.emitter.publish(frame)
    }
}

impl Drop for DeliverySetChannel {
    /// Reaps the retained stdout helper when — and only when — it already
    /// finished. A still-blocked helper is never joined here: joining it
    /// could wedge teardown forever, and the drop must not claim a
    /// termination it did not observe. Every terminal path that returns an
    /// error runs the tracked cleanup first
    /// ([`DeliverySetChannel::cleanup_output_helper`]), so reaching this
    /// drop with a live helper means that cleanup already reported it to
    /// the process owner.
    fn drop(&mut self) {
        self.emitter.reap_output_helper();
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

impl std::str::FromStr for WorkerCommand {
    type Err = ();

    /// Reads a recorded `worker_command` name back into its command. Only
    /// the closed vocabulary [`command_name`] emits is accepted, and a
    /// foreign spelling never resolves, so a residual can never be
    /// attributed to a command that did not run.
    fn from_str(text: &str) -> Result<Self, Self::Err> {
        match text {
            "execute" => Ok(Self::Execute),
            "cancel" => Ok(Self::Cancel),
            "reconcile" => Ok(Self::Reconcile),
            "shutdown" => Ok(Self::Shutdown),
            _ => Err(()),
        }
    }
}

/// The worker command an observation was projected from, read back from
/// the frame's own recorded `worker_command`. A frame that names none (a
/// pre-execution denial, which this loop never emits) is attributed to the
/// Execute slot rather than to a command that did not run.
fn observed_command_name(frame: &WasmHostResultFrame) -> &'static str {
    frame
        .worker_command
        .as_deref()
        .and_then(|name| name.parse::<WorkerCommand>().ok())
        .map_or(EXECUTE_COMMAND, command_name)
}

/// Operation a result event answers for one observed worker command. A
/// Shutdown outcome never projects a frame (the loop returns `None` for
/// it); the arm exists so the mapping stays total. The same vocabulary
/// keys control confirmation: `Execute` never carries an external
/// delivery, so confirming it is always a no-op.
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
            termination: _,
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
                    shutdown_request_won,
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

/// Explicit drain phase of the loop (#2785 I1). Kept separate from
/// [`AdmissionState`] (may new Execute work still be taken?) and
/// [`WorkerState`] (has the worker thread been observed terminated?), so no
/// single flag has to mean all three at once.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum LoopPhase {
    /// New Execute work may be taken from the delivery set.
    Running,
    /// Admission is closed; every already-accepted command and every
    /// accepted control frame is still being serviced.
    Draining,
    /// Every accepted command and control frame settled inside the
    /// admitted bounds.
    Drained,
    /// The worker thread was observed terminated and joined: a clean stop
    /// of this loop, and only of this loop.
    ShutDown,
}

/// Whether the bounded loop may still take new `Execute` work. Only this
/// gate is closed by expiry, revocation, delivery exhaustion or an owner
/// `Shutdown`; the control lane keeps servicing replies and accepted
/// control commands until the worker is observed terminated.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum AdmissionGate {
    /// The one admitted invoke may still be taken and handed to the worker.
    Open,
    /// No further `Execute` may be admitted or handed over. Worker replies
    /// and the one admitted bounded containment/reconciliation action stay
    /// serviced.
    Closed,
}

/// Bounded admission state of the loop (#2785 I1). The one-shot grant flag
/// and the follow-up accounting belong to the admitted operation, not to any
/// of the three protocol states, so they live on their own.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct AdmissionState {
    /// Whether the one admitted invoke may still be taken and handed to
    /// the worker.
    gate: AdmissionGate,
    /// The one-shot grant authority already funded an executed effect.
    one_shot_spent: bool,
    /// Which uncertain-outcome follow-up was already delivered to the
    /// runtime owner. Advanced only after the control command was accepted
    /// by the command channel, never on request alone.
    follow_up: FollowUp,
    /// An admitted Shutdown demanded typed shutdown: the post-outcome path
    /// skips follow-ups and proceeds to drain and typed shutdown (#2568 A3).
    shutdown_demanded: bool,
    /// An owner Cancel is staged for the currently accepted command. This is
    /// interruption demand, not a second command: the bound-1 slot stays
    /// single-owner, the tick interrupts the guest through the stored
    /// engine handle, and the Cancel command itself is admitted and sent by
    /// the control lane once the slot frees. Cleared when the
    /// Cancel is handed to the worker or when the accepted command's own
    /// reply settles, so demand never outlives its execution (#2568 A3,
    /// issue #2785 I2/P1).
    cancel_demanded: bool,
}

/// Bounded state of the ordinary request loop.
///
/// Every transition is explicit: the control loop decides, the tracked
/// worker executes, and nothing here constructs a second runner, a second
/// engine, or a second effect for the same admitted operation.
///
/// The three protocol states are separate fields, never one Boolean
/// (issue #2785 I1): [`Self::admission`] says whether new `Execute` work
/// may still be taken, [`Self::worker`] says how far the one termination
/// protocol progressed, and [`Self::phase`] says whether the accepted
/// command and the accepted control frames have settled. Closing admission
/// never stops the worker, never drops the join handle, and never stops
/// consuming replies.
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
    /// External control admitted but not yet handed to the worker. Shutdown
    /// uses this slot until the loop's tracked Shutdown enqueue succeeds.
    control_token: Option<ControlDeliveryToken>,
    /// Urgent Cancel observed during an accepted command. It remains pending
    /// until that command's reply frees the slot, then takes priority over an
    /// internally requested Reconcile while preserving its owner identity.
    urgent_cancel: Option<PolledControl>,
    /// Exact external control attached to the command the worker accepted.
    accepted_control: Option<ControlDeliveryToken>,
    /// Completion evidence waiting for an ack write retry.
    pending_control_completion: Option<PendingControlCompletion>,
    /// Retained sequence to republish when a request is an exact replay.
    replay: Option<Vec<WasmHostResultFrame>>,
    /// Next event sequence number for this operation, from 0, gapless.
    next_sequence: u64,
    /// The accepted command and its per-command delivery stage. Exactly
    /// one entry exists for the one command slot the bound-1 channel
    /// admits; it is cleared only when that command's outcome is observed.
    delivery: Option<CommandDelivery>,
    /// This loop's own termination protocol.
    worker: WorkerState,
    /// The operation-bound process-termination disposition read back from
    /// the P-03 owner's own evidence for the exact admitted child.
    /// `Some(true)` is the only observation that may be called a clean
    /// stop; `None` and `Some(false)` both stay unresolved for the outer
    /// process-containment owner, whatever this loop did.
    guest_child_exited: Option<bool>,
    /// Drain bound: the admitted grant wall deadline plus the control-poll
    /// cadence the drain itself waits on. Execution already ran under that
    /// same wall limit inside the guest child, so this never shortens a
    /// healthy run.
    drain_deadline: Instant,
    phase: LoopPhase,
    admission: AdmissionState,
    /// The terminal execution evidence for this operation. A failed
    /// publication leaves it in place (issue #2785 I6): the observation
    /// stays, only its delivery failed.
    published: Option<WasmHostResultFrame>,
    denial: Option<LoopError>,
    /// Exact observed P-11 request disposition of the tracked `Shutdown`
    /// command, distinct from worker exit and from `join`.
    shutdown_request_won: Option<bool>,
    /// First bounded residual the drain produced. Kept rather than
    /// returned immediately so the drain itself always runs to its own
    /// terminal state (issue #2785 A4).
    residual: Option<LoopError>,
    /// Cloneable cross-thread guest-interruption handle taken from the
    /// seated engine before the worker owns the runner (#2568 A3). `None`
    /// when the engine offers none; the deadline machinery still bounds the
    /// wait then.
    interrupt: Option<Arc<dyn GuestInterruptHandle>>,
}

impl BoundedRequestLoop {
    /// Creates the loop state from the granted binding, engine mode,
    /// live authority cell, and the admitted guest ceilings that bound the
    /// drain.
    #[must_use]
    pub fn new(
        binding: AdmittedBinding,
        engine: EngineBinding,
        live: Arc<LiveAuthority>,
        drain_deadline: Duration,
    ) -> Self {
        Self {
            binding,
            engine,
            live,
            max_in_flight: 1,
            retained: BTreeMap::new(),
            control_token: None,
            urgent_cancel: None,
            accepted_control: None,
            pending_control_completion: None,
            replay: None,
            next_sequence: 0,
            delivery: None,
            worker: WorkerState::Alive,
            guest_child_exited: None,
            drain_deadline: Instant::now() + drain_deadline,
            phase: LoopPhase::Running,
            admission: AdmissionState {
                gate: AdmissionGate::Open,
                one_shot_spent: false,
                follow_up: FollowUp::None,
                shutdown_demanded: false,
                cancel_demanded: false,
            },
            published: None,
            denial: None,
            shutdown_request_won: None,
            residual: None,
            interrupt: None,
        }
    }

    /// Stores the seated engine's cross-thread interruption handle, taken
    /// before the worker owns the runner (#2568 A3).
    #[must_use]
    pub fn with_interrupt_handle(mut self, handle: Arc<dyn GuestInterruptHandle>) -> Self {
        self.interrupt = Some(handle);
        self
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

    /// Returns the first bounded residual the drain produced, if any.
    #[must_use]
    pub fn residual(&self) -> Option<LoopError> {
        self.residual
    }

    /// Whether ordinary `Execute` admission is still open. Only this gate
    /// closes on expiry, revocation, delivery exhaustion or an owner
    /// `Shutdown`; nothing else about the loop depends on it (#2785 I3).
    fn admission_open(&self) -> bool {
        self.admission.gate == AdmissionGate::Open
            && self.published.is_none()
            && self.denial.is_none()
    }

    /// Closes `Execute` admission and opens the drain, keeping the worker
    /// and the reply-servicing lane untouched.
    fn close_admission(&mut self) {
        self.admission.gate = AdmissionGate::Closed;
        self.begin_drain();
    }

    /// Moves `Running` to `Draining`. Idempotent: every close path calls it,
    /// so a second close is a no-op rather than a second transition.
    fn begin_drain(&mut self) {
        if self.phase == LoopPhase::Running {
            self.phase = LoopPhase::Draining;
        }
    }

    /// Moves `Draining` to `Drained` once every accepted command's outcome
    /// was consumed and every accepted control frame settled. The caller
    /// gates this on a successful drain; idempotent over already-terminal
    /// phases.
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
    /// with admission open, nothing accepted by the worker, and nothing
    /// already requested. The bound-1 command channel admits exactly one
    /// command, so `delivery` is the capacity signal — sending while a
    /// command is accepted would stack a second command behind it.
    fn intake_open(&self) -> bool {
        self.phase == LoopPhase::Running && self.delivery.is_none() && self.admission_open()
    }

    /// The command slot is free: no command was requested and none is
    /// accepted by the worker. The bound-1 channel admits exactly one
    /// command, so this is the single gate every control lane shares.
    fn command_slot_free(&self) -> bool {
        self.delivery.is_none()
    }

    /// Drain-complete predicate: the accepted command's outcome was
    /// consumed and no further command was requested.
    fn drain_complete(&self) -> bool {
        self.delivery.is_none()
    }

    /// Control phase: refresh the observed clock and close admission on a
    /// revoked or expired binding. A trap in one bounded instance never
    /// reaches this state; it is classified and the loop keeps its contract.
    fn tick(&mut self) {
        self.live.observe(edge_now_ms());
        if !self.live.is_live() {
            self.close_admission();
        }
    }

    /// Records the first bounded residual. The drain never returns early on
    /// a residual: the first one is kept and the drain continues so the
    /// worker is always supervised to its own terminal state.
    fn record_residual(&mut self, error: LoopError) {
        if self.residual.is_none() {
            self.residual = Some(error);
        }
    }

    /// Admit phase for one request frame: wire, operation, identity, size,
    /// and live authority checks, then the replay and one-shot consumption
    /// rules. The control operations the loop derives for its own lifecycle
    /// travel through this same frame shape, parse, and validation, so the
    /// loop has one admission path rather than two.
    ///
    /// `owner` records that this frame came from an owner-staged control
    /// delivery rather than the delivery set or this loop's own follow-up, and
    /// is the only thing that lets a later real enqueue be confirmed against
    /// that exact delivery. It is a parameter rather than retained state so it
    /// cannot leak into the next frame's command slot (issue #2896 A2).
    fn admit(&mut self, frame: &WasmHostRequestFrame, owner: bool) -> Result<(), LoopError> {
        let request = WasmHostRequestFrame::parse(frame)?;
        // Drain gate (#2785): once admission closed, new invoke demand is
        // refused with the typed drain-closed denial; already-admitted
        // demand — the control follow-ups settling the admitted attempt —
        // keeps its exact scope through the unchanged arms below.
        if !self.admission_open() && matches!(request, WasmHostRequest::Invoke(_)) {
            return Err(denied("drain-closed"));
        }
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
                if self.admission.one_shot_spent {
                    // The one-shot authority already funded an effect. A
                    // grant intentionally valid for several requests still
                    // needs a distinct admitted request identity; this
                    // delivery set carries exactly one.
                    return Err(denied("one-shot-authority"));
                }
                self.request(WorkerCommand::Execute, false);
            }
            WasmHostRequest::Cancel(control) => {
                check_control(&self.binding, control)?;
                // Admission only validates and requests: the follow-up is
                // spent by `send` after the worker accepts the enqueue, so
                // a full/disconnected channel never advances containment
                // truthfully owed to an accepted command.
                self.request(WorkerCommand::Cancel, owner);
            }
            WasmHostRequest::Reconcile(control) => {
                check_control(&self.binding, control)?;
                self.request(WorkerCommand::Reconcile, owner);
            }
            // An owner Shutdown is not a queued worker command: it closes
            // `Execute` admission and demands typed shutdown. The loop's own
            // tracked termination step is the only protocol that stops the
            // worker, so the demand is recorded here and acted on there
            // (#2568 A3, issue #2785 I5). No command slot is taken, so the
            // reader's retained delivery — not this arm — is what the drain's
            // real enqueue later confirms.
            WasmHostRequest::Shutdown => {
                self.admission.shutdown_demanded = true;
                self.close_admission();
            }
        }
        Ok(())
    }

    /// Queues one control operation this loop derived for its own lifecycle,
    /// through the same frame shape and validation the request path uses. The
    /// frame is not an owner delivery, so the command it requests is never
    /// owner-sourced and never confirms one.
    fn queue_control(&mut self, operation: &str) -> Result<(), LoopError> {
        let frame = WasmHostRequestFrame::control(operation, &self.binding);
        self.admit(&frame, false)
    }

    /// Takes the one command slot for a requested command. The slot is
    /// bounded by the bound-1 command channel, so this is only ever called
    /// when [`Self::command_slot_free`] holds. `owner` records whether an
    /// owner-staged control delivery produced this command, which is what
    /// binds a later enqueue confirmation to that exact delivery instead of
    /// to an operation name two controls can share.
    fn request(&mut self, command: WorkerCommand, owner: bool) {
        self.delivery = Some(CommandDelivery::Requested { command, owner });
    }

    fn hold_control_delivery(&mut self, token: ControlDeliveryToken) -> Result<(), LoopError> {
        if self
            .control_token
            .as_ref()
            .is_some_and(|pending| *pending != token)
        {
            return Err(LoopError::ChannelUnavailable);
        }
        self.control_token = Some(token);
        Ok(())
    }

    fn confirm_accepted_control(
        &self,
        channel: &mut dyn WasmHostRequestChannel,
    ) -> Result<(), LoopError> {
        if let Some(token) = self.accepted_control.as_ref() {
            channel.confirm_control_enqueued(token)?;
        }
        Ok(())
    }

    fn remember_control_outcome(
        &mut self,
        token: ControlDeliveryToken,
        outcome_digest: Option<String>,
    ) {
        self.pending_control_completion = Some(PendingControlCompletion {
            token,
            outcome_digest,
        });
    }

    fn retry_control_completion(
        &mut self,
        channel: &mut dyn WasmHostRequestChannel,
    ) -> Result<(), LoopError> {
        let Some(pending) = self.pending_control_completion.clone() else {
            return Ok(());
        };
        channel.confirm_control_completed(
            &pending.token,
            pending.outcome_digest.as_deref(),
        )?;
        self.pending_control_completion = None;
        Ok(())
    }

    /// The requested command waiting to be handed to the worker, or `None`
    /// when the slot is free or the slot holds an already-accepted command.
    fn requested_command(&self) -> Option<WorkerCommand> {
        match self.delivery {
            Some(CommandDelivery::Requested { command, .. }) => Some(command),
            _ => None,
        }
    }

    /// Whether the accepted command was admitted from an owner-staged control
    /// delivery, and therefore may be confirmed against that delivery once
    /// the command channel really took it. A loop-derived follow-up is never
    /// owner-sourced and confirms nothing (issue #2896 A2).
    fn accepted_owner_delivery(&self) -> bool {
        matches!(
            self.delivery,
            Some(CommandDelivery::Accepted { owner: true, .. })
        )
    }

    /// The command the command channel accepted and whose exact reply is
    /// still owed, or `None` when no command is outstanding. The
    /// correlation token is deliberately not readable here: the bound-1
    /// single-slot worker can only ever reply to the command it was handed,
    /// so the slot itself is the correlation.
    fn accepted_command(&self) -> Option<WorkerCommand> {
        match self.delivery {
            Some(CommandDelivery::Accepted { command, .. }) => Some(command),
            _ => None,
        }
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
        // The accepted command's own reply settled, so interruption demand
        // for that execution is moot: a still-staged Cancel is re-demanded
        // by the next urgent tick while a command stays accepted, and the
        // Cancel command itself travels the control lane.
        self.admission.cancel_demanded = false;
        if outcome.command == WorkerCommand::Shutdown {
            self.shutdown_request_won = outcome.shutdown_request_won;
            return None;
        }
        // The observed command fixes the frame's operation/phase identity:
        // a Cancel outcome answers `OP_CANCEL` in the `contain` phase, a
        // Reconcile outcome answers `OP_RECONCILE` in the `reconcile` phase.
        // Control outcomes never masquerade as Invoke results.
        let WorkerOutcome {
            command,
            result,
            divergence,
            shutdown_request_won: _,
        } = outcome;
        let mut frame = match result {
            Ok(result) => project_result(&self.binding, &self.engine, command, &result, divergence),
            Err(code) if self.admission.follow_up != FollowUp::None => unknown_frame(
                &self.binding,
                command_operation(command),
                command_phase(command),
                Some(command),
                code.as_str(),
            ),
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
        self.admission.one_shot_spent = true;
        if frame.disposition == UNCERTAIN_DISPOSITION {
            self.settle_uncertain(&mut frame);
        } else {
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
    /// uncertain frame is nonterminal while its follow-up is only requested
    /// and terminal once the follow-up was delivered to the runtime owner,
    /// and it is retained either way, so the outcome is never hidden behind
    /// the follow-up step and the original uncertainty is never rewritten.
    /// A follow-up that cannot be requested at all is terminal for the
    /// follow-up only: the unresolved control step is reported as its own
    /// bounded residual instead of being claimed as delivered.
    fn settle_uncertain(&mut self, frame: &mut WasmHostResultFrame) {
        if self.admission.shutdown_demanded {
            // Typed shutdown wins over follow-ups: the uncertain frame is
            // retained terminal as observed — never rewritten — and the loop
            // proceeds to drain and typed shutdown with nothing requested.
            frame.terminal = true;
            self.published = Some(frame.clone());
            return;
        }
        match self.admission.follow_up {
            FollowUp::None if !self.live.is_live() => {
                frame.terminal = false;
                self.request_follow_up(OP_CANCEL);
            }
            FollowUp::None => {
                frame.terminal = false;
                self.request_follow_up(OP_RECONCILE);
            }
            FollowUp::Contained | FollowUp::Reconciled => {
                frame.terminal = true;
                self.published = Some(frame.clone());
            }
        }
    }

    /// Requests exactly one bounded containment/reconciliation action for
    /// an uncertain outcome. The follow-up accounting advances only inside
    /// [`Self::send`] after the command channel accepted the command, so
    /// "requested" and "delivered" never collapse into one fact.
    fn request_follow_up(&mut self, operation: &str) {
        if !self.command_slot_free() || self.admission.follow_up != FollowUp::None {
            return;
        }
        // `queue_control` can only refuse for a control frame the loop
        // itself derived from its own admitted binding; report it as the
        // residual it is instead of discarding it.
        if let Err(error) = self.queue_control(operation) {
            self.record_residual(error);
        }
    }

    /// Hands the requested command to the tracked worker and records it as
    /// accepted. `Full` and `Disconnected` are different refusals and
    /// neither is an accepted command: the requested state survives either
    /// way, so no caller can read a refusal as delivery. Containment and
    /// reconciliation state advances only here, after the worker accepts the
    /// enqueue, so the delivery stays replayable and the drain still owes
    /// its exact outcome to a refused send.
    ///
    /// The accepted slot inherits the owner-source marker from the requested
    /// command it hands over, and never from the command's own name: two
    /// controls of the same kind are not interchangeable, so only a slot
    /// that was admitted from an owner delivery may be confirmed against one
    /// (issue #2896 A2).
    fn send(
        &mut self,
        command: WorkerCommand,
        sender: &SyncSender<WorkerCommand>,
    ) -> Result<(), LoopError> {
        if self.control_token.as_ref().is_some_and(|token| {
            token.operation() != command_operation(command)
        }) {
            return Err(LoopError::ChannelUnavailable);
        }
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
        self.delivery = Some(CommandDelivery::Accepted {
            command,
            token: COMMAND_SEQUENCE.fetch_add(1, Ordering::Relaxed),
            owner,
        });
        self.accepted_control = self.control_token.take();
        match command {
            WorkerCommand::Cancel => {
                self.admission.follow_up = FollowUp::Contained;
                self.admission.cancel_demanded = false;
            }
            WorkerCommand::Reconcile => self.admission.follow_up = FollowUp::Reconciled,
            WorkerCommand::Execute | WorkerCommand::Shutdown => {}
        }
        if command == WorkerCommand::Shutdown {
            self.worker = WorkerState::TerminationRequested;
        }
        Ok(())
    }

    /// Fires the stored guest-interruption handle while a command is
    /// accepted and interruption-class control is demanded (#2568 A3): a
    /// staged owner Cancel recorded as cancel demand, or an admitted
    /// Shutdown. Firing is best-effort and idempotent, so the tick retries
    /// until the outcome arrives — this closes the race where the worker
    /// has accepted the command but not started the child yet. Never sends:
    /// the bound-1 slot stays single-owner.
    fn interrupt_outstanding(&self) {
        if self.accepted_command().is_none() {
            return;
        }
        if !self.admission.cancel_demanded && !self.admission.shutdown_demanded {
            return;
        }
        if let Some(handle) = self.interrupt.as_ref() {
            handle.interrupt();
        }
    }

    /// Projects and best-effort publishes the terminal Unknown frame for an
    /// accepted command whose worker reply never arrived (#2568 A4). The
    /// emitted frame is the durable record of the loss; the loop error still
    /// returns afterwards, so a publication failure here never masks the lost
    /// response. Runs once: a published terminal or a recorded denial
    /// suppresses any later loss projection, and nothing is projected without
    /// an accepted command to observe.
    fn publish_lost_response(
        &mut self,
        channel: &mut dyn WasmHostRequestChannel,
        error: LoopError,
    ) {
        if self.published.is_some() || self.denial.is_some() {
            return;
        }
        let Some(command) = self.accepted_command() else {
            return;
        };
        // A Shutdown outcome never projects a worker-command frame (the
        // validator rejects it); its loss observes the shutdown demand
        // itself in the deny phase with no worker command.
        let (operation, phase, worker_command) = if command == WorkerCommand::Shutdown {
            (OP_SHUTDOWN, RESULT_PHASE_DENY, None)
        } else {
            (
                command_operation(command),
                command_phase(command),
                Some(command),
            )
        };
        let mut frame = unknown_frame(
            &self.binding,
            operation,
            phase,
            worker_command,
            error.code(),
        );
        frame.sequence = self.next_sequence;
        frame.observation_predecessors = self
            .retained
            .get(&frame.request_digest)
            .into_iter()
            .flatten()
            .map(|previous| previous.sequence)
            .collect();
        frame = enforce_frame_budget(frame, self.binding.max_output_bytes);
        frame.terminal = true;
        self.next_sequence = self.next_sequence.saturating_add(1);
        self.published = Some(frame.clone());
        self.retained
            .entry(frame.request_digest.clone())
            .or_default()
            .push(frame.clone());
        let _ = channel.publish(&frame);
    }
}

/// Stores the seated engine's interruption handle on the loop state (#2568
/// A3). Called before the worker owns the runner, so the control loop can
/// terminate pending guest work while a command is outstanding.
fn install_interrupt_handle(
    state: BoundedRequestLoop,
    runner: &WasmHostRunner,
) -> BoundedRequestLoop {
    match runner.interrupt_handle() {
        Some(handle) => state.with_interrupt_handle(handle),
        None => state,
    }
}

/// Runs the bounded ordinary request loop over one granted execution.
///
/// The control phase always runs (authority refresh, drain, revocation,
/// containment, external control intake), the request phase admits at most
/// `max_in_flight` commands, and each reply is projected onto a correlated
/// owner-backed frame.
///
/// Termination is one protocol with three observable steps (issue #2785
/// I5/A6), and the order matters:
///
/// 1. close `Execute` admission only, and keep draining in-flight worker
///    outcomes;
/// 2. hand the worker a tracked `Shutdown` and observe its exact reply —
///    this is the only protocol used while the worker is alive, so sender
///    closure is never mixed with an unobserved best-effort shutdown;
/// 3. join the handle once the worker is observed finished, and only then
///    read the operation's containment disposition back from the outer
///    process-containment owner.
///
/// Every return path — success, denial, drain failure, and the
/// process-level containment path — runs all three steps, so no return path
/// can leave a live join handle unreported.
pub fn run_request_loop(
    runtime: AdmittedRuntime,
    material: &ValidatedDispatchMaterial,
) -> Result<WasmHostResultFrame, LoopError> {
    run_request_loop_with_retention(runtime, material, None)
}

fn run_request_loop_with_retention(
    runtime: AdmittedRuntime,
    material: &ValidatedDispatchMaterial,
    retention: Option<ResultRetention>,
) -> Result<WasmHostResultFrame, LoopError> {
    let binding = AdmittedBinding::from_material(material, &runtime.invocation);
    let request_frame = WasmHostRequestFrame::admitted_invoke(&binding);
    let mut channel = DeliverySetChannel::new(request_frame);
    if let Some(retention) = retention {
        channel = channel.with_result_retention(retention);
    }
    if let Some(directory) = kernel_control_dir() {
        channel = channel.with_kernel_control(KernelControlReader::new(&binding, directory));
    }
    let mut state = BoundedRequestLoop::new(
        binding,
        runtime.engine_binding.clone(),
        Arc::clone(&runtime.live),
        drain_bound(material),
    );
    state = install_interrupt_handle(state, &runtime.runner);
    // The operation-bound process-termination projection is read on this
    // control thread, not inside the worker: it is a read-only handle onto
    // the P-03 owner's own evidence sink and outlives the worker's own move
    // of the runtime (issue #2785 audit, defect 2).
    let termination = runtime.termination.clone();
    let worker = spawn_worker(runtime, state.max_in_flight);
    let drive = drive_loop(
        &mut state,
        &mut channel,
        &worker.commands,
        &worker.outcomes,
        &worker.handle,
    );
    drain_and_shutdown_request_worker(&mut state, &mut channel, &termination, worker, drive)
}

/// Drains accepted work, shuts down and joins the worker, then returns the
/// exact terminal result of the ordinary request loop.
fn drain_and_shutdown_request_worker(
    state: &mut BoundedRequestLoop,
    channel: &mut DeliverySetChannel,
    termination: &ProcessTermination,
    worker: EngineWorker,
    drive: Result<(), LoopError>,
) -> Result<WasmHostResultFrame, LoopError> {
    // Close Execute admission and keep draining (issue #2785 W1): intake
    // returns on close or exhaustion with a command possibly accepted, so
    // replies are polled until the worker idles. Joining with a command
    // accepted or an outcome unconsumed would wedge the worker's Shutdown
    // reply behind the unread outcome on the bound-1 channel.
    state.close_admission();
    drain_to_settlement(
        state,
        channel,
        &worker.commands,
        &worker.outcomes,
        &worker.handle,
    );
    // Step 2: the tracked Shutdown, the single termination protocol
    // (issue #2785 I5). The slot is checked BEFORE the request is taken:
    // requesting first would occupy the slot and clobber an unsettled
    // accepted command, so the check-then-request order is what keeps the
    // accepted-command accounting exact. `send` refuses — rather than
    // silently claiming delivery — if the command channel does not take
    // it. The live authority cell is revoked first, so nothing further can
    // resolve through it while the worker stops.
    state.live.revoke();
    // The loop's own termination protocol, so this request is never
    // owner-sourced: an owner `Shutdown` delivery is bound to this send by
    // the reader's retained slot, not by the command's name. That is what
    // makes the acknowledgement below prove an enqueue for that exact
    // delivery instead of merely a demand that was recorded.
    let shutdown_sent = if state.command_slot_free() {
        state.request(WorkerCommand::Shutdown, false);
        match state.send(WorkerCommand::Shutdown, &worker.commands) {
            Ok(()) => true,
            Err(error) => {
                // A refused Shutdown enqueue stays an explicit bounded
                // residual and is never reported as accepted termination.
                state.record_residual(error);
                false
            }
        }
    } else {
        false
    };
    // The retained owner `Shutdown` delivery is acknowledged only here: after
    // the worker actually accepted the tracked enqueue, and only for the
    // delivery the reader still retains. With no retained delivery — the
    // loop's own termination, or an owner `Shutdown` never yielded — the
    // confirmation is a no-op, so no `enqueued` ack exists for a command the
    // worker did not take (issue #2896 W5/A2). An ack that cannot be staged
    // fails the loop honestly once the worker is joined.
    let mut confirm_error: Option<LoopError> = None;
    if shutdown_sent {
        if let Err(error) = state.confirm_accepted_control(channel) {
            state.record_residual(error);
            confirm_error = Some(error);
        }
    }
    if shutdown_sent {
        drain_to_settlement(
            state,
            channel,
            &worker.commands,
            &worker.outcomes,
            &worker.handle,
        );
    }
    // Step 3: `join` is called only after the worker owner observed the
    // thread finished; the wait keeps draining any late bounded outcome so a
    // producer can never be left blocked on an unread full outcome channel.
    if !supervise_to_worker_exit(state, channel, &worker.outcomes, &worker.handle) {
        // Process-level containment path (issue #2785 A6): the worker is
        // still alive past the admitted drain bound, so this thread is not
        // joinable and cannot be reported as terminated. The process that
        // owns it ends here, the guest child it started is left for the
        // outer process-containment owner to reconcile, and the original
        // unknown effect is retained instead of being reported as a clean
        // shutdown. The retained operation record is this process's written
        // handover to that owner: the loop ends with an explicit unresolved
        // result rather than an implicit stop.
        return Err(contained_failure(state, channel));
    }
    let shutdown_observed = shutdown_sent
        && state.accepted_command() != Some(WorkerCommand::Shutdown)
        && state.shutdown_request_won.is_some();
    if state.drain_complete() && shutdown_observed {
        state.mark_drained();
    }
    // `JoinHandle::join` is called only after the worker owner confirms
    // termination. The wait also drains any late bounded outcome before the
    // handle can be joined.
    let joined = join_shutdown_worker(state, channel, worker.handle, &mut confirm_error);
    if joined {
        state.worker = WorkerState::Terminated;
    }
    // Tracked cleanup of the stdout helper at the terminal edge, then the
    // loop's own bounded residuals, then the outcome of the drive phase.
    let cleanup = channel.cleanup_output_helper();
    let residual = state.residual();
    if let Some(error) = cleanup
        .err()
        .or(residual)
        .or_else(|| drive.err())
        .or_else(|| state.denial())
    {
        return Err(error);
    }
    // Explicit termination accounting (#2785): a worker that never took
    // `Shutdown` or never joined left guest work untracked; that is a
    // failed loop, never a silent success.
    if !shutdown_sent {
        return Err(LoopError::CommandChannelDisconnected {
            command: "shutdown",
        });
    }
    // An accepted Shutdown must be observed to reply. A missing reply is a
    // retained residual, never a silent success; the lost-response
    // projection is best-effort so it never masks the loss itself.
    if shutdown_sent && state.shutdown_request_won.is_none() {
        let error = LoopError::WorkerTerminatedWithoutOutcome {
            command: "shutdown",
        };
        state.publish_lost_response(channel, error);
        state.record_residual(error);
        return Err(error);
    }
    if !joined {
        return Err(LoopError::ChannelUnavailable);
    }
    // A Shutdown ack that could not be staged fails the loop honestly: the
    // delivery stays unacknowledged and the owner must reconcile it, rather
    // than the child reporting success it cannot prove.
    if let Some(error) = confirm_error {
        return Err(error);
    }
    // Child termination, kept separate from cleanup evidence and from the
    // result delivery (issue #2785 I6, audit defect 2): "the worker stopped"
    // is not "the effect is resolved", and neither is "the frame was
    // published". The disposition is read from the P-03 owner's own process
    // evidence for the exact admitted child — an actual exit/reap or an
    // owner-confirmed containment. The seated engine name, this loop's own
    // join, an interrupt request, and the published frame are all other
    // facts and supply none of it. A readback that is missing, failed, or
    // poisoned stays unknown, and an unknown disposition fails the loop
    // rather than reclaiming anything.
    state.guest_child_exited = match termination.observed() {
        ProcessTerminationObservation::Proven => Some(true),
        ProcessTerminationObservation::Unknown => Some(false),
    };
    if state.guest_child_exited != Some(true) {
        return Err(LoopError::OperationContainmentUnresolved {
            operation_id: UNATTESTED_OPERATION,
        });
    }
    state.published().cloned().ok_or(denied("no-request"))
}

/// Joins the terminated worker and confirms its observed Shutdown outcome.
fn join_shutdown_worker(
    state: &mut BoundedRequestLoop,
    channel: &mut dyn WasmHostRequestChannel,
    handle: std::thread::JoinHandle<()>,
    confirm_error: &mut Option<LoopError>,
) -> bool {
    while !handle.is_finished() {
        std::thread::yield_now();
    }
    let joined = handle.join().is_ok();
    if joined {
        state.mark_shutdown();
        // Termination observed: the accepted Shutdown's exact outcome is the
        // joined worker (its reply stays unread by #2785 design), so the
        // delivery completes here with no outcome digest.
        if let Some(token) = state.accepted_control.take() {
            state.remember_control_outcome(token, None);
        }
        if let Err(error) = state.retry_control_completion(channel) {
            state.record_residual(error);
            if confirm_error.is_none() {
                *confirm_error = Some(error);
            }
        }
    }
    joined
}

/// Derives the Kernel control spool directory from the loader path only —
/// never from argv, stdin, or environment: the install directory holding the
/// delivery set. `None` when the loader path is unavailable, in which case
/// the loop serves the delivery set with no external control source.
fn kernel_control_dir() -> Option<PathBuf> {
    admitted_material_path().and_then(|path| path.parent().map(Path::to_path_buf))
}

/// What one external-control intake step admitted.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ExternalIntake {
    /// Nothing was staged.
    None,
    /// A Cancel/Reconcile was admitted and queued: the caller enqueues it
    /// and confirms the delivery only after the worker accepts it.
    Command(WorkerCommand),
    /// A Shutdown was admitted: admission is closed and the drain is
    /// entered, and the delivery is confirmed after the worker accepts the
    /// tracked shutdown in the join tail.
    Shutdown,
}

/// Admits one externally staged Kernel control frame through the same
/// admission path internal control uses. The caller enqueues the admitted
/// command through the loop's normal send handling and continues its tick
/// without pulling a new delivery request; a Shutdown instead closes
/// admission and enters the drain. Admission failure records the exact
/// denial, stages the typed refusal for that exact delivery, and leaves the
/// staged file in place — nothing is acknowledged as enqueued here
/// (issue #2896 W5/A2).
fn admit_external_control(
    state: &mut BoundedRequestLoop,
    channel: &mut dyn WasmHostRequestChannel,
) -> Result<ExternalIntake, LoopError> {
    let Some(control) = channel.poll_control()? else {
        return Ok(ExternalIntake::None);
    };
    if let Err(error) = state.admit(&control.frame) {
        state.record_residual(error);
        channel.reject_delivery(&control.token, error.code())?;
        return Ok(ExternalIntake::None);
    }
    state.hold_control_delivery(control.token)?;
    match state.requested_command() {
        Some(command) => Ok(ExternalIntake::Command(command)),
        None => Ok(ExternalIntake::Shutdown),
    }
}

/// The loop's own terminal residual on a path that ends without a joinable
/// worker (issue #2785 A6/I6). The retained execution evidence, the
/// retained cleanup evidence, and the retained operation record are handed
/// over to the outer process-containment owner as one explicit unresolved
/// disposition: the operation identity stays bound to this process's
/// retained record, so the owner can still reconcile it, and nothing is
/// reclaimed or reported as clean.
fn contained_failure(
    state: &mut BoundedRequestLoop,
    channel: &mut DeliverySetChannel,
) -> LoopError {
    state.worker = WorkerState::Contained;
    let executing = match state.delivery {
        Some(
            CommandDelivery::Requested { command, .. } | CommandDelivery::Accepted { command, .. },
        ) => command_name(command),
        None => EXECUTE_COMMAND,
    };
    let _cleanup = channel.cleanup_output_helper();
    // A command the worker never acknowledged keeps its own residual when
    // the drain already recorded one; otherwise the live worker is what the
    // owner has to terminate.
    if let Some(residual) = state.residual() {
        return residual;
    }
    LoopError::WorkerContained { command: executing }
}

/// Bounded drain window for the admitted grant (issue #2785 W1). The
/// execution itself already ran under the same admitted wall deadline
/// inside the P-03 guest child, so the drain can wait that whole window
/// plus the poll cadence it itself waits on. No new timing policy: these are
/// the admitted ceilings this file already receives.
fn drain_bound(material: &ValidatedDispatchMaterial) -> Duration {
    Duration::from_millis(material.ceilings.wall_deadline_ms) + CONTROL_POLL
}

/// Services the owner-staged control lane exactly once, through the same
/// admission path internal control uses (issue #2785 I3/P1).
///
/// It keeps running after `Execute` admission closed: closing admission
/// stops new execution, never the reply and control servicing needed to
/// terminate the already-owned worker. A versioned control receives an
/// `Enqueued` ack only after the command channel accepts it, then a terminal
/// ack after its observed outcome; the legacy fixed file is retired only by
/// exact-name, byte-verified delete after enqueue. A frame that needs the
/// command slot while a command is accepted stays staged for a later tick,
/// so the accepted command's accounting is never clobbered by a second
/// request (issue #2785 I1/W2).
fn service_control_lane(
    state: &mut BoundedRequestLoop,
    channel: &mut dyn WasmHostRequestChannel,
    commands: &SyncSender<WorkerCommand>,
) -> Result<(), LoopError> {
    // While the bound-1 slot is occupied, the urgent lane scans directly for
    // Cancel/Shutdown. A deferred Reconcile is never installed as the local
    // pending item and cannot hide a later urgent delivery.
    if !state.command_slot_free() {
        return Ok(());
    }
    let Some(control) = channel.poll_control()? else {
        return Ok(());
    };
    match state.admit(&control.frame) {
        Err(error) => {
            state.record_residual(error);
            channel.reject_delivery(&control.token, error.code())?;
        }
        Ok(()) => {
            state.hold_control_delivery(control.token)?;
            if let Some(command) = state.requested_command() {
                state.send(command, commands)?;
                if let Err(error) = state.confirm_accepted_control(channel) {
                    state.record_residual(error);
                }
            }
            // An owner Shutdown remains in `control_token` until the tracked
            // worker Shutdown send in the drain succeeds.
        }
    }
    Ok(())
}

/// Runs the loop's own bounded containment step for an authority window that
/// already closed, taken only while the command slot is free (issue #2785
/// I3). The bounded Store epoch and fuel policy is what actually interrupts
/// the guest; this delivers the owner's containment to the runtime owner at
/// the first point it can accept it. It is a real step of the drain, not
/// only of `Running`: expiry closes `Execute` admission, never the control
/// lane needed to terminate the already-owned worker. A refusal here — a
/// busy slot, an already-spent follow-up, or a control frame the loop's own
/// binding rejects — is recorded as its own bounded residual rather than
/// claimed as delivered.
fn containment_step(state: &mut BoundedRequestLoop) {
    // Never request containment behind an accepted command: the bound-1
    // channel admits exactly one, so the uncertain attempt settles after
    // its own reply arrives, through the follow-up taxonomy.
    if !state.command_slot_free()
        || state.admission.follow_up != FollowUp::None
        || state.live.is_live()
    {
        return;
    }
    if let Err(error) = state.queue_control(OP_CANCEL) {
        state.record_residual(error);
    }
}

/// Records one staged urgent Cancel/Shutdown as interruption demand
/// (#2568 A3). Runs while a command is accepted, so the tick interrupts
/// accepted guest work through the stored engine handle instead of waiting
/// for the reply. Nothing here takes the single command slot: a Shutdown
/// closes admission and waits for the tracked worker shutdown before its
/// terminal ack; a Cancel only sets cancel demand and stays staged until the
/// slot frees, so no second command stacks behind the accepted one (issue
/// #2785 W2) and no delivery is acknowledged for a step that never ran (P1).
fn admit_external_control_urgent(
    state: &mut BoundedRequestLoop,
    channel: &mut dyn WasmHostRequestChannel,
) -> Result<(), LoopError> {
    let Some(control) = channel.poll_control_urgent()? else {
        return Ok(());
    };
    match WasmHostRequestFrame::parse(&control.frame) {
        Ok(WasmHostRequest::Shutdown) => {
            if let Err(error) = state.admit(&control.frame) {
                state.record_residual(error);
                channel.reject_delivery(&control.token, error.code())?;
            } else {
                state.hold_control_delivery(control.token)?;
            }
        }
        Ok(WasmHostRequest::Cancel(control_request)) => {
            match check_control(&state.binding, &control_request) {
            Ok(()) => {
                state.admission.cancel_demanded = true;
                state.urgent_cancel = Some(control.clone());
            }
            Err(error) => {
                let detail = error.code();
                state.record_residual(error);
                channel.reject_delivery(&control.token, error.code())?;
            }
            }
        }
        // Reconcile, Invoke and unparseable bytes never surface here: the
        // urgent poll filters them, so there is nothing to demand.
        Ok(_) | Err(_) => {
            let error = denied("control-operation");
            state.record_residual(error);
            channel.reject_delivery(&control.token, error.code())?;
        }
    }
    Ok(())
}

/// Settles an urgent Cancel after the accepted worker reply frees the single
/// slot. If that observation already closed the result, record a typed
/// refusal; otherwise the Cancel replaces the not-yet-enqueued internal
/// Reconcile request. The spool sequence and delivery token stay unchanged.
fn settle_urgent_cancel(
    state: &mut BoundedRequestLoop,
    channel: &mut dyn WasmHostRequestChannel,
) {
    let Some(control) = state.urgent_cancel.take() else {
        return;
    };
    let refusal = if state.published.is_some() {
        Some(denied("control-after-terminal"))
    } else {
        state.admit(&control.frame).err()
    };
    if let Some(error) = refusal {
        state.record_residual(error);
        if let Err(ack_error) = channel.reject_delivery(&control.token, error.code()) {
            state.record_residual(ack_error);
        }
        return;
    }
    if let Err(error) = state.hold_control_delivery(control.token.clone()) {
        state.record_residual(error);
        if let Err(ack_error) = channel.reject_delivery(&control.token, error.code()) {
            state.record_residual(ack_error);
        }
    }
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
        if let Some(CommandDelivery::Accepted { .. }) = state.delivery {
            poll_pending(state, channel, commands, outcomes, handle)?;
            continue;
        }
        // Single-gate intake (#2785 trigger 2): `tick` may have closed
        // admission after the loop-top check, so recheck before touching
        // the delivery set — no Execute lands after close.
        if !state.intake_open() {
            state.close_admission();
            break;
        }
        // External control stays processable while the loop is idle too: a
        // Kernel Cancel racing the delivery set is admitted before the
        // invoke is pulled, never after it executed. Intake is provably
        // open here (nothing outstanding or queued), so no second command
        // stacks behind an outstanding one.
        match admit_external_control(state, channel)? {
            ExternalIntake::Command(command) => {
                state.send(command, commands)?;
                if let Err(error) = state.confirm_accepted_control(channel) {
                    state.record_residual(error);
                }
                continue;
            }
            ExternalIntake::Shutdown => continue,
            ExternalIntake::None => {}
        }
        // Service the staged control lane through the same admission path
        // internal control uses, then take the loop's own containment step
        // for an authority window that already closed, taken only while the
        // command slot is free.
        service_control_lane(state, channel, commands)?;
        containment_step(state);
        if !state.intake_open() {
            state.close_admission();
            break;
        }
        let Some(frame) = channel.next_frame()? else {
            state.close_admission();
            break;
        };
        if let Err(error) = state.admit(&frame, false) {
            // Record the exact admission denial before it surfaces as a
            // transport-level refusal, so the receipt names the field that
            // actually broke the binding. The delivery-set invoke carries no
            // owner control delivery, so there is nothing to disposition.
            state.denial = Some(error);
            state.close_admission();
            return Err(error);
        }
        if let Some(replay) = state.replay.clone() {
            state.replay = None;
            // Exact replay republishes the retained bounded sequence in
            // order — same events, same sequence numbers, same terminal —
            // without executing again. The terminal projection is the last
            // retained event. The retained sequence is consumed here, so it
            // proves its stream shape first: a corrupted retained sequence
            // fails closed instead of republishing.
            validate_result_stream(&replay)?;
            for event in &replay {
                channel.publish(event)?;
            }
            state.published = replay.last().cloned();
            state.close_admission();
            break;
        }
        if let Some(command) = state.requested_command() {
            // Delivery-set demand carries no owner delivery, so the enqueue
            // confirmation is a no-op by construction; kept so every send
            // site runs the same one check.
            state.send(command, commands)?;
            if let Err(error) = state.confirm_accepted_control(channel) {
                state.record_residual(error);
            }
        }
    }
    Ok(())
}

/// One bounded servicing step for an accepted command: consume its exact
/// reply, or — while the command slot stays occupied because that reply is
/// still owed — keep the control lane responsive.
fn poll_pending(
    state: &mut BoundedRequestLoop,
    channel: &mut dyn WasmHostRequestChannel,
    commands: &SyncSender<WorkerCommand>,
    outcomes: &Receiver<WorkerOutcome>,
    handle: &std::thread::JoinHandle<()>,
) -> Result<(), LoopError> {
    if let Err(error) = state.confirm_accepted_control(channel) {
        state.record_residual(error);
    }
    if let Err(error) = state.retry_control_completion(channel) {
        state.record_residual(error);
    }
    match outcomes.recv_timeout(CONTROL_POLL) {
        Ok(outcome) => consume_worker_outcome(state, channel, commands, outcome),
        Err(RecvTimeoutError::Timeout) => {
            if handle.is_finished() {
                // The worker exited. A reply can arrive between the timeout
                // and the termination observation, so consume that last
                // reply before calling the command's outcome unknown.
                if let Ok(outcome) = outcomes.try_recv() {
                    return consume_worker_outcome(state, channel, commands, outcome);
                }
                let error = LoopError::WorkerTerminatedWithoutOutcome {
                    command: command_name(
                        state.accepted_command().unwrap_or(WorkerCommand::Execute),
                    ),
                };
                state.publish_lost_response(channel, error);
                return Err(error);
            }
            // The command slot is occupied by the accepted command, so no
            // second command may be requested behind it; the owner-staged
            // control lane is still serviced, so a Shutdown is admitted at
            // this tick while a Cancel or Reconcile stays staged for the
            // tick the slot frees (issue #2785 I3). A staged Cancel still
            // interrupts this execution through the urgent demand below.
            // Interrupt, don't queue (#2568 A3): a staged Cancel or Shutdown
            // terminates accepted guest work through the stored engine
            // handle instead of waiting for the reply. Firing never sends,
            // so the bound-1 slot stays single-owner and the uncertain
            // attempt still settles through the follow-up taxonomy once its
            // own reply is observed.
            admit_external_control_urgent(state, channel)?;
            state.interrupt_outstanding();
            Ok(())
        }
        // A disconnected outcome channel can never produce another reply, so
        // the accepted command's outcome stays unknown for the owner that may
        // still contain it. This is a bounded residual of the drain, not an
        // early exit from it: the worker is still supervised to termination.
        Err(RecvTimeoutError::Disconnected) => {
            let error = LoopError::OutcomeChannelDisconnected {
                command: command_name(state.accepted_command().unwrap_or(WorkerCommand::Execute)),
            };
            state.publish_lost_response(channel, error);
            state.record_residual(error);
            Ok(())
        }
    }
}

/// Consumes one worker reply against the exact accepted command it
/// answers, publishes its correlated observation, and hands over the
/// follow-up command the observation itself requested. A delivery failure
/// is reported with its own residual code and never stops the drain.
fn consume_worker_outcome(
    state: &mut BoundedRequestLoop,
    channel: &mut dyn WasmHostRequestChannel,
    commands: &SyncSender<WorkerCommand>,
    outcome: WorkerOutcome,
) -> Result<(), LoopError> {
    // An uncorrelated reply cannot settle an accepted command.
    if state.accepted_command() != Some(outcome.command) {
        return Err(denied("uncorrelated-outcome"));
    }
    let command = outcome.command;
    let accepted_control = state.accepted_control.take();
    // The accepted command's own reply settled, so that accepted slot is
    // retired BEFORE the outcome is observed (issue #2785 audit, defect 1).
    // `on_outcome` may run `settle_uncertain -> request_follow_up`, and that
    // follow-up can only be requested while `command_slot_free()` holds;
    // leaving the old slot occupied would suppress the follow-up the
    // uncertain observation is supposed to send, and clearing the slot
    // afterwards would erase the successor it just selected.
    //
    // The preceding equality check must remain before this mutation.
    state.delivery = None;
    let frame = state.on_outcome(outcome);
    settle_urgent_cancel(state, channel);
    if command != WorkerCommand::Shutdown
        && let Some(token) = accepted_control
    {
        let outcome_digest = frame
            .as_ref()
            .and_then(|frame| serde_json::to_vec(frame).ok())
            .map(|bytes| sha256_hex(&bytes));
        state.remember_control_outcome(token, outcome_digest);
        if let Err(error) = state.retry_control_completion(channel) {
            state.record_residual(error);
        }
    } else if command == WorkerCommand::Shutdown {
        // The tracked worker join is the terminal Shutdown evidence. Keep
        // its token until that exact termination outcome is observed.
        state.accepted_control = accepted_control;
    }
    // Preserve any Requested(Cancel/Reconcile) created by on_outcome: the
    // slot now holds that successor, never the command just settled.
    if let Some(frame) = frame.as_ref() {
        if channel.publish(frame).is_err() {
            // Execution evidence and cleanup evidence stay separate (issue #2785
            // I6): the observation is retained inside the loop, and only its
            // delivery failed. The exact stream fault is the loop's channel
            // fault; what matters here is which observation lost its delivery.
            return Err(LoopError::ResultPublicationFailed {
                observation: observed_command_name(frame),
            });
        }
    }
    if let Some(command) = state.requested_command() {
        state.send(command, commands)?;
        if let Err(error) = state.confirm_accepted_control(channel) {
            state.record_residual(error);
        }
    }
    Ok(())
}

/// Drains the loop to settlement: every accepted command's outcome is
/// observed, every control frame the loop accepted settles, and the
/// reply-servicing lane stays active for the whole drain (issue #2785
/// W1/I3). The drain is bounded by the admitted grant window; exceeding it
/// is an explicit bounded residual, and it leaves the command slot occupied
/// so the accepted command's outcome stays owed rather than disappearing.
fn drain_to_settlement(
    state: &mut BoundedRequestLoop,
    channel: &mut dyn WasmHostRequestChannel,
    commands: &SyncSender<WorkerCommand>,
    outcomes: &Receiver<WorkerOutcome>,
    handle: &std::thread::JoinHandle<()>,
) {
    while !state.drain_complete() {
        if let Some(CommandDelivery::Accepted { .. }) = state.delivery {
            if let Err(error) = poll_pending(state, channel, commands, outcomes, handle) {
                // The reply was consumed but its delivery failed, or the
                // worker ended without it: keep draining, and report the
                // first such failure once the worker is idle.
                if state.drain_complete() {
                    state.record_residual(error);
                    return;
                }
                state.record_residual(error);
            }
        } else if let Some(command) = state.requested_command() {
            if let Err(error) = state.send(command, commands) {
                state.record_residual(error);
                return;
            }
            // A retried external send confirms this exact delivery token;
            // internal follow-ups carry no token and confirm nothing.
            if let Err(error) = state.confirm_accepted_control(channel) {
                state.record_residual(error);
            }
        } else {
            // The command slot is free and nothing is requested: finish
            // the reply lane with one final non-blocking read so no
            // producer is left blocked on a full outcome channel.
            match outcomes.try_recv() {
                Ok(outcome) => {
                    if let Err(error) = consume_worker_outcome(state, channel, commands, outcome) {
                        state.record_residual(error);
                    }
                }
                Err(_) => return,
            }
        }
        state.tick();
        // The control lane keeps running for the whole drain: a window that
        // closed while the loop was draining still gets its one bounded
        // containment action, taken only while the slot is free.
        containment_step(state);
        if !state.drain_complete() && Instant::now() >= state.drain_deadline {
            let command = state
                .accepted_command()
                .or_else(|| state.requested_command())
                .unwrap_or(WorkerCommand::Execute);
            // An accepted control command that never replied is reported as
            // unresolved containment, not as a drain that merely timed out.
            let residual = match command {
                WorkerCommand::Cancel | WorkerCommand::Reconcile => {
                    LoopError::ContainmentUnresolved {
                        command: command_name(command),
                    }
                }
                _ => LoopError::DrainUnsettled {
                    command: command_name(command),
                },
            };
            state.record_residual(residual);
            return;
        }
    }
    if let Err(error) = state.retry_control_completion(channel) {
        state.record_residual(error);
    }
    state.mark_drained();
}

/// Supervises the worker to termination while retaining every outcome still
/// available on the bounded channel (issue #2785 I5). Returns whether the
/// worker thread was observed finished, which is the only condition under
/// which the caller may join. `false` is the process-level containment
/// edge: the handle is still owned by the caller, which reports the
/// operation unresolved rather than returning a live worker.
fn supervise_to_worker_exit(
    state: &mut BoundedRequestLoop,
    channel: &mut dyn WasmHostRequestChannel,
    outcomes: &Receiver<WorkerOutcome>,
    handle: &std::thread::JoinHandle<()>,
) -> bool {
    while !handle.is_finished() {
        if let Err(error) = state.confirm_accepted_control(channel) {
            state.record_residual(error);
        }
        if let Err(error) = state.retry_control_completion(channel) {
            state.record_residual(error);
        }
        match outcomes.recv_timeout(CONTROL_POLL) {
            Ok(outcome) => observe_residual_outcome(state, channel, outcome),
            Err(RecvTimeoutError::Timeout | RecvTimeoutError::Disconnected) => {
                if Instant::now() >= state.drain_deadline {
                    return false;
                }
            }
        }
    }
    while let Ok(outcome) = outcomes.try_recv() {
        observe_residual_outcome(state, channel, outcome);
    }
    // A command still accepted or only requested when the worker ended has
    // no outcome and will never get one: the worker is gone. The lost
    // response is projected best-effort and the loss itself is recorded as
    // this loop's bounded residual, so the projection never becomes the
    // drain verdict.
    if let Some(delivery) = state.delivery {
        let command = match delivery {
            CommandDelivery::Requested { command, .. }
            | CommandDelivery::Accepted { command, .. } => command,
        };
        let error = LoopError::WorkerTerminatedWithoutOutcome {
            command: command_name(command),
        };
        state.publish_lost_response(channel, error);
        state.record_residual(error);
    }
    true
}

/// Consumes one late outcome that arrived while the worker was terminating,
/// under the same slot accounting as [`consume_worker_outcome`] (issue #2785
/// audit, defect 1): the accepted slot is retired before the observation
/// runs, so the observation settles against a free capacity slot.
///
/// The shutdown supervisor holds no command sender, so a follow-up this
/// observation requests is terminalized as unresolved instead of becoming a
/// successor nobody can deliver — the drain is not restarted for it. A reply
/// with no accepted command to settle is an uncorrelated outcome, and a
/// failed delivery is a delivery residual — neither is allowed to change the
/// termination verdict.
fn observe_residual_outcome(
    state: &mut BoundedRequestLoop,
    channel: &mut dyn WasmHostRequestChannel,
    outcome: WorkerOutcome,
) {
    if state.accepted_command() != Some(outcome.command) {
        state.record_residual(denied("uncorrelated-outcome"));
        return;
    }
    let command = outcome.command;
    // The preceding equality check must remain before this mutation.
    let accepted_control = state.accepted_control.take();
    state.delivery = None;
    let frame = state.on_outcome(outcome);
    // The shutdown supervisor owns no sender; a deferred urgent Cancel stays
    // staged and unacknowledged for its external owner to reconcile.
    state.urgent_cancel = None;
    // The observation's follow-up is only reachable through a command
    // sender, and this supervisor owns none. Retiring the request and
    // recording it as unresolved keeps the late observation honest: the
    // control step never became delivered, and the drain does not restart
    // waiting for a command this process can no longer send.
    if let Some(requested) = state.requested_command() {
        state.delivery = None;
        state.record_residual(LoopError::ContainmentUnresolved {
            command: command_name(requested),
        });
    }
    if command != WorkerCommand::Shutdown
        && let Some(token) = accepted_control
    {
        let outcome_digest = frame
            .as_ref()
            .and_then(|frame| serde_json::to_vec(frame).ok())
            .map(|bytes| sha256_hex(&bytes));
        state.remember_control_outcome(token, outcome_digest);
        if let Err(error) = state.retry_control_completion(channel) {
            state.record_residual(error);
        }
    } else if command == WorkerCommand::Shutdown {
        state.accepted_control = accepted_control;
    }
    // A publication failure is recorded against the observation that lost
    // its delivery; the exact stream fault is the loop's channel fault, and
    // what matters here is which observation never reached the owner.
    if let Some(frame) = &frame
        && channel.publish(frame).is_err()
    {
        state.record_residual(LoopError::ResultPublicationFailed {
            observation: observed_command_name(frame),
        });
    }
    if let Err(error) = state.retry_control_completion(channel) {
        state.record_residual(error);
    }
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
    /// The owner has not published this exact generation as a ready,
    /// recoverable delivery: its generation slot records a pending or
    /// failed publication, or names another delivery. Nothing executes
    /// and nothing is deleted — the staged set stays for the owner.
    Publication {
        /// Stable owner publication code: `DELIVERY_PENDING`,
        /// `DELIVERY_FAILED`, or `DELIVERY_IDENTITY_MISMATCH`.
        code: &'static str,
    },
    /// The bounded request loop failed closed.
    Loop(LoopError),
}

impl fmt::Display for OrdinaryDriveError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoDeliverySet => formatter.write_str("ORDINARY_NO_ADMITTED_DELIVERY_SET"),
            Self::DeliveryInProgress { .. } => formatter.write_str("ORDINARY_DELIVERY_IN_PROGRESS"),
            Self::Drive(error) => write!(formatter, "{error}"),
            Self::Publication { code } => write!(formatter, "ORDINARY_{code}"),
            Self::Loop(error) => write!(formatter, "{error}"),
        }
    }
}

impl std::error::Error for OrdinaryDriveError {}

/// Bound on distinct delivery identities one ordinary drive serves.
///
/// Each entry is one consumed generation this process executed to a
/// published terminal; the classifier fences every entry's grant against
/// re-staging, so the set never evicts — past the bound a fresh identity
/// fails closed as in-progress with the staged set left for the owner.
const MAX_SERVED_DELIVERIES_PER_DRIVE: usize = 8;

/// Seals the durable pre-execution `InFlight` claim after admission and
/// before any guest effect (#2786 step 7). A write failure fails closed
/// without executing — admission alone started no guest, so the staged set
/// stays for the owner to re-drive, and a denied delivery leaves no marker.
fn seal_inflight_claim(
    directory: &std::path::Path,
    claim: &crate::dispatch_material::DeliveryClaim,
    now_ms: u64,
) -> Result<(), OrdinaryDriveError> {
    crate::dispatch_material::write_inflight_marker(directory, claim.identity(), now_ms).map_err(
        |_| {
            let identity = claim.identity();
            OrdinaryDriveError::DeliveryInProgress {
                operation_id: identity.operation_id.clone(),
                generation: identity.generation,
                claim_id: identity.claim_id.clone(),
            }
        },
    )
}

/// Seals the durable served evidence for one terminal outcome (#2786 step
/// 7): the complete retained event stream is checked, then the served marker
/// is written before physical reclaim. Every event was durably retained
/// before its stdout write. The pre-execution `InFlight` marker is already durable,
/// so a failed seal still replays on restart instead of re-executing. Any
/// failure preserves the claimed set and reports its original identity as
/// unresolved instead of claiming success.
fn seal_served_outcome(
    directory: &std::path::Path,
    claim: &crate::dispatch_material::DeliveryClaim,
    frame: &OrdinaryOutcome,
    now_ms: u64,
) -> Result<(), OrdinaryDriveError> {
    let result_matches = match read_back_served_stream(directory, claim.identity()) {
        ServedResultReadback::Complete(events) => events.last() == Some(frame),
        ServedResultReadback::Incomplete
        | ServedResultReadback::Conflict
        | ServedResultReadback::Unavailable => false,
    };
    if !result_matches
        || crate::dispatch_material::write_served_marker(directory, claim.identity(), now_ms).is_err()
    {
        let identity = claim.identity();
        return Err(OrdinaryDriveError::DeliveryInProgress {
            operation_id: identity.operation_id.clone(),
            generation: identity.generation,
            claim_id: identity.claim_id.clone(),
        });
    }
    Ok(())
}

/// Typed readback status for the bounded durable result stream.
enum ServedResultReadback {
    Complete(Vec<WasmHostResultFrame>),
    Incomplete,
    Conflict,
    Unavailable,
}

fn result_frames_name_identity(
    events: &[WasmHostResultFrame],
    identity: &StagedDeliveryIdentity,
) -> bool {
    events.iter().all(|frame| {
        frame.operation_id == identity.operation_id
            && frame.claim_id == identity.claim_id
            && frame.grant_digest == identity.grant_digest
            && frame.artifact_digest == identity.artifact_digest
            && frame.input_digest == identity.input_digest
    })
}

/// Reads and validates the complete retained sequence for exactly the staged
/// identity. A legacy terminal-only frame with a nonzero sequence has lost
/// its predecessors and therefore remains incomplete, never replayable.
fn read_back_served_stream(
    directory: &std::path::Path,
    identity: &StagedDeliveryIdentity,
) -> ServedResultReadback {
    let record = match crate::dispatch_material::read_served_result(directory) {
        Ok(Some(record)) => record,
        Ok(None) => return ServedResultReadback::Incomplete,
        Err(MaterialError::Unreadable(_) | MaterialError::TooLarge) => {
            return ServedResultReadback::Unavailable;
        }
        Err(_) => return ServedResultReadback::Conflict,
    };
    if !record.names(identity) {
        return ServedResultReadback::Conflict;
    }
    if let Ok(stream) = serde_json::from_value::<RetainedResultStream>(record.frame.clone()) {
        if stream.wire_id != RETAINED_RESULT_STREAM_WIRE_ID
            || stream.wire_version != RETAINED_RESULT_STREAM_WIRE_VERSION
            || stream.events.is_empty()
            || !result_frames_name_identity(&stream.events, identity)
        {
            return ServedResultReadback::Conflict;
        }
        let Ok(events_json) = serde_json::to_vec(&stream.events) else {
            return ServedResultReadback::Conflict;
        };
        if sha256_hex(&events_json) != stream.events_digest
            || validate_result_prefix(&stream.events).is_err()
        {
            return ServedResultReadback::Conflict;
        }
        let terminal_sequence = stream
            .events
            .last()
            .filter(|event| event.terminal)
            .map(|event| event.sequence);
        if stream.complete {
            if terminal_sequence != stream.terminal_sequence
                || validate_result_stream(&stream.events).is_err()
            {
                return ServedResultReadback::Conflict;
            }
            return ServedResultReadback::Complete(stream.events);
        }
        if terminal_sequence.is_some() || stream.terminal_sequence.is_some() {
            return ServedResultReadback::Conflict;
        }
        return ServedResultReadback::Incomplete;
    }

    let Ok(frame) = serde_json::from_value::<OrdinaryOutcome>(record.frame) else {
        return ServedResultReadback::Conflict;
    };
    if frame.wire_id != WASM_HOST_RESULT_WIRE_ID
        || frame.wire_version != WASM_HOST_RESULT_WIRE_VERSION
        || !result_frames_name_identity(std::slice::from_ref(&frame), identity)
    {
        return ServedResultReadback::Conflict;
    }
    if frame.sequence != 0 {
        return ServedResultReadback::Incomplete;
    }
    if frame.terminal {
        if validate_result_stream(std::slice::from_ref(&frame)).is_err() {
            return ServedResultReadback::Conflict;
        }
        return ServedResultReadback::Complete(vec![frame]);
    }
    if validate_result_prefix(std::slice::from_ref(&frame)).is_err() {
        return ServedResultReadback::Conflict;
    }
    ServedResultReadback::Incomplete
}

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
    let mut served: Vec<crate::dispatch_material::StagedDeliveryIdentity> = Vec::new();
    let mut outcome: Option<OrdinaryOutcome> = None;
    let mut replayed: Option<crate::dispatch_material::StagedDeliveryIdentity> = None;
    // The staged path is the owner's only route into this process, and the
    // previous set was consumed, so any set observed here is either a
    // replacement generation or a same-grant re-stage. Nothing is carried
    // across iterations except the bounded served delivery set below, so no
    // unbounded accumulation is possible.
    while let Some((claim, material)) =
        read_admitted_material().map_err(OrdinaryDriveError::Drive)?
    {
        // The claim arrives with the material from one claim-first read:
        // the pre-read envelope identity selected this operation before
        // the payload files were trusted, so the claim below is that
        // selection — never a copy derived after the fact. Durable
        // retention extends in-memory state across restart: a staged set
        // the served marker names is terminal-unacknowledged (a crash
        // between publish and reclaim), and a staged set the InFlight
        // marker names was claimed for execution (a crash between claim
        // and served durability), so both replay below instead of
        // re-executing.
        let directory = crate::dispatch_material::admitted_material_path()
            .and_then(|path| path.parent().map(std::path::Path::to_path_buf))
            .ok_or(OrdinaryDriveError::Drive(DriveError::NoMaterial))?;
        let served_marker = crate::dispatch_material::read_served_marker(&directory)
            .map_err(|error| OrdinaryDriveError::Drive(DriveError::Material(error)))?;
        let inflight_marker = crate::dispatch_material::read_inflight_marker(&directory)
            .map_err(|error| OrdinaryDriveError::Drive(DriveError::Material(error)))?;
        match crate::dispatch_material::classify_staged_delivery(
            claim.identity(),
            served.as_slice(),
            served_marker.as_ref(),
            inflight_marker.as_ref(),
        ) {
            crate::dispatch_material::StagedDeliveryState::Replay { identity } => {
                // Terminal-unacknowledged read-back: a fresh drive (no
                // in-process outcome) emits the complete retained event
                // sequence for exactly this identity when it is durably
                // available, before any evidence is touched — the replay
                // path deletes nothing. An absent, incomplete, unreadable,
                // or foreign record falls through to the identity-only
                // in-progress report below; same-drive replays keep the
                // in-process projection, never a file read-back.
                if outcome.is_none() {
                    match read_back_served_stream(&directory, &identity) {
                        ServedResultReadback::Complete(events) => {
                            emit_retained_result_stream(&events)
                                .map_err(OrdinaryDriveError::Loop)?;
                            if let Some(frame) = events.last().cloned() {
                                return Ok(frame);
                            }
                        }
                        ServedResultReadback::Incomplete
                        | ServedResultReadback::Conflict
                        | ServedResultReadback::Unavailable => {}
                    }
                }
                // The classifier also treats a differing identity under the
                // same spent grant as Replay, and an InFlight-named set as
                // Replay whether or not its effect settled. Preserve the
                // staged identity; the final projection may reuse an outcome
                // only when this identity exactly matches the latest one
                // served in this process. A replay without a retained
                // result has no acknowledgement to authorize reclamation.
                // Keep the claimed set and durable markers as local
                // identity evidence; the projection below reports
                // DeliveryInProgress with this exact identity until an
                // owner can reconcile it.
                replayed = Some(identity);
                break;
            }
            crate::dispatch_material::StagedDeliveryState::LegacyV1FixedName { identity } => {
                // Explicit v1 compatibility: full admission under the staged
                // identity verbatim, never reinterpreted as a fresh
                // generation with new identity. Bounded served retention:
                // past the bound a fresh identity fails closed as
                // in-progress — the staged set stays for the owner — rather
                // than evicting a spent grant the classifier must remember.
                if served.len() >= MAX_SERVED_DELIVERIES_PER_DRIVE {
                    return Err(OrdinaryDriveError::DeliveryInProgress {
                        operation_id: identity.operation_id,
                        generation: identity.generation,
                        claim_id: identity.claim_id,
                    });
                }
                let _admitted_operation = identity.operation_id.len();
            }
        }
        // Owner publication state gate (#2786 steps 3/7/8): the claim may
        // execute only against the generation the owner itself published
        // as ready. A staged set with no owner record at all is the
        // explicit legacy v1 compatibility state the classifier above
        // admitted; anything the owner did record must name this claim.
        require_ready_publication(&directory, &claim)?;
        let runtime =
            build_admitted_runtime(&material, edge_now_ms()).map_err(OrdinaryDriveError::Drive)?;
        seal_inflight_claim(&directory, &claim, edge_now_ms())?;
        let frame = run_request_loop_with_retention(
            runtime,
            &material,
            Some(ResultRetention::new(&directory, claim.identity())),
        );
        // The delivery set is one-shot: a published terminal outcome reclaims
        // exactly the claimed generation, so a leftover is a fresh-drive
        // signal rather than a silent reuse. Unknown execution, failed
        // publication, lost response, or failed drain retains the exact
        // operation/generation evidence for recovery and never reclaims. The
        // durable retention of the result event stream is the restart
        // readback path, not a second execution.
        match frame {
            Ok(ok_frame) => {
                // Containment evidence is the loop's own terminal condition:
                // it only returns a frame once the operation's effect is
                // attested as settled, so reclaiming here never races an
                // unresolved guest child.
                //
                // The retained event stream and served marker seal durably
                // before physical reclaim, so restart reconciles
                // terminal-unacknowledged state by replaying the original
                // sequence instead of re-executing.
                seal_served_outcome(&directory, &claim, &ok_frame, edge_now_ms())?;
                let reclamation = consume_delivery_set(&claim);
                // The served marker is now durable, so the pre-execution
                // InFlight evidence is redundant: drop it best-effort. A
                // leftover only replays, never re-executes.
                let _ =
                    crate::dispatch_material::clear_inflight_marker(&directory, claim.identity());
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
                served.push(claim.into_identity());
                outcome = Some(ok_frame);
            }
            Err(loop_error) => {
                return Err(OrdinaryDriveError::Loop(loop_error));
            }
        }
    }
    // Only an exact in-process replay of the latest served identity may
    // return the retained terminal frame: the drive holds one terminal, so
    // an older served identity re-staged after a newer serve reports
    // in-progress with its exact identity instead of borrowing the newer
    // result or re-executing under its spent grant. A same-grant replay for
    // another identity cannot borrow that result. Cross-restart
    // terminal-unacknowledged state with a durably retained result already
    // returned that original frame from the replay arm above; only a replay
    // without a retained result reports in-progress with its exact identity.
    // Only a drive that observed nothing staged reports absence.
    match (outcome, replayed) {
        (Some(frame), None) => Ok(frame),
        (Some(frame), Some(identity)) if served.last() == Some(&identity) => Ok(frame),
        (_, Some(identity)) => Err(OrdinaryDriveError::DeliveryInProgress {
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
    crate::dispatch_material::reclaim_claimed_delivery(claim, &directory)
}

/// Requires the owner's own publication state to name this exact
/// generation as ready before the claim executes (#2786 steps 3/7/8).
///
/// The owner slot is located by the claim's own generation and
/// material-set digest, and every owner-recorded field is compared against
/// the claim: a matching pathname, a well-formed token, or a matching
/// grant digest is not a match. A pending or failed owner publication, and
/// a ready record naming another delivery, both fail closed here — nothing
/// executes and nothing is deleted, so the staged set stays for the owner
/// under its exact identity. No owner record at all is the legacy v1
/// fixed-name compatibility state, which stays admissible under full
/// admission with the staged identity verbatim.
///
/// # Errors
///
/// Returns [`OrdinaryDriveError::Publication`] when the owner recorded a
/// state that is not a ready publication of this claim, and
/// [`OrdinaryDriveError::Drive`] when the owner marker is unreadable,
/// malformed, or carries an unsupported identity version.
fn require_ready_publication(
    directory: &Path,
    claim: &crate::dispatch_material::DeliveryClaim,
) -> Result<(), OrdinaryDriveError> {
    let identity = claim.identity();
    match crate::dispatch_material::read_delivery_publication(directory, identity)
        .map_err(|error| OrdinaryDriveError::Drive(DriveError::Material(error)))?
    {
        Some(state) if state.is_ready() && state.names(identity) => Ok(()),
        Some(state) if !state.is_ready() => {
            Err(OrdinaryDriveError::Publication { code: state.code() })
        }
        Some(_) => Err(OrdinaryDriveError::Publication {
            code: "DELIVERY_IDENTITY_MISMATCH",
        }),
        None => Ok(()),
    }
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
