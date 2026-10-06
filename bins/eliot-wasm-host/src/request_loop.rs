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
//!   introduced: exactly one worker is spawned, every return path either
//!   joins it or hands it to a named owner that still holds it (the
//!   containment path joins a worker its drain bound expired on under a
//!   bound of its own — the same admitted window — so an expiry can neither
//!   hang the process on a join that can never return nor leave the
//!   guest-executing thread detached into a running process: a thread still
//!   running when that bound expires has its handle retained by
//!   [`RETAINED_CONTAINED_WORKERS`], which outlives the loop), and the
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
//!   sources. A delivery is acknowledged only after admission plus successful
//!   worker enqueue, by staging an ack beside its exact generation/sequence
//!   name; deliveries are never deleted by the child, and anything
//!   unadmittable stays in place as typed evidence for the owner.
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
//!   Each names the command that produced it — the process-local handover
//!   correlation token carried as `command_sequence` — so within one
//!   recorded stream a consumer can tell which handover each event came
//!   from, using the retained `sequence`/`observation_predecessors` order for
//!   the order itself, and a control event admitted from an owner delivery
//!   names that exact delivery and the acknowledgement the child staged for
//!   it (#2786), never an order or an identity inferred from arrival.
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
//! Observation, local stdout write, owner acknowledgement, and permission to
//! reclaim are four more states kept apart (issue #2787, external audit
//! comment 5868395275). The loop's claim-bound [`ObservedResultRetention`]
//! writes the exact bounded sequence to the existing #2786 result record
//! *before* any of it reaches stdout, and it does so only behind the real
//! [`validate_frame`] (and, for a complete sequence, [`validate_result_stream`])
//! validators, so a frame that cannot prove itself is never written durably and
//! never published either; the retained sequence itself is bounded by
//! [`MAX_RESULT_SEQUENCE`] at the point each observation joins it, and an
//! observation past that bound is an explicit typed capacity failure rather
//! than a dropped prefix. A restart reads that record back through the real
//! per-frame and stream validators over the original recorded bytes, and only
//! a complete sequence is republished through this same owner on the new
//! transport — without admitting a request, issuing a permit, spawning a
//! worker, or deleting anything, and gated on the same retention as every
//! other emission. The loop's own handoff ([`RequestLoopReport`])
//! carries the retained sequence next to the disposition that ended the loop,
//! so a failure never travels alone and an observation is never discarded
//! because something later failed.
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
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{
    Receiver, RecvTimeoutError, SyncSender, TrySendError, channel, sync_channel,
};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use eliot_contracts::sha256_hex;
use eliot_wasm_runtime::lifecycle::{
    DIVERGENCE_REASON_CODE, DivergenceReport, InFlightDisposition, ShadowComparatorOutcome,
};
use eliot_wasm_runtime::{
    EngineBinding, GuestInterruptHandle, InvocationRequest, InvocationResult, Sha256Digest,
    VerificationVerdict,
};

use crate::WasmHostRunner;
use crate::admission::LiveAuthority;
use crate::dispatch_drive::{
    ConformanceRecord, DriveError, LifecycleVerdicts, SeatedVerdicts, conformance_record,
    evaluate_lifecycle_verdicts, evaluate_seated_verdicts, shadow_comparator_for_record,
};
use crate::dispatch_material::{
    ControlAckPhase, ControlFileClass, ExpectedControlBinding, MaterialError,
    ValidatedDispatchMaterial, WASM_CONTROL_ACK_WIRE_ID, WASM_CONTROL_ACK_WIRE_VERSION,
    WASM_CONTROL_KIND_CANCEL, WASM_CONTROL_KIND_RECONCILE, WASM_CONTROL_KIND_SHUTDOWN,
    WASM_CONTROL_MAX_DETAIL_BYTES, WASM_CONTROL_SPOOL_MAX_DELIVERIES, WASM_CONTROL_SPOOL_SCAN_CAP,
    WASM_HOST_CONTROL_FILE_NAME, WasmControlAck, WasmControlDelivery, WasmControlKind,
    admitted_material_path, control_ack_name, control_delivery_name, join_control_delivery,
    parse_control_delivery, parse_control_name, read_control_bytes, retire_legacy_control,
    stage_ack_bytes,
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
///
/// Version 3 adds the two exact coordination facts this family was
/// missing: the process-local handover correlation token of the observed
/// worker command ([`WasmHostResultFrame::command_sequence`], issue #2787
/// S3.5, coordinate with #2785) and the owner's exact control delivery
/// identity plus the acknowledgement the child actually staged for it
/// ([`WasmHostResultFrame::delivery_ack`], issue #2787 S6.2, #2786's exact
/// delivery identity/acknowledgement). Before this version both fields did
/// not exist, so an event named no handover it came from and a control event
/// named no delivery it answered. The token is a process counter, not an
/// owner-issued identity: it is valid inside the recorded stream that carries
/// it and is never compared across processes. An external consumer of
/// version 2 must be migrated: the producer no longer emits it, and every
/// other version is rejected by [`validate_frame`].
pub const WASM_HOST_RESULT_WIRE_VERSION: u16 = 3;
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
/// Closed acknowledgement phase reported on a result event for an owner
/// delivery the child durably staged an `enqueued` ack for, because its
/// command reached the worker. Spelled exactly as
/// [`ControlAckPhase::Enqueued`] serializes, because it names the ack the
/// child staged, not a new phase invented for the result family.
///
/// There is deliberately no `completed` phase here. The child does stage a
/// `completed` ack when it observes a control outcome, but it does so AFTER
/// the observation is retained and after this event is projected, so an
/// emitted event can never attest to an ack that had not been written when
/// the bytes were produced. An event that observed a control outcome and
/// names no staged phase therefore says the delivery was never confirmed —
/// which is exactly what the child knew at emission time.
pub const ACK_PHASE_ENQUEUED: &str = "enqueued";
/// Bound on the retained/emitted result-event sequence per operation
/// (#2787). The follow-up taxonomy admits at most one initial observation
/// plus one follow-up observation per operation, so two events is the
/// structural maximum; the bound leaves headroom for future bounded phases
/// without permitting unbounded growth. It is enforced twice on purpose: at
/// the point an observation joins the retained sequence, and again over the
/// whole aggregate before it is serialized, so the in-memory sequence can
/// never exceed it and the record can never be built from more than it. Past
/// it, retention and emission both fail closed as an explicit typed capacity
/// failure — never a dropped prefix, truncation, or eviction.
pub const MAX_RESULT_SEQUENCE: u64 = 8;

/// Bounded result-byte budget: the largest result frame the loop publishes.
pub const MAX_RESULT_FRAME_BYTES: usize = 64 * 1024;

/// Retained-owner byte budget for one operation's whole result-event
/// aggregate (#2787 audit defect 2).
///
/// It is the served-result record's own allocation guard, so the aggregate is
/// measured against the record that must actually hold it. The aggregate is
/// checked against this budget while it is being built, one event at a time,
/// and a stream that would exceed it fails as an explicit typed capacity
/// error: no prefix is ever dropped to fit, and no event is ever partially
/// retained.
pub const MAX_RETAINED_RESULT_STREAM_BYTES: usize =
    crate::dispatch_material::SERVED_RESULT_MAX_BYTES;

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
///
/// It is a process `static` starting at 1, so a value it mints is comparable
/// only with another value minted by this process without a restart. It is
/// not owner-issued, not durable, and not a command identity any owner ever
/// issued. The order of one operation's observations is not this counter: it
/// is `sequence` with its complete `observation_predecessors` prefix in the
/// retained record (#2787 S3.5), which is written to disk and replayed.
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
/// thread stays owned in every one of these states: the caller joins it only
/// on the paths that observed it finished, and a thread the bounded reap
/// could not join inside its own bound is handed to the process-lifetime
/// owner [`RETAINED_CONTAINED_WORKERS`] rather than dropped.
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
    /// A bound expired with the worker still alive: the operation is
    /// contained, not terminated, and no clean shutdown may be claimed. The
    /// thread itself is then joined into `Reaped` when the bounded reap finds
    /// it finished, which changes no verdict. A reap whose own bound expired
    /// first never joins it: the handle is retained by the process-lifetime
    /// owner [`RETAINED_CONTAINED_WORKERS`] and the thread keeps that owner
    /// instead of being detached.
    Contained,
    /// A bound expired and the bounded reap then observed the worker thread
    /// finished and joined it, so the thread itself is reaped rather than
    /// dropped. This is a thread fact only: the operation is still contained,
    /// `Contained` is not upgraded to `Terminated`, and no process
    /// termination is claimed from it. A reap whose own bound expired first
    /// stays `Contained` — that thread was never joined here, and this state
    /// is not claimed for it.
    Reaped,
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
    /// An admitted capacity bound was exceeded: one result frame is larger
    /// than the admitted result-byte budget, or the retained result-event
    /// sequence is longer than [`MAX_RESULT_SEQUENCE`]. Both are explicit
    /// typed capacity failures. No prefix is ever dropped, truncated or
    /// evicted to make room (#2787 audit defect 2).
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
    /// An observed result event could not be written to the existing
    /// claim-bound durable result record before it was exposed
    /// (#2787 audit defect 3). This is never reported as a safe refusal and
    /// never authorizes re-executing the guest: the original claim stays
    /// uncertain, the claimed set is not reclaimed, and the observed bytes
    /// stay in the loop's retained sequence for the bounded recovery
    /// handoff. A later observation retries the same whole-sequence write, so
    /// a transient fault still lands the full sequence.
    ResultRetentionFailed {
        /// Exact observation that could not be retained durably.
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
    /// path took over. The thread is not a detached worker: its handle was
    /// retained by this process rather than dropped, so the thread keeps an
    /// owner that can still observe whether it finished, and the owner is
    /// told the operation stayed unresolved instead of being told a clean
    /// shutdown happened.
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
            Self::ResultRetentionFailed { .. } => "REQUEST_LOOP_RESULT_RETENTION_FAILED",
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
            | Self::ResultRetentionFailed { observation }
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

/// The exact owner control delivery a control result event answers, and the
/// acknowledgement phase the child actually staged for it (#2787 S6.2, #2786
/// exact delivery identity/acknowledgement).
///
/// This is a result-family type, not a second ack wire: it carries the
/// identity the child READ from the owner's validated delivery bytes plus the
/// phase of the ack it actually staged, so a consumer can join this event to
/// the exact owner slot and can never read a staged ack as owner acceptance.
/// It is deliberately separate from [`WasmControlAck`], whose file the owner
/// writes back in — this travels on the result stream and is never staged as
/// an ack itself. The loop never generates any of these values: each is
/// copied from the delivery the child validated, or is the loop's own
/// observed ack outcome for it.
///
/// Every field is absent together or present together: a delivery this
/// process never read has no identity and therefore no acknowledgement, so
/// the group is [`Option`] as a whole rather than a struct of empty strings.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ControlDeliveryAcknowledgement {
    /// Owner control kind (`cancel`, `reconcile`, `shutdown`) of the
    /// delivery this event answers.
    pub control_kind: String,
    /// Owner sequence of the delivery inside its generation spool.
    pub owner_sequence: u64,
    /// Deterministic owner replay key of the delivery (hex).
    pub replay_key: String,
    /// Lowercase digest of the exact validated delivery bytes (hex).
    pub delivery_digest: String,
    /// Acknowledgement phase the child actually staged for this delivery
    /// before this event was projected, or `None` while the delivery was
    /// still unacknowledged at that moment.
    ///
    /// The only phase that can be present here is `enqueued` (see
    /// [`ACK_PHASE_ENQUEUED`]): the child stages its `completed` ack only
    /// AFTER this event is projected and retained, so an emitted event can
    /// never attest to a phase that had not been written when these bytes
    /// were produced. Absence therefore says exactly what the child knew at
    /// emission time — the delivery was not confirmed yet — and never that an
    /// ack was refused: a refused delivery never reaches the worker and so
    /// never produced an observation at all.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ack_phase: Option<String>,
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
/// Every event additionally names the process-local handover correlation
/// token of the command that produced it
/// ([`command_sequence`](Self::command_sequence)) and, for a control event
/// admitted from an owner delivery, the exact delivery it answers and the
/// acknowledgement the child staged for it
/// ([`delivery_ack`](Self::delivery_ack), #2786). The token distinguishes
/// which handover each event came from within one recorded stream; the order
/// itself is `sequence` with its complete `observation_predecessors` prefix,
/// which is durable. The token is not an owner-issued identity and is never
/// compared across processes, while `delivery_ack` joins a control event to
/// the exact owner spool slot it belongs to.
///
/// Consumers must reject mixed versions, duplicate terminal events, sequence
/// gaps, contradictory command sequences, and contradictory identities. That
/// rejection is not left to a consumer's own reading of this comment:
/// [`validate_result_stream`] is exported from this same owner, so a consumer
/// of captured stdout bytes decodes with this type and rejects with the
/// producer's own validator instead of re-deriving a weaker local check. The
/// loop itself uses it on every emission path and on retained-sequence replay
/// republish.
///
/// Absence stays absence per I5.16: `None` serializes absent,
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
    /// The handover correlation token of the worker command whose reply this
    /// event observes (#2787 S3.5) — the `COMMAND_SEQUENCE` value this loop
    /// stamped on that one accepted command.
    ///
    /// What it is: the process-local number of that single command handover,
    /// read from the accepted command slot while the slot still holds that
    /// command. The bound-1 worker slot means two observations of one
    /// operation can never name the same token, so within a recorded stream
    /// it distinguishes which handover each event came from.
    ///
    /// What it is not, and what no code here enforces: it is not
    /// owner-issued, not durable, and not comparable across processes or
    /// across a restart of this one, because it is a process counter rather
    /// than an identity. It therefore does not order events by a command
    /// identity the owner issued, and it must not be compared with a token
    /// from another process or another run. The retained order of one
    /// operation's observations is `sequence` together with the complete
    /// `observation_predecessors` prefix, both of which live in the durable
    /// retained record. This token adds one more within-stream fact — which
    /// handover produced the event — and is checked only for that internal
    /// consistency (`validate_command_coordination` for its presence
    /// pairing, [`validate_result_stream`] for strict increase within the
    /// stream). A control event's owner-issued delivery identity travels
    /// separately in [`delivery_ack`](Self::delivery_ack); where the owner
    /// did issue a sequence for a command, that is the field that carries it,
    /// not this one.
    ///
    /// `None` for a frame that refuses before any worker command ran: there
    /// was no handover, so there is no command sequence to report and none is
    /// invented.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub command_sequence: Option<u64>,
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
    /// The exact owner control delivery this control event answers, with the
    /// acknowledgement phase the child actually staged for it (#2787 S6.2,
    /// #2786 exact delivery identity/acknowledgement).
    ///
    /// `Some` exactly when the observed worker command came from an
    /// owner-staged control delivery this process validated: the values are
    /// copied from that delivery's own bytes, never generated here, so the
    /// event joins the exact owner spool slot. `None` for the delivery-set
    /// `Execute` and for a loop-derived follow-up, which answer no owner
    /// delivery and therefore acknowledge none. A `Some` value reports what
    /// the CHILD staged locally; it is never owner acceptance, and it never
    /// authorizes reclaiming that delivery's evidence.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub delivery_ack: Option<ControlDeliveryAcknowledgement>,
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
    /// The WASM-versus-declared-reference conformance comparison established
    /// for this result: the observed and the declared result bytes, error
    /// classes, proposed effects, and observed state delta of the same run.
    ///
    /// A value can only exist when that comparison held, because the
    /// comparison's own producer refuses a comparison that does not hold, so
    /// this field never carries a disagreeing pair of sides.
    ///
    /// `None` means this result carries no established comparison. Absence
    /// stays absence: it is never a fabricated, zeroed, or
    /// default-constructed comparison, and it is not a claim that the
    /// component conformed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub conformance: Option<ConformanceRecord>,
    /// The reconciled isolated no-effect shadow comparator outcome for the
    /// same run, when one was built.
    ///
    /// `None` means no comparator outcome was established for this result:
    /// there was no conformance comparison to reconcile its legs over, or no
    /// executor metering to reconcile. Absence stays absence — it is never a
    /// fabricated, zeroed, or default-constructed outcome, and a resource
    /// observation that was not made stays explicitly unknown rather than
    /// zero.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub shadow_comparator: Option<ShadowComparatorOutcome>,
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
///
/// `material` is the validated dispatch material this loop was built from,
/// and it is the only reference source: the conformance comparison and the
/// comparator legs reconciled from it are the existing dispatch-drive
/// owner's own (`conformance_record` / `shadow_comparator_for_record`), so
/// no second semantic core exists here and the declared reference is never
/// derived from the observed guest output.
fn project_result(
    binding: &AdmittedBinding,
    engine: &EngineBinding,
    command: WorkerCommand,
    result: &InvocationResult,
    material: &ValidatedDispatchMaterial,
    divergence: Option<DivergenceReport>,
) -> WasmHostResultFrame {
    let (shadow, canary, rollback, cutover) = lifecycle_frame(evaluate_lifecycle_verdicts(result));
    let (trap, cancelled, drain, rollback_candidate) =
        seated_frame(evaluate_seated_verdicts(result));
    let (fuel_consumed, peak_memory_bytes, table_elements, epoch_ticks) = usage_frames(result);
    let divergence_code = divergence
        .as_ref()
        .map(|_| DIVERGENCE_REASON_CODE.to_owned());
    // The conformance comparison, over this retained result and the
    // validated material, through the existing owner's own call.
    //
    // A missing observation is not an empty observation: with no retained
    // output bytes there are no observed result bytes to compare, so
    // `conformance_record` is never called with a substitute slice and no
    // comparison is carried. The producer's own outcome is what this field
    // reports: a comparison it established, or none. A comparison it refused
    // is reported as no established comparison, which is what a record of a
    // held comparison can honestly be; a reader learns agreement only from a
    // value that is actually present.
    let conformance: Result<Option<ConformanceRecord>, DriveError> = match result.output.as_deref()
    {
        Some(output) => conformance_record(result, output, material),
        None => Ok(None),
    };
    // The comparator reconciles the same run against the comparison's own
    // declared reference values, so it is built only over an established
    // comparison and over the executor's own metering. Without metering there
    // is no metering leg to reconcile, so no comparator outcome is carried;
    // the isolated no-effect shadow comparison, the unknown resource
    // observations, and the producer's own refusals all stay exactly as that
    // owner defines them.
    let established = conformance.as_ref().ok().and_then(|record| record.as_ref());
    let shadow_comparator = match (
        result.output.as_deref(),
        result.receipt.usage.as_ref(),
        established,
    ) {
        (Some(output), Some(usage), Some(record)) => {
            shadow_comparator_for_record(result, output, usage, Some(record))
        }
        _ => None,
    };
    WasmHostResultFrame {
        wire_id: WASM_HOST_RESULT_WIRE_ID.to_owned(),
        wire_version: WASM_HOST_RESULT_WIRE_VERSION,
        phase: command_phase(command).to_owned(),
        worker_command: Some(command_name(command).to_owned()),
        sequence: 0,
        observation_predecessors: Vec::new(),
        command_sequence: None,
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
        delivery_ack: None,
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
        // `Option`'s own default IS `None`: a refusal yields no established
        // comparison rather than a fabricated one, so nothing is invented here.
        conformance: conformance.unwrap_or_default(),
        shadow_comparator,
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

/// Validates the command-coordination half of the result contract (#2787
/// S3.5).
///
/// The rule is a consequence of what the field MEANS, not a new policy: a
/// command sequence exists only for a frame that observed a worker command,
/// and that command produced exactly one handover, so an event that observed
/// a command must carry the token and an event that observed none must not.
/// A frame claiming the handover of a command it also says never ran is a
/// contradiction. No value is refused beyond that pairing: the token is the
/// producer's own process-local [`COMMAND_SEQUENCE`] handover number, so
/// there is nothing about it to judge — it is not owner-issued, and judging
/// its magnitude or comparing it to another producer's would be a policy this
/// contract does not own.
fn validate_command_coordination(frame: &WasmHostResultFrame) -> Result<(), LoopError> {
    match (
        frame.worker_command.is_some(),
        frame.command_sequence.is_some(),
    ) {
        // Observed command with no token: the producer must report the
        // handover it stamped, never leave that correlation absent.
        (true, false) | (false, true) => Err(invalid("command-sequence")),
        (true, true) | (false, false) => Ok(()),
    }
}

/// Validates the exact-delivery half of the result contract (#2787 S6.2).
///
/// A delivery acknowledgement may only be carried by a control observation:
/// the delivery-set `Execute` and a loop-derived containment/reconciliation
/// follow-up answer no owner delivery, so naming one would bind the event to
/// a delivery slot it never came from. The named delivery must also answer the
/// SAME control the observed command was: an event that observed a `reconcile`
/// and names a `cancel` delivery binds two different operations together, which
/// is the exact contradiction a consumer must not have to detect. Every
/// identity field is copied from the owner's validated bytes, so each must be
/// well formed: a control kind from the closed vocabulary, and two lowercase
/// digests.
fn validate_delivery_acknowledgement(frame: &WasmHostResultFrame) -> Result<(), LoopError> {
    let Some(ack) = frame.delivery_ack.as_ref() else {
        return Ok(());
    };
    let control_is_delivery = matches!(
        frame.operation.as_str(),
        OP_CANCEL | OP_RECONCILE | OP_SHUTDOWN
    );
    if !control_is_delivery || frame.worker_command.is_none() {
        return Err(invalid("delivery-ack"));
    }
    // The delivery's own kind must be the operation this event answers, so
    // the exact owner spool slot it names is the slot that produced this
    // command. The operation vocabulary and the owner control vocabulary are
    // the same three words, one `to_owned` mapping each.
    let expected_kind = match frame.operation.as_str() {
        OP_CANCEL => WASM_CONTROL_KIND_CANCEL,
        OP_RECONCILE => WASM_CONTROL_KIND_RECONCILE,
        _ => WASM_CONTROL_KIND_SHUTDOWN,
    };
    if ack.control_kind != expected_kind {
        return Err(invalid("delivery-ack"));
    }
    for digest in [ack.replay_key.as_str(), ack.delivery_digest.as_str()] {
        if !is_lowercase_hex_digest(digest) {
            return Err(invalid("delivery-ack"));
        }
    }
    // The closed phase vocabulary is `enqueued` and absence. A `completed`
    // phase is not accepted because the child stages that ack only after this
    // event is projected, so an event could never attest to it truthfully.
    match ack.ack_phase.as_deref() {
        Some(ACK_PHASE_ENQUEUED) | None => Ok(()),
        Some(_) => Err(invalid("delivery-ack")),
    }
}

/// Whether a value is a lowercase hexadecimal digest of the exact length this
/// codebase records for one (64 hex characters, i.e. SHA-256). An uppercase
/// or truncated value never came from a digest, so it is refused rather than
/// normalized.
fn is_lowercase_hex_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

/// Validates one result frame's internal consistency before emission
/// (#2787 step 5): wire identity/version, closed operation/phase/command
/// vocabulary and their agreement, sequence bound and complete ordered
/// predecessor prefix, the command-sequence and delivery-acknowledgement
/// coordination bindings, output
/// digest/length/hex agreement and omission semantics, and engine-evidence
/// bindings. A frame that cannot prove itself is never emitted; a refusal
/// carries its exact phase with no invented engine, usage, or output
/// evidence, and an unknown outcome stays unknown — local serialization
/// success upgrades nothing.
///
/// This is the same function the emitter runs through
/// [`DeliverySetChannel::publish`], so a consumer validates the frame it
/// decoded with the producer's own rule rather than a re-derived one.
///
/// # Errors
///
/// Returns [`LoopError::ResultInvalid`] when any checked binding disagrees.
pub fn validate_frame(frame: &WasmHostResultFrame) -> Result<(), LoopError> {
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
    validate_command_coordination(frame)?;
    validate_delivery_acknowledgement(frame)?;
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
    // Carried comparison re-proved by the owner's OWN predicate, not by a
    // re-derivation: `Deserialize` bypasses every construction-site refusal in
    // `conformance_record` (component gate, promotion-digest binding, the four
    // digest checks, the missing-state-delta refusal and `!record.holds()`), so a
    // retained frame could otherwise carry two sides that disagree. The frame
    // carries none of `material.input_bytes`, none of the promotion digests and
    // none of the ceilings, so re-deriving the declared reference here is
    // impossible by construction — it is not a weaker second core, it is the same
    // single verdict function the owner exposes, called once more. `None` means
    // no comparison was carried, which is absence and not disagreement, so it is
    // unaffected. Deliberately no presence parity with `shadow_comparator`:
    // `shadow_comparator_for_record` is `Some` only when this comparison, an
    // observed state delta and a usage reading are all `Some`, so a correct
    // frame legitimately carries one without the other.
    match frame.conformance.as_ref() {
        Some(record) if !record.holds() => return Err(invalid("conformance-comparison")),
        Some(_) | None => {}
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
///
/// This is the consumer entry point of the same neutral owner that emits the
/// sequence, so a reader of captured stdout bytes decodes with
/// [`WasmHostResultFrame`] and rejects with THIS function rather than
/// re-deriving a weaker local check. It is the exact validator the emitter
/// runs over a retained sequence for replay republish, and the exact one the
/// disk readback runs; there is no second stream rule.
///
/// # Errors
///
/// Returns [`LoopError::ResultInvalid`] when any event fails
/// [`validate_frame`], when the stream mixes wire identities or versions, when
/// `sequence` values are not gapless from 0, when command sequences do not
/// strictly increase (#2787 S3.5), when more than one event is terminal or
/// none closes the stream, or when the parent identities disagree across
/// events.
pub fn validate_result_stream(events: &[WasmHostResultFrame]) -> Result<(), LoopError> {
    let Some(first) = events.first() else {
        return Err(invalid("result-stream"));
    };
    for event in events {
        validate_frame(event)?;
    }
    let mut terminal_seen = false;
    let mut previous_command: Option<u64> = None;
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
        // Handover order within this one stream (#2787 S3.5): each
        // observation's handover token must be strictly greater than its
        // predecessor's. The bound-1 command slot means two observations can
        // never share one handover, and the loop can only request a
        // follow-up after the previous slot was retired, so a repeat or a
        // step backwards is a contradiction a consumer must reject rather
        // than reorder. This compares the ORIGINAL recorded values, and
        // because the token is a process-local counter, it holds only over
        // this stream — the recorded `sequence` is what orders events, and
        // the owner-issued identity of a control command is `delivery_ack`.
        if let Some(token) = event.command_sequence
            && previous_command.is_some_and(|previous| token <= previous)
        {
            return Err(invalid("command-sequence"));
        }
        previous_command = event.command_sequence.or(previous_command);
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

/// Commitment to the exact bytes of one retained result-event sequence
/// (#2787 audit defect 2).
///
/// It is computed over the ORIGINAL stored values, never over a re-projection
/// of live frames, so the writer and the reader commit to the same bytes and a
/// record whose stored bytes were altered after the fact fails closed.
fn retained_stream_digest(stored: &[serde_json::Value]) -> Result<String, LoopError> {
    let mut commitment = String::new();
    for value in stored {
        let bytes = serde_json::to_vec(value).map_err(|_| invalid("result-stream"))?;
        commitment.push_str(&sha256_hex(&bytes));
    }
    Ok(sha256_hex(commitment.as_bytes()))
}

/// Builds the bounded durable representation of one operation's retained
/// result-event sequence (#2787 audit defect 2), for the existing #2786
/// result record — not a second record and not a second database.
///
/// The three bounds are checked BEFORE the aggregate is allocated or
/// serialized, in this order:
///
/// 1. the event count against [`MAX_RESULT_SEQUENCE`], from the length alone;
/// 2. each event against [`MAX_RESULT_FRAME_BYTES`];
/// 3. the running total against [`MAX_RETAINED_RESULT_STREAM_BYTES`], the
///    retained owner's own budget, after that event's own bytes are measured
///    but before it is joined to the aggregate.
///
/// A sequence that cannot fit produces an explicit typed capacity failure.
/// No prefix is ever dropped to make room and no event is ever partially
/// retained: the only alternative to the whole sequence is the failure.
fn build_retained_result_stream(
    events: &[OrdinaryOutcome],
) -> Result<crate::dispatch_material::RetainedResultStream, LoopError> {
    if events.is_empty() {
        return Err(invalid("result-stream"));
    }
    let count = u64::try_from(events.len()).map_err(|_| LoopError::ResultTooLarge)?;
    if count > MAX_RESULT_SEQUENCE {
        return Err(LoopError::ResultTooLarge);
    }
    let mut stored: Vec<serde_json::Value> = Vec::with_capacity(events.len());
    let mut total = 0usize;
    for event in events {
        let value = serde_json::to_value(event).map_err(|_| invalid("result-stream"))?;
        let bytes = serde_json::to_vec(&value).map_err(|_| invalid("result-stream"))?;
        if bytes.len() > MAX_RESULT_FRAME_BYTES {
            return Err(LoopError::ResultTooLarge);
        }
        total = total.saturating_add(bytes.len());
        if total > MAX_RETAINED_RESULT_STREAM_BYTES {
            return Err(LoopError::ResultTooLarge);
        }
        stored.push(value);
    }
    let terminal_sequence = events
        .last()
        .filter(|event| event.terminal)
        .map(|event| event.sequence);
    let stream_digest = retained_stream_digest(&stored)?;
    Ok(crate::dispatch_material::RetainedResultStream {
        events: stored,
        terminal_sequence,
        stream_digest,
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
        command_sequence: None,
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
        delivery_ack: None,
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
        // No comparison was established: a frame with no engine observation
        // measured nothing, so it compares nothing either and invents
        // neither a conformance record nor a comparator outcome.
        conformance: None,
        shadow_comparator: None,
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
        command_sequence: None,
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
        delivery_ack: None,
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
        // No comparison was established: an unresolved outcome has no
        // declared-reference comparison and no metering to reconcile, and
        // inventing either would claim evidence the observation does not have.
        conformance: None,
        shadow_comparator: None,
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
    fn poll_control(&mut self) -> Result<Option<WasmHostRequestFrame>, LoopError> {
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
    fn poll_control_urgent(&mut self) -> Result<Option<WasmHostRequestFrame>, LoopError> {
        Ok(None)
    }

    /// Confirms that the last polled control delivery for `operation` was
    /// admitted **and** handed to the worker owner. The caller must invoke
    /// this only immediately after the command channel actually took that
    /// command: an acknowledgement written for a demand the loop merely
    /// recorded would report an enqueue that never happened (issue #2896
    /// W5/A2). The default has no external source and confirms nothing.
    ///
    /// # Errors
    ///
    /// Returns [`LoopError::ChannelUnavailable`] when the acknowledgement
    /// cannot be staged.
    fn confirm_control_enqueued(&mut self, _operation: &str) -> Result<(), LoopError> {
        Ok(())
    }

    /// Confirms that the exact worker outcome of the accepted control for
    /// `operation` was observed, carrying the outcome digest when the loop
    /// reports one. The default has no external source and confirms nothing.
    ///
    /// # Errors
    ///
    /// Returns [`LoopError::ChannelUnavailable`] when the acknowledgement
    /// cannot be staged.
    fn confirm_control_completed(
        &mut self,
        _operation: &str,
        _outcome_digest: Option<&str>,
    ) -> Result<(), LoopError> {
        Ok(())
    }

    /// Releases the last polled frame back to staged without admitting it.
    /// Called only when the single command slot is occupied, so a control
    /// step that cannot run yet is re-offered on a later tick instead of
    /// being dropped or admitted twice (issue #2785 P1/W2). The default has
    /// no external source and has nothing to release.
    fn release_control(&mut self) {}

    /// Reports the exact owner delivery identity the child holds for the
    /// control command it has enqueued for `operation`, together with the
    /// acknowledgement phase already staged for it (#2787 S6.2).
    ///
    /// This is a read of the reader's own custody state, not a write and not
    /// an acknowledgement: nothing is staged, nothing is confirmed, and a
    /// `None` means this source never validated an owner delivery for that
    /// operation — so the result event names no delivery and none is
    /// invented. The default has no external source and reports none.
    fn accepted_control_delivery(
        &self,
        _operation: &str,
    ) -> Option<ControlDeliveryAcknowledgement> {
        None
    }

    /// Dispositions the last polled frame as refused for `detail`: the child
    /// itself could not admit it. This is the terminal typed disposition,
    /// never the enqueue acknowledgement — a control that never reached the
    /// worker must not read as enqueued — and the delivery itself is left in
    /// place so the same owner operation stays retained. Temporary slot
    /// pressure is not a refusal: that delivery stays pending and replayable
    /// (issue #2896 W5/A2). The default has no external source and
    /// dispositions nothing.
    fn refuse_control(&mut self, _detail: &'static str) {}

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

    /// Publishes an exact retained result-event sequence in order, through
    /// this channel's own serializer, validator, and emitter, and returns
    /// the terminal event it emitted.
    ///
    /// This is the one replay-publication path. A freshly observed event and
    /// an event read back from durable retention are both emitted by the same
    /// owner, so a replay is the original sequence on a new transport rather
    /// than a second, differently-projected copy. The sequence must prove its
    /// stream shape before any of it is exposed.
    ///
    /// # Errors
    ///
    /// Returns [`LoopError::ResultInvalid`] when the sequence or any of its
    /// events fails validation, [`LoopError::ChannelUnavailable`] when the
    /// stream cannot be written (or stays contended past a caller timeout),
    /// or [`LoopError::ResultTooLarge`] when an event exceeds the budget.
    fn publish_retained_sequence(
        &mut self,
        events: &[WasmHostResultFrame],
    ) -> Result<WasmHostResultFrame, LoopError>;
}

/// Maps an owner control kind onto the loop's closed operation vocabulary.
fn control_operation(kind: WasmControlKind) -> &'static str {
    match kind {
        WasmControlKind::Cancel => OP_CANCEL,
        WasmControlKind::Reconcile => OP_RECONCILE,
        WasmControlKind::Shutdown => OP_SHUTDOWN,
    }
}

/// Builds the one typed `refused` ack this reader ever stages, so a refused
/// delivery has a single spelling whether the child refused it while
/// validating the frame or while admitting it. `detail` names the exact
/// field or code that broke, which is what the owner joins and retains.
fn refused_ack(
    operation_id: &str,
    replay_key: &str,
    delivery_digest: &str,
    generation: u64,
    sequence: u64,
    detail: &str,
) -> WasmControlAck {
    WasmControlAck {
        wire_id: WASM_CONTROL_ACK_WIRE_ID.to_owned(),
        wire_version: WASM_CONTROL_ACK_WIRE_VERSION,
        replay_key: replay_key.to_owned(),
        operation_id: operation_id.to_owned(),
        generation,
        owner_sequence: sequence,
        delivery_digest: delivery_digest.to_owned(),
        phase: ControlAckPhase::Refused,
        detail: Some(detail.to_owned()),
        outcome_digest: None,
    }
}

/// Reports whether a staged ack digest matches the owner's digest shape
/// (64 lowercase hex): the same rule `validate_control_ack`
/// (eliot-kernel-service) applies through `require_digest`.
fn ack_digest_ok(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

/// Reports whether a staged ack detail matches the owner's detail shape
/// (within bound, no control chars, never blank when present): the same
/// rule `validate_control_ack` applies through `require_detail`.
fn ack_detail_ok(detail: Option<&str>) -> bool {
    detail.is_none_or(|value| {
        value.len() <= WASM_CONTROL_MAX_DETAIL_BYTES
            && !value.chars().any(char::is_control)
            && !value.trim().is_empty()
    })
}

/// One polled-but-unconfirmed control delivery: validated and yielded to the
/// loop, but not yet admitted and enqueued, so still unacknowledged and
/// fully replayable. Every identity field it carries is the delivery's own,
/// read from its validated bytes, so an acknowledgement written from it is
/// bound to that delivery's content and not to an operation name two
/// controls can share (issue #2896 A2).
#[derive(Clone, Debug)]
enum PendingControl {
    /// A versioned spool delivery at its exact generation/sequence slot.
    Spool {
        /// Owner control kind.
        kind: WasmControlKind,
        /// Operation identity the delivery names.
        operation_id: String,
        /// Delivery generation (equals the running generation).
        generation: u64,
        /// Owner sequence.
        sequence: u64,
        /// Replay key of the validated delivery.
        replay_key: String,
        /// Digest of the validated delivery.
        delivery_digest: String,
    },
    /// The legacy fixed file, joined under the serialized owner rule.
    Legacy {
        /// Control kind parsed from the staged frame.
        kind: WasmControlKind,
        /// Digest of the admitted bytes; retirement deletes only these.
        digest: String,
    },
}

impl PendingControl {
    /// Returns the owner control kind of the pending delivery.
    fn kind(&self) -> WasmControlKind {
        match self {
            Self::Spool { kind, .. } | Self::Legacy { kind, .. } => *kind,
        }
    }

    /// Returns the loop operation of the pending delivery.
    fn operation(&self) -> &'static str {
        control_operation(self.kind())
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
    /// Owner control kind.
    kind: WasmControlKind,
    /// Operation identity the delivery names.
    operation_id: String,
    /// Delivery generation.
    generation: u64,
    /// Owner sequence.
    sequence: u64,
    /// Replay key of the accepted delivery.
    replay_key: String,
    /// Digest of the accepted delivery.
    delivery_digest: String,
    /// Whether the `enqueued` ack for this delivery is durably staged. A
    /// false value is retried by the next bounded poll, so a command already
    /// handed to the worker is never re-offered as unissued.
    ack_staged: bool,
}

/// Which deliveries one poll is allowed to yield.
///
/// The spool walk itself always takes the first admissible delivery in owner
/// sequence order, because enqueue order is the owner's serialization
/// contract. The interruption lane is the one case where "first" is the
/// wrong answer: a `Reconcile` the owner publishes at the head cannot be
/// handed to the worker while `Execute` holds the command slot, so yielding
/// it would starve the `Cancel` behind it for the whole admitted window and
/// no guest interruption would ever be fired (issue #2896 A6).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ControlPollClass {
    /// Any admissible delivery: the ordinary control lane, which sends the
    /// command to the worker and therefore respects owner sequence order.
    Any,
    /// Only the controls that can stop accepted guest work: the
    /// interruption lane, which never sends and therefore never has to
    /// wait for the command slot.
    Urgent,
}

impl ControlPollClass {
    /// Whether this poll class may yield a delivery of `kind`.
    fn admits(self, kind: WasmControlKind) -> bool {
        match self {
            Self::Any => true,
            Self::Urgent => matches!(kind, WasmControlKind::Cancel | WasmControlKind::Shutdown),
        }
    }
}

/// Bounded control-file reads per poll: at most one spool row of deliveries
/// plus their acks and predecessor links. The walk stops when the budget is
/// spent and resumes on the next tick, so a foreign-filled directory degrades
/// admission instead of growing work without bound.
const CONTROL_POLL_READ_BUDGET: usize = WASM_CONTROL_SPOOL_MAX_DELIVERIES * 3;

/// Evidence disposition for one delivery's declared predecessor link
/// (audit 5868408122, defect 2: "Replace predecessor Boolean read-failure
/// handling with verified/pending/deferred/conflict outcomes").
///
/// Four values, because a `bool` cannot say which of three non-verified
/// answers it holds: only [`Self::Conflict`] authorizes a terminal
/// `Refused` ack, the two pending values leave the delivery staged and
/// unacknowledged for a later poll, and only [`Self::Verified`] admits it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PreviousDisposition {
    /// The declared link was compared against retained predecessor evidence
    /// and agrees with it — or sequence zero legitimately declares no link.
    /// The only value that admits the delivery.
    Verified,
    /// Predecessor evidence exists but has not been read yet, so the declared
    /// link was never compared against anything. Pending, never an admission
    /// and never a refusal: the delivery stays staged and a later poll reads
    /// the evidence.
    AwaitingEvidence,
    /// The bounded control-poll read budget was spent before the predecessor
    /// evidence could be read. This is deferred work, not a finding: the walk
    /// stops and resumes on the next tick, and the delivery is never refused
    /// for a read that did not happen.
    BudgetDeferred,
    /// The declared link was compared against retained predecessor evidence
    /// and disagrees with it — proven conflict. The only value that refuses.
    Conflict,
}

/// Resolution of one delivery's ack slot.
#[derive(Clone, Debug)]
/// Closed outcome set of one ack-slot resolution (issue #2896 W11/A8):
/// every staged-ack shape earns its own variant, so the poll loop can
/// never confuse terminal evidence, garbage, or our own open acceptance.
/// Only [`AckSlot::Free`] and [`AckSlot::Reoffer`] admit or refuse; every
/// other variant leaves the delivery staged and unacknowledged.
enum AckSlot {
    /// The slot is free: the delivery may validate and refuse into it.
    Free,
    /// A prior incarnation left the slot openly accepted and its bytes
    /// still join this exact delivery: re-offer for UNKNOWN recovery.
    Reoffer(WasmControlAck),
    /// A decisive ack (Completed/Refused) bound to this exact delivery:
    /// terminal evidence, never re-admitted.
    Decided,
    /// Our own still-open acceptance occupies the slot.
    OwnOpen,
    /// An ack is staged but its bytes are unreadable: someone's evidence,
    /// never ours to delete or overwrite.
    Unreadable,
    /// An ack is staged but fails the exact owner join
    /// (`validate_control_ack` in eliot-kernel-service): foreign or
    /// corrupt, left in place.
    Unjoined,
    /// The bounded read budget ran out: deferred work, not a finding.
    Deferred,
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
/// control lane. A delivery is acknowledged only through
/// [`Self::confirm_enqueued`], which the loop calls immediately after the
/// command channel actually took that delivery's command: `follow_up`
/// advances only when the command was really handed to the worker (issue
/// #2785 P1/I2), so a delivery the command channel refuses stays staged and
/// replayable instead of being acknowledged for a control step that never
/// ran. A step admission itself refuses is dispositioned with the exact
/// `refused` ack naming the refusal and recorded as the loop's residual —
/// never acknowledged as enqueued; a step that only waits for the occupied
/// command slot stays staged and is re-offered.
///
/// The ordering link is dispositioned, never guessed: a delivery's declared
/// `previous_delivery_digest` is admitted only as
/// [`PreviousDisposition::Verified`], refused only as
/// [`PreviousDisposition::Conflict`], and otherwise left staged for a later
/// poll. A deferred read and an unread predecessor are therefore never
/// reported as proof, in either direction (audit 5868408122, defect 2).
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

    /// Returns one staged control frame of `class` for this operation, or
    /// `None` when nothing admittable of that class is staged. Never fails
    /// the loop and never acknowledges or retires anything: every fault
    /// degrades to nothing pending, and the staged delivery stays replayable
    /// until the loop confirms it after worker enqueue.
    fn poll(&mut self, class: ControlPollClass) -> Option<WasmHostRequestFrame> {
        // An enqueue-confirmed delivery whose `enqueued` ack could not be
        // staged keeps its custody, and the write is retried here before any
        // new scan: a command already handed to the worker must never be
        // re-offered as unissued (issue #2896 W5/A2). The write is best
        // effort here — polling never fails the loop — and the next poll
        // retries it.
        let _ = self.retry_pending_ack();
        // A previous yield that was never confirmed was never enqueued: its
        // delivery is still staged and unacknowledged, so dropping the slot
        // re-discovers it below rather than losing it. The retained
        // `Shutdown` delivery is not dropped: its acknowledgement belongs
        // to the drain's real enqueue, not to this poll.
        self.pending = None;
        let (deliveries, acks) = self.scan_spool()?;
        if deliveries
            .iter()
            .chain(acks.iter())
            .any(|(generation, _)| *generation == self.binding.generation)
        {
            self.versioned_seen = true;
        }
        if let Some(frame) = self.poll_spool(&deliveries, &acks, class) {
            return Some(frame);
        }
        self.poll_legacy(&deliveries, &acks, class)
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

    /// Walks the staged deliveries lowest-first and yields the first
    /// admittable one of `class`. Terminal acks make exact replays
    /// idempotent skips; changed same-sequence content conflicts by leaving
    /// both files for the owner; our-generation refusals stage one typed
    /// refused ack each; foreign generations are skipped without touching
    /// their slots, which belong to their own stream. A delivery the
    /// class does not admit is walked past, not claimed: the interruption
    /// lane must reach the `Cancel` behind an unplaceable `Reconcile`
    /// instead of stopping at it.
    fn poll_spool(
        &mut self,
        deliveries: &[ControlSlot],
        acks: &[ControlSlot],
        class: ControlPollClass,
    ) -> Option<WasmHostRequestFrame> {
        let mut reads = 0usize;
        for &(generation, sequence) in deliveries {
            // The exact delivery is read and parsed BEFORE the ack slot is
            // resolved (issue #2896 W11/A8): the slot joins the staged ack
            // against this delivery's identity, never against bare
            // wire/version/generation/sequence.
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
            let slot = self.open_ack(generation, sequence, &delivery, acks, &mut reads);
            // Only a free slot or a byte-matching re-offer admits or
            // refuses; every other outcome leaves the delivery staged and
            // unacknowledged. A re-offered slot is taken, so refusals never
            // overwrite the retained open acceptance.
            let slot_taken = matches!(slot, AckSlot::Reoffer(_));
            match &slot {
                AckSlot::Free | AckSlot::Reoffer(_) => {}
                AckSlot::Deferred => return None,
                AckSlot::Decided | AckSlot::OwnOpen | AckSlot::Unreadable | AckSlot::Unjoined => {
                    continue;
                }
            }
            // The re-offered ack already joined this exact delivery inside
            // `open_ack`: same digest, never re-acknowledged over the taken
            // slot when the content changed under the sequence.
            if let AckSlot::Reoffer(ack) = &slot {
                debug_assert_eq!(ack.delivery_digest, delivery.delivery_digest);
            }
            let identity = &delivery.identity;
            if identity.generation != generation || identity.owner_sequence != sequence {
                self.refuse_slot(generation, sequence, &delivery, "control-slot", slot_taken);
                continue;
            }
            if identity.generation != self.binding.generation {
                // Foreign generation: never admit, never act, and never
                // stage into its slot — a concurrent replacement stream
                // owns it. Skipping is the refusal; the file stays.
                continue;
            }
            if let Err(refusal) = join_control_delivery(&delivery, &self.binding, edge_now_ms()) {
                self.refuse_slot(generation, sequence, &delivery, refusal.field, slot_taken);
                continue;
            }
            match self.check_previous(generation, sequence, &delivery, &mut reads) {
                PreviousDisposition::Verified => {}
                // A read that ran out of budget is deferred work, not a
                // finding: stop the walk and resume on the next tick rather
                // than refusing a delivery whose predecessor was never
                // compared.
                PreviousDisposition::BudgetDeferred => return None,
                // Predecessor evidence is retained but not yet read, so the
                // declared link was never compared. Leave the delivery staged
                // and unacknowledged: a later poll reads the evidence.
                PreviousDisposition::AwaitingEvidence => continue,
                // Only a compared-and-disagreeing link is a proven conflict,
                // and only a proven conflict is refused.
                PreviousDisposition::Conflict => {
                    self.refuse_slot(
                        generation,
                        sequence,
                        &delivery,
                        "control-previous",
                        slot_taken,
                    );
                    continue;
                }
            }
            let kind = identity.control_kind;
            if !class.admits(kind) {
                // Admissible but not this lane's: leave the file staged and
                // unacknowledged and keep walking. The delivery the owner
                // published first still goes first to the worker, because
                // the ordinary lane is the one that enqueues.
                continue;
            }
            let control = PendingControl::Spool {
                kind,
                operation_id: identity.operation_id.clone(),
                generation,
                sequence,
                replay_key: identity.replay_key.clone(),
                delivery_digest: delivery.delivery_digest.clone(),
            };
            self.retain_shutdown(&control);
            self.pending = Some(control);
            return Some(WasmHostRequestFrame::control(
                control_operation(kind),
                &self.admitted,
            ));
        }
        None
    }

    /// Resolves the ack slot for one already-parsed delivery (issue #2896
    /// W11/A8). The staged ack joins against this exact delivery with the
    /// same checks the owner applies in `validate_control_ack`
    /// (eliot-kernel-service): wire id/version, replay key, operation id,
    /// generation, owner sequence, and delivery digest, plus the detail
    /// bound and the phase/detail/outcome shape. Anything less is
    /// [`AckSlot::Unjoined`], never a silent skip over unchecked fields.
    fn open_ack(
        &self,
        generation: u64,
        sequence: u64,
        delivery: &WasmControlDelivery,
        acks: &[(u64, u64)],
        reads: &mut usize,
    ) -> AckSlot {
        if !acks.contains(&(generation, sequence)) {
            return AckSlot::Free;
        }
        if *reads >= CONTROL_POLL_READ_BUDGET {
            return AckSlot::Deferred;
        }
        *reads += 1;
        let path = self.directory.join(control_ack_name(generation, sequence));
        let Ok(bytes) = read_control_bytes(&path) else {
            return AckSlot::Unreadable;
        };
        let Ok(ack) = serde_json::from_slice::<WasmControlAck>(&bytes) else {
            return AckSlot::Unjoined;
        };
        let identity = &delivery.identity;
        if ack.wire_id != WASM_CONTROL_ACK_WIRE_ID
            || ack.wire_version != WASM_CONTROL_ACK_WIRE_VERSION
            || ack.replay_key != identity.replay_key
            || ack.operation_id != identity.operation_id
            || ack.generation != generation
            || ack.owner_sequence != sequence
            || ack.delivery_digest != delivery.delivery_digest
            || ack
                .detail
                .as_ref()
                .is_some_and(|detail| detail.len() > WASM_CONTROL_MAX_DETAIL_BYTES)
        {
            return AckSlot::Unjoined;
        }
        // Same shape rules the owner applies in `validate_control_ack`; see
        // `ack_digest_ok` / `ack_detail_ok` beside `refused_ack`.
        match (&ack.phase, &ack.detail, &ack.outcome_digest) {
            (ControlAckPhase::Enqueued, _, None) if ack_detail_ok(ack.detail.as_deref()) => {
                let mine = self.accepted.as_ref().is_some_and(|accepted| {
                    accepted.generation == generation && accepted.sequence == sequence
                });
                if mine {
                    AckSlot::OwnOpen
                } else {
                    AckSlot::Reoffer(ack)
                }
            }
            (ControlAckPhase::Completed, _, outcome)
                if ack_detail_ok(ack.detail.as_deref())
                    && outcome.as_deref().is_none_or(ack_digest_ok) =>
            {
                AckSlot::Decided
            }
            (ControlAckPhase::Refused, Some(_), None) if ack_detail_ok(ack.detail.as_deref()) => {
                AckSlot::Decided
            }
            _ => AckSlot::Unjoined,
        }
    }

    /// Resolves one delivery's declared previous-digest link against
    /// retained predecessor evidence and reports which of the four
    /// dispositions it earned.
    ///
    /// Sequence zero opens the stream, so it verifies only when it declares
    /// no link; a sequence that declares one there is a proven conflict. A
    /// later sequence must chain to its retained predecessor, and the link is
    /// compared against whatever evidence the owner still retains: the
    /// predecessor ack first (the primary evidence, staged once the
    /// predecessor was admitted and enqueued), then the staged predecessor
    /// delivery itself. The second read is what keeps the interruption lane
    /// honest *and* live: the urgent lane preempts a head `Reconcile` it
    /// never enqueues, so no ack for that predecessor is ever written, and an
    /// ack-only check would leave every chained `Cancel`/`Shutdown` with
    /// permanently absent evidence — admitted unchecked, or never admitted at
    /// all. The immutable delivery is the owner's own evidence of the digest
    /// the link names, so comparing it is a comparison, not a bypass.
    ///
    /// Absent or undecodable evidence on both paths is
    /// [`PreviousDisposition::AwaitingEvidence`] — pending, never an
    /// admission and never a refusal. A spent read budget is
    /// [`PreviousDisposition::BudgetDeferred`], checked before every read so
    /// this arm is reachable and deferred work is never reported as a
    /// finding. Only a compared-and-disagreeing link is
    /// [`PreviousDisposition::Conflict`].
    fn check_previous(
        &self,
        generation: u64,
        sequence: u64,
        delivery: &WasmControlDelivery,
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
        if *reads >= CONTROL_POLL_READ_BUDGET {
            return PreviousDisposition::BudgetDeferred;
        }
        *reads += 1;
        let ack_path = self
            .directory
            .join(control_ack_name(generation, sequence - 1));
        if let Ok(bytes) = read_control_bytes(&ack_path)
            && let Ok(ack) = serde_json::from_slice::<WasmControlAck>(&bytes)
        {
            return Self::compare_previous(previous, ack.delivery_digest.as_str());
        }
        if *reads >= CONTROL_POLL_READ_BUDGET {
            return PreviousDisposition::BudgetDeferred;
        }
        *reads += 1;
        let delivery_path = self
            .directory
            .join(control_delivery_name(generation, sequence - 1));
        let Ok(bytes) = read_control_bytes(&delivery_path) else {
            return PreviousDisposition::AwaitingEvidence;
        };
        let Ok(staged) = parse_control_delivery(&bytes) else {
            return PreviousDisposition::AwaitingEvidence;
        };
        Self::compare_previous(previous, staged.delivery_digest.as_str())
    }

    /// Compares one declared predecessor link against retained evidence. A
    /// later sequence with no declared link disagrees with that evidence
    /// exactly like a mismatching one: only sequence zero may declare no
    /// link, so a missing declaration is a proven conflict, not a pass.
    fn compare_previous(previous: Option<&str>, evidence: &str) -> PreviousDisposition {
        if previous == Some(evidence) {
            PreviousDisposition::Verified
        } else {
            PreviousDisposition::Conflict
        }
    }

    /// Stages one typed refused ack at an exact free slot. Best-effort: a
    /// staging failure leaves the delivery unacknowledged for the next poll,
    /// and polling never fails the loop. A taken slot is never overwritten.
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

    /// Polls the legacy fixed file under the serialized owner rule: only
    /// while no versioned delivery or ack for this generation was ever
    /// observed, only for the exact running operation and grant, and never
    /// for `Invoke`. Unjoinable content stays in place as owner evidence.
    fn poll_legacy(
        &mut self,
        deliveries: &[(u64, u64)],
        acks: &[(u64, u64)],
        class: ControlPollClass,
    ) -> Option<WasmHostRequestFrame> {
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
        if !class.admits(kind) {
            return None;
        }
        let control = PendingControl::Legacy {
            kind,
            digest: sha256_hex(&bytes),
        };
        self.retain_shutdown(&control);
        self.pending = Some(control);
        Some(frame)
    }

    /// Retains an admitted owner `Shutdown` delivery until its command
    /// channel enqueue is actually proven.
    ///
    /// The transient [`Self::pending`] slot answers "what did the loop just
    /// yield", and the control lane reuses it every tick, so a `Shutdown`
    /// cannot be acknowledged from it: its demand is recorded while a
    /// command may still be accepted, and the drain is what finally hands
    /// `WorkerCommand::Shutdown` to the worker. Retaining the delivery
    /// identity here is what lets [`Self::confirm_enqueued`] write the
    /// `enqueued` ack at the real enqueue and not one tick earlier
    /// (issue #2896 W5/A2).
    ///
    /// The slot is first-wins: the tracked drain sends `Shutdown` exactly
    /// once, so only the first admitted `Shutdown` can be what that send
    /// answers. A later `Shutdown` must never inherit this claim, or one
    /// real enqueue would acknowledge a delivery whose own demand was never
    /// acted on.
    fn retain_shutdown(&mut self, control: &PendingControl) {
        if control.kind() != WasmControlKind::Shutdown || self.shutdown.is_some() {
            return;
        }
        self.shutdown = Some(control.clone());
    }

    /// Offers the first ordered urgent control — one staged Cancel/Shutdown
    /// naming this operation, still unacknowledged — or `None` when nothing
    /// urgent is staged (#2568 A3). Reconcile remains staged and
    /// unacknowledged until idle: it observes a finished attempt, so it
    /// never preempts outstanding work, and the urgent walk steps over it
    /// instead of stopping on it. Cancel/Shutdown also remain
    /// unacknowledged until their owner action reaches the worker, and a
    /// yielded frame is retired only after its demand is accepted and
    /// delivered, never before (issue #2785 P1). No fixed or versioned
    /// control file is consumed here.
    fn poll_urgent(&mut self) -> Option<WasmHostRequestFrame> {
        self.poll(ControlPollClass::Urgent)
    }

    /// Confirms admission plus successful worker enqueue for the pending
    /// delivery of `operation`: a spool delivery stages its `enqueued` ack at
    /// the exact slot, a legacy delivery retires by exact-name byte-verified
    /// delete. An owner `Shutdown` is confirmed from the delivery retained
    /// by [`Self::retain_shutdown`], because its worker enqueue happens in
    /// the drain and not on the tick that yielded it. Any other operation —
    /// or no pending delivery — is a no-op, so internal commands confirm
    /// nothing.
    fn confirm_enqueued(&mut self, operation: &str) -> Result<(), LoopError> {
        // The retained `Shutdown` delivery outranks the transient slot for
        // its own operation: it is the only delivery whose enqueue is
        // confirmed after the control lane has moved on.
        if let Some(retained) = self
            .shutdown
            .clone()
            .filter(|shutdown| shutdown.operation() == operation)
        {
            return self.confirm_delivery_enqueued(retained);
        }
        let Some(pending) = self.pending.clone() else {
            return Ok(());
        };
        if pending.operation() != operation {
            return Ok(());
        }
        self.confirm_delivery_enqueued(pending)
    }

    /// Stages the enqueue acknowledgement for one delivery whose worker
    /// enqueue is already proven, then advances this reader's own slot
    /// accounting. Split out of [`Self::confirm_enqueued`] so the retained
    /// and the transient delivery resolve to exactly one acknowledgement
    /// body, with no branch that could write it twice.
    fn confirm_delivery_enqueued(&mut self, pending: PendingControl) -> Result<(), LoopError> {
        let operation = pending.operation();
        match pending {
            PendingControl::Spool {
                kind,
                operation_id,
                generation,
                sequence,
                replay_key,
                delivery_digest,
            } => {
                // Custody first, then the owner-visible write: the command is
                // already in the worker, so a failed ack stage must not drop
                // this delivery and let a later poll re-offer a command the
                // worker already took as unissued. The write is retried by
                // [`Self::retry_pending_ack`] on the next bounded poll
                // (issue #2896 W5/A2).
                self.accepted = Some(AcceptedControl {
                    kind,
                    operation_id,
                    generation,
                    sequence,
                    replay_key,
                    delivery_digest,
                    ack_staged: false,
                });
                self.retry_pending_ack()?;
            }
            PendingControl::Legacy { digest, .. } => {
                // Best-effort: the file itself remains as visible evidence
                // when retirement fails, so the run continues and a restart
                // re-offers the same bytes under at-least-once delivery.
                let _ = retire_legacy_control(&self.legacy_path, &digest);
                self.legacy_consumed = true;
            }
        }
        if self
            .shutdown
            .as_ref()
            .is_some_and(|shutdown| shutdown.operation() == operation)
        {
            self.shutdown = None;
        }
        self.pending = None;
        Ok(())
    }

    /// Writes the `enqueued` acknowledgement for the enqueue-confirmed
    /// delivery when that write is still owed, and records it as staged.
    ///
    /// This is the only place the child ever writes an `enqueued` ack, and it
    /// runs only for a delivery whose command channel send already succeeded
    /// ([`Self::confirm_delivery_enqueued`]). The body is rebuilt from the
    /// retained [`AcceptedControl`], so it always carries that delivery's own
    /// operation, replay key, generation, owner sequence and delivery digest
    /// (issue #2896 A2).
    fn retry_pending_ack(&mut self) -> Result<(), LoopError> {
        let Some(accepted) = self.accepted.clone() else {
            return Ok(());
        };
        if accepted.ack_staged {
            return Ok(());
        }
        let ack = WasmControlAck {
            wire_id: WASM_CONTROL_ACK_WIRE_ID.to_owned(),
            wire_version: WASM_CONTROL_ACK_WIRE_VERSION,
            replay_key: accepted.replay_key.clone(),
            operation_id: accepted.operation_id.clone(),
            generation: accepted.generation,
            owner_sequence: accepted.sequence,
            delivery_digest: accepted.delivery_digest.clone(),
            phase: ControlAckPhase::Enqueued,
            detail: None,
            outcome_digest: None,
        };
        self.stage_ack(accepted.generation, accepted.sequence, &ack)?;
        if let Some(accepted) = self.accepted.as_mut() {
            accepted.ack_staged = true;
        }
        Ok(())
    }

    /// Confirms the exact observed worker outcome of the accepted delivery
    /// for `operation` by staging its `completed` ack over the exact slot.
    /// Any other operation — including internal commands and legacy
    /// deliveries, which carry no ack slot — is a no-op.
    fn confirm_completed(
        &mut self,
        operation: &str,
        outcome_digest: Option<&str>,
    ) -> Result<(), LoopError> {
        // Only the delivery whose own worker outcome was observed completes.
        // `accepted` is set by the enqueue confirmation and cleared here, so
        // this cannot complete a delivery the worker never received, and the
        // kind check additionally keeps an internal command from completing
        // an owner delivery of the same name.
        let Some(accepted) = self.accepted.clone() else {
            return Ok(());
        };
        if control_operation(accepted.kind) != operation {
            return Ok(());
        }
        // A `completed` ack supersedes any still-unstaged `enqueued` ack for
        // the same slot, so the completion path clears the pending write
        // rather than leaving it to overwrite a terminal phase.
        let outcome_digest = outcome_digest
            .filter(|digest| {
                digest.len() == 64
                    && digest
                        .bytes()
                        .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
            })
            .map(str::to_owned);
        let ack = WasmControlAck {
            wire_id: WASM_CONTROL_ACK_WIRE_ID.to_owned(),
            wire_version: WASM_CONTROL_ACK_WIRE_VERSION,
            replay_key: accepted.replay_key.clone(),
            operation_id: accepted.operation_id.clone(),
            generation: accepted.generation,
            owner_sequence: accepted.sequence,
            delivery_digest: accepted.delivery_digest.clone(),
            phase: ControlAckPhase::Completed,
            detail: None,
            outcome_digest,
        };
        self.stage_ack(accepted.generation, accepted.sequence, &ack)?;
        // The delivery is terminal: its exact outcome is recorded, so the
        // custody slot and any un-staged `enqueued` ack it still owed are
        // both released.
        self.accepted = None;
        Ok(())
    }

    /// Reports the exact delivery identity and staged acknowledgement for the
    /// custody slot this reader currently holds for `operation` (#2787
    /// S6.2).
    ///
    /// It reads only what the reader itself recorded: the delivery's own
    /// validated bytes, and the phase derived from the reader's own ack state
    /// — never a phase assumed because a command happened to run. The
    /// enqueue-confirmed [`Self::accepted`] slot outranks the transient
    /// pending slot, exactly as it does in [`Self::confirm_completed`], so a
    /// delivery whose outcome the child is about to observe is the one named.
    /// A `None` means this reader holds no spool delivery for that operation —
    /// the command was loop-derived, or arrived over the legacy fixed file
    /// that carries no owner identity — and the result event then names none.
    fn accepted_delivery(&self, operation: &str) -> Option<ControlDeliveryAcknowledgement> {
        // The enqueue-confirmed [`Self::accepted`] slot outranks the transient
        // slots, exactly as it does in [`Self::confirm_completed`], so a
        // delivery whose outcome the child is about to observe is the one
        // named. Its identity is read directly off the retained slot rather
        // than rebuilt as a `PendingControl`, because the slot already holds
        // exactly those values.
        if let Some(accepted) = self
            .accepted
            .as_ref()
            .filter(|accepted| control_operation(accepted.kind) == operation)
        {
            // The `enqueued` ack for this exact delivery was durably staged
            // (an un-staged one is retried by the next bounded poll, so a
            // false value here means the write is still owed and nothing is
            // claimed).
            return Some(ControlDeliveryAcknowledgement {
                control_kind: accepted.kind.as_str().to_owned(),
                owner_sequence: accepted.sequence,
                replay_key: accepted.replay_key.clone(),
                delivery_digest: accepted.delivery_digest.clone(),
                ack_phase: accepted.ack_staged.then(|| ACK_PHASE_ENQUEUED.to_owned()),
            });
        }
        // No confirmed delivery: the retained `Shutdown` slot outranks the
        // transient pending one, because its enqueue is proven in the drain
        // and not on the tick that yielded it. Either slot names the delivery
        // only when it really is a spool delivery — the legacy fixed file
        // carries no owner identity, so it names none.
        let control = self
            .shutdown
            .as_ref()
            .filter(|shutdown| shutdown.operation() == operation)
            .or_else(|| {
                self.pending
                    .as_ref()
                    .filter(|pending| pending.operation() == operation)
            })?;
        match control {
            PendingControl::Spool {
                kind,
                sequence,
                replay_key,
                delivery_digest,
                ..
            } => Some(ControlDeliveryAcknowledgement {
                control_kind: kind.as_str().to_owned(),
                owner_sequence: *sequence,
                replay_key: replay_key.clone(),
                delivery_digest: delivery_digest.clone(),
                ack_phase: None,
            }),
            PendingControl::Legacy { .. } => None,
        }
    }

    /// Stages one ack at its exact generation/sequence name.
    fn stage_ack(
        &self,
        generation: u64,
        sequence: u64,
        ack: &WasmControlAck,
    ) -> Result<(), LoopError> {
        let bytes = serde_json::to_vec(ack).map_err(|_| LoopError::ChannelUnavailable)?;
        // Compare-before-write (issue #2896 W10): a slot that already holds
        // other bytes belongs to whoever staged them. Every caller either
        // ignores this result or retries through `ack_staged`, so absorbing
        // the conflict is the only non-impersonating choice — failing the
        // loop on foreign-owned evidence would wedge intake, and overwriting
        // would impersonate it.
        if let Err(error) = stage_ack_bytes(
            &self.directory.join(control_ack_name(generation, sequence)),
            &bytes,
        ) && !matches!(error, MaterialError::DigestMismatch)
        {
            return Err(LoopError::ChannelUnavailable);
        }
        Ok(())
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

    /// Binds a channel that can only republish an exact retained
    /// result-event sequence.
    ///
    /// It admits no request, carries no admitted delivery, and installs no
    /// Kernel control reader, so [`WasmHostRequestChannel::next_frame`]
    /// reports exhaustion from its first poll. A cross-restart replay
    /// therefore reuses this owner's serializer, validator, and emitter
    /// without constructing an `AdmittedRuntime`, issuing a one-shot permit,
    /// spawning a worker, or touching staged evidence.
    #[must_use]
    pub fn replay_only() -> Self {
        Self {
            admitted: None,
            delivered: true,
            control: None,
            emission_broken: false,
            pending_helper: None,
        }
    }

    /// The one serializer, validator, and emitter behind every result event
    /// this owner publishes, whether the event was just observed by a worker
    /// or read back from durable retention for replay.
    ///
    /// Internal consistency first: a frame that cannot prove itself is never
    /// emitted, and a publication failure retains the observed result
    /// through the loop's drain accounting, never an ad hoc fallback. A
    /// successful write plus flush below is an observed local stream write,
    /// not proof the owner durably accepted the result.
    fn emit_validated(&mut self, frame: &WasmHostResultFrame) -> Result<(), LoopError> {
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
        if self.reap_output_helper() {
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

    /// Reaps a retained stdout helper that has finished, reporting whether
    /// a still-unfinished one is holding the contended stream. The helper
    /// handle is only ever joined once observed finished, so no reap path
    /// returns a handle it would then drop live.
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

    /// Runs the loop's own tracked cleanup of the stdout helper at a real
    /// terminal edge: reap a helper that has finished, and fail closed when
    /// one is still blocked.
    ///
    /// A still-blocked helper is the process-level containment edge (issue
    /// #2785 A6): it is never reaped while running, and the result whose
    /// emission it held is reported to the process owner as still unconfirmed
    /// rather than dropped as a clean stop. That is exactly what
    /// [`Self::reap_output_helper`] reports, so the single check below is the
    /// whole edge — a helper that is still held is reported once, as
    /// [`LoopError::OutputHelperContained`], and no second reap could
    /// distinguish it. A stopped stream (`emission_broken`) needs no reap, so
    /// a bounded emission cannot fail twice for one delivery fault.
    pub(crate) fn cleanup_output_helper(&mut self) -> Result<(), LoopError> {
        if self.emission_broken {
            return Ok(());
        }
        if self.reap_output_helper() {
            return Err(LoopError::OutputHelperContained);
        }
        Ok(())
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
        match self.control.as_mut() {
            Some(reader) => Ok(reader.poll(ControlPollClass::Any)),
            None => Ok(None),
        }
    }

    fn release_control(&mut self) {
        if let Some(control) = self.control.as_mut() {
            control.pending = None;
        }
    }

    fn refuse_control(&mut self, detail: &'static str) {
        if let Some(control) = self.control.as_mut() {
            control.refuse_pending(detail);
        }
    }

    fn accepted_control_delivery(&self, operation: &str) -> Option<ControlDeliveryAcknowledgement> {
        self.control
            .as_ref()
            .and_then(|reader| reader.accepted_delivery(operation))
    }

    fn poll_control_urgent(&mut self) -> Result<Option<WasmHostRequestFrame>, LoopError> {
        match self.control.as_mut() {
            Some(reader) => Ok(reader.poll_urgent()),
            None => Ok(None),
        }
    }

    fn confirm_control_enqueued(&mut self, operation: &str) -> Result<(), LoopError> {
        match self.control.as_mut() {
            Some(reader) => reader.confirm_enqueued(operation),
            None => Ok(()),
        }
    }

    fn confirm_control_completed(
        &mut self,
        operation: &str,
        outcome_digest: Option<&str>,
    ) -> Result<(), LoopError> {
        match self.control.as_mut() {
            Some(reader) => reader.confirm_completed(operation, outcome_digest),
            None => Ok(()),
        }
    }

    fn publish(&mut self, frame: &WasmHostResultFrame) -> Result<(), LoopError> {
        self.emit_validated(frame)
    }

    fn publish_retained_sequence(
        &mut self,
        events: &[WasmHostResultFrame],
    ) -> Result<WasmHostResultFrame, LoopError> {
        // The stream proves its shape before any of it is exposed: one wire
        // identity and version, gapless sequences from 0, exactly one closing
        // terminal event, and one consistent parent identity across the whole
        // sequence. A corrupted retained sequence fails closed instead of
        // republishing.
        validate_result_stream(events)?;
        for event in events {
            self.emit_validated(event)?;
        }
        events
            .last()
            .cloned()
            .ok_or_else(|| invalid("result-stream"))
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
        self.reap_output_helper();
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

/// The coordination facts of one command the worker accepted
/// (#2787 S3.5/S6.2).
///
/// `CommandDelivery::Accepted` already holds the #2785 handover token, and
/// the channel reader holds #2786's exact owner delivery identity for the
/// command it enqueued from one. This pairs the two so a result event reports
/// the handover it came from, instead of leaving that implicit, alongside the
/// owner delivery it answers.
///
/// It is read while the accepted slot still holds that command and is never
/// reconstructed afterwards: an event whose handover token is not held here
/// records no command sequence rather than guessing one. A `delivery` of
/// `None` is not a missing value but a fact — that command answered no owner
/// delivery, so it acknowledges none.
type ObservedCommandIdentity = Option<(u64, Option<ControlDeliveryAcknowledgement>)>;

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

/// Process-lifetime owner of every worker handle this process still holds
/// (issue #2785 A6).
///
/// A handle reaches this owner on exactly one path: the bounded reap's own
/// bound expired while the guest-executing thread was still running, so the
/// loop could neither join it inside that bound nor claim it terminated. The
/// loop state is not that owner — the loop state is dropped when
/// `run_request_loop` returns, so a handle parked there would be dropped a
/// moment later, and `JoinHandle::drop` detaches: the thread would then be an
/// untracked live worker, which is what this issue forbids. The process is
/// the one owner that outlives the loop, so the handle is retained here and
/// stays owned for as long as this process runs.
///
/// The retained handle keeps the thread's status knowable rather than
/// untracked: [`JoinHandle::is_finished`] is a live observation, and the next
/// contained worker to be retained joins every retained handle that has
/// finished by then, so a thread that ends after its loop is reaped rather
/// than abandoned. Only an already-finished thread is ever joined, so
/// retaining one can never hang this process.
///
/// Retention owns a thread; it claims nothing about the operation. The
/// unresolved containment residual still reaches the caller, and
/// [`WorkerState::Reaped`] is still set only by the joined path in
/// [`join_contained_worker`].
static RETAINED_CONTAINED_WORKERS: Mutex<Vec<std::thread::JoinHandle<()>>> = Mutex::new(Vec::new());

/// Hands one unjoined contained worker handle to the process-lifetime owner
/// [`RETAINED_CONTAINED_WORKERS`], reaping any retained worker that has
/// finished in the meantime.
///
/// A poisoned lock is taken back rather than dropped: the handle being
/// retained is precisely the thing that must not be lost, so a panic
/// elsewhere in this process must not cost it that ownership. The new handle
/// is stored unconditionally, so no return path here can leave a live thread
/// without an owner.
fn retain_contained_worker(handle: std::thread::JoinHandle<()>) {
    let mut retained = match RETAINED_CONTAINED_WORKERS.lock() {
        Ok(retained) => retained,
        Err(poisoned) => poisoned.into_inner(),
    };
    // Tracked termination, not a second reap path: only a thread already
    // observed finished is joined here, so this never waits and never claims
    // termination. The same `is_finished`-then-`join` discipline the stdout
    // helper owner uses for its own retained handle.
    let mut still_running = Vec::new();
    for worker in retained.drain(..) {
        if worker.is_finished() {
            let _ = worker.join();
        } else {
            still_running.push(worker);
        }
    }
    still_running.push(handle);
    *retained = still_running;
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
    /// engine handle, and the Cancel command itself is admitted, sent and
    /// retired by the control lane once the slot frees. Cleared when the
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
    /// sequence without executing again. Bounded by [`MAX_RESULT_SEQUENCE`]
    /// at the point an event joins the sequence itself
    /// ([`Self::retain_slot_available`]), not only in the later aggregate
    /// builder: an observation that would exceed the bound is an explicit
    /// typed capacity failure, never a dropped prefix.
    retained: BTreeMap<String, Vec<WasmHostResultFrame>>,
    /// The claim-bound durable owner of the observed result sequence
    /// (#2787 audit defect 3). Every observed event is written through it
    /// before it can be exposed on stdout, so retention, local publication,
    /// owner acknowledgement, and permission to reclaim stay four separate
    /// states.
    retention: ObservedResultRetention,
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
    /// The same admitted window as a duration, retained beside its absolute
    /// [`Self::drain_deadline`]. The containment reap is a second phase that
    /// starts after that instant has already been spent — spending it a second
    /// time is what leaves the reap no bound at all — so it anchors on the
    /// admitted ceiling this loop was constructed with. Same owner, same
    /// ceiling, no new timing policy and no new constant.
    drain_window: Duration,
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
    /// The validated dispatch material this loop was built from, retained
    /// exactly as [`binding`](Self::binding) and [`engine`](Self::engine)
    /// were derived from it. It is the only reference source the result
    /// projection has: the conformance comparison and its comparator legs are
    /// built from this material over the retained result by the existing
    /// dispatch-drive owner, never re-derived here and never taken from the
    /// observed guest output. Retained once at construction, not per result.
    material: ValidatedDispatchMaterial,
}

impl BoundedRequestLoop {
    /// Creates the loop state from the granted binding, engine mode,
    /// live authority cell, the claim-bound result retention owner, and the
    /// admitted guest ceilings that bound the drain.
    ///
    /// Retention is required, not optional: a loop that could be built
    /// without a durable owner would have no way to persist an observation
    /// before exposing it, which is exactly the ordering this loop enforces.
    #[must_use]
    pub fn new(
        binding: AdmittedBinding,
        engine: EngineBinding,
        live: Arc<LiveAuthority>,
        drain_deadline: Duration,
        retention: ObservedResultRetention,
        material: &ValidatedDispatchMaterial,
    ) -> Self {
        Self {
            binding,
            engine,
            live,
            max_in_flight: 1,
            retained: BTreeMap::new(),
            retention,
            replay: None,
            next_sequence: 0,
            delivery: None,
            worker: WorkerState::Alive,
            guest_child_exited: None,
            drain_deadline: Instant::now() + drain_deadline,
            drain_window: drain_deadline,
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
            material: material.clone(),
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

    /// The exact bounded result-event sequence observed for this operation,
    /// in observation order (#2787 audit defect 2).
    ///
    /// Every retained event of this operation carries the one sealed request
    /// digest this loop's binding names, so the operation's sequence is that
    /// key's whole entry — never a merge across digests, and never a single
    /// terminal event standing in for the sequence that produced it.
    #[must_use]
    pub fn retained_sequence(&self) -> Vec<WasmHostResultFrame> {
        self.retained
            .get(&self.binding.request_digest)
            .cloned()
            .unwrap_or_default()
    }

    /// Writes the exact observed sequence through the claim-bound result
    /// owner, before any of it can be exposed on stdout (#2787 audit
    /// defect 3).
    ///
    /// The order is validate, then retain, then publish: the REAL existing
    /// validators run over the exact observation BEFORE the durable write,
    /// so a frame that cannot prove itself never reaches the result record.
    /// Until now only the later emitter validated, which meant an invalid
    /// frame was written to disk first and rejected only at publication.
    ///
    /// `validate_frame` is the same per-event validator
    /// [`DeliverySetChannel::publish`] runs, not a second or weaker rule. It
    /// is applied to the newest observation — the event that just joined the
    /// sequence — and the events before it are already covered because
    /// `retained` is seeded empty by [`Self::new`] and has exactly two
    /// mutators, `on_outcome` and `publish_lost_response`, each of which is
    /// followed by this gate on the turn it appends. A future third mutator
    /// must therefore call this same gate, or validate the whole sequence
    /// rather than only its newest event.
    ///
    /// Once the stream is complete (its last event is
    /// the terminal one) the existing `validate_result_stream` additionally
    /// proves the whole sequence's shape — gapless `sequence` values from 0,
    /// one closing terminal, one parent identity — so a record that would be
    /// sealed as a complete stream is checked as one. An incomplete prefix is
    /// explicitly allowed here: the audit's bounded prefix is retained, and a
    /// sequence with no terminal yet is exactly that.
    ///
    /// The write always carries the WHOLE sequence observed so far, so a
    /// later observation still lands the earlier ones that a transient
    /// failure kept off disk. A failure is a validation refusal, a typed
    /// capacity failure, or the retention failure itself; the caller keeps the
    /// original claim uncertain, publishes nothing, reclaims nothing, and
    /// never re-executes the guest.
    fn retain_observed(&self) -> Result<(), LoopError> {
        let events = self.retained_sequence();
        // A complete sequence (one that ends in its terminal event) must also
        // prove its stream shape; an explicit prefix has no terminal to close
        // it yet and is validated event by event only.
        let complete = events.last().is_some_and(|event| event.terminal);
        if let Some(latest) = events.last() {
            validate_frame(latest)?;
        }
        if complete {
            validate_result_stream(&events)?;
        }
        self.retention.retain(&events)
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
    /// single-slot worker can only ever reply to the command it was handed,
    /// so the slot itself is the correlation; the #2785 handover token that
    /// command additionally carries is read by
    /// [`Self::accepted_command_sequence`] (#2787 S3.5).
    fn accepted_command(&self) -> Option<WorkerCommand> {
        match self.delivery {
            Some(CommandDelivery::Accepted { command, .. }) => Some(command),
            _ => None,
        }
    }

    /// The #2785 handover correlation token of the accepted command, or `None`
    /// when no command is outstanding.
    ///
    /// This is the correlation a result event carries as
    /// [`WasmHostResultFrame::command_sequence`]: it is stamped by
    /// [`Self::send`] on the one command handover the worker received, so two
    /// observations of one operation can never name the same token and a
    /// consumer can tell which handover produced which event inside the
    /// recorded stream. It is that process counter, nothing more — it
    /// orders nothing by itself, it is not owner-issued, and it is never
    /// compared outside the stream that recorded it. It is read while the
    /// accepted slot still holds that command, and never guessed
    /// afterwards.
    fn accepted_command_sequence(&self) -> Option<u64> {
        match self.delivery {
            Some(CommandDelivery::Accepted { token, .. }) => Some(token),
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
    ///
    /// `identity` is the coordination facts of the command whose reply this
    /// is (#2787 S3.5/S6.2). The caller reads it from the accepted command
    /// slot BEFORE that slot is retired here, so the event carries the
    /// handover correlation of the command that produced it and the exact
    /// owner delivery it answers — never a value inferred from arrival, and
    /// never a delivery identity the command did not come from.
    ///
    /// `None` means this observation produced no publishable event: either it
    /// was a `Shutdown` outcome, which projects no worker-command frame, or
    /// the retained sequence is already at [`MAX_RESULT_SEQUENCE`] and this
    /// observation became the loop's first bounded residual instead. In the
    /// capacity case nothing is retained and nothing is published, so the
    /// claim stays uncertain and the guest is not re-executed.
    fn on_outcome(
        &mut self,
        outcome: WorkerOutcome,
        identity: ObservedCommandIdentity,
    ) -> Option<WasmHostResultFrame> {
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
            Ok(result) => project_result(
                &self.binding,
                &self.engine,
                command,
                &result,
                &self.material,
                divergence,
            ),
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
        // The event's own coordination facts, read from the accepted command
        // that produced it (#2787 S3.5/S6.2). It is applied before the
        // budget check so an identity ever larger than the frame budget
        // is caught by the same omission rule as any other field, and before
        // the event joins the retained sequence so the durable record carries
        // it too.
        if let Some((command_sequence, delivery)) = identity {
            frame.command_sequence = Some(command_sequence);
            frame.delivery_ack = delivery;
        }
        frame = enforce_frame_budget(frame, self.binding.max_output_bytes);
        self.admission.one_shot_spent = true;
        // The retained sequence is bounded WHERE the frame joins it, not only
        // in the later aggregate builder (#2787). The bound is consulted before
        // the event is copied into the aggregate, so a ninth observation is
        // never allocated into the in-memory sequence and never becomes
        // `self.published`; an over-bound event is an explicit typed capacity
        // failure recorded as this loop's first bounded residual, and no
        // earlier observation is dropped, truncated, or evicted to make room.
        if !self.retain_slot_available(&frame.request_digest) {
            self.record_residual(LoopError::ResultTooLarge);
            return None;
        }
        self.next_sequence = self.next_sequence.saturating_add(1);
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

    /// Whether one more observation may join `digest`'s retained sequence
    /// under [`MAX_RESULT_SEQUENCE`].
    ///
    /// The bound is a real accumulation bound, so it is asked of the sequence
    /// itself, at the append, rather than discovered afterwards while a
    /// larger aggregate is being serialized. The count is derived from the
    /// retained entries themselves, so it cannot disagree with what the
    /// sequence actually holds and therefore cannot let a frame's
    /// `observation_predecessors` name an event the sequence does not retain.
    fn retain_slot_available(&self, digest: &str) -> bool {
        let held = self.retained.get(digest).map_or(0, Vec::len);
        u64::try_from(held).is_ok_and(|count| count < MAX_RESULT_SEQUENCE)
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
        let owner = match self.delivery {
            Some(CommandDelivery::Requested { owner, .. }) => owner,
            _ => false,
        };
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
    /// an accepted command to observe. A retained sequence already at
    /// [`MAX_RESULT_SEQUENCE`] suppresses it too: the projection becomes the
    /// loop's first bounded residual instead, and the loss is neither
    /// truncated into the sequence nor published from outside it.
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
        // The lost command's own coordination facts (#2787 S3.5/S6.2),
        // read from the accepted slot that still holds it: the loss is
        // attributed to the exact command whose reply never arrived, not to
        // the operation as a whole. A `Shutdown` loss projects the demand
        // itself with no worker command, so it names neither a command
        // sequence nor a delivery — a frame that claims no worker command ran
        // cannot also claim the handover of one.
        if worker_command.is_some()
            && let Some((command_sequence, delivery)) = self
                .accepted_command_sequence()
                .map(|token| (token, channel.accepted_control_delivery(operation)))
        {
            frame.command_sequence = Some(command_sequence);
            frame.delivery_ack = delivery;
        }
        frame = enforce_frame_budget(frame, self.binding.max_output_bytes);
        // The error-path observation is bounded exactly like any other, at the
        // point it would join the retained sequence (#2787). Past
        // [`MAX_RESULT_SEQUENCE`] it is not a prefix to trim and not an earlier
        // observation to evict: it becomes this loop's first bounded residual,
        // an explicit typed capacity failure, and is neither retained nor
        // exposed. The claim therefore stays uncertain, nothing is reclaimed,
        // the guest is not re-executed, and the retained sequence still holds
        // every observation it held before.
        if !self.retain_slot_available(&frame.request_digest) {
            self.record_residual(LoopError::ResultTooLarge);
            return;
        }
        frame.terminal = true;
        self.next_sequence = self.next_sequence.saturating_add(1);
        self.published = Some(frame.clone());
        self.retained
            .entry(frame.request_digest.clone())
            .or_default()
            .push(frame.clone());
        // The error-path observation is retained before it is exposed, on
        // the same terms as any other (#2787 audit defect 3), and the
        // exposure is GATED on that retention rather than following it. A
        // stdout write that reached the owner with nothing durable behind it
        // is exactly the state the audit named, so when the claim-bound
        // result owner cannot take these bytes the emission does not happen
        // at all. The persistence failure becomes this loop's first bounded
        // residual and the caller still reports the loss itself, so the claim
        // stays uncertain, the observed bytes stay in the retained sequence
        // for the bounded recovery handoff, and the guest is never
        // re-executed.
        if let Err(error) = self.retain_observed() {
            self.record_residual(error);
            return;
        }
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

/// The claim-bound durable owner of this operation's observed result
/// sequence (#2787 audit defect 3).
///
/// It reaches exactly one place — the existing #2786 served-result record,
/// under the exact staged identity this drive claimed — and it is the only
/// writer of that record on the ordinary path. Threading it into the loop is
/// what makes retention and exposure two separate states: an event is written
/// here before it is published on stdout, so a publication that then fails,
/// or a loop that then fails, still leaves the exact observed bytes on disk
/// for the owner's recovery handoff.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ObservedResultRetention {
    directory: PathBuf,
    identity: crate::dispatch_material::StagedDeliveryIdentity,
}

impl ObservedResultRetention {
    /// Binds retention to the exact claimed identity beside this
    /// installation. It is derived from the claim, never from argv, stdin, or
    /// the environment, so it can only ever name the delivery this drive
    /// actually claimed.
    #[must_use]
    pub fn new(directory: &Path, claim: &crate::dispatch_material::DeliveryClaim) -> Self {
        Self {
            directory: directory.to_path_buf(),
            identity: claim.identity().clone(),
        }
    }

    /// Writes the exact bounded sequence observed so far.
    ///
    /// # Errors
    ///
    /// Returns [`LoopError::ResultTooLarge`] when the sequence cannot fit its
    /// bounds — an explicit capacity failure, never a dropped prefix — and
    /// [`LoopError::ResultRetentionFailed`] when the record itself cannot be
    /// written. Neither is ever reported as a safe refusal of the operation.
    fn retain(&self, events: &[OrdinaryOutcome]) -> Result<(), LoopError> {
        let stream = build_retained_result_stream(events)?;
        crate::dispatch_material::write_served_result(
            &self.directory,
            &self.identity,
            crate::dispatch_material::ServedResultPayload::Stream(stream),
            edge_now_ms(),
        )
        .map_err(|_| LoopError::ResultRetentionFailed {
            observation: events
                .last()
                .map_or(EXECUTE_COMMAND, |event| observed_command_name(event)),
        })
    }
}

/// How the ordinary request loop ended, together with the execution, cleanup,
/// and delivery dispositions it reached (#2787 audit defect 2).
///
/// The served disposition carries no frame of its own. The terminal event is
/// the last event of the retained sequence the report already holds — it is
/// always appended to that sequence before it is published — so naming it
/// again beside the sequence would duplicate a whole result frame, and a
/// duplicate is exactly the drift this handoff exists to prevent: a served
/// report can no longer describe a terminal other than the one in its own
/// sequence. It also keeps this type free of any heap allocation, so no
/// disposition depends on a `Box` that aborts the process when an allocation
/// fails.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LoopCompletion {
    /// The loop published one terminal frame and closed its own execution,
    /// cleanup, and delivery accounting. That terminal is the last event of
    /// the report's retained sequence; read it with
    /// [`RequestLoopReport::served_terminal`].
    Served,
    /// The loop failed. The failure is never returned alone: an observation
    /// this loop made may be the only copy of a guest result, and discarding
    /// it because something later failed would destroy the only record of it.
    Failed {
        /// The exact loop failure that ended the loop.
        failure: LoopError,
    },
}

/// What the ordinary request loop leaves behind: the exact bounded retained
/// result-event sequence for this operation, next to the disposition that
/// ended the loop.
///
/// The handoff exists so execution evidence, cleanup evidence, and delivery
/// disposition are read together and never in place of one another, and so a
/// failure can never travel without the observations that produced it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RequestLoopReport {
    retained: Vec<OrdinaryOutcome>,
    completion: LoopCompletion,
}

impl RequestLoopReport {
    /// The exact bounded retained result-event sequence, in observation
    /// order, for the operation this loop served. It is present on every
    /// disposition, including a failure before any event was observed, where
    /// it is empty.
    #[must_use]
    pub fn retained(&self) -> &[OrdinaryOutcome] {
        &self.retained
    }

    /// Whether the loop published a terminal frame or failed, and with what.
    #[must_use]
    pub fn completion(&self) -> &LoopCompletion {
        &self.completion
    }

    /// The exact terminal frame the loop published, or `None` when the loop
    /// failed.
    ///
    /// It is a borrow of the last event of the sequence this report already
    /// carries, so reading it copies nothing and cannot disagree with the
    /// sequence. `None` here means the loop failed, not that the result was
    /// lost: a failure still carries every observation through
    /// [`Self::retained`].
    #[must_use]
    pub fn served_terminal(&self) -> Option<&OrdinaryOutcome> {
        match &self.completion {
            LoopCompletion::Served => self.retained.last(),
            LoopCompletion::Failed { .. } => None,
        }
    }

    /// The report for a loop that published a terminal frame.
    #[must_use]
    fn served(retained: Vec<OrdinaryOutcome>) -> Self {
        Self {
            retained,
            completion: LoopCompletion::Served,
        }
    }

    /// The report for a failed loop, carrying every observation it made.
    #[must_use]
    fn failed(retained: Vec<OrdinaryOutcome>, failure: LoopError) -> Self {
        Self {
            retained,
            completion: LoopCompletion::Failed { failure },
        }
    }
}

/// Runs the bounded ordinary request loop over one granted execution, and
/// returns what it observed next to how it ended.
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
/// The containment edge is the one place the worker may still be running when
/// the deadline arrives, and its join is bounded by the same admitted window
/// rather than left open: the report returns either way, and what differs is
/// only whether the thread was reaped inside that bound or, when the bound
/// expired first, retained by [`RETAINED_CONTAINED_WORKERS`] — an owner that
/// outlives this loop — before this process hands the unresolved operation to
/// the outer process-containment owner.
///
/// Every disposition — success, denial, drain failure, and the
/// process-level containment path — runs all three steps, so no path can
/// leave a live join handle unreported.
///
/// Every observed result event is proved by the real per-frame validator and,
/// once the stream is complete, by the real stream validator, then written
/// through `retention` — the existing claim-bound result owner — before it is
/// published on stdout; the same gate covers the failure-edge handoff
/// ([`hand_off_observed_sequence`]), so no write reaches the durable record
/// unproved. The whole observed sequence travels back with the loop's
/// disposition, so an observation is never lost to a later failure. The
/// loop's own failure is a [`LoopCompletion::Failed`] disposition beside that
/// sequence rather than a `Result` error, because an error arm returning only
/// the failure would throw away the only copy of an observed guest result.
pub fn run_request_loop(
    runtime: AdmittedRuntime,
    material: &ValidatedDispatchMaterial,
    retention: ObservedResultRetention,
) -> RequestLoopReport {
    let binding = AdmittedBinding::from_material(material, &runtime.invocation);
    let request_frame = WasmHostRequestFrame::admitted_invoke(&binding);
    let mut channel = DeliverySetChannel::new(request_frame);
    if let Some(directory) = kernel_control_dir() {
        channel = channel.with_kernel_control(KernelControlReader::new(&binding, directory));
    }
    let mut state = BoundedRequestLoop::new(
        binding,
        runtime.engine_binding.clone(),
        Arc::clone(&runtime.live),
        drain_bound(material),
        retention,
        material,
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

/// The report for a failed loop edge: the exact bounded sequence observed so
/// far beside the exact failure.
///
/// Every failing edge of the drain reports the same way. Nothing there returns
/// a bare error, because the sequence may be the only copy of an observation
/// that never reached stdout.
fn failed_loop_report(state: &BoundedRequestLoop, failure: LoopError) -> RequestLoopReport {
    RequestLoopReport::failed(state.retained_sequence(), failure)
}

/// Drains accepted work, shuts down and joins the worker, then returns the
/// exact retained result-event sequence of the ordinary request loop together
/// with the disposition that ended it.
fn drain_and_shutdown_request_worker(
    state: &mut BoundedRequestLoop,
    channel: &mut DeliverySetChannel,
    termination: &ProcessTermination,
    worker: EngineWorker,
    drive: Result<(), LoopError>,
) -> RequestLoopReport {
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
    // (issue #2785 I5). The live authority cell is revoked first, so nothing
    // further can resolve through it while the worker stops.
    state.live.revoke();
    let (shutdown_sent, mut confirm_error) =
        request_tracked_shutdown(state, channel, &worker.commands);
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
        // Process-level containment path (issue #2785 A6): the drain bound
        // expired with the worker still alive, so this thread was not
        // observed finished inside that bound. The guest child it started is
        // left for the outer process-containment owner to reconcile, and the
        // original unknown effect is retained instead of being reported as a
        // clean shutdown. The retained operation record is this process's
        // written handover to that owner: the loop ends with an explicit
        // unresolved result rather than an implicit stop.
        let contained = contained_failure(state, channel);
        // The bound that expired is this loop's own drain accounting, not the
        // worker's lifetime. The handle is still owned here, and no return
        // path may leave it unaccounted: a live `JoinHandle` dropped while the
        // thread still runs is precisely the untracked worker this issue
        // forbids, and a join with no bound of its own is precisely the hang.
        // The reap is therefore bounded by the same admitted window the drain
        // used and changes no verdict either way — whether the thread was
        // reaped inside that bound, or the bound expired first and the handle
        // was retained by the process-lifetime owner that outlives this loop,
        // the report below is the unresolved containment failure and the
        // process terminates through the outer process-containment owner. Only
        // the reaped/retained thread fact differs, and it is recorded on the
        // loop state rather than in the verdict.
        join_contained_worker(state, channel, &worker.outcomes, worker.handle);
        return failed_loop_report(state, contained);
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
        return failed_loop_report(state, error);
    }
    // Explicit termination accounting (#2785): a worker that never took
    // `Shutdown` or never joined left guest work untracked; that is a
    // failed loop, never a silent success.
    if !shutdown_sent {
        return failed_loop_report(
            state,
            LoopError::CommandChannelDisconnected {
                command: "shutdown",
            },
        );
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
        return failed_loop_report(state, error);
    }
    if !joined {
        return failed_loop_report(state, LoopError::ChannelUnavailable);
    }
    // A Shutdown ack that could not be staged fails the loop honestly: the
    // delivery stays unacknowledged and the owner must reconcile it, rather
    // than the child reporting success it cannot prove.
    if let Some(error) = confirm_error {
        return failed_loop_report(state, error);
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
        return failed_loop_report(
            state,
            LoopError::OperationContainmentUnresolved {
                operation_id: UNATTESTED_OPERATION,
            },
        );
    }
    // A loop that published a terminal always appended it to the retained
    // sequence first, so the served report names that terminal as its own
    // last event. The `None` arm keeps the exact refusal this loop has always
    // reported for a terminal it cannot name, rather than inventing a new one.
    match state.published() {
        Some(_) => RequestLoopReport::served(state.retained_sequence()),
        None => failed_loop_report(state, denied("no-request")),
    }
}

/// Requests the one tracked `Shutdown` and reports whether the command
/// channel actually accepted it, beside the acknowledgement that could not be
/// staged (issue #2785 I2/I5).
///
/// The slot is checked BEFORE the request is taken: requesting first would
/// occupy the slot and clobber an unsettled accepted command, so the
/// check-then-request order is what keeps the accepted-command accounting
/// exact. `send` refuses — rather than silently claiming delivery — if the
/// command channel does not take it, and that refusal stays an explicit
/// bounded residual rather than becoming accepted termination.
///
/// This is the loop's own termination protocol, so the request is never
/// owner-sourced: an owner `Shutdown` delivery is bound to this send by the
/// reader's retained slot, not by the command's name. That is what makes the
/// acknowledgement prove an enqueue for that exact delivery instead of merely
/// a demand that was recorded. With no retained delivery — the loop's own
/// termination, or an owner `Shutdown` never yielded — the confirmation is a
/// no-op, so no `enqueued` ack exists for a command the worker did not take
/// (issue #2896 W5/A2). An ack that cannot be staged is returned beside the
/// enqueue fact and fails the loop honestly once the worker is joined.
fn request_tracked_shutdown(
    state: &mut BoundedRequestLoop,
    channel: &mut dyn WasmHostRequestChannel,
    commands: &SyncSender<WorkerCommand>,
) -> (bool, Option<LoopError>) {
    let sent = if state.command_slot_free() {
        state.request(WorkerCommand::Shutdown, false);
        match state.send(WorkerCommand::Shutdown, commands) {
            Ok(()) => true,
            Err(error) => {
                state.record_residual(error);
                false
            }
        }
    } else {
        false
    };
    let confirm_error = if sent {
        channel.confirm_control_enqueued(OP_SHUTDOWN).err()
    } else {
        None
    };
    (sent, confirm_error)
}

/// Joins the worker the drain bound expired on, so no return path can drop a
/// live handle, and gives that join a bound so the containment hand-off itself
/// cannot become the hang (issue #2785 A6/I5).
///
/// `JoinHandle::drop` detaches, and a detached guest-executing thread is the
/// untracked worker the issue goal forbids: the guest child it started would
/// keep running with no owner, no outcome accounting and no join. The drain
/// bound that expired is this loop's own accounting — the worker was admitted
/// under the same grant wall deadline inside the P-03 child — so the handle is
/// joined here rather than abandoned, and the wait keeps consuming any late
/// bounded outcome so a producer is never left blocked on a full channel.
///
/// The wait is bounded, because the branch that reaches this function is
/// entered precisely when `handle.is_finished()` was just observed false: a
/// wait whose only exit is that predicate can never leave it, so the caller's
/// report would never be returned and the process would hang instead of
/// terminating through the outer process-containment owner. The bound is not a
/// new timeout. It is [`BoundedRequestLoop::drain_window`] — the admitted
/// grant wall deadline plus this file's control-poll cadence, the same window
/// [`drain_bound`] derives from the same owner (`material.ceilings`) the loop
/// already receives — anchored at the moment the reap starts. The drain's
/// absolute deadline cannot be reused here because it has already been spent
/// by the very expiry that selected this branch; re-spending that same
/// admitted ceiling from here is what keeps this the reap of a worker admitted
/// under that ceiling rather than an open-ended wait.
///
/// On expiry the handle is handed to the process-lifetime owner
/// [`RETAINED_CONTAINED_WORKERS`] rather than dropped, so the thread keeps a
/// named owner and stays knowable through
/// `JoinHandle::is_finished` instead of becoming a detached thread this
/// process can no longer see. Neither the loop state nor this function's own
/// scope can own it: the loop state is dropped when `run_request_loop`
/// returns, and a handle left in this frame would be dropped one line later,
/// which is the same detach with a shorter fuse. The process outlives both,
/// so the process is the owner — and the outer process-containment owner
/// remains the terminal termination for a thread still running when the
/// process ends, as an additional safety net this no longer depends on.
///
/// Retention never upgrades a verdict. `WorkerState::Contained` stays exactly
/// as [`contained_failure`] set it, the accepted command's outcome is still
/// owed rather than lost — so no `WorkerTerminatedWithoutOutcome` is invented
/// for a worker that has not exited, and no `Reaped` is claimed for a thread
/// that was not joined — and the unresolved operation/effect state stays in
/// the report the owner reads, so the loop ends in an explicit unresolved
/// result rather than a false clean drain.
///
/// This join proves thread termination only. It is deliberately NOT process
/// termination evidence: the caller keeps its unresolved containment report
/// whatever this returns, and the worker state reaches [`WorkerState::Reaped`]
/// only on the joined path, never [`WorkerState::Terminated`]. Child
/// termination is still read solely from the P-03 owner's evidence by the
/// caller, so a joined thread can never turn an unknown guest effect into a
/// no-effect claim or authorise reclaiming its recovery evidence (issue #2785
/// I6).
///
/// # Returns
///
/// Nothing directly, and deliberately so: this whole branch is already the
/// containment edge, and the caller holds its unresolved residual from
/// [`contained_failure`]. What the bounded wait changes is only whether the
/// thread is additionally joined — a thread fact that never changes the
/// verdict, exactly as the joined path below shows. The reaped/retained
/// distinction stays in [`BoundedRequestLoop::worker`]; the reported residual
/// stays the containment either way, so a reap that expired can never be
/// reported as joined and can never be reported as a clean drain.
fn join_contained_worker(
    state: &mut BoundedRequestLoop,
    channel: &mut dyn WasmHostRequestChannel,
    outcomes: &Receiver<WorkerOutcome>,
    handle: std::thread::JoinHandle<()>,
) {
    let reap_deadline = Instant::now() + state.drain_window;
    while !handle.is_finished() {
        match outcomes.recv_timeout(CONTROL_POLL) {
            Ok(outcome) => observe_residual_outcome(state, channel, outcome),
            Err(RecvTimeoutError::Timeout) => {}
            // The sender is gone, so no further outcome can arrive and every
            // receive would return at once. Yield rather than spin hot while
            // the thread finishes.
            Err(RecvTimeoutError::Disconnected) => std::thread::yield_now(),
        }
        // The reap bound is checked on the same cadence the wait itself runs
        // on, so an outcome that keeps arriving can never postpone the expiry
        // either. The deadline is read after the receive, never before it, so
        // the last admitted poll is always serviced.
        if Instant::now() >= reap_deadline {
            break;
        }
    }
    if handle.is_finished() {
        while let Ok(outcome) = outcomes.try_recv() {
            observe_residual_outcome(state, channel, outcome);
        }
        // A command this worker never acknowledged has no outcome and will
        // never get one now that the thread is gone. The loss is recorded
        // beside the containment failure rather than replacing it: the
        // unresolved disposition is the containment, and this only says the
        // reply is owed to no one.
        if let Some(delivery) = state.delivery {
            let command = match delivery {
                CommandDelivery::Requested { command, .. }
                | CommandDelivery::Accepted { command, .. } => command,
            };
            state.record_residual(LoopError::WorkerTerminatedWithoutOutcome {
                command: command_name(command),
            });
        }
        // The thread is reaped, so the worker state is a real observation
        // rather than the containment placeholder. It never reaches
        // `Terminated` here: that state is reserved for the ordinary path
        // where the tracked `Shutdown` reply was observed first. A panic
        // inside the worker is the thread's own fact and changes no verdict
        // either — the unresolved report already recorded above stands.
        state.worker = WorkerState::Reaped;
        if handle.join().is_err() {
            state.record_residual(denied("worker-panicked"));
        }
    } else {
        // The reap bound expired with the thread still running. This is the
        // only return path that does not join, and it is precisely the path
        // that must not let the handle fall out of scope: `JoinHandle::drop`
        // detaches, so dropping it here is what turned this worker into the
        // untracked live thread the file's own invariant at
        // `drain_and_shutdown_request_worker` forbids. The handle is therefore
        // moved to the process-lifetime owner, which outlives both this frame
        // and the loop state `run_request_loop` is about to drop.
        //
        // Nothing on this path claims the thread ended: `WorkerState::Contained`
        // stays exactly as `contained_failure` set it, and the accepted
        // command's outcome is still owed rather than lost — so no
        // `WorkerTerminatedWithoutOutcome` is invented for a worker that has
        // not exited, and no `Reaped` is claimed for a thread that was not
        // joined. The caller's containment residual, which names the command
        // still executing inside the worker, is unchanged: this is the result
        // this process hands to the outer process-containment owner.
        // `is_finished` is re-read rather than remembered, so a thread that
        // finished inside the last admitted poll is still joined above instead
        // of being retained.
        retain_contained_worker(handle);
    }
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
        if let Err(error) = channel.confirm_control_completed(OP_SHUTDOWN, None)
            && confirm_error.is_none()
        {
            *confirm_error = Some(error);
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
    let Some(frame) = channel.poll_control()? else {
        return Ok(ExternalIntake::None);
    };
    if let Err(error) = state.admit(&frame, true) {
        let detail = error.code();
        state.denial = Some(error);
        channel.refuse_control(detail);
        return Err(error);
    }
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

/// Acknowledges the enqueue of the command the worker channel just took, but
/// only when that command came from an owner-staged control delivery.
///
/// This is the single place the enqueue acknowledgement is written from a
/// send site, and it is reached only after [`BoundedRequestLoop::send`]
/// returned `Ok`. A command the loop derived for itself — `Execute` from the
/// delivery set, a containment/reconciliation follow-up — carries no owner
/// delivery, so it confirms nothing: no `enqueued` ack can ever exist for a
/// delivery the worker never received (issue #2896 W5/A2).
///
/// # Errors
///
/// Returns [`LoopError::ChannelUnavailable`] when the acknowledgement cannot
/// be staged. The command is already in the worker at that point, so the
/// failure fails the loop honestly instead of reporting an unproven enqueue.
fn confirm_owner_enqueue(
    state: &BoundedRequestLoop,
    channel: &mut dyn WasmHostRequestChannel,
) -> Result<(), LoopError> {
    if !state.accepted_owner_delivery() {
        return Ok(());
    }
    let Some(command) = state.accepted_command() else {
        return Ok(());
    };
    channel.confirm_control_enqueued(command_operation(command))
}

/// Whether the staged frame needs the single command slot to be admitted.
/// `Shutdown` never does: it only closes `Execute` admission and records
/// its demand. Anything unparseable is refused by admission, which likewise
/// needs no slot.
fn frame_needs_command_slot(frame: &WasmHostRequestFrame) -> bool {
    matches!(
        WasmHostRequestFrame::parse(frame),
        Ok(WasmHostRequest::Invoke(_) | WasmHostRequest::Cancel(_) | WasmHostRequest::Reconcile(_))
    )
}

/// Services the owner-staged control lane exactly once, through the same
/// admission path internal control uses (issue #2785 I3/P1).
///
/// It keeps running after `Execute` admission closed: closing admission
/// stops new execution, never the reply and control servicing needed to
/// terminate the already-owned worker. A staged delivery is acknowledged
/// only after the command channel accepted the frame's command, so the
/// delivery edge never acknowledges a request that was not delivered. A
/// frame that needs the command slot while a command is accepted is
/// deferred — released back to staged for a later tick — so the accepted
/// command's accounting is never clobbered by a second request (issue #2785
/// I1/W2). That deferral is temporary slot pressure, not a refusal: nothing
/// is dispositioned and the delivery stays replayable.
///
/// An owner `Shutdown` is admitted here but never acknowledged here: it
/// needs no command slot, so recording its demand is all this step can do,
/// and the command that proves the delivery reached the worker is only sent
/// by the tracked drain. The delivery therefore stays staged and
/// replayable, and the drain's `confirm_control_enqueued(OP_SHUTDOWN)` after
/// that real enqueue is what writes the `enqueued` ack — a demand recorded
/// is not a command the worker took (issue #2896 W5/A2).
fn service_control_lane(
    state: &mut BoundedRequestLoop,
    channel: &mut dyn WasmHostRequestChannel,
    commands: &SyncSender<WorkerCommand>,
) -> Result<(), LoopError> {
    let Some(frame) = channel.poll_control()? else {
        return Ok(());
    };
    if !state.command_slot_free() && frame_needs_command_slot(&frame) {
        channel.release_control();
        return Ok(());
    }
    match state.admit(&frame, true) {
        Err(error) => {
            // The frame never reached the loop's own binding, so the
            // admitted operation itself is not refused by it. The exact
            // refusal is recorded as the loop's residual and the delivery is
            // dispositioned as refused, which is what it is: nothing was
            // handed to the worker, so the `enqueued` ack must not be
            // written for it (issue #2896 W5).
            let detail = error.code();
            state.record_residual(error);
            channel.refuse_control(detail);
        }
        // Enqueued: the command channel took the command, so the delivery is
        // acknowledged and the follow-up accounting advanced. The
        // acknowledgement is written only here, immediately after that real
        // `send`, and only for the delivery this very frame produced. No
        // requested command is an owner `Shutdown`: admission is closed and
        // the loop's own tracked termination step owns stopping the worker,
        // which is the step that confirms the retained Shutdown delivery.
        Ok(()) => {
            if let Some(command) = state.requested_command() {
                state.send(command, commands)?;
                confirm_owner_enqueue(state, channel)?;
            }
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
/// is admitted (it needs no slot) and a Cancel only sets cancel demand, so
/// the control commands themselves are admitted, sent and acknowledged by
/// the control lane once the slot frees — no second command stacks behind
/// the accepted one (issue #2785 W2) and no delivery is acknowledged for a
/// step that never ran (P1). Neither arms acknowledges: the staged delivery
/// is still an unproven enqueue, and a control that failed its own binding
/// check is dispositioned as refused instead (issue #2896 W5/A2).
fn admit_external_control_urgent(
    state: &mut BoundedRequestLoop,
    channel: &mut dyn WasmHostRequestChannel,
) {
    let Ok(Some(frame)) = channel.poll_control_urgent() else {
        return;
    };
    match WasmHostRequestFrame::parse(&frame) {
        Ok(WasmHostRequest::Shutdown) => {
            if let Err(error) = state.admit(&frame, false) {
                let detail = error.code();
                state.record_residual(error);
                channel.refuse_control(detail);
            }
        }
        Ok(WasmHostRequest::Cancel(control)) => match check_control(&state.binding, &control) {
            Ok(()) => state.admission.cancel_demanded = true,
            Err(error) => {
                let detail = error.code();
                state.record_residual(error);
                channel.refuse_control(detail);
            }
        },
        // Reconcile, Invoke and unparseable bytes never surface here: the
        // urgent poll admits only Cancel/Shutdown, so there is nothing to
        // demand and nothing staged is claimed.
        Ok(_) | Err(_) => {}
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
                confirm_owner_enqueue(state, channel)?;
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
            // without executing again, through the one owner that also emits
            // a freshly observed event. The terminal projection is the last
            // retained event. The retained sequence is consumed here, so it
            // proves its stream shape first: a corrupted retained sequence
            // fails closed instead of republishing.
            //
            // This is the one state in which "published but not durable" was
            // reachable, so it is gated on the same claim-bound retention
            // every other emission path has (`publish_lost_response`,
            // `consume_worker_outcome`, `observe_residual_outcome`): the
            // sequence is retained durably, through the existing result owner
            // and behind the same real validators, before any of it reaches
            // the new transport. A retention refusal publishes nothing and
            // leaves the claim uncertain — the bytes are already durable, so
            // nothing is lost, and the guest is not re-executed.
            state.retain_observed()?;
            state.published = Some(channel.publish_retained_sequence(&replay)?);
            state.close_admission();
            break;
        }
        if let Some(command) = state.requested_command() {
            // Delivery-set demand carries no owner delivery, so the enqueue
            // confirmation is a no-op by construction; kept so every send
            // site runs the same one check.
            state.send(command, commands)?;
            confirm_owner_enqueue(state, channel)?;
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
            service_control_lane(state, channel, commands)?;
            // Interrupt, don't queue (#2568 A3): a staged Cancel or Shutdown
            // terminates accepted guest work through the stored engine
            // handle instead of waiting for the reply. Firing never sends,
            // so the bound-1 slot stays single-owner and the uncertain
            // attempt still settles through the follow-up taxonomy once its
            // own reply is observed.
            admit_external_control_urgent(state, channel);
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
    // Whether the command now being settled came from an owner delivery. Read
    // before the accepted slot is retired, because only an owner-sourced
    // command may be completed against one (issue #2896 A2/A3).
    let owner = state.accepted_owner_delivery();
    // The command's coordination facts (#2787 S3.5/S6.2), read from the
    // accepted slot while it still holds that command and before the slot is
    // retired below. An owner-sourced command names the exact delivery the
    // channel reader holds for it, with the acknowledgement phase the reader
    // itself recorded. A command from no owner delivery names the handover it
    // really had and acknowledges no delivery.
    let identity = state.accepted_command_sequence().map(|token| {
        let delivery = channel.accepted_control_delivery(command_operation(command));
        (token, delivery)
    });
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
    let frame = state.on_outcome(outcome, identity);
    // Preserve any Requested(Cancel/Reconcile) created by on_outcome: the
    // slot now holds that successor, never the command just settled.
    if let Some(frame) = frame.as_ref() {
        // Order of the four states, and the reason for it (#2787 audit
        // defect 3): the outcome is observed, then that exact observation is
        // proved by the real validators and retained through the claim-bound
        // result owner, then the local stdout write happens, and the owner
        // acknowledgement follows what the worker actually did. Retention
        // comes first because a stdout write that succeeds and a later
        // cleanup that fails must still leave the observed result on disk;
        // where it cannot, the claim stays uncertain and the guest is never
        // re-executed. A frame that fails its own validation is never
        // written to the record at all.
        state.retain_observed()?;
        // The exact outcome is observed here: complete the accepted
        // control before publishing, so the ack is durable ahead of
        // the best-effort emission the drain may still record.
        let digest = serde_json::to_vec(frame)
            .ok()
            .map(|bytes| sha256_hex(&bytes));
        if owner {
            channel.confirm_control_completed(command_operation(command), digest.as_deref())?;
        }
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
        confirm_owner_enqueue(state, channel)?;
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
            // A retried external send confirms its still-pending delivery;
            // internal follow-ups confirm nothing.
            if let Err(error) = confirm_owner_enqueue(state, channel) {
                state.record_residual(error);
                return;
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
    // The command's coordination facts (#2787 S3.5/S6.2), read from the
    // accepted slot while it still holds that command. The phase is whatever
    // the channel reader itself recorded; this supervisor completes no owner
    // delivery — it owns no command sender, so it stages no `completed` ack —
    // and therefore never claims one.
    let identity = state.accepted_command_sequence().map(|token| {
        let delivery = channel.accepted_control_delivery(command_operation(outcome.command));
        (token, delivery)
    });
    // The preceding equality check must remain before this mutation.
    state.delivery = None;
    let frame = state.on_outcome(outcome, identity);
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
    // This path projects a REAL result event — an observed guest outcome —
    // and therefore owes it the same four separate states every other
    // publication owes, in the same order (#2787 audit defect 3): the outcome
    // is observed above, that exact observation (or bounded prefix) is
    // retained through the existing claim-bound result owner HERE, the local
    // stdout write happens only after that, and the owner acknowledgement
    // and the permission to reclaim stay with their own later states. The
    // retention is the gate, not a prelude: a persistence failure keeps the
    // original claim uncertain, records the failure as this loop's bounded
    // residual, preserves the observed bytes in the retained sequence for
    // the bounded recovery handoff, and publishes nothing — never a safe
    // refusal of the operation and never a re-execution of the guest.
    if let Some(frame) = &frame {
        if let Err(error) = state.retain_observed() {
            state.record_residual(error);
            return;
        }
        // A publication failure is recorded against the observation that
        // lost its delivery; the exact stream fault is the loop's channel
        // fault, and what matters here is which observation never reached
        // the owner. The observation is already durable, so this is a
        // delivery residual and never a loss of the observed bytes.
        if channel.publish(frame).is_err() {
            state.record_residual(LoopError::ResultPublicationFailed {
                observation: observed_command_name(frame),
            });
        }
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
    // Only a fresh or an idempotent re-drive claim executes: a retained
    // result, a foreign first writer, or unknowable slot state all fail
    // closed with the staged set left for the owner (issue #2786 AUD3).
    match crate::dispatch_material::write_inflight_marker(directory, claim.identity(), now_ms) {
        crate::dispatch_material::InFlightClaimOutcome::Acquired
        | crate::dispatch_material::InFlightClaimOutcome::ExistingInFlight => Ok(()),
        _ => {
            let identity = claim.identity();
            Err(OrdinaryDriveError::DeliveryInProgress {
                operation_id: identity.operation_id.clone(),
                generation: identity.generation,
                claim_id: identity.claim_id.clone(),
            })
        }
    }
}

/// Seals the durable served evidence for one terminal outcome (#2786 step
/// 7): the served marker first, then the exact retained result-event
/// sequence, both before physical reclaim.
///
/// This is a finalization, not a first write, and that is now structural
/// rather than incidental: every observed event is written through the same
/// claim-bound result owner BEFORE it can be exposed on stdout, and both
/// publication gates refuse to emit when that write did not land — the drain
/// path in [`consume_worker_outcome`] and the shutdown-supervisor path in
/// [`observe_residual_outcome`] and [`BoundedRequestLoop::publish_lost_response`].
/// A stream that reaches this function has therefore already been persisted,
/// and the write below re-affirms that exact sequence under the served
/// marker; it never records a guest result for the first time. The sequence
/// must be a closed, valid stream first: sealing a prefix would advertise as
/// complete a record whose predecessors were never retained. The
/// pre-execution `InFlight` marker is already durable, so a failed seal
/// still replays on restart instead of re-executing. Any failure preserves
/// the claimed set and reports its original identity as unresolved instead
/// of claiming success.
fn seal_served_outcome(
    directory: &std::path::Path,
    claim: &crate::dispatch_material::DeliveryClaim,
    events: &[OrdinaryOutcome],
    now_ms: u64,
) -> Result<(), OrdinaryDriveError> {
    validate_result_stream(events).map_err(OrdinaryDriveError::Loop)?;
    let stream = build_retained_result_stream(events).map_err(OrdinaryDriveError::Loop)?;
    if crate::dispatch_material::write_served_marker(directory, claim.identity(), now_ms).is_err() {
        let identity = claim.identity();
        return Err(OrdinaryDriveError::DeliveryInProgress {
            operation_id: identity.operation_id.clone(),
            generation: identity.generation,
            claim_id: identity.claim_id.clone(),
        });
    }
    if crate::dispatch_material::write_served_result(
        directory,
        claim.identity(),
        crate::dispatch_material::ServedResultPayload::Stream(stream),
        now_ms,
    )
    .is_err()
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

/// Republishes one complete retained result-event sequence on this process's
/// new transport, through the ordinary result owner's own serializer,
/// validator and emitter (#2787 audit defect 1).
///
/// The owner here is [`DeliverySetChannel::replay_only`], so this path admits
/// no request, issues no permit, spawns no guest worker, and deletes no staged
/// evidence: it is the original sequence, in order, emitted by the same owner
/// that emits a freshly observed event.
///
/// Tracked termination of that emission runs on BOTH edges. A publication
/// failure can leave a still blocked writer in `pending_helper` — a bounded
/// caller timeout is a timeout, never bounded termination of the writer — so
/// the failure edge runs the same tracked cleanup the success edge does instead
/// of returning into the drop, which would discard a live helper handle and
/// report a clean stop. A contained helper is reported to the process owner and
/// outranks the publication error it arrived with, exactly as the ordinary
/// terminal edge does.
fn republish_retained_sequence(
    events: &[WasmHostResultFrame],
) -> Result<OrdinaryOutcome, OrdinaryDriveError> {
    let mut replay_owner = DeliverySetChannel::replay_only();
    let terminal = replay_owner.publish_retained_sequence(events);
    let containment = replay_owner.cleanup_output_helper();
    match (terminal, containment) {
        (Ok(terminal), Ok(())) => Ok(terminal),
        (Ok(_) | Err(_), Err(error)) | (Err(error), Ok(())) => Err(OrdinaryDriveError::Loop(error)),
    }
}

/// Hands the exact retained sequence to the claim-bound result owner one
/// last time on the failure edge (#2787 audit defect 3).
///
/// The report's retained sequence is the only remaining copy of a guest
/// observation once the loop has failed, and the loop's own in-memory state
/// dies with it. Offering those exact bytes to the SAME owner the loop writes
/// through is what keeps a transient retention failure from silently
/// discarding the only copy, and it is a bounded finalization of
/// already-observed bytes — not a second write scheme, not a first write, and
/// not a new acknowledgement. Whether it lands changes nothing else: the
/// claim stays uncertain, nothing is reclaimed, the original failure is still
/// what the caller is told, and the guest is never re-executed.
///
/// The handoff is gated by the same real validators the live path uses, so
/// "every retained observation is proved before it is written" is a property
/// of the write, not an induction over which path happened to observe an event
/// first. These bytes were already proved on their own turns, so the gate is
/// redundant here today; it is kept because a write that can reach the durable
/// record without passing the validators is exactly what this audit removed
/// from the live path.
fn hand_off_observed_sequence(
    directory: &std::path::Path,
    claim: &crate::dispatch_material::DeliveryClaim,
    events: &[OrdinaryOutcome],
) {
    let handoff = ObservedResultRetention::new(directory, claim);
    // A sequence with no closing event is an explicit bounded prefix, and a
    // prefix is what the failure edge legitimately carries, so only a complete
    // sequence is held to the stream rule here — the same distinction
    // `BoundedRequestLoop::retain_observed` makes.
    if let Some(latest) = events.last()
        && validate_frame(latest).is_ok()
        && (!latest.terminal || validate_result_stream(events).is_ok())
    {
        let _handoff_retained = handoff.retain(events);
    }
}

/// Typed readback of the durable result record for exactly one staged replay
/// identity (#2787 audit defect 4).
///
/// Every outcome keeps its own state instead of collapsing into "no record",
/// because they are not the same fact: an absent record says nothing, a
/// foreign or self-contradicting one is a conflict, and a bounded prefix with
/// no closing event is a real observation whose missing events are simply not
/// known. Only a complete, validated sequence is eligible for complete replay.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ServedResultReadback {
    /// A complete result-event sequence for exactly this identity, every
    /// event validated over the original recorded value.
    Complete {
        /// The exact recorded events, in recorded order.
        events: Vec<OrdinaryOutcome>,
    },
    /// The record names this identity but retains only a bounded prefix of
    /// the stream: the events it never stored are not synthesized here, so
    /// this is never a complete replay.
    Incomplete,
    /// The record contradicts the staged identity or itself, including a
    /// record file that exists but cannot be a well-formed record at all
    /// (absent, empty or dual payloads, an unusable `stream_digest`, or a
    /// `terminal_sequence` naming an event the record never stored).
    Conflict,
    /// No usable retained result: absent, unreadable, or oversize. Only these
    /// three states, because a present-but-unusable record is the conflict
    /// above and never an absence.
    Unavailable,
}

/// Reads back the durably retained result for exactly the staged replay
/// identity and classifies it (#2786 step 7, #2787 audit defect 4).
///
/// Validation runs the REAL validators over the ORIGINAL recorded values:
/// each event is decoded and then proved to re-encode to exactly the bytes
/// that were stored, and the stream is then checked with
/// [`validate_result_stream`]. A recomputed substitute is never validated in
/// place of what is on disk. Never executes, never deletes.
fn read_back_served_result(
    directory: &std::path::Path,
    identity: &crate::dispatch_material::StagedDeliveryIdentity,
) -> ServedResultReadback {
    // An absent record, and one that could not be read or is oversize, all
    // answer the same typed state: this identity has no usable retained
    // result. `MaterialError::Malformed` is NOT that state and is not folded
    // into it here. The reader already proved a record file EXISTS at this
    // path; malformed therefore never means absence, it means the bytes there
    // contradict a record this host itself defines — a `ServedResultRecord`
    // that is not valid JSON, that cannot name an identity, that carries
    // zero or both result payloads, whose `stream_digest` is not a hex
    // digest, or whose `terminal_sequence` names an event it never stored.
    // Each is a self-contradicting record and is reported as the conflict it
    // is, with the distinction made here on this side of the reader rather
    // than by editing it. Genuinely unreadable and oversize records keep
    // their own error variants and stay `Unavailable`, so no check is
    // weakened and no absent record is ever reported as a conflict.
    let record = match crate::dispatch_material::read_served_result(directory) {
        Ok(Some(record)) => record,
        Ok(None) => return ServedResultReadback::Unavailable,
        Err(crate::dispatch_material::MaterialError::Malformed) => {
            return ServedResultReadback::Conflict;
        }
        Err(_unreadable_or_oversize) => return ServedResultReadback::Unavailable,
    };
    if !record.names(identity) {
        return ServedResultReadback::Conflict;
    }
    let crate::dispatch_material::ServedResultRecord { frame, stream, .. } = record;
    match stream {
        // The legacy terminal-only payload is reconstructed into the very
        // payload type a writer names, from the value this read already owns,
        // so the v1 case is a shape the classifier really sees rather than a
        // branch that can never be reached. Nothing is copied to do it, and
        // the reader has already proved exactly one payload is present.
        None => match frame {
            Some(frame) => read_back_terminal_only_record(
                crate::dispatch_material::ServedResultPayload::TerminalFrame { frame },
                identity,
            ),
            None => ServedResultReadback::Unavailable,
        },
        Some(stream) => read_back_retained_result_stream(&stream, identity),
    }
}

/// Classifies the #2786 v1 payload, which retained the terminal frame alone.
///
/// It is a complete single-event stream only when that frame is genuinely the
/// whole stream: the first event, naming no predecessors. A terminal that
/// names predecessors was never retained together with them, so the record
/// stays explicitly incomplete and those events are never synthesized.
///
/// [`validate_frame`] is deliberately not enough to answer this. It checks
/// wire identity/version, sequence bound, the ordered predecessor prefix,
/// phase/command agreement, output and engine bindings and the closed
/// vocabularies — but it does NOT read `terminal`: the requirement that a
/// complete stream carries exactly one closing event lives only in
/// [`validate_result_stream`]. So the decision is taken with the REAL stream
/// validator, the same one the v2 arm runs and the same one
/// `publish_retained_sequence` runs before republishing, over the single
/// recorded event. A record that is genuinely complete still answers
/// `Complete`; a record whose event set is not a closed stream is typed
/// honestly here instead of surfacing later as a generic loop error.
fn read_back_terminal_only_record(
    payload: crate::dispatch_material::ServedResultPayload,
    identity: &crate::dispatch_material::StagedDeliveryIdentity,
) -> ServedResultReadback {
    // A record without a stream cannot present any other payload shape, so
    // this arm is unreachable; a mismatched shape is reported as the
    // contradiction it is rather than being read as a terminal frame.
    let crate::dispatch_material::ServedResultPayload::TerminalFrame { frame: recorded } = payload
    else {
        return ServedResultReadback::Conflict;
    };
    let Ok(frame) = decode_recorded_frame(&recorded) else {
        return ServedResultReadback::Conflict;
    };
    if !frame_binds_to_identity(&frame, identity) || validate_frame(&frame).is_err() {
        return ServedResultReadback::Conflict;
    }
    if frame.sequence != 0 || !frame.observation_predecessors.is_empty() {
        return ServedResultReadback::Incomplete;
    }
    // One real event is the whole stream the record retained, and the real
    // stream validator decides what that one event MEANS: it is the only rule
    // that reads `terminal`. The single-event sequence is borrowed exactly as
    // the v2 arm borrows its recorded sequence, never rebuilt, so the recorded
    // value is the one that is judged.
    let events = std::slice::from_ref(&frame);
    if validate_result_stream(events).is_ok() {
        return ServedResultReadback::Complete {
            events: vec![frame],
        };
    }
    // A single event that is not a closing event — for example a non-terminal
    // v1 frame — names this identity and is a real retained observation, but
    // the events that would have followed it were never stored. That is
    // exactly the `Incomplete` case: a bounded prefix whose missing events are
    // not synthesized here, and never a complete replay.
    ServedResultReadback::Incomplete
}

/// Classifies the #2787 v2 payload, the exact retained result-event sequence.
///
/// The commitment is recomputed from the ORIGINAL recorded values, every
/// event proves itself through the real per-frame validator, and only then
/// does the real stream validator decide whether the whole sequence is a
/// closed, gapless stream for this one identity.
fn read_back_retained_result_stream(
    stream: &crate::dispatch_material::RetainedResultStream,
    identity: &crate::dispatch_material::StagedDeliveryIdentity,
) -> ServedResultReadback {
    match retained_stream_digest(&stream.events) {
        Ok(digest) if digest == stream.stream_digest => {}
        Ok(_) | Err(_) => return ServedResultReadback::Conflict,
    }
    let mut events: Vec<OrdinaryOutcome> = Vec::with_capacity(stream.events.len());
    for recorded in &stream.events {
        let Ok(frame) = decode_recorded_frame(recorded) else {
            return ServedResultReadback::Conflict;
        };
        if !frame_binds_to_identity(&frame, identity) || validate_frame(&frame).is_err() {
            return ServedResultReadback::Conflict;
        }
        events.push(frame);
    }
    // Every retained event is a real, valid observation of this operation,
    // but no event closed the stream. That is an explicit incomplete prefix,
    // not a conflict and not an absence: the closing event and anything after
    // it were never retained and are never invented here.
    if stream.terminal_sequence.is_none() {
        return ServedResultReadback::Incomplete;
    }
    // A recorded terminal that is not the closing event, or is not present in
    // the record's own events, contradicts the record itself.
    match (
        events.last().filter(|event| event.terminal),
        stream.terminal_sequence,
    ) {
        (Some(closed), Some(recorded)) if closed.sequence == recorded => {}
        _ => return ServedResultReadback::Conflict,
    }
    if validate_result_stream(&events).is_err() {
        return ServedResultReadback::Conflict;
    }
    ServedResultReadback::Complete { events }
}

/// Decodes one recorded result event and proves it is the ORIGINAL recorded
/// value: the decoded frame must re-encode to exactly those bytes.
///
/// Without this, a record that needed a defaulted, dropped, or substituted
/// field to decode would be validated as if it were the value that was
/// stored.
fn decode_recorded_frame(recorded: &serde_json::Value) -> Result<OrdinaryOutcome, LoopError> {
    let frame: OrdinaryOutcome =
        serde_json::from_value(recorded.clone()).map_err(|_| invalid("result-frame"))?;
    if serde_json::to_value(&frame).map_err(|_| invalid("result-frame"))? != *recorded {
        return Err(invalid("result-frame"));
    }
    Ok(frame)
}

/// Whether one recorded event binds back to the exact staged replay identity:
/// the same operation, claim, grant, artifact, and input the owner staged. A
/// recorded event naming another identity is never republished under this one.
fn frame_binds_to_identity(
    frame: &OrdinaryOutcome,
    identity: &crate::dispatch_material::StagedDeliveryIdentity,
) -> bool {
    frame.operation_id == identity.operation_id
        && frame.claim_id == identity.claim_id
        && frame.grant_digest == identity.grant_digest
        && frame.artifact_digest == identity.artifact_digest
        && frame.input_digest == identity.input_digest
}

/// Seals one served loop report and reclaims exactly the claimed generation
/// (issue #2786 W6): the served marker and the exact retained sequence seal
/// durably before physical reclaim, and the pre-execution `InFlight`
/// evidence drops best-effort after. Returns the claimed identity and the
/// terminal frame the report carried.
fn seal_and_reclaim_served(
    directory: &std::path::Path,
    claim: crate::dispatch_material::DeliveryClaim,
    report: &RequestLoopReport,
) -> Result<
    (
        crate::dispatch_material::StagedDeliveryIdentity,
        OrdinaryOutcome,
    ),
    OrdinaryDriveError,
> {
    // The served terminal is the last event of the sequence this
    // same report carries, so the frame sealed below and the frame
    // returned below cannot be a different observation. A served
    // report without one is the exact refusal the loop has always
    // reported for a terminal it cannot name.
    let Some(terminal) = report.served_terminal() else {
        return Err(OrdinaryDriveError::Loop(denied("no-request")));
    };
    // Containment evidence is the loop's own terminal condition:
    // it only reports served once the operation's effect is
    // attested as settled, so reclaiming here never races an
    // unresolved guest child.
    //
    // The served marker and the exact retained sequence seal
    // durably before physical reclaim, so restart reconciles
    // terminal-unacknowledged state by republishing the original
    // sequence instead of re-executing.
    seal_served_outcome(directory, &claim, report.retained(), edge_now_ms())?;
    let reclamation = consume_delivery_set(&claim);
    // The served marker is now durable, so the pre-execution
    // InFlight evidence is redundant: drop it best-effort. A
    // leftover only replays, never re-executes.
    let _ = crate::dispatch_material::clear_inflight_marker(directory, claim.identity());
    // Bounded residual only: a partial reclamation never
    // overwrites the primary result; retained files stay for
    // maintenance under the exact claimed identity.
    let _residual_complete = match &reclamation {
        crate::dispatch_material::ClaimedReclamation::Reclaimed(detail) => {
            let _reclaimed_operation = detail.identity.operation_id.len();
            detail.fully_reclaimed()
        }
        crate::dispatch_material::ClaimedReclamation::ReplacementPreserved { claimed }
        | crate::dispatch_material::ClaimedReclamation::AlreadyGone { claimed }
        | crate::dispatch_material::ClaimedReclamation::RetainedForRecovery { claimed } => {
            let _preserved_operation = claimed.operation_id.len();
            false
        }
    };
    Ok((claim.into_identity(), terminal.clone()))
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
                // in-process outcome) returns the original retained result
                // for exactly this identity when one is durably retained,
                // before any evidence is touched — the replay path deletes
                // nothing. A retained stream that is complete, and that the
                // real per-frame and stream validators accepted over the
                // recorded values themselves, is republished through the
                // ordinary result owner's own serializer and emitter: the
                // original events, in order, on this process's new
                // transport. That path admits no request, issues no permit,
                // spawns no worker, and touches no staged evidence.
                // Anything else — absent, unreadable, foreign, malformed, or
                // a prefix whose missing events are not known — falls
                // through to the identity-only in-progress report below;
                // same-drive replays keep the in-process projection, never a
                // file read-back.
                if outcome.is_none()
                    && let ServedResultReadback::Complete { events } =
                        read_back_served_result(&directory, &identity)
                {
                    return republish_retained_sequence(&events);
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
                // A legacy pass needs both no owner slot record for this
                // claim and no durable markers at all (issue #2786 A7): a
                // slot-recorded set is new-format (the slot gate below
                // decides), and a slot-less set on a directory whose markers
                // prove versioned sets ran here is stale — it stays for the
                // owner instead of resurrecting as legacy.
                let slot_recorded =
                    crate::dispatch_material::read_delivery_publication(&directory, &identity)
                        .map_err(|error| OrdinaryDriveError::Drive(DriveError::Material(error)))?
                        .is_some();
                if !slot_recorded && crate::dispatch_material::versioned_markers_present(&directory)
                {
                    return Err(OrdinaryDriveError::DeliveryInProgress {
                        operation_id: identity.operation_id,
                        generation: identity.generation,
                        claim_id: identity.claim_id,
                    });
                }
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
        // The claim-bound result owner is threaded into the loop itself, so
        // each observed event is durable before it can be exposed and the
        // whole observed sequence comes back with the loop's disposition. The
        // sequence is borrowed from that report for the whole arm below, so
        // the drive never seals or returns a copy that could differ from the
        // one the loop actually observed.
        let report = run_request_loop(
            runtime,
            &material,
            ObservedResultRetention::new(&directory, &claim),
        );
        // The delivery set is one-shot: a published terminal outcome reclaims
        // exactly the claimed generation, so a leftover is a fresh-drive
        // signal rather than a silent reuse. Unknown execution, failed
        // publication, lost response, or failed drain retains the exact
        // operation/generation evidence for recovery and never reclaims. The
        // in-memory retention of the sequence below is the readback path,
        // not a second execution.
        match report.completion() {
            LoopCompletion::Served => {
                let (identity, terminal) = seal_and_reclaim_served(&directory, claim, &report)?;
                served.push(identity);
                outcome = Some(terminal);
            }
            LoopCompletion::Failed { failure } => {
                // Nothing about the observation is lost here and nothing is
                // reclaimed: every event this loop observed is already
                // durable through the claim-bound owner, written before it
                // could be exposed, so restart replays the exact retained
                // sequence under the still-live InFlight marker instead of
                // re-executing the guest. The failure is reported as itself,
                // never as a safe refusal of the operation.
                hand_off_observed_sequence(&directory, &claim, report.retained());
                return Err(OrdinaryDriveError::Loop(*failure));
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
    // republished that original sequence from the replay arm above; only a
    // replay whose retained record is absent, incomplete, or conflicting
    // reports in-progress with its exact identity.
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
/// fixed-name compatibility state — but only when the directory carries no
/// durable markers: beside markers that prove versioned sets ran here the
/// unrecorded set is refused explicitly instead of admitted as legacy.
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
        // No owner record is legacy compatibility only when the directory
        // carries no durable markers at all; a slot-less set beside markers
        // that prove versioned sets ran here is a torn publication that
        // stays for the owner under an explicit migration refusal (issue
        // #2786 W7).
        None => {
            if crate::dispatch_material::versioned_markers_present(directory) {
                return Err(OrdinaryDriveError::Publication {
                    code: "DELIVERY_SLOT_UNRECORDED",
                });
            }
            Ok(())
        }
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

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod spool_tests {
    use super::*;
    use crate::dispatch_material::{
        ControlDeliveryIdentity, WASM_CONTROL_DELIVERY_WIRE_ID, WASM_CONTROL_DELIVERY_WIRE_VERSION,
    };
    use eliot_contracts::{EpochId, EpochLineageId, ResourceGeneration, StateFence};
    use std::num::NonZeroU64;

    const TEST_LINEAGE: &str = "550e8400-e29b-41d4-a716-446655440000";

    fn test_epoch() -> EpochId {
        EpochId::new(
            EpochLineageId::new(TEST_LINEAGE).expect("valid test lineage"),
            NonZeroU64::new(3).expect("nonzero test sequence"),
        )
        .expect("valid test epoch")
    }

    fn test_fence() -> StateFence {
        StateFence::new(
            test_epoch(),
            ResourceGeneration::new(7).expect("nonzero test generation"),
        )
    }

    fn test_binding(generation: u64) -> AdmittedBinding {
        AdmittedBinding {
            claim_id: "claim-2896".to_owned(),
            operation_id: "operation-2896".to_owned(),
            invocation_id: "operation-2896".to_owned(),
            request_digest: "d".repeat(64),
            grant_digest: "9".repeat(64),
            generation,
            work_scope: "scope-2896".to_owned(),
            authority_epoch_json: "{}".to_owned(),
            component_id: "component-2896".to_owned(),
            artifact_digest: "a".repeat(64),
            input_digest: "i".repeat(64),
            input_bytes: Vec::new(),
            fence_nonce: "fence-2896".to_owned(),
            deterministic_seed: 7,
            max_output_bytes: 1024,
        }
    }

    fn test_delivery(generation: u64, sequence: u64) -> WasmControlDelivery {
        WasmControlDelivery {
            wire_id: WASM_CONTROL_DELIVERY_WIRE_ID.to_owned(),
            wire_version: WASM_CONTROL_DELIVERY_WIRE_VERSION,
            identity: ControlDeliveryIdentity {
                operation_id: "operation-2896".to_owned(),
                invocation_id: "operation-2896".to_owned(),
                claim_id: "claim-2896".to_owned(),
                generation,
                control_kind: WasmControlKind::Reconcile,
                owner_sequence: sequence,
                authority_epoch: test_epoch(),
                state_fence: test_fence(),
                work_scope: "scope-2896".to_owned(),
                principal_digest: "b".repeat(64),
                session_connection: "conn-2896".to_owned(),
                session_epoch: 1,
                dispatch_grant_digest: "c".repeat(64),
                publisher_challenge_id: "challenge-2896".to_owned(),
                publisher_operation: "operation-class-2896".to_owned(),
                publisher_decided_at_unix_ms: 4_000_000_000_000,
                deadline_unix_ms: 4_000_000_060_000,
                replay_key: "e".repeat(64),
                previous_delivery_digest: None,
            },
            delivery_digest: "f".repeat(64),
        }
    }

    fn test_ack(
        delivery: &WasmControlDelivery,
        phase: ControlAckPhase,
        detail: Option<&str>,
        outcome_digest: Option<&str>,
    ) -> WasmControlAck {
        let identity = &delivery.identity;
        WasmControlAck {
            wire_id: WASM_CONTROL_ACK_WIRE_ID.to_owned(),
            wire_version: WASM_CONTROL_ACK_WIRE_VERSION,
            replay_key: identity.replay_key.clone(),
            operation_id: identity.operation_id.clone(),
            generation: identity.generation,
            owner_sequence: identity.owner_sequence,
            delivery_digest: delivery.delivery_digest.clone(),
            phase,
            detail: detail.map(str::to_owned),
            outcome_digest: outcome_digest.map(str::to_owned),
        }
    }

    fn spool_dir(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(name);
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("spool dir writable");
        dir
    }

    fn test_reader(dir: &std::path::Path, generation: u64) -> KernelControlReader {
        KernelControlReader::new(&test_binding(generation), dir.to_path_buf())
    }

    fn stage_ack(dir: &std::path::Path, generation: u64, sequence: u64, ack: &WasmControlAck) {
        let bytes = serde_json::to_vec(ack).expect("ack serializes");
        std::fs::write(dir.join(control_ack_name(generation, sequence)), &bytes)
            .expect("ack writable");
    }

    /// Positive control for the spool builders: no staged ack resolves Free.
    #[test]
    fn ack_slot_free_without_staged_ack() {
        let dir = spool_dir("eliot-2896-ack-slot-free");
        let reader = test_reader(&dir, 7);
        let delivery = test_delivery(7, 0);
        let mut reads = 0_usize;
        assert!(matches!(
            reader.open_ack(7, 0, &delivery, &[], &mut reads),
            AckSlot::Free
        ));
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A decisive Completed ack bound to the exact delivery resolves Decided.
    #[test]
    fn ack_slot_decided_on_completed() {
        let dir = spool_dir("eliot-2896-ack-slot-decided");
        let reader = test_reader(&dir, 7);
        let delivery = test_delivery(7, 0);
        stage_ack(
            &dir,
            7,
            0,
            &test_ack(&delivery, ControlAckPhase::Completed, None, None),
        );
        let mut reads = 0_usize;
        assert!(matches!(
            reader.open_ack(7, 0, &delivery, &[(7, 0)], &mut reads),
            AckSlot::Decided
        ));
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A foreign open acceptance re-offers for UNKNOWN recovery.
    #[test]
    fn ack_slot_reoffer_on_foreign_enqueued() {
        let dir = spool_dir("eliot-2896-ack-slot-reoffer");
        let reader = test_reader(&dir, 7);
        let delivery = test_delivery(7, 0);
        stage_ack(
            &dir,
            7,
            0,
            &test_ack(&delivery, ControlAckPhase::Enqueued, None, None),
        );
        let mut reads = 0_usize;
        assert!(matches!(
            reader.open_ack(7, 0, &delivery, &[(7, 0)], &mut reads),
            AckSlot::Reoffer(_)
        ));
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Our own still-open acceptance occupies the slot.
    #[test]
    fn ack_slot_own_open_for_accepted() {
        let dir = spool_dir("eliot-2896-ack-slot-own");
        let mut reader = test_reader(&dir, 7);
        reader.accepted = Some(AcceptedControl {
            kind: WasmControlKind::Reconcile,
            operation_id: "operation-2896".to_owned(),
            generation: 7,
            sequence: 0,
            replay_key: "e".repeat(64),
            delivery_digest: "f".repeat(64),
            ack_staged: true,
        });
        let delivery = test_delivery(7, 0);
        stage_ack(
            &dir,
            7,
            0,
            &test_ack(&delivery, ControlAckPhase::Enqueued, None, None),
        );
        let mut reads = 0_usize;
        assert!(matches!(
            reader.open_ack(7, 0, &delivery, &[(7, 0)], &mut reads),
            AckSlot::OwnOpen
        ));
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A listed slot with no readable file is someone's evidence, not a free slot.
    #[test]
    fn ack_slot_unreadable_without_ack_file() {
        let dir = spool_dir("eliot-2896-ack-slot-unreadable");
        let reader = test_reader(&dir, 7);
        let delivery = test_delivery(7, 0);
        let mut reads = 0_usize;
        assert!(matches!(
            reader.open_ack(7, 0, &delivery, &[(7, 0)], &mut reads),
            AckSlot::Unreadable
        ));
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A digest the delivery never carried fails the exact join.
    #[test]
    fn ack_slot_unjoined_on_foreign_digest() {
        let dir = spool_dir("eliot-2896-ack-slot-digest");
        let reader = test_reader(&dir, 7);
        let delivery = test_delivery(7, 0);
        let mut ack = test_ack(&delivery, ControlAckPhase::Enqueued, None, None);
        ack.delivery_digest = "0".repeat(64);
        stage_ack(&dir, 7, 0, &ack);
        let mut reads = 0_usize;
        assert!(matches!(
            reader.open_ack(7, 0, &delivery, &[(7, 0)], &mut reads),
            AckSlot::Unjoined
        ));
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A blank refusal detail fails the owner's shape rule.
    #[test]
    fn ack_slot_unjoined_on_blank_refused_detail() {
        let dir = spool_dir("eliot-2896-ack-slot-detail");
        let reader = test_reader(&dir, 7);
        let delivery = test_delivery(7, 0);
        stage_ack(
            &dir,
            7,
            0,
            &test_ack(&delivery, ControlAckPhase::Refused, Some("   "), None),
        );
        let mut reads = 0_usize;
        assert!(matches!(
            reader.open_ack(7, 0, &delivery, &[(7, 0)], &mut reads),
            AckSlot::Unjoined
        ));
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// An outcome digest on Enqueued is a shape violation.
    #[test]
    fn ack_slot_unjoined_on_enqueued_outcome() {
        let dir = spool_dir("eliot-2896-ack-slot-outcome");
        let reader = test_reader(&dir, 7);
        let delivery = test_delivery(7, 0);
        stage_ack(
            &dir,
            7,
            0,
            &test_ack(
                &delivery,
                ControlAckPhase::Enqueued,
                None,
                Some(&"f".repeat(64)),
            ),
        );
        let mut reads = 0_usize;
        assert!(matches!(
            reader.open_ack(7, 0, &delivery, &[(7, 0)], &mut reads),
            AckSlot::Unjoined
        ));
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A refusal never overwrites an occupied slot: the staged acceptance stands.
    #[test]
    fn refuse_never_overwrites_occupied_slot() {
        let dir = spool_dir("eliot-2896-ack-slot-occupied");
        let reader = test_reader(&dir, 7);
        let delivery = test_delivery(7, 0);
        let ack = test_ack(&delivery, ControlAckPhase::Enqueued, None, None);
        stage_ack(&dir, 7, 0, &ack);
        let snapshot = std::fs::read(dir.join(control_ack_name(7, 0))).expect("ack readable");
        reader.refuse_slot(7, 0, &delivery, "control-test", false);
        assert_eq!(
            std::fs::read(dir.join(control_ack_name(7, 0))).expect("ack readable"),
            snapshot
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A refusal stages into a genuinely free slot as Refused.
    #[test]
    fn refuse_stages_into_free_slot() {
        let dir = spool_dir("eliot-2896-ack-slot-refuse-free");
        let reader = test_reader(&dir, 7);
        let delivery = test_delivery(7, 0);
        reader.refuse_slot(7, 0, &delivery, "control-test", false);
        let bytes = std::fs::read(dir.join(control_ack_name(7, 0))).expect("refused ack readable");
        let staged: WasmControlAck = serde_json::from_slice(&bytes).expect("refused ack parses");
        assert_eq!(staged.phase, ControlAckPhase::Refused);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
