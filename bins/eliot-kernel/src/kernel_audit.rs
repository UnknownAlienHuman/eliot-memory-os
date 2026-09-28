//! Kernel-owned durable audit evidence (issue #1837).
//!
//! Architecture: I16.1 durable audit (authority, transitions, receipts,
//! incidents, security, lifecycle; never sampled), I16.3 composite run trace
//! context, I16.4 required operational events, I16.9 full-capture retention
//! for Material/Critical boundaries, I16.10 BLAKE3-chained integrity with
//! Watchdog-domain anchors, I16.11 no hidden telemetry failure, I16.12 trace
//! completeness with explicit missing parts.
//!
//! This module owns the single Kernel audit chain and the single anchor sink:
//! one append-only JSONL chain below the canonical work root
//! (`<work-root>/kernel-audit/audit-events.jsonl`), one BLAKE3
//! previous/current link per record, and one anchor directory holding
//! periodic digest anchors. Anchors store a digest, never semantic memory
//! (A13.8). The anchor sink defaults to
//! `<work-root>/kernel-audit/anchors/`; the Host injects the installer-owned
//! `RuntimeStateRoots::watchdog_state_root` through [`AuditAnchorBinding`]
//! (mirroring the Host-owned eliotd receipt root), and the production launch
//! path always does, so in every running Kernel the periodic anchor lands in
//! the Watchdog failure domain rather than beside the chain it anchors. That
//! default remains a legitimate configuration for a caller that binds no
//! Watchdog domain. There is no second writer, no parallel chain, and no
//! alternate anchor mechanism: every boundary below appends through the
//! composition's one [`KernelAuditChain`] handle.
//!
//! Event posture is uniform and observational: `audit_observe` appends are
//! best-effort and never change an authority decision. The durable ORS
//! record owns lifecycle state; audit is its evidence projection. An append
//! failure is never silent: it emits the stable
//! `KERNEL_AUDIT_APPEND_FAILED` terminal through the #895 diagnostics
//! facade. The I16.11 cascade has two legs. The submit path spools both
//! drafts fsync-sealed before the ORS completion and `audit_chain_records`
//! reconciles that spool against the validated ORS record before reading, so a
//! completed result always yields its full ordered chain. A failed append
//! itself runs the independent cascade owned by
//! [`crate::audit_fallback::KernelAuditFallback`] (issue #1840): the failed
//! draft is retained in the independently persisted audit spool, else the
//! last-resort channel, else the visible control-loss state. Anchor
//! auto-export runs
//! every [`KERNEL_AUDIT_ANCHOR_INTERVAL_RECORDS`] records plus on explicit
//! export; a failed auto-export likewise stays visible through
//! `KERNEL_AUDIT_ANCHOR_FAILED` without failing the append, so the Kernel
//! never depends on Watchdog-domain availability (A13.2).
//!
//! Every record carries the applicable I16.3 lineage or an explicit
//! missing-field declaration in `lineage.missing_fields`. Capture mode is
//! always `FULL`: audit is never sampled.

#![forbid(unsafe_code)]

use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};

use eliot_contracts::{EpochId, StateFence, canonical_json_bytes};
use eliot_ipc::Session;
use eliot_kernel_core::CutoverDecision;
use eliot_kernel_service::EliotdLaunchDescriptor;
use eliot_ors::{HostRequestRecord, HostRequestState, OperationIdentity, SupervisionLeaseSnapshot};
use eliot_process::ProcessStartReceipt;
use eliot_protocol::{
    HostRequestAdmissionReceipt, HostRequestEnvelope, HostRequestResultBody, LocalReadAttempt,
    host_request_operation_id,
};
use serde::{Deserialize, Serialize};

/// Canonical audit record/anchor format version (I16.3 normalization version).
pub const KERNEL_AUDIT_FORMAT_VERSION: u16 = 1;
/// Directory below the canonical work root holding the chain and anchors.
pub const KERNEL_AUDIT_DIR_NAME: &str = "kernel-audit";
/// Append-only canonical-JSON chain file name.
pub const KERNEL_AUDIT_CHAIN_FILE_NAME: &str = "audit-events.jsonl";
/// Anchor sink directory name below the audit directory.
pub const KERNEL_AUDIT_ANCHOR_DIR_NAME: &str = "anchors";
/// Stable `latest` anchor pointer file name inside the anchor sink.
pub const KERNEL_AUDIT_LATEST_ANCHOR_FILE_NAME: &str = "latest-anchor.json";
/// Spool directory name below the audit directory for pending result bindings.
pub const KERNEL_AUDIT_PENDING_DIR_NAME: &str = "pending-bindings";
/// Records between automatic periodic anchor exports.
pub const KERNEL_AUDIT_ANCHOR_INTERVAL_RECORDS: u64 = 64;
/// Previous-hash of the genesis record: 64 zero hex digits.
pub const KERNEL_AUDIT_GENESIS_PREV_HASH: &str =
    "0000000000000000000000000000000000000000000000000000000000000000";
/// Previous-anchor hash when no anchor was exported yet.
pub const KERNEL_AUDIT_GENESIS_ANCHOR_HASH: &str =
    "0000000000000000000000000000000000000000000000000000000000000000";
/// Stable terminal code emitted when an audit append fails.
pub const KERNEL_AUDIT_APPEND_TERMINAL_CODE: &str = "KERNEL_AUDIT_APPEND_FAILED";
/// Stable terminal code emitted when an automatic anchor export fails.
pub const KERNEL_AUDIT_ANCHOR_TERMINAL_CODE: &str = "KERNEL_AUDIT_ANCHOR_FAILED";

/// Returns the BLAKE3 hex digest of `bytes`.
#[must_use]
pub fn blake3_hex(bytes: &[u8]) -> String {
    blake3::hash(bytes).to_hex().to_string()
}

/// Returns a stable nonsecret reference for a physical process binding.
///
/// The image comparison at authenticated peer admission is ASCII
/// case-insensitive on Windows, so normalize that portion identically before
/// hashing the tuple shared by the peer and process-start receipt.
fn process_binding_reference(
    process_id: u32,
    start_time_100ns: u64,
    image_path: &str,
) -> Option<String> {
    let image_path = image_path.to_ascii_lowercase();
    let bytes = canonical_json_bytes(&(process_id, start_time_100ns, image_path)).ok()?;
    Some(format!("process-binding:v1:{}", blake3_hex(&bytes)))
}

/// Returns the stable `lineage_id:sequence` text for one authority epoch.
#[must_use]
pub fn authority_epoch_text(epoch: &EpochId) -> String {
    format!("{}:{}", epoch.lineage_id.as_str(), epoch.sequence)
}

/// Projects the nonsecret owner-launch reference observed at a binding boundary.
///
/// Issue #1807/W7. The accepted and the refused handshake must report the same
/// owner references under the same key, so one projection serves both arms: a
/// reader compares `owner_launch` across `session_bound` and `session_rejected`
/// without having to know which arm produced the record. The projection carries
/// only the descriptor digest, the generation and the authority epoch — never a
/// path, nonce, or other secret — and its mere presence is not evidence that the
/// owner was admitted.
fn owner_launch_reference(launch: &EliotdLaunchDescriptor) -> serde_json::Value {
    serde_json::json!({
        "descriptor_sha256": launch.descriptor_sha256,
        "generation": launch.generation.value(),
        "authority_epoch": authority_epoch_text(&launch.authority_epoch),
    })
}

/// Projects the nonsecret owner process-start-receipt reference observed at a
/// binding boundary.
///
/// Issue #1807/W7. Shares [`owner_launch_reference`]'s one-arm-one-vocabulary
/// rule. The `expected_process_binding_ref` is the shared
/// [`process_binding_reference`] tuple the pipe peer and the start receipt must
/// agree on; a `None` there stays `null` rather than being replaced by a
/// reconstructed or inferred reference, because the tuple could not be formed.
fn owner_process_receipt_reference(receipt: &ProcessStartReceipt) -> serde_json::Value {
    let physical = receipt.identity().physical();
    let process_binding_ref = process_binding_reference(
        physical.process_id(),
        physical.start_time_100ns(),
        physical.image_path(),
    );
    serde_json::json!({
        "expected_process_binding_ref": process_binding_ref,
        "operation_id": receipt.operation_id().as_str(),
        "generation": receipt.accepted_generation().get(),
        "authority_epoch": authority_epoch_text(receipt.binding().state_fence().authority_epoch()),
        "validation_revision": receipt.binding().validation_revision(),
    })
}

/// Projects the operation identity a boundary actually admitted for one attempt.
///
/// Issue #1807/W7. `operation_authorization` is reported as a fact that names
/// the exact admitted operation, never as a bare boolean: an authorization
/// claim without the `(attempt, generation, scope, facet)` tuple it authorizes
/// is not auditable. Used at the dispatch and submission boundaries, which are
/// the only boundaries that hold a live [`LocalReadAttempt`].
fn admitted_operation_authorization(
    attempt: &LocalReadAttempt,
    status: &'static str,
) -> serde_json::Value {
    serde_json::json!({
        "status": status,
        "attempt_id": attempt.attempt_id,
        "fencing_generation": attempt.fencing_generation,
        "scope_id": attempt.scope_id,
        "facet_method": attempt.facet_method,
    })
}

/// Resolves the Kernel-owned audit directory below the canonical work root.
#[must_use]
pub fn kernel_audit_dir(work_root: &Path) -> PathBuf {
    work_root.join(KERNEL_AUDIT_DIR_NAME)
}

/// Resolves the Kernel-owned audit chain file below the canonical work root.
#[must_use]
pub fn kernel_audit_chain_path(work_root: &Path) -> PathBuf {
    kernel_audit_dir(work_root).join(KERNEL_AUDIT_CHAIN_FILE_NAME)
}

/// Resolves the default anchor sink below the canonical work root.
#[must_use]
pub fn kernel_audit_anchor_dir(work_root: &Path) -> PathBuf {
    kernel_audit_dir(work_root).join(KERNEL_AUDIT_ANCHOR_DIR_NAME)
}

/// Host-injected anchor sink binding for the Watchdog failure domain.
///
/// Mirrors the Host-owned eliotd receipt root: an absolute, already existing
/// directory owned outside the Kernel failure domain where the Kernel copies
/// periodic digest anchors. `None` keeps the default sink below the Kernel
/// work root; the sink is always exactly one directory.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuditAnchorBinding {
    dir: PathBuf,
}

impl AuditAnchorBinding {
    /// Binds an absolute anchor sink directory.
    ///
    /// # Errors
    ///
    /// Returns [`KernelAuditError::NotAbsoluteRoot`] when `dir` is not
    /// absolute, or [`KernelAuditError::NotDirectory`] when it does not
    /// exist. The Kernel never creates the Watchdog-domain directory.
    pub fn new(dir: impl Into<PathBuf>) -> Result<Self, KernelAuditError> {
        let dir = dir.into();
        if !dir.is_absolute() {
            return Err(KernelAuditError::NotAbsoluteRoot);
        }
        if !dir.is_dir() {
            return Err(KernelAuditError::NotDirectory);
        }
        Ok(Self { dir })
    }

    /// Returns the bound anchor sink directory.
    #[must_use]
    pub fn dir(&self) -> &Path {
        &self.dir
    }
}

/// Typed audit chain failure. Only the variant crosses diagnostics; path and
/// reason strings never reach the observation channel.
#[derive(Debug)]
pub enum KernelAuditError {
    /// The work root or anchor sink is not absolute.
    NotAbsoluteRoot,
    /// The work root or anchor sink is not an existing directory.
    NotDirectory,
    /// The chain file or anchor file could not be read or written.
    Io {
        /// Failing path, for the caller only.
        path: PathBuf,
        /// OS error text, for the caller only.
        reason: String,
    },
    /// One chain line is not a canonical record.
    ChainCorrupt {
        /// 1-based line number of the offending row.
        line: u64,
        /// Stable corruption reason code.
        reason: &'static str,
    },
    /// The event kind is not in the closed canonical set.
    UnknownEventKind(String),
    /// An anchor does not verify against its chain prefix.
    AnchorMismatch {
        /// Stable mismatch reason code.
        reason: &'static str,
    },
    /// No record exists to anchor.
    EmptyChain,
    /// Canonical JSON encoding failed.
    Serialization(String),
    /// The audit mutex is poisoned.
    LockPoisoned,
}

impl std::fmt::Display for KernelAuditError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotAbsoluteRoot => formatter.write_str("audit root must be absolute"),
            Self::NotDirectory => formatter.write_str("audit root must be an existing directory"),
            Self::Io { path, reason } => {
                write!(
                    formatter,
                    "audit IO failed for {}: {reason}",
                    path.display()
                )
            }
            Self::ChainCorrupt { line, reason } => {
                write!(formatter, "audit chain corrupt at line {line}: {reason}")
            }
            Self::UnknownEventKind(kind) => {
                write!(formatter, "unknown audit event kind: {kind}")
            }
            Self::AnchorMismatch { reason } => {
                write!(formatter, "audit anchor mismatch: {reason}")
            }
            Self::EmptyChain => formatter.write_str("audit chain is empty"),
            Self::Serialization(reason) => {
                write!(formatter, "audit serialization failed: {reason}")
            }
            Self::LockPoisoned => formatter.write_str("audit lock poisoned"),
        }
    }
}

impl std::error::Error for KernelAuditError {}

/// I16.9 assurance class of one audit event.
///
/// Material/Critical authority, effect, finish, and recovery boundaries are
/// full-capture; `Standard` reserves the schema slot for future
/// non-authority audit detail. All three serialize unsampled.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum AuditAssuranceClass {
    /// Authority, effect, finish, or recovery boundary.
    #[serde(rename = "CRITICAL")]
    Critical,
    /// Governed operational boundary with lineage obligations.
    #[serde(rename = "MATERIAL")]
    Material,
    /// Non-authority audit detail (reserved).
    #[serde(rename = "STANDARD")]
    Standard,
}

impl AuditAssuranceClass {
    /// Returns the stable wire code.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Critical => "CRITICAL",
            Self::Material => "MATERIAL",
            Self::Standard => "STANDARD",
        }
    }
}

/// I16.9 capture mode. Audit has exactly one mode: full capture.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum AuditCaptureMode {
    /// Complete required evidence, never sampled.
    #[serde(rename = "FULL")]
    Full,
}

impl AuditCaptureMode {
    /// Returns the stable wire code.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Full => "FULL",
        }
    }
}

/// Closed canonical audit event kinds (I16.4 boundary vocabulary).
///
/// The set is closed: [`KernelAuditChain::append`] rejects any kind outside
/// [`AuditEventKind::ALL`], so the chain can never carry an ad-hoc event.
pub struct AuditEventKind;

impl AuditEventKind {
    /// Chain (re)opened below the work root; the restart boundary record.
    pub const CHAIN_OPENED: &'static str = "chain.opened";
    /// One host-request envelope admitted for routing.
    pub const QUEUE_ENVELOPE_ADMITTED: &'static str = "queue.envelope_admitted";
    /// One linkage-checked query pair queued for the daemon poller.
    pub const QUEUE_LOCAL_READ_ENQUEUED: &'static str = "queue.local_read_enqueued";
    /// One invoke-read routed to its daemon-claimable lane.
    pub const ROUTE_INVOKE_READ_ROUTED: &'static str = "route.invoke_read_routed";
    /// A requested route diverged from the actual serving lane and the work
    /// was rejected without queueing or binding (issue #1839).
    pub const ROUTE_MISMATCH: &'static str = "route.mismatch";
    /// First governed claim minted a fencing lease for one pair.
    pub const LEASE_CLAIM_CREATED: &'static str = "lease.claim_created";
    /// Same-owner re-claim returned the identical current capability.
    pub const LEASE_CLAIM_RECONFIRMED: &'static str = "lease.claim_reconfirmed";
    /// A new owner reassigned the fencing lease (generation bump).
    pub const LEASE_CLAIM_REASSIGNED: &'static str = "lease.claim_reassigned";
    /// A claimed pair's absolute deadline passed before completion; the dead
    /// pair was retired instead of lingering as a stranded claim (issue #1839).
    pub const LEASE_CLAIM_EXPIRED: &'static str = "lease.claim_expired";
    /// A supervision lease was established for the daemon contour.
    pub const LEASE_SUPERVISION_ESTABLISHED: &'static str = "lease.supervision_established";
    /// A supervision lease was renewed for the daemon contour.
    pub const LEASE_SUPERVISION_RENEWED: &'static str = "lease.supervision_renewed";
    /// Supervision evidence was revoked.
    pub const LEASE_SUPERVISION_REVOKED: &'static str = "lease.supervision_revoked";
    /// Expired supervision fenced effect admission.
    pub const LEASE_SUPERVISION_EXPIRED: &'static str = "lease.supervision_expired";
    /// A generation/epoch cutover was applied.
    pub const EPOCH_CUTOVER_APPLIED: &'static str = "epoch.cutover_applied";
    /// An authenticated local peer bound a session.
    pub const SESSION_BOUND: &'static str = "session.bound";
    /// A daemon handshake was refused before session binding.
    pub const SESSION_REJECTED: &'static str = "session.rejected";
    /// A bridge connection and its session were revoked.
    pub const SESSION_REVOKED: &'static str = "session.revoked";
    /// One queued pair was dispatched to the daemon claimer.
    pub const DISPATCH_DAEMON_CLAIM: &'static str = "dispatch.daemon_claim";
    /// The daemon submitted a result body for its claim.
    pub const RESULT_DAEMON_SUBMITTED: &'static str = "result.daemon_submitted";
    /// The Kernel bound a daemon result to its operation (ORS persist).
    pub const RESULT_KERNEL_BOUND: &'static str = "result.kernel_bound";
    /// The Kernel sealed the canonical replayable trace manifest for one
    /// bound result (issue #1838; I16.12).
    pub const TRACE_MANIFEST_SEALED: &'static str = "trace.manifest_sealed";
    /// A stale submission was quarantined without binding.
    pub const RESULT_STALE_QUARANTINED: &'static str = "result.stale_quarantined";
    /// A claimed observe pair deferred to `DeferredNoEffect` and retired its
    /// queue pair (issue #1839).
    pub const DEFER_CLAIM_DEFERRED: &'static str = "defer.claim_deferred";
    /// A canonical admission receipt was issued.
    pub const RECEIPT_ADMISSION_ISSUED: &'static str = "receipt.admission_issued";
    /// The durable eliotd live receipt was published.
    pub const RECEIPT_LIVE_PUBLISHED: &'static str = "receipt.live_published";
    /// A typed cancellation was requested for its exact parent.
    pub const CANCEL_REQUESTED: &'static str = "cancel.requested";
    /// A cancellation reached its exact parent: cancelled, fenced to
    /// `Unknown` past the cancellable window, or already terminal (issue #1839).
    pub const CANCEL_CONFIRMED: &'static str = "cancel.confirmed";
    /// A queued pair was retired (orphan cleanup).
    pub const ORPHAN_QUEUE_RETIRED: &'static str = "orphan.queue_retired";
    /// A lost connection's operations were fenced (orphan cleanup).
    pub const ORPHAN_CONNECTION_FENCED: &'static str = "orphan.connection_fenced";
    /// The approved eliotd child launch committed.
    pub const PROCESS_LAUNCH_COMMITTED: &'static str = "process.launch_committed";
    /// The approved eliotd child launch failed.
    pub const PROCESS_LAUNCH_FAILED: &'static str = "process.launch_failed";
    /// Authenticated daemon readiness was proven.
    pub const PROCESS_READY_PROVEN: &'static str = "process.ready_proven";
    /// Authenticated daemon degradation was recorded.
    pub const PROCESS_DEGRADED: &'static str = "process.degraded";
    /// Authenticated daemon failure was recorded.
    pub const PROCESS_FAILED: &'static str = "process.failed";
    /// The descendant-closure receipt observed for one launched child.
    pub const PROCESS_DESCENDANT_CLOSED: &'static str = "process.descendant_closed";
    /// Ordered safe shutdown was requested.
    pub const SHUTDOWN_DRAIN_REQUESTED: &'static str = "shutdown.drain_requested";
    /// The drain commit decision linearized.
    pub const SHUTDOWN_DRAIN_COMMITTED: &'static str = "shutdown.drain_committed";
    /// The shutdown terminal published.
    pub const SHUTDOWN_TERMINAL_PUBLISHED: &'static str = "shutdown.terminal_published";

    /// Every canonical kind, in schema order.
    pub const ALL: &'static [&'static str] = &[
        Self::CHAIN_OPENED,
        Self::QUEUE_ENVELOPE_ADMITTED,
        Self::QUEUE_LOCAL_READ_ENQUEUED,
        Self::ROUTE_INVOKE_READ_ROUTED,
        Self::ROUTE_MISMATCH,
        Self::LEASE_CLAIM_CREATED,
        Self::LEASE_CLAIM_RECONFIRMED,
        Self::LEASE_CLAIM_REASSIGNED,
        Self::LEASE_CLAIM_EXPIRED,
        Self::LEASE_SUPERVISION_ESTABLISHED,
        Self::LEASE_SUPERVISION_RENEWED,
        Self::LEASE_SUPERVISION_REVOKED,
        Self::LEASE_SUPERVISION_EXPIRED,
        Self::EPOCH_CUTOVER_APPLIED,
        Self::SESSION_BOUND,
        Self::SESSION_REJECTED,
        Self::SESSION_REVOKED,
        Self::DISPATCH_DAEMON_CLAIM,
        Self::RESULT_DAEMON_SUBMITTED,
        Self::RESULT_KERNEL_BOUND,
        Self::TRACE_MANIFEST_SEALED,
        Self::RESULT_STALE_QUARANTINED,
        Self::DEFER_CLAIM_DEFERRED,
        Self::RECEIPT_ADMISSION_ISSUED,
        Self::RECEIPT_LIVE_PUBLISHED,
        Self::CANCEL_REQUESTED,
        Self::CANCEL_CONFIRMED,
        Self::ORPHAN_QUEUE_RETIRED,
        Self::ORPHAN_CONNECTION_FENCED,
        Self::PROCESS_LAUNCH_COMMITTED,
        Self::PROCESS_LAUNCH_FAILED,
        Self::PROCESS_READY_PROVEN,
        Self::PROCESS_DEGRADED,
        Self::PROCESS_FAILED,
        Self::PROCESS_DESCENDANT_CLOSED,
        Self::SHUTDOWN_DRAIN_REQUESTED,
        Self::SHUTDOWN_DRAIN_COMMITTED,
        Self::SHUTDOWN_TERMINAL_PUBLISHED,
    ];

    /// Returns whether `kind` is in the closed canonical set.
    #[must_use]
    pub fn is_canonical(kind: &str) -> bool {
        Self::ALL.contains(&kind)
    }

    /// Returns the closed-kind static matching a runtime kind string.
    ///
    /// The #1840 spool reconcile path rebuilds drafts through this lookup,
    /// so a spooled kind either resolves to its canonical static or is
    /// retained as unknown-kind evidence; a non-canonical kind can never
    /// leak into the chain through a rebuilt draft.
    #[must_use]
    pub(crate) fn canonical(kind: &str) -> Option<&'static str> {
        Self::ALL
            .iter()
            .find(|candidate| **candidate == kind)
            .copied()
    }

    /// Returns the I16.9 assurance class for one canonical kind.
    #[must_use]
    pub fn assurance_class(kind: &str) -> AuditAssuranceClass {
        match kind {
            Self::LEASE_SUPERVISION_ESTABLISHED
            | Self::LEASE_SUPERVISION_RENEWED
            | Self::LEASE_SUPERVISION_REVOKED
            | Self::LEASE_SUPERVISION_EXPIRED
            | Self::EPOCH_CUTOVER_APPLIED
            | Self::SESSION_BOUND
            | Self::SESSION_REJECTED
            | Self::SESSION_REVOKED
            | Self::RESULT_KERNEL_BOUND
            | Self::TRACE_MANIFEST_SEALED
            | Self::RECEIPT_LIVE_PUBLISHED
            | Self::CANCEL_REQUESTED
            | Self::CANCEL_CONFIRMED
            | Self::PROCESS_LAUNCH_FAILED
            | Self::PROCESS_FAILED
            | Self::SHUTDOWN_DRAIN_REQUESTED
            | Self::SHUTDOWN_DRAIN_COMMITTED
            | Self::SHUTDOWN_TERMINAL_PUBLISHED => AuditAssuranceClass::Critical,
            _ => AuditAssuranceClass::Material,
        }
    }
}

/// I16.3 composite run trace context carried by every audit record.
///
/// Each slot holds the Kernel-known value or `None` with the slot name
/// listed in `missing_fields` (I16.12: missing parts explicitly listed).
/// `event_cursor` and `normalization_version` are set at append time;
/// [`AuditLineage::finalize`] computes `missing_fields` there, so no
/// record can carry a stale declaration.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditLineage {
    /// Request-scoped trace identity (`HostRequestIdentity.request_id`).
    pub trace_id: Option<String>,
    /// Kernel operation handle (`hostreq:<sha>`, lease, cutover, or launch).
    pub operation_id: Option<String>,
    /// Governor-owned task identity claimed by the request.
    pub task_id: Option<String>,
    /// Queued work-item handle (the claimed pair's operation).
    pub work_item: Option<String>,
    /// Governed attempt identity of the live fencing lease.
    pub attempt_id: Option<String>,
    /// Durable job identity (process job for launch events).
    pub job_id: Option<String>,
    /// Semantic principal (resolved by eliotd, never by Kernel).
    pub principal: Option<String>,
    /// Durable semantic session identity claimed by the request.
    pub session_id: Option<String>,
    /// Executing controller leg (`kernel` or `eliotd`).
    pub controller: Option<String>,
    /// Governor-owned `WorkScope` identity claimed by the request.
    pub work_scope: Option<String>,
    /// Exact fence observed with the authority decision.
    pub state_fence: Option<StateFence>,
    /// Presenting transport adapter instance (connection identity).
    pub adapter_instance: Option<String>,
    /// Executor-observed process identity.
    pub process_identity: Option<String>,
    /// Nonsecret digest reference to the exact authenticated PID/start/image tuple.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub process_binding_ref: Option<String>,
    /// Native session/run locator (outside Kernel scope: declared missing).
    pub native_session: Option<String>,
    /// Parent-child agent locators (outside Kernel scope: declared missing).
    pub parent_child_locators: Option<String>,
    /// Requested route (capability/linkage selector).
    pub route_receipt_requested: Option<String>,
    /// Actual route receipt (canonical receipt digest).
    pub route_receipt_actual: Option<String>,
    /// Worktree identity (outside Kernel scope: declared missing).
    pub worktree: Option<String>,
    /// Lease under which the work runs (attempt or supervision lease).
    pub environment_lease: Option<String>,
    /// Module/process generation text.
    pub module_generation: Option<String>,
    /// Authority epoch `lineage_id:sequence` text.
    pub authority_epoch: Option<String>,
    /// Event sequence cursor: the record `seq`, set at append.
    pub event_cursor: Option<String>,
    /// Normalization version text, set at append.
    pub normalization_version: Option<String>,
    /// I16.3 slots with no Kernel-known value for this event.
    pub missing_fields: Vec<String>,
}

impl AuditLineage {
    /// Returns an empty lineage; every slot missing until filled.
    #[must_use]
    pub fn empty() -> Self {
        Self {
            trace_id: None,
            operation_id: None,
            task_id: None,
            work_item: None,
            attempt_id: None,
            job_id: None,
            principal: None,
            session_id: None,
            controller: None,
            work_scope: None,
            state_fence: None,
            adapter_instance: None,
            process_identity: None,
            process_binding_ref: None,
            native_session: None,
            parent_child_locators: None,
            route_receipt_requested: None,
            route_receipt_actual: None,
            worktree: None,
            environment_lease: None,
            module_generation: None,
            authority_epoch: None,
            event_cursor: None,
            normalization_version: None,
            missing_fields: Vec::new(),
        }
    }

    /// Fills request/authority slots from one admitted envelope.
    pub fn fill_envelope(&mut self, envelope: &HostRequestEnvelope) {
        let operation_id = host_request_operation_id(envelope);
        Self::fill(&mut self.trace_id, envelope.identity.request_id.as_str());
        Self::fill(&mut self.operation_id, &operation_id);
        Self::fill(&mut self.work_item, &operation_id);
        if let Some(task) = envelope.identity.task_id.as_deref() {
            Self::fill(&mut self.task_id, task);
        }
        if let Some(session) = envelope.identity.session_id.as_deref() {
            Self::fill(&mut self.session_id, session);
        }
        if let Some(scope) = envelope.identity.work_scope_id.as_deref() {
            Self::fill(&mut self.work_scope, scope);
        }
        if self.state_fence.is_none() {
            self.state_fence = Some(envelope.state_fence.clone());
        }
        Self::fill(&mut self.adapter_instance, &envelope.connection_id);
        Self::fill(
            &mut self.route_receipt_requested,
            &envelope.identity.capability,
        );
        Self::fill(
            &mut self.module_generation,
            &envelope.state_fence.resource_generation.value().to_string(),
        );
        Self::fill(
            &mut self.authority_epoch,
            &authority_epoch_text(&envelope.state_fence.authority_epoch),
        );
        Self::fill(&mut self.controller, "kernel");
    }

    /// Fills durable slots from one stored ORS host-request record.
    pub fn fill_stored(&mut self, stored: &HostRequestRecord) {
        Self::fill(&mut self.trace_id, stored.request_id.as_str());
        Self::fill(&mut self.operation_id, stored.operation_id.as_str());
        Self::fill(&mut self.work_item, stored.operation_id.as_str());
        if let Some(task) = stored.task_ref.as_ref() {
            Self::fill(&mut self.task_id, task.as_str());
        }
        if let Some(session) = stored.session_ref.as_ref() {
            Self::fill(&mut self.session_id, session.as_str());
        }
        if let Some(scope) = stored.scope_ref.as_ref() {
            Self::fill(&mut self.work_scope, scope.as_str());
        }
        Self::fill(&mut self.adapter_instance, stored.connection_ref.as_str());
        Self::fill(
            &mut self.route_receipt_requested,
            stored.capability_ref.as_str(),
        );
        Self::fill(&mut self.module_generation, &stored.generation.to_string());
        Self::fill(
            &mut self.authority_epoch,
            &authority_epoch_text(&stored.authority_epoch),
        );
        Self::fill(&mut self.controller, "kernel");
    }

    /// Fills transport/session slots from one authenticated session.
    pub fn fill_session(&mut self, session: &Session) {
        Self::fill(&mut self.adapter_instance, &session.connection_id);
        if let Some(binding) = session.peer.process_binding()
            && let Some(reference) = process_binding_reference(
                binding.process_id(),
                binding.start_time_100ns(),
                binding.image_path(),
            )
        {
            Self::fill(&mut self.process_binding_ref, &reference);
        }
        if self.state_fence.is_none() {
            self.state_fence = Some(session.module_generation.state_fence.clone());
        }
        Self::fill(
            &mut self.module_generation,
            &session
                .module_generation
                .state_fence
                .resource_generation
                .value()
                .to_string(),
        );
        Self::fill(
            &mut self.authority_epoch,
            &authority_epoch_text(&session.authority_epoch),
        );
    }

    /// Marks the daemon execution leg and its presenting owner session.
    pub fn fill_daemon_leg(&mut self, session: &Session) {
        self.fill_session(session);
        self.controller = Some("eliotd".to_owned());
    }

    /// Fills attempt/lease slots from one fenced attempt capability.
    pub fn fill_attempt(&mut self, attempt: &LocalReadAttempt) {
        Self::fill(&mut self.attempt_id, &attempt.attempt_id);
        Self::fill(&mut self.environment_lease, &attempt.attempt_id);
        Self::fill(&mut self.operation_id, &attempt.operation_id);
    }

    /// Fills process slots from one executor-observed start receipt.
    pub fn fill_process_receipt(&mut self, receipt: &ProcessStartReceipt) {
        Self::fill(&mut self.operation_id, receipt.operation_id().as_str());
        Self::fill(&mut self.job_id, receipt.identity().job_id().as_str());
        let physical = receipt.identity().physical();
        if let Some(reference) = process_binding_reference(
            physical.process_id(),
            physical.start_time_100ns(),
            physical.image_path(),
        ) {
            Self::fill(&mut self.process_binding_ref, &reference);
        }
        Self::fill(
            &mut self.process_identity,
            receipt.identity().process_id().as_str(),
        );
        Self::fill(
            &mut self.module_generation,
            &receipt.accepted_generation().get().to_string(),
        );
        Self::fill(&mut self.controller, "kernel");
    }

    /// Fills lease slots from one supervision lease snapshot.
    pub fn fill_supervision_snapshot(&mut self, snapshot: &SupervisionLeaseSnapshot) {
        Self::fill(
            &mut self.operation_id,
            snapshot.receipt.operation_id.as_str(),
        );
        Self::fill(
            &mut self.environment_lease,
            snapshot.receipt.lease_id.as_str(),
        );
        if self.state_fence.is_none() {
            self.state_fence = Some(snapshot.record.binding.state_fence.clone());
        }
        Self::fill(&mut self.controller, "kernel");
    }

    /// Fills epoch/generation slots from one cutover decision.
    pub fn fill_cutover(&mut self, decision: &CutoverDecision) {
        Self::fill(&mut self.operation_id, decision.cutover_id());
        Self::fill(
            &mut self.module_generation,
            &decision.new_generation().value().to_string(),
        );
        Self::fill(
            &mut self.authority_epoch,
            &authority_epoch_text(decision.new_epoch()),
        );
        Self::fill(&mut self.controller, "kernel");
    }

    /// Sets the actual route receipt digest.
    pub fn fill_route_receipt_actual(&mut self, receipt_sha256: &str) {
        Self::fill(&mut self.route_receipt_actual, receipt_sha256);
    }

    /// Fills lineage slots from one sealed trace manifest (issue #1838).
    pub fn fill_manifest(&mut self, manifest: &crate::trace_manifest::TraceManifest) {
        Self::fill(&mut self.trace_id, manifest.trace_id.as_str());
        Self::fill(&mut self.operation_id, &manifest.operation_id);
        Self::fill(&mut self.work_item, &manifest.operation_id);
        if let Some(task) = manifest.task_id.as_deref() {
            Self::fill(&mut self.task_id, task);
        }
        if let Some(session) = manifest.session_id.as_deref() {
            Self::fill(&mut self.session_id, session);
        }
        if let Some(scope) = manifest.work_scope_id.as_deref() {
            Self::fill(&mut self.work_scope, scope);
        }
        if let Some(lease) = manifest.lease_attempt_id.as_deref() {
            Self::fill(&mut self.attempt_id, lease);
            Self::fill(&mut self.environment_lease, lease);
        }
        if self.state_fence.is_none() {
            self.state_fence.clone_from(&manifest.state_fence);
        }
        if let Some(adapter) = manifest
            .adapter_identity
            .as_deref()
            .or(manifest.connection_id.as_deref())
        {
            Self::fill(&mut self.adapter_instance, adapter);
        }
        if let Some(process) = manifest.executor_identity.as_deref() {
            Self::fill(&mut self.process_identity, process);
        }
        if let Some(route) = manifest.requested_route.as_deref() {
            Self::fill(&mut self.route_receipt_requested, route);
        }
        if let Some(route) = manifest.actual_route.as_deref() {
            Self::fill(&mut self.route_receipt_actual, route);
        }
        if let Some(generation) = manifest.module_generation.as_deref() {
            Self::fill(&mut self.module_generation, generation);
        }
        if let Some(epoch) = manifest.authority_epoch.as_deref() {
            Self::fill(&mut self.authority_epoch, epoch);
        }
        Self::fill(&mut self.controller, "kernel");
    }

    fn fill(slot: &mut Option<String>, value: &str) {
        if slot.is_none() && !value.trim().is_empty() {
            *slot = Some(value.to_owned());
        }
    }

    /// Seals cursor/version slots and computes missing-field declarations.
    fn finalize(&mut self, seq: u64) {
        self.event_cursor = Some(seq.to_string());
        self.normalization_version = Some(KERNEL_AUDIT_FORMAT_VERSION.to_string());
        let mut missing = Vec::new();
        for (slot, name) in [
            (&self.trace_id, "trace_id"),
            (&self.operation_id, "operation_id"),
            (&self.task_id, "task_id"),
            (&self.work_item, "work_item"),
            (&self.attempt_id, "attempt_id"),
            (&self.job_id, "job_id"),
            (&self.principal, "principal"),
            (&self.session_id, "session_id"),
            (&self.controller, "controller"),
            (&self.work_scope, "work_scope"),
            (&self.adapter_instance, "adapter_instance"),
            (&self.process_identity, "process_identity"),
            (&self.process_binding_ref, "process_binding_ref"),
            (&self.native_session, "native_session"),
            (&self.parent_child_locators, "parent_child_locators"),
            (&self.route_receipt_requested, "route_receipt_requested"),
            (&self.route_receipt_actual, "route_receipt_actual"),
            (&self.worktree, "worktree"),
            (&self.environment_lease, "environment_lease"),
            (&self.module_generation, "module_generation"),
            (&self.authority_epoch, "authority_epoch"),
        ] {
            if slot.is_none() {
                missing.push(name.to_owned());
            }
        }
        if self.state_fence.is_none() {
            missing.push("state_fence".to_owned());
        }
        self.missing_fields = missing;
    }
}

/// One not-yet-sequenced audit event: closed kind, lineage, and a small
/// digest/identity-only body (I15.4: no content, no free-text errors).
#[derive(Clone, Debug)]
pub struct AuditEventDraft {
    kind: &'static str,
    lineage: AuditLineage,
    body: serde_json::Value,
}

impl AuditEventDraft {
    /// Starts a draft of one closed kind with empty lineage and body.
    #[must_use]
    pub fn new(kind: &'static str) -> Self {
        Self {
            kind,
            lineage: AuditLineage::empty(),
            body: serde_json::Value::Null,
        }
    }

    /// Rebuilds a draft from spooled parts for #1840 reconciliation.
    ///
    /// The caller resolves `kind` through [`AuditEventKind::canonical`];
    /// [`KernelAuditChain::append`] reseals the cursor/version lineage slots
    /// at the new sequence, so spooled pre-finalize lineage stays valid.
    #[must_use]
    pub(crate) fn from_parts(
        kind: &'static str,
        lineage: AuditLineage,
        body: serde_json::Value,
    ) -> Self {
        Self {
            kind,
            lineage,
            body,
        }
    }

    /// Returns the draft kind for #1840 spool retention.
    #[must_use]
    pub(crate) fn kind(&self) -> &'static str {
        self.kind
    }

    /// Returns the draft lineage for #1840 spool retention.
    #[must_use]
    pub(crate) fn lineage(&self) -> &AuditLineage {
        &self.lineage
    }

    /// Returns the draft body for #1840 spool retention.
    #[must_use]
    pub(crate) fn body(&self) -> &serde_json::Value {
        &self.body
    }

    /// Returns the chain (re)opened draft sealing the restart boundary.
    #[must_use]
    pub fn chain_opened(prior_head_seq: u64, prior_head_hash: &str) -> Self {
        let mut lineage = AuditLineage::empty();
        lineage.controller = Some("kernel".to_owned());
        Self {
            kind: AuditEventKind::CHAIN_OPENED,
            lineage,
            body: serde_json::json!({
                "prior_head_seq": prior_head_seq,
                "prior_head_hash": prior_head_hash,
            }),
        }
    }

    /// Returns the envelope-admitted draft for one routed host request.
    #[must_use]
    pub fn queue_envelope_admitted(
        envelope: &HostRequestEnvelope,
        receipt: &HostRequestAdmissionReceipt,
        admitted: &HostRequestRecord,
    ) -> Self {
        let mut lineage = AuditLineage::empty();
        lineage.fill_envelope(envelope);
        lineage.fill_route_receipt_actual(&receipt.receipt_sha256);
        Self {
            kind: AuditEventKind::QUEUE_ENVELOPE_ADMITTED,
            lineage,
            body: serde_json::json!({
                "request_kind": envelope.kind.as_str(),
                "request_digest": envelope.envelope_sha256,
                "receipt_sha256": receipt.receipt_sha256,
                "durable_state": format!("{:?}", admitted.state),
            }),
        }
    }

    /// Returns the admission-receipt-issued draft for one envelope.
    #[must_use]
    pub fn receipt_admission_issued(
        envelope: &HostRequestEnvelope,
        receipt: &HostRequestAdmissionReceipt,
    ) -> Self {
        let mut lineage = AuditLineage::empty();
        lineage.fill_envelope(envelope);
        lineage.fill_route_receipt_actual(&receipt.receipt_sha256);
        Self {
            kind: AuditEventKind::RECEIPT_ADMISSION_ISSUED,
            lineage,
            body: serde_json::json!({
                "operation_id": receipt.operation_id,
                "request_sha256": receipt.request_sha256,
                "receipt_sha256": receipt.receipt_sha256,
                "deadline_unix_ms": receipt.deadline_unix_ms,
            }),
        }
    }

    /// Returns the query-pair-enqueued draft for one invoke-read lane.
    #[must_use]
    pub fn queue_local_read_enqueued(envelope: &HostRequestEnvelope, queued_depth: usize) -> Self {
        let mut lineage = AuditLineage::empty();
        lineage.fill_envelope(envelope);
        Self {
            kind: AuditEventKind::QUEUE_LOCAL_READ_ENQUEUED,
            lineage,
            body: serde_json::json!({
                "lane": "query",
                "request_digest": envelope.envelope_sha256,
                "queued_depth": queued_depth,
            }),
        }
    }

    /// Returns the invoke-read-routed draft naming the actual lane.
    #[must_use]
    pub fn route_invoke_read_routed(
        envelope: &HostRequestEnvelope,
        receipt: &HostRequestAdmissionReceipt,
        lane: &'static str,
    ) -> Self {
        let mut lineage = AuditLineage::empty();
        lineage.fill_envelope(envelope);
        lineage.fill_route_receipt_actual(&receipt.receipt_sha256);
        Self {
            kind: AuditEventKind::ROUTE_INVOKE_READ_ROUTED,
            lineage,
            body: serde_json::json!({
                "requested_capability": envelope.identity.capability,
                "actual_lane": lane,
                "receipt_sha256": receipt.receipt_sha256,
            }),
        }
    }

    /// Returns the route-mismatch draft for one invoke-read that matched no
    /// daemon-claimable lane (issue #1839).
    ///
    /// The requested capability is preserved in lineage
    /// (`route_receipt_requested`) and body; no actual lane exists because the
    /// work was rejected before queueing.
    #[must_use]
    pub fn route_mismatch_routing(envelope: &HostRequestEnvelope, reason: &'static str) -> Self {
        let mut lineage = AuditLineage::empty();
        lineage.fill_envelope(envelope);
        Self {
            kind: AuditEventKind::ROUTE_MISMATCH,
            lineage,
            body: serde_json::json!({
                "requested_route": envelope.identity.capability,
                "actual_lane": serde_json::Value::Null,
                "disposition": "rejected_not_queued",
                "reason": reason,
            }),
        }
    }

    /// Returns the route-mismatch draft for one submit refused because the
    /// stored capability diverged from the serving lane (issue #1839).
    ///
    /// Observation only: the refusal itself is unchanged
    /// ([`TransportError::SessionFenced`](eliot_ipc::TransportError::SessionFenced));
    /// the record names the requested versus actual route so the rejection is
    /// diagnosable instead of silent.
    #[must_use]
    pub fn route_mismatch_submit(
        session: &Session,
        stored: &HostRequestRecord,
        lane: &'static str,
    ) -> Self {
        let mut lineage = AuditLineage::empty();
        lineage.fill_stored(stored);
        lineage.fill_daemon_leg(session);
        Self {
            kind: AuditEventKind::ROUTE_MISMATCH,
            lineage,
            body: serde_json::json!({
                "requested_route": stored.capability_ref.as_str(),
                "actual_lane": lane,
                "disposition": "rejected_submit_refused",
            }),
        }
    }

    /// Returns the fencing-lease claim draft, classified by claim history.
    #[must_use]
    pub fn lease_claim(
        envelope: &HostRequestEnvelope,
        session: &Session,
        attempt: &LocalReadAttempt,
        previous_generation: u64,
        owned_before: bool,
    ) -> Self {
        let kind = if previous_generation == 0 {
            AuditEventKind::LEASE_CLAIM_CREATED
        } else if owned_before {
            AuditEventKind::LEASE_CLAIM_RECONFIRMED
        } else {
            AuditEventKind::LEASE_CLAIM_REASSIGNED
        };
        let mut lineage = AuditLineage::empty();
        lineage.fill_envelope(envelope);
        lineage.fill_daemon_leg(session);
        lineage.fill_attempt(attempt);
        Self {
            kind,
            lineage,
            body: serde_json::json!({
                "attempt_id": attempt.attempt_id,
                "fencing_generation": attempt.fencing_generation,
                "previous_generation": previous_generation,
                "owner_connection_id": session.connection_id,
                "owner_session_epoch": session.session_epoch,
                "expires_at_unix_ms": attempt.expires_at_unix_ms,
                "use_budget": attempt.use_budget,
            }),
        }
    }

    /// Returns the claimed-lease-expiry draft for one deadline-passed pair
    /// (issue #1839).
    ///
    /// `phase` names the route leg that detected the expiry (`admission`,
    /// `submit`, or `defer`); `queue_retired` reports whether the dead pair
    /// was actually removed, so the expiry record stays joined to its
    /// observable cleanup instead of implying removal that never happened.
    /// The presented attempt identity is carried when the leg presented one;
    /// admission-time staging presents none.
    #[must_use]
    #[allow(
        clippy::too_many_arguments,
        reason = "the expiry observation joins session, record, lane, phase, presented attempt, and cleanup outcome in one audited call"
    )]
    pub fn lease_claim_expired(
        session: Option<&Session>,
        stored: &HostRequestRecord,
        lane: &'static str,
        phase: &'static str,
        presented_attempt_id: Option<&str>,
        presented_generation: Option<u64>,
        queue_retired: bool,
    ) -> Self {
        let mut lineage = AuditLineage::empty();
        lineage.fill_stored(stored);
        if let Some(session) = session {
            lineage.fill_daemon_leg(session);
        }
        if let Some(attempt_id) = presented_attempt_id {
            lineage.attempt_id = Some(attempt_id.to_owned());
            lineage.environment_lease = Some(attempt_id.to_owned());
        }
        Self {
            kind: AuditEventKind::LEASE_CLAIM_EXPIRED,
            lineage,
            body: serde_json::json!({
                "lane": lane,
                "phase": phase,
                "request_digest": stored.request_digest,
                "deadline_unix_ms": stored.deadline_unix_ms,
                "presented_attempt_id": presented_attempt_id,
                "presented_generation": presented_generation,
                "queue_retired": queue_retired,
                "durable_state": format!("{:?}", stored.state),
            }),
        }
    }

    /// Returns the outbound-dispatch draft handing one pair to the daemon.
    ///
    /// Issue #1807/W7. Carries the same three separately-keyed facts the
    /// binding events carry, so the already-joined session/envelope/attempt
    /// lineage states which fact was observed at which stage instead of
    /// leaving the reader to infer a stage from the event name. The facts ride
    /// the existing lineage fill; this builds no second join mechanism.
    ///
    /// Only this boundary assesses the operation. It is reached after the
    /// envelope passed route admission and a live fencing-generation claim was
    /// minted for it, so the admitted operation identity is reported verbatim
    /// through [`admitted_operation_authorization`] rather than as a bare
    /// boolean. Authenticated transport is observed here by construction of the
    /// path, not by the presence of a field: dispatch is reachable only through
    /// a session whose `bind_session` arm already returned `Ok`, so the same
    /// authentication fact is recorded again at the stage that consumes it. No
    /// semantic result exists at dispatch, so acceptance stays `not_reached`:
    /// an admitted operation is not an accepted result.
    #[must_use]
    pub fn dispatch_daemon_claim(
        envelope: &HostRequestEnvelope,
        session: &Session,
        attempt: &LocalReadAttempt,
    ) -> Self {
        let mut lineage = AuditLineage::empty();
        lineage.fill_envelope(envelope);
        lineage.fill_daemon_leg(session);
        lineage.fill_attempt(attempt);
        Self {
            kind: AuditEventKind::DISPATCH_DAEMON_CLAIM,
            lineage,
            body: serde_json::json!({
                "lane": "query",
                "attempt_id": attempt.attempt_id,
                "fencing_generation": attempt.fencing_generation,
                "scope_id": attempt.scope_id,
                "facet_method": attempt.facet_method,
                "transport_authentication": "observed_at_dispatch_boundary",
                "operation_authorization": admitted_operation_authorization(
                    attempt,
                    "admitted_for_dispatch",
                ),
                "semantic_result_acceptance": "not_reached",
            }),
        }
    }

    /// Returns the daemon-submitted draft for one result body.
    ///
    /// Issue #1807/W7. Same three separately-keyed facts, same lineage join as
    /// the other attempt-leg events, so the chain states at which stage each
    /// fact was observed. Authenticated transport is observed here: this event
    /// is emitted only after the presenting session's authority epoch, module
    /// generation and State Fence were matched against the queued envelope or
    /// the stored record, and that match is a live check at this call site.
    ///
    /// The authorized operation is reported only when the submitting daemon
    /// actually carried the admitted attempt identity. A submission body
    /// without an attempt is reported as `not_carried_on_submission` rather
    /// than having an authorization reconstructed from the stored record, which
    /// would be inferring a fact from the presence of a field. Acceptance of the
    /// result is `not_assessed`: this event records a presented, fence-matched
    /// result body, and the semantic qualification of that body is a separate
    /// later step, so authentication here can never promote a model result
    /// (issue #1809 owns candidate/disclosure qualification).
    #[must_use]
    pub fn result_daemon_submitted(
        session: &Session,
        body: &HostRequestResultBody,
        stored: &HostRequestRecord,
        envelope: Option<&HostRequestEnvelope>,
        lane: &'static str,
    ) -> Self {
        let mut lineage = AuditLineage::empty();
        if let Some(envelope) = envelope {
            lineage.fill_envelope(envelope);
        }
        lineage.fill_stored(stored);
        lineage.fill_daemon_leg(session);
        if let Some(attempt) = body.attempt.as_ref() {
            lineage.fill_attempt(attempt);
        }
        let operation_authorization = body.attempt.as_ref().map_or_else(
            || serde_json::json!("not_carried_on_submission"),
            |attempt| admitted_operation_authorization(attempt, "admitted_attempt_identity"),
        );
        Self {
            kind: AuditEventKind::RESULT_DAEMON_SUBMITTED,
            lineage,
            body: serde_json::json!({
                "lane": lane,
                "request_digest": body.request_sha256,
                "result_digest": body.result_digest,
                "fence_digest": stored.fence_digest,
                "transport_authentication": "observed_at_result_boundary",
                "operation_authorization": operation_authorization,
                "semantic_result_acceptance": "not_assessed",
            }),
        }
    }

    /// Returns the kernel-bound draft for one persisted result.
    #[must_use]
    pub fn result_kernel_bound(
        session: &Session,
        body: &HostRequestResultBody,
        persisted: &HostRequestRecord,
        envelope: Option<&HostRequestEnvelope>,
        lane: &'static str,
    ) -> Self {
        let mut lineage = AuditLineage::empty();
        if let Some(envelope) = envelope {
            lineage.fill_envelope(envelope);
        }
        lineage.fill_stored(persisted);
        lineage.fill_daemon_leg(session);
        if let Some(attempt) = body.attempt.as_ref() {
            lineage.fill_attempt(attempt);
        }
        Self {
            kind: AuditEventKind::RESULT_KERNEL_BOUND,
            lineage,
            body: serde_json::json!({
                "lane": lane,
                "request_digest": body.request_sha256,
                "result_digest": body.result_digest,
                "durable_state": format!("{:?}", persisted.state),
            }),
        }
    }

    /// Returns the trace-manifest-sealed draft for one bound result.
    ///
    /// The lineage mirrors the manifest's I16.3 slots; the sealed body is the
    /// manifest itself, so [`TraceManifest::find_sealed`](crate::trace_manifest::TraceManifest::find_sealed)
    /// replays the exact record from the retained chain. A manifest that
    /// cannot serialize seals a null body instead of failing the observation:
    /// the kind plus the lineage operation still identify the seal, and
    /// readback honestly reports no manifest.
    #[must_use]
    pub fn trace_manifest_sealed(manifest: &crate::trace_manifest::TraceManifest) -> Self {
        let mut lineage = AuditLineage::empty();
        lineage.fill_manifest(manifest);
        Self {
            kind: AuditEventKind::TRACE_MANIFEST_SEALED,
            lineage,
            body: serde_json::to_value(manifest).unwrap_or(serde_json::Value::Null),
        }
    }

    /// Returns the stale-quarantined draft for one noncanonical submission.
    #[must_use]
    pub fn result_stale_quarantined(
        session: &Session,
        body: &HostRequestResultBody,
        stored: &HostRequestRecord,
        lane: &'static str,
        reason: &'static str,
    ) -> Self {
        let mut lineage = AuditLineage::empty();
        lineage.fill_stored(stored);
        lineage.fill_daemon_leg(session);
        if let Some(attempt) = body.attempt.as_ref() {
            lineage.fill_attempt(attempt);
        }
        Self {
            kind: AuditEventKind::RESULT_STALE_QUARANTINED,
            lineage,
            body: serde_json::json!({
                "lane": lane,
                "request_digest": body.request_sha256,
                "result_digest": body.result_digest,
                "reason": reason,
            }),
        }
    }

    /// Returns the claim-deferred draft for one observe deferral (issue #1839).
    ///
    /// The durable `DeferredNoEffect` persist precedes the observation; the
    /// queue pair retires on the same leg, so `queue_retired` is always true
    /// here and pairs the deferral with its cleanup.
    #[must_use]
    pub fn observe_claim_deferred(
        session: &Session,
        attempt: &LocalReadAttempt,
        routed: &HostRequestRecord,
    ) -> Self {
        let mut lineage = AuditLineage::empty();
        lineage.fill_stored(routed);
        lineage.fill_daemon_leg(session);
        lineage.fill_attempt(attempt);
        Self {
            kind: AuditEventKind::DEFER_CLAIM_DEFERRED,
            lineage,
            body: serde_json::json!({
                "lane": "observe",
                "attempt_id": attempt.attempt_id,
                "fencing_generation": attempt.fencing_generation,
                "attempt_phase": "deferred_no_effect",
                "queue_retired": true,
                "durable_state": format!("{:?}", routed.state),
            }),
        }
    }

    /// Returns the cancellation-requested draft for one exact parent.
    #[must_use]
    pub fn cancel_requested(envelope: &HostRequestEnvelope, admitted: &HostRequestRecord) -> Self {
        let mut lineage = AuditLineage::empty();
        lineage.fill_envelope(envelope);
        Self {
            kind: AuditEventKind::CANCEL_REQUESTED,
            lineage,
            body: serde_json::json!({
                "parent_operation_id": envelope.identity.parent_operation_id,
                "cancellation_id": envelope.identity.cancellation_id,
                "durable_state": format!("{:?}", admitted.state),
            }),
        }
    }

    /// Returns the cancellation-confirmed draft for one exact parent
    /// (issue #1839).
    ///
    /// `outcome` is `cancelled` only after the atomic ORS transition proves
    /// no possible effect, `fenced_unknown` when a claimed attempt remains
    /// unresolved, `reconciling` for an existing recovery, or
    /// `already_terminal` for an already closed parent. The durable ORS
    /// observation precedes this audit record.
    #[must_use]
    pub fn cancel_confirmed(
        envelope: &HostRequestEnvelope,
        parent_operation_id: &str,
        parent_digest: &str,
        outcome: &'static str,
    ) -> Self {
        let mut lineage = AuditLineage::empty();
        lineage.fill_envelope(envelope);
        Self {
            kind: AuditEventKind::CANCEL_CONFIRMED,
            lineage,
            body: serde_json::json!({
                "parent_operation_id": parent_operation_id,
                "parent_digest": parent_digest,
                "cancellation_id": envelope.identity.cancellation_id,
                "outcome": outcome,
            }),
        }
    }

    /// Returns the queue-retired orphan-cleanup draft.
    #[must_use]
    pub fn orphan_queue_retired(operation_id: &str, request_digest: &str) -> Self {
        let mut lineage = AuditLineage::empty();
        lineage.operation_id = Some(operation_id.to_owned());
        lineage.work_item = Some(operation_id.to_owned());
        lineage.controller = Some("kernel".to_owned());
        Self {
            kind: AuditEventKind::ORPHAN_QUEUE_RETIRED,
            lineage,
            body: serde_json::json!({
                "request_digest": request_digest,
            }),
        }
    }

    /// Returns the connection-fenced orphan-cleanup draft.
    ///
    /// `state_fence` is the Kernel's currently admitted authority observed
    /// with the fencing decision; `None` keeps the previous fenceless shape
    /// when that authority is unreadable.
    #[must_use]
    pub fn orphan_connection_fenced(
        connection_id: &str,
        fenced_operations: usize,
        state_fence: Option<&StateFence>,
    ) -> Self {
        let mut lineage = AuditLineage::empty();
        lineage.adapter_instance = Some(connection_id.to_owned());
        lineage.controller = Some("kernel".to_owned());
        if let Some(fence) = state_fence {
            lineage.state_fence = Some(fence.clone());
        }
        Self {
            kind: AuditEventKind::ORPHAN_CONNECTION_FENCED,
            lineage,
            body: serde_json::json!({
                "fenced_operations": fenced_operations,
            }),
        }
    }

    /// Returns the supervision-established draft for one lease snapshot.
    #[must_use]
    pub fn lease_supervision_established(
        snapshot: &SupervisionLeaseSnapshot,
        session: Option<&Session>,
    ) -> Self {
        Self::supervision_snapshot(
            AuditEventKind::LEASE_SUPERVISION_ESTABLISHED,
            snapshot,
            session,
        )
    }

    /// Returns the supervision-renewed draft for one lease snapshot.
    #[must_use]
    pub fn lease_supervision_renewed(
        snapshot: &SupervisionLeaseSnapshot,
        session: Option<&Session>,
    ) -> Self {
        Self::supervision_snapshot(AuditEventKind::LEASE_SUPERVISION_RENEWED, snapshot, session)
    }

    fn supervision_snapshot(
        kind: &'static str,
        snapshot: &SupervisionLeaseSnapshot,
        session: Option<&Session>,
    ) -> Self {
        let mut lineage = AuditLineage::empty();
        lineage.fill_supervision_snapshot(snapshot);
        if let Some(session) = session {
            lineage.fill_session(session);
        }
        Self {
            kind,
            lineage,
            body: serde_json::json!({
                "lease_id": snapshot.receipt.lease_id.as_str(),
                "record_id": snapshot.receipt.record_id.as_str(),
                "revision": snapshot.receipt.revision,
                "operation_order": snapshot.receipt.operation_order,
                "receipt_sha256": snapshot.receipt.receipt_sha256,
            }),
        }
    }

    /// Returns the supervision-revoked draft.
    #[must_use]
    pub fn lease_supervision_revoked() -> Self {
        let mut lineage = AuditLineage::empty();
        lineage.controller = Some("kernel".to_owned());
        Self {
            kind: AuditEventKind::LEASE_SUPERVISION_REVOKED,
            lineage,
            body: serde_json::json!({"scope": "startup-supervision-evidence"}),
        }
    }

    /// Returns the supervision-expired draft.
    ///
    /// `snapshot` is the expired lease's durable head: its binding fence is
    /// the exact authority observed with the expiry decision, so the record
    /// carries it (I16.7: a brief is fenced by its trigger record).
    /// `None` keeps the previous fenceless shape when the head is
    /// unreadable; observation never fails the revocation.
    #[must_use]
    pub fn lease_supervision_expired(snapshot: Option<&SupervisionLeaseSnapshot>) -> Self {
        let mut lineage = AuditLineage::empty();
        lineage.controller = Some("kernel".to_owned());
        if let Some(snapshot) = snapshot {
            lineage.fill_supervision_snapshot(snapshot);
        }
        Self {
            kind: AuditEventKind::LEASE_SUPERVISION_EXPIRED,
            lineage,
            body: serde_json::json!({"effect": "effect-admission-revoked"}),
        }
    }

    /// Returns the epoch-cutover-applied draft for one decision.
    #[must_use]
    pub fn epoch_cutover_applied(decision: &CutoverDecision) -> Self {
        let mut lineage = AuditLineage::empty();
        lineage.fill_cutover(decision);
        Self {
            kind: AuditEventKind::EPOCH_CUTOVER_APPLIED,
            lineage,
            body: serde_json::json!({
                "cutover_id": decision.cutover_id(),
                "old_epoch": authority_epoch_text(decision.old_epoch()),
                "new_epoch": authority_epoch_text(decision.new_epoch()),
                "new_generation": decision.new_generation().value(),
            }),
        }
    }

    /// Returns the session-bound draft for one accepted handshake.
    ///
    /// Issue #1807/W7. Reports the same three separately-keyed facts, the same
    /// `peer_identity_well_formed` observation and the same nonsecret owner
    /// references under the same keys as [`Self::session_rejected`], so the
    /// accepted and the refused handshake are directly comparable. A
    /// declaration that these fields exist is not live execution evidence: each
    /// value below states what this boundary actually observed, and every fact
    /// that was not observed is named as such instead of being inferred from
    /// the presence of an adjacent field.
    ///
    /// This arm is reached only after `Session::establish_with_server` returned
    /// `Ok`, which is exactly where the OS pipe-admitted peer was validated and
    /// the client's module generation, artifact hash, launch nonce and
    /// authority epoch were proven equal to the live server policy. So
    /// authenticated transport is genuinely observed here. The other two facts
    /// are not, and the `bind_session` contract states that acceptance never
    /// implies request admission: no operation is authorized at the binding
    /// boundary, and no semantic result can exist before a request is even
    /// admitted. `operation_authorization` therefore stays `not_assessed` and
    /// `semantic_result_acceptance` stays `not_reached`; a successful
    /// authentication is never allowed to promote a model result (issue #1809
    /// owns candidate/disclosure qualification).
    #[must_use]
    pub fn session_bound(
        session: &Session,
        peer_identity_well_formed: bool,
        owner_launch: Option<&EliotdLaunchDescriptor>,
        owner_process_receipt: Option<&ProcessStartReceipt>,
    ) -> Self {
        let mut lineage = AuditLineage::empty();
        lineage.fill_session(session);
        lineage.controller = Some("kernel".to_owned());
        let owner_launch = owner_launch.map(owner_launch_reference);
        let owner_process_receipt = owner_process_receipt.map(owner_process_receipt_reference);
        Self {
            kind: AuditEventKind::SESSION_BOUND,
            lineage,
            body: serde_json::json!({
                "connection_id": session.connection_id,
                "session_epoch": session.session_epoch,
                "peer_identity_well_formed": peer_identity_well_formed,
                "transport_authentication": "observed_at_binding_boundary",
                "operation_authorization": "not_assessed",
                "semantic_result_acceptance": "not_reached",
                "owner_launch": owner_launch,
                "owner_process_receipt": owner_process_receipt,
            }),
        }
    }

    /// Returns a daemon-handshake refusal draft for the durable audit chain
    /// without promoting peer-supplied identity to authenticated process lineage.
    #[must_use]
    pub fn session_rejected(
        connection_id: &str,
        peer_identity_well_formed: bool,
        public_transport_error: &'static str,
        refusal_cause: Option<&'static str>,
        owner_launch: Option<&EliotdLaunchDescriptor>,
        owner_process_receipt: Option<&ProcessStartReceipt>,
    ) -> Self {
        let mut lineage = AuditLineage::empty();
        lineage.adapter_instance = Some(connection_id.to_owned());
        lineage.controller = Some("kernel".to_owned());
        let owner_launch = owner_launch.map(|launch| {
            AuditLineage::fill(
                &mut lineage.module_generation,
                &launch.generation.value().to_string(),
            );
            AuditLineage::fill(
                &mut lineage.authority_epoch,
                &authority_epoch_text(&launch.authority_epoch),
            );
            owner_launch_reference(launch)
        });
        let owner_process_receipt = owner_process_receipt.map(owner_process_receipt_reference);
        Self {
            kind: AuditEventKind::SESSION_REJECTED,
            lineage,
            body: serde_json::json!({
                "connection_id": connection_id,
                "peer_identity_well_formed": peer_identity_well_formed,
                "transport_authentication": "not_observed_at_binding_boundary",
                "operation_authorization": "not_assessed",
                "semantic_result_acceptance": "not_reached",
                "public_transport_error": public_transport_error,
                "refusal_detail_status": if refusal_cause.is_none() {
                    "unclassified"
                } else {
                    "classified"
                },
                "refusal_cause": refusal_cause,
                "owner_launch": owner_launch,
                "owner_process_receipt": owner_process_receipt,
            }),
        }
    }

    /// Returns the session-revoked draft for one connection.
    #[must_use]
    pub fn session_revoked(connection_id: &str) -> Self {
        let mut lineage = AuditLineage::empty();
        lineage.adapter_instance = Some(connection_id.to_owned());
        lineage.controller = Some("kernel".to_owned());
        Self {
            kind: AuditEventKind::SESSION_REVOKED,
            lineage,
            body: serde_json::json!({"connection_id": connection_id}),
        }
    }

    /// Returns the live-receipt-published draft for one daemon receipt.
    #[must_use]
    pub fn receipt_live_published(
        process: &ProcessStartReceipt,
        supervision_lease_id: &str,
    ) -> Self {
        let mut lineage = AuditLineage::empty();
        lineage.fill_process_receipt(process);
        lineage.environment_lease = Some(supervision_lease_id.to_owned());
        Self {
            kind: AuditEventKind::RECEIPT_LIVE_PUBLISHED,
            lineage,
            body: serde_json::json!({
                "supervision_lease_id": supervision_lease_id,
                "request_digest": process.request_digest(),
            }),
        }
    }

    /// Returns the launch-committed draft for one start receipt.
    #[must_use]
    pub fn process_launch_committed(receipt: &ProcessStartReceipt) -> Self {
        let mut lineage = AuditLineage::empty();
        lineage.fill_process_receipt(receipt);
        Self {
            kind: AuditEventKind::PROCESS_LAUNCH_COMMITTED,
            lineage,
            body: serde_json::json!({
                "operation_id": receipt.operation_id().as_str(),
                "process_id": receipt.identity().process_id().as_str(),
                "pid": receipt.identity().pid(),
                "executable_sha256": receipt.identity().executable_sha256(),
            }),
        }
    }

    /// Returns the launch-failed draft with its stable terminal code.
    ///
    /// `state_fence` is the Kernel's currently admitted authority observed
    /// with the failed launch; `None` keeps the previous fenceless shape
    /// when that authority is unreadable.
    #[must_use]
    pub fn process_launch_failed(
        terminal_code: &'static str,
        state_fence: Option<&StateFence>,
    ) -> Self {
        let mut lineage = AuditLineage::empty();
        lineage.controller = Some("kernel".to_owned());
        if let Some(fence) = state_fence {
            lineage.state_fence = Some(fence.clone());
        }
        Self {
            kind: AuditEventKind::PROCESS_LAUNCH_FAILED,
            lineage,
            body: serde_json::json!({"terminal_code": terminal_code}),
        }
    }

    /// Returns the descendant-closure draft for one launched child
    /// (CHILD-1/CHILD-2, #1918): the exact observed lifecycle and tree state,
    /// never a success claim on its own. Crate-internal: the receipt shape is
    /// a Kernel-internal projection, not exported audit API.
    #[must_use]
    pub(crate) fn descendant_closure(
        receipt: &super::activation_lifecycle::DescendantClosureReceipt,
    ) -> Self {
        let mut lineage = AuditLineage::empty();
        lineage.controller = Some("kernel".to_owned());
        Self {
            kind: AuditEventKind::PROCESS_DESCENDANT_CLOSED,
            lineage,
            body: serde_json::json!({
                "operation_id": receipt.operation_id().as_str(),
                "owner_module": receipt.owner_module(),
                "lifecycle": format!("{:?}", receipt.lifecycle()),
                "cancellation": format!("{:?}", receipt.cancellation()),
                "tree_terminated": receipt.tree_terminated(),
                "all_closed": receipt.all_closed(),
                "evidence_ref": receipt.evidence_ref(),
            }),
        }
    }

    /// Returns the daemon-status draft for one lifecycle transition.
    ///
    /// `state_fence` is the Kernel's currently admitted authority observed
    /// with the transition; `None` keeps the previous fenceless shape when
    /// that authority is unreadable.
    #[must_use]
    pub fn process_daemon_status(
        kind: &'static str,
        receipt: Option<&ProcessStartReceipt>,
        detail: &str,
        state_fence: Option<&StateFence>,
    ) -> Self {
        let mut lineage = AuditLineage::empty();
        if let Some(receipt) = receipt {
            lineage.fill_process_receipt(receipt);
        } else {
            lineage.controller = Some("kernel".to_owned());
        }
        if let Some(fence) = state_fence {
            lineage.state_fence = Some(fence.clone());
        }
        Self {
            kind,
            lineage,
            body: serde_json::json!({"detail": detail}),
        }
    }

    /// Returns the drain-requested draft.
    #[must_use]
    pub fn shutdown_drain_requested() -> Self {
        let mut lineage = AuditLineage::empty();
        lineage.controller = Some("kernel".to_owned());
        Self {
            kind: AuditEventKind::SHUTDOWN_DRAIN_REQUESTED,
            lineage,
            body: serde_json::json!({"scope": "ordered-safe-shutdown"}),
        }
    }

    /// Returns the drain-committed draft for one linearized decision.
    #[must_use]
    pub fn shutdown_drain_committed(generation: &str, fenced_epoch_count: usize) -> Self {
        let mut lineage = AuditLineage::empty();
        lineage.controller = Some("kernel".to_owned());
        Self {
            kind: AuditEventKind::SHUTDOWN_DRAIN_COMMITTED,
            lineage,
            body: serde_json::json!({
                "drain_generation": generation,
                "authority_epochs_fenced": fenced_epoch_count,
            }),
        }
    }

    /// Returns the terminal-published draft for one shutdown outcome.
    #[must_use]
    pub fn shutdown_terminal_published(terminal: &'static str, pending_count: usize) -> Self {
        let mut lineage = AuditLineage::empty();
        lineage.controller = Some("kernel".to_owned());
        Self {
            kind: AuditEventKind::SHUTDOWN_TERMINAL_PUBLISHED,
            lineage,
            body: serde_json::json!({
                "terminal": terminal,
                "pending_count": pending_count,
            }),
        }
    }
}

/// One spooled not-yet-sequenced audit event: the serializable shadow of an
/// [`AuditEventDraft`] (I16.11 result-leg spool).
///
/// The spool stores the draft exactly as built pre-persist (closed kind,
/// full lineage, digest/identity-only body). [`PendingResultBinding`]
/// explains the reconcile contract.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SpooledAuditDraft {
    /// Closed canonical event kind (mapped back to its `&'static` const).
    kind: String,
    /// Composite run trace context as built at spool time.
    lineage: AuditLineage,
    /// Digest/identity-only event detail.
    body: serde_json::Value,
}

impl SpooledAuditDraft {
    /// Snapshots one live draft for the durable spool.
    fn of(draft: &AuditEventDraft) -> Self {
        Self {
            kind: draft.kind.to_owned(),
            lineage: draft.lineage.clone(),
            body: draft.body.clone(),
        }
    }

    /// Rebuilds the live draft, mapping the stored kind to its closed const.
    ///
    /// Returns `None` for a kind outside the two result legs, so a tampered
    /// or corrupt spool entry can never append an ad-hoc event.
    fn into_draft(self) -> Option<AuditEventDraft> {
        let kind = match self.kind.as_str() {
            AuditEventKind::RESULT_DAEMON_SUBMITTED => AuditEventKind::RESULT_DAEMON_SUBMITTED,
            AuditEventKind::RESULT_KERNEL_BOUND => AuditEventKind::RESULT_KERNEL_BOUND,
            _ => return None,
        };
        Some(AuditEventDraft {
            kind,
            lineage: self.lineage,
            body: self.body,
        })
    }
}

/// Durable pre-persist evidence for the two result legs of one operation.
///
/// Written fsync-sealed before the ORS completion it anticipates, cleared
/// once both legs append to the chain. Reconcile replays a surviving entry
/// only against a validated ORS original in `ResultReceived` with matching
/// request/result digests; anything else (no record, no completion, digest
/// mismatch) drops the entry without appending, so the chain never carries
/// a binding the ORS record does not prove.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PendingResultBinding {
    /// Canonical format version.
    format_version: u16,
    /// Spooled operation identity (validated again at reconcile).
    operation_id: String,
    /// Request digest the ORS original must carry.
    request_digest: String,
    /// Result digest the ORS completion must carry.
    result_digest: String,
    /// `result.daemon_submitted` evidence, appended first when missing.
    submitted: SpooledAuditDraft,
    /// `result.kernel_bound` evidence; `durable_state` refreshes from ORS.
    bound: SpooledAuditDraft,
}

impl PendingResultBinding {
    /// Returns whether the entry carries this format and both result legs.
    fn is_well_formed(&self) -> bool {
        self.format_version == KERNEL_AUDIT_FORMAT_VERSION
            && !self.operation_id.trim().is_empty()
            && !self.request_digest.trim().is_empty()
            && !self.result_digest.trim().is_empty()
            && self.submitted.kind == AuditEventKind::RESULT_DAEMON_SUBMITTED
            && self.bound.kind == AuditEventKind::RESULT_KERNEL_BOUND
    }
}

/// One sequenced durable audit record: closed kind, full I16.3 lineage,
/// BLAKE3 previous/current link, and full-capture assurance.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditRecord {
    /// Canonical format version.
    pub format_version: u16,
    /// Chain identity: BLAKE3 identity minted from the genesis record.
    pub chain_id: String,
    /// 1-based sequence number; doubles as the I16.3 event cursor.
    pub seq: u64,
    /// BLAKE3 current hash of the previous record (genesis zeros at 1).
    pub prev_hash: String,
    /// Closed canonical event kind.
    pub kind: String,
    /// Composite run trace context with missing-field declarations.
    pub lineage: AuditLineage,
    /// BLAKE3 digest of the canonical event body.
    pub event_digest: String,
    /// Digest/identity-only event detail.
    pub event_body: serde_json::Value,
    /// I16.9 assurance class derived from the kind.
    pub assurance: AuditAssuranceClass,
    /// Capture mode: always full.
    pub capture_mode: AuditCaptureMode,
    /// Wall-clock milliseconds when the boundary appended the record.
    pub emitted_at_ms: u64,
    /// BLAKE3 over the canonical bytes of every field above.
    pub current_hash: String,
}

/// Hash-covered record view: every field except `current_hash`.
#[derive(Serialize)]
struct AuditRecordHashView<'a> {
    format_version: u16,
    chain_id: &'a str,
    seq: u64,
    prev_hash: &'a str,
    kind: &'a str,
    lineage: &'a AuditLineage,
    event_digest: &'a str,
    event_body: &'a serde_json::Value,
    assurance: AuditAssuranceClass,
    capture_mode: AuditCaptureMode,
    emitted_at_ms: u64,
}

impl AuditRecord {
    /// Returns the canonical bytes covered by `current_hash`.
    fn signing_bytes(&self) -> Result<Vec<u8>, KernelAuditError> {
        let view = AuditRecordHashView {
            format_version: self.format_version,
            chain_id: &self.chain_id,
            seq: self.seq,
            prev_hash: &self.prev_hash,
            kind: &self.kind,
            lineage: &self.lineage,
            event_digest: &self.event_digest,
            event_body: &self.event_body,
            assurance: self.assurance,
            capture_mode: self.capture_mode,
            emitted_at_ms: self.emitted_at_ms,
        };
        canonical_json_bytes(&view)
            .map_err(|error| KernelAuditError::Serialization(error.to_string()))
    }

    /// Recomputes the current hash from the record's own fields.
    fn recomputed_hash(&self) -> Result<String, KernelAuditError> {
        Ok(blake3_hex(&self.signing_bytes()?))
    }
}

/// One periodic digest anchor over a chain prefix (A13.8/I16.10).
///
/// The anchor stores the head digest and sequence, never semantic memory.
/// Anchors chain through `prev_anchor_hash` so a missing anchor export is
/// detectable; the anchor proves history continuity, not semantic truth.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditAnchor {
    /// Canonical format version.
    pub format_version: u16,
    /// Chain identity the anchor covers.
    pub chain_id: String,
    /// Covered prefix head sequence.
    pub head_seq: u64,
    /// Current hash of the covered head record.
    pub head_hash: String,
    /// Digest of the previous anchor (genesis zeros for the first).
    pub prev_anchor_hash: String,
    /// Covered record count (`head_seq` for a gapless chain).
    pub record_count: u64,
    /// Wall-clock milliseconds when the anchor was exported.
    pub exported_at_ms: u64,
    /// BLAKE3 over the canonical bytes of every field above.
    pub anchor_digest: String,
}

/// Hash-covered anchor view: every field except `anchor_digest`.
#[derive(Serialize)]
struct AuditAnchorHashView<'a> {
    format_version: u16,
    chain_id: &'a str,
    head_seq: u64,
    head_hash: &'a str,
    prev_anchor_hash: &'a str,
    record_count: u64,
    exported_at_ms: u64,
}

impl AuditAnchor {
    /// Returns the canonical bytes covered by `anchor_digest`.
    fn signing_bytes(&self) -> Result<Vec<u8>, KernelAuditError> {
        let view = AuditAnchorHashView {
            format_version: self.format_version,
            chain_id: &self.chain_id,
            head_seq: self.head_seq,
            head_hash: &self.head_hash,
            prev_anchor_hash: &self.prev_anchor_hash,
            record_count: self.record_count,
            exported_at_ms: self.exported_at_ms,
        };
        canonical_json_bytes(&view)
            .map_err(|error| KernelAuditError::Serialization(error.to_string()))
    }

    /// Recomputes the anchor digest from the anchor's own fields.
    fn recomputed_digest(&self) -> Result<String, KernelAuditError> {
        Ok(blake3_hex(&self.signing_bytes()?))
    }

    /// Returns the stable anchor file name for one head sequence.
    #[must_use]
    pub fn file_name(head_seq: u64) -> String {
        format!("anchor-{head_seq:010}.json")
    }
}

/// Verified chain shape: a gapless, hash-linked prefix.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ChainVerification {
    /// Chain identity of the verified prefix.
    pub chain_id_hash_prefix: [u8; 8],
    /// Verified record count.
    pub record_count: u64,
    /// Verified head sequence.
    pub head_seq: u64,
}

/// The single Kernel-owned durable audit chain.
///
/// Owns the one append handle for `<work-root>/kernel-audit/audit-events.jsonl`
/// plus the one anchor sink. Exactly one handle exists per composition;
/// every boundary appends through it. `open` replays and verifies the full
/// retained chain, so a Kernel restart resumes — or fails closed on —
/// the exact persisted history.
pub struct KernelAuditChain {
    chain_path: PathBuf,
    anchor_dir: PathBuf,
    file: File,
    chain_id: String,
    head_seq: u64,
    head_hash: String,
    prev_anchor_hash: String,
}

impl KernelAuditChain {
    /// Opens (or creates) the durable chain below the canonical work root.
    ///
    /// Replays and verifies every retained record; any gap, digest, linkage,
    /// or chain-identity mismatch fails closed. Resumes the anchor hash from
    /// the latest retained anchor file when one verifies.
    ///
    /// # Errors
    ///
    /// Returns [`KernelAuditError`] when the root is not an absolute
    /// existing directory, when storage fails, or when retained history
    /// does not verify.
    pub fn open(work_root: &Path) -> Result<Self, KernelAuditError> {
        if !work_root.is_absolute() {
            return Err(KernelAuditError::NotAbsoluteRoot);
        }
        if !work_root.is_dir() {
            return Err(KernelAuditError::NotDirectory);
        }
        let audit_dir = kernel_audit_dir(work_root);
        let chain_path = kernel_audit_chain_path(work_root);
        let anchor_dir = kernel_audit_anchor_dir(work_root);
        let pending_dir = audit_dir.join(KERNEL_AUDIT_PENDING_DIR_NAME);
        for dir in [&audit_dir, &anchor_dir, &pending_dir] {
            std::fs::create_dir_all(dir).map_err(|error| KernelAuditError::Io {
                path: dir.clone(),
                reason: error.to_string(),
            })?;
        }
        let retained = if chain_path.exists() {
            Self::read_chain_file(&chain_path)?
        } else {
            Vec::new()
        };
        let (chain_id, head_seq, head_hash) = match retained.last() {
            Some(head) => (head.chain_id.clone(), head.seq, head.current_hash.clone()),
            None => (String::new(), 0, KERNEL_AUDIT_GENESIS_PREV_HASH.to_owned()),
        };
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&chain_path)
            .map_err(|error| KernelAuditError::Io {
                path: chain_path.clone(),
                reason: error.to_string(),
            })?;
        let mut chain = Self {
            chain_path,
            anchor_dir,
            file,
            chain_id,
            head_seq,
            head_hash,
            prev_anchor_hash: KERNEL_AUDIT_GENESIS_ANCHOR_HASH.to_owned(),
        };
        chain.resume_anchor_hash()?;
        Ok(chain)
    }

    /// Points the single anchor sink at a Host-injected Watchdog-domain dir.
    ///
    /// I16.10 requires the periodic digest anchor to be copied to the
    /// Watchdog failure domain, so the bound directory is proved physically
    /// separate from the chain it anchors before it becomes the sink: a sink
    /// equal to or below the Kernel work root is rejected rather than
    /// silently collapsing back to the same-domain default. Both sides are
    /// canonicalized first so the containment check cannot be defeated by
    /// Windows path casing or a non-canonical declared root.
    ///
    /// # Errors
    ///
    /// Returns [`KernelAuditError::NotDirectory`] when the bound directory is
    /// not readable, [`KernelAuditError::Io`] when either side cannot be
    /// canonicalized, [`KernelAuditError::AnchorMismatch`] when the bound
    /// directory lies inside the Kernel work root, and any error from
    /// resuming the retained anchor hash. The Kernel never creates the
    /// foreign directory.
    pub fn set_anchor_sink(
        &mut self,
        binding: &AuditAnchorBinding,
        kernel_work_root: &Path,
    ) -> Result<(), KernelAuditError> {
        if !binding.dir().is_dir() {
            return Err(KernelAuditError::NotDirectory);
        }
        let anchor_dir =
            std::fs::canonicalize(binding.dir()).map_err(|error| KernelAuditError::Io {
                path: binding.dir().to_path_buf(),
                reason: error.to_string(),
            })?;
        let work_root =
            std::fs::canonicalize(kernel_work_root).map_err(|error| KernelAuditError::Io {
                path: kernel_work_root.to_path_buf(),
                reason: error.to_string(),
            })?;
        if anchor_dir.starts_with(&work_root) {
            return Err(KernelAuditError::AnchorMismatch {
                reason: "anchor_sink_inside_kernel_work_root",
            });
        }
        self.anchor_dir = binding.dir().to_path_buf();
        self.resume_anchor_hash()
    }

    /// Returns the chain identity (empty before the genesis append).
    #[must_use]
    pub fn chain_id(&self) -> &str {
        &self.chain_id
    }

    /// Returns the head sequence (0 before the genesis append).
    #[must_use]
    pub const fn head_seq(&self) -> u64 {
        self.head_seq
    }

    /// Returns the head current hash (genesis zeros before genesis).
    #[must_use]
    pub fn head_hash(&self) -> &str {
        &self.head_hash
    }

    /// Returns the chain file path.
    #[must_use]
    pub fn chain_path(&self) -> &Path {
        &self.chain_path
    }

    /// Returns the active anchor sink directory.
    #[must_use]
    pub fn anchor_dir(&self) -> &Path {
        &self.anchor_dir
    }

    /// Appends one event as the next sequenced record (fsync per append).
    ///
    /// Seals the I16.3 cursor/version slots, computes missing-field
    /// declarations, links the BLAKE3 previous/current hashes, persists one
    /// canonical-JSON line, and runs the periodic anchor export when due.
    /// A failed periodic export stays visible through the anchor terminal
    /// without failing the append.
    ///
    /// # Errors
    ///
    /// Returns [`KernelAuditError`] for a non-canonical kind, a sequence
    /// overflow, canonicalization failure, or a failed durable write.
    pub fn append(
        &mut self,
        draft: AuditEventDraft,
        emitted_at_ms: u64,
    ) -> Result<AuditRecord, KernelAuditError> {
        if !AuditEventKind::is_canonical(draft.kind) {
            return Err(KernelAuditError::UnknownEventKind(draft.kind.to_owned()));
        }
        let seq = self.head_seq.checked_add(1).ok_or(KernelAuditError::Io {
            path: self.chain_path.clone(),
            reason: "audit sequence overflow".to_owned(),
        })?;
        let mut lineage = draft.lineage;
        lineage.finalize(seq);
        let body_bytes = canonical_json_bytes(&draft.body)
            .map_err(|error| KernelAuditError::Serialization(error.to_string()))?;
        let mut record = AuditRecord {
            format_version: KERNEL_AUDIT_FORMAT_VERSION,
            chain_id: self.chain_id.clone(),
            seq,
            prev_hash: self.head_hash.clone(),
            kind: draft.kind.to_owned(),
            lineage,
            event_digest: blake3_hex(&body_bytes),
            event_body: draft.body,
            assurance: AuditEventKind::assurance_class(draft.kind),
            capture_mode: AuditCaptureMode::Full,
            emitted_at_ms,
            current_hash: String::new(),
        };
        if seq == 1 {
            record.chain_id = String::new();
        }
        record.current_hash = record.recomputed_hash()?;
        if seq == 1 {
            record.chain_id.clone_from(&record.current_hash);
            record.current_hash = record.recomputed_hash()?;
            self.chain_id.clone_from(&record.chain_id);
        }
        let line = canonical_json_bytes(&record)
            .map_err(|error| KernelAuditError::Serialization(error.to_string()))?;
        self.file
            .write_all(&line)
            .and_then(|()| self.file.write_all(b"\n"))
            .and_then(|()| self.file.sync_all())
            .map_err(|error| KernelAuditError::Io {
                path: self.chain_path.clone(),
                reason: error.to_string(),
            })?;
        self.head_seq = seq;
        self.head_hash.clone_from(&record.current_hash);
        if seq % KERNEL_AUDIT_ANCHOR_INTERVAL_RECORDS == 0
            && let Err(error) = self.export_anchor(emitted_at_ms)
        {
            crate::kernel_diagnostics::observe_terminal_error(KERNEL_AUDIT_ANCHOR_TERMINAL_CODE);
            let _ = error;
        }
        Ok(record)
    }

    /// Reads and verifies the full retained chain in sequence order.
    ///
    /// # Errors
    ///
    /// Returns [`KernelAuditError`] when the chain file cannot be read or
    /// any record fails sequence, digest, linkage, or identity checks.
    pub fn records(&self) -> Result<Vec<AuditRecord>, KernelAuditError> {
        Self::read_chain_file(&self.chain_path)
    }

    /// Verifies the full retained chain and returns its verified shape.
    ///
    /// # Errors
    ///
    /// Returns [`KernelAuditError`] when verification fails.
    pub fn verify_chain(&self) -> Result<ChainVerification, KernelAuditError> {
        let records = self.records()?;
        let mut prefix = [0u8; 8];
        if let Some(head) = records.last() {
            let bytes = head.chain_id.as_bytes();
            let take = bytes.len().min(8);
            prefix[..take].copy_from_slice(&bytes[..take]);
        }
        Ok(ChainVerification {
            chain_id_hash_prefix: prefix,
            record_count: records.len() as u64,
            head_seq: records.last().map_or(0, |head| head.seq),
        })
    }

    /// Exports a digest anchor over the current head to the anchor sink.
    ///
    /// Writes `anchor-<head_seq>.json` plus the stable `latest-anchor.json`
    /// pointer (atomic rename), fsyncs the anchor file, and advances the
    /// anchor hash chain.
    ///
    /// # Errors
    ///
    /// Returns [`KernelAuditError`] when the chain is empty or the sink
    /// write fails.
    pub fn export_anchor(&mut self, exported_at_ms: u64) -> Result<AuditAnchor, KernelAuditError> {
        if self.head_seq == 0 {
            return Err(KernelAuditError::EmptyChain);
        }
        let mut anchor = AuditAnchor {
            format_version: KERNEL_AUDIT_FORMAT_VERSION,
            chain_id: self.chain_id.clone(),
            head_seq: self.head_seq,
            head_hash: self.head_hash.clone(),
            prev_anchor_hash: self.prev_anchor_hash.clone(),
            record_count: self.head_seq,
            exported_at_ms,
            anchor_digest: String::new(),
        };
        anchor.anchor_digest = anchor.recomputed_digest()?;
        let bytes = canonical_json_bytes(&anchor)
            .map_err(|error| KernelAuditError::Serialization(error.to_string()))?;
        let path = self.anchor_dir.join(AuditAnchor::file_name(self.head_seq));
        Self::write_sync(&path, &bytes)?;
        let staging = self.anchor_dir.join("latest-anchor.json.staging");
        Self::write_sync(&staging, &bytes)?;
        std::fs::rename(
            &staging,
            self.anchor_dir.join(KERNEL_AUDIT_LATEST_ANCHOR_FILE_NAME),
        )
        .map_err(|error| KernelAuditError::Io {
            path: self.anchor_dir.clone(),
            reason: error.to_string(),
        })?;
        self.prev_anchor_hash.clone_from(&anchor.anchor_digest);
        Ok(anchor)
    }

    /// Verifies one anchor against its chain prefix.
    ///
    /// Replays records `1..=head_seq`, rechecks every sequence, digest,
    /// linkage, and identity field, then compares the covered head, count,
    /// and anchor self-digest.
    ///
    /// # Errors
    ///
    /// Returns [`KernelAuditError`] when any check fails.
    pub fn verify_anchor(&self, anchor: &AuditAnchor) -> Result<(), KernelAuditError> {
        if anchor.format_version != KERNEL_AUDIT_FORMAT_VERSION {
            return Err(KernelAuditError::AnchorMismatch {
                reason: "format_version",
            });
        }
        if anchor.recomputed_digest()? != anchor.anchor_digest {
            return Err(KernelAuditError::AnchorMismatch {
                reason: "anchor_digest",
            });
        }
        let records = self.records()?;
        if anchor.head_seq == 0 || anchor.record_count != anchor.head_seq {
            return Err(KernelAuditError::AnchorMismatch {
                reason: "anchor_prefix",
            });
        }
        if (records.len() as u64) < anchor.head_seq {
            return Err(KernelAuditError::AnchorMismatch {
                reason: "prefix_unavailable",
            });
        }
        let Some(head) = records.iter().find(|record| record.seq == anchor.head_seq) else {
            return Err(KernelAuditError::AnchorMismatch { reason: "head_seq" });
        };
        if head.chain_id != anchor.chain_id || head.current_hash != anchor.head_hash {
            return Err(KernelAuditError::AnchorMismatch { reason: "head" });
        }
        Ok(())
    }

    /// Reads one anchor file and checks its self-digest.
    ///
    /// # Errors
    ///
    /// Returns [`KernelAuditError`] when the file cannot be read, parsed,
    /// or its self-digest mismatches.
    pub fn read_anchor(path: &Path) -> Result<AuditAnchor, KernelAuditError> {
        let bytes = std::fs::read(path).map_err(|error| KernelAuditError::Io {
            path: path.to_path_buf(),
            reason: error.to_string(),
        })?;
        let anchor: AuditAnchor =
            serde_json::from_slice(&bytes).map_err(|error| KernelAuditError::Io {
                path: path.to_path_buf(),
                reason: error.to_string(),
            })?;
        if anchor.recomputed_digest()? != anchor.anchor_digest {
            return Err(KernelAuditError::AnchorMismatch {
                reason: "anchor_digest",
            });
        }
        Ok(anchor)
    }

    /// Returns the durable spool directory for pending result bindings.
    fn pending_dir(&self) -> PathBuf {
        let mut dir = self.chain_path.clone();
        dir.pop();
        dir.join(KERNEL_AUDIT_PENDING_DIR_NAME)
    }

    /// Returns the deterministic spool path for one operation.
    ///
    /// The name is a BLAKE3 of the operation identity: operation identities
    /// carry builder-chosen separators that are not filename-safe.
    fn pending_binding_path(&self, operation_id: &str) -> PathBuf {
        self.pending_dir().join(format!(
            "pending-{}.json",
            blake3_hex(operation_id.as_bytes())
        ))
    }

    /// Spools one pending binding durably (staging write, fsync, rename).
    ///
    /// # Errors
    ///
    /// Returns [`KernelAuditError`] when the spool directory or file cannot
    /// be written durably.
    fn spool_pending_binding(&self, entry: &PendingResultBinding) -> Result<(), KernelAuditError> {
        let dir = self.pending_dir();
        std::fs::create_dir_all(&dir).map_err(|error| KernelAuditError::Io {
            path: dir.clone(),
            reason: error.to_string(),
        })?;
        let bytes = canonical_json_bytes(entry)
            .map_err(|error| KernelAuditError::Serialization(error.to_string()))?;
        let path = self.pending_binding_path(&entry.operation_id);
        let staging = path.with_extension("json.staging");
        Self::write_sync(&staging, &bytes)?;
        // The spool name is deterministic per operation, and Windows rename
        // fails over an existing destination, so a retry removes its own
        // prior entry before publishing the replacement.
        let _ = std::fs::remove_file(&path);
        std::fs::rename(&staging, &path).map_err(|error| KernelAuditError::Io {
            path: path.clone(),
            reason: error.to_string(),
        })
    }

    /// Drops the pending spool entry for one operation, if any.
    ///
    /// Best-effort: a surviving entry is harmless because reconcile
    /// re-checks the chain before appending anything.
    fn clear_pending_binding(&self, operation_id: &str) {
        let _ = std::fs::remove_file(self.pending_binding_path(operation_id));
    }

    /// Loads every pending binding entry, keeping per-entry failures.
    ///
    /// Staging files carry no `.json` suffix and are skipped: they are
    /// either mid-write or orphaned by a crash, and the next spool for
    /// their operation overwrites them.
    ///
    /// # Errors
    ///
    /// Returns [`KernelAuditError`] when the spool directory cannot be read.
    fn load_pending_bindings(
        &self,
    ) -> Result<Vec<Result<PendingResultBinding, KernelAuditError>>, KernelAuditError> {
        let dir = self.pending_dir();
        let entries = std::fs::read_dir(&dir).map_err(|error| KernelAuditError::Io {
            path: dir.clone(),
            reason: error.to_string(),
        })?;
        let mut pending = Vec::new();
        for entry in entries {
            let entry = entry.map_err(|error| KernelAuditError::Io {
                path: dir.clone(),
                reason: error.to_string(),
            })?;
            let path = entry.path();
            let name = entry.file_name().to_string_lossy().into_owned();
            let is_spool_entry =
                name.starts_with("pending-") && path.extension().is_some_and(|ext| ext == "json");
            if !is_spool_entry {
                continue;
            }
            let bytes = match std::fs::read(&path) {
                Ok(bytes) => bytes,
                Err(error) => {
                    pending.push(Err(KernelAuditError::Io {
                        path,
                        reason: error.to_string(),
                    }));
                    continue;
                }
            };
            match serde_json::from_slice(&bytes) {
                Ok(entry) => pending.push(Ok(entry)),
                Err(error) => pending.push(Err(KernelAuditError::Io {
                    path,
                    reason: error.to_string(),
                })),
            }
        }
        Ok(pending)
    }

    fn write_sync(path: &Path, bytes: &[u8]) -> Result<(), KernelAuditError> {
        let mut file = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(path)
            .map_err(|error| KernelAuditError::Io {
                path: path.to_path_buf(),
                reason: error.to_string(),
            })?;
        file.write_all(bytes)
            .and_then(|()| file.sync_all())
            .map_err(|error| KernelAuditError::Io {
                path: path.to_path_buf(),
                reason: error.to_string(),
            })
    }

    fn resume_anchor_hash(&mut self) -> Result<(), KernelAuditError> {
        let mut latest: Option<(u64, String)> = None;
        let entries =
            std::fs::read_dir(&self.anchor_dir).map_err(|error| KernelAuditError::Io {
                path: self.anchor_dir.clone(),
                reason: error.to_string(),
            })?;
        for entry in entries {
            let entry = entry.map_err(|error| KernelAuditError::Io {
                path: self.anchor_dir.clone(),
                reason: error.to_string(),
            })?;
            let name = entry.file_name().to_string_lossy().into_owned();
            let Some(rest) = name
                .strip_prefix("anchor-")
                .and_then(|rest| rest.strip_suffix(".json"))
            else {
                continue;
            };
            let Ok(seq) = rest.parse::<u64>() else {
                continue;
            };
            let anchor = Self::read_anchor(&entry.path())?;
            if anchor.head_seq != seq {
                return Err(KernelAuditError::AnchorMismatch {
                    reason: "anchor_file_name",
                });
            }
            if latest.as_ref().is_none_or(|(best, _)| seq > *best) {
                latest = Some((seq, anchor.anchor_digest.clone()));
            }
        }
        if let Some((_, digest)) = latest {
            self.prev_anchor_hash = digest;
        }
        Ok(())
    }

    /// Reads, parses, and fully verifies one chain file in order.
    fn read_chain_file(path: &Path) -> Result<Vec<AuditRecord>, KernelAuditError> {
        let file =
            OpenOptions::new()
                .read(true)
                .open(path)
                .map_err(|error| KernelAuditError::Io {
                    path: path.to_path_buf(),
                    reason: error.to_string(),
                })?;
        let mut records = Vec::new();
        let mut expected_prev = KERNEL_AUDIT_GENESIS_PREV_HASH.to_owned();
        let mut chain_id: Option<String> = None;
        for (index, line) in BufReader::new(file).lines().enumerate() {
            let line_number = index as u64 + 1;
            let line = line.map_err(|error| KernelAuditError::Io {
                path: path.to_path_buf(),
                reason: error.to_string(),
            })?;
            if line.trim().is_empty() {
                return Err(KernelAuditError::ChainCorrupt {
                    line: line_number,
                    reason: "blank_line",
                });
            }
            let record: AuditRecord =
                serde_json::from_str(&line).map_err(|_| KernelAuditError::ChainCorrupt {
                    line: line_number,
                    reason: "unparseable_record",
                })?;
            if record.format_version != KERNEL_AUDIT_FORMAT_VERSION {
                return Err(KernelAuditError::ChainCorrupt {
                    line: line_number,
                    reason: "format_version",
                });
            }
            if record.seq != line_number {
                return Err(KernelAuditError::ChainCorrupt {
                    line: line_number,
                    reason: "sequence_gap",
                });
            }
            if record.prev_hash != expected_prev {
                return Err(KernelAuditError::ChainCorrupt {
                    line: line_number,
                    reason: "prev_link",
                });
            }
            if !AuditEventKind::is_canonical(&record.kind) {
                return Err(KernelAuditError::ChainCorrupt {
                    line: line_number,
                    reason: "event_kind",
                });
            }
            if record.recomputed_hash()? != record.current_hash {
                return Err(KernelAuditError::ChainCorrupt {
                    line: line_number,
                    reason: "current_hash",
                });
            }
            match &chain_id {
                Some(known) if known != &record.chain_id => {
                    return Err(KernelAuditError::ChainCorrupt {
                        line: line_number,
                        reason: "chain_id",
                    });
                }
                Some(_) => {}
                None => chain_id = Some(record.chain_id.clone()),
            }
            expected_prev.clone_from(&record.current_hash);
            records.push(record);
        }
        Ok(records)
    }
}

/// Returns whether the chain already carries one result-leg record.
///
/// Compares by content: closed kind, operation identity, and result digest.
fn chain_has_result_record(
    records: &[AuditRecord],
    kind: &str,
    operation_id: &str,
    result_digest: &str,
) -> bool {
    records.iter().any(|record| {
        record.kind == kind
            && record.lineage.operation_id.as_deref() == Some(operation_id)
            && record
                .event_body
                .get("result_digest")
                .and_then(serde_json::Value::as_str)
                == Some(result_digest)
    })
}

/// Appends one spooled leg unless the chain already carries it.
///
/// Returns `true` when the leg is present afterwards. Returns `false` —
/// after emitting the stable `KERNEL_AUDIT_APPEND_FAILED` terminal — when
/// the leg can neither be rebuilt nor appended; the caller keeps the spool
/// for the next pass.
fn append_missing_result_leg(
    chain: &mut KernelAuditChain,
    records: &[AuditRecord],
    spooled: SpooledAuditDraft,
    operation_id: &str,
    result_digest: &str,
    now: u64,
) -> bool {
    let Some(draft) = spooled.into_draft() else {
        crate::kernel_diagnostics::observe_terminal_error(KERNEL_AUDIT_APPEND_TERMINAL_CODE);
        return false;
    };
    if chain_has_result_record(records, draft.kind, operation_id, result_digest) {
        return true;
    }
    if chain.append(draft, now).is_err() {
        crate::kernel_diagnostics::observe_terminal_error(KERNEL_AUDIT_APPEND_TERMINAL_CODE);
        return false;
    }
    true
}

impl crate::KernelComposition {
    /// Returns the Kernel's currently admitted authority fence, if readable.
    ///
    /// Best-effort like every observation: `None` on a poisoned policy lock.
    /// Trigger drafts fence themselves with this authority so the
    /// Diagnostic Brief compiler can attribute them (I16.7); a `None` here
    /// yields the previous fenceless record shape, never a refusal.
    pub(crate) fn current_state_fence(&self) -> Option<StateFence> {
        self.front_door_policy
            .lock()
            .ok()
            .map(|policy| policy.module_generation.state_fence.clone())
    }

    /// Observes one audit event through the I16.11 fallback cascade.
    ///
    /// Uniform observational posture: best-effort, never changes an
    /// authority decision. The draft runs the composition's single chain
    /// first and then the single audit fallback (issue #1840): a failed
    /// append is retained in the audit spool, else the last-resort
    /// channel, else the visible control-loss state. Every chain failure
    /// still emits the stable `KERNEL_AUDIT_APPEND_FAILED` terminal plus
    /// the cascade retention code (I16.11: silent success is forbidden).
    /// Lock order is chain-then-fallback, matching reconciliation.
    pub(crate) fn audit_observe(&self, draft: AuditEventDraft) -> Option<AuditRecord> {
        let now = crate::unix_ms();
        let Ok(mut chain) = self.kernel_audit.lock() else {
            crate::kernel_diagnostics::observe_terminal_error(KERNEL_AUDIT_APPEND_TERMINAL_CODE);
            return None;
        };
        let Ok(mut fallback) = self.audit_fallback.lock() else {
            if let Ok(record) = chain.append(draft, now) {
                return Some(record);
            }
            crate::kernel_diagnostics::observe_terminal_error(KERNEL_AUDIT_APPEND_TERMINAL_CODE);
            return None;
        };
        match fallback.observe(&mut chain, draft, now) {
            crate::audit_fallback::AuditFallbackOutcome::Appended(record) => Some(record),
            outcome => {
                crate::kernel_diagnostics::observe_terminal_error(
                    KERNEL_AUDIT_APPEND_TERMINAL_CODE,
                );
                if let Some(code) = outcome.retention_code() {
                    crate::kernel_diagnostics::observe_terminal_error(code);
                }
                None
            }
        }
    }

    /// Spools both result-leg drafts durably ahead of the ORS completion.
    ///
    /// I16.11 cascade, second leg: the binding record can only append after
    /// the completion it evidences, so its evidence (plus the submission
    /// leg's) is fsync-sealed first. Best-effort like every observation: a
    /// failed spool emits the stable `KERNEL_AUDIT_APPEND_FAILED` terminal
    /// without changing the submit decision.
    pub(crate) fn spool_pending_result_binding(
        &self,
        submitted: &AuditEventDraft,
        bound: &AuditEventDraft,
        operation_id: &str,
        request_digest: &str,
        result_digest: &str,
    ) {
        let entry = PendingResultBinding {
            format_version: KERNEL_AUDIT_FORMAT_VERSION,
            operation_id: operation_id.to_owned(),
            request_digest: request_digest.to_owned(),
            result_digest: result_digest.to_owned(),
            submitted: SpooledAuditDraft::of(submitted),
            bound: SpooledAuditDraft::of(bound),
        };
        let Ok(chain) = self.kernel_audit.lock() else {
            crate::kernel_diagnostics::observe_terminal_error(KERNEL_AUDIT_APPEND_TERMINAL_CODE);
            return;
        };
        if chain.spool_pending_binding(&entry).is_err() {
            crate::kernel_diagnostics::observe_terminal_error(KERNEL_AUDIT_APPEND_TERMINAL_CODE);
        }
    }

    /// Drops the pending spool entry once both result legs are sealed.
    ///
    /// Best-effort: a surviving entry is harmless because reconcile
    /// re-checks the chain before appending anything.
    pub(crate) fn clear_pending_result_binding(&self, operation_id: &str) {
        if let Ok(chain) = self.kernel_audit.lock() {
            chain.clear_pending_binding(operation_id);
        }
    }

    /// Reconciles the pending-result spool against validated ORS state.
    ///
    /// I16.11 cascade, healing leg: every surviving spool entry replays
    /// only against its validated ORS original (see
    /// `reconcile_pending_entry`). Never fails: healing must not break
    /// chain reads.
    fn reconcile_pending_result_bindings(&self) {
        let pending = {
            let Ok(chain) = self.kernel_audit.lock() else {
                return;
            };
            let Ok(pending) = chain.load_pending_bindings() else {
                crate::kernel_diagnostics::observe_terminal_error(
                    KERNEL_AUDIT_APPEND_TERMINAL_CODE,
                );
                return;
            };
            pending
        };
        for entry in pending {
            self.reconcile_pending_entry(entry);
        }
    }

    /// Reconciles one spool entry against its validated ORS original.
    ///
    /// Compares receipts by content: a completed (`ResultReceived`) record
    /// with matching request/result digests completes the chain with the
    /// legs it still lacks, in causal order (submission before binding);
    /// the binding `durable_state` refreshes from the ORS original. No
    /// record, no completion, or a digest mismatch drops the entry without
    /// appending — the chain never carries a binding the ORS record does
    /// not prove. Corrupt entries and failed appends stay visible through
    /// the stable `KERNEL_AUDIT_APPEND_FAILED` terminal and keep their
    /// spool file for the next pass.
    fn reconcile_pending_entry(&self, entry: Result<PendingResultBinding, KernelAuditError>) {
        let entry = match entry {
            Ok(entry) if entry.is_well_formed() => entry,
            _ => {
                crate::kernel_diagnostics::observe_terminal_error(
                    KERNEL_AUDIT_APPEND_TERMINAL_CODE,
                );
                return;
            }
        };
        let Ok(operation_id) = OperationIdentity::new(entry.operation_id.as_str()) else {
            crate::kernel_diagnostics::observe_terminal_error(KERNEL_AUDIT_APPEND_TERMINAL_CODE);
            return;
        };
        // The audit lock is never held across ORS IO: load and compare the
        // validated original first, then take the lock only for the
        // duplicate check and the ordered appends.
        let Ok(stored) = self
            .generation_gateway
            .ors
            .load_host_request(&operation_id, &entry.request_digest)
        else {
            return;
        };
        let Some(stored) = stored else {
            self.clear_pending_result_binding(&entry.operation_id);
            return;
        };
        if stored.request_digest != entry.request_digest {
            crate::kernel_diagnostics::observe_terminal_error(KERNEL_AUDIT_APPEND_TERMINAL_CODE);
            self.clear_pending_result_binding(&entry.operation_id);
            return;
        }
        if stored.state != HostRequestState::ResultReceived {
            self.clear_pending_result_binding(&entry.operation_id);
            return;
        }
        if stored.result_digest.as_deref() != Some(entry.result_digest.as_str()) {
            crate::kernel_diagnostics::observe_terminal_error(KERNEL_AUDIT_APPEND_TERMINAL_CODE);
            self.clear_pending_result_binding(&entry.operation_id);
            return;
        }
        let PendingResultBinding {
            operation_id,
            result_digest,
            submitted,
            mut bound,
            ..
        } = entry;
        let Some(body) = bound.body.as_object_mut() else {
            crate::kernel_diagnostics::observe_terminal_error(KERNEL_AUDIT_APPEND_TERMINAL_CODE);
            return;
        };
        body.insert(
            "durable_state".to_owned(),
            serde_json::Value::String(format!("{:?}", stored.state)),
        );
        let Ok(mut chain) = self.kernel_audit.lock() else {
            crate::kernel_diagnostics::observe_terminal_error(KERNEL_AUDIT_APPEND_TERMINAL_CODE);
            return;
        };
        let Ok(records) = chain.records() else {
            crate::kernel_diagnostics::observe_terminal_error(KERNEL_AUDIT_APPEND_TERMINAL_CODE);
            return;
        };
        let now = crate::unix_ms();
        if !append_missing_result_leg(
            &mut chain,
            &records,
            submitted,
            &operation_id,
            &result_digest,
            now,
        ) {
            return;
        }
        if !append_missing_result_leg(
            &mut chain,
            &records,
            bound,
            &operation_id,
            &result_digest,
            now,
        ) {
            return;
        }
        drop(chain);
        self.clear_pending_result_binding(&operation_id);
    }

    /// Reads and verifies the full retained audit chain in order.
    ///
    /// Reconciles the I16.11 pending-result spool first: a completed result
    /// always yields its full ordered chain here, even when a crash or a
    /// failed append orphaned its spool entry. Healing is best-effort and
    /// never fails the read.
    ///
    /// # Errors
    ///
    /// Returns [`KernelAuditError`] when the lock is poisoned or the
    /// retained chain does not verify.
    pub fn audit_chain_records(&self) -> Result<Vec<AuditRecord>, KernelAuditError> {
        self.reconcile_pending_result_bindings();
        self.kernel_audit
            .lock()
            .map_err(|_| KernelAuditError::LockPoisoned)?
            .records()
    }

    /// Verifies the full retained audit chain.
    ///
    /// # Errors
    ///
    /// Returns [`KernelAuditError`] when the lock is poisoned or
    /// verification fails.
    pub fn verify_audit_chain(&self) -> Result<ChainVerification, KernelAuditError> {
        self.kernel_audit
            .lock()
            .map_err(|_| KernelAuditError::LockPoisoned)?
            .verify_chain()
    }

    /// Exports a digest anchor over the current head to the anchor sink.
    ///
    /// Best-effort like every observation: a failed export emits the
    /// stable `KERNEL_AUDIT_ANCHOR_FAILED` terminal and returns `None`.
    pub fn export_audit_anchor(&self) -> Option<AuditAnchor> {
        let now = crate::unix_ms();
        let Ok(mut chain) = self.kernel_audit.lock() else {
            crate::kernel_diagnostics::observe_terminal_error(KERNEL_AUDIT_ANCHOR_TERMINAL_CODE);
            return None;
        };
        if let Ok(anchor) = chain.export_anchor(now) {
            Some(anchor)
        } else {
            crate::kernel_diagnostics::observe_terminal_error(KERNEL_AUDIT_ANCHOR_TERMINAL_CODE);
            None
        }
    }

    /// Verifies one anchor file against its retained chain prefix.
    ///
    /// # Errors
    ///
    /// Returns [`KernelAuditError`] when the lock is poisoned, the file
    /// cannot be read, or the anchor does not verify.
    pub fn verify_audit_anchor_file(&self, path: &Path) -> Result<(), KernelAuditError> {
        let anchor = KernelAuditChain::read_anchor(path)?;
        self.kernel_audit
            .lock()
            .map_err(|_| KernelAuditError::LockPoisoned)?
            .verify_anchor(&anchor)
    }

    /// Returns the current audit head (`seq`, `current_hash`).
    pub fn audit_head(&self) -> Option<(u64, String)> {
        self.kernel_audit.lock().ok().map(|chain| {
            let head_seq = chain.head_seq();
            let head_hash = chain.head_hash().to_owned();
            (head_seq, head_hash)
        })
    }

    /// Reconciles spooled audit records into canonical state (issue #1840).
    ///
    /// Best-effort like every observation: lock order is chain-then-
    /// fallback, matching the observe path. Returns `None` when either
    /// lock is poisoned.
    pub fn reconcile_audit_spool(&self) -> Option<crate::audit_fallback::AuditReconcileReport> {
        let now = crate::unix_ms();
        let mut chain = self.kernel_audit.lock().ok()?;
        let mut fallback = self.audit_fallback.lock().ok()?;
        Some(fallback.reconcile(&mut chain, now))
    }

    /// Counts spool records still awaiting reconciliation.
    pub fn audit_spool_pending(&self) -> u64 {
        self.audit_fallback
            .lock()
            .map_or(0, |fallback| fallback.pending_spool_records())
    }

    /// Returns the control-loss counters (`total`, `held`).
    pub fn audit_control_loss(&self) -> (u64, usize) {
        self.audit_fallback.lock().map_or((0, 0), |fallback| {
            (fallback.control_loss_total(), fallback.held_control_loss())
        })
    }
}
