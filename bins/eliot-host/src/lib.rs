//! Production Host composition root.
//!
//! Host is the outer Windows lifecycle owner. It opens the crash-safe Host
//! journal under the installation's durable data root, keeps approved
//! generations separate from semantic state, and owns independent Job Object
//! branches for Kernel and the canonical store dependency.

#![forbid(unsafe_code)]
#![allow(
    dead_code,
    reason = "windows-only helpers are live on Windows; allow for cross-platform check"
)]

/// Host-owned I1.5 activation / demand-start / idle-drain orchestration over
/// the crash-safe `HostStateJournal`.
#[cfg(windows)]
pub mod activation_lifecycle;
/// Backup configuration evidence projection (B-BACKUP-HOST-PREP #958).
pub mod backup_config_projection;
/// Host-owned installation post-restore cutover (#961).
#[cfg(windows)]
pub mod backup_cutover;
/// Host-owned isolated backup destination preparation (B-BACKUP-HOST-PREP #958).
pub mod backup_preparation;
mod credential_control;
#[cfg(windows)]
mod host_activation_durable;
#[cfg(windows)]
mod host_composition_phase_b;
#[cfg(windows)]
mod host_composition_store_recovery;
mod host_composition_validation;
/// Host structured diagnostics facade (F-LOG-HOST-0, #889): compiled
/// once here and imported by the binary; later leaves extend through their
/// own serialized turns, never a second copy.
pub mod host_diagnostics;
mod host_job_launch;
/// Authenticated Kernel ORS introduction readback for cutover evidence
/// (issue #961, F-AUR-1).
#[cfg(windows)]
mod introduction_readback;
#[cfg(windows)]
mod launch_artifact;
#[cfg(windows)]
mod launch_descriptor_validation;
mod launch_options;
/// Exact-generation lease census and retirement admission (#1751 Host
/// owner, consumed by #961 cutover).
#[cfg(windows)]
mod lease_drain;
#[cfg(windows)]
mod reactive_context_delivery;
mod scm_launch;
mod store_kernel_launch_sequence;
/// Host Windows Event Log sink seam (F-LOG-HOST-0, #889): thin bounded
/// wrapper over #984's accepted safe port; typed delivery outcomes, fixed
/// source/event/severity mapping only, never FFI inside Host.
pub mod windows_event_log;

// F-LOG-HOST-1 (#891) lifecycle/SCM observation helpers.
//
// Through the #889 facade only (`host_diagnostics::observe_entrypoint`,
// `observe_entrypoint_with_detail`, `observe_terminal_error`); sink status is
// the live `windows_event_log::event_log_sink_status` answer: `Ok` where
// #984's accepted safe port is live (Windows), typed `EventLogUnavailable`
// elsewhere. Delivery goes through `report_local_event` (landed `bf37d3e1` /
// #1706; synchronous, per-call handle, receipt proves OS acceptance only).
//
// Observation-only contract: every helper projects facts already produced by
// the semantic owner. Arguments are static literals or borrows of
// already-owned identities; no helper computes new digests, opens handles,
// evaluates side-effectful values, acquires locks, or branches the semantic
// result. Sink outcome never alters result/order/status/cleanup. There is no
// mutable global dedup cache: one terminal emission per failed public
// operation is enforced by the single outermost guard per operation, while
// inner phase observations share correlation by stage order only.
pub use host_diagnostics::note_event_log_sink_status;

fn host_lifecycle_observe_requested(boundary: &'static HostLifecycleBoundary) {
    note_event_log_sink_status();
    host_diagnostics::observe_entrypoint_with_detail(
        host_diagnostics::EntrypointStage::Startup,
        host_lifecycle_frozen_event(boundary),
    );
}

fn host_lifecycle_observe_scm(boundary: &'static HostLifecycleBoundary) {
    note_event_log_sink_status();
    host_diagnostics::observe_entrypoint_with_detail(
        host_diagnostics::EntrypointStage::ScmDispatch,
        host_lifecycle_frozen_event(boundary),
    );
}

fn host_lifecycle_observe_drain(boundary: &'static HostLifecycleBoundary) {
    note_event_log_sink_status();
    host_diagnostics::observe_entrypoint_with_detail(
        host_diagnostics::EntrypointStage::ShutdownDrain,
        host_lifecycle_frozen_event(boundary),
    );
}

fn host_lifecycle_observe_terminal(boundary: &'static HostLifecycleBoundary) {
    note_event_log_sink_status();
    host_diagnostics::observe_terminal_error(host_lifecycle_frozen_event(boundary));
}

/// Single-terminal guard for one public fallible operation.
///
/// Armed on entry; the single outermost boundary disarms on success. Any
/// `Err` return (explicit or via `?`) drops armed and emits exactly one
/// terminal record with the operation's frozen code. Emitting here never
/// changes the `Result`: the guard only observes the already-produced
/// outcome. No dedup cache, no lock, no second evaluation.
struct HostTerminalGuard {
    boundary: &'static HostLifecycleBoundary,
    armed: bool,
}

impl HostTerminalGuard {
    fn armed(boundary: &'static HostLifecycleBoundary) -> Self {
        Self {
            boundary,
            armed: true,
        }
    }

    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for HostTerminalGuard {
    fn drop(&mut self) {
        if self.armed {
            host_lifecycle_observe_terminal(self.boundary);
        }
    }
}

/// One frozen lib.rs lifecycle/error boundary (F-LOG-HOST-1, #891 W1).
///
/// Each row binds the W1 contract for one boundary: the source item/span
/// (`source_item`, an item path that survives line drift), the
/// operation/phase (`name`, `operation.phase`), the available owner
/// identities/state/receipt (`owner_state`), the selected emitted event or
/// the exact propagated-to-boundary reason (`event`), the external
/// production caller (`caller`), and the proving test (`test`: a landed
/// starter probe or a TEST-PHASE case number).
struct HostLifecycleBoundary {
    /// Frozen boundary name (`operation.phase`).
    name: &'static str,
    /// Source item owning the boundary (type/function path).
    source_item: &'static str,
    /// Owner identities/state/receipt available at the boundary.
    owner_state: &'static str,
    /// Selected emitted event, or the exact propagated-to-boundary reason
    /// (prefixed `propagated:`) when another boundary owns the emission.
    event: &'static str,
    /// External production caller of the boundary.
    caller: &'static str,
    /// Proving test (landed probe or TEST-PHASE case).
    test: &'static str,
}

/// Frozen finite table of lib.rs lifecycle/error boundaries (#891 W1).
///
/// This is the single source of emitted boundary vocabulary by construction:
/// every production observation selects its static row through a `BOUNDARY_*`
/// identifier, and [`host_lifecycle_frozen_event`] returns that row's frozen
/// `event` spelling. There is no string lookup and no fallback, so an
/// unlisted spelling cannot reach production: [`boundary_by_event`] fails the
/// build, and the uniqueness assertions below reject duplicate rows.
/// Rows whose `event` starts with
/// `propagated:` own no emission; they record exactly where the emission
/// lives instead of duplicating it, per the child-coordination rule.
///
/// Three terminal rows spell their code via `concat!` so this source keeps
/// exactly the literal counts pinned by the landed probes (single stop
/// site, dual restart-unknown sites, single credential-control site);
/// the concatenated value is byte-identical to the frozen code.
const HOST_LIFECYCLE_BOUNDARY_TABLE: &[HostLifecycleBoundary] = &[
    HostLifecycleBoundary {
        name: "jobs.requested",
        source_item: "HostJobBranches::new",
        owner_state: "HostInstallationEpoch/job identity",
        event: "host.jobs requested",
        caller: "HostComposition::open",
        test: "891/case-9",
    },
    HostLifecycleBoundary {
        name: "jobs.admitted",
        source_item: "HostJobBranches::new",
        owner_state: "HostInstallationEpoch/job handles",
        event: "host.jobs admitted",
        caller: "HostComposition::open",
        test: "891/case-9",
    },
    HostLifecycleBoundary {
        name: "jobs-fenced.requested",
        source_item: "HostJobBranches::new_fenced",
        owner_state: "HostInstallationEpoch/fenced identity",
        event: "host.jobs-fenced requested",
        caller: "HostComposition::open",
        test: "891/case-17",
    },
    HostLifecycleBoundary {
        name: "jobs-fenced.admitted",
        source_item: "HostJobBranches::new_fenced",
        owner_state: "HostInstallationEpoch/fenced identity",
        event: "host.jobs-fenced admitted",
        caller: "HostComposition::open",
        test: "891/case-17",
    },
    HostLifecycleBoundary {
        name: "branch-reconcile.requested",
        source_item: "HostJobBranches::reconcile",
        owner_state: "branch liveness/disposition",
        event: "host.branch-reconcile requested",
        caller: "HostComposition::reconcile_approved_contour",
        test: "891/case-13",
    },
    HostLifecycleBoundary {
        name: "kernel-terminate.requested",
        source_item: "HostJobBranches::terminate_kernel",
        owner_state: "kernel job branch",
        event: "host.kernel-terminate requested",
        caller: "HostComposition::stop",
        test: "891/case-6",
    },
    HostLifecycleBoundary {
        name: "kernel-terminate.stopped",
        source_item: "HostJobBranches::terminate_kernel",
        owner_state: "kernel job branch terminated",
        event: "host.kernel-terminate stopped",
        caller: "HostComposition::stop",
        test: "891/case-6",
    },
    HostLifecycleBoundary {
        name: "store-terminate.requested",
        source_item: "HostJobBranches::terminate_store",
        owner_state: "store job branch",
        event: "host.store-terminate requested",
        caller: "HostComposition::stop",
        test: "891/case-6",
    },
    HostLifecycleBoundary {
        name: "store-terminate.stopped",
        source_item: "HostJobBranches::terminate_store",
        owner_state: "store job branch terminated",
        event: "host.store-terminate stopped",
        caller: "HostComposition::stop",
        test: "891/case-6",
    },
    HostLifecycleBoundary {
        name: "cutover-rollback.requested",
        source_item: "HostJobBranches::cutover_with_rollback",
        owner_state: "candidate/prior generations and artifacts",
        event: "host.cutover-rollback requested",
        caller: "none (cutover_generation unwired)",
        test: "891/case-11",
    },
    HostLifecycleBoundary {
        name: "cutover-rollback.restored",
        source_item: "HostJobBranches::cutover_with_rollback",
        owner_state: "prior contour relaunched",
        event: "host.cutover-rollback restored",
        caller: "none (cutover_generation unwired)",
        test: "891/case-11",
    },
    HostLifecycleBoundary {
        name: "cutover-rollback.reactivated",
        source_item: "HostComposition::cutover_generation",
        owner_state: "prior generation/registry/observations",
        event: "host.cutover-rollback reactivated",
        caller: "none (cutover_generation unwired)",
        test: "891/case-11",
    },
    HostLifecycleBoundary {
        name: "open.requested",
        source_item: "HostComposition::open",
        owner_state: "launch options/epoch",
        event: "host.open requested",
        caller: "main::open_host",
        test: "891/case-2",
    },
    HostLifecycleBoundary {
        name: "open.terminal",
        source_item: "HostComposition::open",
        owner_state: "HostInstallationEpoch/owner lease",
        event: "host-open-failed",
        caller: "main::open_host",
        test: "891/case-14",
    },
    HostLifecycleBoundary {
        name: "open.fenced-store-recovery",
        source_item: "HostComposition::open",
        owner_state: "store-recovery fence",
        event: "host.open fenced store-recovery",
        caller: "main::open_host",
        test: "891/case-17",
    },
    HostLifecycleBoundary {
        name: "open.fenced-bridge-stage",
        source_item: "HostComposition::open",
        owner_state: "bridge-stage crash carrier",
        event: "host.open fenced bridge-stage",
        caller: "main::open_host",
        test: "891/case-17",
    },
    HostLifecycleBoundary {
        name: "open.degraded-prepared-without-receipt",
        source_item: "HostComposition::open",
        owner_state: "prepared materialization without receipt",
        event: "host.open degraded prepared-without-receipt",
        caller: "main::open_host",
        test: "891/case-17",
    },
    HostLifecycleBoundary {
        name: "open.fenced-store-recovery-active",
        source_item: "HostComposition::open",
        owner_state: "store-recovery fence on active contour",
        event: "host.open fenced store-recovery-active",
        caller: "main::open_host",
        test: "891/case-17",
    },
    HostLifecycleBoundary {
        name: "open.admitted",
        source_item: "HostComposition::open",
        owner_state: "durable evidence/owner lease",
        event: "host.open admitted",
        caller: "main::open_host",
        test: "891/case-2",
    },
    HostLifecycleBoundary {
        name: "credential-control.requested",
        source_item: "HostComposition::credential_control",
        owner_state: "owner lease credential capability",
        event: "host.credential-control requested",
        caller: "main::service_main",
        test: "891/case-4",
    },
    HostLifecycleBoundary {
        name: "credential-control.terminal",
        source_item: "HostComposition::credential_control",
        owner_state: "owner lease credential capability",
        event: concat!("host-credential-", "control-failed"),
        caller: "main::service_main",
        test: "891/case-14",
    },
    HostLifecycleBoundary {
        name: "credential-control.admitted-receipt",
        source_item: "HostComposition::credential_control",
        owner_state: "control handle, identities only",
        event: "host.credential-control admitted receipt",
        caller: "main::service_main",
        test: "891/case-4",
    },
    HostLifecycleBoundary {
        name: "phase-b.requested",
        source_item: "HostComposition::handle_phase_b_request",
        owner_state: "materialization intent/credential receipt",
        event: "host.phase-b requested",
        caller: "main::process_phase_b_requests",
        test: "891/case-4",
    },
    HostLifecycleBoundary {
        name: "phase-b.unknown-store-recovery-fence",
        source_item: "HostComposition::handle_phase_b_request",
        owner_state: "store-recovery fence/pending ref",
        event: "host.phase-b unknown store-recovery-fence",
        caller: "main::process_phase_b_requests",
        test: "891/case-5",
    },
    HostLifecycleBoundary {
        name: "phase-b.terminal",
        source_item: "HostComposition::handle_phase_b_request",
        owner_state: "materialization intent/pending ref",
        event: "host-phase-b-unknown",
        caller: "main::process_phase_b_requests",
        test: "891/case-14",
    },
    HostLifecycleBoundary {
        name: "phase-b.prepared-receipt",
        source_item: "HostComposition::handle_phase_b_request",
        owner_state: "prepared receipt/transaction intent",
        event: "host.phase-b prepared receipt",
        caller: "main::process_phase_b_requests",
        test: "891/case-4",
    },
    HostLifecycleBoundary {
        name: "phase-b.unknown",
        source_item: "HostComposition::handle_phase_b_request",
        owner_state: "materialization intent/pending ref",
        event: "host.phase-b unknown",
        caller: "main::process_phase_b_requests",
        test: "891/case-5",
    },
    HostLifecycleBoundary {
        name: "phase-b-finalize.requested",
        source_item: "HostComposition::finalize_phase_b_request",
        owner_state: "materialization intent/receipt",
        event: "host.phase-b-finalize requested",
        caller: "main::process_phase_b_requests",
        test: "891/case-4",
    },
    HostLifecycleBoundary {
        name: "phase-b-finalize.ready-completion",
        source_item: "HostComposition::finalize_phase_b_request",
        owner_state: "finalize completion receipt",
        event: "host.phase-b-finalize ready completion",
        caller: "main::process_phase_b_requests",
        test: "891/case-4",
    },
    HostLifecycleBoundary {
        name: "phase-b-finalize.unknown",
        source_item: "HostComposition::finalize_phase_b_request",
        owner_state: "materialization intent/pending ref",
        event: "host.phase-b-finalize unknown",
        caller: "main::process_phase_b_requests",
        test: "891/case-5",
    },
    HostLifecycleBoundary {
        name: "phase-b-finalize.terminal",
        source_item: "HostComposition::finalize_phase_b_request",
        owner_state: "materialization intent/pending ref",
        event: "host-phase-b-finalize-unknown",
        caller: "main::process_phase_b_requests",
        test: "891/case-14",
    },
    HostLifecycleBoundary {
        name: "phase-b-reconcile.requested",
        source_item: "HostComposition::reconcile_phase_b_request",
        owner_state: "materialization intent/durable state",
        event: "host.phase-b-reconcile requested",
        caller: "main::process_phase_b_requests",
        test: "891/case-13",
    },
    HostLifecycleBoundary {
        name: "phase-b-reconcile.unknown-store-recovery-fence",
        source_item: "HostComposition::reconcile_phase_b_request",
        owner_state: "store-recovery fence/pending ref",
        event: "host.phase-b-reconcile unknown store-recovery-fence",
        caller: "main::process_phase_b_requests",
        test: "891/case-13",
    },
    HostLifecycleBoundary {
        name: "phase-b-reconcile.terminal",
        source_item: "HostComposition::reconcile_phase_b_request",
        owner_state: "materialization intent/pending ref",
        event: "host-phase-b-reconcile-unknown",
        caller: "main::process_phase_b_requests",
        test: "891/case-14",
    },
    HostLifecycleBoundary {
        name: "phase-b-reconcile.prepared-readback-replay",
        source_item: "HostComposition::reconcile_phase_b_request",
        owner_state: "prepared readback, query-only",
        event: "host.phase-b-reconcile prepared readback replay",
        caller: "main::process_phase_b_requests",
        test: "891/case-14",
    },
    HostLifecycleBoundary {
        name: "phase-b-reconcile.receipt-readback-replay",
        source_item: "HostComposition::reconcile_phase_b_request",
        owner_state: "receipt readback, query-only",
        event: "host.phase-b-reconcile receipt readback replay",
        caller: "main::process_phase_b_requests",
        test: "891/case-14",
    },
    HostLifecycleBoundary {
        name: "phase-b-reconcile.unknown",
        source_item: "HostComposition::reconcile_phase_b_request",
        owner_state: "materialization intent/pending ref",
        event: "host.phase-b-reconcile unknown",
        caller: "main::process_phase_b_requests",
        test: "891/case-13",
    },
    HostLifecycleBoundary {
        name: "runtime-control.requested",
        source_item: "HostComposition::runtime_control",
        owner_state: "owner lease activation capability",
        event: "host.runtime-control requested",
        caller: "main::service_main",
        test: "891/case-4",
    },
    HostLifecycleBoundary {
        name: "runtime-control.terminal",
        source_item: "HostComposition::runtime_control",
        owner_state: "owner lease activation capability",
        event: "host-runtime-control-failed",
        caller: "main::service_main",
        test: "891/case-14",
    },
    HostLifecycleBoundary {
        name: "runtime-control.admitted-receipt",
        source_item: "HostComposition::runtime_control",
        owner_state: "control handle/queues",
        event: "host.runtime-control admitted receipt",
        caller: "main::service_main",
        test: "891/case-4",
    },
    HostLifecycleBoundary {
        name: "user-automation.owner-requested",
        source_item: "HostComposition::process_user_automation_requests",
        owner_state: "kernel owner/execution queue",
        event: "host.user-automation owner requested",
        caller: "main::process_user_automation_request/process_user_automation_owner_requests",
        test: "891/case-4",
    },
    HostLifecycleBoundary {
        name: "kernel-restart.requested",
        source_item: "HostComposition::handle_kernel_restart_request",
        owner_state: "request/mutation digest",
        event: "host.kernel-restart requested",
        caller: "main::process_runtime_control_requests",
        test: "891/T-B",
    },
    HostLifecycleBoundary {
        name: "kernel-restart.reconcile-delegated-readback",
        source_item: "HostComposition::handle_kernel_restart_request",
        owner_state: "existing restart receipt",
        event: "host.kernel-restart reconcile-delegated readback",
        caller: "main::process_runtime_control_requests",
        test: "891/T-B",
    },
    HostLifecycleBoundary {
        name: "kernel-restart.unknown-owner-fenced",
        source_item: "HostComposition::handle_kernel_restart_request",
        owner_state: "owner fence/pending ref",
        event: "host.kernel-restart unknown owner-fenced",
        caller: "main::process_runtime_control_requests",
        test: "891/T-B",
    },
    HostLifecycleBoundary {
        name: "kernel-restart.terminal",
        source_item: "HostComposition::handle_kernel_restart_request",
        owner_state: "request/pending ref",
        event: concat!("host-kernel-restart-", "unknown"),
        caller: "main::process_runtime_control_requests",
        test: "891/T-B",
    },
    HostLifecycleBoundary {
        name: "kernel-restart.receipt-completion",
        source_item: "HostComposition::handle_kernel_restart_request",
        owner_state: "restart receipt",
        event: "host.kernel-restart receipt completion",
        caller: "main::process_runtime_control_requests",
        test: "891/T-B",
    },
    HostLifecycleBoundary {
        name: "kernel-restart.unknown",
        source_item: "HostComposition::handle_kernel_restart_request",
        owner_state: "request/pending ref",
        event: "host.kernel-restart unknown",
        caller: "main::process_runtime_control_requests",
        test: "891/T-B",
    },
    HostLifecycleBoundary {
        name: "kernel-restart-reconcile.requested",
        source_item: "HostComposition::reconcile_kernel_restart_request",
        owner_state: "request/mutation digest",
        event: "host.kernel-restart-reconcile requested",
        caller: "HostComposition::handle_kernel_restart_request",
        test: "891/T-B",
    },
    HostLifecycleBoundary {
        name: "kernel-restart-reconcile.unknown-owner-fenced",
        source_item: "HostComposition::reconcile_kernel_restart_request",
        owner_state: "owner fence/pending ref",
        event: "host.kernel-restart-reconcile unknown owner-fenced",
        caller: "HostComposition::handle_kernel_restart_request",
        test: "891/T-B",
    },
    HostLifecycleBoundary {
        name: "kernel-restart-reconcile.unknown-validation",
        source_item: "HostComposition::reconcile_kernel_restart_request",
        owner_state: "request/pending ref",
        event: "host.kernel-restart-reconcile unknown validation",
        caller: "HostComposition::handle_kernel_restart_request",
        test: "891/T-B",
    },
    HostLifecycleBoundary {
        name: "kernel-restart-reconcile.receipt-readback-replay",
        source_item: "HostComposition::reconcile_kernel_restart_request",
        owner_state: "restart receipt, query-only",
        event: "host.kernel-restart-reconcile receipt readback replay",
        caller: "HostComposition::handle_kernel_restart_request",
        test: "891/T-B",
    },
    HostLifecycleBoundary {
        name: "kernel-restart-reconcile.unknown-conflict",
        source_item: "HostComposition::reconcile_kernel_restart_request",
        owner_state: "conflicting receipt/pending ref",
        event: "host.kernel-restart-reconcile unknown conflict",
        caller: "HostComposition::handle_kernel_restart_request",
        test: "891/T-B",
    },
    HostLifecycleBoundary {
        name: "kernel-restart-reconcile.unknown-pending",
        source_item: "HostComposition::reconcile_kernel_restart_request",
        owner_state: "pending intent, timeout proves nothing",
        event: "host.kernel-restart-reconcile unknown pending",
        caller: "HostComposition::handle_kernel_restart_request",
        test: "891/case-13",
    },
    HostLifecycleBoundary {
        name: "kernel-restart-reconcile.unknown-snapshot",
        source_item: "HostComposition::reconcile_kernel_restart_request",
        owner_state: "journal snapshot/pending ref",
        event: "host.kernel-restart-reconcile unknown snapshot",
        caller: "HostComposition::handle_kernel_restart_request",
        test: "891/T-B",
    },
    HostLifecycleBoundary {
        name: "kernel-restart-reconcile.unknown",
        source_item: "HostComposition::reconcile_kernel_restart_request",
        owner_state: "request/pending ref",
        event: "host.kernel-restart-reconcile unknown",
        caller: "HostComposition::handle_kernel_restart_request",
        test: "891/T-B",
    },
    HostLifecycleBoundary {
        name: "kernel-restart-reconcile.terminal",
        source_item: "HostComposition::reconcile_kernel_restart_request",
        owner_state: "request/pending ref",
        event: "host-kernel-restart-reconcile-unknown",
        caller: "HostComposition::handle_kernel_restart_request",
        test: "891/T-B",
    },
    HostLifecycleBoundary {
        name: "kernel-restart-execute.requested",
        source_item: "HostComposition::execute_kernel_restart",
        owner_state: "request/pending intent",
        event: "host.kernel-restart-execute requested",
        caller: "HostComposition::handle_kernel_restart_request",
        test: "891/case-5",
    },
    HostLifecycleBoundary {
        name: "kernel-restart-execute.receipt",
        source_item: "HostComposition::execute_kernel_restart",
        owner_state: "restart receipt",
        event: "host.kernel-restart-execute receipt",
        caller: "HostComposition::handle_kernel_restart_request",
        test: "891/case-4",
    },
    HostLifecycleBoundary {
        name: "start.requested",
        source_item: "HostComposition::start_approved_contour",
        owner_state: "approved generation/launch descriptor",
        event: "host.start requested",
        caller: "none (exported API; no in-repo caller)",
        test: "891/case-2",
    },
    HostLifecycleBoundary {
        name: "start.terminal",
        source_item: "HostComposition::start_approved_contour",
        owner_state: "approved generation/launch descriptor",
        event: "host-start-failed",
        caller: "none (exported API; no in-repo caller)",
        test: "891/case-14",
    },
    HostLifecycleBoundary {
        name: "start.started",
        source_item: "HostComposition::start_approved_contour",
        owner_state: "launched contour",
        event: "host.start started",
        caller: "none (exported API; no in-repo caller)",
        test: "891/case-2",
    },
    HostLifecycleBoundary {
        name: "resume-pending.requested",
        source_item: "HostComposition::resume_pending_activation_after_phase_b",
        owner_state: "pending activation",
        event: "host.resume-pending requested",
        caller: "HostComposition::open; HostComposition::finalize_phase_b_request",
        test: "891/case-7",
    },
    HostLifecycleBoundary {
        name: "resume-pending.terminal",
        source_item: "HostComposition::resume_pending_activation_after_phase_b",
        owner_state: "pending activation",
        event: "host-resume-pending-failed",
        caller: "HostComposition::open; HostComposition::finalize_phase_b_request",
        test: "891/case-14",
    },
    HostLifecycleBoundary {
        name: "resume-pending.admitted",
        source_item: "HostComposition::resume_pending_activation_after_phase_b",
        owner_state: "resumed activation",
        event: "host.resume-pending admitted",
        caller: "HostComposition::open; HostComposition::finalize_phase_b_request",
        test: "891/case-7",
    },
    HostLifecycleBoundary {
        name: "resume-pending-receipt.requested",
        source_item: "HostComposition::resume_pending_phase_b_receipt",
        owner_state: "pending receipt",
        event: "host.resume-pending-receipt requested",
        caller: "none (unwired)",
        test: "891/case-7",
    },
    HostLifecycleBoundary {
        name: "start-manifest.requested",
        source_item: "HostComposition::start_manifest_contour",
        owner_state: "manifest/branch/pending",
        event: "host.start-manifest requested",
        caller: "HostComposition::open",
        test: "891/case-7",
    },
    HostLifecycleBoundary {
        name: "start-manifest.started",
        source_item: "HostComposition::start_manifest_contour",
        owner_state: "active contour",
        event: "host.start-manifest started",
        caller: "HostComposition::open",
        test: "891/case-7",
    },
    HostLifecycleBoundary {
        name: "liveness.requested",
        source_item: "HostComposition::liveness_tick",
        owner_state: "branch liveness/gate",
        event: "host.liveness requested",
        caller: "main::run_scm_contour_tick",
        test: "891/case-10",
    },
    HostLifecycleBoundary {
        name: "liveness.terminal",
        source_item: "HostComposition::liveness_tick",
        owner_state: "branch liveness/gate",
        event: "host-liveness-failed",
        caller: "main::run_scm_contour_tick",
        test: "891/case-14",
    },
    HostLifecycleBoundary {
        name: "liveness.observed",
        source_item: "HostComposition::liveness_tick",
        owner_state: "observation, never readiness",
        event: "host.liveness observed",
        caller: "main::run_scm_contour_tick",
        test: "891/case-10",
    },
    HostLifecycleBoundary {
        name: "reconcile.requested",
        source_item: "HostComposition::reconcile_approved_contour",
        owner_state: "branch disposition/journal",
        event: "host.reconcile requested",
        caller: "main::run_scm_contour_tick",
        test: "891/case-15",
    },
    HostLifecycleBoundary {
        name: "reconcile.terminal",
        source_item: "HostComposition::reconcile_approved_contour",
        owner_state: "branch disposition/journal",
        event: "host-reconcile-failed",
        caller: "main::run_scm_contour_tick",
        test: "891/case-14",
    },
    HostLifecycleBoundary {
        name: "reconcile.admitted",
        source_item: "HostComposition::reconcile_approved_contour",
        owner_state: "disposition LiveAwaitingReadiness",
        event: "host.reconcile admitted",
        caller: "main::run_scm_contour_tick",
        test: "891/case-15",
    },
    HostLifecycleBoundary {
        name: "readiness.degraded",
        source_item: "HostComposition::reconcile_branch_readiness_at/persist_authenticated_readiness_degradation",
        owner_state: "readiness observations/gaps",
        event: "host.readiness degraded",
        caller: "HostComposition::reconcile_approved_contour",
        test: "891/case-3",
    },
    HostLifecycleBoundary {
        name: "readiness.requested-proof",
        source_item: "HostComposition::reconcile_branch_readiness_at",
        owner_state: "readiness observations",
        event: "host.readiness requested proof",
        caller: "HostComposition::reconcile_approved_contour",
        test: "891/case-3",
    },
    HostLifecycleBoundary {
        name: "readiness.ready-proof",
        source_item: "HostComposition::reconcile_branch_readiness_at",
        owner_state: "authenticated proof",
        event: "host.readiness ready proof",
        caller: "HostComposition::reconcile_approved_contour",
        test: "891/case-3",
    },
    HostLifecycleBoundary {
        name: "readiness-contour.requested",
        source_item: "HostComposition::current_readiness_contour",
        owner_state: "contour probe, never ready alone",
        event: "host.readiness-contour requested",
        caller: "HostComposition::liveness_tick/reconcile_branch_readiness_at",
        test: "891/case-3",
    },
    HostLifecycleBoundary {
        name: "readiness-proof.requested",
        source_item: "HostComposition::persist_fresh_authenticated_readiness",
        owner_state: "fresh readiness observation",
        event: "host.readiness-proof requested",
        caller: "HostComposition::reconcile_branch_readiness_at",
        test: "891/case-3",
    },
    HostLifecycleBoundary {
        name: "readiness-proof.ready",
        source_item: "HostComposition::persist_fresh_authenticated_readiness",
        owner_state: "confirmed proof fence",
        event: "host.readiness-proof ready",
        caller: "HostComposition::reconcile_branch_readiness_at",
        test: "891/case-3",
    },
    HostLifecycleBoundary {
        name: "degraded-observation.requested",
        source_item: "HostComposition::persist_degraded_process_observation",
        owner_state: "coverage gap/process evidence",
        event: "host.degraded-observation requested",
        caller: "HostComposition::reconcile_approved_contour",
        test: "891/case-17",
    },
    HostLifecycleBoundary {
        name: "branch-fence.requested",
        source_item: "HostComposition::has_durable_branch_fence",
        owner_state: "durable fence probe",
        event: "host.branch-fence requested",
        caller: "main::service_main/HostIdleDrainSupervisor::evaluate",
        test: "891/case-13",
    },
    HostLifecycleBoundary {
        name: "cleanup-active.requested",
        source_item: "HostComposition::cleanup_active_kernel_contour",
        owner_state: "active contour/launch error",
        event: "host.cleanup-active requested",
        caller: "HostComposition::start_manifest_contour",
        test: "891/case-8",
    },
    HostLifecycleBoundary {
        name: "cleanup-launched.requested",
        source_item: "HostComposition::cleanup_launched_contour",
        owner_state: "launched contour/launch error",
        event: "host.cleanup-launched requested",
        caller: "HostComposition::start_manifest_contour",
        test: "891/case-8",
    },
    HostLifecycleBoundary {
        name: "stop.requested",
        source_item: "HostComposition::stop",
        owner_state: "activation/drain records",
        event: "host.stop requested",
        caller: "main::dispatch/finish_console_shutdown/service_main",
        test: "891/T-A",
    },
    HostLifecycleBoundary {
        name: "stop.terminal",
        source_item: "HostComposition::stop",
        owner_state: "activation/drain records/owner lease",
        event: concat!("host-", "stop-failed"),
        caller: "main::dispatch/finish_console_shutdown/service_main",
        test: "891/T-A",
    },
    HostLifecycleBoundary {
        name: "stop.cancellation-requested",
        source_item: "HostComposition::stop",
        owner_state: "running activation/SCM stop control",
        event: "host.stop cancellation requested",
        caller: "main::dispatch/finish_console_shutdown/service_main",
        test: "891/case-12",
    },
    HostLifecycleBoundary {
        name: "drain.requested",
        source_item: "HostComposition::stop",
        owner_state: "DrainRecord Requested/drain_generation",
        event: "host.drain requested",
        caller: "HostComposition::stop",
        test: "891/T-A",
    },
    HostLifecycleBoundary {
        name: "drain.draining",
        source_item: "HostComposition::stop",
        owner_state: "DrainRecord Draining/drain_generation",
        event: "host.drain draining",
        caller: "HostComposition::stop",
        test: "891/T-A",
    },
    HostLifecycleBoundary {
        name: "drain.commit",
        source_item: "HostComposition::stop",
        owner_state: "DrainCommitRecord/lease snapshot",
        event: "host.drain commit",
        caller: "HostComposition::stop",
        test: "891/T-A",
    },
    HostLifecycleBoundary {
        name: "stop.stopped-clean-drained",
        source_item: "HostComposition::stop",
        owner_state: "StoppedClean/clean marker",
        event: "host.stop stopped-clean drained",
        caller: "main::dispatch/finish_console_shutdown/service_main",
        test: "891/T-A",
    },
    HostLifecycleBoundary {
        name: "stop.stopped",
        source_item: "HostComposition::stop",
        owner_state: "released lease/stopped contour",
        event: "host.stop stopped",
        caller: "main::dispatch/finish_console_shutdown/service_main",
        test: "891/T-A",
    },
    HostLifecycleBoundary {
        name: "lifecycle-context.requested",
        source_item: "lifecycle_context",
        owner_state: "epoch/operation/process identity",
        event: "host.lifecycle-context requested",
        caller: "HostComposition::start_manifest_contour",
        test: "891/case-15",
    },
    HostLifecycleBoundary {
        name: "lifecycle-context.terminal",
        source_item: "lifecycle_context",
        owner_state: "epoch/operation/process identity",
        event: "host-lifecycle-context-failed",
        caller: "HostComposition::start_manifest_contour",
        test: "891/case-14",
    },
    HostLifecycleBoundary {
        name: "lifecycle-context.admitted",
        source_item: "lifecycle_context",
        owner_state: "RequestMetadata",
        event: "host.lifecycle-context admitted",
        caller: "HostComposition::start_manifest_contour",
        test: "891/case-15",
    },
    HostLifecycleBoundary {
        name: "propagated.phase-b-rollback",
        source_item: "HostComposition::open (rollback decision)",
        owner_state: "pending activation/prepared materialization",
        event: "propagated: emitted by host_composition_phase_b::rollback_uncommitted_phase_b",
        caller: "main::open_host",
        test: "891/case-11",
    },
    HostLifecycleBoundary {
        name: "propagated.activation-transitions",
        source_item: "HostComposition::transition_activation",
        owner_state: "activation record/journal append",
        event: "propagated: inner edges observed at decision boundaries only",
        caller: "HostComposition::stop",
        test: "891/case-7",
    },
    HostLifecycleBoundary {
        name: "propagated.cutover-candidate-arm",
        source_item: "HostComposition::cutover_generation (candidate arm)",
        owner_state: "candidate generation/registry",
        event: "propagated: candidate launch observed at start-manifest boundary",
        caller: "none (cutover_generation unwired)",
        test: "891/case-11",
    },
    HostLifecycleBoundary {
        name: "activation-admission.requested",
        source_item: "HostComposition::activation_admission",
        owner_state: "activation record/generations",
        event: "host.activation-admission requested",
        caller: "main::report_activation_diagnostics",
        test: "891/case-7",
    },
    HostLifecycleBoundary {
        name: "observable-use.terminal",
        source_item: "HostComposition::note_observable_use",
        owner_state: "activation record/drain generation",
        event: "host-observable-use-failed",
        caller: "main::HostIdleDrainSupervisor::note_observable_use",
        test: "891/case-14",
    },
    HostLifecycleBoundary {
        name: "observable-use.coalesced",
        source_item: "HostComposition::note_observable_use",
        owner_state: "drain generation/coalesced trigger",
        event: "host.observable-use coalesced",
        caller: "main::HostIdleDrainSupervisor::note_observable_use",
        test: "891/case-4",
    },
    HostLifecycleBoundary {
        name: "observable-use.drain-cancelled",
        source_item: "HostComposition::note_observable_use",
        owner_state: "drain record/evidence refs",
        event: "host.observable-use drain-cancelled",
        caller: "main::HostIdleDrainSupervisor::note_observable_use",
        test: "891/case-4",
    },
    HostLifecycleBoundary {
        name: "observable-use.next-generation-queued",
        source_item: "HostComposition::note_observable_use",
        owner_state: "drain commit/queued intent",
        event: "host.observable-use next-generation-queued",
        caller: "main::HostIdleDrainSupervisor::note_observable_use",
        test: "891/case-4",
    },
    HostLifecycleBoundary {
        name: "observable-use.replay-already-consumed",
        source_item: "HostComposition::note_observable_use",
        owner_state: "drain record/evidence refs",
        event: "host.observable-use replay-already-consumed",
        caller: "main::HostIdleDrainSupervisor::note_observable_use",
        test: "891/case-4",
    },
    HostLifecycleBoundary {
        name: "drain-resume.terminal",
        source_item: "HostComposition::resume_cancelled_drain",
        owner_state: "activation record/drain disposition",
        event: "host-drain-resume-failed",
        caller: "main::HostIdleDrainSupervisor::observe_readiness",
        test: "891/case-14",
    },
    HostLifecycleBoundary {
        name: "drain-resume.active-restored",
        source_item: "HostComposition::resume_cancelled_drain",
        owner_state: "drain disposition/readiness proof",
        event: "host.drain-resume active-restored",
        caller: "main::HostIdleDrainSupervisor::observe_readiness",
        test: "891/case-8",
    },
    HostLifecycleBoundary {
        name: "idle-drain.terminal",
        source_item: "HostComposition::begin_idle_drain",
        owner_state: "census code/activation record",
        event: "host-idle-drain-begin-failed",
        caller: "main::HostIdleDrainSupervisor::evaluate",
        test: "891/case-14",
    },
    HostLifecycleBoundary {
        name: "idle-drain.drain-failed-blocked",
        source_item: "HostComposition::begin_idle_drain",
        owner_state: "failed drain attempt/census",
        event: "host.idle-drain drain-failed blocked",
        caller: "main::HostIdleDrainSupervisor::evaluate",
        test: "891/case-8",
    },
    HostLifecycleBoundary {
        name: "idle-drain.not-active",
        source_item: "HostComposition::begin_idle_drain",
        owner_state: "activation state/census",
        event: "host.idle-drain not-active",
        caller: "main::HostIdleDrainSupervisor::evaluate",
        test: "891/case-8",
    },
    HostLifecycleBoundary {
        name: "idle-drain.pre-commit-open",
        source_item: "HostComposition::begin_idle_drain",
        owner_state: "drain record/pre-commit",
        event: "host.idle-drain pre-commit open",
        caller: "main::HostIdleDrainSupervisor::evaluate",
        test: "891/case-8",
    },
    HostLifecycleBoundary {
        name: "idle-drain-rearm.not-active",
        source_item: "HostComposition::rearm_cancelled_drain",
        owner_state: "activation state/predecessor",
        event: "host.idle-drain rearm-not-active",
        caller: "HostComposition::begin_idle_drain",
        test: "891/case-8",
    },
    HostLifecycleBoundary {
        name: "idle-drain-rearm.census-not-idle",
        source_item: "HostComposition::rearm_cancelled_drain",
        owner_state: "lease census/predecessor",
        event: "host.idle-drain rearm-census-not-idle",
        caller: "HostComposition::begin_idle_drain",
        test: "891/case-8",
    },
    HostLifecycleBoundary {
        name: "idle-drain-rearm.requested",
        source_item: "HostComposition::rearm_cancelled_drain",
        owner_state: "predecessor drain/census",
        event: "host.idle-drain rearm-requested",
        caller: "HostComposition::begin_idle_drain",
        test: "891/case-8",
    },
    HostLifecycleBoundary {
        name: "lease-census.requested",
        source_item: "HostComposition::idle_lease_census",
        owner_state: "lease refs/supervision obligation",
        event: "host.lease-census requested",
        caller: "main::HostIdleDrainSupervisor::evaluate/HostComposition::rearm_cancelled_drain",
        test: "891/case-8",
    },
    HostLifecycleBoundary {
        name: "wake-revalidation.observed",
        source_item: "HostComposition::revalidate_pending_wakes",
        owner_state: "pending wakes/trigger evidence",
        event: "host.wake-revalidation observed",
        caller: "HostComposition::note_observable_use",
        test: "891/case-13",
    },
    HostLifecycleBoundary {
        name: "wake-satisfy.terminal",
        source_item: "HostComposition::satisfy_claimed_wakes",
        owner_state: "claimed wakes/activation record",
        event: "host-wake-satisfy-failed",
        caller: "main::HostIdleDrainSupervisor::observe_readiness",
        test: "891/case-14",
    },
    HostLifecycleBoundary {
        name: "wake-satisfied.observed",
        source_item: "HostComposition::satisfy_claimed_wakes",
        owner_state: "satisfied wakes/count",
        event: "host.wake-satisfied observed",
        caller: "main::HostIdleDrainSupervisor::observe_readiness",
        test: "891/case-13",
    },
];

/// Compile-time `&str` equality over raw bytes, so boundary lookup
/// can run in `const` context.
const fn boundary_str_eq(a: &str, b: &str) -> bool {
    let a = a.as_bytes();
    let b = b.as_bytes();
    if a.len() != b.len() {
        return false;
    }
    let mut i = 0;
    while i < a.len() {
        if a[i] != b[i] {
            return false;
        }
        i += 1;
    }
    true
}

/// Returns the frozen row for an emitted `event` spelling, or fails
/// the build when the spelling is not listed: unknown vocabulary
/// can never silently enter production observations.
const fn boundary_by_event(event: &str) -> &'static HostLifecycleBoundary {
    let mut i = 0;
    while i < HOST_LIFECYCLE_BOUNDARY_TABLE.len() {
        if boundary_str_eq(HOST_LIFECYCLE_BOUNDARY_TABLE[i].event, event) {
            return &HOST_LIFECYCLE_BOUNDARY_TABLE[i];
        }
        i += 1;
    }
    panic!("unlisted host lifecycle boundary event");
}

/// Compile-time proof that no two rows share an `event` spelling:
/// every observation selects exactly one boundary.
const fn boundary_table_events_unique() -> bool {
    let mut i = 0;
    while i < HOST_LIFECYCLE_BOUNDARY_TABLE.len() {
        let mut j = i + 1;
        while j < HOST_LIFECYCLE_BOUNDARY_TABLE.len() {
            if boundary_str_eq(
                HOST_LIFECYCLE_BOUNDARY_TABLE[i].event,
                HOST_LIFECYCLE_BOUNDARY_TABLE[j].event,
            ) {
                return false;
            }
            j += 1;
        }
        i += 1;
    }
    true
}

/// Compile-time proof that no two rows share a `name`: every
/// `operation.phase` identity is bound once.
const fn boundary_table_names_unique() -> bool {
    let mut i = 0;
    while i < HOST_LIFECYCLE_BOUNDARY_TABLE.len() {
        let mut j = i + 1;
        while j < HOST_LIFECYCLE_BOUNDARY_TABLE.len() {
            if boundary_str_eq(
                HOST_LIFECYCLE_BOUNDARY_TABLE[i].name,
                HOST_LIFECYCLE_BOUNDARY_TABLE[j].name,
            ) {
                return false;
            }
            j += 1;
        }
        i += 1;
    }
    true
}

const _: () = assert!(
    boundary_table_events_unique(),
    "duplicate event spelling in HOST_LIFECYCLE_BOUNDARY_TABLE",
);
const _: () = assert!(
    boundary_table_names_unique(),
    "duplicate name in HOST_LIFECYCLE_BOUNDARY_TABLE",
);

/// Static boundary identifiers: every observation call selects one of
/// these instead of passing a free string, so the emitted `event`,
/// `name`, `source_item`, `owner_state`, `caller` and `test` always
/// come from the exact frozen row.
const BOUNDARY_JOBS_REQUESTED: &HostLifecycleBoundary = boundary_by_event("host.jobs requested");
const BOUNDARY_JOBS_ADMITTED: &HostLifecycleBoundary = boundary_by_event("host.jobs admitted");
const BOUNDARY_JOBS_FENCED_REQUESTED: &HostLifecycleBoundary =
    boundary_by_event("host.jobs-fenced requested");
const BOUNDARY_JOBS_FENCED_ADMITTED: &HostLifecycleBoundary =
    boundary_by_event("host.jobs-fenced admitted");
const BOUNDARY_BRANCH_RECONCILE_REQUESTED: &HostLifecycleBoundary =
    boundary_by_event("host.branch-reconcile requested");
const BOUNDARY_KERNEL_TERMINATE_REQUESTED: &HostLifecycleBoundary =
    boundary_by_event("host.kernel-terminate requested");
const BOUNDARY_KERNEL_TERMINATE_STOPPED: &HostLifecycleBoundary =
    boundary_by_event("host.kernel-terminate stopped");
const BOUNDARY_STORE_TERMINATE_REQUESTED: &HostLifecycleBoundary =
    boundary_by_event("host.store-terminate requested");
const BOUNDARY_STORE_TERMINATE_STOPPED: &HostLifecycleBoundary =
    boundary_by_event("host.store-terminate stopped");
const BOUNDARY_CUTOVER_ROLLBACK_REQUESTED: &HostLifecycleBoundary =
    boundary_by_event("host.cutover-rollback requested");
const BOUNDARY_CUTOVER_ROLLBACK_RESTORED: &HostLifecycleBoundary =
    boundary_by_event("host.cutover-rollback restored");
const BOUNDARY_CUTOVER_ROLLBACK_REACTIVATED: &HostLifecycleBoundary =
    boundary_by_event("host.cutover-rollback reactivated");
const BOUNDARY_OPEN_REQUESTED: &HostLifecycleBoundary = boundary_by_event("host.open requested");
const BOUNDARY_OPEN_TERMINAL: &HostLifecycleBoundary = boundary_by_event("host-open-failed");
const BOUNDARY_OPEN_FENCED_STORE_RECOVERY: &HostLifecycleBoundary =
    boundary_by_event("host.open fenced store-recovery");
const BOUNDARY_OPEN_FENCED_BRIDGE_STAGE: &HostLifecycleBoundary =
    boundary_by_event("host.open fenced bridge-stage");
const BOUNDARY_OPEN_DEGRADED_PREPARED_WITHOUT_RECEIPT: &HostLifecycleBoundary =
    boundary_by_event("host.open degraded prepared-without-receipt");
const BOUNDARY_OPEN_FENCED_STORE_RECOVERY_ACTIVE: &HostLifecycleBoundary =
    boundary_by_event("host.open fenced store-recovery-active");
const BOUNDARY_OPEN_ADMITTED: &HostLifecycleBoundary = boundary_by_event("host.open admitted");
const BOUNDARY_CREDENTIAL_CONTROL_REQUESTED: &HostLifecycleBoundary =
    boundary_by_event("host.credential-control requested");
const BOUNDARY_CREDENTIAL_CONTROL_TERMINAL: &HostLifecycleBoundary =
    boundary_by_event("host-credential-control-failed");
const BOUNDARY_CREDENTIAL_CONTROL_ADMITTED_RECEIPT: &HostLifecycleBoundary =
    boundary_by_event("host.credential-control admitted receipt");
const BOUNDARY_PHASE_B_REQUESTED: &HostLifecycleBoundary =
    boundary_by_event("host.phase-b requested");
const BOUNDARY_PHASE_B_UNKNOWN_STORE_RECOVERY_FENCE: &HostLifecycleBoundary =
    boundary_by_event("host.phase-b unknown store-recovery-fence");
const BOUNDARY_PHASE_B_TERMINAL: &HostLifecycleBoundary = boundary_by_event("host-phase-b-unknown");
const BOUNDARY_PHASE_B_PREPARED_RECEIPT: &HostLifecycleBoundary =
    boundary_by_event("host.phase-b prepared receipt");
const BOUNDARY_PHASE_B_UNKNOWN: &HostLifecycleBoundary = boundary_by_event("host.phase-b unknown");
const BOUNDARY_PHASE_B_FINALIZE_REQUESTED: &HostLifecycleBoundary =
    boundary_by_event("host.phase-b-finalize requested");
const BOUNDARY_PHASE_B_FINALIZE_READY_COMPLETION: &HostLifecycleBoundary =
    boundary_by_event("host.phase-b-finalize ready completion");
const BOUNDARY_PHASE_B_FINALIZE_UNKNOWN: &HostLifecycleBoundary =
    boundary_by_event("host.phase-b-finalize unknown");
const BOUNDARY_PHASE_B_FINALIZE_TERMINAL: &HostLifecycleBoundary =
    boundary_by_event("host-phase-b-finalize-unknown");
const BOUNDARY_PHASE_B_RECONCILE_REQUESTED: &HostLifecycleBoundary =
    boundary_by_event("host.phase-b-reconcile requested");
const BOUNDARY_PHASE_B_RECONCILE_UNKNOWN_STORE_RECOVERY_FENCE: &HostLifecycleBoundary =
    boundary_by_event("host.phase-b-reconcile unknown store-recovery-fence");
const BOUNDARY_PHASE_B_RECONCILE_TERMINAL: &HostLifecycleBoundary =
    boundary_by_event("host-phase-b-reconcile-unknown");
const BOUNDARY_PHASE_B_RECONCILE_PREPARED_READBACK_REPLAY: &HostLifecycleBoundary =
    boundary_by_event("host.phase-b-reconcile prepared readback replay");
const BOUNDARY_PHASE_B_RECONCILE_RECEIPT_READBACK_REPLAY: &HostLifecycleBoundary =
    boundary_by_event("host.phase-b-reconcile receipt readback replay");
const BOUNDARY_PHASE_B_RECONCILE_UNKNOWN: &HostLifecycleBoundary =
    boundary_by_event("host.phase-b-reconcile unknown");
const BOUNDARY_RUNTIME_CONTROL_REQUESTED: &HostLifecycleBoundary =
    boundary_by_event("host.runtime-control requested");
const BOUNDARY_RUNTIME_CONTROL_TERMINAL: &HostLifecycleBoundary =
    boundary_by_event("host-runtime-control-failed");
const BOUNDARY_RUNTIME_CONTROL_ADMITTED_RECEIPT: &HostLifecycleBoundary =
    boundary_by_event("host.runtime-control admitted receipt");
const BOUNDARY_USER_AUTOMATION_OWNER_REQUESTED: &HostLifecycleBoundary =
    boundary_by_event("host.user-automation owner requested");
const BOUNDARY_KERNEL_RESTART_REQUESTED: &HostLifecycleBoundary =
    boundary_by_event("host.kernel-restart requested");
const BOUNDARY_KERNEL_RESTART_RECONCILE_DELEGATED_READBACK: &HostLifecycleBoundary =
    boundary_by_event("host.kernel-restart reconcile-delegated readback");
const BOUNDARY_KERNEL_RESTART_UNKNOWN_OWNER_FENCED: &HostLifecycleBoundary =
    boundary_by_event("host.kernel-restart unknown owner-fenced");
const BOUNDARY_KERNEL_RESTART_TERMINAL: &HostLifecycleBoundary =
    boundary_by_event("host-kernel-restart-unknown");
const BOUNDARY_KERNEL_RESTART_RECEIPT_COMPLETION: &HostLifecycleBoundary =
    boundary_by_event("host.kernel-restart receipt completion");
const BOUNDARY_KERNEL_RESTART_UNKNOWN: &HostLifecycleBoundary =
    boundary_by_event("host.kernel-restart unknown");
const BOUNDARY_KERNEL_RESTART_RECONCILE_REQUESTED: &HostLifecycleBoundary =
    boundary_by_event("host.kernel-restart-reconcile requested");
const BOUNDARY_KERNEL_RESTART_RECONCILE_UNKNOWN_OWNER_FENCED: &HostLifecycleBoundary =
    boundary_by_event("host.kernel-restart-reconcile unknown owner-fenced");
const BOUNDARY_KERNEL_RESTART_RECONCILE_UNKNOWN_VALIDATION: &HostLifecycleBoundary =
    boundary_by_event("host.kernel-restart-reconcile unknown validation");
const BOUNDARY_KERNEL_RESTART_RECONCILE_RECEIPT_READBACK_REPLAY: &HostLifecycleBoundary =
    boundary_by_event("host.kernel-restart-reconcile receipt readback replay");
const BOUNDARY_KERNEL_RESTART_RECONCILE_UNKNOWN_CONFLICT: &HostLifecycleBoundary =
    boundary_by_event("host.kernel-restart-reconcile unknown conflict");
const BOUNDARY_KERNEL_RESTART_RECONCILE_UNKNOWN_PENDING: &HostLifecycleBoundary =
    boundary_by_event("host.kernel-restart-reconcile unknown pending");
const BOUNDARY_KERNEL_RESTART_RECONCILE_UNKNOWN_SNAPSHOT: &HostLifecycleBoundary =
    boundary_by_event("host.kernel-restart-reconcile unknown snapshot");
const BOUNDARY_KERNEL_RESTART_RECONCILE_UNKNOWN: &HostLifecycleBoundary =
    boundary_by_event("host.kernel-restart-reconcile unknown");
const BOUNDARY_KERNEL_RESTART_RECONCILE_TERMINAL: &HostLifecycleBoundary =
    boundary_by_event("host-kernel-restart-reconcile-unknown");
const BOUNDARY_KERNEL_RESTART_EXECUTE_REQUESTED: &HostLifecycleBoundary =
    boundary_by_event("host.kernel-restart-execute requested");
const BOUNDARY_KERNEL_RESTART_EXECUTE_RECEIPT: &HostLifecycleBoundary =
    boundary_by_event("host.kernel-restart-execute receipt");
const BOUNDARY_START_REQUESTED: &HostLifecycleBoundary = boundary_by_event("host.start requested");
const BOUNDARY_START_TERMINAL: &HostLifecycleBoundary = boundary_by_event("host-start-failed");
const BOUNDARY_START_STARTED: &HostLifecycleBoundary = boundary_by_event("host.start started");
const BOUNDARY_RESUME_PENDING_REQUESTED: &HostLifecycleBoundary =
    boundary_by_event("host.resume-pending requested");
const BOUNDARY_RESUME_PENDING_TERMINAL: &HostLifecycleBoundary =
    boundary_by_event("host-resume-pending-failed");
const BOUNDARY_RESUME_PENDING_ADMITTED: &HostLifecycleBoundary =
    boundary_by_event("host.resume-pending admitted");
const BOUNDARY_RESUME_PENDING_RECEIPT_REQUESTED: &HostLifecycleBoundary =
    boundary_by_event("host.resume-pending-receipt requested");
const BOUNDARY_START_MANIFEST_REQUESTED: &HostLifecycleBoundary =
    boundary_by_event("host.start-manifest requested");
const BOUNDARY_START_MANIFEST_STARTED: &HostLifecycleBoundary =
    boundary_by_event("host.start-manifest started");
const BOUNDARY_LIVENESS_REQUESTED: &HostLifecycleBoundary =
    boundary_by_event("host.liveness requested");
const BOUNDARY_LIVENESS_TERMINAL: &HostLifecycleBoundary =
    boundary_by_event("host-liveness-failed");
const BOUNDARY_LIVENESS_OBSERVED: &HostLifecycleBoundary =
    boundary_by_event("host.liveness observed");
const BOUNDARY_RECONCILE_REQUESTED: &HostLifecycleBoundary =
    boundary_by_event("host.reconcile requested");
const BOUNDARY_RECONCILE_TERMINAL: &HostLifecycleBoundary =
    boundary_by_event("host-reconcile-failed");
const BOUNDARY_RECONCILE_ADMITTED: &HostLifecycleBoundary =
    boundary_by_event("host.reconcile admitted");
const BOUNDARY_READINESS_DEGRADED: &HostLifecycleBoundary =
    boundary_by_event("host.readiness degraded");
const BOUNDARY_READINESS_REQUESTED_PROOF: &HostLifecycleBoundary =
    boundary_by_event("host.readiness requested proof");
const BOUNDARY_READINESS_READY_PROOF: &HostLifecycleBoundary =
    boundary_by_event("host.readiness ready proof");
const BOUNDARY_READINESS_CONTOUR_REQUESTED: &HostLifecycleBoundary =
    boundary_by_event("host.readiness-contour requested");
const BOUNDARY_READINESS_PROOF_REQUESTED: &HostLifecycleBoundary =
    boundary_by_event("host.readiness-proof requested");
const BOUNDARY_READINESS_PROOF_READY: &HostLifecycleBoundary =
    boundary_by_event("host.readiness-proof ready");
const BOUNDARY_DEGRADED_OBSERVATION_REQUESTED: &HostLifecycleBoundary =
    boundary_by_event("host.degraded-observation requested");
const BOUNDARY_BRANCH_FENCE_REQUESTED: &HostLifecycleBoundary =
    boundary_by_event("host.branch-fence requested");
const BOUNDARY_CLEANUP_ACTIVE_REQUESTED: &HostLifecycleBoundary =
    boundary_by_event("host.cleanup-active requested");
const BOUNDARY_CLEANUP_LAUNCHED_REQUESTED: &HostLifecycleBoundary =
    boundary_by_event("host.cleanup-launched requested");
const BOUNDARY_STOP_REQUESTED: &HostLifecycleBoundary = boundary_by_event("host.stop requested");
const BOUNDARY_STOP_TERMINAL: &HostLifecycleBoundary = boundary_by_event("host-stop-failed");
const BOUNDARY_STOP_CANCELLATION_REQUESTED: &HostLifecycleBoundary =
    boundary_by_event("host.stop cancellation requested");
const BOUNDARY_DRAIN_REQUESTED: &HostLifecycleBoundary = boundary_by_event("host.drain requested");
const BOUNDARY_DRAIN_DRAINING: &HostLifecycleBoundary = boundary_by_event("host.drain draining");
const BOUNDARY_DRAIN_COMMIT: &HostLifecycleBoundary = boundary_by_event("host.drain commit");
const BOUNDARY_STOP_STOPPED_CLEAN_DRAINED: &HostLifecycleBoundary =
    boundary_by_event("host.stop stopped-clean drained");
const BOUNDARY_STOP_STOPPED: &HostLifecycleBoundary = boundary_by_event("host.stop stopped");
const BOUNDARY_LIFECYCLE_CONTEXT_REQUESTED: &HostLifecycleBoundary =
    boundary_by_event("host.lifecycle-context requested");
const BOUNDARY_LIFECYCLE_CONTEXT_TERMINAL: &HostLifecycleBoundary =
    boundary_by_event("host-lifecycle-context-failed");
const BOUNDARY_LIFECYCLE_CONTEXT_ADMITTED: &HostLifecycleBoundary =
    boundary_by_event("host.lifecycle-context admitted");
const BOUNDARY_ACTIVATION_ADMISSION_REQUESTED: &HostLifecycleBoundary =
    boundary_by_event("host.activation-admission requested");
const BOUNDARY_OBSERVABLE_USE_TERMINAL: &HostLifecycleBoundary =
    boundary_by_event("host-observable-use-failed");
const BOUNDARY_OBSERVABLE_USE_COALESCED: &HostLifecycleBoundary =
    boundary_by_event("host.observable-use coalesced");
const BOUNDARY_OBSERVABLE_USE_DRAIN_CANCELLED: &HostLifecycleBoundary =
    boundary_by_event("host.observable-use drain-cancelled");
const BOUNDARY_OBSERVABLE_USE_NEXT_GENERATION_QUEUED: &HostLifecycleBoundary =
    boundary_by_event("host.observable-use next-generation-queued");
const BOUNDARY_OBSERVABLE_USE_REPLAY_ALREADY_CONSUMED: &HostLifecycleBoundary =
    boundary_by_event("host.observable-use replay-already-consumed");
const BOUNDARY_DRAIN_RESUME_TERMINAL: &HostLifecycleBoundary =
    boundary_by_event("host-drain-resume-failed");
const BOUNDARY_DRAIN_RESUME_ACTIVE_RESTORED: &HostLifecycleBoundary =
    boundary_by_event("host.drain-resume active-restored");
const BOUNDARY_IDLE_DRAIN_TERMINAL: &HostLifecycleBoundary =
    boundary_by_event("host-idle-drain-begin-failed");
const BOUNDARY_IDLE_DRAIN_DRAIN_FAILED_BLOCKED: &HostLifecycleBoundary =
    boundary_by_event("host.idle-drain drain-failed blocked");
const BOUNDARY_IDLE_DRAIN_NOT_ACTIVE: &HostLifecycleBoundary =
    boundary_by_event("host.idle-drain not-active");
const BOUNDARY_IDLE_DRAIN_PRE_COMMIT_OPEN: &HostLifecycleBoundary =
    boundary_by_event("host.idle-drain pre-commit open");
const BOUNDARY_IDLE_DRAIN_REARM_NOT_ACTIVE: &HostLifecycleBoundary =
    boundary_by_event("host.idle-drain rearm-not-active");
const BOUNDARY_IDLE_DRAIN_REARM_CENSUS_NOT_IDLE: &HostLifecycleBoundary =
    boundary_by_event("host.idle-drain rearm-census-not-idle");
const BOUNDARY_IDLE_DRAIN_REARM_REQUESTED: &HostLifecycleBoundary =
    boundary_by_event("host.idle-drain rearm-requested");
const BOUNDARY_LEASE_CENSUS_REQUESTED: &HostLifecycleBoundary =
    boundary_by_event("host.lease-census requested");
const BOUNDARY_WAKE_REVALIDATION_OBSERVED: &HostLifecycleBoundary =
    boundary_by_event("host.wake-revalidation observed");
const BOUNDARY_WAKE_SATISFY_TERMINAL: &HostLifecycleBoundary =
    boundary_by_event("host-wake-satisfy-failed");
const BOUNDARY_WAKE_SATISFIED_OBSERVED: &HostLifecycleBoundary =
    boundary_by_event("host.wake-satisfied observed");
/// Returns the frozen `event` spelling for the selected boundary row.
///
/// Every production observation passes its static [`HOST_LIFECYCLE_BOUNDARY_TABLE`]
/// row, so the table is the single source of emitted boundary vocabulary by
/// construction: there is no string lookup and no fallback an unlisted
/// spelling could pass through.
fn host_lifecycle_frozen_event(boundary: &'static HostLifecycleBoundary) -> &'static str {
    boundary.event
}

pub use credential_control::{HostCredentialControl, HostPhaseBRequest, HostPhaseBRequestQueue};
pub use eliot_host_control_endpoint::{
    HOST_RUNTIME_CONTROL_PIPE, HostRuntimeControl, HostRuntimeControlQueue,
    HostUserAutomationExecutionEnvelope, HostUserAutomationExecutionQueue,
    UserAutomationHostExecutionEndpoint, UserAutomationHostExecutionRequest,
    UserAutomationHostExecutionResponse, UserAutomationRuntimeError, pop_user_automation_execution,
    process_user_automation_execution_queue, reject_unbound_user_automation_execution,
};
use eliot_host_service::runtime_control::runtime_control_unknown_ref;
pub use eliot_host_service::runtime_control::{
    HostKernelRestartReceipt, HostRuntimeControlOperation, HostRuntimeControlRequest,
    HostRuntimeControlResponse, HostStoreRecoveryReceipt,
};
#[cfg(windows)]
use launch_artifact::{
    LaunchLease, approved_locator, approved_phase_b_destination_locator, open_launch_lease,
    verify_launch_digest,
};
#[cfg(all(test, windows))]
use launch_descriptor_validation::verify_host_artifact_at;
#[cfg(windows)]
use launch_descriptor_validation::{
    KernelLaunchBinding, validate_eliotd_launch_descriptor,
    validate_eliotd_launch_descriptor_bytes, validate_store_bootstrap_descriptor,
    verify_current_host_artifact,
};
pub use launch_options::HostLaunchOptions;
use launch_options::valid_sha256_text;
#[cfg(windows)]
pub use lease_drain::{GenerationRetirementBarrier, GenerationRetirementFence};
#[cfg(windows)]
pub use reactive_context_delivery::{
    HostReactiveContextDeliveryError, HostReactiveContextProducer, HostReactiveContextProducerError,
};
pub use scm_launch::{
    HOST_SCM_CAUSE_MAX_CHARS, HostScmRegistrationCause, ValidatedHostScmLaunch,
    classify_host_scm_inspection, validate_host_scm_bootstrap,
};
pub use store_kernel_launch_sequence::StoreLivenessEvidence;
#[cfg(all(test, windows))]
use store_kernel_launch_sequence::{StoreKernelLaunchError, launch_store_then_kernel};

use std::ffi::OsString;
use std::io;
#[cfg(windows)]
use std::io::{Read, Seek, Write};
use std::path::{Path, PathBuf};
#[cfg(all(windows, test))]
type Duration = std::time::Duration;
#[cfg(windows)]
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use eliot_contracts::{AuthorityEpoch, EpochContractError, EpochId, ResourceGeneration};
#[cfg(windows)]
use eliot_contracts::{ClockReading, ProductId, RequestId, RequestMetadata, SourceId, StateFence};
#[cfg(windows)]
use eliot_host_service::{HostDurableJobAdapter, HostWakeIntentAdapter};
use eliot_host_state::{
    ActivationState, AppendReceipt, DrainRecord, DrainState, EpochIdentity, EpochLineageId,
    EpochTransition, HostInstallationEpoch, HostObservationRecord, HostState,
    HostStateJournalService, HostStateRecord, IdempotencyIdentity, JournalBackend, JournalError,
    KernelJobBinding, KernelRecord, NonceState, OneTimeNonceState, PriorKernelDisposition,
    ProductionHostStateJournal, ReconcileOutcome, RecordFence, RecoveryLineageEvidence,
    RedbJournalBackend, StoreRebindRecord, StoreRebindState, host_owner_epoch_digest,
    record_checksum,
};
use eliot_installation::{
    ActivationCommitFence, ActivePhaseBRebindIntent, ActivePhaseBRebindReceipt,
    ActivePhaseBRebindRecovery, AgentBridgePhaseBBinding, AgentBridgePreparedBinding,
    AgentBridgeStagePrepared, ApprovedGenerationRegistry, CandidateManifest,
    CredentialAccessReceipt, HostCredentialControlResponse, HostPhaseBMaterializationIntent,
    HostPhaseBMaterializationReceipt, HostPhaseBPreparedMaterialization, HostPhaseBPreparedReceipt,
    InstallationEpoch, InstallationError, InstallationProfile,
    InstallerServiceRegistrationApproval, InstallerServiceRole, LOCAL_SERVICE_SID,
    PHASE_B_PENDING_MARKER, PendingActivationState, PhaseBLiveBinding,
    ProvisionedSupervisionAuthority, RedbInstallationRegistry, RuntimeLaunchDescriptor,
    StoreCredentialProvider, StoreCredentialScope,
    phase_b_credential_receipt_digest as installation_phase_b_credential_receipt_digest,
    phase_b_host_state_root_digest as installation_phase_b_host_state_root_digest,
    phase_b_scm_selector, phase_b_static_template_for_candidate,
    phase_b_watchdog_selector_digest as installation_phase_b_watchdog_selector_digest,
};
#[cfg(windows)]
use eliot_kernel_core::AuthoritySnapshotBindingWire;
use eliot_kernel_core::KernelRuntimeHealthEvidence;
#[cfg(all(test, windows))]
use eliot_kernel_service::KERNEL_CONTROL_PIPE;
use eliot_kernel_service::{
    EliotdLaunchDescriptor, HostJobBinding, HostKernelCandidateBinding, HostProcessBinding,
    HostStartupEvidence, HostStoreBootstrapRequirement, KernelActivationPermit,
    KernelActivationQuery, KernelActivationReceipt, KernelControlCommand, KernelControlRequest,
    KernelControlResponse, KernelReadyReceipt, KernelServiceState,
    ProcessAuthorityHandoffDescriptor, RestartBudget, StoreBootstrapHandoff, StoreProcessBinding,
    StoreRebindHandoff, StoreRebindQuery, StoreRebindReceipt, control_request_frame,
    decode_control_response_frame, semantic_store_config_hash_from_json,
};
use eliot_observation_contracts::{
    CoverageGap, GapDisposition, ObservationRecordEnvelope, ObservationRecordKind,
};
#[cfg(windows)]
use eliot_ors::{
    EpochIdentity as OrsEpochIdentity, EpochLineage, OpaqueLabel, OperationIdentity,
    StateFenceSnapshot,
};
use eliot_platform::{PlatformHandle, SecretReference, ServiceState};
#[cfg(windows)]
use eliot_platform_windows::{
    DirectoryPublicationError, DirectoryPublicationOutcome, FileIdentity,
    OwnedDirectoryPublication, OwnedDirectoryRetirementOutcome,
    OwnedDirectoryRetirementPrecondition, ProtectedRuntimePathLease, retire_owned_directory_exact,
    windows_paths_equal,
};
use eliot_platform_windows::{
    ELIOT_HOST_SERVICE_NAME, ELIOT_WATCHDOG_SERVICE_NAME, HostOwnerLease, HostOwnerLeaseError,
    HostOwnerLeaseReleaseError, ProtectedRootLease, ServiceAccount, ServiceRegistrationRequest,
    ServiceRegistrationRuntimeInspection, ServiceStartMode, ServiceStopOutcome, TerminatedJobChild,
    WindowsPlatform, fresh_kernel_activation_nonce,
};
#[cfg(windows)]
use eliot_process::DispatchAuthorityId;
use eliot_runtime_contracts::{
    HealthDimension, HealthVector, KernelActivationState, ServiceProcessRecord,
    ServiceProcessState, SupervisionJournalEpoch, SupervisionLeaseIncarnationBinding,
};
#[cfg(windows)]
use eliot_runtime_contracts::{
    SUPERVISION_LEASE_FILE_NAME, SignedSupervisionLease, SupervisionLeaseVerifier,
    WATCHDOG_ADMISSION_FILE_NAME, WATCHDOG_PUBLICATION_DIRECTORY_PREFIX,
    WATCHDOG_PUBLICATION_FILE_NAME, WATCHDOG_PUBLICATION_RETAINED_LIMIT, WatchdogAdmissionTemplate,
    WatchdogPublicationBundle, WatchdogPublicationRetentionPlan,
};
use sha2::{Digest as _, Sha256};

#[cfg(windows)]
use eliot_ipc::{DeliveryOutcome, NamedPipeTransport, TransportLimits};
use thiserror::Error;
use uuid::Uuid;

pub const SERVICE_NAME: &str = ELIOT_HOST_SERVICE_NAME;
pub const PROTOCOL_VERSION: &str = "eliot.host.v1";
pub const HOST_JOURNAL_RELATIVE_PATH: &str = "Eliot/host/host-state-journal.redb";
const HOST_JOURNAL_FILE_NAME: &str = "host-state-journal.redb";
/// Stable production-boundary identity for the Host Store-rebind seam.
pub const HOST_STORE_REBIND_PRODUCTION_DISCRIMINATOR: &str =
    "eliot-host::production-store-rebind:v1";
/// Stable discriminator for the crash fence that exists because Host-owned
/// `KILL_ON_JOB_CLOSE` Jobs make a prior Store/Kernel process contour
/// unattachable after Host death.  The fenced query is deliberately an
/// operation-specific Unknown/manual new-lineage directive, never a positive
/// attach or receipt adoption.
pub const HOST_STORE_RECOVERY_KILL_ON_JOB_CLOSE_CRASH_FENCE_DISCRIMINATOR: &str =
    "eliot-host::store-recovery::kill-on-job-close-crash-fence:v1";
const STORE_RECOVERY_CRASH_FENCE_UNKNOWN_REASON: &str =
    "store-recovery-crash-fence-manual-new-lineage";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct HostStoreRebindProductionBoundary;
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct HostRuntimeControlProductionBoundary;
const STORE_SEMANTIC_CONFIG_HASH_PENDING: &str = PHASE_B_PENDING_MARKER;
pub const HOST_RUNTIME_CONTROL_PRODUCTION_DISCRIMINATOR: &str =
    eliot_host_service::runtime_control::HOST_RUNTIME_CONTROL_PRODUCTION_DISCRIMINATOR;

#[cfg(test)]
type TestResult = Result<(), Box<dyn std::error::Error>>;

#[cfg(test)]
type TestError = Box<dyn std::error::Error>;

#[cfg(test)]
mod launch_options_tests;

#[derive(Debug, Error)]
pub enum HostError {
    #[error("host state store: {0}")]
    State(#[from] eliot_platform::HostStateError),
    #[error("host state journal: {0}")]
    Journal(#[from] JournalError),
    #[error("installation registry: {0}")]
    Installation(#[from] InstallationError),
    #[error("host platform: {0}")]
    Platform(String),
    #[error("host is already stopped")]
    Stopped,
    #[error("host installation identity is required")]
    MissingInstallation,
    #[error("approved process contour is unavailable: {0}")]
    ProcessContour(String),
    #[error("Store child is not live ({evidence})")]
    StoreNotLive { evidence: StoreLivenessEvidence },
    #[error("Host child cleanup requires recovery: {0}")]
    RecoveryRequired(String),
    #[cfg(windows)]
    #[error("Watchdog coverage is unavailable: {0}")]
    WatchdogCoverageUnavailable(String),
    #[cfg(windows)]
    #[error("Host-owned Store recovery is required: {0}")]
    StoreRecoveryRequired(#[from] StoreRecoveryRequired),
    #[error("another live Host owns this installation")]
    OwnerLeaseHeld,
    #[error("Host owner lease recovery is required: {0}")]
    OwnerLeaseRecovery(String),
}

#[cfg(windows)]
use eliot_platform_windows::{
    JobObjectIdentity, PinnedRuntimeFile, ProcessIdentity, RunningJobChild, UserOwnedRootLease,
    WindowsAdapterError, observe_named_pipe_peer_process,
};

#[cfg(windows)]
const KERNEL_BOOTSTRAP_ENVIRONMENT: [&str; 7] = [
    "ELIOT_KERNEL_CONTROL_PIPE",
    "ELIOT_HOST_PROCESS_ID",
    "ELIOT_HOST_PROCESS_START",
    "ELIOT_HOST_PROCESS_IMAGE",
    "ELIOT_KERNEL_RECEIPT_ROOT",
    "ELIOT_KERNEL_ORS_ROOT",
    "ELIOT_RUNTIME_STATE_ROOTS_DIGEST",
];

#[cfg(windows)]
mod phase_b_projection;
#[cfg(windows)]
use phase_b_projection::{
    host_process_identity_digest, host_process_identity_digest_for_host, phase_b_authority_marker,
    phase_b_build_authority_descriptor, phase_b_build_authority_descriptor_for_rebind,
    phase_b_credential_receipt_digest, phase_b_manifest_digest, phase_b_prepared_public_receipt,
    phase_b_public_receipt, phase_b_public_receipt_from_binding, phase_b_root_binding_digest,
    phase_b_watchdog_selector_digest, validate_phase_b_credential_receipt,
};

#[cfg(windows)]
mod phase_b_previous_authority;
#[cfg(windows)]
use phase_b_previous_authority::{
    PhaseBPreviousBinding, phase_b_authority_is_observable, phase_b_observe_previous_binding,
    phase_b_open_existing, phase_b_validate_authority, phase_b_validate_durable_previous_binding,
};

#[cfg(windows)]
mod phase_b_materialization;
#[cfg(all(windows, test))]
use phase_b_materialization::phase_b_template_path;
#[cfg(windows)]
use phase_b_materialization::{
    agent_bridge_admission_descriptor, open_agent_bridge_final_lease, phase_b_bytes_digest,
    phase_b_lease_bytes, phase_b_lease_identity, phase_b_materialize_file_with_rollback,
    phase_b_remove_rollback_backup, phase_b_restore_or_remove, phase_b_template_bytes,
};

mod notify_fallback_setup;
pub use notify_fallback_setup::{
    NotifyFallbackRegistration, NotifyFallbackSetup, NotifyFallbackSetupInputs,
    PublishedNotifyDeclaration, publish_notify_fallback_declaration, register_notify_fallback,
    setup_notify_fallback_per_user,
};
#[cfg(windows)]
pub(crate) use phase_b_materialization::phase_b_materialize_file;

#[cfg(windows)]
mod phase_b_previous_projection;
#[cfg(all(test, windows))]
use phase_b_previous_projection::phase_b_live_installation_epoch;
#[cfg(windows)]
use phase_b_previous_projection::{
    phase_b_activation_binding, phase_b_json_string, phase_b_json_u64, phase_b_live_launch,
    phase_b_previous_bootstrap_digest, phase_b_previous_config_digest,
    phase_b_previous_config_value, phase_b_previous_eliotd_digest, phase_b_previous_live_launch,
    phase_b_receipt_digest,
};

fn nonce_after_activation_failure(
    current: &OneTimeNonceState,
) -> Result<OneTimeNonceState, JournalError> {
    match current.state() {
        NonceState::Issued => current.revoke(),
        NonceState::Unissued | NonceState::Consumed | NonceState::Revoked => Ok(current.clone()),
    }
}

fn finish_active_kernel_cleanup(
    durable: Result<(), HostError>,
    cleanup: impl FnOnce() -> Result<(), HostError>,
) -> Result<(), HostError> {
    let cleanup = cleanup();
    match (durable, cleanup) {
        (Ok(()), cleanup) => cleanup,
        (Err(durable), Err(cleanup)) => Err(HostError::RecoveryRequired(format!(
            "durable Kernel failure transition failed ({durable}); contour cleanup result: {cleanup}"
        ))),
        (Err(durable), Ok(())) => Err(durable),
    }
}

#[cfg(windows)]
mod kernel_activation_driver;
#[cfg(windows)]
use kernel_activation_driver::DurableKernelActivationDriver;

#[cfg(windows)]
mod host_startup_evidence;
#[cfg(windows)]
mod kernel_front_door_client;
#[cfg(all(windows, test))]
use kernel_front_door_client::kernel_front_door_acl_mode;
#[cfg(windows)]
use kernel_front_door_client::{
    HostKernelUserAutomationOwner, activation_response_or_reconcile,
    connect_authenticated_kernel_front_door, kernel_control_request,
    validate_authenticated_kernel_peer,
};

#[cfg(all(windows, test))]
mod kernel_front_door_tests {
    use super::{LOCAL_SERVICE_SID, kernel_front_door_acl_mode};
    use eliot_platform_windows::KernelFrontDoorAclMode;

    #[test]
    fn bridge_disabled_uses_service_only_acl() {
        assert_eq!(
            kernel_front_door_acl_mode(None),
            KernelFrontDoorAclMode::ServiceOnly
        );
    }

    #[test]
    fn bridge_sid_is_the_only_extra_acl_contour() {
        let approved = "S-1-5-21-1000";
        assert_eq!(
            kernel_front_door_acl_mode(Some(approved)),
            KernelFrontDoorAclMode::SystemAndLocalServiceWithClient {
                client_sid: approved.to_owned()
            }
        );
        assert_ne!(
            kernel_front_door_acl_mode(Some("S-1-5-21-2000")),
            kernel_front_door_acl_mode(Some(approved))
        );
        assert_ne!(approved, LOCAL_SERVICE_SID);
    }
}

fn unique_ready_evidence<'a>(
    ready: &'a KernelReadyReceipt,
    prefix: &str,
) -> Result<&'a PlatformHandle, HostError> {
    let mut matching = ready
        .evidence_refs
        .iter()
        .filter(|evidence| evidence.as_str().starts_with(prefix));
    let evidence = matching.next().ok_or_else(|| {
        HostError::ProcessContour(format!("Kernel readiness is missing {prefix} evidence"))
    })?;
    if matching.next().is_some() {
        return Err(HostError::ProcessContour(format!(
            "Kernel readiness contains ambiguous {prefix} evidence"
        )));
    }
    Ok(evidence)
}

fn validated_store_proof_fence(
    requirement: &HostStoreBootstrapRequirement,
    ready: &KernelReadyReceipt,
    approved_store_artifact: &PlatformHandle,
    approved_config: &PlatformHandle,
    request_generation: ResourceGeneration,
) -> Result<PlatformHandle, HostError> {
    requirement
        .validate()
        .map_err(|error| HostError::ProcessContour(error.to_string()))?;
    if requirement.approved_artifact_hash != *approved_store_artifact
        || requirement.approved_config_hash != *approved_config
        || requirement.store_generation != request_generation
        || requirement.state_fence.resource_generation != request_generation
    {
        return Err(HostError::ProcessContour(
            "Store proof is not bound to the approved generation contour".to_owned(),
        ));
    }
    let validation = unique_ready_evidence(ready, "kernel-store-validation:")?;
    let revision = validation
        .as_str()
        .strip_prefix("kernel-store-validation:")
        .and_then(|value| value.parse::<u64>().ok())
        .filter(|value| *value > 0)
        .ok_or_else(|| {
            HostError::ProcessContour(
                "Kernel readiness carries a stale or invalid Store validation snapshot".to_owned(),
            )
        })?;
    let health = unique_ready_evidence(ready, "kernel-store-health:")?;
    let health_binding = health
        .as_str()
        .strip_prefix("kernel-store-health:")
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| {
            HostError::ProcessContour(
                "Kernel readiness carries an invalid Store health proof".to_owned(),
            )
        })?;
    let digest = sha256_json(&(
        &requirement.state_fence,
        requirement.store_generation,
        approved_store_artifact,
        approved_config,
        revision,
        health_binding,
    ))?;
    PlatformHandle::new(digest).map_err(|error| HostError::Platform(error.to_string()))
}

fn validate_probe_response(
    request: &KernelControlRequest,
    activation: &KernelActivationReceipt,
    response: &KernelControlResponse,
) -> Result<(KernelReadyReceipt, KernelRuntimeHealthEvidence), HostError> {
    request
        .validate()
        .map_err(|error| HostError::ProcessContour(error.to_string()))?;
    response
        .validate()
        .map_err(|error| HostError::ProcessContour(error.to_string()))?;
    if !matches!(&request.command, KernelControlCommand::ProbeReady)
        || response.message_id != request.message_id
        || response.request_digest != request.payload_digest
        || response.error.is_some()
        || response.state != KernelServiceState::Ready
        || response.activation_receipt.is_some()
    {
        return Err(HostError::ProcessContour(
            "Kernel ProbeReady response binding failed".to_owned(),
        ));
    }
    let ready = response.receipt.clone().ok_or_else(|| {
        HostError::ProcessContour("Kernel did not return a ready receipt".to_owned())
    })?;
    let runtime_health = response.runtime_health.clone().ok_or_else(|| {
        HostError::ProcessContour(
            "Kernel did not return the canonical runtime-health carrier".to_owned(),
        )
    })?;
    runtime_health
        .validate()
        .map_err(|error| HostError::ProcessContour(error.to_string()))?;
    let process_health = runtime_health.process_health();
    if !runtime_health
        .authority_epoch()
        .is_same_authority(&request.candidate.kernel_epoch)
        || runtime_health.module_generation() != activation.generation
        || process_health.process_id() != ready.process.process_id.as_str()
        || process_health.process_state() != ready.process.state
        || process_health.health().canonical != ready.health
    {
        return Err(HostError::ProcessContour(
            "Kernel runtime-health carrier is foreign to the exact readiness contour".to_owned(),
        ));
    }
    let supervision = response.supervision_lease.as_ref().ok_or_else(|| {
        HostError::ProcessContour(
            "Kernel did not return the exact current supervision ORS snapshot".to_owned(),
        )
    })?;
    supervision
        .validate()
        .map_err(|error| HostError::ProcessContour(error.to_string()))?;
    let payload = &supervision.record.artifact.payload;
    if payload.installation_id != request.candidate.installation_id.as_str()
        || payload.host_epoch != request.candidate.host_epoch
        || payload.activation_id != request.candidate.activation_id.as_str()
        || payload.activation_generation != activation.generation
        || payload.kernel_epoch != request.candidate.kernel_epoch
        || payload.state_fence.authority_epoch != request.candidate.kernel_epoch
        || payload.state_fence.resource_generation != activation.generation
        || supervision.record.state != eliot_runtime_contracts::LeaseState::Active
        || supervision.record.projection != eliot_ors::SupervisionLeaseProjection::Active
    {
        return Err(HostError::ProcessContour(
            "Kernel supervision snapshot is foreign to the exact readiness contour".to_owned(),
        ));
    }
    ready
        .validate_for_probe(request, activation)
        .map_err(|error| HostError::ProcessContour(error.to_string()))?;
    Ok((ready, runtime_health))
}

#[cfg(windows)]
struct AuthenticatedKernelReadiness {
    request: KernelControlRequest,
    response: KernelControlResponse,
    ready: KernelReadyReceipt,
    runtime_health: KernelRuntimeHealthEvidence,
    supervision_lease: eliot_ors::SupervisionLeaseSnapshot,
    store_fence: PlatformHandle,
    peer_evidence: PlatformHandle,
}

#[cfg(windows)]
#[derive(Clone, Debug, Eq, PartialEq)]
struct PublishedSupervisionIdentity {
    lease_id: PlatformHandle,
    ors_receipt_digest: PlatformHandle,
    publication_digest: PlatformHandle,
}

#[cfg(windows)]
impl PublishedSupervisionIdentity {
    fn evidence_refs(&self) -> Result<[PlatformHandle; 3], HostError> {
        Ok([
            PlatformHandle::new(format!("supervision-lease:{}", self.lease_id.as_str()))
                .map_err(|error| HostError::Platform(error.to_string()))?,
            PlatformHandle::new(format!(
                "supervision-ors-receipt:{}",
                self.ors_receipt_digest.as_str()
            ))
            .map_err(|error| HostError::Platform(error.to_string()))?,
            PlatformHandle::new(format!(
                "watchdog-publication:{}",
                self.publication_digest.as_str()
            ))
            .map_err(|error| HostError::Platform(error.to_string()))?,
        ])
    }

    fn is_bound_by(&self, evidence_refs: &[PlatformHandle]) -> Result<bool, HostError> {
        Ok(self
            .evidence_refs()?
            .iter()
            .all(|expected| evidence_refs.contains(expected)))
    }
}

#[cfg(windows)]
fn readiness_supervision_fence_matches(
    supervision: &PublishedSupervisionIdentity,
    publication_is_exact: bool,
    evidence_refs: &[PlatformHandle],
) -> bool {
    publication_is_exact && supervision.is_bound_by(evidence_refs).unwrap_or(false)
}

#[cfg(windows)]
fn require_exact_supervision_head(
    expected: &eliot_ors::SupervisionLeaseSnapshot,
    read_current: impl FnOnce() -> Result<eliot_ors::SupervisionLeaseSnapshot, HostError>,
) -> Result<(), HostError> {
    if read_current()? != *expected {
        return Err(HostError::RecoveryRequired(
            "Kernel ORS head changed after Watchdog publication and before readiness journal admission"
                .to_owned(),
        ));
    }
    Ok(())
}

#[cfg(windows)]
pub(crate) struct HostJobBranches {
    kernel: Option<RunningJobChild<PlatformHandle>>,
    store: Option<RunningJobChild<PlatformHandle>>,
    kernel_identity: JobObjectIdentity,
    store_identity: JobObjectIdentity,
    kernel_launch_binding: Option<KernelLaunchBinding>,
    kernel_executable: Option<PathBuf>,
    store_bridge_executable: Option<PathBuf>,
    kernel_lease: Option<LaunchLease>,
    store_lease: Option<LaunchLease>,
    config_path: Option<PathBuf>,
    config_lease: Option<LaunchLease>,
    store_bootstrap_lease: Option<LaunchLease>,
    eliotd_config_lease: Option<LaunchLease>,
    eliotd_descriptor_lease: Option<LaunchLease>,
    store_bootstrap_requirement: Option<HostStoreBootstrapRequirement>,
    config_pin: Option<PinnedRuntimeFile>,
    portable_root: Option<UserOwnedRootLease>,
    launch: Option<RuntimeLaunchDescriptor>,
    kernel_artifact_digest: Option<PlatformHandle>,
    store_artifact_digest: Option<PlatformHandle>,
    config_digest: Option<PlatformHandle>,
    store_config_semantic_hash: Option<PlatformHandle>,
    approved_generation: Option<PlatformHandle>,
    agent_bridge_admission: Option<eliot_kernel_service::AgentBridgeAdmissionDescriptor>,
    kernel_candidate: Option<HostKernelCandidateBinding>,
    kernel_activation_receipt: Option<KernelActivationReceipt>,
    kernel_restart_attempts: u8,
    store_restart_attempts: u8,
}

/// Independent branch disposition after one bounded reconciliation pass.
#[cfg(windows)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HostBranchDisposition {
    /// Both Host-owned branches are live but have not yet supplied a fresh
    /// authenticated readiness proof.
    LiveAwaitingReadiness,
    /// Both Host-owned branches have an authenticated readiness proof inside
    /// its exact bounded lease.
    Healthy,
    /// Both branches may still be live, but the authoritative readiness proof
    /// is absent, expired, rejected, or durably unknown.  The retained contour
    /// remains independently recoverable and is not killed by this outcome.
    ReadinessDegraded,
    /// Kernel authority is unavailable; the canonical store is not stopped.
    KernelDegraded,
    /// Canonical store is unavailable; Kernel is not stopped.
    StoreDegraded,
    /// Both process branches are unavailable after their independent bounds.
    BothDegraded,
}

#[cfg(windows)]
mod readiness_gate;
#[cfg(all(windows, test))]
use readiness_gate::{DEFAULT_READINESS_CADENCE, ReadinessFailureKind};
#[cfg(windows)]
use readiness_gate::{
    HostReadinessGate, ReadinessCadence, ReadinessContourIdentity, ReadinessGateAction,
    readiness_failure_kind, reconcile_authenticated_readiness,
};

#[cfg(windows)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ScmStoreRecoveryRoute {
    Recovered,
    Fenced(HostBranchDisposition),
    Continue(HostBranchDisposition),
}

#[cfg(windows)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[allow(
    clippy::struct_excessive_bools,
    reason = "the four independent liveness facts are the explicit SCM route discriminator"
)]
struct ScmStoreRecoveryObservation {
    store_requires_restart: bool,
    kernel_live: bool,
    kernel_requires_activation: bool,
    store_present: bool,
}

/// Routes both the early Store-dead observation and the late Store-dead result
/// from generic reconciliation through the Host-owned durable operation. The
/// callback is `execute_store_recovery` in production; this shared discriminator
/// is also the deterministic seam for proving the liveness race cannot bypass
/// the durable outer intent.
#[cfg(windows)]
fn route_scm_store_recovery(
    observation: ScmStoreRecoveryObservation,
    reconciled: Option<Result<HostBranchDisposition, HostError>>,
    request: &HostRuntimeControlRequest,
    recover: impl FnOnce(&HostRuntimeControlRequest) -> Result<(), HostError>,
) -> Result<ScmStoreRecoveryRoute, HostError> {
    let recovery_required = if observation.store_requires_restart {
        true
    } else {
        match reconciled {
            Some(Ok(disposition)) => return Ok(ScmStoreRecoveryRoute::Continue(disposition)),
            Some(Err(HostError::StoreRecoveryRequired(_))) => true,
            Some(Err(error)) => return Err(error),
            None => {
                return Err(HostError::RecoveryRequired(
                    "Store reconciliation result was omitted without an early Store-dead observation"
                        .to_owned(),
                ));
            }
        }
    };
    debug_assert!(recovery_required);
    if !observation.kernel_live || observation.kernel_requires_activation {
        return Ok(ScmStoreRecoveryRoute::Fenced(
            HostBranchDisposition::BothDegraded,
        ));
    }
    if !observation.store_present {
        return Ok(ScmStoreRecoveryRoute::Fenced(
            HostBranchDisposition::StoreDegraded,
        ));
    }
    match recover(request) {
        Ok(()) => Ok(ScmStoreRecoveryRoute::Recovered),
        Err(_) => Ok(ScmStoreRecoveryRoute::Fenced(
            HostBranchDisposition::StoreDegraded,
        )),
    }
}

/// Result of one cheap SCM liveness tick.  The tick never performs bounded
/// restart, file/digest verification, Kernel pipe I/O, or journal append.
#[cfg(windows)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HostLivenessTick {
    /// A prior authenticated proof remains valid for the entire exact contour.
    HealthyLeasePreserved,
    /// A failed proof is still inside its bounded retry cadence.
    ReadinessRetryPending,
    /// Full reconciliation and, if live, authoritative readiness are due.
    FullReconcileDue,
}

#[cfg(windows)]
fn classify_liveness_tick(
    gate: &mut HostReadinessGate,
    liveness: HostBranchDisposition,
    contour: Option<Result<ReadinessContourIdentity, HostError>>,
    now: std::time::Instant,
) -> HostLivenessTick {
    if liveness != HostBranchDisposition::LiveAwaitingReadiness {
        gate.branch_degraded();
        return HostLivenessTick::FullReconcileDue;
    }
    let contour = match contour {
        Some(Ok(contour)) => Some(contour),
        Some(Err(_)) | None => None,
    };
    match gate.action(contour.as_ref(), now) {
        ReadinessGateAction::PreserveAuthenticatedHealth => HostLivenessTick::HealthyLeasePreserved,
        ReadinessGateAction::RetryPending(_failure) => HostLivenessTick::ReadinessRetryPending,
        ReadinessGateAction::ProbeDue => HostLivenessTick::FullReconcileDue,
    }
}

#[cfg(windows)]
fn descriptor_bound_liveness_tick(
    gate: &mut HostReadinessGate,
    liveness: HostBranchDisposition,
    active_manifest: Option<&CandidateManifest>,
    current_contour: impl FnOnce(
        &PlatformHandle,
        &PlatformHandle,
        &PlatformHandle,
        &PlatformHandle,
    ) -> Result<ReadinessContourIdentity, HostError>,
    now: std::time::Instant,
) -> HostLivenessTick {
    let contour = (liveness == HostBranchDisposition::LiveAwaitingReadiness).then(|| {
        let manifest = active_manifest
            .ok_or_else(|| HostError::ProcessContour("no approved active generation".to_owned()))?;
        let (kernel_artifact, store_artifact) = manifest
            .host_child_artifact_digests()
            .map_err(|error| HostError::ProcessContour(error.to_string()))?;
        current_contour(
            &manifest.generation,
            kernel_artifact,
            store_artifact,
            &manifest.config_digest,
        )
    });
    classify_liveness_tick(gate, liveness, contour, now)
}

#[cfg(windows)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum BranchLiveness {
    Live,
    Dead,
}

#[cfg(windows)]
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum StoreRecoveryRequired {
    #[error("Store became dead during branch reconciliation")]
    LateDead,
}

#[cfg(windows)]
#[allow(dead_code)]
enum CutoverLaunchOutcome {
    Candidate,
    Rollback { candidate_error: String },
}

#[cfg(windows)]
#[allow(dead_code)]
impl CutoverLaunchOutcome {
    fn activation_generation<'a>(
        &self,
        candidate: &'a PlatformHandle,
        prior: &'a PlatformHandle,
    ) -> &'a PlatformHandle {
        match self {
            Self::Candidate => candidate,
            Self::Rollback { .. } => prior,
        }
    }
}

#[cfg(windows)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ReconciliationObservation {
    Live,
    Dead,
    Unknown,
}

#[cfg(windows)]
struct ReconciliationState<S, K> {
    store: Option<S>,
    kernel: Option<K>,
    store_restart_attempts: u8,
    kernel_restart_attempts: u8,
}

#[cfg(windows)]
#[allow(
    clippy::too_many_lines,
    reason = "bounded Kernel-only restart stays ordered while Store recovery remains Host-owned"
)]
fn reconcile_state_machine<S, K, SO, KO, KT, KL>(
    state: &mut ReconciliationState<S, K>,
    mut observe_store: SO,
    mut observe_kernel: KO,
    mut terminate_kernel: KT,
    mut launch_kernel: KL,
) -> Result<HostBranchDisposition, StoreRecoveryRequired>
where
    SO: FnMut(Option<&S>) -> ReconciliationObservation,
    KO: FnMut(Option<&K>) -> ReconciliationObservation,
    KT: FnMut(&mut Option<K>) -> Result<(), ()>,
    KL: FnMut() -> Result<K, ()>,
{
    let kernel_observation = observe_kernel(state.kernel.as_ref());
    let store_observation = observe_store(state.store.as_ref());
    if store_observation == ReconciliationObservation::Dead {
        // The generic branch machine may retain and restart Kernel, but it
        // has no durable outer-intent authority for Store mutation.  A Store
        // death observed after its caller's guard is therefore handed back to
        // HostComposition, which owns execute_store_recovery.
        return Err(StoreRecoveryRequired::LateDead);
    }
    let kernel_dead = kernel_observation == ReconciliationObservation::Dead;
    let mut kernel_degraded = kernel_observation == ReconciliationObservation::Unknown;
    let store_degraded = store_observation == ReconciliationObservation::Unknown;

    if kernel_dead && !store_degraded && state.store.is_some() {
        if terminate_kernel(&mut state.kernel).is_err() || state.kernel_restart_attempts >= 1 {
            kernel_degraded = true;
        } else {
            state.kernel_restart_attempts += 1;
            if let Ok(kernel) = launch_kernel() {
                state.kernel = Some(kernel);
                if observe_kernel(state.kernel.as_ref()) != ReconciliationObservation::Live {
                    kernel_degraded = true;
                    if terminate_kernel(&mut state.kernel).is_err() {
                        kernel_degraded = true;
                    }
                }
            } else {
                kernel_degraded = true;
            }
        }
    } else if kernel_dead {
        kernel_degraded = true;
    }

    if state.kernel.is_none() || kernel_observation == ReconciliationObservation::Unknown {
        kernel_degraded = true;
    }
    Ok(match (kernel_degraded, store_degraded) {
        (false, false) => HostBranchDisposition::LiveAwaitingReadiness,
        (true, false) => HostBranchDisposition::KernelDegraded,
        (false, true) => HostBranchDisposition::StoreDegraded,
        (true, true) => HostBranchDisposition::BothDegraded,
    })
}

#[cfg(windows)]
#[allow(dead_code)]
impl HostJobBranches {
    /// Installs the exact Phase-B bridge descriptor for the next Kernel
    /// launch/relaunch. `None` is the legacy, bridge-disabled contour.
    fn set_agent_bridge_admission(
        &mut self,
        descriptor: Option<eliot_kernel_service::AgentBridgeAdmissionDescriptor>,
    ) {
        self.agent_bridge_admission = descriptor;
    }

    /// Creates two owner-scoped Job identities.  The actual Job handles are
    /// created only by the approved suspended launch below; there is no
    /// unbound PID assignment path.
    ///
    /// # Errors
    ///
    /// Returns an error if either owner-scoped Job identity is invalid.
    pub fn new(host: &HostInstallationEpoch) -> Result<Self, WindowsAdapterError> {
        // F-LOG-HOST-1: phase only; the outermost `open` guard owns the single
        // terminal for this contour. Liveness is not readiness here.
        host_lifecycle_observe_requested(BOUNDARY_JOBS_REQUESTED);
        let suffix = format!(
            "{}-{}",
            host.epoch.current.lineage_id.as_str(),
            host.epoch.current.sequence
        );
        let kernel_identity = JobObjectIdentity::new(format!("Local\\Eliot-Host-Kernel-{suffix}"))?;
        let store_identity = JobObjectIdentity::new(format!("Local\\Eliot-Host-Store-{suffix}"))?;
        let kernel_launch_binding = KernelLaunchBinding::observe_current()?;
        host_lifecycle_observe_requested(BOUNDARY_JOBS_ADMITTED);
        Ok(Self {
            kernel: None,
            store: None,
            kernel_identity,
            store_identity,
            kernel_launch_binding: Some(kernel_launch_binding),
            kernel_executable: None,
            store_bridge_executable: None,
            kernel_lease: None,
            store_lease: None,
            config_path: None,
            config_lease: None,
            store_bootstrap_lease: None,
            eliotd_config_lease: None,
            eliotd_descriptor_lease: None,
            store_bootstrap_requirement: None,
            config_pin: None,
            portable_root: None,
            launch: None,
            kernel_artifact_digest: None,
            store_artifact_digest: None,
            config_digest: None,
            store_config_semantic_hash: None,
            approved_generation: None,
            agent_bridge_admission: None,
            kernel_candidate: None,
            kernel_activation_receipt: None,
            kernel_restart_attempts: 0,
            store_restart_attempts: 0,
        })
    }

    /// Creates an inert Job projection for feature-gated physical recovery
    /// tests without requiring a live Kernel named-pipe peer. The production
    /// constructor above remains the only path that observes the current
    /// process binding; this helper never launches or adopts a child.
    #[cfg(test)]
    pub(crate) fn new_test_support(
        host: &HostInstallationEpoch,
    ) -> Result<Self, WindowsAdapterError> {
        let mut branches = Self::new_fenced(host)?;
        let image_path = std::env::current_exe()
            .map_err(|_| WindowsAdapterError::InvalidInput)?
            .to_string_lossy()
            .into_owned();
        branches.kernel_launch_binding = Some(KernelLaunchBinding {
            pipe_identity: PlatformHandle::new(KERNEL_CONTROL_PIPE)
                .map_err(|_| WindowsAdapterError::InvalidInput)?,
            host_process: HostProcessBinding {
                process_id: std::process::id(),
                start_time_100ns: 1,
                image_path,
            },
        });
        Ok(branches)
    }

    /// Creates the inert identity projection used while Store recovery is
    /// fenced. No current-process observation or child/Job launch is allowed
    /// on this startup path; the binding is populated only by a later
    /// approved contour admission.
    pub fn new_fenced(host: &HostInstallationEpoch) -> Result<Self, WindowsAdapterError> {
        // F-LOG-HOST-1: phase only; outermost `open` owns the terminal.
        host_lifecycle_observe_requested(BOUNDARY_JOBS_FENCED_REQUESTED);
        let suffix = format!(
            "{}-{}",
            host.epoch.current.lineage_id.as_str(),
            host.epoch.current.sequence
        );
        let branches = Self {
            kernel: None,
            store: None,
            kernel_identity: JobObjectIdentity::new(format!("Local\\Eliot-Host-Kernel-{suffix}"))?,
            store_identity: JobObjectIdentity::new(format!("Local\\Eliot-Host-Store-{suffix}"))?,
            kernel_launch_binding: None,
            kernel_executable: None,
            store_bridge_executable: None,
            kernel_lease: None,
            store_lease: None,
            config_path: None,
            config_lease: None,
            store_bootstrap_lease: None,
            eliotd_config_lease: None,
            eliotd_descriptor_lease: None,
            store_bootstrap_requirement: None,
            config_pin: None,
            portable_root: None,
            launch: None,
            kernel_artifact_digest: None,
            store_artifact_digest: None,
            config_digest: None,
            store_config_semantic_hash: None,
            approved_generation: None,
            agent_bridge_admission: None,
            kernel_candidate: None,
            kernel_activation_receipt: None,
            kernel_restart_attempts: 0,
            store_restart_attempts: 0,
        };
        host_lifecycle_observe_requested(BOUNDARY_JOBS_FENCED_ADMITTED);
        Ok(branches)
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "each value is an explicit launch-authority binding; ambient input is injectable only for scrub tests"
    )]
    fn environment_from<I>(
        ambient: I,
        host: &HostInstallationEpoch,
        generation: &PlatformHandle,
        config_digest: &PlatformHandle,
        artifact: &PlatformHandle,
        config_path: &Path,
        job_identity: &JobObjectIdentity,
        kernel_launch_binding: Option<&KernelLaunchBinding>,
        receipt_binding: Option<(&Path, &Path, &PlatformHandle)>,
    ) -> Vec<(OsString, OsString)>
    where
        I: IntoIterator<Item = (OsString, OsString)>,
    {
        let mut environment = ambient
            .into_iter()
            .filter(|(key, _)| {
                let key = key.to_string_lossy();
                ![
                    "ELIOT_APPROVED_GENERATION",
                    "ELIOT_GENERATION_CONFIG_DIGEST",
                    "ELIOT_APPROVED_ARTIFACT",
                    "ELIOT_GENERATION_CONFIG_PATH",
                    "ELIOT_HOST_INSTALLATION",
                    "ELIOT_HOST_EPOCH",
                    "ELIOT_ACTIVATION_NONCE",
                    "ELIOT_JOB_OBJECT_ID",
                ]
                .into_iter()
                .chain(KERNEL_BOOTSTRAP_ENVIRONMENT)
                .any(|reserved| key.eq_ignore_ascii_case(reserved))
            })
            .collect::<Vec<_>>();
        environment.extend([
            (
                OsString::from("ELIOT_APPROVED_GENERATION"),
                OsString::from(generation.as_str()),
            ),
            (
                OsString::from("ELIOT_GENERATION_CONFIG_DIGEST"),
                OsString::from(config_digest.as_str()),
            ),
            (
                OsString::from("ELIOT_APPROVED_ARTIFACT"),
                OsString::from(artifact.as_str()),
            ),
            (
                OsString::from("ELIOT_GENERATION_CONFIG_PATH"),
                config_path.as_os_str().to_owned(),
            ),
            (
                OsString::from("ELIOT_HOST_INSTALLATION"),
                OsString::from(host.installation.as_str()),
            ),
            (
                OsString::from("ELIOT_HOST_EPOCH"),
                OsString::from(host.epoch.current.sequence.to_string()),
            ),
            (
                OsString::from("ELIOT_JOB_OBJECT_ID"),
                OsString::from(job_identity.name()),
            ),
        ]);
        if let Some(binding) = kernel_launch_binding {
            environment.extend([
                (
                    OsString::from(KERNEL_BOOTSTRAP_ENVIRONMENT[0]),
                    OsString::from(binding.pipe_identity.as_str()),
                ),
                (
                    OsString::from(KERNEL_BOOTSTRAP_ENVIRONMENT[1]),
                    OsString::from(binding.host_process.process_id.to_string()),
                ),
                (
                    OsString::from(KERNEL_BOOTSTRAP_ENVIRONMENT[2]),
                    OsString::from(binding.host_process.start_time_100ns.to_string()),
                ),
                (
                    OsString::from(KERNEL_BOOTSTRAP_ENVIRONMENT[3]),
                    OsString::from(&binding.host_process.image_path),
                ),
            ]);
            if let Some((receipt_root, ors_root, roots_digest)) = receipt_binding {
                environment.extend([
                    (
                        OsString::from(KERNEL_BOOTSTRAP_ENVIRONMENT[4]),
                        receipt_root.as_os_str().to_owned(),
                    ),
                    (
                        OsString::from(KERNEL_BOOTSTRAP_ENVIRONMENT[5]),
                        ors_root.as_os_str().to_owned(),
                    ),
                    (
                        OsString::from(KERNEL_BOOTSTRAP_ENVIRONMENT[6]),
                        OsString::from(roots_digest.as_str()),
                    ),
                ]);
            }
        }
        environment
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "the launch environment projection binds the complete admitted Host, generation, process, and receipt contour"
    )]
    fn environment(
        host: &HostInstallationEpoch,
        generation: &PlatformHandle,
        config_digest: &PlatformHandle,
        artifact: &PlatformHandle,
        config_path: &Path,
        job_identity: &JobObjectIdentity,
        kernel_launch_binding: Option<&KernelLaunchBinding>,
        receipt_binding: Option<(&Path, &Path, &PlatformHandle)>,
    ) -> Vec<(OsString, OsString)> {
        Self::environment_from(
            std::env::vars_os(),
            host,
            generation,
            config_digest,
            artifact,
            config_path,
            job_identity,
            kernel_launch_binding,
            receipt_binding,
        )
    }

    /// Sends one closed Host startup evidence payload (I1.11 steps 1, 2, 4) on
    /// the live authenticated control connection and checks the exact
    /// response binding.
    ///
    /// The Kernel records steps only from validated fields; any rejection —
    /// including the not-yet-landed consumer arms — fails this start closed
    /// instead of proceeding to `ProbeReady` without evidence. The sequence
    /// continues the caller's per-connection numbering.
    ///
    /// # Errors
    ///
    /// Returns an error when the evidence cannot be built, delivered, or
    /// exactly bound to its response.
    #[cfg(windows)]
    #[allow(
        clippy::too_many_arguments,
        reason = "the evidence send binds journal, manifest, candidate, fence, roots, and sequence explicitly so no binding is inferred"
    )]
    async fn send_host_startup_evidence<B: JournalBackend>(
        transport: &mut NamedPipeTransport,
        journal: &HostStateJournalService<B>,
        active_manifest: &CandidateManifest,
        candidate: &HostKernelCandidateBinding,
        generation_handle: &PlatformHandle,
        authority_generation: ResourceGeneration,
        host_state_root: &Path,
        store_data_root: &Path,
        sequence: u64,
    ) -> Result<(), HostError> {
        let evidence = host_startup_evidence::build_host_startup_evidence(
            journal,
            active_manifest,
            candidate,
            authority_generation,
            candidate.kernel_epoch.clone(),
            host_state_root,
            store_data_root,
        )?;
        Self::send_bound_host_startup_evidence(
            transport,
            &evidence,
            candidate,
            generation_handle,
            sequence,
        )
        .await
    }

    /// Sends one already-built startup-evidence carrier on this connection and
    /// requires the exact response binding.
    ///
    /// I1.5 (#1750): this is the single wire seam for the carrier, shared by
    /// the activation sequence and by the bounded readiness cadence that
    /// republishes a CURRENT independent Watchdog observation before its repeat
    /// probe. One send, one binding check, no second protocol.
    ///
    /// # Errors
    ///
    /// Returns an error when the frame cannot be delivered with a known
    /// outcome, or when the Kernel response is not exactly bound to this
    /// request.
    #[cfg(windows)]
    async fn send_bound_host_startup_evidence(
        transport: &mut NamedPipeTransport,
        evidence: &HostStartupEvidence,
        candidate: &HostKernelCandidateBinding,
        generation_handle: &PlatformHandle,
        sequence: u64,
    ) -> Result<(), HostError> {
        let request = kernel_control_request(
            candidate,
            evidence.state_fence.resource_generation,
            KernelControlCommand::ReportHostStartupEvidence(evidence.clone()),
            sequence,
        )?;
        let frame = control_request_frame(
            format!(
                "host-control:{}:{}",
                generation_handle.as_str(),
                candidate.activation_id.as_str()
            ),
            &request,
        )
        .map_err(|error| HostError::ProcessContour(error.to_string()))?;
        match transport
            .send_frame(&frame, TransportLimits::default())
            .await
            .map_err(|error| HostError::ProcessContour(error.to_string()))?
        {
            DeliveryOutcome::Delivered => {}
            DeliveryOutcome::UnknownOutcome => {
                return Err(HostError::RecoveryRequired(
                    "Kernel startup-evidence delivery outcome is unknown".to_owned(),
                ));
            }
        }
        let response = transport
            .receive_frame(TransportLimits::default())
            .await
            .map_err(|error| HostError::ProcessContour(error.to_string()))?;
        let response = decode_control_response_frame(&response)
            .map_err(|error| HostError::ProcessContour(error.to_string()))?;
        if response.message_id != request.message_id
            || response.request_digest != request.payload_digest
            || response.error.is_some()
        {
            return Err(HostError::ProcessContour(
                "Kernel startup-evidence response binding failed".to_owned(),
            ));
        }
        Ok(())
    }

    /// Completes the authenticated Host↔Kernel lifecycle before Host
    /// publishes any successful contour observation.
    #[allow(
        clippy::too_many_arguments,
        clippy::too_many_lines,
        reason = "the explicit durable activation transaction preserves the ordered generation, journal, prior-disposition, and authority bindings"
    )]
    fn complete_kernel_control<B: JournalBackend>(
        &mut self,
        generation: &PlatformHandle,
        host: &HostInstallationEpoch,
        journal: &HostStateJournalService<B>,
        activation_id: &PlatformHandle,
        activation_generation: &EpochTransition,
        prior_kernel_disposition: PriorKernelDisposition,
        kernel_generation: EpochTransition,
        kernel_authority_epoch: EpochId,
        active_manifest: &CandidateManifest,
    ) -> Result<(KernelActivationReceipt, KernelReadyReceipt), HostError> {
        let launch = self.launch.as_ref().ok_or_else(|| {
            HostError::ProcessContour("runtime launch descriptor is missing".to_owned())
        })?;
        let kernel_artifact = self.kernel_artifact_digest.as_ref().ok_or_else(|| {
            HostError::ProcessContour("Kernel artifact digest is missing".to_owned())
        })?;
        let config_digest = self
            .config_digest
            .as_ref()
            .ok_or_else(|| HostError::ProcessContour("config digest is missing".to_owned()))?;
        let kernel = self
            .kernel
            .as_ref()
            .ok_or_else(|| HostError::ProcessContour("Kernel process is missing".to_owned()))?;
        let process = kernel.evidence().process();
        if !kernel
            .job_processes()
            .map_err(|error| HostError::ProcessContour(error.to_string()))?
            .iter()
            .any(|observed| observed == process)
        {
            return Err(HostError::ProcessContour(
                "Job observation does not contain the exact launched Kernel process".to_owned(),
            ));
        }
        match kernel
            .observe()
            .map_err(|error| HostError::ProcessContour(error.to_string()))?
        {
            eliot_platform_windows::RunningJobObservation::Running { active_processes }
                if active_processes > 0 => {}
            eliot_platform_windows::RunningJobObservation::Running { .. } => {
                return Err(HostError::ProcessContour(
                    "Kernel Job reports zero active processes".to_owned(),
                ));
            }
            eliot_platform_windows::RunningJobObservation::RootExited { .. }
            | eliot_platform_windows::RunningJobObservation::Exited { .. } => {
                return Err(HostError::ProcessContour(
                    "Kernel exited before authenticated control".to_owned(),
                ));
            }
        }
        let expected_kernel_image = self
            .kernel_executable
            .as_ref()
            .ok_or_else(|| HostError::ProcessContour("Kernel image is missing".to_owned()))?
            .clone();
        let authority_epoch = AuthorityEpoch::new(host.epoch.current.sequence.get())
            .map_err(|error| HostError::ProcessContour(error.to_string()))?;
        // Kernel authenticates the connected Host peer against this exact
        // value, so it is read from the live current-process handle. A PID
        // alone would not make PID reuse or image substitution observable.
        let kernel_launch_binding = self.kernel_launch_binding.as_ref().ok_or_else(|| {
            HostError::ProcessContour(
                "Kernel launch binding is unavailable while Host is fenced".to_owned(),
            )
        })?;
        kernel_launch_binding.validate_current()?;
        // Inert projection of the Host-retained Kernel Job. It grants nothing:
        // Kernel must reopen the named Job and re-observe its own root
        // membership before it will author readiness.
        let recoverable_job = kernel.evidence().recoverable_job_binding();
        let job_binding: HostJobBinding = serde_json::from_value(
            serde_json::to_value(&recoverable_job)
                .map_err(|error| HostError::ProcessContour(error.to_string()))?,
        )
        .map_err(|error| HostError::ProcessContour(error.to_string()))?;
        job_binding
            .validate()
            .map_err(|error| HostError::ProcessContour(error.to_string()))?;
        let journal_state = journal
            .snapshot()
            .map_err(|error| HostError::ProcessContour(error.to_string()))?;
        let activation_record = journal_state.activation.as_ref().ok_or_else(|| {
            HostError::ProcessContour(
                "Host journal has no current activation for supervision incarnation".to_owned(),
            )
        })?;
        if activation_record.activation_id != *activation_id {
            return Err(HostError::ProcessContour(
                "Host journal activation identity does not match Kernel candidate".to_owned(),
            ));
        }
        let predecessor = match (
            matches!(
                prior_kernel_disposition,
                PriorKernelDisposition::NoPriorKernel
            ),
            journal_state.readiness_observations.last(),
        ) {
            (true, None) => None,
            (true, Some(_)) => {
                return Err(HostError::RecoveryRequired(
                    "NoPriorKernel is inconsistent with retained readiness history".to_owned(),
                ));
            }
            (false, None) => {
                return Err(HostError::RecoveryRequired(
                    "Kernel restart has no retained supervision predecessor observation".to_owned(),
                ));
            }
            (false, Some(observation)) => Some(
                observation
                    .active_supervision_lease
                    .clone()
                    .ok_or_else(|| {
                        HostError::RecoveryRequired(
                            "retained readiness observation has no exact supervision predecessor"
                                .to_owned(),
                        )
                    })?,
            ),
        };
        let approved_supervision_authority = launch
            .provisioned_supervision_authority()
            .map_err(|error| HostError::ProcessContour(error.to_string()))?;
        let approved_template = approved_supervision_authority
            .watchdog_admission_template()
            .map_err(|error| HostError::ProcessContour(error.to_string()))?;
        let supervision_incarnation = SupervisionLeaseIncarnationBinding {
            supervision_lease_scope_id: launch.supervision_lease_scope_id().to_owned(),
            supervision_lease_id: String::new(),
            scope_ref_digest: String::new(),
            installation_id: host.installation.as_str().to_owned(),
            host_epoch: SupervisionJournalEpoch {
                lineage_id: host.epoch.current.lineage_id.as_str().to_owned(),
                sequence: host.epoch.current.sequence.get(),
            },
            activation_id: activation_id.as_str().to_owned(),
            activation_generation: SupervisionJournalEpoch {
                lineage_id: activation_generation.current.lineage_id.as_str().to_owned(),
                sequence: activation_generation.current.sequence.get(),
            },
            kernel_generation: SupervisionJournalEpoch {
                lineage_id: kernel_generation.current.lineage_id.as_str().to_owned(),
                sequence: kernel_generation.current.sequence.get(),
            },
            watchdog_epoch: SupervisionJournalEpoch {
                lineage_id: activation_record
                    .lineage
                    .watchdog_epoch
                    .lineage_id
                    .as_str()
                    .to_owned(),
                sequence: activation_record.lineage.watchdog_epoch.sequence.get(),
            },
            observation_scope: approved_template.observation_scope.clone(),
            wake_policy: approved_template.wake_policy.clone(),
            predecessor,
        }
        .with_derived_ids()
        .map_err(|error| HostError::ProcessContour(error.to_string()))?;
        supervision_incarnation
            .validate()
            .map_err(|error| HostError::ProcessContour(error.to_string()))?;
        let candidate = HostKernelCandidateBinding {
            installation_id: host.installation.clone(),
            host_epoch: authority_epoch,
            kernel_epoch: kernel_authority_epoch,
            activation_id: activation_id.clone(),
            artifact_hash: kernel_artifact.clone(),
            config_hash: config_digest.clone(),
            job_object_id: PlatformHandle::new(kernel.job_identity().name())
                .map_err(|error| HostError::ProcessContour(error.to_string()))?,
            pipe_identity: kernel_launch_binding.pipe_identity.clone(),
            host_process: kernel_launch_binding.host_process.clone(),
            job_binding,
            supervision_incarnation,
            restart_budget: RestartBudget::new(3, 3)
                .map_err(|error| HostError::ProcessContour(error.to_string()))?,
            // The bridge descriptor is projected only after the exact
            // Phase-B public receipt and protected profile/declaration pair
            // have been reopened and the staged executable revalidated.
            agent_bridge_admission: self.agent_bridge_admission.clone(),
            containment_action: None,
        };
        candidate
            .validate()
            .map_err(|error| HostError::ProcessContour(error.to_string()))?;
        let root = recoverable_job.root();
        let root_process = root.process();
        let file_identity = root.executable_file_identity();
        let durable_job = KernelJobBinding {
            job_name: PlatformHandle::new(recoverable_job.job_identity().name())
                .map_err(|error| HostError::ProcessContour(error.to_string()))?,
            owner: PlatformHandle::new("Kernel")
                .map_err(|error| HostError::ProcessContour(error.to_string()))?,
            root_pid: root_process.process_id,
            root_start_time_100ns: root_process.start_time_100ns,
            root_image_path: PlatformHandle::new(root_process.image_path.clone())
                .map_err(|error| HostError::ProcessContour(error.to_string()))?,
            root_volume_serial_number: file_identity.volume_serial_number,
            root_file_index: file_identity.file_index,
        };
        let process_record = ServiceProcessRecord {
            process_id: format!(
                "pid:{}:start:{}",
                root_process.process_id, root_process.start_time_100ns
            ),
            owner: "Kernel".to_owned(),
            state: ServiceProcessState::Starting,
            health: HealthVector::healthy(),
            authority_epoch: AuthorityEpoch::new(candidate.kernel_epoch.sequence.get())
                .map_err(|error| HostError::ProcessContour(error.to_string()))?,
        };
        let mut activation = DurableKernelActivationDriver::bind_candidate(
            journal,
            host,
            activation_id,
            activation_generation,
            kernel_artifact.clone(),
            candidate.pipe_identity.clone(),
            durable_job,
            prior_kernel_disposition,
            kernel_generation,
            process_record,
        )?;
        let store = self.store.as_ref().ok_or_else(|| {
            HostError::ProcessContour("Store process is missing before Kernel bootstrap".to_owned())
        })?;
        let store_process = store.evidence().process();
        if !store
            .job_processes()
            .map_err(|error| HostError::ProcessContour(error.to_string()))?
            .iter()
            .any(|observed| observed == store_process)
        {
            return Err(HostError::ProcessContour(
                "Store Job observation does not contain the exact launched Store process"
                    .to_owned(),
            ));
        }
        let store_handoff = StoreBootstrapHandoff {
            requirement: self.store_bootstrap_requirement.clone().ok_or_else(|| {
                HostError::ProcessContour(
                    "Store bootstrap requirement is missing before Kernel bootstrap".to_owned(),
                )
            })?,
            process_binding: StoreProcessBinding {
                process: HostProcessBinding {
                    process_id: store_process.process_id,
                    start_time_100ns: store_process.start_time_100ns,
                    image_path: store_process.image_path.clone(),
                },
                job: PlatformHandle::new(store.job_identity().name())
                    .map_err(|error| HostError::ProcessContour(error.to_string()))?,
            },
        };
        store_handoff
            .validate()
            .map_err(|error| HostError::ProcessContour(error.to_string()))?;
        // Host deliberately authors no readiness receipt. Readiness is proven
        // by Kernel from its own live process, Job, authority, configuration
        // and Store observations, and arrives on the ProbeReady response.
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|error| HostError::ProcessContour(error.to_string()))?;
        let ready = runtime.block_on(async {
            let mut transport =
                connect_authenticated_kernel_front_door(&candidate, process).await?;
            validate_authenticated_kernel_peer(
                transport.peer_identity(),
                process.process_id,
                process.start_time_100ns,
                &expected_kernel_image,
            )?;
            let limits = TransportLimits::default();
            let commands = vec![
                KernelControlCommand::BootstrapStore(store_handoff),
                KernelControlCommand::Reconcile,
                KernelControlCommand::Shadow,
                KernelControlCommand::PrepareHandoff,
            ];
            for (index, command) in commands.into_iter().enumerate() {
                let sequence = u64::try_from(index + 1)
                    .map_err(|error| HostError::ProcessContour(error.to_string()))?;
                let message_id = PlatformHandle::new(format!(
                    "{}:{}",
                    candidate.activation_id.as_str(),
                    sequence
                ))
                .map_err(|error| HostError::ProcessContour(error.to_string()))?;
                let request = KernelControlRequest {
                    wire_id: eliot_kernel_service::KERNEL_CONTROL_WIRE_ID.to_owned(),
                    wire_version: eliot_kernel_service::KERNEL_CONTROL_WIRE_VERSION,
                    message_id: message_id.clone(),
                    sequence,
                    peer_process_id: std::process::id(),
                    generation: launch.authority_generation,
                    candidate: candidate.clone(),
                    command,
                    payload_digest: String::new(),
                }
                .with_computed_digest()
                .map_err(|error| HostError::ProcessContour(error.to_string()))?;
                let frame = control_request_frame(
                    format!(
                        "host-control:{}:{}",
                        generation.as_str(),
                        candidate.activation_id.as_str()
                    ),
                    &request,
                )
                .map_err(|error| HostError::ProcessContour(error.to_string()))?;
                match transport
                    .send_frame(&frame, limits)
                    .await
                    .map_err(|error| HostError::ProcessContour(error.to_string()))?
                {
                    DeliveryOutcome::Delivered => {}
                    DeliveryOutcome::UnknownOutcome => {
                        return Err(HostError::RecoveryRequired(
                            "Kernel control delivery outcome is unknown".to_owned(),
                        ));
                    }
                }
                let response = transport
                    .receive_frame(limits)
                    .await
                    .map_err(|error| HostError::ProcessContour(error.to_string()))?;
                let response = decode_control_response_frame(&response)
                    .map_err(|error| HostError::ProcessContour(error.to_string()))?;
                if response.message_id != message_id
                    || response.request_digest != request.payload_digest
                    || response.error.is_some()
                {
                    return Err(HostError::ProcessContour(
                        "Kernel control response binding failed".to_owned(),
                    ));
                }
            }
            activation.handoff_prepared()?;
            activation.prior_disposition_committed()?;
            let permit = activation.issue_nonce(&candidate, launch.authority_generation)?;
            activation.activating()?;
            let activate_request = kernel_control_request(
                &candidate,
                launch.authority_generation,
                KernelControlCommand::Activate(permit.clone()),
                5,
            )?;
            let activate_digest = activate_request.payload_digest.clone();
            let activate_frame = control_request_frame(
                format!(
                    "host-control:{}:{}",
                    generation.as_str(),
                    candidate.activation_id.as_str()
                ),
                &activate_request,
            )
            .map_err(|error| HostError::ProcessContour(error.to_string()))?;
            let delivered_response = match transport.send_frame(&activate_frame, limits).await {
                Ok(DeliveryOutcome::Delivered) => Some(
                    transport
                        .receive_frame(limits)
                        .await
                        .map_err(|error| HostError::RecoveryRequired(error.to_string()))
                        .and_then(|frame| {
                            decode_control_response_frame(&frame)
                                .map_err(|error| HostError::RecoveryRequired(error.to_string()))
                        }),
                ),
                Ok(DeliveryOutcome::UnknownOutcome) | Err(_) => None,
            };
            let direct_receipt = delivered_response
                .map(|response| {
                    activation_response_or_reconcile(
                        response,
                        &activate_request.message_id,
                        &activate_request.payload_digest,
                    )
                })
                .transpose()?
                .flatten();
            let (activation_receipt, probe_sequence) = if let Some(receipt) = direct_receipt {
                (receipt, 6)
            } else {
                // Do not resend the permit.  Reconnect and query the exact
                // operation/request digest without carrying nonce material.
                // Receive/decode/binding loss after Delivered is also an
                // unknown outcome and follows this same path.
                drop(transport);
                transport = connect_authenticated_kernel_front_door(&candidate, process)
                    .await
                    .map_err(|error| HostError::RecoveryRequired(error.to_string()))?;
                validate_authenticated_kernel_peer(
                    transport.peer_identity(),
                    process.process_id,
                    process.start_time_100ns,
                    &expected_kernel_image,
                )
                .map_err(|error| HostError::RecoveryRequired(error.to_string()))?;
                let query = KernelActivationQuery {
                    operation_id: permit.operation_id.clone(),
                    activate_request_digest: activate_digest,
                };
                let query_request = kernel_control_request(
                    &candidate,
                    launch.authority_generation,
                    KernelControlCommand::ReconcileActivation(query),
                    1,
                )?;
                let query_frame = control_request_frame(
                    format!(
                        "host-control:{}:{}",
                        generation.as_str(),
                        candidate.activation_id.as_str()
                    ),
                    &query_request,
                )
                .map_err(|error| HostError::ProcessContour(error.to_string()))?;
                match transport
                    .send_frame(&query_frame, limits)
                    .await
                    .map_err(|error| HostError::RecoveryRequired(error.to_string()))?
                {
                    DeliveryOutcome::Delivered => {}
                    DeliveryOutcome::UnknownOutcome => {
                        return Err(HostError::RecoveryRequired(
                            "Kernel activation reconciliation outcome is unknown".to_owned(),
                        ));
                    }
                }
                let response = transport
                    .receive_frame(limits)
                    .await
                    .map_err(|error| HostError::RecoveryRequired(error.to_string()))?;
                let response = decode_control_response_frame(&response)
                    .map_err(|error| HostError::RecoveryRequired(error.to_string()))?;
                if response.message_id != query_request.message_id
                    || response.request_digest != query_request.payload_digest
                    || response.error.is_some()
                {
                    return Err(HostError::RecoveryRequired(
                        "Kernel activation reconciliation response was not exact".to_owned(),
                    ));
                }
                let receipt = response.activation_receipt.ok_or_else(|| {
                    HostError::RecoveryRequired(
                        "Kernel did not retain the queried activation operation".to_owned(),
                    )
                })?;
                (receipt, 2)
            };
            activation_receipt
                .validate(&permit)
                .map_err(|error| HostError::ProcessContour(error.to_string()))?;
            // I1.11 steps 1, 2, 4: closed Host startup evidence rides this
            // connection after Activate and before ProbeReady, continuing the
            // strict per-connection sequence. Any rejection fails closed.
            Self::send_host_startup_evidence(
                &mut transport,
                journal,
                active_manifest,
                &candidate,
                generation,
                launch.authority_generation,
                Path::new(launch.runtime_state_roots.host_state_root.as_str()),
                Path::new(launch.runtime_state_roots.store_data_root.as_str()),
                probe_sequence,
            )
            .await?;
            let probe_request = kernel_control_request(
                &candidate,
                launch.authority_generation,
                KernelControlCommand::ProbeReady,
                probe_sequence + 1,
            )?;
            let probe_frame = control_request_frame(
                format!(
                    "host-control:{}:{}",
                    generation.as_str(),
                    candidate.activation_id.as_str()
                ),
                &probe_request,
            )
            .map_err(|error| HostError::ProcessContour(error.to_string()))?;
            match transport
                .send_frame(&probe_frame, limits)
                .await
                .map_err(|error| HostError::ProcessContour(error.to_string()))?
            {
                DeliveryOutcome::Delivered => {}
                DeliveryOutcome::UnknownOutcome => {
                    return Err(HostError::RecoveryRequired(
                        "Kernel ProbeReady delivery outcome is unknown".to_owned(),
                    ));
                }
            }
            let response = transport
                .receive_frame(limits)
                .await
                .map_err(|error| HostError::ProcessContour(error.to_string()))?;
            let response = decode_control_response_frame(&response)
                .map_err(|error| HostError::ProcessContour(error.to_string()))?;
            // Startup uses the same canonical carrier gate as every later
            // readiness probe. A ready receipt alone cannot authorize the
            // activation: the owner-produced health/compatibility evidence
            // must bind to this exact request, generation, epoch, process,
            // and health vector before Host commits Active.
            let (ready, _runtime_health) =
                validate_probe_response(&probe_request, &activation_receipt, &response)?;
            Ok((activation_receipt, ready))
        });
        let (activation_receipt, ready) = match ready {
            Ok(receipts) => receipts,
            Err(error) => {
                let failure = activation.fail("kernel-control-activation-failed");
                return Err(match failure {
                    Ok(()) => error,
                    Err(failure) => HostError::RecoveryRequired(format!(
                        "Kernel activation failed ({error}); durable failure transition failed ({failure})"
                    )),
                });
            }
        };
        if let Err(error) = activation.active(&candidate, &activation_receipt, &ready) {
            let failure = activation.fail("kernel-active-commit-failed");
            return Err(match failure {
                Ok(()) => error,
                Err(failure) => HostError::RecoveryRequired(format!(
                    "Kernel Active commit failed ({error}); durable revoke failed ({failure})"
                )),
            });
        }
        self.kernel_candidate = Some(candidate);
        self.kernel_activation_receipt = Some(activation_receipt.clone());
        self.reconcile_store_rebind_records(
            generation,
            journal,
            host,
            activation_id,
            activation_generation,
        )?;
        Ok((activation_receipt, ready))
    }

    #[cfg(windows)]
    #[allow(
        clippy::too_many_arguments,
        reason = "the exact query carries every authenticated process and request binding"
    )]
    async fn query_store_rebind_exact(
        operation_id: &PlatformHandle,
        request_digest: &str,
        generation: &PlatformHandle,
        candidate: &HostKernelCandidateBinding,
        authority_generation: ResourceGeneration,
        kernel_process_id: u32,
        kernel_process_start_time_100ns: u64,
        expected_kernel_image: &Path,
        label: &str,
    ) -> Result<Option<StoreRebindReceipt>, HostError> {
        let kernel_process = ProcessIdentity {
            process_id: kernel_process_id,
            start_time_100ns: kernel_process_start_time_100ns,
            image_path: expected_kernel_image
                .to_str()
                .ok_or_else(|| HostError::ProcessContour("Kernel image is not UTF-8".to_owned()))?
                .to_owned(),
        };
        let mut transport = connect_authenticated_kernel_front_door(candidate, &kernel_process)
            .await
            .map_err(|error| HostError::RecoveryRequired(error.to_string()))?;
        validate_authenticated_kernel_peer(
            transport.peer_identity(),
            kernel_process_id,
            kernel_process_start_time_100ns,
            expected_kernel_image,
        )
        .map_err(|error| HostError::RecoveryRequired(error.to_string()))?;
        let query = StoreRebindQuery {
            operation_id: operation_id.clone(),
            request_digest: request_digest.to_owned(),
        };
        let request = KernelControlRequest {
            wire_id: eliot_kernel_service::KERNEL_CONTROL_WIRE_ID.to_owned(),
            wire_version: eliot_kernel_service::KERNEL_CONTROL_WIRE_VERSION,
            message_id: fresh_identity(&format!("{label}-message"))?,
            sequence: 1,
            peer_process_id: std::process::id(),
            generation: authority_generation,
            candidate: candidate.clone(),
            command: KernelControlCommand::ReconcileRebindStore(query),
            payload_digest: String::new(),
        }
        .with_computed_digest()
        .map_err(|error| HostError::ProcessContour(error.to_string()))?;
        let frame = control_request_frame(
            format!(
                "{label}:{}:{}",
                generation.as_str(),
                candidate.activation_id.as_str()
            ),
            &request,
        )
        .map_err(|error| HostError::ProcessContour(error.to_string()))?;
        match transport
            .send_frame(&frame, TransportLimits::default())
            .await
            .map_err(|error| HostError::RecoveryRequired(error.to_string()))?
        {
            DeliveryOutcome::Delivered => {}
            DeliveryOutcome::UnknownOutcome => {
                return Err(HostError::RecoveryRequired(
                    "Store rebind exact query delivery outcome is unknown".to_owned(),
                ));
            }
        }
        let frame = transport
            .receive_frame(TransportLimits::default())
            .await
            .map_err(|error| HostError::RecoveryRequired(error.to_string()))?;
        let response = decode_control_response_frame(&frame)
            .map_err(|error| HostError::RecoveryRequired(error.to_string()))?;
        if response.message_id != request.message_id
            || response.request_digest != request.payload_digest
            || response.error.is_some()
        {
            return Err(HostError::RecoveryRequired(
                "Store rebind exact query response was not bound".to_owned(),
            ));
        }
        let Some(receipt) = response.store_rebind_receipt else {
            return Ok(None);
        };
        if receipt.operation_id != *operation_id || receipt.request_digest != request_digest {
            return Err(HostError::RecoveryRequired(
                "Store rebind exact query receipt identity mismatch".to_owned(),
            ));
        }
        receipt
            .validate()
            .map_err(|error| HostError::RecoveryRequired(error.to_string()))?;
        let candidate_digest = candidate
            .compute_digest()
            .map_err(|error| HostError::RecoveryRequired(error.to_string()))?;
        if receipt.candidate_binding_digest != candidate_digest
            || receipt.generation != authority_generation
            || receipt.authority_epoch != candidate.kernel_epoch
        {
            return Err(HostError::RecoveryRequired(
                "Store rebind exact query receipt candidate lineage mismatch".to_owned(),
            ));
        }
        Ok(Some(receipt))
    }

    #[cfg(windows)]
    #[allow(
        clippy::too_many_lines,
        reason = "exact Store recovery keeps Host journal, candidate, peer and terminal disposition checks in one boundary"
    )]
    fn reconcile_store_rebind_records<B: JournalBackend>(
        &self,
        generation: &PlatformHandle,
        journal: &HostStateJournalService<B>,
        host: &HostInstallationEpoch,
        activation_id: &PlatformHandle,
        activation_generation: &EpochTransition,
    ) -> Result<(), HostError> {
        let records = journal
            .snapshot()?
            .store_rebinds
            .into_iter()
            .filter(|record| {
                matches!(
                    record.state,
                    StoreRebindState::Pending | StoreRebindState::Unknown
                )
            })
            .collect::<Vec<_>>();
        if records.is_empty() {
            return Ok(());
        }
        let launch = self.launch.as_ref().ok_or_else(|| {
            HostError::RecoveryRequired(
                "Store rebind startup recovery has no runtime launch descriptor".to_owned(),
            )
        })?;
        let candidate = self.kernel_candidate.as_ref().ok_or_else(|| {
            HostError::RecoveryRequired(
                "Store rebind startup recovery has no Kernel candidate".to_owned(),
            )
        })?;
        let candidate_digest = candidate
            .compute_digest()
            .map_err(|error| HostError::RecoveryRequired(error.to_string()))?;
        let active_fence = record_fence(host, activation_id, activation_generation);
        let kernel = self.kernel.as_ref().ok_or_else(|| {
            HostError::RecoveryRequired(
                "Store rebind startup recovery has no live Kernel".to_owned(),
            )
        })?;
        let kernel_process = kernel.evidence().process();
        let expected_kernel_image = self.kernel_executable.as_ref().ok_or_else(|| {
            HostError::RecoveryRequired(
                "Store rebind startup recovery has no Kernel image".to_owned(),
            )
        })?;
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|error| HostError::ProcessContour(error.to_string()))?;
        let mut unknown = Vec::new();
        runtime.block_on(async {
            for record in records {
                if record.fence != active_fence
                    || record.candidate_binding_digest.as_str() != candidate_digest
                {
                    let operation_id = record.operation_id.clone();
                    let request_digest = record.request_digest.as_str().to_owned();
                    persist_store_rebind_disposition(
                        journal,
                        &operation_id,
                        &request_digest,
                        StoreRebindState::Unknown,
                    )?;
                    unknown.push(format!(
                        "{}:{}: Store rebind journal lineage is not the active Host candidate",
                        operation_id.as_str(),
                        request_digest
                    ));
                    continue;
                }
                let result = Self::query_store_rebind_exact(
                    &record.operation_id,
                    record.request_digest.as_str(),
                    generation,
                    candidate,
                    launch.authority_generation,
                    kernel_process.process_id,
                    kernel_process.start_time_100ns,
                    expected_kernel_image,
                    "host-store-rebind-startup-query",
                )
                .await;
                match result {
                    Ok(Some(receipt)) => {
                        append_store_rebind_terminal(
                            journal,
                            record,
                            StoreRebindState::Committed,
                            Some(&receipt),
                        )?;
                    }
                    Ok(None) => {
                        append_store_rebind_terminal(
                            journal,
                            record,
                            StoreRebindState::Aborted,
                            None,
                        )?;
                    }
                    Err(error) => {
                        let operation_id = record.operation_id.clone();
                        let request_digest = record.request_digest.as_str().to_owned();
                        persist_store_rebind_disposition(
                            journal,
                            &operation_id,
                            &request_digest,
                            StoreRebindState::Unknown,
                        )?;
                        unknown.push(format!(
                            "{}:{}: {}",
                            operation_id.as_str(),
                            request_digest,
                            error
                        ));
                    }
                }
            }
            Ok::<(), HostError>(())
        })?;
        if unknown.is_empty() {
            Ok(())
        } else {
            Err(HostError::RecoveryRequired(format!(
                "Store rebind startup recovery remains unknown: {}",
                unknown.join(", ")
            )))
        }
    }

    #[cfg(windows)]
    #[allow(
        clippy::too_many_lines,
        reason = "single ordered Host↔Kernel rebind transaction"
    )]
    fn rebind_store_control(
        &self,
        generation: &PlatformHandle,
        journal: &ProductionHostStateJournal,
        host: &HostInstallationEpoch,
        activation_id: &PlatformHandle,
        activation_generation: &EpochTransition,
        store_recovery: Option<(&Path, &HostRuntimeControlRequest)>,
    ) -> Result<StoreRebindReceipt, HostError> {
        let launch = self.launch.as_ref().ok_or_else(|| {
            HostError::ProcessContour("runtime launch descriptor is missing".to_owned())
        })?;
        let candidate = self.kernel_candidate.as_ref().ok_or_else(|| {
            HostError::ProcessContour("retained Kernel candidate binding is missing".to_owned())
        })?;
        self.kernel_activation_receipt.as_ref().ok_or_else(|| {
            HostError::ProcessContour("retained Kernel activation receipt is missing".to_owned())
        })?;
        let requirement = self.store_bootstrap_requirement.clone().ok_or_else(|| {
            HostError::ProcessContour("retained Store bootstrap requirement is missing".to_owned())
        })?;
        let store = self.store.as_ref().ok_or_else(|| {
            HostError::ProcessContour("Store process is missing for rebind".to_owned())
        })?;
        let store_process = store.evidence().process();
        if !store
            .job_processes()
            .map_err(|error| HostError::ProcessContour(error.to_string()))?
            .iter()
            .any(|observed| observed == store_process)
        {
            return Err(HostError::ProcessContour(
                "Store Job observation does not contain exact relaunched Store process".to_owned(),
            ));
        }
        self.reconcile_store_rebind_records(
            generation,
            journal,
            host,
            activation_id,
            activation_generation,
        )?;
        let candidate_digest = candidate
            .compute_digest()
            .map_err(|error| HostError::ProcessContour(error.to_string()))?;
        let mut hasher = Sha256::new();
        hasher.update(
            serde_json::to_vec(&requirement.state_fence)
                .map_err(|error| HostError::ProcessContour(error.to_string()))?,
        );
        hasher.update(launch.authority_generation.value().to_le_bytes());
        hasher.update(candidate.kernel_epoch.lineage_id.as_str().as_bytes());
        hasher.update(candidate.kernel_epoch.sequence.get().to_le_bytes());
        hasher.update(requirement.approved_artifact_hash.as_str().as_bytes());
        hasher.update(requirement.approved_config_hash.as_str().as_bytes());
        hasher.update(store_process.process_id.to_le_bytes());
        hasher.update(store_process.start_time_100ns.to_le_bytes());
        hasher.update(store_process.image_path.as_bytes());
        hasher.update(
            PlatformHandle::new(store.job_identity().name())
                .map_err(|error| HostError::ProcessContour(error.to_string()))?
                .as_str()
                .as_bytes(),
        );
        hasher.update(candidate_digest.as_bytes());
        let store_fence = format!("{:x}", hasher.finalize());
        let snapshot = journal.snapshot().map_err(HostError::Journal)?;
        let snapshot_pending = snapshot.store_rebinds.into_iter().find(|record| {
            matches!(
                record.state,
                StoreRebindState::Pending | StoreRebindState::Unknown
            )
        });
        let mut disposition_operation_id = snapshot_pending
            .as_ref()
            .map(|record| record.operation_id.clone());
        let mut disposition_request_digest = snapshot_pending
            .as_ref()
            .map(|record| record.request_digest.as_str().to_owned());
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|error| HostError::ProcessContour(error.to_string()))?;
        let result = runtime.block_on(async {
            let expected_kernel_image = self
                .kernel_executable
                .as_ref()
                .ok_or_else(|| HostError::ProcessContour("Kernel image is missing".to_owned()))?
                .clone();
            let kprocess = self
                .kernel
                .as_ref()
                .ok_or_else(|| HostError::ProcessContour("Kernel process is missing".to_owned()))?
                .evidence()
                .process();
            let mut transport =
                connect_authenticated_kernel_front_door(candidate, kprocess).await?;
            validate_authenticated_kernel_peer(
                transport.peer_identity(),
                kprocess.process_id,
                kprocess.start_time_100ns,
                &expected_kernel_image,
            )?;
            if let Some(pending) = snapshot_pending.clone() {
                let pending_query = StoreRebindQuery {
                    operation_id: pending.operation_id.clone(),
                    request_digest: pending.request_digest.as_str().to_owned(),
                };
                let pending_query_request = KernelControlRequest {
                    wire_id: eliot_kernel_service::KERNEL_CONTROL_WIRE_ID.to_owned(),
                    wire_version: eliot_kernel_service::KERNEL_CONTROL_WIRE_VERSION,
                    message_id: fresh_identity("store-rebind-query-pending")?,
                    sequence: 1,
                    peer_process_id: std::process::id(),
                    generation: launch.authority_generation,
                    candidate: candidate.clone(),
                    command: KernelControlCommand::ReconcileRebindStore(pending_query.clone()),
                    payload_digest: String::new(),
                }
                .with_computed_digest()
                .map_err(|error| HostError::ProcessContour(error.to_string()))?;
                let pending_frame = control_request_frame(
                    format!(
                        "host-rebind-query-pending:{}:{}",
                        generation.as_str(),
                        candidate.activation_id.as_str()
                    ),
                    &pending_query_request,
                )
                .map_err(|error| HostError::ProcessContour(error.to_string()))?;
                let mut query_transport =
                    connect_authenticated_kernel_front_door(candidate, kprocess)
                        .await
                        .map_err(|error| HostError::ProcessContour(error.to_string()))?;
                validate_authenticated_kernel_peer(
                    query_transport.peer_identity(),
                    kprocess.process_id,
                    kprocess.start_time_100ns,
                    &expected_kernel_image,
                )
                .map_err(|error| HostError::ProcessContour(error.to_string()))?;
                if query_transport
                    .send_frame(&pending_frame, TransportLimits::default())
                    .await
                    .is_ok()
                    && let Ok(frame) = query_transport
                        .receive_frame(TransportLimits::default())
                        .await
                    && let Ok(response) = decode_control_response_frame(&frame)
                    && response.message_id == pending_query_request.message_id
                    && response.request_digest == pending_query_request.payload_digest
                    && response.error.is_none()
                    && let Some(receipt) = response.store_rebind_receipt
                    && receipt.operation_id == pending.operation_id
                    && receipt.request_digest == pending.request_digest.as_str()
                {
                    append_store_rebind_terminal(
                        journal,
                        pending,
                        StoreRebindState::Committed,
                        Some(&receipt),
                    )?;
                    return Ok(receipt);
                }
                return Err(HostError::RecoveryRequired(
                    "store rebind pending requires successful query before fresh operation"
                        .to_owned(),
                ));
            }
            let operation_id = fresh_identity("store-rebind")?;
            disposition_operation_id = Some(operation_id.clone());
            let handoff = StoreRebindHandoff {
                operation_id: operation_id.clone(),
                request_digest: "0".repeat(64),
                requirement: requirement.clone(),
                process_binding: StoreProcessBinding {
                    process: HostProcessBinding {
                        process_id: store_process.process_id,
                        start_time_100ns: store_process.start_time_100ns,
                        image_path: store_process.image_path.clone(),
                    },
                    job: PlatformHandle::new(store.job_identity().name())
                        .map_err(|error| HostError::ProcessContour(error.to_string()))?,
                },
                candidate_binding_digest: candidate_digest.clone(),
                generation: launch.authority_generation,
                authority_epoch: candidate.kernel_epoch.clone(),
                store_fence: store_fence.clone(),
            };
            handoff
                .validate()
                .map_err(|error| HostError::ProcessContour(error.to_string()))?;
            let mut handoff_with_digest = handoff.clone();
            let canonical = handoff_with_digest
                .canonical_request_digest()
                .map_err(|error| HostError::ProcessContour(error.to_string()))?;
            handoff_with_digest.request_digest = canonical.clone();
            handoff_with_digest
                .validate_canonical_digest()
                .map_err(|error| HostError::ProcessContour(error.to_string()))?;
            if let Some((host_state_root, recovery_request)) = store_recovery {
                // Publish the outer->inner identity before the inner journal
                // request or delivery. A crash after Kernel commits can then
                // identify exactly one canonical StoreRebind; destination
                // state and an unrelated committed record are insufficient.
                persist_store_recovery_inner_binding(
                    host_state_root,
                    recovery_request,
                    host,
                    &handoff_with_digest,
                )?;
            }
            // Retain the exact request identity before any frame construction
            // or delivery can fail; every later terminal disposition must use
            // this operation/request pair rather than a current fence.
            disposition_request_digest = Some(canonical.clone());
            let request = KernelControlRequest {
                wire_id: eliot_kernel_service::KERNEL_CONTROL_WIRE_ID.to_owned(),
                wire_version: eliot_kernel_service::KERNEL_CONTROL_WIRE_VERSION,
                message_id: fresh_identity("store-rebind-req")?,
                sequence: 1,
                peer_process_id: std::process::id(),
                generation: launch.authority_generation,
                candidate: candidate.clone(),
                command: KernelControlCommand::RebindStore(handoff_with_digest.clone()),
                payload_digest: canonical.clone(),
            };
            request
                .validate()
                .map_err(|error| HostError::ProcessContour(error.to_string()))?;
            let pending_record = StoreRebindRecord {
                fence: record_fence(host, activation_id, activation_generation),
                operation: operation(&format!(
                    "store-rebind:{}",
                    handoff_with_digest.operation_id.as_str()
                ))?,
                state: StoreRebindState::Pending,
                operation_id: handoff_with_digest.operation_id.clone(),
                request_digest: PlatformHandle::new(canonical.clone())
                    .map_err(|error| HostError::Platform(error.to_string()))?,
                requirement: PlatformHandle::new(format!(
                    "{:x}",
                    Sha256::digest(
                        serde_json::to_vec(&handoff.requirement)
                            .map_err(|error| HostError::Platform(error.to_string()))?
                    )
                ))
                .map_err(|error| HostError::Platform(error.to_string()))?,
                candidate_binding_digest: PlatformHandle::new(
                    handoff_with_digest.candidate_binding_digest.clone(),
                )
                .map_err(|error| HostError::Platform(error.to_string()))?,
                store_fence: PlatformHandle::new(handoff_with_digest.store_fence.clone())
                    .map_err(|error| HostError::Platform(error.to_string()))?,
                process_id: handoff_with_digest.process_binding.process.process_id,
                process_start_time_100ns: handoff_with_digest
                    .process_binding
                    .process
                    .start_time_100ns,
                process_image_path: PlatformHandle::new(
                    handoff_with_digest
                        .process_binding
                        .process
                        .image_path
                        .clone(),
                )
                .map_err(|error| HostError::Platform(error.to_string()))?,
                job_name: handoff_with_digest.process_binding.job.clone(),
                generation: handoff_with_digest.generation.value(),
                authority_epoch: handoff_with_digest.authority_epoch.sequence.get(),
                receipt_request_digest: None,
                receipt_store_fence: None,
            };
            append_reconciled(journal, HostStateRecord::StoreRebind(pending_record))?;
            let frame = control_request_frame(
                format!(
                    "host-rebind:{}:{}",
                    generation.as_str(),
                    candidate.activation_id.as_str()
                ),
                &request,
            )
            .map_err(|error| HostError::ProcessContour(error.to_string()))?;
            let limits = TransportLimits::default();
            let outer_digest = request.payload_digest.clone();
            let outer_message_id = request.message_id.clone();
            let delivered = match transport.send_frame(&frame, limits).await {
                Ok(DeliveryOutcome::Delivered) => true,
                Ok(DeliveryOutcome::UnknownOutcome) | Err(_) => false,
            };
            let receipt = if delivered {
                match transport.receive_frame(limits).await {
                    Ok(frame) => match decode_control_response_frame(&frame) {
                        Ok(response)
                            if response.message_id == outer_message_id
                                && response.request_digest == outer_digest
                                && response.error.is_none() =>
                        {
                            response.store_rebind_receipt
                        }
                        Ok(_) | Err(_) => None,
                    },
                    Err(_) => None,
                }
            } else {
                None
            };
            let final_receipt = if let Some(r) = receipt {
                if r.operation_id != operation_id || r.request_digest != outer_digest {
                    return Err(HostError::ProcessContour(
                        "Store rebind direct receipt mismatch".to_owned(),
                    ));
                }
                r
            } else {
                drop(transport);
                let mut transport2 = connect_authenticated_kernel_front_door(candidate, kprocess)
                    .await
                    .map_err(|error| HostError::RecoveryRequired(error.to_string()))?;
                validate_authenticated_kernel_peer(
                    transport2.peer_identity(),
                    kprocess.process_id,
                    kprocess.start_time_100ns,
                    &expected_kernel_image,
                )
                .map_err(|error| HostError::RecoveryRequired(error.to_string()))?;
                let query = StoreRebindQuery {
                    operation_id: operation_id.clone(),
                    request_digest: outer_digest.clone(),
                };
                let query_request = KernelControlRequest {
                    wire_id: eliot_kernel_service::KERNEL_CONTROL_WIRE_ID.to_owned(),
                    wire_version: eliot_kernel_service::KERNEL_CONTROL_WIRE_VERSION,
                    message_id: fresh_identity("store-rebind-query")?,
                    sequence: 1,
                    peer_process_id: std::process::id(),
                    generation: launch.authority_generation,
                    candidate: candidate.clone(),
                    command: KernelControlCommand::ReconcileRebindStore(query),
                    payload_digest: String::new(),
                }
                .with_computed_digest()
                .map_err(|error| HostError::ProcessContour(error.to_string()))?;
                let query_frame = control_request_frame(
                    format!(
                        "host-rebind-query:{}:{}",
                        generation.as_str(),
                        candidate.activation_id.as_str()
                    ),
                    &query_request,
                )
                .map_err(|error| HostError::ProcessContour(error.to_string()))?;
                match transport2.send_frame(&query_frame, limits).await {
                    Ok(DeliveryOutcome::Delivered) => {}
                    _ => {
                        return Err(HostError::RecoveryRequired(
                            "Store rebind reconciliation delivery is unknown".to_owned(),
                        ));
                    }
                }
                let response = transport2
                    .receive_frame(limits)
                    .await
                    .map_err(|error| HostError::RecoveryRequired(error.to_string()))?;
                let response = decode_control_response_frame(&response)
                    .map_err(|error| HostError::RecoveryRequired(error.to_string()))?;
                if response.message_id != query_request.message_id
                    || response.request_digest != query_request.payload_digest
                    || response.error.is_some()
                {
                    return Err(HostError::RecoveryRequired(
                        "Store rebind reconciliation response not exact".to_owned(),
                    ));
                }
                response.store_rebind_receipt.ok_or_else(|| {
                    HostError::RecoveryRequired(
                        "Store rebind reconciliation confirmed operation is not committed"
                            .to_owned(),
                    )
                })?
            };
            if final_receipt.candidate_binding_digest != candidate_digest
                || final_receipt.generation != launch.authority_generation
                || final_receipt.authority_epoch != candidate.kernel_epoch
                || final_receipt.store_fence != store_fence
                || final_receipt.process_binding.process.process_id != store_process.process_id
                || final_receipt.process_binding.process.start_time_100ns
                    != store_process.start_time_100ns
                || final_receipt.process_binding.process.image_path != store_process.image_path
                || final_receipt.process_binding.job.as_str() != store.job_identity().name()
            {
                return Err(HostError::ProcessContour(
                    "Store rebind receipt binding mismatch".to_owned(),
                ));
            }
            if final_receipt.request_digest != canonical
                || final_receipt.operation_id != handoff_with_digest.operation_id
                || final_receipt.store_fence != handoff_with_digest.store_fence
            {
                return Err(HostError::ProcessContour(
                    "Store rebind receipt exact fields mismatch".to_owned(),
                ));
            }
            final_receipt
                .validate()
                .map_err(|error| HostError::ProcessContour(error.to_string()))?;
            let expected_requirement_digest = format!(
                "{:x}",
                Sha256::digest(
                    serde_json::to_vec(&handoff.requirement)
                        .map_err(|error| HostError::Platform(error.to_string()))?
                )
            );
            if final_receipt.requirement_digest != expected_requirement_digest {
                return Err(HostError::ProcessContour(
                    "Store rebind receipt requirement digest mismatch".to_owned(),
                ));
            }
            let committed_record = StoreRebindRecord {
                fence: record_fence(host, activation_id, activation_generation),
                operation: operation(&format!(
                    "store-rebind:{}:committed",
                    handoff_with_digest.operation_id.as_str()
                ))?,
                state: StoreRebindState::Committed,
                operation_id: handoff_with_digest.operation_id.clone(),
                request_digest: PlatformHandle::new(canonical.clone())
                    .map_err(|error| HostError::Platform(error.to_string()))?,
                requirement: PlatformHandle::new(format!(
                    "{:x}",
                    Sha256::digest(
                        serde_json::to_vec(&handoff.requirement)
                            .map_err(|error| HostError::Platform(error.to_string()))?
                    )
                ))
                .map_err(|error| HostError::Platform(error.to_string()))?,
                candidate_binding_digest: PlatformHandle::new(
                    handoff_with_digest.candidate_binding_digest.clone(),
                )
                .map_err(|error| HostError::Platform(error.to_string()))?,
                store_fence: PlatformHandle::new(handoff_with_digest.store_fence.clone())
                    .map_err(|error| HostError::Platform(error.to_string()))?,
                process_id: handoff_with_digest.process_binding.process.process_id,
                process_start_time_100ns: handoff_with_digest
                    .process_binding
                    .process
                    .start_time_100ns,
                process_image_path: PlatformHandle::new(
                    handoff_with_digest
                        .process_binding
                        .process
                        .image_path
                        .clone(),
                )
                .map_err(|error| HostError::Platform(error.to_string()))?,
                job_name: handoff_with_digest.process_binding.job.clone(),
                generation: handoff_with_digest.generation.value(),
                authority_epoch: handoff_with_digest.authority_epoch.sequence.get(),
                receipt_request_digest: Some(
                    PlatformHandle::new(final_receipt.request_digest.clone())
                        .map_err(|error| HostError::Platform(error.to_string()))?,
                ),
                receipt_store_fence: Some(
                    PlatformHandle::new(final_receipt.store_fence.clone())
                        .map_err(|error| HostError::Platform(error.to_string()))?,
                ),
            };
            append_reconciled(journal, HostStateRecord::StoreRebind(committed_record))?;
            Ok(final_receipt)
        });
        if let Err(error) = &result {
            let disposition = if error
                .to_string()
                .contains("Store rebind reconciliation confirmed operation is not committed")
            {
                StoreRebindState::Aborted
            } else {
                StoreRebindState::Unknown
            };
            let disposition_operation_id = disposition_operation_id.as_ref().ok_or_else(|| {
                HostError::RecoveryRequired(
                    "Store rebind failed before an exact operation identity was retained"
                        .to_owned(),
                )
            })?;
            let disposition_request_digest =
                disposition_request_digest.as_deref().ok_or_else(|| {
                    HostError::RecoveryRequired(
                        "Store rebind failed before an exact request digest was retained"
                            .to_owned(),
                    )
                })?;
            if let Err(disposition_error) = persist_store_rebind_disposition(
                journal,
                disposition_operation_id,
                disposition_request_digest,
                disposition,
            ) {
                return Err(HostError::RecoveryRequired(format!(
                    "Store rebind failed ({error}); durable disposition failed: {disposition_error}"
                )));
            }
        }
        result
    }

    #[allow(
        clippy::too_many_lines,
        reason = "the authenticated repeat keeps retained contour, peer, request, response, and Store proof checks in one fail-closed boundary"
    )]
    fn probe_kernel_readiness(
        &self,
        approved_generation: &PlatformHandle,
        approved_kernel_artifact: &PlatformHandle,
        approved_store_artifact: &PlatformHandle,
        approved_config: &PlatformHandle,
        supervision_evidence: &HostStartupEvidence,
    ) -> Result<AuthenticatedKernelReadiness, HostError> {
        let launch = self.launch.as_ref().ok_or_else(|| {
            HostError::ProcessContour("runtime launch descriptor is missing".to_owned())
        })?;
        let candidate = self.kernel_candidate.as_ref().ok_or_else(|| {
            HostError::ProcessContour("retained Kernel candidate binding is missing".to_owned())
        })?;
        let activation = self.kernel_activation_receipt.as_ref().ok_or_else(|| {
            HostError::ProcessContour("retained Kernel activation receipt is missing".to_owned())
        })?;
        let requirement = self.store_bootstrap_requirement.as_ref().ok_or_else(|| {
            HostError::ProcessContour("retained Store bootstrap requirement is missing".to_owned())
        })?;
        let semantic_config_hash = self.store_config_semantic_hash.as_ref().ok_or_else(|| {
            HostError::ProcessContour("retained Store semantic config hash is missing".to_owned())
        })?;
        if self.approved_generation.as_ref() != Some(approved_generation)
            || self.kernel_artifact_digest.as_ref() != Some(approved_kernel_artifact)
            || self.store_artifact_digest.as_ref() != Some(approved_store_artifact)
            || self.config_digest.as_ref() != Some(approved_config)
            || candidate.artifact_hash != *approved_kernel_artifact
            || candidate.config_hash != *approved_config
            || activation.candidate_binding_digest
                != candidate
                    .compute_digest()
                    .map_err(|error| HostError::ProcessContour(error.to_string()))?
            || activation.generation != launch.authority_generation
            || activation.authority_epoch != candidate.kernel_epoch
        {
            return Err(HostError::ProcessContour(
                "retained Kernel control contour is not the approved active generation".to_owned(),
            ));
        }
        let kernel = self
            .kernel
            .as_ref()
            .ok_or_else(|| HostError::ProcessContour("Kernel process is missing".to_owned()))?;
        let process = kernel.evidence().process();
        if !kernel
            .job_processes()
            .map_err(|error| HostError::ProcessContour(error.to_string()))?
            .iter()
            .any(|observed| observed == process)
        {
            return Err(HostError::ProcessContour(
                "Job observation does not contain the exact active Kernel process".to_owned(),
            ));
        }
        match kernel
            .observe()
            .map_err(|error| HostError::ProcessContour(error.to_string()))?
        {
            eliot_platform_windows::RunningJobObservation::Running { active_processes }
                if active_processes > 0 => {}
            _ => {
                return Err(HostError::ProcessContour(
                    "active Kernel Job is not live for ProbeReady".to_owned(),
                ));
            }
        }
        let expected_kernel_image = self
            .kernel_executable
            .as_ref()
            .ok_or_else(|| HostError::ProcessContour("Kernel image is missing".to_owned()))?;
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|error| HostError::ProcessContour(error.to_string()))?;
        runtime.block_on(async {
            let mut transport = connect_authenticated_kernel_front_door(candidate, process).await?;
            validate_authenticated_kernel_peer(
                transport.peer_identity(),
                process.process_id,
                process.start_time_100ns,
                expected_kernel_image,
            )?;
            let peer_digest = sha256_json(&(
                process.process_id,
                process.start_time_100ns,
                expected_kernel_image,
                approved_kernel_artifact,
            ))?;
            let peer_evidence = PlatformHandle::new(format!("kernel-peer:{peer_digest}"))
                .map_err(|error| HostError::Platform(error.to_string()))?;
            // I1.5 (#1750): the independent Watchdog observation is republished
            // on this connection before the probe, so Kernel binds a CURRENT
            // owner observation to this contour and this consumer fence rather
            // than answering the probe from retained text. It occupies the first
            // command on the strict per-connection sequence and the probe
            // follows as the second.
            HostJobBranches::send_bound_host_startup_evidence(
                &mut transport,
                supervision_evidence,
                candidate,
                approved_generation,
                1,
            )
            .await?;
            let request = KernelControlRequest {
                wire_id: eliot_kernel_service::KERNEL_CONTROL_WIRE_ID.to_owned(),
                wire_version: eliot_kernel_service::KERNEL_CONTROL_WIRE_VERSION,
                message_id: fresh_identity("kernel-probe")?,
                sequence: 2,
                peer_process_id: std::process::id(),
                generation: launch.authority_generation,
                candidate: candidate.clone(),
                command: KernelControlCommand::ProbeReady,
                payload_digest: String::new(),
            }
            .with_computed_digest()
            .map_err(|error| HostError::ProcessContour(error.to_string()))?;
            let frame = control_request_frame(
                format!(
                    "host-probe:{}:{}",
                    approved_generation.as_str(),
                    candidate.activation_id.as_str()
                ),
                &request,
            )
            .map_err(|error| HostError::ProcessContour(error.to_string()))?;
            match transport
                .send_frame(&frame, TransportLimits::default())
                .await
                .map_err(|error| HostError::ProcessContour(error.to_string()))?
            {
                DeliveryOutcome::Delivered => {}
                DeliveryOutcome::UnknownOutcome => {
                    return Err(HostError::RecoveryRequired(
                        "Kernel repeat ProbeReady delivery outcome is unknown".to_owned(),
                    ));
                }
            }
            let frame = transport
                .receive_frame(TransportLimits::default())
                .await
                .map_err(|error| HostError::ProcessContour(error.to_string()))?;
            let response = decode_control_response_frame(&frame)
                .map_err(|error| HostError::ProcessContour(error.to_string()))?;
            let (ready, runtime_health) = validate_probe_response(&request, activation, &response)?;
            let supervision_lease = response.supervision_lease.clone().ok_or_else(|| {
                HostError::ProcessContour(
                    "Kernel did not return the exact current supervision ORS snapshot".to_owned(),
                )
            })?;
            let store_fence = validated_store_proof_fence(
                requirement,
                &ready,
                approved_store_artifact,
                semantic_config_hash,
                request.generation,
            )?;
            Ok(AuthenticatedKernelReadiness {
                request,
                response,
                ready,
                runtime_health,
                supervision_lease,
                store_fence,
                peer_evidence,
            })
        })
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "relaunch keeps every approved authority binding explicit at the process boundary"
    )]
    fn relaunch_kernel(
        &self,
        generation: &PlatformHandle,
        config_digest: &PlatformHandle,
        config_path: &Path,
        artifact: &PlatformHandle,
        approved_executable_path: &PlatformHandle,
        approved_config_path: &PlatformHandle,
        host: &HostInstallationEpoch,
    ) -> Result<RunningJobChild<PlatformHandle>, HostError> {
        let executable = self
            .kernel_executable
            .clone()
            .ok_or_else(|| HostError::ProcessContour("Kernel image is not recorded".to_owned()))?;
        let executable_lease = self
            .kernel_lease
            .as_ref()
            .ok_or_else(|| HostError::ProcessContour("Kernel image lease is missing".to_owned()))?;
        let config_lease = self.config_lease.as_ref().ok_or_else(|| {
            HostError::ProcessContour("generation config lease is missing".to_owned())
        })?;
        let config_pin = self.config_pin.as_ref().ok_or_else(|| {
            HostError::ProcessContour("generation config pin is missing".to_owned())
        })?;
        let launch = self.launch.as_ref().ok_or_else(|| {
            HostError::ProcessContour("runtime launch descriptor is missing".to_owned())
        })?;
        let config_handle = PlatformHandle::new(config_path.to_string_lossy().into_owned())
            .map_err(|error| HostError::ProcessContour(error.to_string()))?;
        launch
            .validate_for_config(&config_handle)
            .map_err(|error| HostError::ProcessContour(error.to_string()))?;
        let eliotd_config_lease = self.eliotd_config_lease.as_ref().ok_or_else(|| {
            HostError::ProcessContour("eliotd Governor config lease is missing".to_owned())
        })?;
        if eliotd_config_lease.path() != Path::new(launch.eliotd_config_path.as_str()) {
            return Err(HostError::ProcessContour(
                "eliotd Governor config lease is not bound to the approved path".to_owned(),
            ));
        }
        verify_launch_digest(
            eliotd_config_lease,
            &launch.eliotd_config_digest,
            "runtime.eliotd_config",
        )?;
        let eliotd_descriptor_lease = self.eliotd_descriptor_lease.as_ref().ok_or_else(|| {
            HostError::ProcessContour("eliotd launch descriptor lease is missing".to_owned())
        })?;
        validate_eliotd_launch_descriptor(
            eliotd_descriptor_lease,
            &launch.eliotd_descriptor_digest,
            launch,
        )?;
        let (kernel_working_directory, _) =
            Self::approved_working_directories(launch, self.portable_root.as_ref(), config_path)?;
        // T6-D2 front-door anchor (issue #461): the stored 22-value contour
        // gains the sealed digest-bound Doctor path so the relaunched Kernel
        // receives the exact 24-value launch options. Missing anchors fail
        // closed, never defaulted.
        let kernel_arguments = host_job_launch::kernel_arguments_with_doctor_anchor(
            &launch.kernel_arguments,
            &launch.doctor_executable_path,
        )?;
        let child = Self::launch(
            &executable,
            executable_lease,
            &self.kernel_identity,
            generation,
            config_digest,
            artifact,
            config_path,
            config_lease,
            approved_executable_path,
            approved_config_path,
            config_pin,
            host,
            &kernel_arguments,
            &kernel_working_directory,
            self.kernel_launch_binding.as_ref(),
            Some((
                Path::new(launch.runtime_state_roots.host_state_root.as_str()),
                Path::new(launch.runtime_state_roots.kernel_ors_root.as_str()),
                &launch.runtime_state_roots.roots_digest,
            )),
        )?;
        Ok(child)
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "relaunch keeps every approved authority binding explicit at the process boundary"
    )]
    fn relaunch_store(
        &self,
        generation: &PlatformHandle,
        config_digest: &PlatformHandle,
        config_path: &Path,
        artifact: &PlatformHandle,
        approved_executable_path: &PlatformHandle,
        approved_config_path: &PlatformHandle,
        host: &HostInstallationEpoch,
    ) -> Result<RunningJobChild<PlatformHandle>, HostError> {
        let executable = self
            .store_bridge_executable
            .clone()
            .ok_or_else(|| HostError::ProcessContour("store image is not recorded".to_owned()))?;
        let executable_lease = self
            .store_lease
            .as_ref()
            .ok_or_else(|| HostError::ProcessContour("store image lease is missing".to_owned()))?;
        let config_lease = self.config_lease.as_ref().ok_or_else(|| {
            HostError::ProcessContour("generation config lease is missing".to_owned())
        })?;
        let config_pin = self.config_pin.as_ref().ok_or_else(|| {
            HostError::ProcessContour("generation config pin is missing".to_owned())
        })?;
        let launch = self.launch.as_ref().ok_or_else(|| {
            HostError::ProcessContour("runtime launch descriptor is missing".to_owned())
        })?;
        launch
            .require_phase_b_live()
            .map_err(|error| HostError::RecoveryRequired(error.to_string()))?;
        let config_handle = PlatformHandle::new(config_path.to_string_lossy().into_owned())
            .map_err(|error| HostError::ProcessContour(error.to_string()))?;
        launch
            .validate_for_config(&config_handle)
            .map_err(|error| HostError::ProcessContour(error.to_string()))?;
        let store_bootstrap_lease = self.store_bootstrap_lease.as_ref().ok_or_else(|| {
            HostError::ProcessContour("Store bootstrap descriptor lease is missing".to_owned())
        })?;
        if store_bootstrap_lease.path()
            != Path::new(launch.store_bootstrap_descriptor_path.as_str())
        {
            return Err(HostError::ProcessContour(
                "Store bootstrap descriptor lease is not bound to the approved path".to_owned(),
            ));
        }
        let semantic_config_hash = self.store_config_semantic_hash.as_ref().ok_or_else(|| {
            HostError::ProcessContour("Store semantic config hash is missing".to_owned())
        })?;
        let expected_bootstrap = validate_store_bootstrap_descriptor(
            store_bootstrap_lease,
            &launch.store_bootstrap_descriptor_digest,
            artifact,
            semantic_config_hash,
            host.host_process_nonce().as_handle(),
        )?;
        if self.store_bootstrap_requirement.as_ref() != Some(&expected_bootstrap) {
            return Err(HostError::ProcessContour(
                "retained Store bootstrap requirement changed before relaunch".to_owned(),
            ));
        }
        let eliotd_config_lease = self.eliotd_config_lease.as_ref().ok_or_else(|| {
            HostError::ProcessContour("eliotd Governor config lease is missing".to_owned())
        })?;
        if eliotd_config_lease.path() != Path::new(launch.eliotd_config_path.as_str()) {
            return Err(HostError::ProcessContour(
                "eliotd Governor config lease is not bound to the approved path".to_owned(),
            ));
        }
        verify_launch_digest(
            eliotd_config_lease,
            &launch.eliotd_config_digest,
            "runtime.eliotd_config",
        )?;
        let eliotd_descriptor_lease = self.eliotd_descriptor_lease.as_ref().ok_or_else(|| {
            HostError::ProcessContour("eliotd launch descriptor lease is missing".to_owned())
        })?;
        validate_eliotd_launch_descriptor(
            eliotd_descriptor_lease,
            &launch.eliotd_descriptor_digest,
            launch,
        )?;
        let (_, store_working_directory) =
            Self::approved_working_directories(launch, self.portable_root.as_ref(), config_path)?;
        let child = Self::launch(
            &executable,
            executable_lease,
            &self.store_identity,
            generation,
            config_digest,
            artifact,
            config_path,
            config_lease,
            approved_executable_path,
            approved_config_path,
            config_pin,
            host,
            &launch.store_bridge_arguments,
            &store_working_directory,
            None,
            None,
        )?;
        Ok(child)
    }

    fn branch_state(
        child: Option<&RunningJobChild<PlatformHandle>>,
    ) -> Result<BranchLiveness, String> {
        match child {
            Some(child) => {
                let process = child.evidence().process();
                if !child
                    .job_processes()
                    .map_err(|error| error.to_string())?
                    .iter()
                    .any(|observed| observed == process)
                {
                    return Err(
                        "Job observation does not contain the exact launched process".to_owned(),
                    );
                }
                match child.observe().map_err(|error| error.to_string())? {
                    eliot_platform_windows::RunningJobObservation::Running { active_processes }
                        if active_processes > 0 =>
                    {
                        Ok(BranchLiveness::Live)
                    }
                    eliot_platform_windows::RunningJobObservation::Running { .. } => {
                        Err("running observation reports zero active processes".to_owned())
                    }
                    eliot_platform_windows::RunningJobObservation::RootExited { .. }
                    | eliot_platform_windows::RunningJobObservation::Exited { .. } => {
                        Ok(BranchLiveness::Dead)
                    }
                }
            }
            None => Ok(BranchLiveness::Dead),
        }
    }

    /// Proves the process contour is still before any no-return/service
    /// boundary for a first-install abort. Unknown Job observations and any
    /// retained launch/recovery object fail closed; callers must preserve the
    /// durable pending carrier in those cases.
    pub(crate) fn pre_no_return_abort_liveness(&self) -> Result<(), String> {
        let kernel = Self::branch_state(self.kernel.as_ref())?;
        let store = Self::branch_state(self.store.as_ref())?;
        if !matches!(kernel, BranchLiveness::Dead)
            || !matches!(store, BranchLiveness::Dead)
            || self.has_recorded_contour()
            || self.launch.is_some()
            || self.kernel_candidate.is_some()
            || self.kernel_activation_receipt.is_some()
        {
            return Err(
                "Host Job contour has live, unknown, or retained service progress".to_owned(),
            );
        }
        Ok(())
    }

    fn liveness_only(&self) -> HostBranchDisposition {
        let kernel_live = matches!(
            Self::branch_state(self.kernel.as_ref()),
            Ok(BranchLiveness::Live)
        );
        let store_live = matches!(
            Self::branch_state(self.store.as_ref()),
            Ok(BranchLiveness::Live)
        );
        match (kernel_live, store_live) {
            (true, true) => HostBranchDisposition::LiveAwaitingReadiness,
            (false, true) => HostBranchDisposition::KernelDegraded,
            (true, false) => HostBranchDisposition::StoreDegraded,
            (false, false) => HostBranchDisposition::BothDegraded,
        }
    }

    fn validate_running_kernel_candidate(
        &self,
        candidate: &HostKernelCandidateBinding,
    ) -> Result<(), HostError> {
        let running_kernel = self.kernel.as_ref().ok_or_else(|| {
            HostError::ProcessContour("active Kernel process is missing".to_owned())
        })?;
        let running_process = running_kernel.evidence().process();
        let candidate_job = &candidate.job_binding;
        if candidate_job.job.name != self.kernel_identity.name()
            || running_process.process_id != candidate_job.root.process.process_id
            || running_process.start_time_100ns != candidate_job.root.process.start_time_100ns
            || running_process.image_path != candidate_job.root.process.image_path
        {
            return Err(HostError::ProcessContour(
                "live Kernel Job/process is not the retained candidate binding".to_owned(),
            ));
        }
        Ok(())
    }

    /// Reconciles the retained Kernel branch and an already-live Store with one
    /// bounded restart attempt for Kernel failure. A failed branch never
    /// terminates a healthy sibling or reuses an observed PID. A dead Store is
    /// rejected here because only [`HostComposition`] owns the durable outer
    /// recovery intent required before Store termination.
    ///
    /// # Errors
    ///
    /// Returns an error if retained process/configuration identity changes or
    /// a protected file, digest, or approved path cannot be revalidated.
    #[allow(
        clippy::too_many_arguments,
        clippy::too_many_lines,
        reason = "ordered branch reconciliation keeps all authority bindings visible and fail-closed"
    )]
    pub fn reconcile(
        &mut self,
        generation: &PlatformHandle,
        config_digest: &PlatformHandle,
        config_path: &Path,
        approved_kernel_path: &PlatformHandle,
        approved_store_bridge_path: &PlatformHandle,
        approved_config_path: &PlatformHandle,
        kernel_artifact: &PlatformHandle,
        store_artifact: &PlatformHandle,
        host: &HostInstallationEpoch,
    ) -> Result<HostBranchDisposition, HostError> {
        // F-LOG-HOST-1: phase only; outer `reconcile_approved_contour` owns
        // the single terminal. Liveness here is never readiness.
        host_lifecycle_observe_requested(BOUNDARY_BRANCH_RECONCILE_REQUESTED);
        // This low-level branch helper has no journal/outer-intent authority.
        // A dead Store must therefore be recovered by HostComposition's one
        // durable Store-recovery operation, never by the generic relaunch
        // closures below.  Keep the guard here as a fail-closed backstop for
        // future callers that might otherwise reintroduce the old bypass.
        if matches!(
            Self::branch_state(self.store.as_ref()),
            Ok(BranchLiveness::Dead)
        ) {
            return Err(StoreRecoveryRequired::LateDead.into());
        }
        if self
            .kernel_artifact_digest
            .as_ref()
            .is_some_and(|digest| digest != kernel_artifact)
            || self
                .store_artifact_digest
                .as_ref()
                .is_some_and(|digest| digest != store_artifact)
            || self
                .config_digest
                .as_ref()
                .is_some_and(|digest| digest != config_digest)
        {
            return Err(HostError::ProcessContour(
                "approved generation material changed; bounded cutover is required".to_owned(),
            ));
        }
        let profile = self
            .launch
            .as_ref()
            .map_or(InstallationProfile::SystemService, |launch| launch.profile);
        if let Some(root) = self.portable_root.as_ref() {
            root.verify_stable_identity()
                .map_err(|error| HostError::ProcessContour(error.to_string()))?;
            let approved_root = self
                .launch
                .as_ref()
                .and_then(|launch| launch.portable_root.as_ref())
                .ok_or_else(|| {
                    HostError::ProcessContour("portable root binding is missing".to_owned())
                })?;
            if root.path() != Path::new(approved_root.as_str()) {
                return Err(HostError::ProcessContour(
                    "portable root lease path changed outside the approved contour".to_owned(),
                ));
            }
        }
        let canonical_config = approved_locator(config_path, approved_config_path, profile)?;
        if self.config_path.as_ref() != Some(&canonical_config) {
            return Err(HostError::ProcessContour(
                "generation config path changed outside the approved contour".to_owned(),
            ));
        }
        let config_lease = self.config_lease.as_ref().ok_or_else(|| {
            HostError::ProcessContour("generation config lease is missing".to_owned())
        })?;
        if config_lease.path() != canonical_config {
            return Err(HostError::ProcessContour(
                "generation config lease is not the approved path".to_owned(),
            ));
        }
        config_lease.verify().map_err(HostError::ProcessContour)?;
        verify_launch_digest(config_lease, config_digest, "runtime.config")?;
        if let Some(kernel) = &self.kernel_executable {
            let approved = approved_locator(kernel, approved_kernel_path, profile)?;
            let lease = self.kernel_lease.as_ref().ok_or_else(|| {
                HostError::ProcessContour("Kernel image lease is missing".to_owned())
            })?;
            if approved != *kernel || lease.path() != kernel {
                return Err(HostError::ProcessContour(
                    "Kernel image lease is not the approved path".to_owned(),
                ));
            }
            lease.verify().map_err(HostError::ProcessContour)?;
            verify_launch_digest(lease, kernel_artifact, "runtime.kernel_artifact")?;
        }
        if let Some(store) = &self.store_bridge_executable {
            let approved = approved_locator(store, approved_store_bridge_path, profile)?;
            let lease = self.store_lease.as_ref().ok_or_else(|| {
                HostError::ProcessContour("store image lease is missing".to_owned())
            })?;
            if approved != *store || lease.path() != store {
                return Err(HostError::ProcessContour(
                    "store image lease is not the approved path".to_owned(),
                ));
            }
            lease.verify().map_err(HostError::ProcessContour)?;
            verify_launch_digest(lease, store_artifact, "runtime.store_artifact")?;
        }
        let mut state = ReconciliationState {
            store: self.store.take(),
            kernel: self.kernel.take(),
            store_restart_attempts: self.store_restart_attempts,
            kernel_restart_attempts: self.kernel_restart_attempts,
        };
        let disposition = reconcile_state_machine(
            &mut state,
            |store| match Self::branch_state(store) {
                Ok(BranchLiveness::Live) => ReconciliationObservation::Live,
                Ok(BranchLiveness::Dead) => ReconciliationObservation::Dead,
                Err(_) => ReconciliationObservation::Unknown,
            },
            |kernel| match Self::branch_state(kernel) {
                Ok(BranchLiveness::Live) => ReconciliationObservation::Live,
                Ok(BranchLiveness::Dead) => ReconciliationObservation::Dead,
                Err(_) => ReconciliationObservation::Unknown,
            },
            |kernel| {
                let Some(child) = kernel.as_mut() else {
                    return Ok(());
                };
                child
                    .terminate_in_place(0xE017_0001)
                    .map(|_| {
                        kernel.take();
                    })
                    .map_err(|_| ())
            },
            || {
                self.relaunch_kernel(
                    generation,
                    config_digest,
                    config_path,
                    kernel_artifact,
                    approved_kernel_path,
                    approved_config_path,
                    host,
                )
                .map_err(|_| ())
            },
        )
        .map_err(HostError::from);
        self.store = state.store;
        self.kernel = state.kernel;
        self.store_restart_attempts = state.store_restart_attempts;
        self.kernel_restart_attempts = state.kernel_restart_attempts;
        disposition
    }

    /// Performs a bounded side-by-side cutover with an explicit rollback
    /// image.  The old branches are drained before the candidate is admitted;
    /// if candidate startup or suspended validation fails, only the supplied
    /// prior approved images may be relaunched.
    ///
    /// # Errors
    ///
    /// Returns an error when shutdown, candidate admission, or restoration of
    /// the prior approved contour fails.
    #[allow(
        clippy::too_many_arguments,
        dead_code,
        reason = "candidate and rollback authority sets stay explicit to prevent cross-generation substitution"
    )]
    fn cutover_with_rollback(
        &mut self,
        candidate_kernel: &Path,
        candidate_store: &Path,
        prior_kernel: &Path,
        prior_store: &Path,
        candidate_generation: &PlatformHandle,
        candidate_config_digest: &PlatformHandle,
        candidate_config_path: &Path,
        candidate_kernel_path: &PlatformHandle,
        candidate_store_path: &PlatformHandle,
        candidate_approved_config_path: &PlatformHandle,
        candidate_kernel_artifact: &PlatformHandle,
        candidate_store_artifact: &PlatformHandle,
        prior_generation: &PlatformHandle,
        prior_config_digest: &PlatformHandle,
        prior_config_path: &Path,
        prior_kernel_path: &PlatformHandle,
        prior_store_path: &PlatformHandle,
        prior_approved_config_path: &PlatformHandle,
        prior_kernel_artifact: &PlatformHandle,
        prior_store_artifact: &PlatformHandle,
        candidate_launch: &RuntimeLaunchDescriptor,
        prior_launch: &RuntimeLaunchDescriptor,
        host: &HostInstallationEpoch,
    ) -> Result<CutoverLaunchOutcome, HostError> {
        self.terminate_store_then_kernel()?;
        match self.start_approved(
            candidate_kernel,
            candidate_store,
            candidate_generation,
            candidate_config_digest,
            candidate_config_path,
            candidate_kernel_path,
            candidate_store_path,
            candidate_approved_config_path,
            candidate_kernel_artifact,
            candidate_store_artifact,
            host,
            candidate_launch,
        ) {
            Ok(()) => Ok(CutoverLaunchOutcome::Candidate),
            Err(candidate_error) => {
                // F-LOG-HOST-1: rollback requested versus verified
                // restoration. The candidate failed, so restoration of the
                // prior approved contour is now requested; the pair
                // completes at `host.cutover-rollback restored` below.
                host_lifecycle_observe_requested(BOUNDARY_CUTOVER_ROLLBACK_REQUESTED);
                let rollback = self
                    .start_approved(
                        prior_kernel,
                        prior_store,
                        prior_generation,
                        prior_config_digest,
                        prior_config_path,
                        prior_kernel_path,
                        prior_store_path,
                        prior_approved_config_path,
                        prior_kernel_artifact,
                        prior_store_artifact,
                        host,
                        prior_launch,
                    )
                    .map_err(|error| {
                        HostError::ProcessContour(format!(
                            "candidate failed ({candidate_error}); rollback failed ({error})"
                        ))
                    });
                rollback.map(|()| {
                    // F-LOG-HOST-1: prior contour relaunched, so the
                    // requested restoration is verified by its owner.
                    host_lifecycle_observe_requested(BOUNDARY_CUTOVER_ROLLBACK_RESTORED);
                    CutoverLaunchOutcome::Rollback {
                        candidate_error: candidate_error.to_string(),
                    }
                })
            }
        }
    }

    /// Terminates the Kernel branch during bounded rollback or shutdown.
    ///
    /// # Errors
    ///
    /// Returns an error if the owned Kernel Job branch cannot be terminated.
    pub fn terminate_kernel(&mut self) -> Result<(), HostError> {
        // F-LOG-HOST-1: phase only; outer `stop`/reconcile owns the terminal.
        // Termination requested is distinct from stopped.
        host_lifecycle_observe_drain(BOUNDARY_KERNEL_TERMINATE_REQUESTED);
        if let Some(kernel) = self.kernel.as_mut() {
            kernel
                .terminate_in_place(0xE017_0001)
                .map_err(|error| HostError::RecoveryRequired(error.to_string()))?;
            self.kernel.take();
        }
        self.kernel_candidate = None;
        self.kernel_activation_receipt = None;
        host_lifecycle_observe_drain(BOUNDARY_KERNEL_TERMINATE_STOPPED);
        Ok(())
    }

    /// Terminates the store branch during bounded rollback or shutdown.
    ///
    /// # Errors
    ///
    /// Returns an error if the owned store Job branch cannot be terminated.
    pub fn terminate_store(&mut self) -> Result<(), HostError> {
        // F-LOG-HOST-1: phase only; outer `stop`/reconcile owns the terminal.
        host_lifecycle_observe_drain(BOUNDARY_STORE_TERMINATE_REQUESTED);
        if let Some(store) = self.store.as_mut() {
            store
                .terminate_in_place(0xE017_0002)
                .map_err(|error| HostError::RecoveryRequired(error.to_string()))?;
            self.store.take();
        }
        host_lifecycle_observe_drain(BOUNDARY_STORE_TERMINATE_STOPPED);
        Ok(())
    }

    #[allow(dead_code)]
    fn terminate_store_then_kernel(&mut self) -> Result<(), HostError> {
        let store = self.terminate_store();
        let kernel = self.terminate_kernel();
        match (store, kernel) {
            (Ok(()), Ok(())) => Ok(()),
            (store, kernel) => Err(HostError::RecoveryRequired(format!(
                "Store-first termination was incomplete: store={store:?}; kernel={kernel:?}"
            ))),
        }
    }

    fn clear_recorded_contour(&mut self) {
        self.kernel_executable = None;
        self.store_bridge_executable = None;
        self.kernel_lease = None;
        self.store_lease = None;
        self.config_path = None;
        self.config_lease = None;
        self.store_bootstrap_lease = None;
        self.eliotd_config_lease = None;
        self.eliotd_descriptor_lease = None;
        self.store_bootstrap_requirement = None;
        self.config_pin = None;
        self.kernel_artifact_digest = None;
        self.store_artifact_digest = None;
        self.config_digest = None;
        self.agent_bridge_admission = None;
        self.store_config_semantic_hash = None;
        self.approved_generation = None;
        self.kernel_candidate = None;
        self.kernel_activation_receipt = None;
        self.portable_root = None;
        self.launch = None;
        self.kernel_restart_attempts = 0;
        self.store_restart_attempts = 0;
    }

    /// Returns the durable mechanics identity of the Kernel branch.
    #[must_use]
    pub fn kernel_name(&self) -> &str {
        self.kernel_identity.name()
    }

    /// Returns the durable mechanics identity of the store branch.
    #[must_use]
    pub fn store_name(&self) -> &str {
        self.store_identity.name()
    }

    #[must_use]
    pub fn kernel_process(&self) -> Option<&ProcessIdentity> {
        self.kernel.as_ref().map(|child| child.evidence().process())
    }

    #[must_use]
    pub fn store_process(&self) -> Option<&ProcessIdentity> {
        self.store.as_ref().map(|child| child.evidence().process())
    }

    #[must_use]
    pub fn has_recorded_contour(&self) -> bool {
        self.kernel.is_some()
            || self.store.is_some()
            || self.kernel_executable.is_some()
            || self.store_bridge_executable.is_some()
    }
}

fn fresh_identity(prefix: &str) -> Result<PlatformHandle, HostError> {
    PlatformHandle::new(format!("{prefix}-{}", Uuid::new_v4().simple()))
        .map_err(|error| HostError::Platform(error.to_string()))
}

/// Mints a fresh canonical epoch lineage. Only this Host owner boundary (and
/// explicit recovery callers) mints lineages; deserializers and reporters
/// never do.
fn fresh_lineage_id() -> Result<EpochLineageId, HostError> {
    EpochLineageId::new(Uuid::new_v4().to_string())
        .map_err(|error| HostError::Platform(error.to_string()))
}

/// Maps a canonical epoch-contract failure onto the Host journal taxonomy
/// without inventing lineage or sequence authority.
fn epoch_contract_error(error: &EpochContractError) -> JournalError {
    match error {
        EpochContractError::SequenceOverflow => JournalError::Sequence,
        _ => JournalError::EpochLineageConflict,
    }
}

#[cfg(windows)]
mod watchdog_service_start;
#[cfg(windows)]
use watchdog_service_start::{
    InstalledWatchdogControl, InstalledWatchdogRuntimeInspection,
    approved_service_registration_request, select_watchdog_approval_for_inspection,
    start_installed_watchdog, verify_watchdog_scm_running,
};
#[cfg(all(test, windows))]
use watchdog_service_start::{
    InstalledWatchdogStartControl, WATCHDOG_START_TIMEOUT_MS, WatchdogStartClock,
    require_running_watchdog, start_installed_watchdog_with_clock, watchdog_start_wait,
};

fn sha256_json(value: &impl serde::Serialize) -> Result<String, HostError> {
    let bytes =
        serde_json::to_vec(value).map_err(|error| HostError::ProcessContour(error.to_string()))?;
    Ok(format!("{:x}", Sha256::digest(bytes)))
}

#[cfg(windows)]
mod watchdog_publication;
#[cfg(windows)]
use watchdog_publication::{
    observe_host_watchdog_publication, publish_current_watchdog_supervision_bundle,
    read_manifest_current_supervision_lease, supervision_publication_identity,
    verify_exact_current_watchdog_publication,
};
#[cfg(windows)]
mod watchdog_heartbeat;

#[cfg(windows)]
fn host_owned_store_recovery_request(
    host: &HostInstallationEpoch,
    activation_id: &PlatformHandle,
    activation_generation: &EpochTransition,
    generation: &PlatformHandle,
    config_digest: &PlatformHandle,
) -> Result<HostRuntimeControlRequest, HostError> {
    let identity_digest = sha256_json(&(
        "eliot-host::scm-store-recovery:v1",
        &host.installation,
        &host.epoch,
        activation_id,
        activation_generation,
        generation,
        config_digest,
    ))?;
    let request_id =
        PlatformHandle::new(format!("host-owned-scm-store-recovery:{identity_digest}"))
            .map_err(|error| HostError::ProcessContour(error.to_string()))?;
    HostRuntimeControlRequest::new(HostRuntimeControlOperation::RecoverStore, request_id)
        .map_err(HostError::ProcessContour)
}

fn phase_b_unknown_ref(
    prefix: &str,
    operation: &str,
    intent: &HostPhaseBMaterializationIntent,
) -> PlatformHandle {
    PlatformHandle::new(format!(
        "{prefix}:operation={operation}:transaction_id={}:effect_id={}:request_digest={}",
        intent.transaction_id.as_str(),
        intent.effect_id.as_str(),
        intent.request_digest.as_str()
    ))
    .unwrap_or_else(|_| unreachable!())
}

fn root_epoch(lineage_id: EpochLineageId) -> EpochTransition {
    EpochTransition::genesis(lineage_id)
}

fn fresh_host_epoch(
    installation: PlatformHandle,
    recovery: Option<RecoveryLineageEvidence>,
) -> Result<HostInstallationEpoch, HostError> {
    Ok(HostInstallationEpoch {
        installation,
        epoch: root_epoch(fresh_lineage_id()?),
        nonce: fresh_identity("host-process-nonce")?,
        recovery,
    })
}

fn child_host_epoch(parent: &HostInstallationEpoch) -> Result<HostInstallationEpoch, HostError> {
    Ok(HostInstallationEpoch {
        installation: parent.installation.clone(),
        epoch: EpochTransition::direct_child(&parent.epoch.current)
            .map_err(|error| epoch_contract_error(&error))?,
        nonce: fresh_identity("host-process-nonce")?,
        recovery: None,
    })
}

fn operation(label: &str) -> Result<IdempotencyIdentity, HostError> {
    Ok(IdempotencyIdentity {
        operation_id: fresh_identity(label)?,
        idempotency_key: fresh_identity(&format!("{label}-idempotency"))?,
    })
}

/// Deterministic journal mutation identity for one pre-commit drain re-arm.
///
/// The journal keys `applied_operations` on this identity, so a re-arm retried
/// after a crash or an `OutcomeUnknown` append must reuse it and append
/// byte-identical record bytes to replay instead of forking a second attempt.
/// [`operation`] mints two fresh identities per call and therefore can never
/// reach the replay result; the cutover and Store-rebind seams already use one
/// deterministic identity per logical mutation.
///
/// Every input is a durable fact of the attempt — the activation fence, the
/// drain generation, the exact cancelled predecessor record checksum, the
/// authoritative census code and the appended stage — so the identity is a
/// function of the attempt itself and not of process-local time or call order.
/// One identity per appended stage follows the cutover and Store-rebind
/// convention: sharing one identity across two appended records would be a
/// checksum conflict, not a second mutation.
#[cfg(windows)]
fn drain_rearm_operation(
    fence: &RecordFence,
    drain_generation: &EpochTransition,
    predecessor_checksum: &str,
    census_code: &str,
    stage: &str,
) -> Result<IdempotencyIdentity, HostError> {
    let attempt = sha256_json(&(
        "eliot-host::drain-rearm:v1",
        stage,
        &fence.activation_id,
        &fence.activation_generation,
        drain_generation,
        predecessor_checksum,
        census_code,
    ))?;
    Ok(IdempotencyIdentity {
        operation_id: PlatformHandle::new(format!("host-drain-rearm:{stage}:{attempt}"))
            .map_err(|error| HostError::Platform(error.to_string()))?,
        idempotency_key: PlatformHandle::new(attempt)
            .map_err(|error| HostError::Platform(error.to_string()))?,
    })
}

fn record_fence(
    host: &HostInstallationEpoch,
    activation_id: &PlatformHandle,
    activation_generation: &EpochTransition,
) -> RecordFence {
    RecordFence {
        host: host.clone(),
        activation_id: activation_id.clone(),
        activation_generation: activation_generation.clone(),
    }
}

mod journal_append;
#[cfg(windows)]
use journal_append::{
    append_authenticated_kernel_readiness_with_heartbeat, append_store_rebind_terminal,
    persist_store_rebind_disposition,
};
// The pre-transport append stays covered by journal tests through the
// glob import below them; outside tests nothing else calls it.
#[cfg(windows)]
#[cfg_attr(not(test), allow(unused_imports))]
use journal_append::append_authenticated_kernel_readiness;
#[cfg(test)]
use journal_append::{append_clean_marker, exact_termination_binding_matches};
use journal_append::{
    append_reconciled, clean_marker_record, degraded_activation, drain_commit_record_for_stop,
    initial_activation_record, pending_activation_binding, terminated_prior_kernel,
    transition_activation_record, transition_activation_record_with_evidence,
};

mod store_recovery_fence;
use store_recovery_fence::{
    ActivePhaseBRebindRecoveryKind, StoreRecoveryReopenFence, StoreRecoveryStartupFence,
    active_phase_b_rebind_recovery_kind,
};

mod host_epoch_reopen;
#[cfg(all(windows, test))]
use host_epoch_reopen::open_test_support_epoch;
#[cfg(windows)]
use host_epoch_reopen::{open_production_epoch, persist_pending_recovery};
#[cfg(test)]
use host_epoch_reopen::{open_production_epoch_from_backend, reopen_existing_epoch};

#[cfg(windows)]
mod host_durable_persistence;

#[cfg(windows)]
mod runtime_restart_state;
#[cfg(windows)]
use runtime_restart_state::{
    RuntimeRestartPendingPublication, has_runtime_restart_pending, load_durable_runtime_restarts,
    persist_runtime_restart_pending, persist_runtime_restart_receipt,
    read_bounded_runtime_restart_file, rebind_runtime_restart_receipt,
};
#[cfg(all(windows, test))]
use runtime_restart_state::{
    runtime_restart_pending_path, runtime_restart_receipt_path, runtime_restart_store_dir,
};

#[cfg(windows)]
mod store_recovery_persistence;
#[cfg(all(windows, test))]
use store_recovery_persistence::store_recovery_receipt_path;
#[cfg(windows)]
use store_recovery_persistence::{
    StoreRecoveryPendingIdentity, StoreRecoveryPendingPublication,
    cleanup_completed_store_recovery_supporting_evidence,
    cleanup_store_recovery_supporting_evidence_for, committed_store_rebind_receipt,
    has_store_recovery_pending, load_durable_store_recoveries,
    persist_store_recovery_inner_binding, persist_store_recovery_pending,
    persist_store_recovery_receipt, persist_store_recovery_termination_evidence,
    read_store_recovery_pending_identity, read_store_recovery_receipt,
    rebind_store_recovery_receipt, store_recovery_inner_binding_path, store_recovery_pending_path,
    store_recovery_termination_path,
};

#[cfg(windows)]
mod store_recovery_evidence;
#[cfg(windows)]
use store_recovery_evidence::{
    StoreRecoveryInnerBinding, StoreRecoveryTerminationEvidence, read_store_recovery_inner_binding,
    read_store_recovery_termination_evidence,
};

#[cfg(windows)]
#[derive(Clone, Debug)]
struct WatchdogStartRecoveryCarrier {
    registration: ServiceRegistrationRequest,
    platform_root: PathBuf,
    heartbeat_state_root: PathBuf,
    issued_descriptor: watchdog_heartbeat::HeartbeatTransportDescriptor,
    initial_stopped_without_process: bool,
    descriptor_published: bool,
    start_may_have_issued: bool,
}

/// Host-owned lifecycle state and installation activation registry.
#[allow(
    clippy::struct_excessive_bools,
    reason = "the lifecycle flags are independent durable shutdown and lease-release fences"
)]
pub struct HostComposition {
    #[allow(
        dead_code,
        reason = "zero-sized marker binds the production Store-rebind seam"
    )]
    store_rebind_boundary: HostStoreRebindProductionBoundary,
    #[allow(
        dead_code,
        reason = "zero-sized marker binds the production runtime-control seam"
    )]
    runtime_control_boundary: HostRuntimeControlProductionBoundary,
    journal: ProductionHostStateJournal,
    /// Retained canonical Host state root for short-lived installation-registry
    /// opens (#1339, A13.9).
    ///
    /// Host is the registry's live compare-and-swap owner, but it never
    /// retains the exclusive redb `Database` across the process lifetime:
    /// every Phase-B and recovery mutation opens a short-lived
    /// `RedbInstallationRegistry` via `open_registry_store_at` (bounded
    /// `DatabaseAlreadyOpen` retry), commits one expected-revision CAS, and
    /// drops the handle before any wait; readbacks re-open the same way. The
    /// installer releases its staging writer before the SCM start +
    /// convergence wait (`bins/eliot/src/main.rs` INSTALL-WATCHDOG-APPROVAL
    /// `drop(registry)`), and readers (Watchdog short-lived
    /// `inspect_existing_at`, installer reconcile `open_existing_at`) treat
    /// `DatabaseAlreadyOpen` lock contention as bounded transient retry. The
    /// cached `registry` projection below is revision-keyed and rebuildable
    /// from these short-lived opens; it never creates authority or freshness.
    registry_host_root: PathBuf,
    #[cfg(test)]
    test_registry_file: Option<PathBuf>,
    registry: ApprovedGenerationRegistry,
    launch_options: HostLaunchOptions,
    host: HostInstallationEpoch,
    activation_generation: EpochTransition,
    activation_id: PlatformHandle,
    running: bool,
    #[cfg(windows)]
    jobs: HostJobBranches,
    #[cfg(windows)]
    readiness_gate: HostReadinessGate,
    #[cfg(windows)]
    phase_b: Option<HostPhaseBMaterialization>,
    #[cfg(windows)]
    watchdog_start_recovery: Option<WatchdogStartRecoveryCarrier>,
    #[cfg(windows)]
    runtime_restarts: std::collections::HashMap<String, HostKernelRestartReceipt>,
    #[cfg(windows)]
    runtime_control_queue: HostRuntimeControlQueue,
    #[cfg(windows)]
    user_automation_execution_queue: HostUserAutomationExecutionQueue,
    #[cfg(windows)]
    store_recovery_startup_fence: StoreRecoveryStartupFence,
    active_phase_b_rebind_recovery: ActivePhaseBRebindRecoveryKind,
    owner_lease: HostOwnerLease,
    pending_record: Option<HostStateRecord>,
    durable_finalized: bool,
    owner_released: bool,
    shutdown_failed: bool,
}

#[cfg(windows)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum HostStartupBranch {
    Active,
    Pending,
}

/// Exact external authority bytes supplied for Host Phase B.
///
/// The installer never constructs this value. Host accepts it only after the
/// real Host installation epoch is open and validates the descriptor's digest,
/// ORS snapshot fence, and candidate/epoch binding before publication.
#[cfg(windows)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HostPhaseBInput {
    /// Canonical serialized [`ProcessAuthorityHandoffDescriptor`] bytes.
    pub authority_descriptor_bytes: Vec<u8>,
}

/// Receipt for one complete Host Phase B materialization.
///
/// The manifest remains immutable. `file_identities` are post-publication OS
/// observations and therefore are deliberately kept out of the manifest and
/// its digest domain.
#[cfg(windows)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HostPhaseBMaterialization {
    transaction_id: Option<PlatformHandle>,
    effect_id: Option<PlatformHandle>,
    credential_receipt_digest: Option<PlatformHandle>,
    host_owner_epoch: Option<PlatformHandle>,
    host_process_identity: Option<PlatformHandle>,
    manifest_digest: PlatformHandle,
    host_epoch: EpochIdentity,
    host_process_nonce: PlatformHandle,
    activation_generation: EpochIdentity,
    authority_descriptor_digest: PlatformHandle,
    store_bootstrap_descriptor_digest: PlatformHandle,
    config_file_digest: PlatformHandle,
    semantic_config_hash: PlatformHandle,
    eliotd_descriptor_digest: PlatformHandle,
    /// Exact Phase-B request bound to this materialization, when it was
    /// published through the transaction-owned installer handoff.
    request_digest: Option<PlatformHandle>,
    public_receipt_digest: Option<PlatformHandle>,
    /// Exact stage/profile/declaration proof for the optional Agent Bridge.
    /// This is never synthesized from a manifest or runtime descriptor.
    agent_bridge: Option<AgentBridgePreparedBinding>,
    /// Final provider proof, populated only after `FinalizePhaseB` CAS.
    agent_bridge_final: Option<AgentBridgePhaseBBinding>,
    file_identities: [FileIdentity; 4],
    launch: RuntimeLaunchDescriptor,
}

#[cfg(windows)]
impl HostPhaseBMaterialization {
    /// Returns the immutable candidate manifest digest bound by this receipt.
    #[must_use]
    pub const fn manifest_digest(&self) -> &PlatformHandle {
        &self.manifest_digest
    }

    /// Returns the exact Host epoch observed before Phase B publication.
    #[must_use]
    pub const fn host_epoch(&self) -> &EpochIdentity {
        &self.host_epoch
    }

    /// Returns the fresh Host process nonce that owns this materialization.
    #[must_use]
    pub const fn host_process_nonce(&self) -> &PlatformHandle {
        &self.host_process_nonce
    }

    /// Returns the live launch overlay consumed by Host process admission.
    #[must_use]
    pub const fn launch(&self) -> &RuntimeLaunchDescriptor {
        &self.launch
    }

    /// Returns the physical SHA-256 of the materialized Store config bytes.
    #[must_use]
    pub const fn config_file_digest(&self) -> &PlatformHandle {
        &self.config_file_digest
    }

    /// Returns the semantic Store approved-config hash.
    #[must_use]
    pub const fn semantic_config_hash(&self) -> &PlatformHandle {
        &self.semantic_config_hash
    }

    /// Returns post-materialization identities in authority/config/bootstrap/
    /// eliotd descriptor order.
    #[must_use]
    pub const fn file_identities(&self) -> &[FileIdentity; 4] {
        &self.file_identities
    }

    /// Returns the verified Agent Bridge proof, when this is a bridge-enabled
    /// Phase-B materialization.
    #[must_use]
    pub const fn agent_bridge(&self) -> Option<&AgentBridgePreparedBinding> {
        self.agent_bridge.as_ref()
    }

    #[must_use]
    pub const fn final_agent_bridge(&self) -> Option<&AgentBridgePhaseBBinding> {
        self.agent_bridge_final.as_ref()
    }
}

#[cfg(windows)]
trait ApprovedHostStartupPort {
    fn start_approved_manifest(
        &mut self,
        manifest: &CandidateManifest,
        branch: HostStartupBranch,
        kernel_executable: &Path,
        store_bridge_executable: &Path,
        store_artifact: &PlatformHandle,
        pending: Option<&eliot_installation::PendingActivation>,
    ) -> Result<(), HostError>;
}

#[cfg(windows)]
fn start_approved_manifest_contour<P: ApprovedHostStartupPort>(
    port: &mut P,
    manifest: &CandidateManifest,
    branch: HostStartupBranch,
    pending: Option<&eliot_installation::PendingActivation>,
) -> Result<(), HostError> {
    let (approved_kernel_path, approved_store_bridge_path, _) = manifest.host_child_paths();
    let (_, store_artifact) = manifest
        .host_child_artifact_digests()
        .map_err(|error| HostError::ProcessContour(error.to_string()))?;
    port.start_approved_manifest(
        manifest,
        branch,
        Path::new(approved_kernel_path.as_str()),
        Path::new(approved_store_bridge_path.as_str()),
        store_artifact,
        pending,
    )
}

/// Bounded `DatabaseAlreadyOpen` retry budget for the Host registry open
/// (s37/#1339). Six attempts back off 250ms, 500ms, 1s, then 2s capped, so
/// the worst-case wait stays near 8s: inside the SCM start-pending window
/// and always interruptible by process stop.
const HOST_REGISTRY_OPEN_RETRY_ATTEMPTS: u32 = 6;
const HOST_REGISTRY_OPEN_RETRY_BASE_MS: u64 = 250;
const HOST_REGISTRY_OPEN_RETRY_MAX_MS: u64 = 2_000;

/// Returns true when `error` carries redb file-lock contention (a live writer
/// holds the registry file). This mirrors the Watchdog reader probe
/// (`FileWatchdogAdmission::is_transient_registry_lock`): matching is
/// case-insensitive and requires the lock marker so unrelated platform text
/// that merely mentions an open path stays fail-closed.
fn installation_registry_lock_contended(error: &InstallationError) -> bool {
    let folded = error.to_string().to_ascii_lowercase();
    folded.contains("cannot acquire lock")
        || ((folded.contains("already open") || folded.contains("alreadyopen"))
            && folded.contains("lock"))
}

/// Opens the existing installation registry below `host_state_root`,
/// tolerating a short writer-release race with bounded backoff.
///
/// The installer staging writer is released before the SCM start +
/// convergence wait, so lock contention here is a release race, not a held
/// owner (A13.9). Each attempt opens a fresh short-lived root lease and
/// re-proves the exact retained-root identity before touching the database;
/// every non-contention failure still fails closed immediately.
///
/// # Errors
///
/// Returns [`HostError::Platform`] when the root lease or path proof fails,
/// and [`HostError::Installation`] when the registry open fails, including
/// contention that outlasts the bounded retry budget.
pub(crate) fn open_installation_registry_with_transient_retry(
    host_state_root: &Path,
) -> Result<Option<RedbInstallationRegistry>, HostError> {
    let mut attempt = 0_u32;
    loop {
        let root_lease = ProtectedRootLease::open_existing(host_state_root)
            .map_err(|error| HostError::Platform(error.to_string()))?;
        let canonical = root_lease
            .canonical_path()
            .map_err(|error| HostError::Platform(error.to_string()))?;
        if canonical.as_path() != host_state_root {
            return Err(HostError::ProcessContour(
                "SCM Host state root is not the exact retained installation root".to_owned(),
            ));
        }
        match RedbInstallationRegistry::open_existing_at(root_lease) {
            Ok(store) => return Ok(store),
            Err(error)
                if installation_registry_lock_contended(&error)
                    && attempt < HOST_REGISTRY_OPEN_RETRY_ATTEMPTS =>
            {
                attempt += 1;
                let shift = attempt.saturating_sub(1).min(3);
                let backoff_ms = (HOST_REGISTRY_OPEN_RETRY_BASE_MS << shift)
                    .min(HOST_REGISTRY_OPEN_RETRY_MAX_MS);
                std::thread::sleep(std::time::Duration::from_millis(backoff_ms));
            }
            Err(error) => return Err(HostError::Installation(error)),
        }
    }
}

/// Opens one short-lived installation-registry writer below
/// `host_state_root` (#1339, A13.9).
///
/// Each caller drops the returned handle immediately after one bounded CAS or
/// load; no handle is retained across waits. Returns
/// [`HostError::ProcessContour`] when the registry file is absent.
///
/// # Errors
///
/// Returns [`HostError`] when the root lease, path proof, or bounded
/// contention retry fails.
pub(crate) fn open_registry_store_at(
    host_state_root: &Path,
) -> Result<RedbInstallationRegistry, HostError> {
    open_installation_registry_with_transient_retry(host_state_root)?.ok_or_else(|| {
        HostError::ProcessContour(
            "SCM Host state root has no approved-generation registry".to_owned(),
        )
    })
}

/// One real, type-checked backup dispatch target (#961).
///
/// The dispatch table in
/// [`HostComposition::register_backup_dispatch`] carries owner-path markers
/// for documentation; this enum is the routing decision the production
/// dispatch arms actually follow, so a cutover cannot reach the #961 owner
/// chain through an unchecked string. Each variant names exactly one
/// admitted owner port:
/// - `Prepare` — [`HostComposition::backup_dispatch_prepare`], delegating to
///   [`crate::backup_preparation::DelegatedPreparation::prepare`];
/// - `Cutover` — [`HostComposition::backup_dispatch_cutover`], delegating to
///   [`crate::backup_cutover::execute_cutover`] under a separate cutover
///   admission.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BackupDispatchTarget {
    Prepare,
    Cutover,
}

impl HostComposition {
    /// Opens one short-lived installation-registry handle below the retained
    /// Host root (#1339, A13.9). The caller drops it after one CAS or load.
    pub(crate) fn open_registry_store(&self) -> Result<RedbInstallationRegistry, HostError> {
        #[cfg(test)]
        if let Some(path) = self.test_registry_file.as_ref() {
            return RedbInstallationRegistry::open_test_support(path)
                .map_err(HostError::Installation);
        }
        open_registry_store_at(&self.registry_host_root)
    }

    /// Prepares one isolated backup destination through registry-committed
    /// owner evidence (B-BACKUP-HOST-PREP #958).
    ///
    /// Binds the delegation sink to live composition authority: the
    /// presented caller passes the
    /// [`BackupCallerAuth`](crate::backup_preparation::BackupCallerAuth)
    /// owner gate (held lease covers the launch installation, presented
    /// source equals it), and the destination is prepared from inspected
    /// owner evidence through the caller-supplied journal sink. The sink
    /// returns alongside the destination so the caller can reconcile,
    /// cancel, or clean up the same operation later. Durable production
    /// journal binding awaits the Host-state owner's preparation record
    /// variant; until then the sink stays a port. Caller-channel
    /// authentication beyond this installation binding stays parameterized
    /// pending role-bound control contracts.
    ///
    /// # Errors
    ///
    /// Returns [`PreparationError`](crate::backup_preparation::PreparationError)
    /// when the caller gate, lease/installation binding, owner evidence,
    /// admission, or journal persistence fails closed.
    pub fn prepare_backup_destination<J: crate::backup_preparation::PreparationJournal>(
        &self,
        journal: J,
        caller: &crate::backup_preparation::BackupCallerAuth,
        request: &crate::backup_preparation::PresentedPreparationRequest,
    ) -> Result<
        (
            crate::backup_preparation::DelegatedPreparation<J>,
            crate::backup_preparation::PreparedDestination,
        ),
        crate::backup_preparation::PreparationError,
    > {
        use crate::backup_preparation::{DelegatedPreparation, OwnerEvidence, PreparationError};
        caller.authenticate_for_owner(
            &self.owner_lease,
            self.launch_options.installation(),
            &request.source_installation_id,
        )?;
        let evidence = OwnerEvidence::inspect(&self.registry_host_root)?;
        // Registry-revision fence (A13.9 short-lived reads): the owner evidence
        // above was read at one CAS revision, and preparing against a registry
        // that moved since would mix owner generations. Refuse with no effect.
        if evidence.revision() != self.registry.revision() {
            return Err(PreparationError::InvalidRequest {
                field: "owner_evidence_revision",
                reason: "owner registry moved between inspection and preparation".to_owned(),
            });
        }
        let mut sink = DelegatedPreparation::new(journal);
        let prepared = sink.prepare(&evidence, request)?;
        Ok((sink, prepared))
    }

    /// Accepted backup dispatch table (#954 envelope/method bridge, #962).
    ///
    /// Each entry is `(operation, owner path marker, needs_cutover_admission)`:
    /// `PREPARE_ISOLATED_RESTORE` resolves through the #958 owner preparation
    /// chain (see [`HostComposition::backup_dispatch_prepare`], which calls
    /// [`DelegatedPreparation::prepare`](crate::backup_preparation::DelegatedPreparation::prepare));
    /// `ADMIT_CUTOVER` resolves through the #961 owner cutover chain
    /// (`crate::backup_cutover::execute_cutover`) exclusively under a separate
    /// cutover admission. No algorithm is reimplemented here. Registration
    /// runs [`HostComposition::validate_backup_dispatch_prepare_routing`]
    /// over the table so the routing cannot rot unwired.
    pub fn register_backup_dispatch() -> [(
        eliot_protocol::backup::BackupOperationKind,
        &'static str,
        bool,
    ); 2] {
        use eliot_protocol::backup::BackupOperationKind as BackupOp;
        let dispatch = [
            (
                BackupOp::PrepareIsolatedRestore,
                "crate::backup_preparation::DelegatedPreparation::prepare",
                false,
            ),
            (
                BackupOp::AdmitCutover,
                "crate::backup_cutover::execute_cutover",
                true,
            ),
        ];
        // Pin the preparation routing validation into registration;
        // wiring-only, no backup operation runs here.
        Self::validate_backup_dispatch_prepare_routing(dispatch);
        dispatch
    }

    /// Validates the accepted backup dispatch routing shared by
    /// registration and preparation (#962).
    ///
    /// Wiring-only pin: the closed two-entry table carries the preparation
    /// path without cutover admission and the cutover path with it, while
    /// rehearsal completion resolves to no entry so rehearsal can never
    /// route to cutover. [`HostComposition::register_backup_dispatch`]
    /// invokes this validation, and so does
    /// [`HostComposition::backup_dispatch_prepare`] before delegating to
    /// [`HostComposition::prepare_backup_destination`]; no backup operation
    /// runs here.
    fn validate_backup_dispatch_prepare_routing(
        dispatch: [(
            eliot_protocol::backup::BackupOperationKind,
            &'static str,
            bool,
        ); 2],
    ) {
        use eliot_protocol::backup::BackupOperationKind as BackupOp;
        // Length is pinned by the `[T; 2]` type; pin the routing contents.
        let [
            (prepare_op, prepare_marker, prepare_admission),
            (cutover_op, cutover_marker, cutover_admission),
        ] = dispatch;
        debug_assert_eq!(prepare_op, BackupOp::PrepareIsolatedRestore);
        debug_assert!(!prepare_marker.is_empty());
        debug_assert!(!prepare_admission);
        debug_assert_eq!(cutover_op, BackupOp::AdmitCutover);
        debug_assert!(!cutover_marker.is_empty());
        debug_assert!(cutover_admission);
        debug_assert_eq!(
            Self::backup_dispatch_needs_cutover_admission(BackupOp::PrepareIsolatedRestore),
            Some(false)
        );
        debug_assert_eq!(
            Self::backup_dispatch_needs_cutover_admission(BackupOp::AdmitCutover),
            Some(true)
        );
        debug_assert_eq!(
            Self::backup_dispatch_needs_cutover_admission(BackupOp::CompleteRehearsal),
            None
        );
        // Pin the type-checked routing table against the admission table and
        // the registration table: every registration entry must resolve
        // the same real dispatch target, and rehearsal completion must
        // resolve none in both.
        debug_assert_eq!(
            Self::backup_dispatch_target(BackupOp::PrepareIsolatedRestore),
            Some(BackupDispatchTarget::Prepare)
        );
        debug_assert_eq!(
            Self::backup_dispatch_target(BackupOp::AdmitCutover),
            Some(BackupDispatchTarget::Cutover)
        );
        debug_assert_eq!(
            Self::backup_dispatch_target(BackupOp::CompleteRehearsal),
            None
        );
        for (operation, _, needs_cutover_admission) in dispatch {
            // Every registered entry must resolve a real type-checked
            // dispatch target: the marker table alone is documentation, so
            // without this an entry could name a path that no typed arm
            // follows.
            debug_assert!(Self::backup_dispatch_target(operation).is_some());
            // The registration flag is the "needs a separate cutover
            // admission" bit, so it must agree with the admission table.
            // It is deliberately NOT compared against `is_some()`: a
            // prepared operation resolves a `Prepare` target and still
            // needs no cutover admission.
            debug_assert_eq!(
                Self::backup_dispatch_needs_cutover_admission(operation),
                Some(needs_cutover_admission)
            );
        }
    }

    /// Reports whether one backup operation needs a separate cutover
    /// admission on the dispatch table (#962).
    ///
    /// Returns `Some(false)` for the preparation path, `Some(true)` for the
    /// cutover path, and `None` for operations with no dispatch entry.
    /// Rehearsal guard: `COMPLETE_REHEARSAL` returns `None`, so a rehearsal
    /// completion can never resolve cutover.
    pub fn backup_dispatch_needs_cutover_admission(
        operation: eliot_protocol::backup::BackupOperationKind,
    ) -> Option<bool> {
        use eliot_protocol::backup::BackupOperationKind as BackupOp;
        match operation {
            BackupOp::PrepareIsolatedRestore => Some(false),
            BackupOp::AdmitCutover => Some(true),
            // `CompleteRehearsal` and every other operation share this arm:
            // rehearsal completion has no dispatch entry, so it can never
            // resolve cutover.
            _ => None,
        }
    }

    /// Resolves one admitted backup operation to the real owner dispatch
    /// target the Host composition actually follows (#961).
    ///
    /// The dispatch table's `&'static str` markers stay documentation; this
    /// typed resolution is the routing decision the production cutover arm
    /// is dispatched on, so a cutover reaches
    /// [`HostComposition::backup_dispatch_cutover`] through a type-checked
    /// match instead of an unchecked string. `None` is returned for every
    /// operation with no dispatch entry, including `COMPLETE_REHEARSAL`.
    /// [`HostComposition::validate_backup_dispatch_prepare_routing`] pins
    /// this table against the registration table and against
    /// [`HostComposition::backup_dispatch_needs_cutover_admission`], so the
    /// two cannot rot apart.
    pub fn backup_dispatch_target(
        operation: eliot_protocol::backup::BackupOperationKind,
    ) -> Option<BackupDispatchTarget> {
        use eliot_protocol::backup::BackupOperationKind as BackupOp;
        match operation {
            BackupOp::PrepareIsolatedRestore => Some(BackupDispatchTarget::Prepare),
            BackupOp::AdmitCutover => Some(BackupDispatchTarget::Cutover),
            // No dispatch entry: rehearsal completion and every other
            // operation can never resolve a dispatch target.
            _ => None,
        }
    }

    /// Dispatches one accepted preparation through the existing owner chain
    /// (#962). This delegates to
    /// [`HostComposition::prepare_backup_destination`], which authenticates
    /// the caller, inspects owner evidence, and runs
    /// [`DelegatedPreparation::prepare`](crate::backup_preparation::DelegatedPreparation::prepare);
    /// the production caller chain is preserved and no algorithm is
    /// reimplemented here.
    ///
    /// # Errors
    ///
    /// Returns [`PreparationError`](crate::backup_preparation::PreparationError)
    /// when the caller gate, lease/installation binding, owner evidence,
    /// admission, or journal persistence fails closed.
    pub fn backup_dispatch_prepare<J: crate::backup_preparation::PreparationJournal>(
        &self,
        journal: J,
        caller: &crate::backup_preparation::BackupCallerAuth,
        request: &crate::backup_preparation::PresentedPreparationRequest,
    ) -> Result<
        (
            crate::backup_preparation::DelegatedPreparation<J>,
            crate::backup_preparation::PreparedDestination,
        ),
        crate::backup_preparation::PreparationError,
    > {
        // Route through the shared dispatch validation before delegating:
        // preparation must resolve without cutover admission, cutover with
        // it, and rehearsal completion to no entry.
        Self::validate_backup_dispatch_prepare_routing(Self::register_backup_dispatch());
        self.prepare_backup_destination(journal, caller, request)
    }

    /// Dispatches one admitted installation cutover through the existing
    /// owner chain (#961). This is the exact admitted cutover port
    /// delegation: it is the production caller of
    /// [`crate::backup_cutover::execute_cutover`], which is the owner path
    /// the registration marker names.
    ///
    /// Real owner calls, in order: the operation resolved from the admitted
    /// cutover payload through
    /// [`crate::backup_cutover::admitted_cutover_operation`], which proves the
    /// presented body is the body the admitted envelope committed to and then
    /// requires the separately supplied selector to agree with the operation
    /// that body authorizes (a rehearsal completion, or any other selector,
    /// authorizes nothing and a valid selector can never override an unrelated
    /// admitted body); the shared
    /// [`HostComposition::validate_backup_dispatch_prepare_routing`] pin; a
    /// fresh short-lived registry readback through
    /// [`Self::open_registry_store`] plus
    /// [`RedbInstallationRegistry::load`] feeding
    /// [`crate::backup_cutover::validate_cutover_request`] (the same
    /// fail-closed gate set the owner runs, never a local boolean); the
    /// durable Host activation identity read from the journal owner, so the
    /// activation bound by the cutover is the Host's own committed
    /// generation and not a caller-supplied copy; then
    /// [`crate::backup_cutover::execute_cutover`], which re-reads the
    /// registry owner (TOCTOU fence), re-proves the retained cutover body
    /// against the admitted envelope at the effect boundary, live-verifies
    /// the prior capability-introduction set through the authenticated Kernel
    /// front door, requires the exact-fence
    /// [`GenerationRetirementBarrier`], and only then performs the
    /// activation CAS. Finally the bounded reconciliation is closed by
    /// re-reading the real registry owner and projecting it through
    /// [`crate::backup_cutover::reconcile_cutover_outcome`] under the same
    /// operation identity, so a lost response or a crash between the
    /// registry and the journal returns the exact `Unknown` disposition
    /// instead of a local assumption. No algorithm is reimplemented here and
    /// no cutover is executed at Host startup: this method runs only when an
    /// admitted cutover operation is dispatched.
    ///
    /// Prior-generation process/SCM retirement remains a separate explicitly
    /// authorized
    /// [`Self::backup_dispatch_cutover_retire`] step holding the
    /// returned barrier; source retention and erasure are never automatic
    /// cleanup here.
    ///
    /// # Errors
    ///
    /// Returns [`CutoverError`](crate::backup_cutover::CutoverError) when the
    /// separately supplied operation does not match the operation the admitted
    /// cutover payload authorizes, the Host activation is absent, the owner
    /// gate set, retirement barrier, or registry CAS refuses, or the
    /// post-commit owner readback does not show the committed target
    /// generation.
    #[cfg(windows)]
    #[allow(
        clippy::too_many_lines,
        reason = "the admitted cutover port delegation keeps the owner gate set, the durable activation binding, and the owner-readback reconciliation in one fail-closed boundary"
    )]
    pub fn backup_dispatch_cutover(
        &mut self,
        operation: eliot_protocol::backup::BackupOperationKind,
        request: &crate::backup_cutover::CutoverRequest,
        evidence: &crate::backup_cutover::IsolatedRecoveryEvidence,
        retirement: &GenerationRetirementFence,
    ) -> Result<
        (
            crate::backup_cutover::CutoverOutcome,
            GenerationRetirementBarrier,
        ),
        crate::backup_cutover::CutoverError,
    > {
        use crate::backup_cutover::{
            CutoverDisposition, CutoverError, OwnerObservationCoherence,
            admitted_cutover_operation, execute_cutover, plan_cutover_attempt,
            reconcile_cutover_outcome, validate_cutover_identity, validate_cutover_request,
        };
        // Real dispatch decision, resolved from the admitted cutover payload
        // itself rather than from the routing table: the presented body must
        // first prove it is the body the owner admitted, and only then does the
        // separately supplied selector have to agree with the operation that
        // body authorizes. A selector is therefore never the thing that
        // authorizes a cutover, and it cannot override an admitted body.
        let admitted = admitted_cutover_operation(request)?;
        if operation != admitted {
            return Err(CutoverError::NotSeparatelyAdmitted(format!(
                "separately supplied backup operation {operation:?} does not match the \
                 admitted cutover operation {admitted:?}"
            )));
        }
        // Route through the shared dispatch validation before delegating,
        // exactly as the preparation arm does.
        Self::validate_backup_dispatch_prepare_routing(Self::register_backup_dispatch());
        // Owner gate set against a fresh registry projection, through the
        // owner's own validator. No local boolean stands in for any gate.
        let registry = self
            .open_registry_store()?
            .load()
            .map_err(|error| CutoverError::Registry(error.to_string()))?;
        // Authenticated identity FIRST, then the retained-operation
        // classification, then admission. The classification reports a typed
        // difference between "no such operation", "terminally refused" and
        // "same key, different content", so running it against an
        // unauthenticated presented operation id would be a pre-authentication
        // oracle. Authentication first, classification second, admission third.
        validate_cutover_identity(request)?;
        // The retained operation is classified and the registry's
        // operation-bound outcome resolved BEFORE the admission gate set's
        // expected-predecessor check, so an exact committed retry and an
        // interrupted post-CAS operation are no longer refused by a gate that is
        // false by construction once their own activation committed (#2737).
        // The gate this yields is derived from the durable classification,
        // never asserted here.
        let plan = plan_cutover_attempt(self, request, &registry)?;
        let validated =
            validate_cutover_request(request, evidence, &registry, plan.predecessor_gate())?;
        drop(registry);
        // The activation bound to the cutover is the Host journal owner's
        // committed generation, never a caller-supplied copy.
        let state = self.journal.snapshot().map_err(|error| {
            CutoverError::HostTransition(HostError::OwnerLeaseRecovery(error.to_string()))
        })?;
        let activation = state
            .activation
            .as_ref()
            .ok_or(CutoverError::HostTransition(HostError::OwnerLeaseRecovery(
                "cutover dispatch has no durable Host activation".to_owned(),
            )))?;
        let activation_id = activation.activation_id.clone();
        let activation_generation = activation.fence.activation_generation.clone();
        let (committed, barrier) = execute_cutover(
            self,
            &validated,
            retirement,
            &activation_id,
            &activation_generation,
        )?;
        // Bounded reconciliation closed by a real owner readback under the
        // same operation identity. The retirement is resolved through the same
        // journal-owner lookup the disposition port uses, so this projection
        // never asserts an absent retirement it did not look up, and it never
        // attaches a presented receipt as if it proved one. The registry flip
        // alone is therefore the observed proof and the honest disposition is
        // `RetirementPending`.
        //
        // The projection runs only for a PROVEN commit. An unresolved outcome
        // is returned exactly as its owner observation produced it, so this
        // read model can never restate a retained unknown as progress (#2737).
        if committed.disposition != CutoverDisposition::Committed {
            return Ok((committed, barrier));
        }
        // The registry and the journal are separate owners with no shared
        // transaction, so the pair is only one moment if the journal is sampled
        // on BOTH sides of the registry read. The pre-registry sample is what
        // brackets the load; a sample taken only after it would leave the load
        // outside the compared interval and certify a torn pair as settled.
        let before = self.journal.snapshot().map_err(|error| {
            CutoverError::HostTransition(HostError::OwnerLeaseRecovery(error.to_string()))
        })?;
        let readback = self
            .open_registry_store()?
            .load()
            .map_err(|error| CutoverError::Registry(error.to_string()))?;
        let durable = self.journal.snapshot().map_err(|error| {
            CutoverError::HostTransition(HostError::OwnerLeaseRecovery(error.to_string()))
        })?;
        // The retirement is resolved by the SAME journal owner through a further
        // read, so it must be bracketed on its far side exactly as
        // `read_cutover_disposition` brackets it: resolve it FROM `durable` and
        // take one more sample afterwards to prove `durable` is still current.
        // Resolving it after the coherence decision - which is what this path did
        // - left the retirement observation strictly outside the compared
        // interval while the `Reconciled` arm gates on that interval. Two
        // consequences, both fail-closed but both false: a record landing between
        // the last sample and the lookup is reported as `UnboundRetirement`
        // ("a substituted record") when the status port would have reported
        // `ConcurrentOwnerMovement` ("the owners moved"), and a positive
        // history claim is gated by a coherence proof that does not cover the
        // observation it gates. This is the same stale-currency defect
        // `read_cutover_disposition` already closed on the status side.
        let retirement =
            crate::backup_cutover::resolve_cutover_retirement(self, &durable, request, None)?;
        // A failed READ is a failure, never a concurrency fact: it is propagated
        // with the same error the surrounding reads use, so it can never be
        // reported as owner movement.
        let coherence = match self.journal.snapshot() {
            Ok(resampled)
                if crate::backup_cutover::cutover_observation_unchanged(&before, &durable)
                    && crate::backup_cutover::cutover_observation_unchanged(
                        &durable, &resampled,
                    ) =>
            {
                OwnerObservationCoherence::Coherent
            }
            Ok(_) => OwnerObservationCoherence::Moving,
            Err(error) => {
                return Err(CutoverError::HostTransition(HostError::OwnerLeaseRecovery(
                    error.to_string(),
                )));
            }
        };
        let reconciled = reconcile_cutover_outcome(
            request,
            durable.pending_cutover.as_ref(),
            readback.committed_cutover_activation(),
            readback.active_generation(),
            &retirement,
            coherence,
        );
        if reconciled.disposition != CutoverDisposition::RetirementPending {
            return Ok((reconciled, barrier));
        }
        // Reached only when the projection above DID return `RetirementPending`,
        // which requires both a coherent pair and the registry's own
        // operation-bound receipt. A torn pair returned `Unknown` +
        // `ConcurrentOwnerMovement` at the branch above, so the proven
        // `Committed` never reaches here unreported.
        Ok((committed, barrier))
    }

    /// Exact admitted cutover disposition for one operation, read from the
    /// real owners after a lost response, a crash between the registry and
    /// the journal, or a cancellation.
    ///
    /// [#962](crate::backup_cutover) or the public command surface. It owns no
    /// algorithm. It re-reads the Host journal's own durable cutover
    /// projection, the installation registry's active generation and its
    /// operation-bound cutover receipt, and the retirement record the journal
    /// owner actually applied for this exact cutover operation, then projects
    /// them through
    /// [`crate::backup_cutover::reconcile_cutover_outcome`], so the returned
    /// disposition is the exact state of the operation rather than a local
    /// assumption, and
    /// [`crate::backup_cutover::CutoverOutcome::residual`] names whatever
    /// uncertainty the owners left behind. No caller assertion is accepted: this
    /// port takes no `validated` flag, so the pure mapper cannot certify
    /// qualification from a caller's word, and an unqualified read answers
    /// `Requested`. The optional `retirement_receipt`
    /// is a lookup HINT, never the proof: it is believed only when it names the
    /// transaction identity the journal owner computed for the record it
    /// resolved, so an unrelated genuine `AppendReceipt` cannot produce
    /// `Reconciled`. No cutover effect is performed here, nothing is appended
    /// or mutated, and nothing is retried.
    ///
    /// # Errors
    ///
    /// Returns [`HostError`] when the durable Host journal or the installation
    /// registry cannot be read. A failed read is an error, never a
    /// disposition: reporting a state the owners did not prove is exactly the
    /// local assumption this method exists to remove.
    #[cfg(windows)]
    pub fn backup_dispatch_cutover_disposition(
        &self,
        request: &crate::backup_cutover::CutoverRequest,
        retirement_receipt: Option<&eliot_host_state::AppendReceipt>,
    ) -> Result<crate::backup_cutover::CutoverOutcome, HostError> {
        crate::backup_cutover::read_cutover_disposition(self, request, retirement_receipt)
    }

    /// Executes the separately authorized prior-generation retirement that
    /// completes one committed cutover.
    ///
    /// This is the second admitted cutover port, and it is the only entry to the
    /// prior-generation retirement effect. Retirement is never
    /// automatic cleanup: the caller must present the
    /// [`GenerationRetirementBarrier`] returned by
    /// [`Self::backup_dispatch_cutover`] for the same operation and an explicit
    /// non-empty retirement authorization. Only then is the durable
    /// `EpochRetirement` record appended. The source installation is retained
    /// until this record commits, and source data destruction stays a separate
    /// explicitly authorized action.
    ///
    /// The epoch to retire is **not** a parameter. It is derived from the
    /// durable owners by
    /// [`crate::backup_cutover::resolve_predecessor_retirement_relation`], which
    /// requires an owner-issued
    /// [`eliot_host_state::PredecessorRetirementRelation`] mapping this
    /// cutover's exact `expected_predecessor` generation onto one exact
    /// outstanding Host epoch (#2868). A caller-selected epoch was previously
    /// accepted and proved only that it was *some* unretired prior epoch of this
    /// installation, so with two outstanding prior epochs the cutover could
    /// retire the wrong one and later report the other as the consumed
    /// predecessor's completion. When the owners do not establish the relation
    /// this port returns a typed `Unknown` +
    /// [`CutoverResidual::PredecessorEpochUnknown`](crate::backup_cutover::CutoverResidual::PredecessorEpochUnknown)
    /// outcome and appends nothing.
    ///
    /// # Errors
    ///
    /// Returns [`CutoverError`](crate::backup_cutover::CutoverError) when the
    /// separately supplied operation does not match the operation the admitted
    /// cutover payload authorizes, the authorization is empty, the owner-issued
    /// relation does not bind this operation's predecessor generation to the
    /// epoch being retired, or the journal owner refuses the retirement record.
    #[cfg(windows)]
    pub fn backup_dispatch_cutover_retire(
        &self,
        operation: eliot_protocol::backup::BackupOperationKind,
        request: &crate::backup_cutover::CutoverRequest,
        evidence: &crate::backup_cutover::IsolatedRecoveryEvidence,
        barrier: &GenerationRetirementBarrier,
        retirement_authorization: &PlatformHandle,
    ) -> Result<crate::backup_cutover::CutoverOutcome, crate::backup_cutover::CutoverError> {
        use crate::backup_cutover::{
            CutoverError, admitted_cutover_operation, retire_authorized_generation,
        };
        // Same admitted-payload resolution as the activation port: the body
        // must prove it is the body the owner admitted, and the separately
        // supplied selector must then agree with the operation that body
        // authorizes. Retirement never runs on a selector's word alone.
        let admitted = admitted_cutover_operation(request)?;
        if operation != admitted {
            return Err(CutoverError::NotSeparatelyAdmitted(format!(
                "separately supplied backup operation {operation:?} does not match the \
                 admitted cutover operation {admitted:?}"
            )));
        }
        Self::validate_backup_dispatch_prepare_routing(Self::register_backup_dispatch());
        retire_authorized_generation(self, request, evidence, barrier, retirement_authorization)
    }

    /// Opens the durable Host contour for one installation identity and
    /// advances its persisted epoch before any process admission.
    ///
    /// # Errors
    ///
    /// Returns an error if installation identity, owner-lease acquisition,
    /// durable admission, recovery state, or approved process startup fails.
    #[allow(
        clippy::too_many_lines,
        reason = "Host reopen keeps the epoch, registry, and Phase-B crash-recovery ordering in one boundary"
    )]
    pub fn open(launch_options: HostLaunchOptions) -> Result<Self, HostError> {
        // F-LOG-HOST-1: request/admitted distinction; single terminal via
        // guard. Missing evidence suppresses `admitted`, never a new branch.
        host_lifecycle_observe_requested(BOUNDARY_OPEN_REQUESTED);
        let mut host_terminal = HostTerminalGuard::armed(BOUNDARY_OPEN_TERMINAL);
        // Backup dispatch wiring (#962): pin the accepted preparation /
        // cutover routing into the production startup path so it cannot rot
        // unwired. Wiring-only: no backup operation runs here.
        Self::validate_backup_dispatch_prepare_routing(Self::register_backup_dispatch());
        if launch_options.installation().as_str().trim().is_empty() {
            return Err(HostError::MissingInstallation);
        }
        let installation = launch_options.installation().clone();
        let owner_lease = HostOwnerLease::acquire(&installation).map_err(owner_lease_error)?;
        let host_state_root = launch_options.host_state_root().to_path_buf();
        let root_lease = ProtectedRootLease::open_existing(&host_state_root)
            .map_err(|error| HostError::Platform(error.to_string()))?;
        let canonical_root = root_lease
            .canonical_path()
            .map_err(|error| HostError::Platform(error.to_string()))?;
        if canonical_root != host_state_root {
            return Err(HostError::ProcessContour(
                "SCM Host state root is not the exact retained installation root".to_owned(),
            ));
        }
        // s37/#1339, A13.9: the installer staging writer is released before
        // the SCM start + convergence wait, so `DatabaseAlreadyOpen` here is
        // a short release race, not a held owner. Retry it with bounded
        // backoff; every other open failure still fails closed immediately.
        // `root_lease` stays in this scope for the canonical-path proof;
        // each attempt opens a fresh short-lived lease inside the helper.
        // The handle below is short-lived (open-load-drop); Host retains only
        // `host_state_root` and re-opens per CAS/readback.
        let mut registry = {
            let store = open_registry_store_at(&host_state_root)?;
            let loaded = store.load()?;
            drop(store);
            loaded
        };
        let pending_for_reopen = registry.pending_activation().cloned();
        Self::validate_launch_options_for_registry(
            &launch_options,
            &registry,
            pending_for_reopen.as_ref(),
        )?;
        #[cfg(windows)]
        {
            let startup_manifest = pending_for_reopen
                .as_ref()
                .map(|pending| &pending.manifest)
                .or_else(|| registry.active().map(|generation| &generation.manifest))
                .ok_or_else(|| {
                    HostError::ProcessContour(
                        "SCM launch authority has no approved generation".to_owned(),
                    )
                })?;
            verify_current_host_artifact(startup_manifest)?;
        }
        if let Some(pending) = pending_for_reopen.as_ref()
            && pending
                .manifest
                .runtime_launch
                .installation_epoch
                .installation
                != installation
        {
            let reason = "pending activation installation epoch is stale";
            let host_capability = owner_lease.activation_capability();
            persist_pending_recovery(
                &host_state_root,
                &mut registry,
                &host_capability,
                pending,
                reason,
            )?;
            return Err(HostError::RecoveryRequired(reason.to_owned()));
        }
        // Rehydrate and validate every durable runtime-restart record before
        // opening the journal or creating any runtime job branch. A malformed
        // or ambiguous record must stop admission before Host can mutate the
        // physical runtime or adopt a restart outcome.
        let durable_restarts = {
            #[cfg(windows)]
            {
                load_durable_runtime_restarts(&host_state_root)?
            }
            #[cfg(not(windows))]
            {
                std::collections::HashMap::new()
            }
        };
        let durable_store_recovery_fences = {
            #[cfg(windows)]
            {
                load_durable_store_recoveries(&host_state_root)?
            }
            #[cfg(not(windows))]
            {
                Vec::new()
            }
        };
        let journal_path = host_state_root.join(HOST_JOURNAL_FILE_NAME);
        let (
            journal,
            host,
            activation_generation,
            activation_id,
            store_recovery_startup_fence,
            active_phase_b_rebind_recovery,
        ) = open_production_epoch(
            &journal_path,
            installation,
            pending_for_reopen.as_ref(),
            registry.active_phase_b_rebind(),
            &durable_store_recovery_fences,
        )?;
        #[cfg(windows)]
        let jobs = if store_recovery_startup_fence.is_fenced() {
            HostJobBranches::new_fenced(&host)
        } else {
            HostJobBranches::new(&host)
        }
        .map_err(|error| HostError::Platform(error.to_string()))?;
        let mut composition = Self {
            store_rebind_boundary: HostStoreRebindProductionBoundary,
            runtime_control_boundary: HostRuntimeControlProductionBoundary,
            journal,
            registry_host_root: host_state_root,
            #[cfg(test)]
            test_registry_file: None,
            registry,
            launch_options,
            host,
            activation_generation,
            activation_id,
            running: true,
            #[cfg(windows)]
            jobs,
            #[cfg(windows)]
            readiness_gate: HostReadinessGate::with_cadence(ReadinessCadence::default()),
            #[cfg(windows)]
            phase_b: None,
            #[cfg(windows)]
            watchdog_start_recovery: None,
            #[cfg(windows)]
            runtime_restarts: durable_restarts,
            #[cfg(windows)]
            runtime_control_queue: std::sync::Arc::new(std::sync::Mutex::new(
                std::collections::VecDeque::new(),
            )),
            #[cfg(windows)]
            user_automation_execution_queue: std::sync::Arc::new(std::sync::Mutex::new(
                std::collections::VecDeque::new(),
            )),
            #[cfg(windows)]
            store_recovery_startup_fence,
            active_phase_b_rebind_recovery,
            owner_lease,
            pending_record: None,
            durable_finalized: false,
            owner_released: false,
            shutdown_failed: false,
        };
        #[cfg(windows)]
        if composition.store_recovery_startup_fence.is_fenced() {
            // A durable Store recovery fence is resolved only by the
            // authenticated ReconcileStoreRecovery route.  The `jobs` value
            // above is an inert identity holder with no current-process
            // observation, Job handle, or child; no Phase-B materialization,
            // child launch, or readiness publication may run before the exact
            // inner contour is reconstructed.
            composition.readiness_gate.branch_degraded();
            // F-LOG-HOST-1: fenced is distinct from admitted; no false ready.
            host_terminal.disarm();
            host_lifecycle_observe_requested(BOUNDARY_OPEN_FENCED_STORE_RECOVERY);
            return Ok(composition);
        }
        #[cfg(windows)]
        if let Some(pending) = composition.registry.pending_activation().cloned() {
            if pending.phase_b_agent_bridge_stage_prepared.is_some()
                && pending.phase_b_prepared.is_none()
            {
                // The executable stage is an independent durable crash
                // carrier.  Reconcile it before considering prepared data,
                // but do not manufacture a profile/declaration or publish a
                // pair: the exact original handoff must retry preparation.
                Self::reconcile_pending_agent_bridge_stage(&pending)?;
                composition.readiness_gate.branch_degraded();
                // F-LOG-HOST-1: fenced bridge-stage is not admitted/ready.
                host_terminal.disarm();
                host_lifecycle_observe_requested(BOUNDARY_OPEN_FENCED_BRIDGE_STAGE);
                return Ok(composition);
            }
            if let Some(prepared) = pending.phase_b_prepared.as_ref() {
                let prior_bridge = composition
                    .registry
                    .last_committed_activation_fence()
                    .and_then(|fence| fence.phase_b_live_binding.as_ref())
                    .and_then(|binding| binding.agent_bridge.as_ref());
                let mut materialization = match composition.rehydrate_phase_b_from_prepared(
                    &pending.manifest,
                    prepared,
                    Some(&pending),
                    prior_bridge,
                ) {
                    Ok(materialization) => materialization,
                    Err(error) if pending.phase_b_receipt.is_none() => {
                        composition.rollback_uncommitted_phase_b(&pending, prepared)?;
                        return Err(error);
                    }
                    Err(error) => return Err(error),
                };
                if let Some(receipt) = pending.phase_b_receipt.as_ref() {
                    materialization
                        .agent_bridge_final
                        .clone_from(&receipt.agent_bridge);
                }
                composition.phase_b = Some(materialization.clone());
                let pending_after_readback = composition
                    .registry
                    .pending_activation()
                    .cloned()
                    .ok_or_else(|| {
                        HostError::RecoveryRequired(
                            "Phase-B preparation disappeared during restart readback".to_owned(),
                        )
                    })?;
                if pending_after_readback.phase_b_receipt.is_none() {
                    if pending_after_readback.phase_b_prepared_receipt.is_none() {
                        let intent =
                            pending_after_readback
                                .phase_b_intent
                                .as_ref()
                                .ok_or_else(|| {
                                    HostError::RecoveryRequired(
                                        "Phase-B preparation has no matching transaction intent"
                                            .to_owned(),
                                    )
                                })?;
                        let receipt = phase_b_prepared_public_receipt(
                            intent,
                            &materialization,
                            &composition.host,
                            Some(&pending_after_readback),
                        )?;
                        let host_capability = composition.owner_lease.activation_capability();
                        composition.persist_pending_phase_b_prepared_receipt(
                            &pending_after_readback,
                            &receipt,
                            &host_capability,
                        )?;
                    }
                    composition.readiness_gate.branch_degraded();
                    // F-LOG-HOST-1: prepared without receipt is degraded, not ready.
                    host_terminal.disarm();
                    host_lifecycle_observe_requested(
                        BOUNDARY_OPEN_DEGRADED_PREPARED_WITHOUT_RECEIPT,
                    );
                    return Ok(composition);
                } else if let Some(binding) = materialization.agent_bridge() {
                    // A crash after the receipt CAS and before backup cleanup
                    // is harmless: exact receipt readback above is the
                    // durable ownership proof, so cleanup may now finish.
                    phase_b_remove_rollback_backup(
                        std::path::Path::new(binding.profile_path.as_str()),
                        "Agent Bridge admission profile",
                    )?;
                    phase_b_remove_rollback_backup(
                        std::path::Path::new(binding.declaration_path.as_str()),
                        "Agent Bridge client declaration",
                    )?;
                }
                if let Err(error) = composition.resume_pending_activation_after_phase_b() {
                    // The resume boundary already emitted this terminal failure.
                    host_terminal.disarm();
                    return Err(error);
                }
            }
            // Phase A deliberately has no authority descriptor. Keep this
            // Host owner alive in a fenced, non-admissible state until the
            // external ORS handoff reaches the Host-owned Phase-B method.
            // Once a destination is observable, startup performs exact
            // readback/reconciliation; an incomplete/stale Phase-B contour
            // remains fenced and is resumable only with a fresh exact handoff.
            if phase_b_authority_is_observable(&pending.manifest)? {
                match Self::reconcile_phase_b_for_manifest(&pending.manifest) {
                    Ok(_) => composition.reconcile_pending_activation(&pending)?,
                    Err(HostError::RecoveryRequired(_)) => {}
                    Err(error) => return Err(error),
                }
            }
        } else if let Some(active) = composition.registry.active().cloned() {
            if composition.store_recovery_startup_fence.is_fenced() {
                // A prior Host died while an exact RecoverStore intent was
                // unresolved. New Job names, PIDs, activation nonce, and Host
                // epoch cannot satisfy the prior committed inner receipt.
                // Keep the runtime-control query surface alive, but admit no
                // Phase-B/process/readiness contour for this fresh owner.
                composition.readiness_gate.branch_degraded();
                // F-LOG-HOST-1: fenced is distinct from admitted.
                host_terminal.disarm();
                host_lifecycle_observe_requested(BOUNDARY_OPEN_FENCED_STORE_RECOVERY_ACTIVE);
                return Ok(composition);
            }
            // A committed ActiveVerified fence is source evidence only.  Every
            // Host restart must mint a fresh owner-bound Phase-B rebind before
            // any approved child contour is admitted; destination bytes alone
            // are never treated as current authority.
            composition.rebind_active_phase_b_on_open(
                &active,
                composition.active_phase_b_rebind_recovery,
            )?;
            start_approved_manifest_contour(
                &mut composition,
                &active.manifest,
                HostStartupBranch::Active,
                None,
            )?;
        }
        // F-LOG-HOST-1: admitted only with durable evidence; guard disarmed.
        host_terminal.disarm();
        host_lifecycle_observe_requested(BOUNDARY_OPEN_ADMITTED);
        Ok(composition)
    }

    /// Returns the Host epoch bound to this process.
    #[must_use]
    pub const fn host_epoch(&self) -> &HostInstallationEpoch {
        &self.host
    }

    /// Creates the credential control only from this live Host composition's
    /// owner lease.  Callers receive an opaque authenticated server handle;
    /// the raw `LocalService` Credential Manager provider is not public.
    ///
    /// # Errors
    ///
    /// Returns an error if the live Host owner capability or protected state
    /// root cannot be admitted.
    #[cfg(windows)]
    pub fn credential_control(&self) -> Result<HostCredentialControl, HostError> {
        // F-LOG-HOST-1: SCM receipt boundary; identities only, never secret
        // values/env/payloads. Single terminal via guard.
        host_lifecycle_observe_scm(BOUNDARY_CREDENTIAL_CONTROL_REQUESTED);
        let mut host_terminal = HostTerminalGuard::armed(BOUNDARY_CREDENTIAL_CONTROL_TERMINAL);
        let capability = self
            .owner_lease
            .credential_mutation_capability()
            .map_err(|error| HostError::Platform(error.to_string()))?;
        let control = HostCredentialControl::new(
            self.host.clone(),
            self.launch_options.host_state_root().to_path_buf(),
            capability,
            std::sync::Arc::new(std::sync::Mutex::new(std::collections::VecDeque::new())),
        )
        .map_err(HostError::Platform)?;
        host_terminal.disarm();
        host_lifecycle_observe_scm(BOUNDARY_CREDENTIAL_CONTROL_ADMITTED_RECEIPT);
        Ok(control)
    }

    /// Handles one authenticated, transaction-bound Phase-B request on the
    /// mutable Host owner thread. The worker has already authenticated the
    /// installer and verified the prior `LocalService` receipt; this method is
    /// the only production ingress that can publish the live overlay and
    /// resume the pending activation.
    #[cfg(windows)]
    #[allow(
        clippy::too_many_lines,
        reason = "Phase-B request keeps authenticated handoff, durable CAS reload, receipt, and resume ordering together"
    )]
    pub fn handle_phase_b_request(
        &mut self,
        intent: &HostPhaseBMaterializationIntent,
        credential_receipt: &CredentialAccessReceipt,
    ) -> HostCredentialControlResponse {
        // F-LOG-HOST-1: SCM receipt vs Unknown; failed vs unknown preserved
        // by distinct details/codes. One terminal per Unknown outcome; the
        // inner `?` chain shares correlation and never emits its own terminal.
        host_lifecycle_observe_scm(BOUNDARY_PHASE_B_REQUESTED);
        if self.store_recovery_startup_fence.is_fenced() {
            host_lifecycle_observe_scm(BOUNDARY_PHASE_B_UNKNOWN_STORE_RECOVERY_FENCE);
            host_lifecycle_observe_terminal(BOUNDARY_PHASE_B_TERMINAL);
            return HostCredentialControlResponse::Unknown {
                pending_ref: phase_b_unknown_ref(
                    "store-recovery-fence",
                    "MaterializePhaseB",
                    intent,
                ),
            };
        }
        let result = (|| {
            intent
                .validate()
                .map_err(|error| HostError::RecoveryRequired(error.to_string()))?;
            let pending = self.registry.pending_activation().cloned().ok_or_else(|| {
                HostError::RecoveryRequired(
                    "Phase-B handoff requires the exact pending activation".to_owned(),
                )
            })?;
            validate_phase_b_credential_receipt(credential_receipt, &pending.manifest, intent)?;
            let manifest_digest = phase_b_manifest_digest(&pending.manifest)?;
            let expected_static_template = phase_b_static_template_for_candidate(&pending.manifest)
                .map_err(|error| HostError::ProcessContour(error.to_string()))?;
            let credential_receipt_digest = phase_b_credential_receipt_digest(credential_receipt)?;
            if let Some(receipt) = pending.phase_b_receipt.as_ref()
                && receipt.validate().is_ok()
                && receipt.transaction_id == intent.transaction_id
                && receipt.effect_id == intent.effect_id
                && receipt.candidate_manifest_digest == manifest_digest
                && receipt.request_digest == intent.request_digest
                && intent.credential_receipt_digest == credential_receipt_digest
            {
                // A prior Host process may have completed publication and
                // the pending registry CAS while the installer response was
                // lost. Rehydrate the prepared contour and continue the
                // activation handoff without rematerializing any destination.
                // This closes the response-loss window after the receipt CAS
                // but before the activation terminal CAS.
                return Err(HostError::RecoveryRequired(
                    "Phase-B is already final; use ReconcilePhaseB".to_owned(),
                ));
            }
            let live_process_identity = host_process_identity_digest()?;
            if intent.transaction_id != pending.transaction_id
                || intent.installation_plan_digest != pending.plan_digest
                || intent.candidate_manifest_digest != manifest_digest
                || intent.static_template != expected_static_template
                || credential_receipt.transaction_id != pending.transaction_id
                || credential_receipt.effect_id != intent.credential_effect_id
                || credential_receipt.host_owner_epoch != host_owner_epoch_digest(&self.host)?
                || credential_receipt.host_process_identity != live_process_identity
                || intent.host_state_root_digest != phase_b_root_binding_digest(&pending.manifest)?
                || intent.watchdog_selector_digest
                    != phase_b_watchdog_selector_digest(&pending.manifest)?
                || intent.credential_receipt_digest != credential_receipt_digest
            {
                return Err(HostError::RecoveryRequired(
                    "Phase-B handoff binding does not match the live Host contour".to_owned(),
                ));
            }
            let host_capability = self.owner_lease.activation_capability();
            // This CAS is the durable crash boundary immediately before the
            // first destination publication. A restarted Host can therefore
            // distinguish an untouched pending activation from an interrupted
            // Phase-B contour without consulting `self.phase_b` memory.
            self.persist_pending_phase_b_intent(&pending, intent, &host_capability)?;
            let authority_descriptor_bytes = phase_b_build_authority_descriptor(
                &pending.manifest,
                &self.host,
                &self.activation_generation.current,
                intent,
            )?;
            let mut materialization = self.materialize_phase_b(
                &pending.manifest,
                &HostPhaseBInput {
                    authority_descriptor_bytes,
                },
                None,
            )?;
            materialization.transaction_id = Some(intent.transaction_id.clone());
            materialization.effect_id = Some(intent.effect_id.clone());
            materialization.credential_receipt_digest =
                Some(intent.credential_receipt_digest.clone());
            materialization.request_digest = Some(intent.request_digest.clone());
            // `materialize_phase_b` durably records the executable-stage
            // proof and prepared binding.  The pre-materialization snapshot
            // is therefore stale; constructing a receipt from it would omit
            // the bridge proof and make a response-loss restart unable to
            // validate the exact contour.
            let pending_after_materialization =
                self.registry.pending_activation().cloned().ok_or_else(|| {
                    HostError::RecoveryRequired(
                        "Phase-B materialization lost the exact pending activation".to_owned(),
                    )
                })?;
            if pending_after_materialization.transaction_id != pending.transaction_id
                || pending_after_materialization.plan_digest != pending.plan_digest
                || pending_after_materialization.approval != pending.approval
                || pending_after_materialization.phase_b_intent.as_ref() != Some(intent)
            {
                return Err(HostError::RecoveryRequired(
                    "Phase-B materialization changed the exact pending transaction contour"
                        .to_owned(),
                ));
            }
            let receipt = phase_b_prepared_public_receipt(
                intent,
                &materialization,
                &self.host,
                Some(&pending_after_materialization),
            )?;
            materialization.host_owner_epoch = Some(receipt.host_owner_epoch.clone());
            materialization.host_process_identity = Some(receipt.host_process_identity.clone());
            materialization.public_receipt_digest = Some(receipt.receipt_digest.clone());
            self.persist_pending_phase_b_prepared_receipt(
                &pending_after_materialization,
                &receipt,
                &host_capability,
            )?;
            self.phase_b = Some(materialization.clone());
            Ok(receipt)
        })();
        match result {
            Ok(receipt) => {
                // Receipt (prepared) is distinct from completion (finalized).
                host_lifecycle_observe_scm(BOUNDARY_PHASE_B_PREPARED_RECEIPT);
                HostCredentialControlResponse::PhaseBPrepared {
                    receipt: Box::new(receipt),
                }
            }
            Err(_error) => {
                host_lifecycle_observe_scm(BOUNDARY_PHASE_B_UNKNOWN);
                host_lifecycle_observe_terminal(BOUNDARY_PHASE_B_TERMINAL);
                HostCredentialControlResponse::Unknown {
                    pending_ref: phase_b_unknown_ref("phase-b", "MaterializePhaseB", intent),
                }
            }
        }
    }

    /// Commits the provider's final Phase-B proof after retained-handle
    /// verification. Prepared state alone never resumes activation.
    #[cfg(windows)]
    pub fn finalize_phase_b_request(
        &mut self,
        intent: &HostPhaseBMaterializationIntent,
        credential_receipt: &CredentialAccessReceipt,
        final_receipt: &HostPhaseBMaterializationReceipt,
    ) -> HostCredentialControlResponse {
        // F-LOG-HOST-1: prepared receipt vs ready completion; Unknown never
        // false-success. Single terminal for the Unknown outcome.
        host_lifecycle_observe_scm(BOUNDARY_PHASE_B_FINALIZE_REQUESTED);
        let mut resume_terminal_emitted = false;
        let result = (|| {
            intent
                .validate()
                .map_err(|error| HostError::RecoveryRequired(error.to_string()))?;
            final_receipt
                .validate()
                .map_err(|error| HostError::RecoveryRequired(error.to_string()))?;
            let pending = self.registry.pending_activation().cloned().ok_or_else(|| {
                HostError::RecoveryRequired(
                    "FinalizePhaseB requires the exact pending activation".to_owned(),
                )
            })?;
            validate_phase_b_credential_receipt(credential_receipt, &pending.manifest, intent)?;
            let prepared = pending.phase_b_prepared_receipt.as_ref().ok_or_else(|| {
                HostError::RecoveryRequired(
                    "FinalizePhaseB has no durable prepared receipt".to_owned(),
                )
            })?;
            if pending.phase_b_receipt.is_some()
                || final_receipt.transaction_id != intent.transaction_id
                || final_receipt.effect_id != intent.effect_id
                || final_receipt.candidate_manifest_digest != intent.candidate_manifest_digest
                || final_receipt.request_digest != intent.request_digest
                || prepared.transaction_id != final_receipt.transaction_id
                || prepared.effect_id != final_receipt.effect_id
                || prepared.request_digest != final_receipt.request_digest
                || prepared.candidate_manifest_digest != final_receipt.candidate_manifest_digest
                || prepared.host_owner_epoch != final_receipt.host_owner_epoch
                || prepared.host_process_identity != final_receipt.host_process_identity
                || prepared.authority_descriptor_digest != final_receipt.authority_descriptor_digest
                || prepared.config_file_digest != final_receipt.config_file_digest
                || prepared.store_bootstrap_descriptor_digest
                    != final_receipt.store_bootstrap_descriptor_digest
                || prepared.eliotd_descriptor_digest != final_receipt.eliotd_descriptor_digest
                || prepared.provisioned_supervision_authority
                    != final_receipt.provisioned_supervision_authority
                || prepared
                    .agent_bridge
                    .as_ref()
                    .map(|b| b.stage_prepared.clone())
                    != final_receipt
                        .agent_bridge
                        .as_ref()
                        .map(|b| b.prepared.stage_prepared.clone())
            {
                return Err(HostError::RecoveryRequired(
                    "final Phase-B receipt is not bound to the prepared proof".to_owned(),
                ));
            }
            if let Some(final_bridge) = final_receipt.agent_bridge.as_ref() {
                let prepared_bridge = prepared.agent_bridge.as_ref().ok_or_else(|| {
                    HostError::RecoveryRequired(
                        "final bridge proof has no prepared counterpart".to_owned(),
                    )
                })?;
                if !final_bridge.matches_prepared_core(prepared_bridge) {
                    return Err(HostError::RecoveryRequired(
                        "final bridge proof substituted its prepared core".to_owned(),
                    ));
                }
                final_bridge
                    .validate_against_phase_b(intent, &pending)
                    .map_err(HostError::Installation)?;
                let _lease = open_agent_bridge_final_lease(
                    final_bridge,
                    final_bridge.approved_user_sid.as_str(),
                )?;
            } else if intent.agent_bridge_source.is_some() || prepared.agent_bridge.is_some() {
                return Err(HostError::RecoveryRequired(
                    "bridge-enabled Phase-B final proof is absent".to_owned(),
                ));
            }
            let host_capability = self.owner_lease.activation_capability();
            self.persist_pending_phase_b_receipt(&pending, final_receipt, &host_capability)?;
            if let Some(materialization) = self.phase_b.as_mut() {
                materialization
                    .agent_bridge_final
                    .clone_from(&final_receipt.agent_bridge);
            }
            self.resume_pending_activation_after_phase_b()
                .inspect_err(|_| resume_terminal_emitted = true)?;
            Ok(final_receipt.clone())
        })();
        if let Ok(receipt) = result {
            // Ready completion is distinct from prepared receipt.
            host_lifecycle_observe_scm(BOUNDARY_PHASE_B_FINALIZE_READY_COMPLETION);
            HostCredentialControlResponse::PhaseBReady {
                receipt: Box::new(receipt),
            }
        } else {
            host_lifecycle_observe_scm(BOUNDARY_PHASE_B_FINALIZE_UNKNOWN);
            if !resume_terminal_emitted {
                host_lifecycle_observe_terminal(BOUNDARY_PHASE_B_FINALIZE_TERMINAL);
            }
            HostCredentialControlResponse::Unknown {
                pending_ref: phase_b_unknown_ref("phase-b-finalize", "FinalizePhaseB", intent),
            }
        }
    }

    /// Handles a durable Phase-B response-loss retry without invoking any
    /// materialization or activation mutation. The live Host composition is
    /// the query owner; after activation commit it first authenticates the
    /// exact registry terminal and then reuses only its matching in-memory
    /// receipt. The committed registry fence is sufficient to rehydrate the
    /// public receipt after a Host process restart; destination bytes are
    /// never accepted as a substitute.
    #[cfg(windows)]
    #[allow(
        clippy::too_many_lines,
        reason = "Phase-B query keeps pending/committed binding and response-loss reconciliation in one fail-closed boundary"
    )]
    pub fn reconcile_phase_b_request(
        &mut self,
        intent: &HostPhaseBMaterializationIntent,
        credential_receipt: &CredentialAccessReceipt,
    ) -> HostCredentialControlResponse {
        // F-LOG-HOST-1: query-only replay/readback is never another commit.
        // Unknown stays Unknown, never false-success; single terminal.
        host_lifecycle_observe_scm(BOUNDARY_PHASE_B_RECONCILE_REQUESTED);
        if self.store_recovery_startup_fence.is_fenced() {
            host_lifecycle_observe_scm(BOUNDARY_PHASE_B_RECONCILE_UNKNOWN_STORE_RECOVERY_FENCE);
            host_lifecycle_observe_terminal(BOUNDARY_PHASE_B_RECONCILE_TERMINAL);
            return HostCredentialControlResponse::Unknown {
                pending_ref: phase_b_unknown_ref("store-recovery-fence", "ReconcilePhaseB", intent),
            };
        }
        // Query-only prepared readback: return the exact durable prepared
        // wire proof without rehydrating, converging ACLs, or resuming.
        if let Some(pending) = self.registry.pending_activation().cloned()
            && let Some(receipt) = pending.phase_b_prepared_receipt.as_ref()
            && pending.phase_b_receipt.is_none()
            && intent.validate().is_ok()
            && validate_phase_b_credential_receipt(credential_receipt, &pending.manifest, intent)
                .is_ok()
            && receipt.validate().is_ok()
            && receipt.transaction_id == intent.transaction_id
            && receipt.effect_id == intent.effect_id
            && receipt.request_digest == intent.request_digest
        {
            // F-LOG-HOST-1: replay/readback, not another commit.
            host_lifecycle_observe_scm(BOUNDARY_PHASE_B_RECONCILE_PREPARED_READBACK_REPLAY);
            return HostCredentialControlResponse::PhaseBPrepared {
                receipt: Box::new(receipt.clone()),
            };
        }
        let result = (|| {
            intent
                .validate()
                .map_err(|error| HostError::RecoveryRequired(error.to_string()))?;
            let (
                manifest,
                plan_digest,
                committed_binding,
                pending_intent,
                pending_prepared,
                pending_prepared_receipt,
                pending_receipt,
            ) = if let Some(pending) = self.registry.pending_activation().cloned() {
                if pending
                    .phase_b_intent
                    .as_ref()
                    .is_some_and(|saved| saved != intent)
                {
                    return Err(HostError::RecoveryRequired(
                        "pending Phase-B intent belongs to a different request".to_owned(),
                    ));
                }
                (
                    pending.manifest,
                    pending.plan_digest,
                    None,
                    pending.phase_b_intent,
                    pending.phase_b_prepared,
                    pending.phase_b_prepared_receipt,
                    pending.phase_b_receipt,
                )
            } else {
                let active = self.registry.active().cloned().ok_or_else(|| {
                        HostError::RecoveryRequired(
                            "Phase-B query has neither the exact pending nor committed active generation"
                                .to_owned(),
                        )
                    })?;
                let manifest_digest = phase_b_manifest_digest(&active.manifest)?;
                let terminal = self
                    .open_registry_store()?
                    .read_committed_activation_receipt(
                        &intent.transaction_id,
                        &intent.installation_plan_digest,
                        &active.manifest.generation,
                    )
                    .map_err(HostError::Installation)?;
                let binding = terminal
                    .commit_fence()
                    .phase_b_live_binding
                    .clone()
                    .ok_or_else(|| {
                        HostError::RecoveryRequired(
                            "committed activation is missing its Phase-B binding".to_owned(),
                        )
                    })?;
                if binding.manifest_digest != manifest_digest {
                    return Err(HostError::RecoveryRequired(
                        "committed Phase-B binding belongs to a different manifest".to_owned(),
                    ));
                }
                (
                    active.manifest,
                    terminal.plan_digest().clone(),
                    Some(binding),
                    None,
                    None,
                    None,
                    None,
                )
            };
            let manifest_digest = phase_b_manifest_digest(&manifest)?;
            let expected_static_template = phase_b_static_template_for_candidate(&manifest)
                .map_err(|error| HostError::ProcessContour(error.to_string()))?;
            validate_phase_b_credential_receipt(credential_receipt, &manifest, intent)?;
            let live_process_identity = if committed_binding.is_none()
                && pending_receipt.is_none()
                && pending_intent.is_none()
            {
                Some(host_process_identity_digest()?)
            } else {
                None
            };
            if intent.installation_plan_digest != plan_digest
                || intent.candidate_manifest_digest != manifest_digest
                || intent.static_template != expected_static_template
                || credential_receipt.transaction_id != intent.transaction_id
                || credential_receipt.effect_id != intent.credential_effect_id
                || (committed_binding.is_none()
                    && pending_receipt.is_none()
                    && pending_intent.is_none()
                    && (credential_receipt.host_owner_epoch
                        != host_owner_epoch_digest(&self.host)?
                        || Some(credential_receipt.host_process_identity.clone())
                            != live_process_identity))
                || intent.host_state_root_digest != phase_b_root_binding_digest(&manifest)?
                || intent.watchdog_selector_digest != phase_b_watchdog_selector_digest(&manifest)?
                || intent.credential_receipt_digest
                    != phase_b_credential_receipt_digest(credential_receipt)?
                || pending_prepared.as_ref().is_some_and(|prepared| {
                    prepared.host_owner_epoch != credential_receipt.host_owner_epoch
                        || prepared.host_process_identity
                            != credential_receipt.host_process_identity
                })
            {
                return Err(HostError::RecoveryRequired(
                    "Phase-B query binding does not match the live Host contour".to_owned(),
                ));
            }
            if let Some(binding) = committed_binding.as_ref() {
                return phase_b_public_receipt_from_binding(
                    intent,
                    binding,
                    credential_receipt,
                    self.registry.pending_activation(),
                );
            }
            if let Some(receipt) = pending_receipt.as_ref() {
                if receipt.validate().is_err()
                    || receipt.transaction_id != intent.transaction_id
                    || receipt.effect_id != intent.effect_id
                    || receipt.candidate_manifest_digest != manifest_digest
                    || receipt.request_digest != intent.request_digest
                    || receipt.host_owner_epoch != credential_receipt.host_owner_epoch
                    || receipt.host_process_identity != credential_receipt.host_process_identity
                {
                    return Err(HostError::RecoveryRequired(
                        "pending Phase-B receipt is not bound to the exact query".to_owned(),
                    ));
                }
                // ReconcilePhaseB is query-only.  The receipt CAS may be
                // durable while activation continuation was interrupted, but
                // this operation must not rehydrate, start children, append
                // journal records, or advance the registry.  The mutable
                // continuation is owned by the Host startup/worker contour.
                return Ok(receipt.clone());
            }
            if let Some(receipt) = pending_prepared_receipt.as_ref() {
                if receipt.validate().is_err()
                    || receipt.transaction_id != intent.transaction_id
                    || receipt.effect_id != intent.effect_id
                    || receipt.candidate_manifest_digest != manifest_digest
                    || receipt.request_digest != intent.request_digest
                {
                    return Err(HostError::RecoveryRequired(
                        "pending prepared Phase-B receipt is not bound to the exact query"
                            .to_owned(),
                    ));
                }
                return Err(HostError::RecoveryRequired(
                    "Phase-B remains prepared; provider finalization is required".to_owned(),
                ));
            }
            if pending_intent.is_some() && pending_prepared.is_none() {
                return Err(HostError::RecoveryRequired(
                    "Phase-B publication was interrupted after its durable intent and before its receipt; rollback/recovery is required"
                        .to_owned(),
                ));
            }
            let materialization = self.phase_b.as_ref().ok_or_else(|| {
                HostError::RecoveryRequired(
                    "Host has no rehydrated Phase-B materialization for the durable preparation"
                        .to_owned(),
                )
            })?;
            if materialization.manifest_digest != manifest_digest {
                return Err(HostError::RecoveryRequired(
                    "Host Phase-B receipt belongs to a different manifest".to_owned(),
                ));
            }
            if let Some(prepared) = pending_prepared.as_ref()
                && (materialization.transaction_id.as_ref() != Some(&prepared.transaction_id)
                    || materialization.effect_id.as_ref() != Some(&prepared.effect_id)
                    || materialization.request_digest.as_ref() != Some(&prepared.request_digest)
                    || materialization.credential_receipt_digest.as_ref()
                        != Some(&prepared.credential_receipt_digest)
                    || materialization.authority_descriptor_digest
                        != prepared.authority_descriptor_digest
                    || materialization.config_file_digest != prepared.config_file_digest
                    || materialization.store_bootstrap_descriptor_digest
                        != prepared.store_bootstrap_descriptor_digest
                    || materialization.eliotd_descriptor_digest
                        != prepared.eliotd_descriptor_digest
                    || materialization.launch != prepared.launch)
            {
                return Err(HostError::RecoveryRequired(
                    "in-memory Phase-B materialization does not match the durable preparation"
                        .to_owned(),
                ));
            }
            phase_b_public_receipt(
                intent,
                materialization,
                &self.host,
                self.registry.pending_activation(),
            )
        })();
        match result {
            Ok(receipt) => {
                // Committed receipt readback is replay, not another commit.
                host_lifecycle_observe_scm(BOUNDARY_PHASE_B_RECONCILE_RECEIPT_READBACK_REPLAY);
                HostCredentialControlResponse::PhaseBReady {
                    receipt: Box::new(receipt),
                }
            }
            Err(_error) => {
                host_lifecycle_observe_scm(BOUNDARY_PHASE_B_RECONCILE_UNKNOWN);
                host_lifecycle_observe_terminal(BOUNDARY_PHASE_B_RECONCILE_TERMINAL);
                HostCredentialControlResponse::Unknown {
                    pending_ref: phase_b_unknown_ref("phase-b-query", "ReconcilePhaseB", intent),
                }
            }
        }
    }

    #[cfg(windows)]
    #[allow(missing_docs, clippy::missing_errors_doc)]
    pub fn runtime_control(&self) -> Result<HostRuntimeControl, HostError> {
        // F-LOG-HOST-1: SCM control receipt boundary; single terminal.
        host_lifecycle_observe_scm(BOUNDARY_RUNTIME_CONTROL_REQUESTED);
        let mut host_terminal = HostTerminalGuard::armed(BOUNDARY_RUNTIME_CONTROL_TERMINAL);
        let capability = self.owner_lease.activation_capability();
        let _guard = capability
            .live_guard()
            .map_err(|e| HostError::Platform(e.to_string()))?;
        let control = HostRuntimeControl::new_with_capability_and_user_automation(
            std::sync::Arc::clone(&self.runtime_control_queue),
            std::sync::Arc::clone(&self.user_automation_execution_queue),
            &capability,
        )
        .map_err(HostError::Platform)?;
        host_terminal.disarm();
        host_lifecycle_observe_scm(BOUNDARY_RUNTIME_CONTROL_ADMITTED_RECEIPT);
        Ok(control)
    }

    #[cfg(windows)]
    fn user_automation_owner(&self) -> Result<HostKernelUserAutomationOwner, HostError> {
        let candidate = self.jobs.kernel_candidate.clone().ok_or_else(|| {
            HostError::ProcessContour(
                "UserAutomation owner has no retained Kernel candidate".to_owned(),
            )
        })?;
        let activation = self.jobs.kernel_activation_receipt.clone().ok_or_else(|| {
            HostError::ProcessContour(
                "UserAutomation owner has no Kernel activation receipt".to_owned(),
            )
        })?;
        let kernel_process = self.jobs.kernel_process().cloned().ok_or_else(|| {
            HostError::ProcessContour(
                "UserAutomation owner has no retained live Kernel process".to_owned(),
            )
        })?;
        self.jobs.validate_running_kernel_candidate(&candidate)?;
        HostKernelUserAutomationOwner::new(candidate, activation, kernel_process)
    }

    /// Drains the authenticated `UserAutomation` queue through the retained
    /// Kernel front-door owner and the canonical Host journal Wake owner.
    ///
    /// The queue carries the channel evidence selected by the authenticated
    /// runtime-control transport. An endpoint is therefore composed per
    /// request from that exact binding; a request can never borrow another
    /// request's connection identity or fence. The Durable Job adapter calls
    /// the Kernel's authenticated Dreamer route, which in turn calls the
    /// retained canonical Store gateway. Wake cancellation remains a direct
    /// operation of the sole Host journal owner.
    #[cfg(windows)]
    pub fn process_user_automation_requests(
        &self,
        queue: &HostUserAutomationExecutionQueue,
    ) -> Result<usize, HostError> {
        let queue_empty = queue
            .lock()
            .map_err(|_| {
                HostError::ProcessContour("UserAutomation owner queue lock is poisoned".to_owned())
            })?
            .is_empty();
        if queue_empty {
            return Ok(0);
        }
        host_lifecycle_observe_scm(BOUNDARY_USER_AUTOMATION_OWNER_REQUESTED);
        let (kernel_owner, unavailable_reason) = match self.user_automation_owner() {
            Ok(owner) => (Some(owner), None),
            Err(error) => (None, Some(error.to_string())),
        };
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_io()
            .enable_time()
            .build()
            .map_err(|error| HostError::Platform(error.to_string()))?;
        runtime.block_on(async {
            let mut processed = 0;
            while let Some(envelope) = pop_user_automation_execution(queue) {
                let request = envelope.request().clone();
                let session = envelope.session().clone();
                let response =
                    if let Some(owner) = kernel_owner.as_ref() {
                        match owner.owner_binding() {
                            Ok(owner_binding) if session.owner() == &owner_binding => {
                                let endpoint =
                                    UserAutomationHostExecutionEndpoint::new_with_owner_binding(
                                        owner_binding,
                                        HostDurableJobAdapter::new(owner),
                                        HostWakeIntentAdapter::new(&self.journal),
                                    );
                                match endpoint {
                                    Ok(endpoint) => {
                                        Box::pin(endpoint.execute_authenticated_response(
                                            request.clone(),
                                            session,
                                        ))
                                        .await
                                    }
                                    Err(error) => UserAutomationHostExecutionResponse::failed_for(
                                        &request, error,
                                    ),
                                }
                            }
                            Ok(_) => UserAutomationHostExecutionResponse::failed_for(
                                &request,
                                UserAutomationRuntimeError::IdentityConflict,
                            ),
                            Err(error) => UserAutomationHostExecutionResponse::failed_for(
                                &request,
                                UserAutomationRuntimeError::Unavailable(error.to_string()),
                            ),
                        }
                    } else {
                        UserAutomationHostExecutionResponse::failed_for(
                            &request,
                            UserAutomationRuntimeError::Unavailable(
                                unavailable_reason
                                    .as_deref()
                                    .unwrap_or("UserAutomation Kernel owner is unavailable")
                                    .to_owned(),
                            ),
                        )
                    };
                let _ = envelope.respond(response);
                processed += 1;
            }
            Ok::<usize, HostError>(processed)
        })
    }

    #[cfg(windows)]
    #[allow(missing_docs)]
    pub fn runtime_control_queue(&self) -> HostRuntimeControlQueue {
        std::sync::Arc::clone(&self.runtime_control_queue)
    }

    /// Returns the bounded `UserAutomation` owner queue admitted by the
    /// authenticated runtime-control endpoint.
    #[cfg(windows)]
    pub fn user_automation_execution_queue(&self) -> HostUserAutomationExecutionQueue {
        std::sync::Arc::clone(&self.user_automation_execution_queue)
    }

    #[cfg(windows)]
    pub fn handle_kernel_restart_request(
        &mut self,
        request: &HostRuntimeControlRequest,
    ) -> HostRuntimeControlResponse {
        // F-LOG-HOST-1: SCM receipt vs Unknown; control receipt distinct from
        // completion. Unsupported op stays typed Unknown, never false-success.
        // One terminal per Unknown outcome; inner `execute` shares correlation
        // and never emits its own terminal.
        host_lifecycle_observe_scm(BOUNDARY_KERNEL_RESTART_REQUESTED);
        if request.operation == HostRuntimeControlOperation::ReconcileKernelRestart {
            // Reconcile is query-only replay, not another restart commit.
            host_lifecycle_observe_scm(BOUNDARY_KERNEL_RESTART_RECONCILE_DELEGATED_READBACK);
            return self.reconcile_kernel_restart_request(request);
        }
        if self
            .owner_lease
            .activation_capability()
            .live_guard()
            .is_err()
        {
            host_lifecycle_observe_scm(BOUNDARY_KERNEL_RESTART_UNKNOWN_OWNER_FENCED);
            host_lifecycle_observe_terminal(BOUNDARY_KERNEL_RESTART_TERMINAL);
            return HostRuntimeControlResponse::unknown_for(
                request,
                runtime_control_unknown_ref("kernel-restart", request),
            );
        }
        let result = self.execute_kernel_restart(request);
        match result {
            Ok(receipt) => {
                host_lifecycle_observe_scm(BOUNDARY_KERNEL_RESTART_RECEIPT_COMPLETION);
                HostRuntimeControlResponse::restarted_for(request, receipt)
            }
            Err(_error) => {
                // Unsupported op, pending/unknown, or failed restart all stay
                // typed Unknown preserving identity; never false-success.
                host_lifecycle_observe_scm(BOUNDARY_KERNEL_RESTART_UNKNOWN);
                host_lifecycle_observe_terminal(BOUNDARY_KERNEL_RESTART_TERMINAL);
                HostRuntimeControlResponse::unknown_for(
                    request,
                    runtime_control_unknown_ref("kernel-restart", request),
                )
            }
        }
    }

    #[cfg(windows)]
    #[allow(clippy::too_many_lines, missing_docs)]
    pub fn reconcile_kernel_restart_request(
        &mut self,
        request: &HostRuntimeControlRequest,
    ) -> HostRuntimeControlResponse {
        // F-LOG-HOST-1: reconcile is query-only replay; Unknown never
        // false-success and never rewrites the durable receipt. Timeout or
        // possible state change stays Unknown until reconciliation evidence.
        // One terminal per Unknown outcome; success readback is replay.
        host_lifecycle_observe_scm(BOUNDARY_KERNEL_RESTART_RECONCILE_REQUESTED);
        if self
            .owner_lease
            .activation_capability()
            .live_guard()
            .is_err()
        {
            host_lifecycle_observe_scm(BOUNDARY_KERNEL_RESTART_RECONCILE_UNKNOWN_OWNER_FENCED);
            host_lifecycle_observe_terminal(BOUNDARY_KERNEL_RESTART_RECONCILE_TERMINAL);
            return HostRuntimeControlResponse::unknown_for(
                request,
                runtime_control_unknown_ref("kernel-restart-reconcile", request),
            );
        }
        if request.validate().is_err() {
            host_lifecycle_observe_scm(BOUNDARY_KERNEL_RESTART_RECONCILE_UNKNOWN_VALIDATION);
            host_lifecycle_observe_terminal(BOUNDARY_KERNEL_RESTART_RECONCILE_TERMINAL);
            return HostRuntimeControlResponse::unknown_for(
                request,
                runtime_control_unknown_ref("kernel-restart-reconcile", request),
            );
        }
        let key = request.mutation_digest.as_str().to_owned();
        if let Some(receipt) = self.runtime_restarts.get(&key).cloned() {
            return if let Ok(receipt) = rebind_runtime_restart_receipt(&receipt, request) {
                host_lifecycle_observe_scm(
                    BOUNDARY_KERNEL_RESTART_RECONCILE_RECEIPT_READBACK_REPLAY,
                );
                HostRuntimeControlResponse::restarted_for(request, receipt)
            } else {
                host_lifecycle_observe_scm(BOUNDARY_KERNEL_RESTART_RECONCILE_UNKNOWN_CONFLICT);
                host_lifecycle_observe_terminal(BOUNDARY_KERNEL_RESTART_RECONCILE_TERMINAL);
                HostRuntimeControlResponse::unknown_for(
                    request,
                    runtime_control_unknown_ref("kernel-restart-reconcile-conflict", request),
                )
            };
        }
        match has_runtime_restart_pending(self.launch_options.host_state_root(), &key) {
            Ok(true) | Err(_) => {
                // Pending or unreadable pending stays Unknown; a timeout is
                // never proof of effect or non-effect.
                host_lifecycle_observe_scm(BOUNDARY_KERNEL_RESTART_RECONCILE_UNKNOWN_PENDING);
                host_lifecycle_observe_terminal(BOUNDARY_KERNEL_RESTART_RECONCILE_TERMINAL);
                return HostRuntimeControlResponse::unknown_for(
                    request,
                    runtime_control_unknown_ref("kernel-restart-pending", request),
                );
            }
            Ok(false) => {}
        }
        let snapshot = match self.journal.snapshot() {
            Ok(s) => s,
            Err(_e) => {
                host_lifecycle_observe_scm(BOUNDARY_KERNEL_RESTART_RECONCILE_UNKNOWN_SNAPSHOT);
                host_lifecycle_observe_terminal(BOUNDARY_KERNEL_RESTART_RECONCILE_TERMINAL);
                return HostRuntimeControlResponse::unknown_for(
                    request,
                    runtime_control_unknown_ref("kernel-restart-reconcile-snapshot", request),
                );
            }
        };
        if let Some(kernel) = snapshot.kernel.as_ref() {
            let _ = kernel;
        }
        host_lifecycle_observe_scm(BOUNDARY_KERNEL_RESTART_RECONCILE_UNKNOWN);
        host_lifecycle_observe_terminal(BOUNDARY_KERNEL_RESTART_RECONCILE_TERMINAL);
        HostRuntimeControlResponse::unknown_for(
            request,
            runtime_control_unknown_ref("kernel-restart-reconcile-unknown", request),
        )
    }

    #[cfg(windows)]
    #[allow(
        clippy::too_many_lines,
        clippy::map_unwrap_or,
        clippy::needless_borrow,
        missing_docs
    )]
    fn execute_kernel_restart(
        &mut self,
        request: &HostRuntimeControlRequest,
    ) -> Result<HostKernelRestartReceipt, HostError> {
        // F-LOG-HOST-1: inner phase only; outer `handle_kernel_restart_request`
        // owns the single terminal. Unsupported op stays typed, never success.
        host_lifecycle_observe_scm(BOUNDARY_KERNEL_RESTART_EXECUTE_REQUESTED);
        request.validate().map_err(HostError::ProcessContour)?;
        if request.operation != HostRuntimeControlOperation::RestartKernel {
            return Err(HostError::ProcessContour(
                "unsupported runtime-control operation".to_owned(),
            ));
        }
        let key = request.mutation_digest.as_str().to_owned();
        if let Some(existing) = self.runtime_restarts.get(&key).cloned() {
            return Ok(existing);
        }
        if has_runtime_restart_pending(self.launch_options.host_state_root(), &key)? {
            return Err(HostError::RecoveryRequired(
                "Kernel restart intent is pending and outcome is unknown; reconcile required"
                    .to_owned(),
            ));
        }
        self.ensure_recovery_admission_open()?;
        let capability = self.owner_lease.activation_capability();
        let guard = capability
            .live_guard()
            .map_err(|e| HostError::Platform(e.to_string()))?;
        if persist_runtime_restart_pending(
            self.launch_options.host_state_root(),
            request,
            &self.host,
        )? == RuntimeRestartPendingPublication::Replay
        {
            return Err(HostError::RecoveryRequired(
                "Kernel restart intent is already pending; reconcile required".to_owned(),
            ));
        }
        drop(guard);
        drop(capability);
        let store_before = self.jobs.store_process().cloned().ok_or_else(|| {
            HostError::ProcessContour("Store process is missing before Kernel restart".to_owned())
        })?;
        let store_job_before = self.jobs.store_name().to_owned();
        let store_fence_before = match self.journal.snapshot()?.readiness_observations.last() {
            Some(observation) => observation.store_fence.clone(),
            None => PlatformHandle::new("0".repeat(64))
                .map_err(|error| HostError::Platform(error.to_string()))?,
        };
        let current_kernel =
            self.journal.snapshot()?.kernel.clone().ok_or_else(|| {
                HostError::ProcessContour("no active Kernel to restart".to_owned())
            })?;
        if current_kernel.state != KernelActivationState::Active {
            return Err(HostError::ProcessContour(
                "Kernel is not Active; restart requires Active".to_owned(),
            ));
        }
        if current_kernel.process.is_none() || current_kernel.candidate_job_binding.is_none() {
            return Err(HostError::OwnerLeaseRecovery(
                "prior Kernel process/job binding is absent; cannot prove termination".to_owned(),
            ));
        }
        let old_generation = current_kernel.kernel_generation.clone();
        let host_clone = self.host.clone();
        let activation_id = self.activation_id.clone();
        let activation_generation = self.activation_generation.clone();
        let terminated_child = {
            let kernel_mut = self
                .jobs
                .kernel
                .as_mut()
                .ok_or_else(|| HostError::ProcessContour("Kernel Job is missing".to_owned()))?;
            kernel_mut
                .terminate_in_place(0xE017_0001)
                .map_err(|e| HostError::RecoveryRequired(e.to_string()))?
        };
        if !terminated_child.job_empty() || !terminated_child.root_reaped() {
            return Err(HostError::RecoveryRequired(
                "Kernel termination did not produce job-empty/root-reaped evidence".to_owned(),
            ));
        }
        if terminated_child.process().process_id == 0
            || terminated_child.process().start_time_100ns == 0
        {
            return Err(HostError::RecoveryRequired(
                "Terminated Kernel child has invalid identity".to_owned(),
            ));
        }
        self.jobs.kernel.take();
        let fail_driver =
            DurableKernelActivationDriver::resume(&self.journal, current_kernel.clone());
        let fail_result = {
            let mut driver = fail_driver;
            driver.fail(&format!(
                "kernel-restart:{}",
                request.request_digest.as_str()
            ))
        };
        match fail_result {
            Ok(()) => {}
            Err(HostError::Journal(JournalError::OutcomeUnknown { transaction_id })) => {
                match self.journal.reconcile(&transaction_id)? {
                    ReconcileOutcome::Committed => {
                        let _ = self.journal.reconcile(&transaction_id);
                    }
                    ReconcileOutcome::NotCommitted | ReconcileOutcome::StillUnknown => {
                        return Err(HostError::Journal(JournalError::OutcomeUnknown {
                            transaction_id,
                        }));
                    }
                }
            }
            Err(e) => return Err(e),
        }
        let (next_prior, kernel_generation, kernel_authority_epoch) = self
            .next_kernel_activation_context(
                self.jobs
                    .launch
                    .as_ref()
                    .ok_or_else(|| HostError::ProcessContour("launch missing".to_owned()))?
                    .authority_state_fence
                    .authority_epoch
                    .clone(),
                Some(&terminated_child),
            )?;
        let prior_kernel = terminated_prior_kernel(&current_kernel, &terminated_child)?;
        if !matches!(prior_kernel, PriorKernelDisposition::Terminated(_))
            || !matches!(next_prior, PriorKernelDisposition::Terminated(_))
        {
            return Err(HostError::ProcessContour(
                "next context did not prove terminated".to_owned(),
            ));
        }
        if prior_kernel != next_prior {
            return Err(HostError::RecoveryRequired(
                "Prior kernel disposition does not match durable terminated evidence".to_owned(),
            ));
        }
        let active_manifest = self
            .registry
            .active()
            .ok_or_else(|| HostError::ProcessContour("no active manifest".to_owned()))?
            .manifest
            .clone();
        let (kernel_artifact, _) = active_manifest
            .host_child_artifact_digests()
            .map_err(|e| HostError::ProcessContour(e.to_string()))?;
        let config_digest = self
            .jobs
            .config_digest
            .clone()
            .ok_or_else(|| HostError::ProcessContour("config digest missing".to_owned()))?;
        let config_path = self
            .jobs
            .config_path
            .clone()
            .ok_or_else(|| HostError::ProcessContour("config path missing".to_owned()))?;
        let approved_kernel_path = active_manifest.host_child_paths().0;
        let new_child = self.jobs.relaunch_kernel(
            &active_manifest.generation,
            &config_digest,
            &config_path,
            &kernel_artifact,
            &approved_kernel_path,
            &active_manifest.host_child_paths().2,
            &host_clone,
        )?;
        self.jobs.kernel = Some(new_child);
        let launch_generation = active_manifest.generation.clone();
        let complete_result = self.jobs.complete_kernel_control(
            &launch_generation,
            &host_clone,
            &self.journal,
            &activation_id,
            &activation_generation,
            prior_kernel,
            kernel_generation.clone(),
            kernel_authority_epoch,
            &active_manifest,
        );
        let (activation_receipt, ready_receipt) = match complete_result {
            Ok(v) => v,
            Err(HostError::Journal(JournalError::OutcomeUnknown { transaction_id })) => {
                let query = KernelActivationQuery {
                    operation_id: PlatformHandle::new(
                        kernel_generation.current.lineage_id.as_str().to_owned(),
                    )
                    .map_err(|error| HostError::Platform(error.to_string()))?,
                    activate_request_digest: transaction_id.as_str().to_owned(),
                };
                let _ = self.journal.reconcile(&transaction_id)?;
                let _ = query;
                return Err(HostError::Journal(JournalError::OutcomeUnknown {
                    transaction_id,
                }));
            }
            Err(e) => {
                let _ = self.jobs.terminate_kernel();
                return Err(e);
            }
        };
        let store_after =
            self.jobs.store_process().cloned().ok_or_else(|| {
                HostError::ProcessContour("Store missing after restart".to_owned())
            })?;
        if store_before.process_id != store_after.process_id
            || store_before.start_time_100ns != store_after.start_time_100ns
            || store_before.image_path != store_after.image_path
            || store_job_before != self.jobs.store_name()
        {
            return Err(HostError::ProcessContour(
                "Store PID/start/image/Job changed during Kernel restart".to_owned(),
            ));
        }
        let store_snapshot_before = store_fence_before;
        let store_snapshot_after = self
            .journal
            .snapshot()?
            .readiness_observations
            .last()
            .map(|o| o.store_fence.clone())
            .unwrap_or(store_snapshot_before.clone());
        if store_snapshot_before != store_snapshot_after
            && !store_snapshot_after.as_str().is_empty()
        {
            return Err(HostError::RecoveryRequired(
                "Store fence changed during Kernel restart; exact unchanged fence required"
                    .to_owned(),
            ));
        }
        let ready_digest = PlatformHandle::new(sha256_json(&ready_receipt)?)
            .map_err(|error| HostError::Platform(error.to_string()))?;
        let activation_digest = PlatformHandle::new(sha256_json(&activation_receipt)?)
            .map_err(|error| HostError::Platform(error.to_string()))?;
        let store_fence = match self.journal.snapshot()?.readiness_observations.last() {
            Some(observation) => observation.store_fence.clone(),
            None => PlatformHandle::new("0".repeat(64))
                .map_err(|error| HostError::Platform(error.to_string()))?,
        };
        let old_gen_handle = PlatformHandle::new(format!(
            "{:x}",
            Sha256::digest(
                format!(
                    "{}:{}",
                    old_generation.current.lineage_id.as_str(),
                    old_generation.current.sequence
                )
                .as_bytes()
            )
        ))
        .map_err(|error| HostError::Platform(error.to_string()))?;
        let new_gen_handle = PlatformHandle::new(format!(
            "{:x}",
            Sha256::digest(
                format!(
                    "{}:{}",
                    kernel_generation.current.lineage_id.as_str(),
                    kernel_generation.current.sequence
                )
                .as_bytes()
            )
        ))
        .map_err(|error| HostError::Platform(error.to_string()))?;
        let mut receipt = HostKernelRestartReceipt {
            mutation_digest: request.mutation_digest.clone(),
            request_digest: request.request_digest.clone(),
            old_kernel_generation: old_gen_handle,
            new_kernel_generation: new_gen_handle,
            store_fence,
            activation_receipt_digest: activation_digest,
            ready_receipt_digest: ready_digest,
            receipt_digest: PlatformHandle::new("0".repeat(64))
                .map_err(|error| HostError::Platform(error.to_string()))?,
        };
        receipt.receipt_digest = receipt.computed_digest().map_err(HostError::Platform)?;
        receipt.validate().map_err(HostError::Platform)?;
        persist_runtime_restart_receipt(self.launch_options.host_state_root(), &receipt)?;
        self.runtime_restarts.insert(key, receipt.clone());
        self.readiness_gate.branch_degraded();
        // F-LOG-HOST-1: receipt (restart) is distinct from reconcile readback.
        host_lifecycle_observe_scm(BOUNDARY_KERNEL_RESTART_EXECUTE_RECEIPT);
        Ok(receipt)
    }

    /// Returns the canonical owner-object name held for this composition.
    ///
    /// The handle itself remains private and is released only after durable
    /// shutdown completion and `HostComposition` drop.
    #[must_use]
    pub fn owner_lease_name(&self) -> &str {
        self.owner_lease.name()
    }

    /// Reads the Host-only operational state from the crash-safe journal.
    ///
    /// # Errors
    ///
    /// Returns an error if the durable Host state cannot be loaded.
    pub fn snapshot(&self) -> Result<HostState, HostError> {
        self.journal.snapshot().map_err(HostError::Journal)
    }

    /// Returns the installation-owned approved-generation registry.
    #[must_use]
    pub const fn registry(&self) -> &ApprovedGenerationRegistry {
        &self.registry
    }

    fn resume_pending_record(&mut self) -> Result<(), HostError> {
        if let Some(pending) = self.pending_record.take()
            && let Err(error) = append_reconciled(&self.journal, pending.clone())
        {
            self.pending_record = Some(pending);
            return Err(error);
        }
        Ok(())
    }

    fn append_record(&mut self, record: HostStateRecord) -> Result<AppendReceipt, HostError> {
        self.resume_pending_record()?;
        match append_reconciled(&self.journal, record.clone()) {
            Ok(receipt) => Ok(receipt),
            Err(error @ HostError::Journal(JournalError::OutcomeUnknown { .. })) => {
                self.pending_record = Some(record);
                Err(error)
            }
            Err(error) => Err(error),
        }
    }

    fn transition_activation(
        &mut self,
        state: ActivationState,
        label: &str,
    ) -> Result<(), HostError> {
        let current = self.journal.snapshot()?.activation.ok_or_else(|| {
            HostError::OwnerLeaseRecovery("activation record is absent".to_owned())
        })?;
        self.append_record(HostStateRecord::Activation(transition_activation_record(
            &current, state, label,
        )?))?;
        Ok(())
    }

    #[cfg(windows)]
    fn transition_activation_with_readiness_evidence(
        &mut self,
        state: ActivationState,
        label: &str,
    ) -> Result<(), HostError> {
        let snapshot = self.journal.snapshot()?;
        let evidence = snapshot
            .readiness_observations
            .last()
            .map(|observation| observation.evidence_refs.clone())
            .ok_or_else(|| {
                HostError::RecoveryRequired(
                    "live activation transition has no fresh readiness observation".to_owned(),
                )
            })?;
        if evidence.is_empty() {
            return Err(HostError::RecoveryRequired(
                "live activation transition has no fresh heartbeat evidence".to_owned(),
            ));
        }
        // The readiness owner appends this record only after the typed
        // continuous-coverage check. Do not reclassify authority by parsing
        // a serialized evidence prefix here.
        let current = snapshot.activation.ok_or_else(|| {
            HostError::OwnerLeaseRecovery("activation record is absent".to_owned())
        })?;
        self.append_record(HostStateRecord::Activation(
            transition_activation_record_with_evidence(&current, state, label, &evidence)?,
        ))?;
        Ok(())
    }

    #[cfg(windows)]
    fn persist_degraded_activation(
        &mut self,
        generation: &PlatformHandle,
        label: &str,
        failure_ref: &PlatformHandle,
        directive: &str,
    ) -> Result<(), HostError> {
        let snapshot = self.journal.snapshot()?;
        let current = snapshot.activation.ok_or_else(|| {
            HostError::OwnerLeaseRecovery("activation record is absent".to_owned())
        })?;
        if current.state == ActivationState::DegradedRecovery {
            // The activation reducer has no DegradedRecovery ->
            // DegradedRecovery edge. Preserve each newly observed cause as a
            // separate durable coverage-gap observation instead of silently
            // retaining only the first cause or manufacturing a second
            // activation state.
            let already_recorded = snapshot.observations.iter().rev().any(|observation| {
                observation
                    .observation
                    .coverage_gap
                    .as_ref()
                    .is_some_and(|gap| {
                        gap.reason_ref == label
                            && gap
                                .evidence_refs
                                .iter()
                                .any(|value| value == failure_ref.as_str())
                    })
            });
            if !already_recorded {
                self.persist_degraded_process_observation(
                    generation,
                    HostBranchDisposition::ReadinessDegraded,
                    Some(label),
                    Some(failure_ref),
                )?;
            }
            return Ok(());
        }
        self.append_record(HostStateRecord::Activation(degraded_activation(
            &current,
            label,
            failure_ref,
            directive,
        )?))?;
        Ok(())
    }

    #[cfg(windows)]
    fn persist_current_watchdog_degraded(&mut self, label: &str) -> Result<(), HostError> {
        let activation_generation = self
            .journal
            .snapshot()?
            .activation
            .ok_or_else(|| HostError::OwnerLeaseRecovery("activation record is absent".to_owned()))?
            .fence
            .activation_generation
            .current
            .clone();
        let target_generation = self
            .registry
            .pending_activation()
            .map(|pending| pending.manifest.generation.clone())
            .or_else(|| {
                self.registry
                    .active()
                    .map(|active| active.manifest.generation.clone())
            })
            .ok_or_else(|| {
                HostError::RecoveryRequired(
                    "Watchdog degradation has no exact approved target generation".to_owned(),
                )
            })?;
        let failure_ref = PlatformHandle::new(format!(
            "host-watchdog-coverage-unavailable:{}:{}",
            activation_generation.lineage_id.as_str(),
            activation_generation.sequence.get()
        ))
        .map_err(|error| HostError::Platform(error.to_string()))?;
        self.persist_degraded_activation(
            &target_generation,
            label,
            &failure_ref,
            "restore-watchdog-coverage",
        )
    }

    #[cfg(windows)]
    fn start_watchdog(
        &mut self,
        phase_b: &HostPhaseBMaterialization,
        scm_launch: &RuntimeLaunchDescriptor,
        approval: &InstallerServiceRegistrationApproval,
        context: RequestMetadata,
    ) -> Result<(), HostError> {
        phase_b
            .launch
            .require_phase_b_live()
            .map_err(|error| HostError::RecoveryRequired(error.to_string()))?;
        if phase_b.authority_descriptor_digest.as_str() == PHASE_B_PENDING_MARKER
            || phase_b.authority_descriptor_digest != phase_b.launch.authority_descriptor_digest
        {
            return Err(HostError::RecoveryRequired(
                "Watchdog admission lacks the exact Host-published authority digest".to_owned(),
            ));
        }
        let launch = &phase_b.launch;
        if scm_launch.generation != launch.generation
            || scm_launch.authority_descriptor_path != launch.authority_descriptor_path
            || scm_launch.watchdog_executable_path != launch.watchdog_executable_path
        {
            return Err(HostError::RecoveryRequired(
                "Watchdog SCM selector source is not the immutable manifest launch".to_owned(),
            ));
        }
        if approval.role() != InstallerServiceRole::Watchdog
            || approval.generation() != &launch.generation
        {
            return Err(HostError::ProcessContour(
                "Watchdog SCM approval is not bound to the requested generation".to_owned(),
            ));
        }
        let image = PathBuf::from(launch.watchdog_executable_path.as_str());
        let portable_root = if launch.profile == InstallationProfile::PortableDev {
            Some(
                UserOwnedRootLease::open_existing(Path::new(
                    launch
                        .portable_root
                        .as_ref()
                        .ok_or_else(|| {
                            HostError::ProcessContour("portable root is missing".to_owned())
                        })?
                        .as_str(),
                ))
                .map_err(|error| HostError::ProcessContour(error.to_string()))?,
            )
        } else {
            None
        };
        let lease = open_launch_lease(launch.profile, portable_root.as_ref(), &image)?;
        verify_launch_digest(
            &lease,
            &launch.watchdog_artifact_digest,
            "runtime.watchdog_artifact",
        )?;
        let mut platform = WindowsPlatform::new(PathBuf::from(launch.kernel_work_root.as_str()))
            .map_err(|error| HostError::Platform(error.to_string()))?;
        let registration = approved_service_registration_request(
            scm_launch,
            approval,
            InstallerServiceRole::Watchdog,
            &launch.watchdog_executable_path,
        )?;
        debug_assert_eq!(registration.binary_path(), image.as_path());
        if self.watchdog_start_recovery.is_some() {
            return Err(HostError::RecoveryRequired(
                "a prior Watchdog start still has an unreconciled recovery carrier".to_owned(),
            ));
        }
        let initial_stopped_without_process = matches!(
            platform.inspect_service_registration_runtime(&registration),
            ServiceRegistrationRuntimeInspection::Matching { observation }
                if observation.is_stopped() && observation.process().is_none()
        );
        // Transport1750 step 1: mint the per-instance heartbeat rendezvous
        // (ACL-restricted pipe plus 256-bit challenge) and publish it
        // through the trusted contour the Watchdog already reads (the
        // installer-approved Host state root, bound to the exact approved
        // registration bootstrap). Any issuance failure fails this start
        // closed: no descriptor, no supervised claim later. A live bound
        // prior is kept, never rotated: the rendezvous belongs to the
        // running incarnation until it provably stops.
        let heartbeat_bootstrap = registration.bootstrap().ok_or_else(|| {
            HostError::ProcessContour("Watchdog registration has no typed bootstrap".to_owned())
        })?;
        let heartbeat_state_root = Path::new(launch.runtime_state_roots.host_state_root.as_str());
        let heartbeat_issued = watchdog_heartbeat::HeartbeatTransportDescriptor::issue(
            heartbeat_bootstrap.installation_id(),
            heartbeat_bootstrap.transaction_plan_generation(),
        )?;
        self.watchdog_start_recovery = Some(WatchdogStartRecoveryCarrier {
            registration: registration.clone(),
            platform_root: PathBuf::from(launch.kernel_work_root.as_str()),
            heartbeat_state_root: heartbeat_state_root.to_path_buf(),
            issued_descriptor: heartbeat_issued.clone(),
            initial_stopped_without_process,
            // Publishing is an externally visible atomic replacement. Mark
            // it as potentially complete before dispatch so a response-loss
            // error cannot make abort infer that the file is absent.
            descriptor_published: true,
            start_may_have_issued: false,
        });
        heartbeat_issued.publish(heartbeat_state_root)?;
        if let Some(carrier) = self.watchdog_start_recovery.as_mut() {
            // StartServiceW may have crossed its provider boundary even when
            // the helper returns an error or an unknown convergence result.
            carrier.start_may_have_issued = true;
        }
        start_installed_watchdog(&mut platform, &registration, context)?;
        // Transport1750 step 2: bind the rendezvous to the SCM-verified
        // incarnation now Running. Admission and the writer both pin this
        // pair, so an unbound start admits nothing. When publish retained a
        // live bound prior and this start brought a new SCM process, the
        // heal path re-resolves: a provably stopped prior rotates to the
        // issued challenge and binds the new process, while a still-live
        // owner keeps the rendezvous and the conflict fails closed.
        let scm = match platform.inspect_registration_runtime(&registration) {
            InstalledWatchdogRuntimeInspection::Matching {
                state,
                wait_hint_ms,
                process,
            } => verify_watchdog_scm_running(&registration, state, wait_hint_ms, process.as_ref())?,
            _ => {
                return Err(HostError::RecoveryRequired(
                    "Watchdog is not Running for heartbeat incarnation bind".to_owned(),
                ));
            }
        };
        watchdog_heartbeat::HeartbeatTransportDescriptor::bind_incarnation_or_heal(
            &heartbeat_issued,
            heartbeat_state_root,
            scm.process.process_id,
            scm.process.start_time_100ns,
        )?;
        Ok(())
    }

    #[cfg(windows)]
    fn watchdog_start_inputs_for_manifest(
        &self,
        manifest: &CandidateManifest,
    ) -> Result<Option<(ServiceRegistrationRequest, PathBuf, PathBuf)>, HostError> {
        let Some(approval) = select_watchdog_approval_for_inspection(&self.registry, manifest)?
        else {
            return Ok(None);
        };
        let launch = &manifest.runtime_launch;
        let registration = approved_service_registration_request(
            launch,
            &approval,
            InstallerServiceRole::Watchdog,
            &launch.watchdog_executable_path,
        )?;
        Ok(Some((
            registration,
            PathBuf::from(launch.kernel_work_root.as_str()),
            PathBuf::from(launch.runtime_state_roots.host_state_root.as_str()),
        )))
    }

    #[cfg(windows)]
    fn pending_watchdog_start_inputs(
        &self,
        pending: &eliot_installation::PendingActivation,
    ) -> Result<Option<(ServiceRegistrationRequest, PathBuf, PathBuf)>, HostError> {
        self.watchdog_start_inputs_for_manifest(&pending.manifest)
    }

    #[cfg(windows)]
    fn reconcile_watchdog_start_bound(
        &mut self,
        registration: ServiceRegistrationRequest,
        platform_root: PathBuf,
        heartbeat_state_root: PathBuf,
    ) -> Result<(), HostError> {
        let carrier = self.watchdog_start_recovery.clone();
        if let Some(carrier) = carrier.as_ref() {
            if carrier.registration != registration
                || !windows_paths_equal(&carrier.platform_root, &platform_root)
                || !windows_paths_equal(&carrier.heartbeat_state_root, &heartbeat_state_root)
            {
                return Err(HostError::RecoveryRequired(
                    "Watchdog recovery carrier is not bound to the pending launch".to_owned(),
                ));
            }
            if !carrier.initial_stopped_without_process {
                return Err(HostError::RecoveryRequired(
                    "Watchdog start was not admitted from an exact stopped/no-process state"
                        .to_owned(),
                ));
            }
        }

        let platform = WindowsPlatform::new(platform_root)
            .map_err(|error| HostError::Platform(error.to_string()))?;
        let mut stopped_process = None;
        match platform.inspect_service_registration_runtime(&registration) {
            ServiceRegistrationRuntimeInspection::Matching { observation }
                if observation.is_stopped() && observation.process().is_none() => {}
            ServiceRegistrationRuntimeInspection::Matching { observation }
                if observation.is_running() =>
            {
                let Some(carrier) = carrier.as_ref() else {
                    return Err(HostError::RecoveryRequired(
                        "Watchdog is Running without an operation-bound start carrier".to_owned(),
                    ));
                };
                if !carrier.descriptor_published || !carrier.start_may_have_issued {
                    return Err(HostError::RecoveryRequired(
                        "Running Watchdog lacks the complete operation-bound start carrier"
                            .to_owned(),
                    ));
                }
                let process = observation.process().ok_or_else(|| {
                    HostError::RecoveryRequired(
                        "Watchdog Running state has no handle-bound process identity".to_owned(),
                    )
                })?;
                let current_descriptor =
                    watchdog_heartbeat::HeartbeatTransportDescriptor::load(&heartbeat_state_root)?
                        .ok_or_else(|| {
                            HostError::RecoveryRequired(
                                "Running Watchdog has no heartbeat descriptor for rollback binding"
                                    .to_owned(),
                            )
                        })?;
                if current_descriptor.pipe_name != carrier.issued_descriptor.pipe_name
                    || current_descriptor.host_challenge_nonce
                        != carrier.issued_descriptor.host_challenge_nonce
                    || current_descriptor.service_instance_guid
                        != carrier.issued_descriptor.service_instance_guid
                    || current_descriptor.installation_id
                        != carrier.issued_descriptor.installation_id
                    || current_descriptor.transaction_plan_generation
                        != carrier.issued_descriptor.transaction_plan_generation
                    || current_descriptor.watchdog_incarnation_pid != process.process_id
                    || current_descriptor.watchdog_incarnation_start_100ns
                        != process.start_time_100ns
                {
                    return Err(HostError::RecoveryRequired(
                        "Running Watchdog is not the exact heartbeat-bound start peer".to_owned(),
                    ));
                }
                let runtime_identity_digest =
                    observation.runtime_identity_digest().ok_or_else(|| {
                        HostError::RecoveryRequired(
                            "Running Watchdog has no runtime identity digest".to_owned(),
                        )
                    })?;
                let stop_request = carrier
                    .registration
                    .clone()
                    .with_expected_runtime_identity_digest(runtime_identity_digest)
                    .map_err(|error| HostError::RecoveryRequired(error.to_string()))?;
                match platform
                    .stop_service_registration(&stop_request)
                    .map_err(|error| HostError::RecoveryRequired(error.to_string()))?
                {
                    ServiceStopOutcome::Stopped { .. }
                    | ServiceStopOutcome::AlreadyStopped { .. } => {
                        stopped_process = Some((process.process_id, process.start_time_100ns));
                    }
                    ServiceStopOutcome::AlreadyStopping { .. }
                    | ServiceStopOutcome::EffectUnknown => {
                        return Err(HostError::RecoveryRequired(
                            "Watchdog stop outcome is not durably known".to_owned(),
                        ));
                    }
                }
            }
            ServiceRegistrationRuntimeInspection::Matching { observation } => {
                return Err(HostError::RecoveryRequired(format!(
                    "Watchdog SCM state {:?} is not a safe abort boundary",
                    observation.state()
                )));
            }
            ServiceRegistrationRuntimeInspection::Absent => {
                return Err(HostError::RecoveryRequired(
                    "Watchdog registration is absent during start rollback".to_owned(),
                ));
            }
            ServiceRegistrationRuntimeInspection::Mismatched
            | ServiceRegistrationRuntimeInspection::Unknown { .. } => {
                return Err(HostError::RecoveryRequired(
                    "Watchdog registration cannot be authoritatively reconciled".to_owned(),
                ));
            }
        }

        if stopped_process.is_some() {
            match platform.inspect_service_registration_runtime(&registration) {
                ServiceRegistrationRuntimeInspection::Matching { observation }
                    if observation.is_stopped() && observation.process().is_none() => {}
                _ => {
                    return Err(HostError::RecoveryRequired(
                        "Watchdog stop lacks exact stopped/no-process readback".to_owned(),
                    ));
                }
            }
        }

        if let Some(carrier) = carrier.as_ref() {
            watchdog_heartbeat::remove_start_artifacts_exact(
                &heartbeat_state_root,
                &carrier.issued_descriptor,
                stopped_process,
            )?;
            self.watchdog_start_recovery = None;
        } else {
            watchdog_heartbeat::require_no_start_artifacts(&heartbeat_state_root)?;
        }
        Ok(())
    }

    /// Reconciles every Watchdog effect before the first-install registry
    /// abort.  A service stop is admitted only when this Host's carrier proves
    /// that the approved registration was initially stopped, the current SCM
    /// process is the exact bound heartbeat peer, and the stop primitive
    /// confirms the post-call state.  Restarted Hosts have no operation-bound
    /// carrier and therefore accept only an exact stopped SCM service with no
    /// heartbeat artifacts; all other states remain recovery-required.
    #[cfg(windows)]
    pub(crate) fn reconcile_watchdog_start_for_abort(
        &mut self,
        pending: &eliot_installation::PendingActivation,
    ) -> Result<(), HostError> {
        let Some((registration, platform_root, heartbeat_state_root)) =
            self.pending_watchdog_start_inputs(pending)?
        else {
            return Ok(());
        };
        self.reconcile_watchdog_start_bound(registration, platform_root, heartbeat_state_root)
    }

    #[cfg(windows)]
    fn next_kernel_activation_context(
        &self,
        manifest_authority_epoch: EpochId,
        termination: Option<&eliot_platform_windows::TerminatedJobChild>,
    ) -> Result<(PriorKernelDisposition, EpochTransition, EpochId), HostError> {
        let state = self.journal.snapshot()?;
        if state.prior_kernel_unknown {
            return Err(HostError::OwnerLeaseRecovery(
                "prior Kernel disposition is unknown".to_owned(),
            ));
        }
        let prior = state.kernel.as_ref().or(state.prior_kernel.as_ref());
        let Some(prior) = prior else {
            let activation = state.activation.ok_or_else(|| {
                HostError::OwnerLeaseRecovery("activation record is absent".to_owned())
            })?;
            return Ok((
                PriorKernelDisposition::NoPriorKernel,
                EpochTransition {
                    current: activation.lineage.kernel_epoch,
                    parent: None,
                },
                manifest_authority_epoch,
            ));
        };
        if state.kernel.is_some()
            && !matches!(
                prior.state,
                KernelActivationState::Failed | KernelActivationState::ManualRecovery
            )
        {
            return Err(HostError::OwnerLeaseRecovery(
                "current Kernel must be durably failed before direct-child restart".to_owned(),
            ));
        }
        let generation = prior.direct_child_generation()?;
        let prior_authority = prior
            .process
            .as_ref()
            .ok_or_else(|| {
                HostError::OwnerLeaseRecovery("prior Kernel process binding is absent".to_owned())
            })?
            .authority_epoch
            .value();
        let next_sequence_value = manifest_authority_epoch.sequence.get().max(
            prior_authority.checked_add(1).ok_or_else(|| {
                HostError::OwnerLeaseRecovery("Kernel authority epoch overflow".to_owned())
            })?,
        );
        let next_sequence = std::num::NonZeroU64::new(next_sequence_value).ok_or_else(|| {
            HostError::OwnerLeaseRecovery("Kernel authority epoch overflow".to_owned())
        })?;
        let authority = EpochId::new(manifest_authority_epoch.lineage_id.clone(), next_sequence)
            .map_err(|error| HostError::ProcessContour(error.to_string()))?;
        let prior_disposition = terminated_prior_kernel(
            prior,
            termination.ok_or_else(|| {
                HostError::OwnerLeaseRecovery(
                    "authoritative prior Kernel termination evidence is unavailable".to_owned(),
                )
            })?,
        )?;
        Ok((prior_disposition, generation, authority))
    }

    #[cfg(windows)]
    #[allow(dead_code)]
    fn fail_current_kernel_record(&self, evidence: &str) -> Result<(), HostError> {
        let current = self.journal.snapshot()?.kernel.ok_or_else(|| {
            HostError::OwnerLeaseRecovery(
                "Kernel failure transition has no durable Kernel record".to_owned(),
            )
        })?;
        DurableKernelActivationDriver::resume(&self.journal, current).fail(evidence)
    }

    #[cfg(windows)]
    #[allow(dead_code)]
    fn activate_launched_kernel(
        &mut self,
        generation: &PlatformHandle,
        manifest_authority_epoch: EpochId,
    ) -> Result<KernelReadyReceipt, HostError> {
        let (prior_kernel, kernel_generation, kernel_authority_epoch) =
            self.next_kernel_activation_context(manifest_authority_epoch, None)?;
        let active_manifest = self
            .registry
            .active()
            .ok_or_else(|| HostError::ProcessContour("no approved active generation".to_owned()))?;
        let (_, receipt) = self.jobs.complete_kernel_control(
            generation,
            &self.host,
            &self.journal,
            &self.activation_id,
            &self.activation_generation,
            prior_kernel,
            kernel_generation,
            kernel_authority_epoch,
            &active_manifest.manifest,
        )?;
        if let Err(error) = self.accept_kernel_ready(&receipt) {
            let durable = self.fail_current_kernel_record("kernel-ready-accept-failed");
            return Err(match durable {
                Ok(()) => error,
                Err(durable) => HostError::RecoveryRequired(format!(
                    "Kernel ready receipt failed ({error}); durable failure transition failed ({durable})"
                )),
            });
        }
        Ok(receipt)
    }

    /// Starts the currently approved Kernel and store images in their
    /// independent Host-owned Job branches.  The registry is checked before
    /// any process is created, and the launch contour binds generation,
    /// configuration digest, installation and Host epoch into the child
    /// environment.
    ///
    /// # Errors
    ///
    /// Returns an error if admission is fenced, no approved generation exists,
    /// or process identity, artifact, configuration, launch, or persistence fails.
    #[cfg(windows)]
    pub fn start_approved_contour(
        &mut self,
        kernel_executable: impl AsRef<Path>,
        store_executable: impl AsRef<Path>,
    ) -> Result<(), HostError> {
        // F-LOG-HOST-1: request vs admitted vs started vs ready preserved.
        // Single terminal via guard; inner `start_manifest_contour` is phase
        // only and shares correlation without its own terminal.
        host_lifecycle_observe_requested(BOUNDARY_START_REQUESTED);
        let mut host_terminal = HostTerminalGuard::armed(BOUNDARY_START_TERMINAL);
        let active =
            self.registry.active().cloned().ok_or_else(|| {
                HostError::ProcessContour("no approved active generation".to_owned())
            })?;
        self.ensure_material_admission_open_for_target(&active.manifest.generation, false)?;
        let (_, store_artifact) = active
            .manifest
            .host_child_artifact_digests()
            .map_err(|error| HostError::ProcessContour(error.to_string()))?;
        self.start_manifest_contour(
            &active.manifest,
            kernel_executable.as_ref(),
            store_executable.as_ref(),
            store_artifact,
            None,
        )?;
        host_terminal.disarm();
        // Started is distinct from ready: readiness still requires its own
        // authenticated proof via the readiness contour.
        host_lifecycle_observe_requested(BOUNDARY_START_STARTED);
        Ok(())
    }

    /// Resumes one pending activation after Host Phase B has materialized its
    /// exact live authority and Store descriptors. The pending registry record
    /// remains non-admissible until this explicit Host-owned continuation
    /// observes the fresh process/readiness contour and commits it.
    ///
    /// # Errors
    ///
    /// Returns an error if no pending activation exists, Phase B is absent or
    /// stale, or the exact pending contour cannot be reconciled.
    #[cfg(windows)]
    pub fn resume_pending_activation_after_phase_b(&mut self) -> Result<(), HostError> {
        // F-LOG-HOST-1: pending resume boundary; single terminal via guard.
        host_lifecycle_observe_requested(BOUNDARY_RESUME_PENDING_REQUESTED);
        let mut host_terminal = HostTerminalGuard::armed(BOUNDARY_RESUME_PENDING_TERMINAL);
        let pending = self.registry.pending_activation().cloned().ok_or_else(|| {
            HostError::ProcessContour("no pending activation requires Phase-B resume".to_owned())
        })?;
        let manifest_digest = phase_b_manifest_digest(&pending.manifest)?;
        if self
            .phase_b
            .as_ref()
            .is_none_or(|receipt| receipt.manifest_digest != manifest_digest)
        {
            return Err(HostError::RecoveryRequired(
                "pending activation has no exact Phase-B materialization receipt".to_owned(),
            ));
        }
        self.reconcile_pending_activation(&pending)?;
        host_terminal.disarm();
        host_lifecycle_observe_requested(BOUNDARY_RESUME_PENDING_ADMITTED);
        Ok(())
    }

    #[cfg(windows)]
    fn resume_pending_phase_b_receipt(&mut self) -> Result<(), HostError> {
        // F-LOG-HOST-1: inner phase only; outer resume owns the terminal.
        host_lifecycle_observe_requested(BOUNDARY_RESUME_PENDING_RECEIPT_REQUESTED);
        let pending = self.registry.pending_activation().cloned().ok_or_else(|| {
            HostError::RecoveryRequired(
                "Phase-B receipt continuation has no exact pending activation".to_owned(),
            )
        })?;
        let manifest_digest = phase_b_manifest_digest(&pending.manifest)?;
        if self
            .phase_b
            .as_ref()
            .is_none_or(|materialization| materialization.manifest_digest != manifest_digest)
        {
            let prepared = pending.phase_b_prepared.as_ref().ok_or_else(|| {
                HostError::RecoveryRequired(
                    "Phase-B receipt continuation has no durable preparation".to_owned(),
                )
            })?;
            let prior_bridge = self
                .registry
                .last_committed_activation_fence()
                .and_then(|fence| fence.phase_b_live_binding.as_ref())
                .and_then(|binding| binding.agent_bridge.as_ref());
            let materialization = self.rehydrate_phase_b_from_prepared(
                &pending.manifest,
                prepared,
                Some(&pending),
                prior_bridge,
            )?;
            self.phase_b = Some(materialization);
        }
        // This is the exact post-receipt continuation. It may start the
        // already-approved child contour, but it never republishes Phase-B
        // bytes or issues a second materialization effect.
        self.resume_pending_activation_after_phase_b()
    }

    #[cfg(windows)]
    #[allow(
        clippy::too_many_lines,
        reason = "ordered Phase-B receipt admission, sibling start, and child readiness remain one fenced lifecycle boundary"
    )]
    fn start_manifest_contour(
        &mut self,
        manifest: &CandidateManifest,
        kernel_executable: &Path,
        store_executable: &Path,
        store_artifact: &PlatformHandle,
        pending: Option<&eliot_installation::PendingActivation>,
    ) -> Result<(), HostError> {
        // F-LOG-HOST-1: inner phase only; outer `start_approved_contour`/`open`
        // owns the single terminal. Requested vs started vs ready preserved:
        // started here is never readiness.
        host_lifecycle_observe_requested(BOUNDARY_START_MANIFEST_REQUESTED);
        Self::validate_launch_options_for_manifest(&self.launch_options, manifest)?;
        let manifest_digest = phase_b_manifest_digest(manifest)?;
        let phase_b = match self
            .phase_b
            .clone()
            .filter(|receipt| receipt.manifest_digest == manifest_digest)
        {
            Some(receipt) => receipt,
            None => Self::reconcile_phase_b_for_manifest(manifest)?,
        };
        phase_b
            .launch
            .require_phase_b_live()
            .map_err(|error| HostError::RecoveryRequired(error.to_string()))?;
        if phase_b.host_epoch != self.host.epoch.current
            || phase_b.host_process_nonce != self.host.nonce
        {
            return Err(HostError::RecoveryRequired(
                "Host Phase-B receipt is not bound to the current Host epoch/nonce".to_owned(),
            ));
        }
        let watchdog_approval = select_watchdog_approval_for_inspection(&self.registry, manifest)?;
        if manifest.runtime_launch.profile == InstallationProfile::SystemService
            && watchdog_approval.is_none()
        {
            return Err(HostError::WatchdogCoverageUnavailable(
                "SystemService activation requires the installer-owned Watchdog approval"
                    .to_owned(),
            ));
        }
        let current = self.journal.snapshot()?.activation.ok_or_else(|| {
            HostError::OwnerLeaseRecovery("activation record is absent".to_owned())
        })?;
        let mut next = transition_activation_record(
            &current,
            ActivationState::Starting,
            if pending.is_some() {
                "host-start-pending"
            } else {
                "host-start-approved"
            },
        )?;
        if let Some(pending) = pending {
            next.trigger_evidence
                .push(pending_activation_binding(pending)?);
        }
        next.trigger_evidence
            .push(phase_b_activation_binding(&phase_b)?);
        self.append_record(HostStateRecord::Activation(next))?;
        if let Some(watchdog_approval) = watchdog_approval.as_ref()
            && let Err(error) = self.start_watchdog(
                &phase_b,
                &manifest.runtime_launch,
                watchdog_approval,
                lifecycle_context(&self.host, "watchdog-start")?,
            )
        {
            return self.cleanup_launched_contour(error);
        }
        let (kernel_artifact, approved_store_artifact) = match manifest
            .host_child_artifact_digests()
        {
            Ok(value) => value,
            Err(error) => {
                return self.cleanup_launched_contour(HostError::ProcessContour(error.to_string()));
            }
        };
        if approved_store_artifact != store_artifact {
            return self.cleanup_launched_contour(HostError::ProcessContour(
                "Store bridge artifact digest is not the approved manifest digest".to_owned(),
            ));
        }
        let (approved_kernel_path, approved_store_path, approved_config_path) =
            manifest.host_child_paths();
        let config_path = PathBuf::from(approved_config_path.as_str());
        let (prior_kernel, kernel_generation, kernel_authority_epoch) = match self
            .next_kernel_activation_context(
                phase_b.launch.authority_state_fence.authority_epoch.clone(),
                None,
            ) {
            Ok(value) => value,
            Err(error) => return self.cleanup_launched_contour(error),
        };
        if let Err(error) = self.jobs.start_approved(
            kernel_executable,
            store_executable,
            &manifest.generation,
            &phase_b.config_file_digest,
            &config_path,
            approved_kernel_path,
            approved_store_path,
            approved_config_path,
            kernel_artifact,
            store_artifact,
            &self.host,
            &phase_b.launch,
        ) {
            return self.cleanup_launched_contour(error);
        }
        let agent_bridge_admission = match (phase_b.agent_bridge(), phase_b.final_agent_bridge()) {
            (Some(_prepared), None) => Err(HostError::RecoveryRequired(
                "Agent Bridge admission requires the final provider binding".to_owned(),
            )),
            (_, Some(binding)) => agent_bridge_admission_descriptor(
                phase_b.launch.profile,
                self.jobs.portable_root.as_ref(),
                binding,
            )
            .map(Some),
            (None, None) => Ok(None),
        };
        let agent_bridge_admission = match agent_bridge_admission {
            Ok(value) => value,
            Err(error) => return self.cleanup_launched_contour(error),
        };
        self.jobs.set_agent_bridge_admission(agent_bridge_admission);
        let (_activation_receipt, receipt) = match self.jobs.complete_kernel_control(
            &manifest.generation,
            &self.host,
            &self.journal,
            &self.activation_id,
            &self.activation_generation,
            prior_kernel,
            kernel_generation,
            kernel_authority_epoch,
            manifest,
        ) {
            Ok(value) => value,
            Err(error) => return self.cleanup_launched_contour(error),
        };
        if let Err(error) = self.accept_kernel_ready(&receipt) {
            return self.cleanup_active_kernel_contour(error, "kernel-ready-accept-failed");
        }
        // Fresh process/readiness evidence, including the Host-observed
        // Watchdog heartbeat admission, must succeed before any live
        // governance profile is published. The earlier ordering made a
        // transient heartbeat loss indistinguishable from Active.
        if let Err(error) = self.persist_process_observations(&manifest.generation) {
            return self.cleanup_active_kernel_contour(error, "host-process-observation-failed");
        }
        if let Err(error) = self.transition_activation_with_readiness_evidence(
            ActivationState::ControlReady,
            "host-kernel-control-ready",
        ) {
            return self.cleanup_active_kernel_contour(error, "host-control-ready-commit-failed");
        }
        if let Err(error) = self.transition_activation_with_readiness_evidence(
            ActivationState::Active,
            "host-runtime-active",
        ) {
            return self.cleanup_active_kernel_contour(error, "host-active-commit-failed");
        }
        // The full contour is now Active and the start carrier no longer
        // guards a pending first-install abort. Any earlier failure kept it
        // intact for exact SCM/heartbeat reconciliation.
        self.watchdog_start_recovery = None;
        // F-LOG-HOST-1: started only; readiness needs its own proof.
        host_lifecycle_observe_requested(BOUNDARY_START_MANIFEST_STARTED);
        Ok(())
    }

    #[cfg(windows)]
    fn accept_kernel_ready(&self, receipt: &KernelReadyReceipt) -> Result<(), HostError> {
        if receipt.activation_id != self.activation_id {
            return Err(HostError::ProcessContour(
                "Kernel ready receipt activation mismatch".to_owned(),
            ));
        }
        Ok(())
    }

    /// Activates one approved generation only after a bounded process cutover;
    /// a rejected candidate restores the registry's previous LKG projection.
    ///
    /// # Errors
    ///
    /// Returns an error if admission is fenced, either generation is invalid,
    /// cutover or rollback fails, or the registry cannot be persisted.
    #[cfg(windows)]
    #[allow(
        clippy::too_many_lines,
        dead_code,
        reason = "candidate activation and exact rollback reactivation form one ordered durable cutover transaction"
    )]
    fn cutover_generation(
        &mut self,
        generation: &PlatformHandle,
        candidate_kernel: impl AsRef<Path>,
        candidate_store: impl AsRef<Path>,
        prior_kernel: impl AsRef<Path>,
        prior_store: impl AsRef<Path>,
    ) -> Result<(), HostError> {
        self.ensure_material_admission_open_for_target(generation, false)?;
        let host_capability = self.owner_lease.activation_capability();
        let pending = self.registry.pending_activation().cloned().ok_or_else(|| {
            HostError::ProcessContour("cutover requires a pending activation".to_owned())
        })?;
        if pending.manifest.generation != *generation {
            return Err(HostError::ProcessContour(
                "cutover pending generation does not match request".to_owned(),
            ));
        }
        let prior = self.registry.active().cloned().ok_or_else(|| {
            HostError::ProcessContour("no active generation to cut over".to_owned())
        })?;
        let candidate = self
            .registry
            .generations()
            .iter()
            .find(|item| item.manifest.generation == *generation)
            .cloned()
            .ok_or_else(|| {
                HostError::ProcessContour("candidate generation is not approved".to_owned())
            })?;
        let (candidate_kernel_artifact, candidate_store_artifact) = candidate
            .manifest
            .host_child_artifact_digests()
            .map_err(|error| HostError::ProcessContour(error.to_string()))?;
        let (prior_kernel_artifact, prior_store_artifact) = prior
            .manifest
            .host_child_artifact_digests()
            .map_err(|error| HostError::ProcessContour(error.to_string()))?;
        let (candidate_kernel_path, candidate_store_path, candidate_config_path) =
            candidate.manifest.host_child_paths();
        let (prior_kernel_path, prior_store_path, prior_config_path) =
            prior.manifest.host_child_paths();
        let candidate_config_locator = PathBuf::from(candidate_config_path.as_str());
        let prior_config_locator = PathBuf::from(prior_config_path.as_str());
        let result = self.jobs.cutover_with_rollback(
            candidate_kernel.as_ref(),
            candidate_store.as_ref(),
            prior_kernel.as_ref(),
            prior_store.as_ref(),
            &candidate.manifest.generation,
            &candidate.manifest.config_digest,
            &candidate_config_locator,
            candidate_kernel_path,
            candidate_store_path,
            candidate_config_path,
            candidate_kernel_artifact,
            candidate_store_artifact,
            &prior.manifest.generation,
            &prior.manifest.config_digest,
            &prior_config_locator,
            prior_kernel_path,
            prior_store_path,
            prior_config_path,
            prior_kernel_artifact,
            prior_store_artifact,
            &candidate.manifest.runtime_launch,
            &prior.manifest.runtime_launch,
            &self.host,
        );
        let launch = match result {
            Ok(launch) => launch,
            Err(error) => {
                let registry_root = self.registry_host_root.clone();
                persist_pending_recovery(
                    &registry_root,
                    &mut self.registry,
                    &host_capability,
                    &pending,
                    &error.to_string(),
                )?;
                return Err(error);
            }
        };
        if let Err(error) = self.fail_current_kernel_record("kernel-cutover-prior-terminated") {
            let cleanup = self.cleanup_launched_contour(error);
            let registry_root = self.registry_host_root.clone();
            persist_pending_recovery(
                &registry_root,
                &mut self.registry,
                &host_capability,
                &pending,
                "prior Kernel termination evidence failed",
            )?;
            return cleanup;
        }

        let launched_generation = launch
            .activation_generation(&candidate.manifest.generation, &prior.manifest.generation);
        if launched_generation == &prior.manifest.generation {
            let CutoverLaunchOutcome::Rollback { candidate_error } = &launch else {
                return Err(HostError::OwnerLeaseRecovery(
                    "cutover launch target discriminator was inconsistent".to_owned(),
                ));
            };
            if let Err(error) = self.activate_launched_kernel(
                &prior.manifest.generation,
                prior
                    .manifest
                    .runtime_launch
                    .authority_state_fence
                    .authority_epoch
                    .clone(),
            ) {
                return self.cleanup_launched_contour(HostError::RecoveryRequired(format!(
                    "candidate launch failed ({candidate_error}); rollback activation failed ({error})"
                )));
            }
            if let Err(error) = persist_pending_recovery(
                &self.registry_host_root.clone(),
                &mut self.registry,
                &host_capability,
                &pending,
                candidate_error,
            ) {
                return self.cleanup_active_kernel_contour(error, "rollback-registry-save-failed");
            }
            if let Err(error) = self.persist_process_observations(&prior.manifest.generation) {
                return self
                    .cleanup_active_kernel_contour(error, "rollback-process-observation-failed");
            }
            // F-LOG-HOST-1: rollback requested versus verified
            // restoration. The prior contour is durably reactivated
            // (kernel reactivated, registry persisted, observations
            // persisted); the returned Err reports the candidate
            // rejection, not a rollback failure.
            host_lifecycle_observe_requested(BOUNDARY_CUTOVER_ROLLBACK_REACTIVATED);
            return Err(HostError::ProcessContour(format!(
                "candidate rejected; prior approved contour durably reactivated: {candidate_error}"
            )));
        }

        if let Err(candidate_error) = self.activate_launched_kernel(
            &candidate.manifest.generation,
            candidate
                .manifest
                .runtime_launch
                .authority_state_fence
                .authority_epoch
                .clone(),
        ) {
            self.jobs.terminate_store_then_kernel()?;
            self.jobs.start_approved(
                prior_kernel.as_ref(),
                prior_store.as_ref(),
                &prior.manifest.generation,
                &prior.manifest.config_digest,
                &prior_config_locator,
                prior_kernel_path,
                prior_store_path,
                prior_config_path,
                prior_kernel_artifact,
                prior_store_artifact,
                &self.host,
                &prior.manifest.runtime_launch,
            )?;
            if let Err(rollback_error) = self.activate_launched_kernel(
                &prior.manifest.generation,
                prior
                    .manifest
                    .runtime_launch
                    .authority_state_fence
                    .authority_epoch
                    .clone(),
            ) {
                return self.cleanup_launched_contour(HostError::RecoveryRequired(format!(
                    "candidate activation failed ({candidate_error}); rollback activation failed ({rollback_error})"
                )));
            }
            let reason = candidate_error.to_string();
            if let Err(error) = persist_pending_recovery(
                &self.registry_host_root.clone(),
                &mut self.registry,
                &host_capability,
                &pending,
                &reason,
            ) {
                return self.cleanup_active_kernel_contour(error, "rollback-registry-save-failed");
            }
            if let Err(error) = self.persist_process_observations(&prior.manifest.generation) {
                return self
                    .cleanup_active_kernel_contour(error, "rollback-process-observation-failed");
            }
            return Err(HostError::ProcessContour(format!(
                "candidate activation failed; prior approved contour durably reactivated: {candidate_error}"
            )));
        }

        if let Err(error) = self.persist_process_observations(&candidate.manifest.generation) {
            let reason = error.to_string();
            let cleanup =
                self.cleanup_active_kernel_contour(error, "candidate-process-observation-failed");
            let registry_root = self.registry_host_root.clone();
            persist_pending_recovery(
                &registry_root,
                &mut self.registry,
                &host_capability,
                &pending,
                &reason,
            )?;
            cleanup
        } else {
            self.commit_pending_durable(&pending, &host_capability)?;
            Ok(())
        }
    }

    /// Runs one liveness-only SCM tick against the retained process handles.
    ///
    /// This path observes only Job/process liveness and rederives the exact
    /// readiness identity from in-memory approved bindings plus the journal
    /// service's in-memory snapshot projection.  It never restarts a branch,
    /// rehashes a file, opens the Kernel pipe, or performs durable journal I/O.
    ///
    /// # Errors
    ///
    /// Returns an error only when Host admission itself is fenced.
    #[cfg(windows)]
    pub fn liveness_tick(&mut self) -> Result<HostLivenessTick, HostError> {
        // F-LOG-HOST-1: liveness is never readiness. Single terminal via
        // guard; the readiness contour here is identity rederivation only.
        host_lifecycle_observe_requested(BOUNDARY_LIVENESS_REQUESTED);
        let mut host_terminal = HostTerminalGuard::armed(BOUNDARY_LIVENESS_TERMINAL);
        self.ensure_admission_open()?;
        let liveness = self.jobs.liveness_only();
        let active_manifest = self.registry.active().map(|active| &active.manifest);
        let mut readiness_gate = std::mem::take(&mut self.readiness_gate);
        let tick = descriptor_bound_liveness_tick(
            &mut readiness_gate,
            liveness,
            active_manifest,
            |generation, kernel, store, config| {
                self.current_readiness_contour(generation, kernel, store, config)
            },
            std::time::Instant::now(),
        );
        let tick = if matches!(tick, HostLivenessTick::HealthyLeasePreserved)
            && active_manifest.is_some_and(|manifest| {
                manifest.runtime_launch.profile == InstallationProfile::SystemService
            }) {
            // A cached Host readiness lease is not a current Watchdog
            // heartbeat. Force the supervised contour through a fresh probe.
            readiness_gate.branch_degraded();
            HostLivenessTick::FullReconcileDue
        } else {
            tick
        };
        self.readiness_gate = readiness_gate;
        host_terminal.disarm();
        // Liveness observation only; never claims ready.
        host_lifecycle_observe_requested(BOUNDARY_LIVENESS_OBSERVED);
        Ok(tick)
    }

    /// Reconciles the approved contour and records fresh process observations.
    ///
    /// # Errors
    ///
    /// Returns an error if admission is fenced, approved material cannot be
    /// revalidated, or branch reconciliation/activation fails.  Authoritative
    /// readiness failures return [`HostBranchDisposition::ReadinessDegraded`]
    /// while preserving the independently recoverable process contour.
    #[cfg(windows)]
    #[allow(clippy::too_many_lines, reason = "ordered branch reconciliation")]
    pub fn reconcile_approved_contour(&mut self) -> Result<HostBranchDisposition, HostError> {
        // F-LOG-HOST-1: reconcile vs liveness vs readiness preserved.
        // Readiness is claimed only inside `reconcile_branch_readiness_at`
        // with authenticated evidence; this outer only admits the contour.
        host_lifecycle_observe_requested(BOUNDARY_RECONCILE_REQUESTED);
        let mut host_terminal = HostTerminalGuard::armed(BOUNDARY_RECONCILE_TERMINAL);
        self.ensure_admission_open()?;
        let active =
            self.registry.active().cloned().ok_or_else(|| {
                HostError::ProcessContour("no approved active generation".to_owned())
            })?;
        let (kernel_artifact, store_artifact) = active
            .manifest
            .host_child_artifact_digests()
            .map_err(|error| HostError::ProcessContour(error.to_string()))?;
        let (approved_kernel_path, approved_store_path, approved_config_path) =
            active.manifest.host_child_paths();
        let config_path = PathBuf::from(approved_config_path.as_str());
        let materialized_config_digest = self.jobs.config_digest.clone().ok_or_else(|| {
            HostError::RecoveryRequired(
                "approved reconciliation has no Phase-B materialized config".to_owned(),
            )
        })?;
        let live_launch = self.jobs.launch.clone().ok_or_else(|| {
            HostError::RecoveryRequired(
                "approved reconciliation has no Phase-B live launch".to_owned(),
            )
        })?;
        let kernel_requires_activation = matches!(
            HostJobBranches::branch_state(self.jobs.kernel.as_ref()),
            Ok(BranchLiveness::Dead)
        );
        let store_requires_restart = matches!(
            HostJobBranches::branch_state(self.jobs.store.as_ref()),
            Ok(BranchLiveness::Dead)
        );
        if kernel_requires_activation || store_requires_restart {
            self.readiness_gate.branch_degraded();
        }
        if kernel_requires_activation {
            let current = self.journal.snapshot()?.kernel.ok_or_else(|| {
                HostError::OwnerLeaseRecovery(
                    "dead Kernel branch has no durable Kernel record".to_owned(),
                )
            })?;
            DurableKernelActivationDriver::resume(&self.journal, current)
                .fail("kernel-process-observed-dead")?;
        }
        let reconciled = if store_requires_restart {
            None
        } else {
            Some(self.jobs.reconcile(
                &active.manifest.generation,
                &materialized_config_digest,
                &config_path,
                approved_kernel_path,
                approved_store_path,
                approved_config_path,
                kernel_artifact,
                store_artifact,
                &self.host,
            ))
        };
        // Re-observe after generic reconciliation.  A Store can die after
        // the outer liveness check and the generic guard; only this shared
        // route may turn that typed late-dead result into Store mutation.
        let kernel_live = matches!(
            HostJobBranches::branch_state(self.jobs.kernel.as_ref()),
            Ok(BranchLiveness::Live)
        );
        let request = self
            .scm_store_recovery_request(&active.manifest.generation, &materialized_config_digest)?;
        let route = route_scm_store_recovery(
            ScmStoreRecoveryObservation {
                store_requires_restart,
                kernel_live,
                kernel_requires_activation,
                store_present: self.jobs.store.is_some(),
            },
            reconciled,
            &request,
            |request| self.execute_store_recovery(request).map(|_| ()),
        )?;
        let disposition = match route {
            ScmStoreRecoveryRoute::Recovered => {
                let disposition = self.reconcile_branch_readiness_at(
                    &active.manifest.generation,
                    kernel_artifact,
                    store_artifact,
                    &materialized_config_digest,
                    HostBranchDisposition::LiveAwaitingReadiness,
                    std::time::Instant::now(),
                );
                host_terminal.disarm();
                return Ok(disposition);
            }
            ScmStoreRecoveryRoute::Fenced(disposition) => {
                if let Err(error) = self.persist_degraded_process_observation(
                    &active.manifest.generation,
                    disposition,
                    None,
                    None,
                ) {
                    self.readiness_gate.fail(
                        None,
                        readiness_failure_kind(&error),
                        std::time::Instant::now(),
                    );
                    host_terminal.disarm();
                    return Ok(HostBranchDisposition::ReadinessDegraded);
                }
                if active.manifest.runtime_launch.profile == InstallationProfile::SystemService {
                    let (reason_ref, directive) = match disposition {
                        HostBranchDisposition::KernelDegraded => {
                            ("host-kernel-degraded", "recover-kernel-readiness")
                        }
                        HostBranchDisposition::StoreDegraded => {
                            ("host-store-degraded", "recover-store-readiness")
                        }
                        HostBranchDisposition::BothDegraded => (
                            "host-kernel-and-store-degraded",
                            "recover-runtime-readiness",
                        ),
                        HostBranchDisposition::ReadinessDegraded => {
                            ("host-readiness-degraded", "recover-runtime-readiness")
                        }
                        HostBranchDisposition::LiveAwaitingReadiness
                        | HostBranchDisposition::Healthy => {
                            host_terminal.disarm();
                            return Ok(HostBranchDisposition::ReadinessDegraded);
                        }
                    };
                    let failure_ref = PlatformHandle::new(format!(
                        "{reason_ref}:{}",
                        active.manifest.generation.as_str()
                    ))
                    .map_err(|error| HostError::Platform(error.to_string()))?;
                    self.persist_degraded_activation(
                        &active.manifest.generation,
                        "host-runtime-degraded",
                        &failure_ref,
                        directive,
                    )?;
                }
                host_terminal.disarm();
                return Ok(disposition);
            }
            ScmStoreRecoveryRoute::Continue(disposition) => disposition,
        };
        if kernel_requires_activation && self.jobs.kernel.is_some() {
            let (prior_kernel, kernel_generation, kernel_authority_epoch) = self
                .next_kernel_activation_context(
                    live_launch.authority_state_fence.authority_epoch.clone(),
                    None,
                )?;
            if let Err(error) = self.jobs.complete_kernel_control(
                &active.manifest.generation,
                &self.host,
                &self.journal,
                &self.activation_id,
                &self.activation_generation,
                prior_kernel,
                kernel_generation,
                kernel_authority_epoch,
                &active.manifest,
            ) {
                let cleanup = self.jobs.terminate_kernel();
                return Err(match cleanup {
                    Ok(()) => error,
                    Err(cleanup) => HostError::RecoveryRequired(format!(
                        "Kernel restart activation failed ({error}); Kernel cleanup failed ({cleanup})"
                    )),
                });
            }
        }
        let disposition = self.reconcile_branch_readiness_at(
            &active.manifest.generation,
            kernel_artifact,
            store_artifact,
            &materialized_config_digest,
            disposition,
            std::time::Instant::now(),
        );
        host_terminal.disarm();
        // Admitted only; ready vs degraded is owned by the readiness contour.
        host_lifecycle_observe_requested(BOUNDARY_RECONCILE_ADMITTED);
        Ok(disposition)
    }

    /// Persists the durable degraded activation fence for one already-degraded
    /// supervised system-service branch.
    ///
    /// The recovery directive and the reason reference are derived from the
    /// exact branch disposition, never from a liveness signal, and the
    /// `DegradedRecovery` record is appended before any later observation. A
    /// handle or journal failure fails the readiness gate and reports `false`
    /// so the caller returns degraded instead of claiming readiness.
    #[cfg(windows)]
    fn persist_supervised_degraded_activation(
        &mut self,
        generation: &PlatformHandle,
        disposition: HostBranchDisposition,
        now: std::time::Instant,
    ) -> bool {
        let (reason_ref, directive) = match disposition {
            HostBranchDisposition::KernelDegraded => {
                ("host-kernel-degraded", "recover-kernel-readiness")
            }
            HostBranchDisposition::StoreDegraded => {
                ("host-store-degraded", "recover-store-readiness")
            }
            HostBranchDisposition::BothDegraded => (
                "host-kernel-and-store-degraded",
                "recover-runtime-readiness",
            ),
            HostBranchDisposition::ReadinessDegraded => {
                ("host-readiness-degraded", "recover-runtime-readiness")
            }
            HostBranchDisposition::LiveAwaitingReadiness | HostBranchDisposition::Healthy => {
                return false;
            }
        };
        let failure_ref = match PlatformHandle::new(format!("{reason_ref}:{}", generation.as_str()))
        {
            Ok(reference) => reference,
            Err(error) => {
                let error = HostError::Platform(error.to_string());
                self.readiness_gate
                    .fail(None, readiness_failure_kind(&error), now);
                return false;
            }
        };
        if let Err(error) = self.persist_degraded_activation(
            generation,
            "host-runtime-degraded",
            &failure_ref,
            directive,
        ) {
            self.readiness_gate
                .fail(None, readiness_failure_kind(&error), now);
            return false;
        }
        true
    }

    #[cfg(windows)]
    fn reconcile_branch_readiness_at(
        &mut self,
        generation: &PlatformHandle,
        kernel_artifact: &PlatformHandle,
        store_artifact: &PlatformHandle,
        config: &PlatformHandle,
        disposition: HostBranchDisposition,
        now: std::time::Instant,
    ) -> HostBranchDisposition {
        // F-LOG-HOST-1: readiness is claimed only with authenticated proof.
        // Degraded vs ready preserved; liveness alone never becomes ready.
        // Phase only; outer reconcile owns the terminal.
        let supervised_system_service = self
            .registry
            .generations()
            .iter()
            .find(|item| item.manifest.generation == *generation)
            .is_some_and(|item| {
                item.manifest.runtime_launch.profile == InstallationProfile::SystemService
            });
        if disposition != HostBranchDisposition::LiveAwaitingReadiness {
            self.readiness_gate.branch_degraded();
            host_lifecycle_observe_requested(BOUNDARY_READINESS_DEGRADED);
            if supervised_system_service
                && !self.persist_supervised_degraded_activation(generation, disposition, now)
            {
                return HostBranchDisposition::ReadinessDegraded;
            }
            // The durable activation fence above is written BEFORE this
            // observation, so a failure here cannot leave a supervised contour
            // observably `Active` in the durable projection. We still fail
            // closed and return degraded.
            if let Err(error) =
                self.persist_degraded_process_observation(generation, disposition, None, None)
            {
                self.readiness_gate
                    .fail(None, readiness_failure_kind(&error), now);
                return HostBranchDisposition::ReadinessDegraded;
            }
            return disposition;
        }
        // A late Store recovery result is not proof that Host supervision
        // recovered.  Require the exact current Active activation generation
        // before any fresh positive readiness observation is appended; a
        // Starting, DegradedRecovery, missing, or unreadable activation remains
        // a visible recovery boundary.
        let activation = match self.journal.snapshot() {
            Ok(state) => state.activation,
            Err(error) => {
                self.readiness_gate.fail(
                    None,
                    readiness_failure_kind(&HostError::Journal(error)),
                    now,
                );
                return HostBranchDisposition::ReadinessDegraded;
            }
        };
        let Some(activation) = activation else {
            self.readiness_gate.fail(
                None,
                readiness_failure_kind(&HostError::OwnerLeaseRecovery(
                    "activation record is absent".to_owned(),
                )),
                now,
            );
            return HostBranchDisposition::ReadinessDegraded;
        };
        if activation.state != ActivationState::Active
            || activation.fence.activation_generation != self.activation_generation
        {
            self.readiness_gate.fail(
                None,
                readiness_failure_kind(&HostError::RecoveryRequired(
                    "fresh readiness requires the exact current Active Host activation".to_owned(),
                )),
                now,
            );
            return HostBranchDisposition::ReadinessDegraded;
        }
        host_lifecycle_observe_requested(BOUNDARY_READINESS_REQUESTED_PROOF);
        let contour =
            self.current_readiness_contour(generation, kernel_artifact, store_artifact, config);
        let contour_unavailable = contour.is_err();
        let mut readiness_gate = std::mem::take(&mut self.readiness_gate);
        // A live SystemService activation must not reuse a cached readiness
        // lease: every full reconcile consumes a fresh Watchdog heartbeat.
        readiness_gate.branch_degraded();
        let mut watchdog_failure = false;
        let outcome = reconcile_authenticated_readiness(&mut readiness_gate, contour, now, || {
            let result = self.persist_fresh_authenticated_readiness(generation);
            watchdog_failure = matches!(&result, Err(HostError::WatchdogCoverageUnavailable(_)));
            result
        });
        self.readiness_gate = readiness_gate;
        // Ready only when the authenticated gate admits it; degraded stays
        // degraded. A failed supervised proof also records a cause-specific
        // recovery state; generic Store/Kernel failures are not mislabeled as
        // Watchdog loss.
        if outcome == HostBranchDisposition::Healthy {
            let activation_state = self
                .journal
                .snapshot()
                .ok()
                .and_then(|state| state.activation)
                .map(|activation| activation.state);
            if activation_state == Some(ActivationState::DegradedRecovery) {
                // The durable state model does not permit a same-generation
                // jump from DegradedRecovery back to ControlReady/Active.
                // Keep the fence explicit; a new activation generation or
                // owner-led recovery must perform the legal transition.
                self.readiness_gate.branch_degraded();
                return HostBranchDisposition::ReadinessDegraded;
            }
            host_lifecycle_observe_requested(BOUNDARY_READINESS_READY_PROOF);
        } else if !self.persist_authenticated_readiness_degradation(
            generation,
            outcome,
            watchdog_failure,
            contour_unavailable,
            supervised_system_service,
            now,
        ) {
            return HostBranchDisposition::ReadinessDegraded;
        }
        outcome
    }

    /// Re-observes the independent Watchdog branch for one readiness contour
    /// and returns the closed carrier that publishes it.
    ///
    /// I1.5 (#1750): a repeated readiness probe is an ordinary request and must
    /// not be answered from the observation retained since activation. This
    /// re-runs the SAME single producer the startup path uses, so the live SCM
    /// Watchdog incarnation is re-read from the OS right now (bound PID/start
    /// pair, process liveness, and image bytes equal to the approved Watchdog
    /// artifact) and the whole carrier is rebuilt from fresh probes. It runs on
    /// the Host's own bounded readiness cadence, never synchronously on an
    /// ordinary request, and it introduces no second supervisor, no second
    /// observation protocol and no new wire field.
    ///
    /// # Errors
    ///
    /// Returns the producer's own typed reason: an unreadable journal, no
    /// usable active manifest, an unbound or dead Watchdog incarnation, a
    /// substituted Watchdog image, a tampered Blob manifest, or a contour that
    /// is not the approved active generation.
    #[cfg(windows)]
    fn reobserve_watchdog_supervision_evidence(
        &self,
        generation: &PlatformHandle,
    ) -> Result<HostStartupEvidence, HostError> {
        let launch = self.jobs.launch.as_ref().ok_or_else(|| {
            HostError::ProcessContour("runtime launch descriptor is missing".to_owned())
        })?;
        let candidate = self.jobs.kernel_candidate.as_ref().ok_or_else(|| {
            HostError::ProcessContour("retained Kernel candidate binding is missing".to_owned())
        })?;
        if self.jobs.approved_generation.as_ref() != Some(generation) {
            return Err(HostError::ProcessContour(
                "readiness re-observation is not for the approved active generation".to_owned(),
            ));
        }
        let active = self
            .registry
            .generations()
            .iter()
            .find(|item| item.manifest.generation == *generation)
            .ok_or_else(|| {
                HostError::ProcessContour(
                    "readiness re-observation generation is not present in the approved registry"
                        .to_owned(),
                )
            })?;
        host_startup_evidence::build_host_startup_evidence(
            &self.journal,
            &active.manifest,
            candidate,
            launch.authority_generation,
            candidate.kernel_epoch.clone(),
            self.launch_options.host_state_root(),
            Path::new(launch.runtime_state_roots.store_data_root.as_str()),
        )
    }

    /// Persists the durable evidence for one failed authenticated readiness
    /// proof, with a cause-specific reason.
    ///
    /// A refused independent-Watchdog proof, an unreadable readiness contour,
    /// and a generic readiness degradation are three distinct causes and are
    /// never collapsed into one label. The durable activation fence is written
    /// FIRST for a supervised system-service branch, so a degraded supervised
    /// contour can never be observed as still `Active` in the durable
    /// projection even if the later process observation fails; non-supervised
    /// profiles never wrote an activation fence on this path. Every failure
    /// closes the readiness gate and reports `false`.
    #[cfg(windows)]
    fn persist_authenticated_readiness_degradation(
        &mut self,
        generation: &PlatformHandle,
        outcome: HostBranchDisposition,
        watchdog_failure: bool,
        contour_unavailable: bool,
        supervised_system_service: bool,
        now: std::time::Instant,
    ) -> bool {
        let (reason_ref, directive) = if watchdog_failure {
            (
                "host-watchdog-coverage-unavailable",
                "restore-watchdog-coverage",
            )
        } else if contour_unavailable {
            (
                "host-readiness-contour-unavailable",
                "recover-runtime-readiness",
            )
        } else {
            ("host-readiness-degraded", "recover-runtime-readiness")
        };
        let failure_ref = match PlatformHandle::new(format!("{reason_ref}:{}", generation.as_str()))
        {
            Ok(reference) => reference,
            Err(error) => {
                let error = HostError::Platform(error.to_string());
                self.readiness_gate
                    .fail(None, readiness_failure_kind(&error), now);
                return false;
            }
        };
        if supervised_system_service
            && let Err(error) = self.persist_degraded_activation(
                generation,
                "host-readiness-degraded",
                &failure_ref,
                directive,
            )
        {
            self.readiness_gate
                .fail(None, readiness_failure_kind(&error), now);
            return false;
        }
        if let Err(error) = self.persist_degraded_process_observation(
            generation,
            outcome,
            Some(reason_ref),
            Some(&failure_ref),
        ) {
            self.readiness_gate
                .fail(None, readiness_failure_kind(&error), now);
            return false;
        }
        host_lifecycle_observe_requested(BOUNDARY_READINESS_DEGRADED);
        true
    }

    /// Returns whether either approved process branch or its bounded recovery
    /// record remains present for reconciliation.
    #[cfg(windows)]
    #[must_use]
    pub fn has_process_contour(&self) -> bool {
        self.jobs.has_recorded_contour()
    }

    #[cfg(windows)]
    fn persist_process_observations(
        &mut self,
        generation: &PlatformHandle,
    ) -> Result<(), HostError> {
        let now = std::time::Instant::now();
        let contour = self.persist_fresh_authenticated_readiness(generation)?;
        if !self.readiness_gate.grant(contour, now) {
            return Err(HostError::ProcessContour(
                "journaled readiness contour has no Store proof fence".to_owned(),
            ));
        }
        Ok(())
    }

    #[cfg(windows)]
    #[allow(
        clippy::too_many_lines,
        reason = "readiness contour validates the retained Kernel, Store, semantic-config, Job, and journal identities as one fence"
    )]
    fn current_readiness_contour(
        &self,
        generation: &PlatformHandle,
        kernel_artifact: &PlatformHandle,
        store_artifact: &PlatformHandle,
        config: &PlatformHandle,
    ) -> Result<ReadinessContourIdentity, HostError> {
        // F-LOG-HOST-1: contour probe only; never claims ready by itself.
        // The ready claim happens only after the authenticated proof fence.
        host_lifecycle_observe_requested(BOUNDARY_READINESS_CONTOUR_REQUESTED);
        if self.jobs.approved_generation.as_ref() != Some(generation)
            || self.jobs.kernel_artifact_digest.as_ref() != Some(kernel_artifact)
            || self.jobs.store_artifact_digest.as_ref() != Some(store_artifact)
            || self.jobs.config_digest.as_ref() != Some(config)
        {
            return Err(HostError::ProcessContour(
                "retained readiness contour is not the approved active generation".to_owned(),
            ));
        }
        let candidate = self.jobs.kernel_candidate.as_ref().ok_or_else(|| {
            HostError::ProcessContour("retained Kernel candidate binding is missing".to_owned())
        })?;
        let requirement = self
            .jobs
            .store_bootstrap_requirement
            .as_ref()
            .ok_or_else(|| {
                HostError::ProcessContour(
                    "retained Store bootstrap requirement is missing".to_owned(),
                )
            })?;
        requirement
            .validate()
            .map_err(|error| HostError::ProcessContour(error.to_string()))?;
        let semantic_config_hash =
            self.jobs
                .store_config_semantic_hash
                .as_ref()
                .ok_or_else(|| {
                    HostError::ProcessContour(
                        "retained Store semantic config hash is missing".to_owned(),
                    )
                })?;
        if candidate.artifact_hash != *kernel_artifact
            || candidate.config_hash != *config
            || requirement.approved_artifact_hash != *store_artifact
            || requirement.approved_config_hash != *semantic_config_hash
            || requirement.state_fence.authority_epoch != candidate.kernel_epoch
        {
            return Err(HostError::ProcessContour(
                "retained readiness authority or artifact binding is stale".to_owned(),
            ));
        }
        self.jobs.validate_running_kernel_candidate(candidate)?;
        let candidate_job = &candidate.job_binding;
        let state = self.journal.snapshot()?;
        let active = state.kernel.as_ref().ok_or_else(|| {
            HostError::ProcessContour("readiness contour has no Kernel record".to_owned())
        })?;
        let active_process = active.process.as_ref().ok_or_else(|| {
            HostError::ProcessContour("active Kernel process binding is absent".to_owned())
        })?;
        let active_job = active.candidate_job_binding.as_ref().ok_or_else(|| {
            HostError::ProcessContour("active Kernel Job binding is absent".to_owned())
        })?;
        if active.state != KernelActivationState::Active
            || active.one_time_nonce.state() != NonceState::Consumed
            || active.activation_identity != candidate.activation_id
            || active.approved_artifact_hash != *kernel_artifact
            || active.active_pipe_identity.as_ref() != Some(&candidate.pipe_identity)
            || active_process.authority_epoch.value() != candidate.kernel_epoch.sequence.get()
            || active_process.process_id
                != format!(
                    "pid:{}:start:{}",
                    candidate_job.root.process.process_id,
                    candidate_job.root.process.start_time_100ns
                )
            || active_job.job_name.as_str() != candidate_job.job.name
            || active_job.root_pid != candidate_job.root.process.process_id
            || active_job.root_start_time_100ns != candidate_job.root.process.start_time_100ns
            || active_job.root_image_path.as_str() != candidate_job.root.process.image_path
            || active_job.root_volume_serial_number
                != candidate_job.root.executable.volume_serial_number
            || active_job.root_file_index != candidate_job.root.executable.file_index
        {
            return Err(HostError::ProcessContour(
                "durable Kernel is not the retained Active+Consumed contour".to_owned(),
            ));
        }
        let active_kernel_record_checksum =
            PlatformHandle::new(record_checksum(&HostStateRecord::Kernel(active.clone()))?)
                .map_err(|error| HostError::Platform(error.to_string()))?;
        let candidate_binding_digest = PlatformHandle::new(
            candidate
                .compute_digest()
                .map_err(|error| HostError::ProcessContour(error.to_string()))?,
        )
        .map_err(|error| HostError::Platform(error.to_string()))?;
        let store_requirement_digest = PlatformHandle::new(sha256_json(requirement)?)
            .map_err(|error| HostError::Platform(error.to_string()))?;
        let registry_generation = self
            .registry
            .generations()
            .iter()
            .find(|item| item.manifest.generation == *generation)
            .ok_or_else(|| {
                HostError::ProcessContour(
                    "readiness generation is absent from the durable registry".to_owned(),
                )
            })?;
        let registry_authority = self
            .registry
            .provisioned_supervision_authority_for_generation(generation)
            .map_err(|error| HostError::ProcessContour(error.to_string()))?
            .ok_or_else(|| {
                HostError::ProcessContour(
                    "readiness generation has no durable provisioned supervision authority"
                        .to_owned(),
                )
            })?;
        let launch_authority = self
            .jobs
            .launch
            .as_ref()
            .ok_or_else(|| {
                HostError::ProcessContour(
                    "readiness contour has no retained Phase-B launch overlay".to_owned(),
                )
            })?
            .provisioned_supervision_authority()
            .map_err(|error| HostError::ProcessContour(error.to_string()))?;
        if launch_authority != registry_authority {
            return Err(HostError::ProcessContour(
                "retained Phase-B launch authority differs from durable registry authority"
                    .to_owned(),
            ));
        }
        let template = registry_authority
            .watchdog_admission_template()
            .map_err(|error| HostError::ProcessContour(error.to_string()))?;
        let current_supervision = read_manifest_current_supervision_lease(
            &registry_generation.manifest,
            &candidate.supervision_incarnation.supervision_lease_id,
        )?;
        let supervision_identity =
            supervision_publication_identity(&template, &current_supervision)?;
        let expected_publication_path = self.launch_options.host_state_root().join(format!(
            "{WATCHDOG_PUBLICATION_DIRECTORY_PREFIX}{}",
            current_supervision.receipt.receipt_sha256
        ));
        let publication_is_exact = observe_host_watchdog_publication(&expected_publication_path)
            .and_then(|observed| {
                verify_exact_current_watchdog_publication(
                    &observed,
                    &template,
                    &current_supervision,
                )
            })
            .is_ok();
        let store_proof_fence = state.readiness_observations.last().and_then(|observation| {
            (readiness_supervision_fence_matches(
                &supervision_identity,
                publication_is_exact,
                &observation.evidence_refs,
            ) && observation.active_kernel_record_checksum == active_kernel_record_checksum
                && observation.fence == active.fence
                && observation.kernel_process.process_id == active_process.process_id
                && observation.kernel_job == *active_job
                && observation.config_digest == *config
                && observation.authority_epoch == candidate.kernel_epoch.sequence.get())
            .then(|| observation.store_fence.clone())
        });
        Ok(ReadinessContourIdentity {
            approved_generation: generation.clone(),
            approved_kernel_artifact: kernel_artifact.clone(),
            approved_store_artifact: store_artifact.clone(),
            approved_config: config.clone(),
            active_kernel_record_checksum,
            candidate_binding_digest,
            store_requirement_digest,
            store_proof_fence,
            supervision_lease_id: Some(supervision_identity.lease_id),
            supervision_ors_receipt_digest: Some(supervision_identity.ors_receipt_digest),
            watchdog_publication_digest: Some(supervision_identity.publication_digest),
        })
    }

    #[cfg(windows)]
    /// Re-verifies the SCM-bound Watchdog incarnation and consumes one
    /// armed heartbeat admission window for this readiness proof.
    ///
    /// Transport1750 steps 5-7: a disarmed contour (no descriptor file)
    /// returns no refs and preserves current behavior exactly; an armed
    /// contour with no fresh admitted heartbeat fails closed. The SCM
    /// re-verification is read-only and introduces no Job, kill-handle, or
    /// SCM stop capability.
    #[cfg(windows)]
    fn observe_watchdog_heartbeat_for_admission(
        &self,
        manifest: &CandidateManifest,
        proof: &AuthenticatedKernelReadiness,
    ) -> Result<watchdog_heartbeat::AdmittedHostHeartbeat, HostError> {
        let scm_launch = &manifest.runtime_launch;
        let Some(approval) = select_watchdog_approval_for_inspection(&self.registry, manifest)?
        else {
            return Err(HostError::WatchdogCoverageUnavailable(
                "approved SystemService generation has no Watchdog SCM approval".to_owned(),
            ));
        };
        let registration = approved_service_registration_request(
            scm_launch,
            &approval,
            InstallerServiceRole::Watchdog,
            &scm_launch.watchdog_executable_path,
        )?;
        let mut platform =
            WindowsPlatform::new(PathBuf::from(scm_launch.kernel_work_root.as_str()))
                .map_err(|error| HostError::Platform(error.to_string()))?;
        let scm = match platform.inspect_registration_runtime(&registration) {
            InstalledWatchdogRuntimeInspection::Matching {
                state,
                wait_hint_ms,
                process,
            } => verify_watchdog_scm_running(&registration, state, wait_hint_ms, process.as_ref())?,
            _ => {
                return Err(HostError::WatchdogCoverageUnavailable(
                    "Watchdog is not Running for heartbeat admission".to_owned(),
                ));
            }
        };
        let expected_kernel_epoch = proof
            .supervision_lease
            .record
            .binding
            .kernel_epoch
            .sequence
            .get();
        let expected_watchdog_epoch = proof
            .supervision_lease
            .record
            .binding
            .watchdog_epoch
            .value();
        let admitted = watchdog_heartbeat::observe_armed_heartbeat_admitted(
            self.launch_options.host_state_root(),
            expected_kernel_epoch,
            expected_watchdog_epoch,
            &scm,
        )
        .map_err(|error| match error {
            HostError::WatchdogCoverageUnavailable(_) => error,
            _ => HostError::WatchdogCoverageUnavailable(
                "fresh Watchdog heartbeat admission did not prove coverage".to_owned(),
            ),
        })?;
        if admitted.observation.coverage != watchdog_heartbeat::HostHeartbeatCoverage::Continuous {
            return Err(HostError::WatchdogCoverageUnavailable(
                "fresh Watchdog heartbeat did not prove continuous coverage".to_owned(),
            ));
        }
        Ok(admitted)
    }
    #[cfg(windows)]
    #[allow(
        clippy::too_many_lines,
        reason = "fresh readiness keeps probe, exact supervision publication, final ORS fence, journal append, and readback in causal order"
    )]
    fn persist_fresh_authenticated_readiness(
        &mut self,
        generation: &PlatformHandle,
    ) -> Result<ReadinessContourIdentity, HostError> {
        // F-LOG-HOST-1: ready only with actual proof fence; phase only here,
        // outer reconcile owns the terminal. Never claims ready from liveness.
        host_lifecycle_observe_requested(BOUNDARY_READINESS_PROOF_REQUESTED);
        // A pending candidate is approved but intentionally not active until
        // this fresh proof crosses the registry CAS.  Resolve the exact
        // generation from the registry projection rather than treating the
        // active pointer as readiness authority.
        let active = self
            .registry
            .generations()
            .iter()
            .find(|item| item.manifest.generation == *generation)
            .cloned()
            .ok_or_else(|| {
                HostError::ProcessContour(
                    "readiness probe generation is not present in the approved registry".to_owned(),
                )
            })?;
        let (kernel_artifact, store_artifact) = active
            .manifest
            .host_child_artifact_digests()
            .map_err(|error| HostError::ProcessContour(error.to_string()))?;
        let materialized_config_digest = self.jobs.config_digest.as_ref().ok_or_else(|| {
            HostError::ProcessContour(
                "readiness probe has no materialized Store config digest".to_owned(),
            )
        })?;
        // I1.5 (#1750): republish a CURRENT independent Watchdog observation
        // before the repeat probe, on this bounded readiness cadence, so the
        // probe is answered from a fresh owner observation instead of from the
        // one retained since activation. The carrier rides the same connection
        // and the same strict per-connection command sequence as the probe.
        let supervision_evidence = self.reobserve_watchdog_supervision_evidence(generation)?;
        let contour = self.current_readiness_contour(
            generation,
            kernel_artifact,
            store_artifact,
            materialized_config_digest,
        )?;
        let proof = self.jobs.probe_kernel_readiness(
            generation,
            kernel_artifact,
            store_artifact,
            materialized_config_digest,
            &supervision_evidence,
        )?;
        let registry_authority = self
            .registry
            .provisioned_supervision_authority_for_generation(generation)
            .map_err(|error| HostError::ProcessContour(error.to_string()))?
            .cloned()
            .ok_or_else(|| {
                HostError::ProcessContour(
                    "readiness generation has no durable provisioned supervision authority"
                        .to_owned(),
                )
            })?;
        let launch_authority = self
            .jobs
            .launch
            .as_ref()
            .ok_or_else(|| {
                HostError::ProcessContour(
                    "readiness contour has no retained Phase-B launch overlay".to_owned(),
                )
            })?
            .provisioned_supervision_authority()
            .map_err(|error| HostError::ProcessContour(error.to_string()))?;
        if launch_authority != &registry_authority {
            return Err(HostError::ProcessContour(
                "retained Phase-B launch authority differs from durable registry authority"
                    .to_owned(),
            ));
        }
        let watchdog_template = registry_authority
            .watchdog_admission_template()
            .map_err(|error| HostError::ProcessContour(error.to_string()))?;
        // The publication bundle is published for its durable side effect
        // (exact current bundle plus trust-anchor signature verification);
        // the admitted identity below is derived single-source from the same
        // Kernel-renewed snapshot, never from this return value.
        let published_supervision = publish_current_watchdog_supervision_bundle(
            self.launch_options.host_state_root(),
            &active.manifest,
            &watchdog_template,
            &registry_authority.watchdog_admission_template_digest,
            &proof.supervision_lease,
        )?;
        require_exact_supervision_head(&proof.supervision_lease, || {
            read_manifest_current_supervision_lease(
                &active.manifest,
                proof.supervision_lease.record.lease_id.as_str(),
            )
        })?;
        // Transport1750 steps 7-8: the admitted readiness stores the Host
        // observation digest, coverage, and receive time alongside kernel
        // readiness and the watchdog-branch ref. Disarmed contours
        // contribute no refs; armed contours fail closed without a fresh
        // admitted heartbeat.
        let supervised_system_service =
            active.manifest.runtime_launch.profile == InstallationProfile::SystemService;
        let heartbeat_refs = if supervised_system_service {
            self.observe_watchdog_heartbeat_for_admission(&active.manifest, &proof)?
                .evidence_refs
        } else {
            Vec::new()
        };
        if supervised_system_service && heartbeat_refs.is_empty() {
            return Err(HostError::WatchdogCoverageUnavailable(
                "fresh Watchdog heartbeat evidence is empty".to_owned(),
            ));
        }
        let (_, admitted_supervision) = append_authenticated_kernel_readiness_with_heartbeat(
            &self.journal,
            &proof,
            kernel_artifact,
            materialized_config_digest,
            &watchdog_template,
            &heartbeat_refs,
        )?;
        debug_assert_eq!(
            published_supervision, admitted_supervision,
            "single-snapshot supervision identity diverged between publication and journal admission"
        );
        let confirmed = self.current_readiness_contour(
            generation,
            kernel_artifact,
            store_artifact,
            materialized_config_digest,
        )?;
        if !confirmed.same_probe_input_contour(&contour)
            || confirmed.store_proof_fence.as_ref() != Some(&proof.store_fence)
            || confirmed.supervision_lease_id.as_ref() != Some(&admitted_supervision.lease_id)
            || confirmed.supervision_ors_receipt_digest.as_ref()
                != Some(&admitted_supervision.ors_receipt_digest)
            || confirmed.watchdog_publication_digest.as_ref()
                != Some(&admitted_supervision.publication_digest)
        {
            return Err(HostError::ProcessContour(
                "readiness contour changed while admitting the proof".to_owned(),
            ));
        }
        // F-LOG-HOST-1: ready only now that the proof fence is confirmed.
        host_lifecycle_observe_requested(BOUNDARY_READINESS_PROOF_READY);
        Ok(confirmed)
    }

    #[cfg(windows)]
    fn persist_degraded_process_observation(
        &mut self,
        generation: &PlatformHandle,
        disposition: HostBranchDisposition,
        reason_override: Option<&str>,
        failure_ref: Option<&PlatformHandle>,
    ) -> Result<(), HostError> {
        // F-LOG-HOST-1: degraded is distinct from ready; phase only.
        host_lifecycle_observe_requested(BOUNDARY_DEGRADED_OBSERVATION_REQUESTED);
        debug_assert_ne!(
            disposition,
            HostBranchDisposition::LiveAwaitingReadiness,
            "degraded observations cannot admit readiness"
        );
        let state = self.journal.snapshot()?;
        let activation = state.activation.ok_or_else(|| {
            HostError::OwnerLeaseRecovery("activation record is absent".to_owned())
        })?;
        let observation_id = fresh_identity("host-branch-observation")?;
        let (obligation_profile_ref, default_reason_ref) = match disposition {
            HostBranchDisposition::KernelDegraded => {
                ("runtime-live-v3-readiness", "host-kernel-degraded")
            }
            HostBranchDisposition::StoreDegraded => {
                ("canonical-store-readiness", "host-store-degraded")
            }
            HostBranchDisposition::BothDegraded => (
                "runtime-live-v3-readiness",
                "host-kernel-and-store-degraded",
            ),
            HostBranchDisposition::ReadinessDegraded => {
                ("runtime-live-v3-readiness", "host-readiness-degraded")
            }
            HostBranchDisposition::LiveAwaitingReadiness | HostBranchDisposition::Healthy => {
                return Err(HostError::ProcessContour(
                    "healthy disposition cannot be recorded as degraded".to_owned(),
                ));
            }
        };
        let reason_ref = reason_override.unwrap_or(default_reason_ref);
        let mut evidence_refs = vec![generation.as_str().to_owned()];
        if let Some(failure_ref) = failure_ref {
            evidence_refs.push(failure_ref.as_str().to_owned());
        }
        self.append_record(HostStateRecord::Observation(HostObservationRecord {
            fence: activation.fence,
            operation: operation("host-process-observation")?,
            observation: ObservationRecordEnvelope {
                record_id: observation_id.as_str().to_owned(),
                kind: ObservationRecordKind::CoverageGap,
                event: None,
                coverage_gap: Some(CoverageGap {
                    gap_id: observation_id.as_str().to_owned(),
                    obligation_profile_ref: obligation_profile_ref.to_owned(),
                    reason_ref: reason_ref.to_owned(),
                    affected_interval: None,
                    disposition: GapDisposition::BlockDependentTransition,
                    protected: true,
                    evidence_refs,
                }),
                journal_control_event: false,
                parent_record_id: None,
            },
            binding_evidence_refs: vec![generation.clone()],
        }))?;
        Ok(())
    }

    #[cfg(windows)]
    /// Returns whether a durable degraded-branch recovery fence is active.
    ///
    /// # Errors
    ///
    /// Returns an error if the durable Host state cannot be loaded.
    pub fn has_durable_branch_fence(&self) -> Result<bool, HostError> {
        // F-LOG-HOST-1: guard probe only; never a terminal and never readiness.
        host_lifecycle_observe_requested(BOUNDARY_BRANCH_FENCE_REQUESTED);
        let state = self.snapshot()?;
        let supervised = self.registry.active().is_some_and(|active| {
            active.manifest.runtime_launch.profile == InstallationProfile::SystemService
        });
        Ok(self.store_recovery_startup_fence.is_fenced()
            || self.pending_record.is_some()
            || state.activation.as_ref().is_some_and(|activation| {
                activation.state == ActivationState::Failed
                    || (supervised
                        && matches!(
                            activation.state,
                            ActivationState::Starting | ActivationState::DegradedRecovery
                        ))
            })
            || (supervised
                && state
                    .activation
                    .as_ref()
                    .is_some_and(|activation| activation.state == ActivationState::Active)
                && !self.jobs.has_recorded_contour()))
    }

    #[cfg(windows)]
    fn cleanup_active_kernel_contour(
        &mut self,
        error: HostError,
        evidence: &str,
    ) -> Result<(), HostError> {
        // F-LOG-HOST-1: cleanup phase only; outer start/stop owns the terminal.
        // `evidence` is an already-produced typed reason, never free text.
        host_lifecycle_observe_drain(BOUNDARY_CLEANUP_ACTIVE_REQUESTED);
        let durable = self
            .journal
            .snapshot()
            .map_err(HostError::Journal)
            .and_then(|state| {
                let current = state.kernel.ok_or_else(|| {
                    HostError::OwnerLeaseRecovery(
                        "active Kernel cleanup has no durable Kernel record".to_owned(),
                    )
                })?;
                DurableKernelActivationDriver::resume(&self.journal, current).fail(evidence)
            });
        finish_active_kernel_cleanup(durable, || self.cleanup_launched_contour(error))
    }

    #[cfg(windows)]
    fn reconcile_watchdog_start_for_cleanup(&mut self) -> Result<(), HostError> {
        let Some((registration, platform_root, heartbeat_state_root)) =
            self.watchdog_start_recovery.as_ref().map(|carrier| {
                (
                    carrier.registration.clone(),
                    carrier.platform_root.clone(),
                    carrier.heartbeat_state_root.clone(),
                )
            })
        else {
            return Ok(());
        };
        self.reconcile_watchdog_start_bound(registration, platform_root, heartbeat_state_root)
    }

    #[cfg(windows)]
    fn cleanup_launched_contour(&mut self, error: HostError) -> Result<(), HostError> {
        // F-LOG-HOST-1: cleanup phase only; outer owns the terminal.
        host_lifecycle_observe_drain(BOUNDARY_CLEANUP_LAUNCHED_REQUESTED);
        let projection = (|| -> Result<(), HostError> {
            let activation_state = self
                .journal
                .snapshot()?
                .activation
                .map(|activation| activation.state);
            if matches!(&error, HostError::WatchdogCoverageUnavailable(_)) {
                self.persist_current_watchdog_degraded("host-watchdog-coverage-start-failed")
            } else if self.registry.active().is_some_and(|active| {
                active.manifest.runtime_launch.profile == InstallationProfile::SystemService
            }) && matches!(
                activation_state,
                Some(
                    ActivationState::Starting
                        | ActivationState::ControlReady
                        | ActivationState::Active
                )
            ) {
                // A failed supervised startup/cutover cannot leave a live-looking
                // contour admissible to a later material caller. Use the existing
                // recovery-state projection so the mandatory directive is
                // persisted with a legal transition edge.
                let failure_ref = PlatformHandle::new("host-start-failed:recovery-required")
                    .map_err(|error| HostError::Platform(error.to_string()))?;
                let target_generation = self
                    .registry
                    .pending_activation()
                    .map(|pending| pending.manifest.generation.clone())
                    .or_else(|| {
                        self.registry
                            .active()
                            .map(|active| active.manifest.generation.clone())
                    })
                    .ok_or_else(|| {
                        HostError::RecoveryRequired(
                            "failed startup has no exact target generation for recovery".to_owned(),
                        )
                    })?;
                self.persist_degraded_activation(
                    &target_generation,
                    "host-start-failed",
                    &failure_ref,
                    "recover-startup",
                )
            } else {
                Ok(())
            }
        })();
        // Known child cleanup is unconditional. A journal/degraded-projection
        // failure must never leave Store or Kernel alive merely because the
        // failure capsule could not be persisted first.
        let watchdog = self.reconcile_watchdog_start_for_cleanup();
        let store = self.jobs.terminate_store();
        let kernel = self.jobs.terminate_kernel();
        match (projection, watchdog, kernel, store) {
            (Ok(()), Ok(()), Ok(()), Ok(())) => {
                self.jobs.clear_recorded_contour();
                Err(error)
            }
            (projection, watchdog, kernel, store) => Err(HostError::RecoveryRequired(format!(
                "persistence failed ({error}); launched contour cleanup requires recovery: projection={projection:?}, watchdog={watchdog:?}, kernel={kernel:?}, store={store:?}"
            ))),
        }
    }

    fn ensure_admission_open(&self) -> Result<(), HostError> {
        // F-LOG-HOST-1: guard phase only; callers own the single terminal.
        // Requested vs admitted preserved: fenced is never admitted.
        if !self.running {
            return Err(HostError::Stopped);
        }
        #[cfg(windows)]
        if self.store_recovery_startup_fence.is_fenced() {
            return Err(HostError::OwnerLeaseRecovery(
                "crashed Store recovery fence blocks fresh admission".to_owned(),
            ));
        }
        if self.pending_record.is_some() || self.shutdown_failed {
            return Err(HostError::OwnerLeaseRecovery(
                "durable Host release/recovery is still pending".to_owned(),
            ));
        }
        Ok(())
    }

    fn ensure_recovery_admission_open(&self) -> Result<(), HostError> {
        self.ensure_admission_open()?;
        #[cfg(windows)]
        {
            let state = self.journal.snapshot()?;
            if state.activation.as_ref().is_some_and(|activation| {
                matches!(
                    activation.state,
                    ActivationState::Failed | ActivationState::Starting
                )
            }) {
                return Err(HostError::OwnerLeaseRecovery(
                    "durable Host activation is not in a recovery-capable state".to_owned(),
                ));
            }
        }
        Ok(())
    }

    /// Requires the live authority needed by a material Host operation.
    ///
    /// Observation and explicit recovery callers use
    /// [`Self::ensure_admission_open`] so a degraded activation can still be
    /// inspected or drained. Phase-B, cutover, restart, and backup operations
    /// use this stricter boundary and cannot reuse a stale live profile after
    /// supervision loss.
    fn ensure_material_admission_open(&self) -> Result<(), HostError> {
        self.ensure_material_admission_open_with_options(false)
    }

    fn ensure_material_admission_open_with_options(
        &self,
        allow_unrecorded_open_contour: bool,
    ) -> Result<(), HostError> {
        self.ensure_admission_open()?;
        #[cfg(windows)]
        {
            let state = self.journal.snapshot()?;
            let supervised = self.registry.active().is_some_and(|active| {
                active.manifest.runtime_launch.profile == InstallationProfile::SystemService
            });
            if state.activation.as_ref().is_some_and(|activation| {
                activation.state == ActivationState::Failed
                    || (supervised
                        && matches!(
                            activation.state,
                            ActivationState::Starting | ActivationState::DegradedRecovery
                        ))
            }) {
                return Err(HostError::OwnerLeaseRecovery(
                    "durable degraded Host activation blocks material admission".to_owned(),
                ));
            }
            if supervised
                && !allow_unrecorded_open_contour
                && state
                    .activation
                    .as_ref()
                    .is_some_and(|activation| activation.state == ActivationState::Active)
                && !self.jobs.has_recorded_contour()
            {
                return Err(HostError::OwnerLeaseRecovery(
                    "stale Active Host activation has no recorded process contour".to_owned(),
                ));
            }
        }
        Ok(())
    }

    /// Binds a Host material boundary to one exact approved generation.
    /// The active pointer is not sufficient evidence for a pending cutover or
    /// Phase-B continuation; the target must be present in the durable
    /// registry and any retained Phase-B overlay must name the same target.
    #[cfg(windows)]
    pub(crate) fn ensure_material_admission_open_for_target(
        &self,
        target: &PlatformHandle,
        allow_unrecorded_open_contour: bool,
    ) -> Result<(), HostError> {
        self.ensure_material_admission_open_with_options(allow_unrecorded_open_contour)?;
        let target_is_approved = self
            .registry
            .active()
            .is_some_and(|active| &active.manifest.generation == target)
            || self
                .registry
                .pending_activation()
                .is_some_and(|pending| &pending.manifest.generation == target)
            || self
                .registry
                .generations()
                .iter()
                .any(|entry| &entry.manifest.generation == target);
        if !target_is_approved {
            return Err(HostError::RecoveryRequired(
                "material target generation is not the exact approved registry target".to_owned(),
            ));
        }
        if let Some(phase_b) = self.phase_b.as_ref()
            && &phase_b.launch.generation != target
        {
            return Err(HostError::RecoveryRequired(
                "retained Phase-B materialization belongs to a different target generation"
                    .to_owned(),
            ));
        }
        Ok(())
    }

    /// Admits only the exact durable pending-activation continuation.  This
    /// is recovery of an already-approved target, never a fresh activation
    /// route and never a general bypass for a degraded Host.
    #[cfg(windows)]
    pub(crate) fn ensure_pending_activation_continuation_open(
        &self,
        pending: &eliot_installation::PendingActivation,
    ) -> Result<(), HostError> {
        self.ensure_admission_open()?;
        if self.registry.pending_activation() != Some(pending) {
            return Err(HostError::RecoveryRequired(
                "pending activation continuation is not the exact durable pending target"
                    .to_owned(),
            ));
        }
        if !matches!(
            pending.state,
            PendingActivationState::Pending | PendingActivationState::RecoveryRequired { .. }
        ) {
            return Err(HostError::RecoveryRequired(
                "pending activation continuation is not in a recoverable pending state".to_owned(),
            ));
        }
        let state = self.journal.snapshot()?.activation.ok_or_else(|| {
            HostError::OwnerLeaseRecovery("activation record is absent".to_owned())
        })?;
        // Only `Stopped` has a legal edge to the `Starting` transition that
        // `start_manifest_contour` will construct. The activation reducer has
        // no `Starting -> Starting` and no `DegradedRecovery -> Starting` edge,
        // so admitting those states here would accept a continuation that the
        // journal append then rejects, leaving the carrier stuck on the same
        // illegal transition. An unclean `Starting`/`DegradedRecovery` record
        // needs an explicit recovery contour, not a fresh pending start.
        if state.state != ActivationState::Stopped {
            return Err(HostError::OwnerLeaseRecovery(format!(
                "pending activation continuation requires a durable Stopped activation; current state is {:?}",
                state.state
            )));
        }
        Ok(())
    }

    /// Requests a bounded Host stop. SCM owns the sibling Watchdog and is not
    /// represented by either Host Job Object branch.
    ///
    /// # Errors
    ///
    /// Returns an error if the Host is already stopped or if process
    /// termination, durable shutdown finalization, or owner-lease release fails.
    #[allow(
        clippy::too_many_lines,
        reason = "the ordered durable drain, process termination, clean-marker commit, and lease-release sequence is one security-critical transaction"
    )]
    pub fn stop(&mut self) -> Result<(), HostError> {
        // F-LOG-HOST-1: stop/drain distinct. Requested vs Draining vs
        // StoppedClean are three durable records sharing one drain_generation
        // correlation; draining vs drained and requested vs stopped are never
        // merged. Cancellation requested stays distinct from stopped via the
        // labelled pair below. Single terminal via guard; inner terminates
        // are phase only.
        host_lifecycle_observe_drain(BOUNDARY_STOP_REQUESTED);
        let mut host_terminal = HostTerminalGuard::armed(BOUNDARY_STOP_TERMINAL);
        if !self.running {
            return Err(HostError::Stopped);
        }
        // F-LOG-HOST-1: cancellation requested versus stopped. A running
        // activation exists, so the SCM stop control now cancels it; the
        // labelled pair completes at `host.stop stopped` below.
        host_lifecycle_observe_drain(BOUNDARY_STOP_CANCELLATION_REQUESTED);
        #[cfg(windows)]
        if self.store_recovery_startup_fence.is_fenced() {
            self.readiness_gate.branch_degraded();
            self.shutdown_failed = true;
            return Err(HostError::RecoveryRequired(
                "crashed Store recovery remains Unknown; clean shutdown cannot erase its fence"
                    .to_owned(),
            ));
        }
        self.resume_pending_record()?;
        if !self.durable_finalized {
            let state = self.journal.snapshot()?;
            let activation = state.activation.clone().ok_or_else(|| {
                HostError::OwnerLeaseRecovery("activation record is absent".to_owned())
            })?;
            let mut degraded_recovery_stop = false;
            match activation.state {
                ActivationState::Stopped if activation.failure_and_recovery_directive.is_some() => {
                    degraded_recovery_stop = true;
                }
                ActivationState::Stopped => {}
                ActivationState::Active => {
                    let drain_generation = activation.fence.activation_generation.clone();
                    if state.drain.is_none() {
                        self.append_record(HostStateRecord::Drain(DrainRecord {
                            fence: activation.fence.clone(),
                            operation: operation("host-drain-request")?,
                            drain_generation: drain_generation.clone(),
                            state: DrainState::Requested,
                            evidence_refs: vec![
                                PlatformHandle::new("scm-stop-request")
                                    .map_err(|error| HostError::Platform(error.to_string()))?,
                            ],
                            expected_predecessor: None,
                        }))?;
                        // F-LOG-HOST-1: drain Requested is distinct from
                        // Draining; shares one drain_generation correlation.
                        host_lifecycle_observe_drain(BOUNDARY_DRAIN_REQUESTED);
                    }
                    if self
                        .journal
                        .snapshot()?
                        .drain
                        .as_ref()
                        .is_some_and(|drain| drain.state == DrainState::Requested)
                    {
                        self.append_record(HostStateRecord::Drain(DrainRecord {
                            fence: activation.fence.clone(),
                            operation: operation("host-drain-start")?,
                            drain_generation: drain_generation.clone(),
                            state: DrainState::Draining,
                            evidence_refs: vec![
                                PlatformHandle::new("host-admission-closed")
                                    .map_err(|error| HostError::Platform(error.to_string()))?,
                            ],
                            expected_predecessor: None,
                        }))?;
                        // F-LOG-HOST-1: Draining is distinct from Requested and
                        // from drained/StoppedClean; one correlation.
                        host_lifecycle_observe_drain(BOUNDARY_DRAIN_DRAINING);
                    }
                    if self
                        .journal
                        .snapshot()?
                        .activation
                        .as_ref()
                        .is_some_and(|current| current.state == ActivationState::Active)
                    {
                        self.transition_activation(ActivationState::Draining, "host-draining")?;
                    }
                    if self.journal.snapshot()?.drain_commit.is_none() {
                        // I14.23/I1.5: the commit carries the exact Kernel
                        // lease/receipt snapshot observed in the journal, so
                        // recovery can prove which authority was fenced. The
                        // snapshot rule is owned by the journal helper; an
                        // empty snapshot is admitted only when the journal
                        // proves nothing remains to fence.
                        let snapshot = self.journal.snapshot()?;
                        let commit = drain_commit_record_for_stop(
                            &snapshot,
                            &activation,
                            &drain_generation,
                        )?;
                        // F-LOG-HOST-1: drain commit is distinct from
                        // Requested/Draining; one drain_generation
                        // correlation.
                        host_lifecycle_observe_drain(BOUNDARY_DRAIN_COMMIT);
                        self.append_record(HostStateRecord::DrainCommit(commit))?;
                    }
                }
                ActivationState::Draining if state.drain_commit.is_some() => {}
                ActivationState::Draining => {
                    // I14.23/I1.5: this is the linearization point the ordered
                    // sequence still owes. The idle-drain prologue already
                    // appended `Draining`, so arriving here with
                    // `drain_commit == None` is the normal unlinearized
                    // pre-commit window, not an unusable activation: it is
                    // routed through the same `DrainCommit` append the
                    // `Active` arm uses, so there stays exactly one commit
                    // writer, one commit shape and one lease/receipt snapshot
                    // rule, and the reducer's own `Draining -> StoppedClean`
                    // edge further below is reused unchanged. The durable
                    // drain record supplies the exact `drain_generation` this
                    // commit correlates with; a `Draining` activation without
                    // one is a durable inconsistency and never a clean stop.
                    let drain = state.drain.as_ref().ok_or_else(|| {
                        HostError::OwnerLeaseRecovery(
                            "Host activation is Draining without a durable drain record".to_owned(),
                        )
                    })?;
                    let commit =
                        drain_commit_record_for_stop(&state, &activation, &drain.drain_generation)?;
                    // F-LOG-HOST-1: drain commit is distinct from
                    // Requested/Draining; one drain_generation correlation.
                    host_lifecycle_observe_drain(BOUNDARY_DRAIN_COMMIT);
                    self.append_record(HostStateRecord::DrainCommit(commit))?;
                }
                ActivationState::DegradedRecovery => {
                    // A degraded supervision record is a durable fence, not an
                    // excuse to fabricate a clean stop. Move through the
                    // model's legal Stopped edge, terminate known children, and
                    // return a recovery-required outcome below.
                    degraded_recovery_stop = true;
                    self.transition_activation(ActivationState::Stopped, "host-degraded-stop")?;
                }
                other => {
                    return Err(HostError::OwnerLeaseRecovery(format!(
                        "Host activation {other:?} cannot enter clean shutdown"
                    )));
                }
            }
            #[cfg(windows)]
            {
                let store = self.jobs.terminate_store();
                let kernel = self.jobs.terminate_kernel();
                if store.is_err() || kernel.is_err() {
                    self.shutdown_failed = true;
                    return Err(HostError::RecoveryRequired(format!(
                        "Store-first stop requires recovery: store={store:?}; kernel={kernel:?}"
                    )));
                }
            }
            if degraded_recovery_stop {
                // A degraded stop deliberately has no clean marker: the
                // journal owner would reject one because the contour is not
                // StoppedClean. Release the in-process owner only after the
                // durable Stopped record and known-child termination, then
                // leave the recovery directive for a new activation owner.
                if !self.owner_released {
                    if let Err(error) = self
                        .owner_lease
                        .release()
                        .map_err(owner_lease_release_error)
                    {
                        self.shutdown_failed = true;
                        return Err(error);
                    }
                    self.owner_released = true;
                }
                self.running = false;
                self.shutdown_failed = true;
                return Err(HostError::RecoveryRequired(
                    "Host stopped with a durable degraded-supervision directive; a new activation generation is required"
                        .to_owned(),
                ));
            }
            if self
                .journal
                .snapshot()?
                .activation
                .as_ref()
                .is_some_and(|current| current.state == ActivationState::Draining)
            {
                self.transition_activation(ActivationState::StoppedClean, "host-stopped-clean")?;
                // F-LOG-HOST-1: StoppedClean (drained) is distinct from
                // Draining and from requested/stopped.
                host_lifecycle_observe_drain(BOUNDARY_STOP_STOPPED_CLEAN_DRAINED);
            }
            #[cfg(windows)]
            cleanup_completed_store_recovery_supporting_evidence(
                self.launch_options.host_state_root(),
            )?;
            let state = self.journal.snapshot()?;
            let marker = clean_marker_record(
                &state,
                &self.host,
                &self.activation_id,
                &self.activation_generation,
            )?;
            self.append_record(marker)?;
            self.durable_finalized = true;
        }
        if !self.owner_released {
            if let Err(error) = self
                .owner_lease
                .release()
                .map_err(owner_lease_release_error)
            {
                self.shutdown_failed = true;
                return Err(error);
            }
            self.owner_released = true;
        }
        self.running = false;
        self.shutdown_failed = false;
        // F-LOG-HOST-1: stopped is distinct from requested/draining; the
        // single guard terminal stays armed only for failures.
        host_terminal.disarm();
        host_lifecycle_observe_drain(BOUNDARY_STOP_STOPPED);
        Ok(())
    }

    #[must_use]
    pub const fn running(&self) -> bool {
        self.running
    }

    /// Returns whether a prior shutdown attempt recorded a release/recovery
    /// failure. A stopped composition with this flag is not a clean success.
    #[must_use]
    pub const fn shutdown_failed(&self) -> bool {
        self.shutdown_failed
    }

    #[cfg(windows)]
    /// Returns the physical Host job branches for service composition.
    #[must_use]
    #[allow(dead_code)]
    pub(crate) const fn jobs(&self) -> &HostJobBranches {
        &self.jobs
    }
}

#[cfg(windows)]
impl ApprovedHostStartupPort for HostComposition {
    fn start_approved_manifest(
        &mut self,
        manifest: &CandidateManifest,
        branch: HostStartupBranch,
        kernel_executable: &Path,
        store_bridge_executable: &Path,
        store_artifact: &PlatformHandle,
        pending: Option<&eliot_installation::PendingActivation>,
    ) -> Result<(), HostError> {
        debug_assert_eq!(
            matches!(branch, HostStartupBranch::Pending),
            pending.is_some()
        );
        self.start_manifest_contour(
            manifest,
            kernel_executable,
            store_bridge_executable,
            store_artifact,
            pending,
        )
    }
}

#[cfg(windows)]
fn lifecycle_context(
    host: &HostInstallationEpoch,
    operation: &str,
) -> Result<RequestMetadata, HostError> {
    // F-LOG-HOST-1: lifecycle identity projection only; preserves exact
    // installation/process/start/generation/operation identities already
    // produced by the owner. `operation` is a static caller literal, never
    // SCM payload/env/credentials. Single terminal via manual observe: the
    // guard cannot wrap this free function without changing its signature.
    host_lifecycle_observe_requested(BOUNDARY_LIFECYCLE_CONTEXT_REQUESTED);
    let request_id = RequestId::new(format!(
        "host:{}:{}:{}:{}",
        host.epoch.current.lineage_id,
        host.epoch.current.sequence,
        operation,
        std::process::id()
    ))
    .map_err(|error| {
        host_lifecycle_observe_terminal(BOUNDARY_LIFECYCLE_CONTEXT_TERMINAL);
        HostError::Platform(error.to_string())
    })?;
    let context = RequestMetadata {
        request_id,
        session_id: None,
        task_id: None,
        product_id: ProductId::new("eliot-host").map_err(|error| {
            host_lifecycle_observe_terminal(BOUNDARY_LIFECYCLE_CONTEXT_TERMINAL);
            HostError::Platform(error.to_string())
        })?,
        source_id: SourceId::new("eliot-host-service").map_err(|error| {
            host_lifecycle_observe_terminal(BOUNDARY_LIFECYCLE_CONTEXT_TERMINAL);
            HostError::Platform(error.to_string())
        })?,
        state_fence: StateFence::new(host.epoch.current.clone(), ResourceGeneration::genesis()),
        clock: ClockReading::default(),
    };
    host_lifecycle_observe_requested(BOUNDARY_LIFECYCLE_CONTEXT_ADMITTED);
    Ok(context)
}

fn owner_lease_error(error: HostOwnerLeaseError) -> HostError {
    match error {
        HostOwnerLeaseError::LiveOwner => HostError::OwnerLeaseHeld,
        HostOwnerLeaseError::ExistingObject => HostError::OwnerLeaseRecovery(
            "a pre-existing Host owner object is untrusted; explicit recovery is required"
                .to_owned(),
        ),
        HostOwnerLeaseError::AbandonedOwner => HostError::OwnerLeaseRecovery(
            "the previous Host owner abandoned its mutex; inspect durable shutdown state before retrying"
                .to_owned(),
        ),
        HostOwnerLeaseError::OwnershipUncertain { win32_error } => HostError::OwnerLeaseRecovery(
            format!("Windows could not classify the owner mutex (Win32 error {win32_error})"),
        ),
        HostOwnerLeaseError::CreationFailed { win32_error } => HostError::Platform(format!(
            "Host owner mutex could not be created or opened (Win32 error {win32_error})"
        )),
        HostOwnerLeaseError::UnsupportedPlatform => HostError::Platform(
            "Host owner lease is unavailable on this platform; refusing Host admission".to_owned(),
        ),
    }
}

fn owner_lease_release_error(error: HostOwnerLeaseReleaseError) -> HostError {
    HostError::OwnerLeaseRecovery(format!(
        "owner release failed; durable recovery remains required: {error}"
    ))
}

#[cfg(test)]
fn test_provisioned_supervision_authority(
    installation_id: &str,
    candidate_generation: &str,
    authority_generation: ResourceGeneration,
) -> ProvisionedSupervisionAuthority {
    let signer = eliot_runtime_contracts::Ed25519SupervisionLeaseSigner::from_secret_key(
        "eliot-kernel",
        "test-supervision-key",
        [0x39; 32],
    )
    .unwrap_or_else(|_| unreachable!());
    let trust_anchor = eliot_runtime_contracts::SupervisionTrustAnchor::new(
        installation_id,
        "eliot-kernel",
        "test-supervision-key",
        signer.public_key().to_vec(),
    )
    .unwrap_or_else(|_| unreachable!());
    let key_reference = eliot_runtime_contracts::SupervisionSealedKeyReference::new(
        "test-supervision-authority.sealed",
        "S-1-5-80-1-2-3-4-5",
        eliot_runtime_contracts::SupervisionSealedKeyFileIdentity {
            canonical_path_digest: "1".repeat(64),
            volume_serial_number: 7,
            file_index: 11,
            security_descriptor_digest: "2".repeat(64),
        },
        "3".repeat(64),
    )
    .unwrap_or_else(|_| unreachable!());
    ProvisionedSupervisionAuthority::new(
        "test-supervision-scope",
        candidate_generation,
        authority_generation,
        key_reference,
        trust_anchor,
    )
    .unwrap_or_else(|_| unreachable!())
}

#[cfg(all(test, windows))]
mod watchdog_service_tests;

#[cfg(test)]
mod journal_tests;

#[cfg(all(test, windows))]
mod tests;

impl From<io::Error> for HostError {
    fn from(error: io::Error) -> Self {
        Self::Platform(error.to_string())
    }
}
