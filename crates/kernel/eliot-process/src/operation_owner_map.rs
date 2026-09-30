//! Frozen operation-to-owner map for process control (issue #1775, item W1-map).
//!
//! This module freezes the actual operation-to-owner map the issue demands:
//! every lifecycle operation that can start, reconnect, stop, mutate, adopt,
//! or attach a credential to a process is traced through its real
//! Host/Kernel/Store adapter callers, and each row records the admitted
//! target, the physical observation, the challenge/owner-token proof, the
//! current authority check, the effect primitive, and the reconciliation
//! receipt, plus the production caller that performs it.
//!
//! Normative sources (read before editing; code bows to them on conflict):
//!
//! - I3.3 (installation survey): an unrelated compatible process is an
//!   observation/import candidate, never an implicit installation member.
//!   Setup never kills, adopts, or reuses one merely because its port or
//!   binary name matches.
//! - I3.4 (process origin, capability challenge and readiness evidence):
//!   `ProcessOriginEvidence` is evidence, never authority; kill, mutation,
//!   adoption, or credential attachment additionally requires a current
//!   ownership-challenge receipt binding installation identity, process start
//!   identity, generation/epoch, and a non-reusable nonce or owner-token
//!   challenge. Port occupancy, executable family, PID files, or path
//!   similarity alone can never authorize control.
//! - I3.15 (installation and update transaction): Host owns
//!   activation/recovery once its `HostInstallationEpoch` is established; the
//!   transaction never adopts an unknown process and never reconstructs
//!   approval from paths/PIDs.
//! - I7.20 (agent-facing error contract): collisions and unproven ownership
//!   surface as typed recovery directives (`PROCESS_OWNERSHIP_UNPROVEN`,
//!   `STALE_STATE_FENCE`, `CANCELLATION_UNCONFIRMED`), never as silent
//!   success or destructive cleanup by name.
//!
//! What this module is not:
//!
//! - It mints nothing, checks nothing at runtime, and authorizes nothing.
//!   Every query here is a frozen registry lookup over string literals that a
//!   verifier can confirm with `grep`. Authority lives only in the cited
//!   symbols (`OriginChallengeAuthority::decide`, the gateway effect
//!   boundary, the Host retained-branch owners).
//! - It is not the refuted predecessor. The earlier W1-map claim rested on
//!   `bins/eliotd/src/activation_projection.rs::revalidate_owner_map_against_outcome`,
//!   which compares a Governor agent-activation builder's own output against
//!   its own input flag and names no Store endpoint, retained launch
//!   descriptor, physical binding, challenge, grant, gateway, cancellation,
//!   or reconciliation. That function is untouched by this module and must
//!   not be cited as this map.
//! - Read-only status is disjoint by construction and has no row here:
//!   `ProcessControlOperation::ReadStatus`/`ProbeObserve` resolve to
//!   `Observed` in `gate_process_control` and are unrepresentable as an
//!   `OriginControlOperation` (`NotAControlOperation`), so no status receipt
//!   can convert into a control request.
//!
//! Blocked rows (`OwnerAdmission::Blocked`) are concrete code gaps recorded
//! honestly: the dispatch gate refuses those classes before any gateway or
//! executor entry, and no production caller is admitted. A missing required
//! caller check is a gap, never permission to assert the path is absent.

use super::OriginControlOperation;

/// How the owner behind one map row is admitted.
///
/// Exactly one variant applies per row. `Blocked` rows name the refusing
/// symbol in [`OperationOwnerRecord::gap`]; they carry no caller.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum OwnerAdmission {
    /// A current Kernel-issued [`OriginControlGrant`](super::OriginControlGrant)
    /// for exactly the row's operation, decided by the Kernel-owned
    /// authority and rechecked at the effect boundary.
    ChallengeGrant,
    /// A retained Host-owned Job branch (outer kill domain) the Host itself
    /// created and still holds. Pre-Kernel Host authority by design: Host
    /// start/cleanup must not depend on a running Kernel.
    RetainedHostBranch,
    /// The admitted suspended-launch proof for a child with no start
    /// identity yet: approved artifacts/digests/leases, suspended spawn,
    /// exact image identity before resume, and post-launch Job-membership
    /// plus liveness observation.
    BootstrappedLaunch,
    /// No admitted production caller. The row records the concrete refusal
    /// instead of coverage.
    Blocked,
}

/// One frozen operation-to-owner record.
///
/// Every `&'static str` field names exact `path.rs::Symbol` identities a
/// verifier can confirm by reading the tree. `gap` is empty unless
/// `admission` is [`OwnerAdmission::Blocked`].
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct OperationOwnerRecord {
    /// Which of the six issue lifecycle operations this row covers.
    /// `stop/cancel` has two rows: the challenge-grant Kill path and the
    /// retained-handle Host termination path.
    pub lifecycle: &'static str,
    /// The challenge operation class, or `None` for the pre-challenge Host
    /// bootstrap/recovery rows that precede any control class.
    pub operation: Option<OriginControlOperation>,
    /// The exact target admitted for this operation.
    pub admitted_target: &'static str,
    /// The neutral physical observation (never authority by itself).
    pub physical_observation: &'static str,
    /// The challenge/owner-token proof the caller must carry.
    pub proof: &'static str,
    /// The current authority check evaluated before the effect.
    pub authority_check: &'static str,
    /// The primitive that performs the physical effect.
    pub effect_primitive: &'static str,
    /// The durable receipt the caller reconciles afterwards.
    pub reconciliation_receipt: &'static str,
    /// Production callers, `"; "`-separated, or `"none admitted"`.
    pub production_caller: &'static str,
    /// How the owner behind this row is admitted.
    pub admission: OwnerAdmission,
    /// Concrete gap description; empty unless blocked.
    pub gap: &'static str,
}

/// Fresh Store launch through the approved Host contour.
///
/// The child has no start identity before creation, so no challenge can be
/// demanded of it: admission is the suspended-launch proof itself, and the
/// endpoint preflight only classifies what it saw.
pub static FRESH_STORE_LAUNCH_ROW: OperationOwnerRecord = OperationOwnerRecord {
    lifecycle: "fresh Store launch",
    operation: None,
    admitted_target: "planned Store loopback endpoint plus data-root binding from RuntimeLaunchDescriptor::canonical_store_arguments; unborn child with no start identity yet",
    physical_observation: "bins/eliot-host/src/host_job_launch.rs::store_endpoint_foreign_occupant (read-only Occupied/Absent/Unreadable loopback-listener observation) via ::ensure_store_endpoint_available (FreshDependencyStart posture); listener PID is observation only",
    proof: "admitted suspended-launch proof: bins/eliot-host/src/host_job_launch.rs::HostJobBranches::launch (SuspendedJobChild spawn plus validate plus resume) over the approved executable, digest, lease, and config bindings checked by ::HostJobBranches::start_approved",
    authority_check: "start_approved contour gates (already-running refusal, phase-B live, approved locator plus digest verification) and post-launch Job-membership plus observe() liveness closure",
    effect_primitive: "bins/eliot-host/src/store_kernel_launch_sequence.rs::launch_store_then_kernel (Store first, then Kernel readiness)",
    reconciliation_receipt: "retained Host-owned Job branch (RunningJobChild::evidence) plus bins/eliot-host/src/store_kernel_launch_sequence.rs::StoreLivenessEvidence plus host.launch lifecycle observations",
    production_caller: "bins/eliot-host/src/lib.rs::cutover_with_rollback; bins/eliot-host/src/lib.rs::start_manifest_contour; bins/eliot-host/src/lib.rs::cutover_generation_contour",
    admission: OwnerAdmission::BootstrappedLaunch,
    gap: "",
};

/// Owned reconnect of a proven retained Store child.
///
/// Only a caller that proved the old child's Job membership and committed
/// predecessor binding may pass its PID; any other occupant produces the
/// typed collision directive and an unreadable owner defers.
pub static OWNED_RECONNECT_ROW: OperationOwnerRecord = OperationOwnerRecord {
    lifecycle: "owned reconnect",
    operation: None,
    admitted_target: "retained old Store child PID plus the planned endpoint it may still own",
    physical_observation: "bins/eliot-host/src/host_job_launch.rs::ensure_store_endpoint_available_or_owned with Some(retained_pid) (OwnedReconnect posture); occupant PID compared against the retained PID; degenerate PID-0 claims and corrupt PID-0 observations fail closed",
    proof: "retained-child proof: exact PID/start/image validity plus Job containment (job_processes) plus committed predecessor binding (require_committed_predecessor_store_bind); zero PID/start/image refused before calling",
    authority_check: "same retained proof set re-checked at relaunch; endpoint must be free or self-owned before termination destroys evidence",
    effect_primitive: "crates/kernel/eliot-platform-windows/src/process_job.rs::terminate_in_place(0xE017_0002) of the proven old child, then relaunch_store on the retained approved bindings",
    reconciliation_receipt: "committed StoreRebind journal record plus retained new-child evidence plus the store_restart_attempts counter",
    production_caller: "bins/eliot-host/src/host_composition_store_recovery.rs::execute_store_recovery",
    admission: OwnerAdmission::RetainedHostBranch,
    gap: "",
};

/// Stop/cancel of a Kernel-managed process under a current Kill grant.
///
/// The only challenge-grant control path with an admitted production caller:
/// packaging is completeness-only, issuance/decision stay Kernel-owned, and
/// the effect boundary rechecks target then currency against the live
/// contour and clock.
pub static CHALLENGE_KILL_ROW: OperationOwnerRecord = OperationOwnerRecord {
    lifecycle: "stop/cancel (challenge grant)",
    operation: Some(OriginControlOperation::Kill),
    admitted_target: "Kernel-managed operation_id plus the retained start-receipt identity held for the same object at the boundary",
    physical_observation: "bins/eliot-kernel/src/process_execution.rs::ProcessExecutionGateway::inspect plus bins/eliot-kernel/src/daemon_request_dispatch.rs::validate_origin_inspection (Running lifecycle, same authority, generation, and physical identity)",
    proof: "Kernel-issued OriginControlGrant for Kill via OriginControlPresentation, decided by bins/eliot-kernel/src/process_execution.rs::ProcessExecutionGateway::decide_origin_control; packaged (never minted) by bins/eliotd/src/process_origin.rs::request_origin_control",
    authority_check: "bins/eliot-kernel/src/daemon_request_dispatch.rs::validate_origin_control_operation (Kill-only) plus validate_origin_session_fence plus material admission, then ProcessExecutionGateway::authorize_effect_with_grant (OriginControlGrant::binds_target_for_operation, then ::binds_effect_currency against live epoch lineage, sequence, and clock)",
    effect_primitive: "executor.cancel via ProcessExecutionGateway::cancel_with_origin_grant_inner (Kill-only guard in ::cancel_with_origin_grant)",
    reconciliation_receipt: "CancellationReceipt plus descendant-closure receipt (ProcessExecutionGateway::close_registered_descendant) plus ProcessExecutionGateway::reconcile to ProcessEvidence under authorize_operation",
    production_caller: "bins/eliot-kernel/src/daemon_request_dispatch.rs::origin_control_decide_operation",
    admission: OwnerAdmission::ChallengeGrant,
    gap: "",
};

/// Stop/cancel of a Host-owned branch through its retained Job handle.
///
/// Covers rollback, shutdown, and the hung-child case: a hung managed child
/// need not answer a newly invented challenge protocol when the accepted
/// retained-handle contract already provides fresh proof, and Host cleanup
/// must never wait on a running Kernel.
pub static HOST_TERMINATE_ROW: OperationOwnerRecord = OperationOwnerRecord {
    lifecycle: "stop/cancel (retained Host branch)",
    operation: None,
    admitted_target: "retained self.store / self.kernel Host-owned Job branch (outer kill domain)",
    physical_observation: "retained RunningJobChild::evidence().process(), with exact Job-membership proof (job_processes) in the recovery variant before termination",
    proof: "retained Host-owned outer kill-domain Job handle: pre-Kernel Host authority, no challenge demanded and none accepted from names, PIDs, or listener ports",
    authority_check: "branch presence (if let Some) plus BOUNDARY_*_TERMINATE drain phases; recovery variant additionally requires the committed predecessor binding before termination",
    effect_primitive: "crates/kernel/eliot-platform-windows/src/process_job.rs::terminate_in_place (0xE017_0001 Kernel, 0xE017_0002 Store)",
    reconciliation_receipt: "host_lifecycle_observe_drain(BOUNDARY_*_TERMINATE_STOPPED) plus branch take; recovery variant keeps the committed StoreRebind record",
    production_caller: "bins/eliot-host/src/lib.rs::terminate_kernel; bins/eliot-host/src/lib.rs::terminate_store; bins/eliot-host/src/lib.rs::terminate_store_then_kernel; bins/eliot-host/src/host_composition_store_recovery.rs::execute_store_recovery",
    admission: OwnerAdmission::RetainedHostBranch,
    gap: "",
};

/// Mutation: refused before any gateway or executor entry.
///
/// Packaging forwards `Mutate`, but the dispatch gate admits Kill only, so
/// no production caller can carry a mutation grant to an effect.
pub static MUTATE_BLOCKED_ROW: OperationOwnerRecord = OperationOwnerRecord {
    lifecycle: "mutation",
    operation: Some(OriginControlOperation::Mutate),
    admitted_target: "none admitted",
    physical_observation: "packaging binds PhysicalProcessBinding via bins/eliotd/src/process_origin.rs::request_origin_control, but no caller may proceed past dispatch",
    proof: "none admitted",
    authority_check: "bins/eliot-kernel/src/daemon_request_dispatch.rs::validate_origin_control_operation rejects every non-Kill class with SessionFenced before gateway and executor entry (pinned by the refusal assertion beside it)",
    effect_primitive: "none: refused before executor entry",
    reconciliation_receipt: "none",
    production_caller: "none admitted",
    admission: OwnerAdmission::Blocked,
    gap: "concrete gap: Mutate has packaging but no admitted production caller; any future caller must pass a Kill-style front-door gate, per-operation grant binding, and effect-boundary recheck before an effect primitive is named here",
};

/// Explicit adoption/import: refused before any gateway or executor entry.
///
/// Per I3.3 a foreign process stays an observation/import candidate; there
/// is no admitted adoption caller, and the collision path authorizes no
/// adoption, reuse, or automatic migration.
pub static ADOPT_BLOCKED_ROW: OperationOwnerRecord = OperationOwnerRecord {
    lifecycle: "explicit adoption/import",
    operation: Some(OriginControlOperation::Adopt),
    admitted_target: "none admitted",
    physical_observation: "packaging binds PhysicalProcessBinding via bins/eliotd/src/process_origin.rs::request_origin_control, but no caller may proceed past dispatch; endpoint observations stay observations",
    proof: "none admitted",
    authority_check: "bins/eliot-kernel/src/daemon_request_dispatch.rs::validate_origin_control_operation rejects every non-Kill class with SessionFenced before gateway and executor entry (pinned by the refusal assertion beside it)",
    effect_primitive: "none: refused before executor entry",
    reconciliation_receipt: "none",
    production_caller: "none admitted",
    admission: OwnerAdmission::Blocked,
    gap: "concrete gap: Adopt has packaging but no admitted production caller; explicit legacy inspection/import remains read-only until a separately admitted migration/ownership transition exists, and any future caller must satisfy the same per-operation gate, binding, and recheck as the Kill path before an effect primitive is named here",
};

/// Credential attachment: refused before any gateway or executor entry.
///
/// The packaging function forwards `AttachCredential` yet has no non-test
/// caller (only the `eliotd` re-export), and the dispatch gate admits Kill
/// only, so no reusable credential can reach an unidentified listener
/// through an admitted caller. The Host collision path likewise authorizes
/// no credential attachment.
pub static ATTACH_CREDENTIAL_BLOCKED_ROW: OperationOwnerRecord = OperationOwnerRecord {
    lifecycle: "credential attachment",
    operation: Some(OriginControlOperation::AttachCredential),
    admitted_target: "none admitted",
    physical_observation: "no admitted connection binding exists: the endpoint preflight (bins/eliot-host/src/host_job_launch.rs::ensure_store_endpoint_available_or_owned) proves no socket identity and its directive authorizes no credential attachment",
    proof: "none admitted",
    authority_check: "bins/eliot-kernel/src/daemon_request_dispatch.rs::validate_origin_control_operation rejects every non-Kill class with SessionFenced before gateway and executor entry (pinned by the refusal assertion beside it)",
    effect_primitive: "none: refused before executor entry",
    reconciliation_receipt: "none",
    production_caller: "none admitted",
    admission: OwnerAdmission::Blocked,
    gap: "concrete gap: AttachCredential has packaging (bins/eliotd/src/process_origin.rs::request_origin_control, re-exported by bins/eliotd/src/lib.rs) but zero non-test callers and no admitted dispatch path; binding an actual connection plus retained process identity through the transport/platform mechanism, or an explicit refusal when that proof is unavailable, is implementation work still open",
};

/// The frozen table in lifecycle order. Its order and length are frozen:
/// review any diff to this table as a policy change, not a refactor.
pub static FROZEN_OPERATION_OWNER_MAP: &[OperationOwnerRecord; 7] = &[
    FRESH_STORE_LAUNCH_ROW,
    OWNED_RECONNECT_ROW,
    CHALLENGE_KILL_ROW,
    HOST_TERMINATE_ROW,
    MUTATE_BLOCKED_ROW,
    ADOPT_BLOCKED_ROW,
    ATTACH_CREDENTIAL_BLOCKED_ROW,
];

/// Returns the frozen table in lifecycle order.
#[must_use]
pub fn frozen_operation_owner_map() -> &'static [OperationOwnerRecord] {
    FROZEN_OPERATION_OWNER_MAP
}

/// Returns the frozen row for one challenge operation class.
///
/// The match is exhaustive over [`OriginControlOperation`]: adding a control
/// class fails compilation here until its owner row is frozen, which is the
/// freeze guarantee. This maps a class to its documented row; it grants
/// nothing and checks no proof.
#[must_use]
pub fn owner_record_for(operation: OriginControlOperation) -> &'static OperationOwnerRecord {
    match operation {
        OriginControlOperation::Kill => &FROZEN_OPERATION_OWNER_MAP[2],
        OriginControlOperation::Mutate => &FROZEN_OPERATION_OWNER_MAP[4],
        OriginControlOperation::Adopt => &FROZEN_OPERATION_OWNER_MAP[5],
        OriginControlOperation::AttachCredential => &FROZEN_OPERATION_OWNER_MAP[6],
    }
}

/// Returns the two pre-challenge Host bootstrap rows: fresh launch first,
/// owned reconnect second.
#[must_use]
pub fn bootstrap_rows() -> [&'static OperationOwnerRecord; 2] {
    [
        &FROZEN_OPERATION_OWNER_MAP[0],
        &FROZEN_OPERATION_OWNER_MAP[1],
    ]
}

/// Returns the only challenge classes with an admitted production caller.
///
/// Today exactly [`OriginControlOperation::Kill`] is admitted; every other
/// class maps to a blocked row. Any admission change must land in this
/// table first.
#[must_use]
pub const fn admitted_challenge_operations() -> [OriginControlOperation; 1] {
    [OriginControlOperation::Kill]
}

/// Reports whether a `path.rs::Symbol` caller string is documented in the
/// frozen table.
///
/// This is a registry lookup for verifiers (exact match against the
/// `"; "`-separated [`OperationOwnerRecord::production_caller`] entries),
/// never an authorization decision: presence in this table proves a caller
/// was reviewed, not that any proof it carries is current.
#[must_use]
pub fn is_documented_production_caller(caller: &str) -> bool {
    FROZEN_OPERATION_OWNER_MAP
        .iter()
        .flat_map(|row| row.production_caller.split("; "))
        .any(|documented| documented == caller)
}
