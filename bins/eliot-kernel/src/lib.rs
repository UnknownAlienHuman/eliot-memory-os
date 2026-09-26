//! The Kernel composition root — ARCH-MOD-01 (A13.2/A13.3; I6.4-I6.5/I7.1-I7.5/I7.14).
//!
//! Kernel owns process lifetime and selects one concrete transport boundary.
//! It does not duplicate protocol, platform, or task-runtime policy: those
//! contracts are supplied by the lower-layer packages and are assembled here
//! exactly once.
//!
//! Architecture: ARCH-MOD-01, A13.2, A13.3, A8.1, ARCH-WDG-01, ARCH-RES-01, ARCH-RES-04
//! Implementation: I6.4, I6.5, I7.1, I7.2, I7.3, I7.4, I7.5, I7.14, I1.4, I1.5, I2.2, I2.23, I8.1, I8.2, I8.3, I8.4, I14.10, I14.15
//! Neutral Kernel admission/transport only; no Governor semantics, Store SDK, or default success.
//! Forbidden authority: no semantic oracle, alternate lease authority, unbounded restart, or daemon-owned canonical transition.
//!
//! Capability cells (§15 req.1; I01-02; #13 thin bridge surface):
//! cell 1 front-door/IPC admission — `agent_bridge`, `front_door_listener`,
//!   `front_door_session`, `frame_dispatch` (+6), `host_request_route` (+6),
//!   `daemon_session_guard` (+2), `runtime_identity` (+8);
//! cell 2 epochs/fencing/leases — `supervision_lease_authority`,
//!   `daemon_session_guard` (+1), `daemon_supervision` (+8);
//! cell 3 ORS/generation state — `generation_recovery` (+5);
//! cell 4 control reserve/lifecycle gateway — `control_plane` (+6);
//! cell 5 generation routing — `generation_control`, `generation_recovery` (+3);
//! cell 6 daemon/store-rebind dispatch — `daemon_request_dispatch` (+7),
//!   `store_receipt_dispatch`, `control_plane` (+4), `frame_dispatch` (+1),
//!   `host_request_route` (+1);
//! cell 7 health/readiness view — `health_view`, `daemon_request_dispatch` (+6),
//!   plus the I1.13 Kernel-unavailability admission guard and restricted
//!   Recovery View (`kernel_unavailability`);
//! cell 8 process/daemon/store runtime — `process_execution`,
//!   `process_execution_client`, `daemon_runtime`, `daemon_process_launch`,
//!   `daemon_live_receipt`, `daemon_supervision` (+2), `runtime_identity` (+1),
//!   `canonical_store_runtime`;
//! ROOT composition/entry — this `lib` (`KernelComposition`), the
//!   `eliot-kernel` binary `main` plus `startup_binding` and
//!   `front_door_driver`, `composition_bootstrap`, `kernel_build_contract`,
//!   `kernel_config`;
//! debt/out-of-scope for #15 — `r13_os_harness`, `r13_two_token_harness`,
//!   `tests`, `tests/`; agent-bridge admission honors the #13 thin-surface
//!   boundary, and process ownership follows I01-02.

#![forbid(unsafe_code)]

#[cfg(windows)]
mod agent_bridge;
mod backup_capture;
mod backup_capture_ports;
mod backup_restore;
mod backup_restore_ports;
mod blob_store_controller;
mod canonical_store_runtime;
mod composition_bootstrap;
mod control_plane;
mod kernel_build_contract;
mod kernel_config;
/// Kernel structured diagnostics facade (F-LOG-KERNEL-0, #895): compiled
/// once here and imported by the binary; later leaves extend through their
/// own serialized turns, never a second copy.
pub mod kernel_diagnostics;
mod process_execution;
mod process_execution_client;
mod supervision_lease_authority;
mod testd_terminal_completion_route;

/// Public wire-operation name for the authenticated `TestD` completion route.
pub use testd_terminal_completion_route::OPERATION as TESTD_TERMINAL_COMPLETION_OPERATION;

pub use backup_capture::{
    ArchivedFenceRelation, CaptureEvidenceLevel, CaptureReport, CaptureRequest, CaptureState,
    KernelBackupCapture, request_from_ports,
};
pub use backup_capture_ports::{
    CaptureBudgets, CaptureCallerAuth, CapturePorts, FrozenCapturePlan, KernelCaptureError,
    PublicationPort, PublicationReceipt, PublishedArchive, SnapshotRelation,
    require_capture_admitted,
};
pub use backup_restore::{
    BlobOwnerClient, CanonicalOwnerClient, CutoverQualification, InvalidationKind,
    InvalidationOwnerClient, KernelBackupRestore, KernelRestoreOutcome, OrsOwnerClient,
    PurgeOwnerClient, phase_owner,
};
pub use backup_restore_ports::{
    DESTINATION_ADMISSION_FILE, DestinationManifestEvidence, KernelIsolatedDestination,
    KernelRestoreError, MAX_DESTINATION_LABEL_LEN, OrsRestoreBinding, OrsRestoreJournal,
    PinnedDestinationAdmission, RESTORE_EVIDENCE_FILE, RESTORE_ISOLATED_AREA,
    RESTORE_JOURNAL_IDENTITY, RESTORE_JOURNAL_OWNER_LABEL, RESTORE_JOURNAL_PAYLOAD_AREA,
    RestorePorts, backup_to_kernel, check_kernel_effect_fence, kernel_to_backup, ors_to_backup,
    require_production_admitted,
};
pub use blob_store_controller::{
    BLOB_INLINE_THRESHOLD_DEFAULT_BYTES, BLOB_INLINE_THRESHOLD_MAX_BYTES,
    BLOB_MANIFEST_FORMAT_VERSION, BlobCaptureOutcome, BlobDemand, BlobProbeStatus,
    BlobProbeSuccess, BlobReadyReceipt, BlobRef, BlobStoreController, BlobStoreManifest,
};
pub(crate) use kernel_build_contract::PreparedAuthorityMaterial;
#[cfg(windows)]
pub use kernel_build_contract::SupervisionLeaseAuthorityConfig;
pub use kernel_build_contract::{
    AuthorityDescriptorContour, AuthorityPreparationError, EliotdReceiptRootBinding,
    KernelBuildError,
};
pub use kernel_config::KernelConfig;
pub(crate) use process_execution::{
    CanonicalStoreAttachmentTransaction, KernelPathAdmission, ProcessExecutionGateway,
    ProcessPathProof,
};
pub use process_execution::{ProcessExecutionAuthorityConfig, WindowsDispatchSnapshotCodec};
#[cfg(test)]
use process_execution::{
    ProcessStartGuard, ProcessStartPorts, RESERVED_STORE_SNAPSHOT_HEAD, ValidationContextSlot,
    authorize_process_owner, project_store_snapshot, run_process_start,
};
pub use process_execution_client::process_execution_client;
pub(crate) use shutdown_drain::{
    DRAIN_RECEIPT_DEADLINE, DrainCommitDecision, DrainHalt, DrainWakeDisposition, ShutdownPhase,
    ShutdownTerminal, coordinator_for, reverse_quiescence_order,
};
/// Kernel-owned exact-fence lease census for the I1.5 idle-drain gate.
mod idle_lease_census;
pub(crate) use idle_lease_census::KernelIdleLeaseCensus;
pub(crate) use startup_coordinator::StartupCoordinator;
pub use startup_coordinator::{
    AuthorityCeiling, GovernanceEnforcement, GovernanceObservation, GovernanceProfile,
    GovernanceSupervision, STARTUP_FINAL_STEP, STARTUP_FIRST_STEP, StartupPrerequisite,
    StartupRejection, StartupStatus, startup_step_name,
};
#[cfg(windows)]
pub use supervision_lease_authority::{
    KernelSupervisionLeaseAuthority, ProtectedSupervisionLeaseSigner,
    SupervisionLeaseAuthorityError,
};
#[cfg(windows)]
use supervision_lease_authority::{
    SupervisionProgressRenewalError, daemon_renewal_receipt_for_decision,
    daemon_supervision_current_state, supervision_binding_matches_contour,
    supervision_operation_identity,
};
#[cfg(all(test, windows))]
pub(crate) use supervision_lease_authority::{
    supervision_authority_root_spec, verification_context_for_supervision_payload,
    verify_superseded_supervision_replay,
};

#[cfg(test)]
use eliot_kernel_core::{
    AuthoritySnapshotBindingWire, ProcessExecutionReplayAbort, ProcessExecutionReplayBegin,
    ProcessExecutionReplayRecord, ProcessExecutionReplayState, process_admission_digest,
};

mod daemon_live_receipt;
#[cfg(windows)]
mod daemon_process_launch;
mod daemon_request_dispatch;
mod daemon_runtime;
mod daemon_session_guard;
mod daemon_supervision;
mod dispatch_launch;
mod doctor_recovery_ledger;
mod dreamer_job_dispatch;
mod frame_dispatch;
mod front_door_listener;
mod front_door_session;
mod generation_control;
mod generation_recovery;
mod health_view;
pub use health_view::KernelActivationView;
#[cfg(windows)]
mod host_request_route;
pub mod kernel_unavailability;
mod native_worker_lifecycle_route;
mod native_worker_reconcile_route;
mod native_worker_replay_route;
pub mod notify_operation_identity;
mod provider_capability_route;
pub mod reactive_restore_serve;
mod request_dispatch;
mod research_provider_route;
mod runtime_identity;
mod shutdown_drain;
mod startup_coordinator;
mod wasm_runtime_port_grant;
use daemon_session_guard::caller_binding;
#[cfg(all(windows, test))]
use daemon_supervision::EliotdSupervisionSuccessorEvidence;
use daemon_supervision::{DaemonRuntimeState, DaemonRuntimeStatus, daemon_status_proves_ready};
#[cfg(windows)]
use daemon_supervision::{
    DaemonSupervisionContour, DaemonSupervisionProgressState, EliotdLiveReceiptDisposition,
    classify_eliotd_live_receipt_transition,
};
use generation_recovery::OrsGenerationCoordinator;
#[cfg(test)]
use generation_recovery::update_handshake_policy;
#[cfg(windows)]
use host_request_route::HostRequestOperationRef;
#[cfg(windows)]
use host_request_route::WATCHDOG_INTENT_SUBMIT_OPERATION;
use runtime_identity::stable_owner_principal_digest;
#[cfg(windows)]
use runtime_identity::{
    eliotd_launch_attempt_identity, eliotd_operation_id, fresh_eliotd_launch_descriptor,
    observed_session_principal_binding,
};

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;

/// DISPATCH-CONTOUR-2 Slice B launch contour (issues #461 and #22).
///
/// The composed dispatch owner plus admit-then-launch through the admitted
/// process executor, parameterized once for the Doctor, testd, and
/// native-worker one-shot workers. The front-door dispatch arm admits
/// through this contour; the production caller composes and launches
/// through it.
pub use dispatch_launch::{
    ChildStartOutcome, DispatchGrant, DispatchLaunchError, DispatchedWorkerKind,
    DoctorChildBinding, DoctorLaunchMaterial, DoctorLaunchOutcome, DoctorLaunchSkip,
    NATIVE_WORKER_DISPATCH_AUTHORITY_PREFIX, NATIVE_WORKER_DISPATCH_DERIVATION_DOMAIN,
    NATIVE_WORKER_DISPATCH_LAUNCH_GRANT_HEAD, NativeWorkerDispatchDerivation,
    NativeWorkerLaunchMaterial, NativeWorkerLaunchOutcome, NativeWorkerLaunchSkip,
    PreparedDoctorLaunch, PreparedNativeWorkerLaunch, PreparedTestdLaunch, ReadyDoctorLaunch,
    ReadyNativeWorkerLaunch, ReadyTestdLaunch, ReconcileLaunchedOutcome, SpawnedChild,
    TestdLaunchMaterial, TestdLaunchOutcome, TestdLaunchSkip, UncertainSpawn,
    compose_dispatch_contour, compose_doctor_front_door, compose_production_doctor_front_door,
    compose_production_native_worker_front_door, compose_production_testd_front_door,
    dispatch_contour, doctor_repair_advertised, launch_admitted_doctor_attempt,
    launch_admitted_native_worker_attempt, launch_admitted_testd_attempt,
    native_worker_dispatch_derivation, native_worker_dispatch_derivation_from_epoch_json,
    native_worker_material_bytes, native_worker_production_composed, prepare_doctor_launch,
    prepare_native_worker_launch, prepare_testd_launch, reconcile_launched_doctor_attempt,
    reconcile_launched_native_worker_attempt, reconcile_launched_testd_attempt,
    release_launched_attempt, start_ready_doctor_launch, start_ready_native_worker_launch,
    start_ready_testd_launch, testd_admission_advertised, testd_production_composed,
    trigger_admitted_doctor_launch,
};
/// Kernel-owned durable Doctor recovery ledger (DISPATCH-WIRE part D).
///
/// The production redb owner composed through
/// [`dispatch_launch::compose_production_doctor_front_door`].
pub use doctor_recovery_ledger::{KernelDoctorRecoveryLedger, doctor_recovery_ledger_path};
/// K2 Dreamer wire seam for the front-door dispatch/driver arms (T12-05).
///
/// The dispatch arm (`frame_dispatch`) and the driver arm
/// (`front_door_driver`) depend only on this closed wire identity plus the
/// K0 request/response types. Slice K2 routes through the K1 gateway
/// (`KernelStoreGateway::dreamer_job`); no process is spawned here and no
/// worker binding is invented (worker handoff is T12-09).
pub use dreamer_job_dispatch::DREAMER_JOB_WIRE_ID;
use eliot_contracts::{
    ArtifactId, AuthorityEpoch, ContractId, RequestId, ResourceGeneration, StateFence,
    canonical_json_bytes,
};
use eliot_ipc::{
    AcceptedAgentBridgeTransport, HandshakeResult, PeerIdentity, ServerFirstConnection,
    ServerHandshakePolicy, Session, TransportError, TransportLimits,
};
use eliot_kernel_core::{
    AuthoritySnapshotBinding, BoundCanonicalOwner, DispatchSnapshotCodec, GenerationRoute,
    GenerationRouter, GovernorClosureRestore, KernelError, ProcessDispatchAuthorityController,
    RouteScope, bind_canonical_owner, owner_bundle_digest,
};
#[cfg(windows)]
pub use eliot_kernel_service::KernelStoreGateway;
#[cfg(windows)]
use eliot_kernel_service::StoreRebindQuery;
use eliot_kernel_service::{
    AgentBridgeAdmissionDescriptor, EliotdLaunchDescriptor, HostKernelCandidateBinding,
    HostStartupEvidence, HostStoreBootstrapRequirement, KERNEL_CONTROL_PIPE,
    KernelActivationPermit, KernelActivationReceipt, KernelControlCommand, KernelControlRequest,
    KernelControlResponse, KernelReadyReceipt, KernelService, KernelServiceError,
    KernelServiceState, ProcessAuthorityHandoffDescriptor, ProcessExecutionRequest,
    ProcessExecutionResponse, ProcessObservation, StoreBootstrapHandoff,
    USER_AUTOMATION_KERNEL_CAPABILITY, USER_AUTOMATION_KERNEL_MODULE_ID,
    USER_AUTOMATION_KERNEL_PRINCIPAL_BINDING, USER_AUTOMATION_KERNEL_PRIVACY_CLASS,
};
/// P-07 Doctor wire seam for the front-door dispatch/driver arms (T6-D2 Slice B).
///
/// The dispatch arm (`frame_dispatch`) and the session binder
/// (`front_door_session`) depend only on these existing `doctor.rs` /
/// `doctor_front_door.rs` symbols. Slice B admits through the composed
/// dispatch contour (`dispatch_launch`, over `handle_doctor_repair_attempt`)
/// at the marked call site in `frame_dispatch::execute_doctor_request`.
pub use eliot_kernel_service::{
    AuthenticatedDoctorSession, ComposedDoctorFrontDoor, DOCTOR_REPAIR_WIRE_ID,
    DOCTOR_REPAIR_WIRE_VERSION, DoctorAdmissionContext, DoctorRecipeRegistry,
    DoctorRepairAdmission, DoctorRepairAttemptRequest, DoctorRepairResponse,
    advertise_doctor_repair, handle_doctor_repair_attempt, route_doctor_repair,
};
/// P-07 testd wire seam for the front-door dispatch/driver arms (T6-X1 Slice B).
///
/// The dispatch arm (`frame_dispatch`) and the session binder
/// (`front_door_session`) depend only on these existing
/// `testd_front_door.rs` symbols. Slice B admits through the composed
/// dispatch contour (`dispatch_launch`, over
/// `handle_testd_admission_attempt`) at the marked call site in
/// `frame_dispatch::execute_testd_request`.
pub use eliot_kernel_service::{
    AuthenticatedTestdSession, TESTD_ADMISSION_WIRE_ID, TESTD_ADMISSION_WIRE_VERSION,
    TestdAdmission, TestdAdmissionAttemptRequest, TestdAdmissionContext, TestdAdmissionEnvelope,
    TestdAdmissionResponse, handle_testd_admission_attempt, reconcile_testd_admission,
    route_testd_admission,
};
/// P-07 native-worker claim wire seam for the front-door dispatch/driver arms
/// (DISPATCH-CAUSE-FIX, issues #461/#20/#22).
///
/// The session binder (`front_door_session`) and the dispatch contour
/// (`dispatch_launch`) depend only on these existing
/// `protocol/native_worker_claim.rs` + `lifecycle.rs` symbols. Slice
/// DISPATCH-CAUSE-FIX admits through the composed dispatch contour
/// (`dispatch_launch`, over `KernelService::admit_native_worker_claim`) and
/// binds the module through the same front-door session mechanism
/// Doctor/Testd use (no dedicated `AuthenticatedNativeWorkerSession` type
/// exists on this base).
pub use eliot_kernel_service::{
    NATIVE_WORKER_CLAIM_WIRE_ID, NATIVE_WORKER_CLAIM_WIRE_VERSION, NativeWorkerClaimReceipt,
    NativeWorkerClaimRequest, NativeWorkerClaimResponse,
};
#[cfg(test)]
use eliot_ors::CanonicalEvidenceProvider;
use eliot_ors::{AuthorityHandoffBegin, AuthorityHandoffRecord, AuthorityHandoffState, OrsError};
use eliot_ors::{
    OperationIdentity, OperationalRecoveryStore, RedbRecoveryStore, SupervisionLeaseOperation,
    SupervisionLeasePrepareRequest, SupervisionLeaseSnapshot,
};
#[cfg(test)]
pub use eliot_ors::{SupervisionLeaseCommitTicket, SupervisionLeaseStageReceipt};
#[cfg(test)]
use eliot_platform::ClockObservation;
#[cfg(windows)]
use eliot_platform::PlatformHandle;
#[cfg(windows)]
use eliot_platform_windows::{
    ELIOT_WATCHDOG_SERVICE_NAME, FileIdentity as WindowsFileIdentity, NamedPipePeerKind,
    NamedPipePeerProfile, NamedPipePeerSet, ProtectedRootLease, ProtectedRuntimePathLease,
    PublicationOutcome, PublicationPrecondition, observe_running_eliot_watchdog_process,
    publish_atomic_owned_runtime_receipt, read_protected_file, resolve_service_sid,
    windows_paths_equal,
};
#[cfg(test)]
pub use eliot_platform_windows::{
    InstallerRootPrimitiveSpec, InstallerRootProfile, WindowsSupervisionAuthorityKeyStore,
    protected_program_data_root,
};
use eliot_platform_windows::{UserOwnedPathLease, UserOwnedRootLease, WindowsPlatform};
#[cfg(test)]
pub use eliot_process::EliotdLiveSupervisionEvidence;
use eliot_process::{
    ActionLeaseRef, DispatchAuthorityId, EliotdLiveReadyEvidence, EliotdLiveReceipt,
    EnvironmentInheritance, EnvironmentProjection, FencingToken, Generation, ImageId, JobId,
    KernelDispatchKey, ProcessCallerSession, ProcessExecutionAdmissionRequest,
    ProcessExecutionError, ProcessIntent, ProcessOwnerBinding, ProcessSessionBinding,
    ProcessSessionClass, ProcessStartReceipt, ProcessTransportRebindReceipt, ProcessTreeId,
    ResourceLimits, SessionId,
};
#[cfg(test)]
use eliot_process::{
    DispatchValidationContext, ProcessLaunchAdmission, ProcessLifecycle, ProcessRequest,
    SuspendedProcessIdentity, ValidatedDispatch,
};
#[cfg(test)]
use eliot_process_executor::{DispatchValidationPort, WindowsProcessExecutor};
use eliot_protocol::{
    AGENT_BRIDGE_ACTIVATION_OPERATION, AGENT_BRIDGE_MODULE_ID, AGENT_BRIDGE_PEER_CHALLENGE_WIRE_ID,
    AGENT_BRIDGE_PEER_CHALLENGE_WIRE_VERSION, AgentActivationOwnerReadback,
    AgentActivationResolutionDisposition, AgentActivationResolutionResult,
    AgentActivationResolutionTicket, AgentActivationResultAck, AgentActivationResultReconcile,
    AgentBridgeActivationDenialCode, AgentBridgeActivationDisposition, AgentBridgeActivationFence,
    AgentBridgeActivationRequest, AgentBridgeActivationResponse, AgentBridgeAuthenticatedBinding,
    AgentBridgeClientDeclaration, AgentBridgePeerAdmissionReceipt, AgentBridgePeerChallenge,
    EncodingProfile, Frame, FrameKind, MessageType, ProtocolPayload, RequestIdentity,
};
use eliot_runtime::{Runtime, RuntimeConfig, ShutdownOutcome};
#[cfg(test)]
pub use eliot_runtime_contracts::SupervisionLeasePredecessorIdentity;
#[cfg(windows)]
use eliot_runtime_contracts::SupervisionLeaseTerminalDisposition;
#[cfg(windows)]
use eliot_runtime_contracts::{
    DaemonSupervisionCurrentState, DaemonSupervisionHeartbeatError,
    DaemonSupervisionRenewalDecision, DaemonSupervisionRenewalOutcome,
    DaemonSupervisionRenewalPolicy, DaemonSupervisionRenewalReceipt,
    DaemonSupervisionRenewalRequest, evaluate_daemon_supervision_renewal,
};
#[cfg(test)]
pub use eliot_runtime_contracts::{
    Ed25519SupervisionLeaseSigner, ProvisionedSupervisionAuthority, SupervisionLease,
    SupervisionLeaseActiveStateBinding, SupervisionLeaseError, SupervisionLeasePredecessorProof,
    SupervisionLeaseSigner, SupervisionLeaseVerificationContext, SupervisionLeaseVerifier,
    SupervisionSealedKeyReference, SupervisionTrustAnchor,
};
use eliot_runtime_contracts::{
    HealthVector, LeaseState, ModuleGeneration, ModuleGenerationState, SupervisionGenerationBinding,
};
use eliot_store_api::StoreHealth;
#[cfg(test)]
use eliot_store_api::{
    CanonicalValidationSnapshot, StateFence as StoreStateFence, StoreHealthStatus,
};
/// Kernel-owned mechanical projection used to bind Governor R4 evidence to
/// the live generation route and exact State Fence.
pub use generation_control::ActiveGenerationRegistryProjection;
use serde::Serialize;
use sha2::{Digest as _, Sha256};
/// WASM runtime port-grant seam for the front-door dispatch arm (#1780).
///
/// The dispatch arm (`frame_dispatch`) admits through this closed grant
/// constructor; bundle publication and launch composition live in
/// `daemon_request_dispatch`. The grant attests transport + freshness only
/// and issues no permits, Governor observations, or keys.
pub use wasm_runtime_port_grant::{
    HostBinaryFacts, KernelObservedGrantFacts, WASM_PORT_GRANT_OPERATION, WasmGrantRequest,
    WasmPortGrant, handle_wasm_port_grant, issue_wasm_port_grant, validate_wasm_port_grant,
};

#[cfg(all(test, windows))]
use canonical_store_runtime::attach_then_retain_canonical_store;
#[cfg(windows)]
pub(crate) use canonical_store_runtime::{
    is_store_rebind_latest_committed, store_rebind_receipt_from_ors_record,
    store_rebind_record_is_committed, store_rebind_record_is_pending, store_rebind_record_matches,
};
#[cfg(all(test, windows))]
use eliot_ipc::NamedPipeServer;
#[cfg(all(test, windows))]
use eliot_ipc::NamedPipeTransport;
#[cfg(windows)]
use eliot_platform_windows::{
    NamedPipePeerExpectation, current_process_named_pipe_expectation,
    observe_named_pipe_peer_process, observe_named_pipe_peer_process_in_job,
};

use front_door_session::IpcImplementation;

/// Stable Kernel process identity and wire revision.
pub const SERVICE_NAME: &str = "eliot-kernel";
pub const PROTOCOL_VERSION: &str = "eliot.kernel.v1";
pub const DEFAULT_PIPE_NAME: &str = KERNEL_CONTROL_PIPE;
/// Stable production-boundary identity for the Kernel Store-rebind seam.
pub const KERNEL_STORE_REBIND_PRODUCTION_DISCRIMINATOR: &str =
    "eliot-kernel::production-store-rebind:v1";
const STORE_BRIDGE_ROUTE: &str = "store_bridge";
const ACTIVE_DAEMON_CALLER: &str = "eliotd";
/// Wave-2 single timing owner for supervision-lease renewal (Implements #88).
///
/// `DaemonSupervisionRenewalPolicy` owns every renewal bound; the retired
/// parallel `SUPERVISION_LEASE_VALIDITY_MS` / `SUPERVISION_LEASE_RENEW_AFTER_MS`
/// constants must not be reintroduced beside it. The windows preserve the
/// established lease shape (60s validity, renewal due after 30s); the
/// observation freshness bounds match the wave-1 contract proof values.
/// Watchdog coverage is not inferred from daemon self-report. Lease renewal
/// remains available for front-door/lease continuity, while I1.11 step 11 and
/// Material/Critical supervision admission stay closed until an independent
/// Host-observed Watchdog signal is carried into Kernel. The stale-cursor
/// horizon (three missed renewal intervals, see
/// `DaemonSupervisionProgressState`) applies regardless. `StoreHealth`
/// (`health_view::daemon_health`) remains a separate evidence-only view and
/// never renews.
#[cfg(windows)]
pub(crate) const SUPERVISION_LEASE_RENEWAL_POLICY: DaemonSupervisionRenewalPolicy =
    DaemonSupervisionRenewalPolicy {
        validity_ms: 60_000,
        renew_after_ms: 30_000,
        max_observation_age_ms: 10_000,
        max_wall_skew_ms: 5_000,
        require_watchdog_coverage: false,
    };
const ELIOTD_RECEIPT_PENDING_DEPENDENCY: &str = "eliotd-process-receipt";
const ELIOTD_RECEIPT_PENDING_REASON: &str = "exact launched process receipt publication is pending";
#[cfg(windows)]
const AGENT_BRIDGE_ACTIVATION_WINDOW_MS: u64 = 30_000;
#[cfg(windows)]
/// A daemon claim admission is recorded for a short, bounded interval. The
/// mark below is a single-admission record, not a retry timer: a ticket whose
/// claim was already admitted is never re-queued while result-less (#66
/// C4/A3). Reconsideration requires a retained typed transient result with a
/// changed-dependency discriminator on the submit path, never the lease clock.
const AGENT_ACTIVATION_CLAIM_LEASE_MS: u64 = 1_000;
#[cfg(windows)]
const ELIOTD_MAX_RECOVERY_ATTEMPTS: u64 = 1;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct KernelStoreRebindProductionBoundary;

const fn probe_ready_state_admitted(state: KernelServiceState) -> bool {
    matches!(
        state,
        KernelServiceState::Activating | KernelServiceState::Ready | KernelServiceState::Degraded
    )
}

/// The complete, production Kernel composition.
pub struct KernelComposition {
    #[allow(
        dead_code,
        reason = "zero-sized marker binds the production Store-rebind seam"
    )]
    store_rebind_boundary: KernelStoreRebindProductionBoundary,
    work_root: PathBuf,
    runtime: Runtime,
    platform: Arc<WindowsPlatform>,
    ipc: IpcImplementation,
    generation_gateway: OrsGenerationCoordinator,
    service: Arc<Mutex<KernelService>>,
    generations: Mutex<GenerationRouter>,
    generation_poison: Mutex<Option<String>>,
    front_door_policy: Mutex<ServerHandshakePolicy>,
    process_gateway: Option<Arc<ProcessExecutionGateway>>,
    store_bootstrap: Option<HostStoreBootstrapRequirement>,
    daemon_launch: Option<EliotdLaunchDescriptor>,
    eliotd_receipt_binding: Option<EliotdReceiptRootBinding>,
    /// The current immutable launch binding. Recovery replaces this only
    /// after the previous process effect is known terminal; the original
    /// Host-approved descriptor remains retained in `daemon_launch`.
    daemon_active_launch: Mutex<Option<EliotdLaunchDescriptor>>,
    kernel_artifact_sha256: Option<String>,
    eliotd_descriptor_artifact_sha256: Option<String>,
    /// Host-approved WASM-host executable path retained for the grant-arm
    /// host-facts call-in (#1780). `None` fails that arm closed; the live
    /// image digest is re-proved at launch, never cached as authority here.
    wasm_host_executable_path: Option<PathBuf>,
    /// Digest bound to `wasm_host_executable_path`, validated at assembly.
    wasm_host_artifact_sha256: Option<String>,
    daemon_runtime: Mutex<DaemonRuntimeState>,
    daemon_status_changed: tokio::sync::Notify,
    #[cfg(windows)]
    daemon_recovery_gate: tokio::sync::Mutex<()>,
    #[cfg(windows)]
    daemon_recovery_attempts: AtomicU64,
    #[cfg(windows)]
    store_handoff: Mutex<Option<StoreBootstrapHandoff>>,
    #[cfg(windows)]
    /// Serializes Store rebind mutation with exact replay queries.  A service
    /// receipt is created before the ORS commit boundary, so a query must not
    /// observe that in-memory receipt while the rebind transaction is still
    /// able to roll back.
    store_rebind_gate: tokio::sync::Mutex<()>,
    approved_config_hash: Option<String>,
    canonical_store_claimed: AtomicBool,
    /// Kernel-owned Blob Store demand controller (I1.11 step 4). `None`
    /// while no approved blob manifest was injected; `Some` validates the
    /// manifest at startup without starting the generation.
    blob_store: Mutex<Option<BlobStoreController>>,
    /// Kernel-owned production restore adapter (issue #960). Held without
    /// effects until the #962 owner-channel turn drives restores through it;
    /// the durable journal is injected per execution, never constructed here.
    backup_restore: KernelBackupRestore,
    /// Kernel-owned cross-owner backup capture coordinator (issue #959).
    /// Holds the work root only; every capture consumes already-accepted
    /// owner evidence and publishes once through the admitted owner port.
    backup_capture: KernelBackupCapture,
    #[cfg(windows)]
    canonical_store_gateway: Mutex<Option<Arc<KernelStoreGateway>>>,
    #[cfg(windows)]
    supervision_lease_authority: Option<Arc<KernelSupervisionLeaseAuthority>>,
    /// The atomically retained Host-approved bridge profile and its protected
    /// declaration, if the active candidate supplied one.
    #[cfg(windows)]
    agent_bridge_profile: Mutex<Option<AgentBridgeProfile>>,
    /// Serializes the complete bridge profile transition boundary. Promotion
    /// holds the write guard while it fences, drains, and publishes a profile;
    /// synchronous bridge and host ingress holds one read guard across its
    /// state publication. The guard is never held across an async wait.
    #[cfg(windows)]
    agent_bridge_transition: RwLock<()>,
    #[cfg(windows)]
    /// Host-carried descriptor retained as inert composition input. It is
    /// never exposed to the front door until the matching candidate is Ready.
    agent_bridge_admission: Option<AgentBridgeAdmissionDescriptor>,
    #[cfg(windows)]
    agent_bridge_peer_set_revision: AtomicU64,
    #[cfg(windows)]
    agent_bridge_peer_set_changed: tokio::sync::Notify,
    #[cfg(windows)]
    agent_bridge_connections: Mutex<BTreeMap<String, AgentBridgeConnectionState>>,
    #[cfg(windows)]
    agent_activation_pending: Mutex<AgentActivationPendingState>,
    #[cfg(windows)]
    agent_activation_changed: tokio::sync::Notify,
    /// Full typed semantic resolution results are projected into the single
    /// `agent_activation_pending` owner below. ORS remains the durable
    /// authority; there is no second in-memory semantic ledger.
    /// Connection-scoped index of staged P-04 host-request operations. The
    /// durable ORS record is the owner; this index only lets disconnect revoke
    /// fence the presenting connection's still-uncertain operations to
    /// `Unknown` without enumerating the store.
    #[cfg(windows)]
    host_request_connection_index: Mutex<BTreeMap<String, Vec<HostRequestOperationRef>>>,
    /// Boot-unique seed for local-read attempt identities. Minted once per
    /// composition so attempt IDs never repeat across restarts: a capability
    /// serialized before a restart can never match a claim record minted after
    /// it, even when the fencing generation restarts at 1.
    #[cfg(windows)]
    local_read_claim_boot_nonce: u64,
    /// Canonical startup sequence coordinator (I1.11 steps 1-11). The single
    /// ordered readiness/authority-ceiling gate consulted by normal-write and
    /// Material/Critical admission paths instead of inferring readiness from
    /// process liveness or pipe availability.
    startup_coordinator: Mutex<StartupCoordinator>,
    /// Canonical P-07 durable owner binding (`#2100`). `None` until the
    /// Governor feed publishes the first owner bundle; `Some` once
    /// [`KernelComposition::bind_p07_owner`] binds the port at the exact
    /// admitted revision. Refresh and recovery rebind through the same
    /// retained ORS handle below, never through a second store.
    p07_owner: Mutex<Option<BoundCanonicalOwner>>,
    /// Canonical content digest of the bound owner bundle, computed by the
    /// one shared definition both sides call. The owner readback serves it
    /// so the Governor feed can prove the Kernel bound its exact bytes.
    p07_owner_digest: Mutex<Option<String>>,
    /// Serializes P-07 owner publication with Resolved Session publication.
    /// The bridge read lock is held from the current-owner comparison through
    /// the in-memory Session/connection update; owner bind/refresh/recovery
    /// takes the write lock, so an owner rotation cannot pass between them.
    p07_owner_transition: RwLock<()>,
    /// ORS handle retained for P-07 owner bind/refresh/recovery. Cloned
    /// from the assembly store so later owner operations never reopen the
    /// database file or invent a second recovery store.
    p07_ors: Arc<RedbRecoveryStore>,
}

impl KernelComposition {
    /// Returns the Kernel-owned production restore adapter (issue #960).
    ///
    /// Invocation arrives with the #962 owner-channel turn; until then the
    /// adapter is held without effects.
    #[must_use]
    pub fn backup_restore(&self) -> &KernelBackupRestore {
        &self.backup_restore
    }

    /// Returns the Kernel-owned cross-owner backup capture coordinator
    /// (issue #959).
    ///
    /// The coordinator is not merely held: `dispatch_backup_frame`'s verify
    /// arm calls [`KernelBackupCapture::verify_only`] through this accessor
    /// (`request_dispatch.rs`, `handle_backup_verify`), so the object is
    /// reached on the production front door today. What is still absent is the
    /// *capture* side of it — `capture` and `request_from_ports` have no
    /// production caller and no production [`PublicationPort`] provider, which
    /// is the owner-blocked half this issue's `backup.create` leg refuses with
    /// `plan_gap` naming #959.
    #[must_use]
    pub fn backup_capture(&self) -> &KernelBackupCapture {
        &self.backup_capture
    }

    /// Runs one isolated restore on the composition-owned durable ORS journal
    /// (issue #960).
    ///
    /// This is the production entry: the journal is the `RedbRecoveryStore`
    /// this composition already opened and owns, so a caller cannot substitute
    /// an in-memory, JSON-file or no-op journal for a production restore, and
    /// the per-execution journal is built from that owner handle plus the
    /// Kernel's own live effect fence.
    ///
    /// The owner-channel transport that reaches this entry is #962's frame
    /// arm; until it lands, nothing dispatches here, and no placeholder call
    /// stands in for it.
    pub fn backup_restore_with_ors_journal(
        &self,
        bundle: &eliot_backup::BackupBundle,
        target: eliot_backup::RestoreContext,
        ports: &RestorePorts<'_>,
        identity: &OrsRestoreBinding,
    ) -> Result<KernelRestoreOutcome, KernelRestoreError> {
        self.backup_restore
            .restore_with_ors_journal(&self.p07_ors, bundle, target, ports, identity)
    }
}

#[cfg(windows)]
#[derive(Clone, Debug)]
struct AgentBridgeProfile {
    admission: AgentBridgeAdmissionDescriptor,
    declaration: AgentBridgeClientDeclaration,
}

#[cfg(windows)]
#[derive(Debug)]
struct AgentBridgeConnectionState {
    exchange: ServerFirstConnection,
    declaration: AgentBridgeClientDeclaration,
    peer: PeerIdentity,
    accepted_transport: Option<AcceptedAgentBridgeTransport>,
    /// Kernel-owned transport Session retained after successful activation.
    session: Option<Session>,
    activation_completed: bool,
}

#[cfg(windows)]
#[derive(Default)]
struct AgentActivationPendingState {
    fifo: VecDeque<String>,
    entries: BTreeMap<String, AgentActivationPending>,
    /// Bounded replay ledger. A request identity is never rebound to a new
    /// connection after completion or disconnect.
    replay: BTreeMap<String, String>,
    /// Bounded durable semantic-result retention, keyed by ticket identity.
    /// One ticket accepts at most one result identity: the bridge waiter
    /// consumes the `entries` leg after projecting, but this record is kept
    /// so an exact replay stays idempotent, a changed same-ticket result
    /// conflicts, and a lost acknowledgement reconciles without a second
    /// Governor read. Retention never expires on the ticket deadline; a
    /// terminal accepted result outlives it.
    results: BTreeMap<String, AgentActivationResultRecord>,
    /// Insertion order of `results` for bounded eviction. Live pending
    /// entries are skipped when this order is pruned so an active bridge
    /// waiter can never lose the result it is waiting to project.
    result_order: VecDeque<String>,
    /// Kernel-owned lifecycle fence for each ticket. It is deliberately
    /// separate from the result payload: a cancellation/expiry terminal can
    /// never be confused with a semantic `FailedInternal` result.
    lifecycle: BTreeMap<String, AgentActivationLifecycle>,
    /// Predecessor tickets that already minted a durable successor. This
    /// mirrors the ORS `successor_ticket_id` fence so a later request cannot
    /// repeatedly select the same immutable `NotReady` result.
    successor_consumed: BTreeSet<String>,
}

#[cfg(windows)]
#[derive(Clone)]
struct AgentActivationPending {
    ticket: AgentActivationResolutionTicket,
    request: AgentBridgeActivationRequest,
    /// Private Kernel single-admission mark; it is deliberately absent from
    /// the wire ticket so retries cannot mint or select a caller-owned
    /// identity. Once set, the ticket is never handed out again while
    /// result-less (#66 C4/A3): an unanswered ticket rests until the
    /// Kernel-owned deadline instead of looping the resolver.
    claim_lease_until_unix_ms: Option<u64>,
    /// Fresh dependency discriminator supplied by the authenticated daemon
    /// claim. It is checked before a successor enters `Claimed`.
    claim_dependency_ref: Option<String>,
    claim_dependency_revision: Option<String>,
    /// A fresh ticket may be linked to one retained `NotReady` predecessor;
    /// the predecessor result itself is immutable and is never replaced.
    successor_of: Option<AgentActivationSuccessorBinding>,
    /// Authenticated current owner readback stored by Kernel when the exact
    /// result is durably accepted. It is a readback join, not a second
    /// semantic resolver.
    owner_readback: Option<AgentActivationOwnerReadback>,
}

/// Closed Kernel lifecycle fence for one activation ticket.
#[cfg(windows)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum AgentActivationLifecycle {
    Pending,
    Claimed,
    Accepted,
    DeferredNotReady,
    Cancelled,
    Expired,
    Reconciling,
}

#[cfg(windows)]
impl From<eliot_ors::ActivationLifecycleState> for AgentActivationLifecycle {
    fn from(state: eliot_ors::ActivationLifecycleState) -> Self {
        match state {
            eliot_ors::ActivationLifecycleState::Pending => Self::Pending,
            eliot_ors::ActivationLifecycleState::Claimed => Self::Claimed,
            eliot_ors::ActivationLifecycleState::ResultAccepted => Self::Accepted,
            eliot_ors::ActivationLifecycleState::DeferredNotReady => Self::DeferredNotReady,
            eliot_ors::ActivationLifecycleState::Cancelled => Self::Cancelled,
            eliot_ors::ActivationLifecycleState::Expired => Self::Expired,
            eliot_ors::ActivationLifecycleState::Reconciling => Self::Reconciling,
        }
    }
}

/// Immutable predecessor evidence cached from the durable ORS lifecycle. ORS
/// remains the authority; this is not a second semantic result or resolver.
#[cfg(windows)]
type AgentActivationSuccessorBinding = eliot_ors::ActivationSuccessorBinding;

/// Submission phase of one retained v2 semantic result.
///
/// Absence of a record means the ticket is still awaiting its result. A
/// retained record is never re-queued by claim-lease expiry: an uncertain
/// claim is durably marked `Reconciling` and removed from the live queue.
/// A result-less ticket is admitted at most once; the sole re-queue path for
/// a deferred result is a fresh, gated successor submission, never admission
/// or the lease clock.
#[cfg(windows)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum AgentActivationResultPhase {
    /// Terminal result. Exact replay is idempotent; any changed same-ticket
    /// result is an identity conflict, even across deadline expiry.
    AcceptedTerminal,
    /// `NotReady` deferral. Reconsideration requires due time (the new
    /// observation must not predate the retained `not_before`) and a changed
    /// named dependency revision; anything else conflicts.
    DeferredNotReady,
}

/// Exact retained semantic result for one Kernel-issued ticket: result
/// identity, payload digest, full typed disposition, and submission phase.
/// The immutable ticket payload carries the connection identity; this cache
/// never restores a live connection or Session after restart.
#[cfg(windows)]
#[derive(Clone)]
struct AgentActivationResultRecord {
    result: AgentActivationResolutionResult,
    /// Opaque bridge demand identity from the immutable ticket. It binds a
    /// successor to the same demand without carrying semantic authority.
    demand_id: String,
    phase: AgentActivationResultPhase,
    retention_order: u64,
}

/// Pure replay classifier for v2 results. The `NotReady` supersede gate is
/// applied by the submit path only when this classifier reports `Conflict`.
#[cfg(windows)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ActivationResultDisposition {
    Commit,
    ExactReplay,
    Conflict,
}

#[cfg(windows)]
fn classify_activation_result(
    existing: Option<&AgentActivationResolutionResult>,
    incoming: &AgentActivationResolutionResult,
) -> ActivationResultDisposition {
    match existing {
        None => ActivationResultDisposition::Commit,
        Some(existing) if existing.result_sha256 == incoming.result_sha256 => {
            ActivationResultDisposition::ExactReplay
        }
        Some(_) => ActivationResultDisposition::Conflict,
    }
}

#[cfg(windows)]
impl AgentActivationPendingState {
    pub(crate) fn from_rehydrated_results(
        results: BTreeMap<String, AgentActivationResultRecord>,
        lifecycle: BTreeMap<String, AgentActivationLifecycle>,
        successor_consumed: BTreeSet<String>,
    ) -> Self {
        let mut state = Self::default();
        let mut result_order = results
            .values()
            .map(|record| record.result.ticket_id.clone())
            .collect::<Vec<_>>();
        result_order.sort_by_key(|ticket_id| {
            results
                .get(ticket_id)
                .map_or(0, |record| record.retention_order)
        });
        state.result_order = result_order.into_iter().collect();
        state.lifecycle = lifecycle;
        state.successor_consumed = successor_consumed;
        state.results = results;
        state
    }

    fn mark_lifecycle(&mut self, ticket_id: &str, lifecycle: AgentActivationLifecycle) {
        self.lifecycle.insert(ticket_id.to_owned(), lifecycle);
        if self.lifecycle.len() > eliot_ors::MAX_ACTIVATION_LIFECYCLE_RECORDS
            && let Some(oldest) = self
                .lifecycle
                .iter()
                .find(|(candidate, _)| {
                    !self.entries.contains_key(*candidate) && !self.results.contains_key(*candidate)
                })
                .map(|(candidate, _)| candidate.clone())
        {
            self.lifecycle.remove(&oldest);
        }
    }

    fn lifecycle(&self, ticket_id: &str) -> AgentActivationLifecycle {
        self.lifecycle
            .get(ticket_id)
            .copied()
            .unwrap_or(AgentActivationLifecycle::Pending)
    }

    /// Finds the one retained `NotReady` predecessor for this exact bridge
    /// demand that may authorize a fresh successor ticket. The due-time check
    /// only makes a candidate eligible for staging; `claim_at` still requires
    /// the authenticated daemon's fresh changed-revision discriminator before
    /// transitioning it to `Claimed`. A same-ticket replacement is never
    /// returned, and an unrelated demand cannot inherit predecessor evidence.
    fn successor_candidate_for(
        &self,
        now: u64,
        demand_id: &str,
    ) -> Result<Option<AgentActivationSuccessorBinding>, TransportError> {
        let mut candidates = self
            .results
            .values()
            .filter(|record| {
                record.demand_id == demand_id
                    && !self.successor_consumed.contains(&record.result.ticket_id)
                    && self.lifecycle(&record.result.ticket_id)
                        == AgentActivationLifecycle::DeferredNotReady
                    && matches!(
                        &record.result.disposition,
                        AgentActivationResolutionDisposition::NotReady { .. }
                    )
            })
            .collect::<Vec<_>>();
        candidates.sort_by_key(|record| record.retention_order);
        let Some(record) = candidates.last().copied() else {
            return Ok(None);
        };
        let AgentActivationResolutionDisposition::NotReady { retry, .. } =
            &record.result.disposition
        else {
            return Err(TransportError::SessionFenced);
        };
        if now < retry.not_before_unix_ms {
            return Err(TransportError::IdentityConflict);
        }
        if self.entries.values().any(|entry| {
            entry
                .successor_of
                .as_ref()
                .is_some_and(|successor| successor.predecessor_ticket_id == record.result.ticket_id)
        }) {
            return Err(TransportError::IdentityConflict);
        }
        Ok(Some(AgentActivationSuccessorBinding {
            predecessor_ticket_id: record.result.ticket_id.clone(),
            predecessor_ticket_sha256: record.result.ticket_sha256.clone(),
            predecessor_result_sha256: record.result.result_sha256.clone(),
            dependency_ref: retry.dependency_ref.clone(),
            observed_dependency_revision: retry.observed_dependency_revision.clone(),
            not_before_unix_ms: retry.not_before_unix_ms,
        }))
    }

    fn claim_at(
        &mut self,
        now: u64,
        dependency_ref: &str,
        dependency_revision: &str,
    ) -> Option<AgentActivationResolutionTicket> {
        let queue_len = self.fifo.len();
        for _ in 0..queue_len {
            let ticket_id = self.fifo.pop_front()?;
            // A retained semantic result (v2) is terminal-or-deferred
            // durable state: claim-lease expiry is not a semantic delta and
            // never re-queues it. A result-less lost claim is removed from
            // the live queue and reconciled by the durable owner.
            if self.results.contains_key(&ticket_id) {
                continue;
            }
            let Some(entry) = self.entries.get(&ticket_id) else {
                continue;
            };
            if activation_deadline_expired(now, entry.ticket.kernel_deadline_unix_ms) {
                continue;
            }
            if entry.claim_lease_until_unix_ms.is_some() {
                self.fifo.push_back(ticket_id);
                continue;
            }
            let successor = entry.successor_of.clone();
            if let Some(successor) = successor.as_ref() {
                let Some(predecessor) = self.results.get(&successor.predecessor_ticket_id) else {
                    self.fifo.push_back(ticket_id);
                    continue;
                };
                let AgentActivationResolutionDisposition::NotReady {
                    retry: predecessor_retry,
                    ..
                } = &predecessor.result.disposition
                else {
                    self.fifo.push_back(ticket_id);
                    continue;
                };
                if now < predecessor_retry.not_before_unix_ms
                    || successor.dependency_ref != dependency_ref
                    || dependency_revision == predecessor_retry.observed_dependency_revision
                {
                    // A due-time-only observation is not claimable. Keep the
                    // successor staged and invisible to the daemon until the
                    // authenticated owner supplies a changed discriminator.
                    self.fifo.push_back(ticket_id);
                    continue;
                }
            }
            let Some(entry) = self.entries.get_mut(&ticket_id) else {
                continue;
            };
            entry.claim_lease_until_unix_ms = Some(
                now.saturating_add(AGENT_ACTIVATION_CLAIM_LEASE_MS)
                    .min(entry.ticket.kernel_deadline_unix_ms),
            );
            entry.claim_dependency_ref = Some(dependency_ref.to_owned());
            entry.claim_dependency_revision = Some(dependency_revision.to_owned());
            let ticket = entry.ticket.clone();
            self.mark_lifecycle(&ticket_id, AgentActivationLifecycle::Claimed);
            return Some(ticket);
        }
        None
    }

    /// Checks the canonical result map and its insertion order without
    /// changing either representation. The order is a bijection with the map:
    /// every ticket occurs exactly once and no ticket is omitted or extraneous.
    #[cfg(windows)]
    fn result_ledger_is_consistent(&self) -> bool {
        let max = eliot_ors::MAX_ACTIVATION_RESULT_RETENTION_RECORDS;
        if self.results.len() > max || self.result_order.len() > max {
            return false;
        }
        let mut ordered = BTreeSet::new();
        for ticket_id in &self.result_order {
            if !self.results.contains_key(ticket_id) || !ordered.insert(ticket_id) {
                return false;
            }
        }
        ordered.len() == self.results.len()
            && self
                .results
                .iter()
                .all(|(ticket_id, record)| ticket_id == &record.result.ticket_id)
            && self
                .results
                .keys()
                .all(|ticket_id| ordered.contains(ticket_id))
    }

    /// Validates the local ledger shape before publication. ORS, under the
    /// same pending lock, is the sole authority for bounded eviction; the
    /// cache never selects a victim independently.
    #[cfg(windows)]
    fn result_retention_eviction_plan(&self, _ticket_id: &str) -> Option<Vec<String>> {
        if !self.result_ledger_is_consistent() {
            return None;
        }
        Some(Vec::new())
    }

    /// Stages the canonical result map/order update before the durable write.
    /// ORS performs bounded eviction under the same pending lock and returns
    /// the exact victim identities; this cache never chooses a different
    /// victim independently.
    #[cfg(windows)]
    fn stage_result_retention(
        &self,
        record: AgentActivationResultRecord,
    ) -> Option<(
        BTreeMap<String, AgentActivationResultRecord>,
        VecDeque<String>,
    )> {
        let ticket_id = record.result.ticket_id.clone();
        let victims = self.result_retention_eviction_plan(&ticket_id)?;
        let mut results = self.results.clone();
        let mut result_order = self.result_order.clone();
        for victim in victims {
            results.remove(&victim)?;
            let before = result_order.len();
            result_order.retain(|candidate| candidate != &victim);
            if result_order.len().saturating_add(1) != before {
                return None;
            }
        }
        if !results.contains_key(&ticket_id) {
            result_order.push_back(ticket_id.clone());
        }
        results.insert(ticket_id, record);
        Some((results, result_order))
    }

    /// Publishes a previously staged canonical result after durable ORS
    /// success. `stage_result_retention` proves the ticket exists in the copy;
    /// the debug assertion documents that internal invariant without adding a
    /// post-commit error path for an otherwise unreachable state.
    #[cfg(windows)]
    fn publish_staged_result_retention(
        &mut self,
        mut staged: (
            BTreeMap<String, AgentActivationResultRecord>,
            VecDeque<String>,
        ),
        ticket_id: &str,
        retention_order: u64,
        evicted_ticket_ids: &[String],
    ) {
        debug_assert!(staged.0.contains_key(ticket_id));
        for evicted_ticket_id in evicted_ticket_ids {
            staged.0.remove(evicted_ticket_id);
            staged.1.retain(|candidate| candidate != evicted_ticket_id);
        }
        if let Some(record) = staged.0.get_mut(ticket_id) {
            record.retention_order = retention_order;
        }
        self.results = staged.0;
        self.result_order = staged.1;
    }
}

/// Server-first bridge handshake material returned by Kernel composition.
/// This carries transport evidence only; it is not a Kernel `Session`.
#[cfg(windows)]
#[derive(Debug)]
pub struct AgentBridgeHandshake {
    pub connection_id: String,
    pub challenge: AgentBridgePeerChallenge,
    pub challenge_frame: Frame,
}

/// Result of the closed Kernel semantic gateway for one authenticated frame.
///
/// The transport/session loop owns the connection lifetime. This action only
/// says whether a validated frame may receive a bounded protocol reply, must
/// fence the session, or requests the one Kernel shutdown path.
#[derive(Debug)]
pub enum KernelFrameAction {
    /// Return a bounded liveness or status reply.
    Reply(Frame),
    /// Execute one authenticated, provider-neutral process operation.
    Process {
        /// Correlation identity to echo in the response.
        request_id: RequestId,
        /// Validated inert operation.
        request: ProcessExecutionRequest,
        /// Server-derived ephemeral session binding; never wire supplied.
        session_binding: ProcessSessionBinding,
    },
    /// Execute one narrow authenticated `eliotd` lifecycle operation.  The
    /// operation is handled by Kernel's daemon contour, while Store-backed
    /// health remains an asynchronous physical probe.
    Daemon {
        /// Correlation identity to echo in the response.
        request_id: RequestId,
        /// Exact authenticated request identity admitted on the same frame.
        identity: RequestIdentity,
        /// Closed operation name from the daemon application wire.
        operation: String,
        /// Bounded operation payload.
        payload: serde_json::Value,
    },
    /// Execute one authenticated Doctor repair-attempt operation (T6-D2 P-07).
    /// The operation carries the exact Doctor wire identity; ledger-bound
    /// admission itself is owned by the P-07 doctor handler through
    /// `eliot_kernel_service::doctor` (`route_doctor_repair` /
    /// `admit_doctor_repair`). New-effect intake is `Ready`-gated per kind;
    /// cancel/reconcile control additionally routes while `Degraded`.
    Doctor {
        /// Correlation identity to echo in the response.
        request_id: RequestId,
        /// Closed operation name; must equal `DOCTOR_REPAIR_WIRE_ID`.
        operation: String,
        /// Bounded operation payload carrying the typed repair-attempt request.
        payload: serde_json::Value,
        /// The original transport control classification.  The typed Doctor
        /// owner still validates the closed envelope before admitting it.
        control: bool,
    },
    /// Execute one authenticated testd admission operation (T6-X1 P-07).
    /// The operation carries the exact testd wire identity; job-bound
    /// admission itself is owned by the P-07 testd handler through
    /// `eliot_kernel_service::testd_front_door` (`route_testd_admission` /
    /// `handle_testd_admission_attempt`). New-execution intake is
    /// `Ready`-gated per kind; cancel/reconcile control additionally routes
    /// while `Degraded`.
    Testd {
        /// Correlation identity to echo in the response.
        request_id: RequestId,
        /// Exact authenticated owner identity from the EBP frame. The
        /// terminal route compares it with the durable pre-dispatch binding.
        identity: RequestIdentity,
        /// Closed operation name; must equal `TESTD_ADMISSION_WIRE_ID`.
        operation: String,
        /// Bounded operation payload carrying the typed admission request.
        payload: serde_json::Value,
        /// The original transport control classification. The typed `TestD`
        /// owner remains the final authority on cancellation versus submit.
        control: bool,
    },
    /// Execute one authenticated Dreamer job operation (T12-05 K2).
    /// The operation carries the exact Dreamer wire identity; ledger-bound
    /// admission itself is owned by the K1 gateway
    /// (`KernelStoreGateway::dreamer_job`). Intake is `Ready`-gated; the
    /// authenticated caller is the `eliotd` requester and the presented
    /// `JobRole` must agree with it, never grant rights. No process is
    /// spawned inside this handler.
    Dreamer {
        /// Correlation identity to echo in the response.
        request_id: RequestId,
        /// Closed operation name; must equal `DREAMER_JOB_WIRE_ID`.
        operation: String,
        /// Bounded operation payload carrying context plus typed job request.
        payload: serde_json::Value,
    },
    /// Execute one authenticated bounded research-provider operation (#24).
    ///
    /// The operation carries the exact research dispatch wire identity; the
    /// admission itself is owned by the Kernel research-provider route
    /// (`crate::research_provider_route`), which re-queries the live authority
    /// epoch and the session's module-generation State Fence on every call. No
    /// provider process is spawned inside this handler: the admitted operation
    /// is executed by `eliot-mod-research` through the shared governed process
    /// contour, and the returned material stays candidate-only.
    Research {
        /// Correlation identity to echo in the response.
        request_id: RequestId,
        /// Closed operation name from the research-provider wire.
        operation: String,
        /// Bounded operation payload carrying the typed dispatch envelope.
        payload: serde_json::Value,
    },
    /// Return a typed rejection, then fence the connection.
    Fence(Frame),
}

fn unix_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_millis()
        .try_into()
        .unwrap_or(u64::MAX)
}

#[cfg(windows)]
fn activation_deadline_expired(now: u64, deadline: u64) -> bool {
    now >= deadline
}

/// Closed shape of one live SCM Watchdog incarnation observation:
/// `host-scm-watchdog:{pid}:{start_time_100ns}:{image_sha256}`.
///
/// I1.11 step 1 makes SCM the named channel for the independent Watchdog
/// service state, so the digest that carries it is a live process identity plus
/// the digest of the live Watchdog image bytes. A path string, a lease revision
/// or a health flag is not this shape and is refused.
const LIVE_SCM_WATCHDOG_OBSERVATION_PREFIX: &str = "host-scm-watchdog";

/// Validates the closed carrier shape of one live SCM Watchdog incarnation
/// observation.
///
/// This proves the SHAPE of the observation carrier and nothing else. It does
/// not query SCM, does not probe process liveness or responsiveness, and does
/// not re-hash the Watchdog image. It is not a live observation and must never
/// be cited as one.
///
/// I1.5 (#1750): the live observation is produced by the Host observation
/// owner, which revalidates the bound PID/start pair against the live OS and
/// the live image bytes against the approved Watchdog artifact before it
/// publishes the carrier. What makes the resulting claim current is
/// [`KernelComposition::admit_host_observed_watchdog_branch`] binding that
/// observation to one exact contour and consumer fence, and
/// [`StartupCoordinator::admit_supervision_observation`] requiring it to still
/// be inside its own finite validity interval. This validator runs once, where
/// the record is created, so no consumer ever decides supervision from
/// re-parsed retained text.
///
/// # Errors
///
/// Returns a fixed-shape reason when the carrier does not name a Watchdog
/// process identity with a non-zero pid, a non-zero process start and a
/// non-empty image digest, and nothing else.
fn verify_scm_watchdog_observation_shape(
    digest: &eliot_platform::PlatformHandle,
) -> Result<(), &'static str> {
    const MALFORMED: &str = "Host SCM Watchdog observation is malformed";
    let mut parts = digest.as_str().split(':');
    if parts.next() != Some(LIVE_SCM_WATCHDOG_OBSERVATION_PREFIX) {
        return Err(MALFORMED);
    }
    let Ok(process_id) = parts.next().ok_or(MALFORMED)?.parse::<u32>() else {
        return Err(MALFORMED);
    };
    let Ok(process_start) = parts.next().ok_or(MALFORMED)?.parse::<u64>() else {
        return Err(MALFORMED);
    };
    let image_sha256 = parts.next().ok_or(MALFORMED)?;
    if parts.next().is_some() || process_id == 0 || process_start == 0 || image_sha256.is_empty() {
        return Err(MALFORMED);
    }
    Ok(())
}

#[cfg(windows)]
fn load_agent_bridge_declaration(
    admission: &AgentBridgeAdmissionDescriptor,
) -> Result<AgentBridgeClientDeclaration, KernelBuildError> {
    admission
        .validate()
        .map_err(|error| KernelBuildError::Service(error.to_string()))?;
    let path = Path::new(admission.client_declaration_path.as_str());
    let bytes = read_protected_file(path, eliot_protocol::MAX_FRAME_BYTES as u64)
        .map_err(|error| KernelBuildError::Service(error.to_string()))?;
    let declaration: AgentBridgeClientDeclaration = serde_json::from_slice(&bytes)
        .map_err(|error| KernelBuildError::Service(error.to_string()))?;
    admission
        .validate_client_declaration(&declaration)
        .map_err(|error| KernelBuildError::Service(error.to_string()))?;
    Ok(declaration)
}

#[cfg(windows)]
impl KernelComposition {
    fn ors_path_for_config(config: &KernelConfig) -> Result<PathBuf, KernelBuildError> {
        let Some(binding) = config.eliotd_receipt_binding.as_ref() else {
            return Ok(config.work_root.join(".eliot").join("kernel-ors.redb"));
        };
        binding.validate().map_err(KernelBuildError::Service)?;
        #[cfg(windows)]
        {
            let lease = ProtectedRootLease::open_existing(binding.kernel_ors_root())
                .map_err(|error| KernelBuildError::Service(error.to_string()))?;
            let canonical = lease
                .canonical_path()
                .map_err(|error| KernelBuildError::Service(error.to_string()))?;
            if !windows_paths_equal(&canonical, binding.kernel_ors_root())
                || lease.verify_stable_identity().is_err()
            {
                return Err(KernelBuildError::Service(
                    "manifest-bound Kernel ORS root identity is unavailable".to_owned(),
                ));
            }
            Ok(canonical.join("kernel-ors.redb"))
        }
        #[cfg(not(windows))]
        {
            Err(KernelBuildError::Service(
                "manifest-bound Kernel ORS root requires Windows retained-path proof".to_owned(),
            ))
        }
    }

    /// Returns the discriminator bound to the production Kernel composition.
    #[must_use]
    pub const fn production_store_rebind_discriminator() -> &'static str {
        KERNEL_STORE_REBIND_PRODUCTION_DISCRIMINATOR
    }

    #[allow(clippy::too_many_lines)]
    fn recover_store_rebind_state(
        ors: &RedbRecoveryStore,
        service: &mut eliot_kernel_service::KernelService,
        store_bootstrap: Option<&HostStoreBootstrapRequirement>,
    ) -> Result<Option<eliot_kernel_service::StoreBootstrapHandoff>, String> {
        let mut records = ors.load_all_store_rebinds().map_err(|e| e.to_string())?;
        let mut reconciled_committed = Vec::new();
        for pending in records
            .iter()
            .filter(|r| r.state == eliot_ors::StoreRebindReplayState::Pending)
        {
            let aborted = ors
                .abort_store_rebind(&pending.operation_id, &pending.request_digest)
                .map_err(|error| {
                    format!(
                        "startup Store rebind abort/reconciliation failed for {}: {error}",
                        pending.operation_id.as_str()
                    )
                })?;
            if !aborted {
                let after = ors
                    .load_store_rebind(&pending.operation_id, &pending.request_digest)
                    .map_err(|error| {
                        format!(
                            "startup Store rebind abort readback failed for {}: {error}",
                            pending.operation_id.as_str()
                        )
                    })?
                    .ok_or_else(|| {
                        format!(
                            "startup Store rebind abort returned false without exact readback for {}",
                            pending.operation_id.as_str()
                        )
                    })?;
                if after.state != eliot_ors::StoreRebindReplayState::Committed
                    || after.receipt.as_deref() != Some(after.request_digest.as_str())
                {
                    return Err(format!(
                        "startup Store rebind abort did not reach a terminal disposition for {}",
                        pending.operation_id.as_str()
                    ));
                }
                reconciled_committed.push(after);
            }
        }
        records.extend(reconciled_committed);
        let Some(requirement) = store_bootstrap else {
            return Ok(None);
        };
        let requirement_digest = {
            let bytes = serde_json::to_vec(requirement).map_err(|e| e.to_string())?;
            format!("{:x}", Sha256::digest(&bytes))
        };
        // Select the latest durable commit only within the exact current
        // bootstrap lineage. An unrelated newer lineage must not shadow a
        // recoverable handoff for this requirement.
        let lineage_committed: Vec<_> = records
            .iter()
            .filter(|r| {
                r.state == eliot_ors::StoreRebindReplayState::Committed
                    && r.requirement_digest == requirement_digest
                    && r.generation == requirement.state_fence.resource_generation.value()
                    && r.authority_epoch == requirement.state_fence.authority_epoch.sequence.get()
            })
            .cloned()
            .collect();
        let legacy_zeros = lineage_committed
            .iter()
            .filter(|r| r.commit_order == 0)
            .count();
        if legacy_zeros > 1 {
            return Err(
                "Store rebind legacy commit order requires migration/recovery: ambiguous lineage"
                    .to_owned(),
            );
        }
        if legacy_zeros == 1 && lineage_committed.len() > 1 {
            let max_order = lineage_committed
                .iter()
                .map(|r| r.commit_order)
                .max()
                .unwrap_or(0);
            if max_order > 0 {
                let non_zero_latest = lineage_committed
                    .iter()
                    .filter(|r| r.commit_order > 0)
                    .max_by_key(|r| {
                        (
                            r.commit_order,
                            r.operation_id.as_str().to_owned(),
                            r.request_digest.clone(),
                        )
                    });
                if let Some(record) = non_zero_latest.cloned() {
                    let receipt = store_rebind_receipt_from_ors_record(
                        &record,
                        &requirement.state_fence.authority_epoch,
                    )
                    .map_err(|error| error.to_string())?;
                    service
                        .restore_store_rebind_for_recovery(
                            receipt.clone(),
                            record.request_digest.clone(),
                        )
                        .map_err(|e| e.to_string())?;
                    return Ok(Some(eliot_kernel_service::StoreBootstrapHandoff {
                        requirement: requirement.clone(),
                        process_binding: receipt.process_binding.clone(),
                    }));
                }
            } else {
                return Err(
                    "Store rebind legacy commit order requires migration/recovery".to_owned(),
                );
            }
        }
        let committed = lineage_committed.into_iter().max_by_key(|r| {
            (
                r.commit_order,
                r.operation_id.as_str().to_owned(),
                r.request_digest.clone(),
            )
        });
        let Some(record) = committed else {
            return Ok(None);
        };
        let receipt =
            store_rebind_receipt_from_ors_record(&record, &requirement.state_fence.authority_epoch)
                .map_err(|error| error.to_string())?;
        service
            .restore_store_rebind_for_recovery(receipt.clone(), record.request_digest.clone())
            .map_err(|e| e.to_string())?;
        Ok(Some(eliot_kernel_service::StoreBootstrapHandoff {
            requirement: requirement.clone(),
            process_binding: receipt.process_binding.clone(),
        }))
    }
}

impl KernelComposition {
    /// Acquires the read side of the bridge profile transition boundary.
    ///
    /// Each synchronous ingress acquires this exactly once and passes through
    /// private under-transition helpers. In particular, callers must not
    /// reacquire it from a nested helper while a promotion writer may be
    /// queued: `std::sync::RwLock` can block recursive readers in that state.
    #[cfg(windows)]
    pub(crate) fn agent_bridge_transition_read(
        &self,
    ) -> Result<std::sync::RwLockReadGuard<'_, ()>, TransportError> {
        self.agent_bridge_transition
            .read()
            .map_err(|_| TransportError::SessionFenced)
    }

    /// Acquires the write side of the bridge profile transition boundary.
    /// The caller must keep it through profile fencing, ownership drain, and
    /// replacement publication.
    #[cfg(windows)]
    pub(crate) fn agent_bridge_transition_write(
        &self,
    ) -> Result<std::sync::RwLockWriteGuard<'_, ()>, TransportError> {
        self.agent_bridge_transition
            .write()
            .map_err(|_| TransportError::SessionFenced)
    }

    /// Monotonic revision of the promoted bridge profile. The production
    /// listener uses this to rebuild a pending pipe after Host activation
    /// changes the bounded DACL/peer set.
    #[cfg(windows)]
    #[must_use]
    pub fn agent_bridge_peer_set_revision(&self) -> u64 {
        self.agent_bridge_peer_set_revision.load(Ordering::Acquire)
    }

    /// Waits for a real peer-set change without cancelling an in-flight pipe
    /// authentication. The revision check before and after registration makes
    /// the notification lost-wake safe.
    #[cfg(windows)]
    pub async fn wait_for_agent_bridge_peer_set_revision(&self, observed: u64) -> u64 {
        loop {
            let current = self.agent_bridge_peer_set_revision();
            if current != observed {
                return current;
            }
            let notified = self.agent_bridge_peer_set_changed.notified();
            if self.agent_bridge_peer_set_revision() != observed {
                return self.agent_bridge_peer_set_revision();
            }
            notified.await;
        }
    }

    #[cfg(windows)]
    pub fn note_agent_bridge_peer_set_change(&self) {
        self.agent_bridge_peer_set_revision
            .fetch_add(1, Ordering::AcqRel);
        // `notify_one` retains a permit if the listener changes state in the
        // check-to-await gap; `notify_waiters` would lose that wake.
        self.agent_bridge_peer_set_changed.notify_one();
    }

    /// Verifies that the retained bridge declaration binds the live Kernel
    /// front-door policy, and returns the exact config-snapshot digest.
    ///
    /// Narrow S1 seam for the Instrument R13 conformance harness: the policy
    /// lock and its snapshot never leave this composition.
    #[cfg(windows)]
    pub fn verify_harness_kernel_policy(
        &self,
        declaration: &AgentBridgeClientDeclaration,
    ) -> Result<String, String> {
        let policy = self
            .front_door_policy
            .lock()
            .map_err(|_| "Kernel policy lock poisoned".to_owned())?
            .clone();
        let policy_artifact = policy
            .config_snapshot
            .get("artifact_digest")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| "Kernel policy artifact digest is absent".to_owned())?;
        let policy_config_digest = sha256_json(&policy.config_snapshot)
            .map_err(|error| format!("compute Kernel policy digest: {error}"))?;
        if policy.session_principal_binding != declaration.expected_kernel_principal_binding
            || policy.module_generation.state_fence.authority_epoch
                != declaration.expected_kernel_authority_epoch
            || policy.module_generation.generation != declaration.expected_kernel_generation
            || policy_artifact != declaration.expected_kernel_artifact_sha256
            || policy_config_digest != declaration.expected_kernel_config_snapshot_sha256
        {
            return Err(
                "retained declaration does not bind the actual LocalService Kernel policy"
                    .to_owned(),
            );
        }
        Ok(policy_config_digest)
    }

    /// Installs the retained Host-approved bridge profile and declaration.
    ///
    /// Narrow S2 seam for the Instrument R13 conformance harness: the profile
    /// lock never leaves this composition.
    #[cfg(windows)]
    pub fn install_harness_bridge_profile(
        &self,
        admission: AgentBridgeAdmissionDescriptor,
        declaration: AgentBridgeClientDeclaration,
    ) -> Result<(), String> {
        *self
            .agent_bridge_profile
            .lock()
            .map_err(|_| "bridge profile lock poisoned".to_owned())? = Some(AgentBridgeProfile {
            admission,
            declaration,
        });
        Ok(())
    }

    /// Runs the exact harness candidate lifecycle through the single Kernel
    /// transition boundary: `reconcile`, `Shadow`, `PrepareHandoff`, permit
    /// activation, receipt, and `Ready` publication.
    ///
    /// Narrow S3 seam for the Instrument R13 conformance harness: the service
    /// handle never leaves this composition.
    #[cfg(windows)]
    pub fn activate_harness_candidate(
        &self,
        candidate: &HostKernelCandidateBinding,
        permit: &KernelActivationPermit,
        expected_config_snapshot_sha256: &str,
    ) -> Result<KernelActivationReceipt, String> {
        // Implements #1967: Material authority issuance consults the startup
        // coordinator. The rejection names the unmet I1.11 prerequisite.
        {
            let coordinator = self
                .startup_coordinator
                .lock()
                .map_err(|_| "startup gate lock poisoned".to_owned())?;
            coordinator
                .admit_normal_write()
                .map_err(|rejection| rejection.to_string())?;
        }
        let mut service = self
            .service
            .lock()
            .map_err(|_| "Kernel service lock poisoned".to_owned())?;
        service
            .reconcile(candidate.clone())
            .map_err(|error| format!("reconcile Kernel candidate: {error}"))?;
        service
            .apply(KernelControlCommand::Shadow)
            .map_err(|error| format!("shadow Kernel candidate: {error}"))?;
        service
            .apply(KernelControlCommand::PrepareHandoff)
            .map_err(|error| format!("prepare Kernel handoff: {error}"))?;
        let receipt = service
            .activate_permit(
                permit,
                permit.generation,
                expected_config_snapshot_sha256.to_owned(),
            )
            .map_err(|error| format!("activate Kernel candidate: {error}"))?;
        let activation_nonce_digest = service
            .activation_receipt()
            .ok_or_else(|| "Kernel activation receipt missing".to_owned())?
            .activation_nonce_digest
            .clone();
        service
            .publish_ready(KernelReadyReceipt {
                activation_id: candidate.activation_id.clone(),
                activation_operation_id: permit.operation_id.clone(),
                activation_nonce_digest,
                process: ProcessObservation {
                    process_id: PlatformHandle::new(format!(
                        "pid:{}:start:{}",
                        candidate.host_process.process_id, candidate.host_process.start_time_100ns
                    ))
                    .map_err(|error| error.to_string())?,
                    job_object_id: candidate.job_object_id.clone(),
                    state: eliot_runtime_contracts::ServiceProcessState::Ready,
                    health: HealthVector::healthy(),
                    evidence_refs: vec![
                        PlatformHandle::new("r13-two-token-worker-evidence")
                            .map_err(|error| error.to_string())?,
                    ],
                },
                health: HealthVector::healthy(),
                evidence_refs: vec![
                    PlatformHandle::new("r13-two-token-worker-evidence")
                        .map_err(|error| error.to_string())?,
                ],
            })
            .map_err(|error| format!("publish Kernel Ready state: {error}"))?;
        Ok(receipt)
    }

    /// Reports whether the typed denial path unexpectedly minted a transport
    /// session or auth binding.
    ///
    /// Narrow S5 seam for the Instrument R13 conformance harness: the
    /// connection table never leaves this composition.
    #[cfg(windows)]
    pub fn harness_has_agent_bridge_session(&self) -> Result<bool, String> {
        Ok(self
            .agent_bridge_connections
            .lock()
            .map_err(|_| "bridge connection lock poisoned".to_owned())?
            .values()
            .any(|state| state.session.is_some() || state.activation_completed))
    }

    #[cfg(windows)]
    async fn fence_store_rebind_runtime(
        &self,
        gateway: &Arc<KernelStoreGateway>,
        reason: impl Into<String>,
    ) -> Result<(), KernelBuildError> {
        let reason = reason.into();
        {
            let mut service = self
                .service
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            service.fence_generation(reason).map_err(|error| {
                KernelBuildError::Service(format!("generation fence failed: {error}"))
            })?;
        }
        gateway.fence();
        let old = self
            .canonical_store_gateway
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();
        if let Some(old) = old
            && !Arc::ptr_eq(&old, gateway)
        {
            old.fence_and_drain(Duration::from_secs(5))
                .await
                .map_err(KernelBuildError::Service)?;
        }
        Ok(())
    }

    #[cfg(windows)]
    fn commit_store_rebind_attachment<'a>(
        attachment: &mut Option<Box<dyn CanonicalStoreAttachmentTransaction + 'a>>,
    ) {
        if let Some(attachment) = attachment.take() {
            attachment.commit();
        }
    }

    #[cfg(windows)]
    #[allow(
        clippy::too_many_lines,
        reason = "single ordered Store rebind transaction"
    )]
    async fn rebind_store(
        &self,
        handoff: eliot_kernel_service::StoreRebindHandoff,
        request_digest: String,
    ) -> Result<eliot_kernel_service::StoreRebindReceipt, KernelBuildError> {
        // Implements #1967: normal canonical writes consult the startup
        // coordinator rather than inferring readiness from liveness. The
        // rejection names the unmet I1.11 prerequisite; inspection paths
        // never consult this gate.
        if let Err(error) = self.admit_normal_write() {
            return Err(KernelBuildError::Service(error.to_string()));
        }
        handoff
            .validate()
            .map_err(|e| KernelBuildError::Service(e.to_string()))?;
        handoff
            .validate_canonical_digest()
            .map_err(|e| KernelBuildError::Service(e.to_string()))?;
        if request_digest != handoff.request_digest {
            return Err(KernelBuildError::Service(
                "Store rebind request digest must equal canonical handoff digest".to_owned(),
            ));
        }
        if self.store_bootstrap.as_ref() != Some(&handoff.requirement) {
            return Err(KernelBuildError::Service(
                "Store rebind requirement is not the immutable bootstrap descriptor".to_owned(),
            ));
        }
        if request_digest.len() != 64
            || !request_digest
                .bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
        {
            return Err(KernelBuildError::Service(
                "Store rebind outer digest invalid".to_owned(),
            ));
        }
        let expected_fence = {
            let mut hasher = Sha256::new();
            hasher.update(
                serde_json::to_vec(&handoff.requirement.state_fence)
                    .map_err(|e| KernelBuildError::Service(e.to_string()))?,
            );
            hasher.update(handoff.generation.value().to_le_bytes());
            hasher.update(handoff.authority_epoch.sequence.get().to_le_bytes());
            hasher.update(
                handoff
                    .requirement
                    .approved_artifact_hash
                    .as_str()
                    .as_bytes(),
            );
            hasher.update(handoff.requirement.approved_config_hash.as_str().as_bytes());
            hasher.update(handoff.process_binding.process.process_id.to_le_bytes());
            hasher.update(
                handoff
                    .process_binding
                    .process
                    .start_time_100ns
                    .to_le_bytes(),
            );
            hasher.update(handoff.process_binding.process.image_path.as_bytes());
            hasher.update(handoff.process_binding.job.as_str().as_bytes());
            hasher.update(handoff.candidate_binding_digest.as_bytes());
            format!("{:x}", hasher.finalize())
        };
        if expected_fence != handoff.store_fence {
            return Err(KernelBuildError::Service(
                "Store rebind fence does not bind fresh peer evidence".to_owned(),
            ));
        }
        let observed = observe_named_pipe_peer_process_in_job(
            handoff.process_binding.job.as_str(),
            handoff.process_binding.process.process_id,
        )
        .map_err(|e| KernelBuildError::Principal(e.to_string()))?;
        let observed_binding = observed.process_binding();
        if observed_binding.process_id() != handoff.process_binding.process.process_id
            || observed_binding.start_time_100ns()
                != handoff.process_binding.process.start_time_100ns
            || observed_binding.image_path() != handoff.process_binding.process.image_path
        {
            return Err(KernelBuildError::Principal(
                "Store rebind process binding does not match observed Job peer".to_owned(),
            ));
        }
        let expectation =
            eliot_platform_windows::NamedPipePeerExpectation::new_with_process_and_job_binding(
                handoff.requirement.expected_peer_sid.as_str(),
                handoff.requirement.expected_peer_session_id,
                observed,
            )
            .map_err(|e| KernelBuildError::Principal(e.to_string()))?;
        let _ = expectation;
        let timeout = Duration::from_millis(handoff.requirement.timeout_ms());
        let requirement = handoff.requirement.clone();
        let job = handoff.process_binding.job.clone();
        let process = handoff.process_binding.process.clone();
        let observed2 = observe_named_pipe_peer_process_in_job(job.as_str(), process.process_id)
            .map_err(|e| KernelBuildError::Principal(e.to_string()))?;
        if observed2.process_binding().process_id() != process.process_id
            || observed2.process_binding().start_time_100ns() != process.start_time_100ns
            || observed2.process_binding().image_path() != process.image_path
        {
            return Err(KernelBuildError::Principal(
                "Store rebind second observation mismatch".to_owned(),
            ));
        }
        let expectation2 =
            eliot_platform_windows::NamedPipePeerExpectation::new_with_process_and_job_binding(
                requirement.expected_peer_sid.as_str(),
                requirement.expected_peer_session_id,
                observed2,
            )
            .map_err(|e| KernelBuildError::Principal(e.to_string()))?;
        let transport = eliot_ipc::NamedPipeTransport::connect_authenticated(
            requirement.canonical_pipe_identity.as_str(),
            timeout,
            &expectation2,
        )
        .await
        .map_err(KernelBuildError::Transport)?;
        let client =
            eliot_kernel_service::EbpCanonicalStoreClient::connect(transport, requirement.clone())
                .await
                .map_err(|e| match e {
                    eliot_kernel_service::StoreClientError::Transport(e)
                    | eliot_kernel_service::StoreClientError::Contract(e) => {
                        KernelBuildError::Service(e)
                    }
                    eliot_kernel_service::StoreClientError::Store(e) => {
                        KernelBuildError::Service(e.to_string())
                    }
                })?;
        let route_scope = eliot_kernel_core::RouteScope::new(STORE_BRIDGE_ROUTE)
            .map_err(|e| KernelBuildError::Core(e.to_string()))?;
        let routes = self
            .generation_route_snapshot()
            .map_err(|e| KernelBuildError::Core(e.to_string()))?;
        let route = routes
            .route(&route_scope)
            .map_err(|e| KernelBuildError::Core(e.to_string()))?
            .clone();
        // Exact tuple equality is the authorization rule (Implements #64).
        if !route
            .authority_epoch()
            .is_same_authority(requirement.authority_epoch())
            || route.active_generation() != requirement.store_generation
            || requirement.route_identity.as_str() != STORE_BRIDGE_ROUTE
        {
            return Err(KernelBuildError::Core(
                "store rebind does not match active Kernel store route".to_owned(),
            ));
        }
        let requirement_digest = {
            let bytes = serde_json::to_vec(&handoff.requirement)
                .map_err(|e| KernelBuildError::Service(e.to_string()))?;
            format!("{:x}", Sha256::digest(&bytes))
        };
        let operation = eliot_ors::OperationIdentity::new(handoff.operation_id.as_str())
            .map_err(|e| KernelBuildError::Service(e.to_string()))?;
        let durable_replay = if let Some(existing) = self
            .generation_gateway
            .ors
            .load_store_rebind(&operation, &request_digest)
            .map_err(|e| KernelBuildError::Service(e.to_string()))?
        {
            if store_rebind_record_is_committed(
                &existing,
                &handoff,
                &request_digest,
                &requirement_digest,
            ) {
                if !is_store_rebind_latest_committed(&self.generation_gateway.ors, &existing)
                    .map_err(|e| KernelBuildError::Service(e.to_string()))?
                {
                    return Err(KernelBuildError::Service(
                        "Store rebind superseded by newer durable commit".to_owned(),
                    ));
                }
                Some(store_rebind_receipt_from_ors_record(
                    &existing,
                    &handoff.authority_epoch,
                )?)
            } else {
                if !store_rebind_record_matches(
                    &existing,
                    &handoff,
                    &request_digest,
                    &requirement_digest,
                ) {
                    return Err(KernelBuildError::Service(
                        "existing store rebind conflicts".to_owned(),
                    ));
                }
                None
            }
        } else {
            None
        };
        // A durable exact commit is the idempotence source of truth.  Check
        // it before requiring the volatile service to be Ready so a replay
        // after Kernel publication loss can recover from ORS rather than
        // treating the in-memory Degraded state as a conflicting operation.
        {
            let service = self
                .service
                .lock()
                .map_err(|_| KernelBuildError::Service("service lock poisoned".to_owned()))?;
            if service.state() != eliot_kernel_service::KernelServiceState::Ready
                && !(durable_replay.is_some()
                    && service.state() == eliot_kernel_service::KernelServiceState::Degraded)
            {
                return Err(KernelBuildError::Service(
                    "Store rebind requires Ready Kernel".to_owned(),
                ));
            }
            let candidate = service
                .candidate_binding()
                .ok_or(KernelBuildError::Service(
                    "Store rebind missing candidate".to_owned(),
                ))?;
            let expected = candidate
                .compute_digest()
                .map_err(|e| KernelBuildError::Service(e.to_string()))?;
            if expected != handoff.candidate_binding_digest {
                return Err(KernelBuildError::Service(
                    "Store rebind candidate binding mismatch".to_owned(),
                ));
            }
        }
        let gateway = std::sync::Arc::new(KernelStoreGateway::new(
            self.service.clone(),
            std::sync::Arc::new(client),
            route.clone(),
            // I14.21 (#1690): the rebind gateway recovers against the same
            // composition-retained Kernel ORS handle as the live gateway.
            Some(std::sync::Arc::clone(&self.generation_gateway.ors)),
        ));
        let receipt = {
            let mut svc = self
                .service
                .lock()
                .map_err(|_| KernelBuildError::Service("service lock poisoned".to_owned()))?;
            if durable_replay.is_none()
                && svc.state() != eliot_kernel_service::KernelServiceState::Ready
            {
                return Err(KernelBuildError::Service(
                    "Store rebind requires Ready Kernel (fence recheck)".to_owned(),
                ));
            }
            if svc.candidate_binding().is_some_and(|c| {
                c.compute_digest()
                    .is_ok_and(|d| d != handoff.candidate_binding_digest)
            }) {
                return Err(KernelBuildError::Service(
                    "Store rebind candidate binding mismatch (fence recheck)".to_owned(),
                ));
            }
            if let Some(restored) = durable_replay.clone() {
                svc.restore_store_rebind_for_replay(restored.clone(), request_digest.clone())
                    .map_err(|error| KernelBuildError::Service(error.to_string()))?;
                restored
            } else {
                svc.rebind_store(&handoff, request_digest.clone())
                    .map_err(|error| KernelBuildError::Service(error.to_string()))
                    .inspect_err(|_| gateway.fence())?
            }
        };
        // Close service admission before exposing the replacement gateway.
        // This ordering is the no-dual-writer fence: the old gateway remains
        // retained but cannot admit new work while ORS is being finalized.
        let attachment_result: Result<
            Box<dyn CanonicalStoreAttachmentTransaction>,
            KernelBuildError,
        > = self
            .process_gateway
            .as_ref()
            .map_or_else(
                || {
                    Err(KernelBuildError::Service(
                        "process authority is required before canonical Store rebind".to_owned(),
                    ))
                },
                |pg| {
                    pg.replace_canonical_store(Arc::clone(&gateway))
                        .map(|a| Box::new(a) as Box<dyn CanonicalStoreAttachmentTransaction>)
                        .map_err(|e| KernelBuildError::Service(e.to_string()))
                },
            )
            .inspect_err(|_| gateway.fence());
        let mut attachment = Some(match attachment_result {
            Ok(attachment) => attachment,
            Err(error) => {
                let mut service = self
                    .service
                    .lock()
                    .map_err(|_| KernelBuildError::Service("service lock poisoned".to_owned()))?;
                service.rollback_store_rebind_for_recovery_failure();
                return Err(error);
            }
        });
        if durable_replay.is_none() {
            let pending = eliot_ors::StoreRebindReplayRecord {
                operation_id: operation.clone(),
                request_digest: request_digest.clone(),
                candidate_binding_digest: handoff.candidate_binding_digest.clone(),
                store_fence: handoff.store_fence.clone(),
                requirement_digest: requirement_digest.clone(),
                process_id: handoff.process_binding.process.process_id,
                process_start_time_100ns: handoff.process_binding.process.start_time_100ns,
                process_image_path: handoff.process_binding.process.image_path.clone(),
                job_name: handoff.process_binding.job.as_str().to_owned(),
                generation: handoff.generation.value(),
                authority_epoch: handoff.authority_epoch.sequence.get(),
                state: eliot_ors::StoreRebindReplayState::Pending,
                receipt: None,
                commit_order: 0,
            };
            let begin_result = self.generation_gateway.ors.begin_store_rebind(&pending);
            if let Err(begin_error) = begin_result {
                let reconciled = self
                    .generation_gateway
                    .ors
                    .load_store_rebind(&operation, &request_digest);
                match reconciled {
                    Ok(Some(record))
                        if store_rebind_record_is_committed(
                            &record,
                            &handoff,
                            &request_digest,
                            &requirement_digest,
                        ) => {}
                    Ok(Some(record))
                        if store_rebind_record_is_pending(
                            &record,
                            &handoff,
                            &request_digest,
                            &requirement_digest,
                        ) =>
                    {
                        match self
                            .generation_gateway
                            .ors
                            .abort_store_rebind(&operation, &request_digest)
                        {
                            Ok(_) => {
                                let after_abort = match self
                                    .generation_gateway
                                    .ors
                                    .load_store_rebind(&operation, &request_digest)
                                {
                                    Ok(after_abort) => after_abort,
                                    Err(readback_error) => {
                                        Self::commit_store_rebind_attachment(&mut attachment);
                                        self.fence_store_rebind_runtime(
                                            &gateway,
                                            format!(
                                                "Store rebind abort readback failed: {readback_error}"
                                            ),
                                        )
                                        .await?;
                                        return Err(KernelBuildError::Service(format!(
                                            "Store rebind begin outcome is uncertain after abort: {begin_error}; abort readback: {readback_error}"
                                        )));
                                    }
                                };
                                match after_abort {
                                    None => {
                                        let mut service = self.service.lock().map_err(|_| {
                                            KernelBuildError::Service(
                                                "service lock poisoned".to_owned(),
                                            )
                                        })?;
                                        service.rollback_store_rebind_for_recovery_failure();
                                        return Err(KernelBuildError::Service(
                                            begin_error.to_string(),
                                        ));
                                    }
                                    Some(record)
                                        if store_rebind_record_is_committed(
                                            &record,
                                            &handoff,
                                            &request_digest,
                                            &requirement_digest,
                                        ) => {}
                                    Some(_) => {
                                        Self::commit_store_rebind_attachment(&mut attachment);
                                        self.fence_store_rebind_runtime(
                                        &gateway,
                                        format!(
                                            "Store rebind begin abort remained durable: {begin_error}"
                                        ),
                                    )
                                    .await?;
                                        return Err(KernelBuildError::Service(format!(
                                            "Store rebind begin outcome is uncertain after abort: {begin_error}"
                                        )));
                                    }
                                }
                            }
                            Err(abort_error) => {
                                Self::commit_store_rebind_attachment(&mut attachment);
                                self.fence_store_rebind_runtime(
                                &gateway,
                                format!(
                                    "Store rebind begin abort failed ({begin_error}): {abort_error}"
                                ),
                            )
                            .await?;
                                return Err(KernelBuildError::Service(format!(
                                    "Store rebind begin outcome is uncertain: {begin_error}; abort: {abort_error}"
                                )));
                            }
                        }
                    }
                    Ok(None) => {
                        let mut service = self.service.lock().map_err(|_| {
                            KernelBuildError::Service("service lock poisoned".to_owned())
                        })?;
                        service.rollback_store_rebind_for_recovery_failure();
                        return Err(KernelBuildError::Service(begin_error.to_string()));
                    }
                    Ok(Some(record)) => {
                        Self::commit_store_rebind_attachment(&mut attachment);
                        self.fence_store_rebind_runtime(
                            &gateway,
                            format!(
                                "Store rebind begin readback conflicted for {}",
                                record.operation_id.as_str()
                            ),
                        )
                        .await?;
                        return Err(KernelBuildError::Service(
                            "Store rebind begin readback conflicted".to_owned(),
                        ));
                    }
                    Err(readback_error) => {
                        Self::commit_store_rebind_attachment(&mut attachment);
                        self.fence_store_rebind_runtime(
                            &gateway,
                            format!(
                                "Store rebind begin readback failed ({begin_error}): {readback_error}"
                            ),
                        )
                        .await?;
                        return Err(KernelBuildError::Service(format!(
                            "Store rebind begin outcome is uncertain: {begin_error}; readback: {readback_error}"
                        )));
                    }
                }
            }
        }
        let committed_result = {
            let committed = eliot_ors::StoreRebindReplayRecord {
                operation_id: operation.clone(),
                request_digest: request_digest.clone(),
                candidate_binding_digest: handoff.candidate_binding_digest.clone(),
                store_fence: handoff.store_fence.clone(),
                requirement_digest: requirement_digest.clone(),
                process_id: handoff.process_binding.process.process_id,
                process_start_time_100ns: handoff.process_binding.process.start_time_100ns,
                process_image_path: handoff.process_binding.process.image_path.clone(),
                job_name: handoff.process_binding.job.as_str().to_owned(),
                generation: handoff.generation.value(),
                authority_epoch: handoff.authority_epoch.sequence.get(),
                state: eliot_ors::StoreRebindReplayState::Committed,
                receipt: Some(receipt.request_digest.clone()),
                commit_order: 0,
            };
            self.generation_gateway
                .ors
                .persist_store_rebind(&committed)
                .map_err(|error| KernelBuildError::Service(error.to_string()))
        };
        if let Err(error) = committed_result {
            let readback = self
                .generation_gateway
                .ors
                .load_store_rebind(&operation, &request_digest);
            match readback {
                Ok(Some(record))
                    if store_rebind_record_is_committed(
                        &record,
                        &handoff,
                        &request_digest,
                        &requirement_digest,
                    ) => {}
                Ok(Some(record))
                    if store_rebind_record_is_pending(
                        &record,
                        &handoff,
                        &request_digest,
                        &requirement_digest,
                    ) =>
                {
                    match self
                        .generation_gateway
                        .ors
                        .abort_store_rebind(&operation, &request_digest)
                    {
                        Ok(_) => {
                            let after_abort = self
                                .generation_gateway
                                .ors
                                .load_store_rebind(&operation, &request_digest);
                            match after_abort {
                                Ok(None) => {
                                    let mut service = self.service.lock().map_err(|_| {
                                        KernelBuildError::Service(
                                            "service lock poisoned".to_owned(),
                                        )
                                    })?;
                                    service.rollback_store_rebind_for_recovery_failure();
                                    return Err(error);
                                }
                                Ok(Some(after))
                                    if store_rebind_record_is_committed(
                                        &after,
                                        &handoff,
                                        &request_digest,
                                        &requirement_digest,
                                    ) => {}
                                Ok(Some(_)) => {
                                    Self::commit_store_rebind_attachment(&mut attachment);
                                    self.fence_store_rebind_runtime(
                                        &gateway,
                                        "Store rebind commit abort readback remained non-terminal",
                                    )
                                    .await?;
                                    return Err(KernelBuildError::Service(
                                        "Store rebind commit outcome is uncertain after abort"
                                            .to_owned(),
                                    ));
                                }
                                Err(readback_error) => {
                                    Self::commit_store_rebind_attachment(&mut attachment);
                                    self.fence_store_rebind_runtime(
                                    &gateway,
                                    format!(
                                        "Store rebind commit abort readback failed: {readback_error}"
                                    ),
                                )
                                    .await?;
                                    return Err(KernelBuildError::Service(format!(
                                        "Store rebind commit outcome is uncertain: {error}; abort readback: {readback_error}"
                                    )));
                                }
                            }
                        }
                        Err(abort_error) => {
                            Self::commit_store_rebind_attachment(&mut attachment);
                            self.fence_store_rebind_runtime(
                                &gateway,
                                format!(
                                    "Store rebind commit abort failed ({error}): {abort_error}"
                                ),
                            )
                            .await?;
                            return Err(KernelBuildError::Service(format!(
                                "Store rebind commit outcome is uncertain: {error}; abort: {abort_error}"
                            )));
                        }
                    }
                }
                Ok(None) => {
                    let mut service = self.service.lock().map_err(|_| {
                        KernelBuildError::Service("service lock poisoned".to_owned())
                    })?;
                    service.rollback_store_rebind_for_recovery_failure();
                    return Err(error);
                }
                Ok(Some(record)) => {
                    Self::commit_store_rebind_attachment(&mut attachment);
                    self.fence_store_rebind_runtime(
                        &gateway,
                        format!(
                            "Store rebind commit readback conflicted for {}",
                            record.operation_id.as_str()
                        ),
                    )
                    .await?;
                    return Err(KernelBuildError::Service(
                        "Store rebind commit readback conflicted".to_owned(),
                    ));
                }
                Err(readback_error) => {
                    Self::commit_store_rebind_attachment(&mut attachment);
                    self.fence_store_rebind_runtime(
                        &gateway,
                        format!("Store rebind commit readback failed ({error}): {readback_error}"),
                    )
                    .await?;
                    return Err(KernelBuildError::Service(format!(
                        "Store rebind commit outcome is uncertain: {error}; readback: {readback_error}"
                    )));
                }
            }
        }
        let service_commit_error = self
            .service
            .lock()
            .map(|mut service| {
                service
                    .commit_store_rebind()
                    .err()
                    .map(|error| error.to_string())
            })
            .map_err(|_| {
                KernelBuildError::Service("service lock poisoned after ORS commit".to_owned())
            });
        let service_commit_error = match service_commit_error {
            Ok(error) => error,
            Err(error) => {
                Self::commit_store_rebind_attachment(&mut attachment);
                self.fence_store_rebind_runtime(
                    &gateway,
                    "Store rebind service lock poisoned after ORS commit",
                )
                .await?;
                return Err(error);
            }
        };
        if let Some(error) = service_commit_error {
            Self::commit_store_rebind_attachment(&mut attachment);
            self.fence_store_rebind_runtime(
                &gateway,
                format!("Store rebind service commit publication failed: {error}"),
            )
            .await?;
            return Err(KernelBuildError::Service(error));
        }
        let old_gateway_for_drain = self
            .canonical_store_gateway
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();
        if let Some(old) = old_gateway_for_drain
            && !Arc::ptr_eq(&old, &gateway)
            && let Err(error) = old.fence_and_drain(Duration::from_secs(5)).await
        {
            Self::commit_store_rebind_attachment(&mut attachment);
            self.fence_store_rebind_runtime(
                &gateway,
                format!("Store rebind old gateway drain failed: {error}"),
            )
            .await?;
            return Err(KernelBuildError::Service(format!(
                "Store rebind old gateway drain failed: {error}"
            )));
        }
        let old_gateway =
            match (|| {
                let mut gw_guard = self.canonical_store_gateway.lock().map_err(|_| {
                    KernelBuildError::Service("store gateway lock poisoned".to_owned())
                })?;
                let mut handoff_guard = self.store_handoff.lock().map_err(|_| {
                    KernelBuildError::Service("Store handoff lock poisoned".to_owned())
                })?;
                let old = gw_guard.replace(Arc::clone(&gateway));
                *handoff_guard = Some(eliot_kernel_service::StoreBootstrapHandoff {
                    requirement: handoff.requirement.clone(),
                    process_binding: handoff.process_binding.clone(),
                });
                Ok::<Option<Arc<KernelStoreGateway>>, KernelBuildError>(old)
            })() {
                Ok(old) => old,
                Err(error) => {
                    Self::commit_store_rebind_attachment(&mut attachment);
                    let mut svc = self
                        .service
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner);
                    svc.fence_generation(format!("store rebind composition fenced: {error}"))
                        .map_err(|fence_error| {
                            KernelBuildError::Service(format!(
                                "store rebind composition fencing failed: {fence_error}"
                            ))
                        })?;
                    gateway.fence();
                    return Err(error);
                }
            };
        Self::commit_store_rebind_attachment(&mut attachment);
        if let Some(old) = old_gateway {
            old.fence();
        }
        Ok(receipt)
    }

    /// Returns whether Host/installation authority bindings were injected.
    /// The normal composition is intentionally not process-ready.
    #[must_use]
    pub fn process_execution_configured(&self) -> bool {
        self.process_gateway.is_some()
    }

    /// Returns the protected supervision authority only when Host injected a
    /// complete key reference and installation trust anchor.
    #[cfg(windows)]
    #[must_use]
    pub fn supervision_lease_authority(&self) -> Option<&KernelSupervisionLeaseAuthority> {
        self.supervision_lease_authority.as_deref()
    }

    /// Returns the platform surface owned by this composition.
    #[must_use]
    pub fn platform(&self) -> &WindowsPlatform {
        &self.platform
    }

    /// Structured startup status for one Governance Profile (Implements
    /// #1967). Reports the completed I1.11 step, the blocking prerequisite,
    /// degraded optional capabilities, and the current authority ceiling.
    /// Inspection views use this; they never gate on it.
    #[must_use]
    pub fn startup_status(&self, profile: GovernanceProfile) -> StartupStatus {
        self.startup_coordinator.lock().map_or_else(
            |poison| poison.into_inner().startup_status(profile),
            |coordinator| coordinator.startup_status(profile),
        )
    }

    /// Current authority ceiling for one Governance Profile. Incomplete ORS
    /// reconciliation, store schema probe, epoch recovery, or supervision
    /// evidence caps the ceiling at low-impact regardless of profile.
    #[must_use]
    pub fn startup_authority_ceiling(&self, profile: GovernanceProfile) -> AuthorityCeiling {
        self.startup_coordinator
            .lock()
            .map_or(AuthorityCeiling::LowImpact, |coordinator| {
                coordinator.authority_ceiling(profile)
            })
    }

    /// Material/Critical authority admission for one Governance Profile.
    /// Startup completeness is checked first with its named prerequisite;
    /// the profile ceiling alone decides once startup is complete.
    ///
    /// This is the startup-gate half of the Material decision and is the
    /// surface the origin-control decide path consults. It does not stand in
    /// for current independent Watchdog coverage: a protected effect that must
    /// be admitted as independently supervised additionally passes
    /// [`Self::admit_material_authority_for_fence`], which verifies the live
    /// Watchdog branch for the exact target fence.
    ///
    /// # Errors
    ///
    /// Returns the blocking [`StartupRejection`] or the profile-ceiling
    /// rejection as a platform error carrying the named prerequisite.
    pub fn admit_material_authority(
        &self,
        profile: GovernanceProfile,
    ) -> Result<(), KernelServiceError> {
        let coordinator = self
            .startup_coordinator
            .lock()
            .map_err(|_| KernelServiceError::Platform("startup gate lock poisoned".to_owned()))?;
        coordinator
            .admit_material_authority(profile)
            .map_err(|rejection| KernelServiceError::Platform(rejection.to_string()))
    }

    /// Normal canonical-write admission through the startup coordinator.
    /// Inspection remains allowed; a blocked write fails with the named
    /// unmet startup prerequisite.
    ///
    /// # Errors
    ///
    /// Returns the blocking [`StartupRejection`] naming the unmet
    /// prerequisite, or a lock-poison platform error.
    pub fn admit_normal_write(&self) -> Result<(), KernelServiceError> {
        let coordinator = self
            .startup_coordinator
            .lock()
            .map_err(|_| KernelServiceError::Platform("startup gate lock poisoned".to_owned()))?;
        coordinator
            .admit_normal_write()
            .map_err(|rejection| KernelServiceError::Platform(rejection.to_string()))
    }

    /// Validate the exact Kernel target fence before a protected effect.
    ///
    /// The fence is supplied by the authenticated route, never reconstructed
    /// from an operation payload.  This check is deliberately separate from
    /// the global startup cursor: a cursor can prove that prerequisites were
    /// observed, but it cannot stand in for current independent Watchdog
    /// coverage.  The verified current candidate binding is returned so the
    /// supervision check reuses this one read instead of taking the
    /// non-reentrant service lock twice.
    fn validate_material_target_fence(
        &self,
        target: &StateFence,
    ) -> Result<eliot_kernel_service::HostKernelCandidateBinding, KernelServiceError> {
        target
            .validate()
            .map_err(|error| KernelServiceError::Platform(error.to_string()))?;
        let service = self.service.lock().map_err(|_| {
            KernelServiceError::Platform("material target lock poisoned".to_owned())
        })?;
        if service.state() != KernelServiceState::Ready || service.generation_fenced() {
            return Err(KernelServiceError::Platform(
                "material target is not the current Ready Kernel generation".to_owned(),
            ));
        }
        let candidate = service.candidate_binding().ok_or_else(|| {
            KernelServiceError::Platform(
                "material target has no current candidate binding".to_owned(),
            )
        })?;
        let activation = service.activation_receipt().ok_or_else(|| {
            KernelServiceError::Platform(
                "material target has no current activation receipt".to_owned(),
            )
        })?;
        if candidate.kernel_epoch != target.authority_epoch
            || activation.generation != target.resource_generation
            || activation.authority_epoch != target.authority_epoch
        {
            return Err(KernelServiceError::Platform(
                "material target fence is not the current activation generation".to_owned(),
            ));
        }
        // The activation receipt is the authoritative live fence. Compare it
        // two-sidedly so a caller cannot smuggle a `task_revision`,
        // `policy_revision`, or `integration_revision` that Kernel never
        // issued: `is_compatible_with` treats the live side's `None` as a
        // wildcard, and only the reverse direction rejects that asymmetry.
        let live_fence = StateFence::new(activation.authority_epoch.clone(), activation.generation);
        if !eliot_contracts::fences_match_exact(target, &live_fence) {
            return Err(KernelServiceError::Platform(
                "material target fence carries revisions the current activation did not issue"
                    .to_owned(),
            ));
        }
        Ok(candidate.clone())
    }

    /// Material/Critical authority admission for one exact target fence.
    ///
    /// The decision has two independent halves. The first is mechanical: the
    /// presented fence must be the live, Ready, unfenced activation contour
    /// (see [`Self::validate_material_target_fence`]) and the profile ceiling
    /// must actually permit Material effects. The second is supervision: the
    /// independent Watchdog branch must currently verify. Only then is work
    /// admitted as independently supervised.
    ///
    /// A verified branch admits; an unverified branch pauses with the explicit
    /// `WATCHDOG_COVERAGE_UNAVAILABLE` degraded-profile refusal and the
    /// Human-risk path requirement. The supervision half reads the revocable
    /// I1.11 supervision step, never a latched cursor and never lease
    /// continuity alone.
    pub(crate) fn admit_material_authority_for_fence(
        &self,
        profile: GovernanceProfile,
        target: &StateFence,
    ) -> Result<(), KernelServiceError> {
        let candidate = self.validate_material_target_fence(target)?;
        if !matches!(
            profile.ceiling(),
            AuthorityCeiling::Material | AuthorityCeiling::Critical
        ) {
            return Err(KernelServiceError::Platform(
                "material authority refused: governance profile does not permit Material effects"
                    .to_owned(),
            ));
        }
        self.verify_watchdog_supervision_branch(&candidate, target)
            .map_err(|reason| {
                KernelServiceError::Platform(format!(
                    "{}: {reason}; Material/Critical work is paused under runtime-degraded-v3 and requires the explicit Human-risk path",
                    eliot_kernel_service::ProcessExecutionRejection::WATCHDOG_COVERAGE_UNAVAILABLE
                ))
            })
    }

    /// Admits one Host-observed Watchdog branch observation for the exact
    /// candidate contour it was probed under, and records the I1.11 supervision
    /// step from it.
    ///
    /// This consumes the existing `HostStartupEvidence` carrier. Host already
    /// revalidates the live SCM Watchdog incarnation when it builds that
    /// carrier: the bound PID/start pair must still be live in the OS and the
    /// live image bytes must still hash to the approved Watchdog artifact.
    /// Kernel binds that observation to the presented candidate, to the exact
    /// State Fence it was observed under, and to its own Watchdog epoch, and
    /// only then marks the supervision step with that observation's own
    /// observation time and a finite validity interval. The step is revocable,
    /// so a new activation contour is unverified again until Host observes the
    /// branch under that contour, and the observation stops verifying once it
    /// leaves its validity interval. Coverage is never re-derived from lease
    /// continuity or `eliotd` self-report.
    ///
    /// # Errors
    ///
    /// Returns a platform error when the carrier is not exactly bound to the
    /// presented candidate, when the probe fence is not the presented target
    /// fence, when the supervision incarnation has no non-zero Watchdog epoch,
    /// when the SCM Watchdog incarnation digest is not a well-formed live
    /// observation, or when this observation contradicts the recorded one under
    /// the same contour and fence.
    #[cfg(windows)]
    pub(crate) fn admit_host_observed_watchdog_branch(
        &self,
        evidence: &HostStartupEvidence,
        candidate: &eliot_kernel_service::HostKernelCandidateBinding,
        target: &StateFence,
    ) -> Result<(), KernelServiceError> {
        let candidate_digest = candidate.compute_digest().map_err(|_| {
            KernelServiceError::Platform(
                "Watchdog branch observation candidate has no computable digest".to_owned(),
            )
        })?;
        if evidence.candidate_digest != candidate_digest
            || evidence.state_fence != *target
            || !eliot_contracts::fences_match_exact(&evidence.state_fence, target)
        {
            return Err(KernelServiceError::Platform(
                "Host Watchdog branch observation is not bound to the presented candidate contour"
                    .to_owned(),
            ));
        }
        let incarnation = &candidate.supervision_incarnation;
        if incarnation.watchdog_epoch.sequence == 0 {
            return Err(KernelServiceError::Platform(
                "Host Watchdog branch observation has no non-zero Watchdog epoch".to_owned(),
            ));
        }
        verify_scm_watchdog_observation_shape(&evidence.scm_watchdog_observation_digest)
            .map_err(|reason| KernelServiceError::Platform(reason.to_owned()))?;
        let candidate_digest =
            eliot_platform::PlatformHandle::new(candidate_digest).map_err(|_| {
                KernelServiceError::Platform(
                    "Watchdog branch observation candidate digest is not a valid handle".to_owned(),
                )
            })?;
        self.record_host_observed_supervision_evidence(
            &evidence.scm_watchdog_observation_digest,
            &candidate_digest,
            &evidence.state_fence,
            &incarnation.watchdog_epoch,
        )
    }

    /// Probe/readiness admission for the independent Watchdog branch.
    ///
    /// I1.5 (#1750) and I1.11 steps 1/11: Host validates the independent
    /// Watchdog service state through SCM, so a readiness receipt may only be
    /// authored for a contour whose branch Kernel can currently prove. The
    /// proof is a conjunction:
    ///
    /// 1. the independent Watchdog observation Host published for THIS contour
    ///    is still recorded, still bound to this exact candidate contour, and
    ///    still bound to the exact consumer State Fence being presented;
    /// 2. that observation is still inside the finite validity interval its own
    ///    observation time opens, so an observation that was current at startup
    ///    cannot authorize supervised readiness indefinitely; and
    /// 3. the whole supervised-branch verification
    ///    ([`Self::verify_watchdog_supervision_branch`]) succeeds, including the
    ///    two-sided join of the observed Watchdog epoch to the current signed
    ///    `Active` lease.
    ///
    /// This is deliberately NOT a lease-derived watchdog-epoch equality, and it
    /// is not a re-read of retained text: a renewed signed lease advances
    /// neither the observation time nor the progress frontier, so a contour whose
    /// branch was never observed, or whose observation has aged out, does not
    /// verify. What these predicates establish is a claim about the freshness
    /// and binding of the evidence they consume — not that they distinguish, on
    /// their own, every stopped, replaced or wedged Watchdog state inside one
    /// still-valid observation window.
    ///
    /// # Errors
    ///
    /// Returns a platform error naming the exact observation fact that no
    /// longer holds, or the exact supervision fact that failed to verify.
    #[cfg(windows)]
    pub(crate) fn admit_probe_watchdog_branch(
        &self,
        candidate: &eliot_kernel_service::HostKernelCandidateBinding,
        target: &StateFence,
    ) -> Result<(), KernelServiceError> {
        let candidate_digest = candidate.compute_digest().map_err(|_| {
            KernelServiceError::Platform(
                "readiness refused: the presented candidate contour has no computable digest"
                    .to_owned(),
            )
        })?;
        // Freshness, contour binding and fence binding are decided here, at the
        // probe, against the same observation record the supervised branch is
        // verified from — so a probe cannot author a ready receipt on an
        // observation that has already expired or belongs to another contour or
        // fence.
        //
        // This is a gate, not a value producer: the observed Watchdog epoch it
        // reads is deliberately not bound here. `verify_watchdog_supervision_branch`
        // re-reads the same record itself and joins the epoch to the signed
        // lease, so binding it at this call site would produce a value nothing
        // consumes.
        self.startup_coordinator
            .lock()
            .map_err(|_| KernelServiceError::Platform("startup gate lock poisoned".to_owned()))?
            .admit_supervision_observation(candidate_digest.as_str(), target, unix_ms())
            .map_err(|reason| {
                KernelServiceError::Platform(format!(
                    "readiness refused: {reason}; no current independent Watchdog observation is bound to this contour and fence, supervised readiness is withheld and the contour stays degraded"
                ))
            })?;
        self.verify_watchdog_supervision_branch(candidate, target)
            .map_err(|reason| {
                KernelServiceError::Platform(format!(
                    "readiness refused: {reason}; supervised readiness is withheld and the contour stays degraded"
                ))
            })
    }

    /// Revokes the recorded independent-supervision evidence at the one
    /// owner-correct moment it can no longer describe the live contour: a new
    /// candidate activation is admitted (I1.5).
    ///
    /// A previously verified Watchdog branch belonged to the previous
    /// activation generation, host epoch, and Watchdog epoch. Admitting a new
    /// contour therefore withdraws the claim until Host observes the branch
    /// again under that contour. This never un-observes an earlier I1.11 step
    /// and never grants anything.
    ///
    /// # Errors
    ///
    /// Returns a lock-poison platform error.
    pub(crate) fn revoke_supervision_evidence(&self) -> Result<(), KernelServiceError> {
        let mut coordinator = self
            .startup_coordinator
            .lock()
            .map_err(|_| KernelServiceError::Platform("startup gate lock poisoned".to_owned()))?;
        coordinator.revoke_supervision_evidence();
        Ok(())
    }

    /// Admits a process `Start` admission under Material/Critical authority.
    ///
    /// The target fence is derived from the already-validated admission, never
    /// from caller-supplied loose fields, so the front-door path and the
    /// dispatch-launch path cannot drift into checking different generations.
    /// This performs no external effect and never retries.
    pub(crate) fn admit_material_process_start(
        &self,
        admission: &eliot_process::ProcessExecutionAdmissionRequest,
    ) -> Result<(), KernelServiceError> {
        let target_generation =
            eliot_contracts::ResourceGeneration::new(admission.state_fence().generation().get())
                .map_err(|error| KernelServiceError::Platform(error.to_string()))?;
        let target_fence = StateFence::new(
            admission.state_fence().authority_epoch().clone(),
            target_generation,
        );
        self.admit_material_authority_for_fence(GovernanceProfile::full(), &target_fence)
    }

    /// Records one real owner-produced I1.11 evidence item. Out-of-order
    /// evidence is retained without advancing the contiguous readiness cursor;
    /// missing earlier steps therefore remain blocking and cannot be inferred
    /// from a later successful probe.
    ///
    /// I1.11 step 11 is the supervision step. It is not reachable here: a
    /// signed lease, a successful process handshake, or `ProbeReady` alone is
    /// lease continuity, not an independent Watchdog observation. The only
    /// production producer is
    /// [`Self::record_host_observed_supervision_evidence`], which runs only
    /// after `admit_host_observed_watchdog_branch` accepted a live SCM
    /// Watchdog incarnation for the presented contour.
    pub(crate) fn record_startup_evidence(&self, step: u8) -> Result<(), KernelServiceError> {
        if step == STARTUP_FINAL_STEP {
            return Err(KernelServiceError::Platform(
                "startup step 11 requires an independent Host-observed Watchdog signal".to_owned(),
            ));
        }
        self.record_startup_evidence_inner(step)
    }

    /// Records the I1.11 supervision step from one verified independent
    /// Watchdog branch observation.
    ///
    /// This is the sole production producer of [`STARTUP_FINAL_STEP`] and of
    /// the supervision progress frontier. The caller must have just accepted an
    /// independent Watchdog observation bound to the presented candidate
    /// contour, its exact consumer State Fence and its own Watchdog epoch; the
    /// observation is retained with all of those bindings plus the moment it was
    /// accepted, so a later admission proves the claim came from that
    /// observation and not from lease bookkeeping. The step is revocable, so a
    /// later contour change keeps Material/Critical admission closed until Host
    /// observes the branch again, and the observation stops verifying when it
    /// leaves its finite validity interval.
    ///
    /// # Errors
    ///
    /// Returns a lock-poison platform error, the coordinator's fixed-shape
    /// reason for a malformed carrier or a zero validity interval, or the
    /// contradiction reason when this observation disagrees with the recorded
    /// one under the same contour and fence.
    #[cfg(windows)]
    pub(crate) fn record_host_observed_supervision_evidence(
        &self,
        incarnation: &eliot_platform::PlatformHandle,
        candidate_digest: &eliot_platform::PlatformHandle,
        state_fence: &StateFence,
        watchdog_epoch: &eliot_runtime_contracts::SupervisionJournalEpoch,
    ) -> Result<(), KernelServiceError> {
        let mut coordinator = self
            .startup_coordinator
            .lock()
            .map_err(|_| KernelServiceError::Platform("startup gate lock poisoned".to_owned()))?;
        coordinator
            .record_live_supervision_evidence(
                incarnation.clone(),
                candidate_digest.clone(),
                state_fence.clone(),
                watchdog_epoch.clone(),
                unix_ms(),
                // I1.5 (#1750): the finite freshness interval is not a new
                // constant. `SUPERVISION_LEASE_RENEWAL_POLICY` is the single
                // timing owner for supervision and already declares
                // `max_observation_age_ms`; reusing it keeps one clock and one
                // bound for a supervision claim, and the comment on that policy
                // forbids reintroducing a parallel bound beside it.
                SUPERVISION_LEASE_RENEWAL_POLICY.max_observation_age_ms,
            )
            .map_err(KernelServiceError::Platform)
    }

    /// Ordered I1.11 cursor update shared by the general and
    /// supervision-only producers.
    fn record_startup_evidence_inner(&self, step: u8) -> Result<(), KernelServiceError> {
        let mut coordinator = self
            .startup_coordinator
            .lock()
            .map_err(|_| KernelServiceError::Platform("startup gate lock poisoned".to_owned()))?;
        coordinator
            .record_live_evidence(step)
            .map_err(KernelServiceError::Platform)
    }

    /// Records blob large-payload degradation (I1.11 step 4). Never blocks
    /// Material by itself; it is reported in startup status.
    pub fn note_startup_blob_degraded(&self) -> Result<(), KernelServiceError> {
        let mut coordinator = self
            .startup_coordinator
            .lock()
            .map_err(|_| KernelServiceError::Platform("startup gate lock poisoned".to_owned()))?;
        coordinator.note_blob_degraded();
        Ok(())
    }

    /// Records optional-capability degradation (I1.11 step 9). Never blocks
    /// Material by itself; it is reported in startup status.
    pub fn note_startup_capability_degraded(&self) -> Result<(), KernelServiceError> {
        let mut coordinator = self
            .startup_coordinator
            .lock()
            .map_err(|_| KernelServiceError::Platform("startup gate lock poisoned".to_owned()))?;
        coordinator.note_capability_degraded();
        Ok(())
    }

    #[cfg(test)]
    fn poison_generation_for_test(&self) {
        let Ok(mut generation_poison) = self.generation_poison.lock() else {
            panic!("generation poison lock");
        };
        *generation_poison = Some("test publication failure".to_owned());
        if let Ok(mut service) = self.service.lock() {
            service
                .fence_generation("test publication failure")
                .unwrap_or_else(|_| unreachable!());
        }
    }

    /// Builds the correlated response frame for one process operation.
    pub fn process_response_frame(
        &self,
        session: &Session,
        request_id: RequestId,
        response: &ProcessExecutionResponse,
    ) -> Result<Frame, TransportError> {
        let mut frame = status_frame(
            session,
            FrameKind::Response,
            MessageType::Result,
            serde_json::to_value(response).map_err(|_| TransportError::SessionFenced)?,
        )?;
        frame.request_id = Some(request_id);
        frame.validate()?;
        Ok(frame)
    }

    #[cfg(windows)]
    fn daemon_supervision_contour(
        &self,
        session: &Session,
        process: &ProcessStartReceipt,
    ) -> Result<DaemonSupervisionContour, KernelServiceError> {
        process
            .validate()
            .map_err(|_| KernelServiceError::ReadinessNotProven)?;
        let (candidate, activation) = {
            let service = self
                .service
                .lock()
                .map_err(|_| KernelServiceError::Platform("service lock poisoned".to_owned()))?;
            let candidate = service
                .candidate_binding()
                .cloned()
                .ok_or(KernelServiceError::ReadinessNotProven)?;
            let activation = service
                .activation_receipt()
                .cloned()
                .ok_or(KernelServiceError::ReadinessNotProven)?;
            (candidate, activation)
        };
        candidate
            .validate()
            .map_err(|_| KernelServiceError::ReadinessNotProven)?;
        candidate
            .supervision_incarnation
            .validate()
            .map_err(|_| KernelServiceError::ReadinessNotProven)?;
        let candidate_digest = candidate
            .compute_digest()
            .map_err(|_| KernelServiceError::ReadinessNotProven)?;
        if activation.candidate_binding_digest != candidate_digest
            || activation.authority_epoch != candidate.kernel_epoch
            || session.module_generation.module_id.as_str() != ACTIVE_DAEMON_CALLER
            || !session
                .authority_epoch
                .is_same_authority(&activation.authority_epoch)
            || session.module_generation.generation != activation.generation
            || process.accepted_generation().get() != session.module_generation.generation.value()
        {
            return Err(KernelServiceError::ReadinessNotProven);
        }
        let state_fence =
            StateFence::new(activation.authority_epoch.clone(), activation.generation);
        if session.module_generation.state_fence != state_fence {
            return Err(KernelServiceError::ReadinessNotProven);
        }
        let authority = self
            .supervision_lease_authority
            .as_ref()
            .ok_or(KernelServiceError::ReadinessNotProven)?;
        if authority.supervision_lease_scope_id()
            != candidate.supervision_incarnation.supervision_lease_scope_id
        {
            return Err(KernelServiceError::ReadinessNotProven);
        }
        let physical = process.identity().physical();
        let generation_binding = SupervisionGenerationBinding {
            target_id: session.module_generation.artifact_id.as_str().to_owned(),
            target_generation: session.module_generation.generation,
            module_id: session.module_generation.module_id.as_str().to_owned(),
            module_generation: session.module_generation.generation,
            process_id: format!(
                "pid:{}:start:{}",
                physical.process_id(),
                physical.start_time_100ns()
            ),
            process_generation: ResourceGeneration::new(process.accepted_generation().get())
                .map_err(|_| KernelServiceError::ReadinessNotProven)?,
        };
        Ok(DaemonSupervisionContour {
            candidate_digest,
            incarnation: candidate.supervision_incarnation,
            activation,
            generation_binding,
            state_fence,
        })
    }

    #[cfg(windows)]
    fn active_supervision_binding(
        contour: &DaemonSupervisionContour,
        issued_at_ms: u64,
        policy: &DaemonSupervisionRenewalPolicy,
    ) -> Result<eliot_ors::SupervisionLeaseBinding, SupervisionLeaseAuthorityError> {
        if issued_at_ms == 0 {
            return Err(SupervisionLeaseAuthorityError::Configuration(
                "supervision issue time is zero".to_owned(),
            ));
        }
        policy.validate().map_err(|error| {
            SupervisionLeaseAuthorityError::Configuration(format!(
                "supervision renewal policy rejected: {error}"
            ))
        })?;
        let expires_at_ms = issued_at_ms
            .checked_add(policy.validity_ms)
            .ok_or_else(|| {
                SupervisionLeaseAuthorityError::Configuration(
                    "supervision validity interval overflowed".to_owned(),
                )
            })?;
        let renew_before_ms = issued_at_ms
            .checked_add(policy.renew_after_ms)
            .ok_or_else(|| {
                SupervisionLeaseAuthorityError::Configuration(
                    "supervision renewal interval overflowed".to_owned(),
                )
            })?;
        let incarnation = &contour.incarnation;
        Ok(eliot_ors::SupervisionLeaseBinding {
            scope_ref: OperationIdentity::new(
                incarnation
                    .derived_scope_ref()
                    .map_err(|error| SupervisionLeaseAuthorityError::Contract(error.to_string()))?,
            )?,
            observation_scope: incarnation.observation_scope.clone(),
            installation_id: OperationIdentity::new(incarnation.installation_id.clone())?,
            host_epoch: AuthorityEpoch::new(incarnation.host_epoch.sequence)
                .map_err(|error| SupervisionLeaseAuthorityError::Contract(error.to_string()))?,
            activation_id: OperationIdentity::new(incarnation.activation_id.clone())?,
            activation_generation: contour.activation.generation,
            kernel_epoch: contour.activation.authority_epoch.clone(),
            watchdog_epoch: AuthorityEpoch::new(incarnation.watchdog_epoch.sequence)
                .map_err(|error| SupervisionLeaseAuthorityError::Contract(error.to_string()))?,
            generation_binding: contour.generation_binding.clone(),
            state_fence: contour.state_fence.clone(),
            issued_at_ms,
            expires_at_ms,
            renew_before_ms,
            wake_policy: incarnation.wake_policy.clone(),
            state: LeaseState::Active,
            terminal_disposition: None,
            revocation_reason: None,
            revocation_id: None,
            revocation_epoch: None,
        })
    }

    #[cfg(windows)]
    fn supersede_predecessor(
        authority: &KernelSupervisionLeaseAuthority,
        contour: &DaemonSupervisionContour,
    ) -> Result<(), SupervisionLeaseAuthorityError> {
        let Some(predecessor) = contour.incarnation.predecessor.as_ref() else {
            return Ok(());
        };
        predecessor
            .validate()
            .map_err(|error| SupervisionLeaseAuthorityError::Contract(error.to_string()))?;
        let current = authority
            .current_snapshot(&predecessor.supervision_lease_id)?
            .ok_or(SupervisionLeaseAuthorityError::Ors(
                OrsError::SupervisionLeaseBindingMismatch,
            ))?;
        current
            .validate()
            .map_err(SupervisionLeaseAuthorityError::Ors)?;
        if current.record.state == LeaseState::Superseded
            && current.record.projection == eliot_ors::SupervisionLeaseProjection::Terminal
            && current
                .record
                .artifact
                .payload
                .ors_mirror
                .previous_receipt_sha256
                .as_deref()
                == Some(predecessor.ors_receipt_sha256.as_str())
        {
            return authority.verify_superseded_replay(&current, predecessor);
        }
        if current.record.state != LeaseState::Active
            || current.record.projection != eliot_ors::SupervisionLeaseProjection::Active
            || current.receipt.receipt_sha256 != predecessor.ors_receipt_sha256
        {
            return Err(SupervisionLeaseAuthorityError::Ors(
                OrsError::SupervisionLeaseBindingMismatch,
            ));
        }
        let stage = if let Some(stage) =
            authority.staged_snapshot(&predecessor.supervision_lease_id)?
        {
            if stage.ticket.operation != SupervisionLeaseOperation::Supersede
                || stage.ticket.expected_revision != Some(current.record.revision)
                || stage.ticket.previous_receipt_sha256.as_deref()
                    != Some(predecessor.ors_receipt_sha256.as_str())
                || stage.ticket.binding.state != LeaseState::Superseded
                || stage.ticket.binding.terminal_disposition
                    != Some(SupervisionLeaseTerminalDisposition::Superseded)
            {
                return Err(SupervisionLeaseAuthorityError::Ors(
                    OrsError::SupervisionLeaseTicketConflict,
                ));
            }
            stage
        } else {
            let mut binding = current.record.binding.clone();
            binding.state = LeaseState::Superseded;
            binding.terminal_disposition = Some(SupervisionLeaseTerminalDisposition::Superseded);
            let ticket_id = supervision_operation_identity(
                "supersede-ticket",
                &predecessor.supervision_lease_id,
                Some(&predecessor.ors_receipt_sha256),
            )?;
            authority.prepare(SupervisionLeasePrepareRequest {
                operation_id: supervision_operation_identity(
                    "supersede-operation",
                    &predecessor.supervision_lease_id,
                    Some(&predecessor.ors_receipt_sha256),
                )?,
                ticket_id,
                lease_id: OperationIdentity::new(predecessor.supervision_lease_id.clone())?,
                expected_revision: Some(current.record.revision),
                operation: SupervisionLeaseOperation::Supersede,
                binding,
            })?
        };
        let terminal = authority.commit_terminal(&stage.ticket)?;
        if terminal.record.state != LeaseState::Superseded
            || terminal.record.projection != eliot_ors::SupervisionLeaseProjection::Terminal
            || terminal
                .record
                .artifact
                .payload
                .ors_mirror
                .previous_receipt_sha256
                .as_deref()
                != Some(predecessor.ors_receipt_sha256.as_str())
        {
            return Err(SupervisionLeaseAuthorityError::Ors(
                OrsError::SupervisionLeaseBindingMismatch,
            ));
        }
        authority.verify_superseded_replay(&terminal, predecessor)
    }

    #[cfg(windows)]
    fn commit_or_replay_active_supervision(
        authority: &KernelSupervisionLeaseAuthority,
        contour: &DaemonSupervisionContour,
        now_ms: u64,
    ) -> Result<SupervisionLeaseSnapshot, SupervisionLeaseAuthorityError> {
        let lease_id = contour.incarnation.supervision_lease_id.as_str();
        Self::supersede_predecessor(authority, contour)?;
        if let Some(current) = authority.current_snapshot(lease_id)? {
            authority.verify_active_snapshot(&current, lease_id, now_ms)?;
            if !supervision_binding_matches_contour(&current.record.binding, contour)? {
                return Err(SupervisionLeaseAuthorityError::Ors(
                    OrsError::SupervisionLeaseBindingMismatch,
                ));
            }
            return Ok(current);
        }
        let stage = if let Some(stage) = authority.staged_snapshot(lease_id)? {
            if stage.ticket.operation != SupervisionLeaseOperation::Commit
                || stage.ticket.expected_revision.is_some()
                || stage.ticket.binding.state != LeaseState::Active
                || !supervision_binding_matches_contour(&stage.ticket.binding, contour)?
                || now_ms >= stage.ticket.binding.expires_at_ms
            {
                return Err(SupervisionLeaseAuthorityError::Ors(
                    OrsError::SupervisionLeaseTicketConflict,
                ));
            }
            stage
        } else {
            let binding = Self::active_supervision_binding(
                contour,
                now_ms,
                &SUPERVISION_LEASE_RENEWAL_POLICY,
            )?;
            authority.prepare(SupervisionLeasePrepareRequest {
                ticket_id: supervision_operation_identity("commit-ticket", lease_id, None)?,
                operation_id: supervision_operation_identity("commit-operation", lease_id, None)?,
                lease_id: OperationIdentity::new(lease_id.to_owned())?,
                expected_revision: None,
                operation: SupervisionLeaseOperation::Commit,
                binding,
            })?
        };
        let current = authority.commit_active(&stage.ticket)?;
        authority.verify_active_snapshot(&current, lease_id, now_ms)?;
        if !supervision_binding_matches_contour(&current.record.binding, contour)? {
            return Err(SupervisionLeaseAuthorityError::Ors(
                OrsError::SupervisionLeaseBindingMismatch,
            ));
        }
        Ok(current)
    }

    /// Renews the exact active supervision lease from process continuity when
    /// no admitted progress observation is available. This preserves the
    /// front-door lease only; it never records I1.11 step 11 or grants
    /// Material authority.
    #[cfg(windows)]
    fn renew_current_supervision(
        authority: &KernelSupervisionLeaseAuthority,
        contour: &DaemonSupervisionContour,
        now_ms: u64,
    ) -> Result<SupervisionLeaseSnapshot, SupervisionLeaseAuthorityError> {
        let lease_id = contour.incarnation.supervision_lease_id.as_str();
        let current =
            authority
                .current_snapshot(lease_id)?
                .ok_or(SupervisionLeaseAuthorityError::Ors(
                    OrsError::SupervisionLeaseBindingMismatch,
                ))?;
        authority.verify_active_snapshot(&current, lease_id, now_ms)?;
        if !supervision_binding_matches_contour(&current.record.binding, contour)? {
            return Err(SupervisionLeaseAuthorityError::Ors(
                OrsError::SupervisionLeaseBindingMismatch,
            ));
        }
        if now_ms < current.record.binding.renew_before_ms {
            return Ok(current);
        }
        let stage = if let Some(stage) = authority.staged_snapshot(lease_id)? {
            if stage.ticket.operation != SupervisionLeaseOperation::Renew
                || stage.ticket.expected_revision != Some(current.record.revision)
                || stage.ticket.previous_receipt_sha256.as_deref()
                    != Some(current.receipt.receipt_sha256.as_str())
                || stage.ticket.binding.state != LeaseState::Active
                || !supervision_binding_matches_contour(&stage.ticket.binding, contour)?
                || now_ms >= stage.ticket.binding.expires_at_ms
            {
                return Err(SupervisionLeaseAuthorityError::Ors(
                    OrsError::SupervisionLeaseTicketConflict,
                ));
            }
            stage
        } else {
            let binding = Self::active_supervision_binding(
                contour,
                now_ms,
                &SUPERVISION_LEASE_RENEWAL_POLICY,
            )?;
            authority.prepare(SupervisionLeasePrepareRequest {
                ticket_id: supervision_operation_identity(
                    "renew-ticket",
                    lease_id,
                    Some(&current.receipt.receipt_sha256),
                )?,
                operation_id: supervision_operation_identity(
                    "renew-operation",
                    lease_id,
                    Some(&current.receipt.receipt_sha256),
                )?,
                lease_id: OperationIdentity::new(lease_id.to_owned())?,
                expected_revision: Some(current.record.revision),
                operation: SupervisionLeaseOperation::Renew,
                binding,
            })?
        };
        let renewed = authority.commit_active(&stage.ticket)?;
        authority.verify_active_snapshot(&renewed, lease_id, now_ms)?;
        if renewed.record.revision <= current.record.revision
            || !supervision_binding_matches_contour(&renewed.record.binding, contour)?
        {
            return Err(SupervisionLeaseAuthorityError::Ors(
                OrsError::SupervisionLeaseBindingMismatch,
            ));
        }
        Ok(renewed)
    }

    /// Pure progress-renewal decision (issue #88, wave 2): joins one daemon
    /// observation request against the exact Kernel current state through the
    /// single timing owner, and advances Kernel-owned progress continuity.
    ///
    /// Check order: owner policy coherence, stale-cursor horizon (expired
    /// leases never auto-revive, even for eligible observations), Kernel
    /// binding pinning from shape-valid observations only, then the contract
    /// join. `Renewed` records nothing here: the caller records via
    /// [`DaemonSupervisionProgressState::record_renewed`] only after the ORS
    /// commit and post-verify both succeed. Every other non-renewing outcome
    /// updates continuity (`DegradedNoRenewal` and join refusals count a
    /// miss; `ReconciliationRequired` latches the flag; `NotDue` and exact
    /// replay change nothing). `StoreHealth` never reaches this route: it
    /// carries no observation identity and fails request validation.
    #[cfg(windows)]
    pub(crate) fn decide_daemon_supervision_progress_renewal(
        request: &DaemonSupervisionRenewalRequest,
        current: &DaemonSupervisionCurrentState,
        progress: &mut DaemonSupervisionProgressState,
        policy: &DaemonSupervisionRenewalPolicy,
        now_ms: u64,
    ) -> Result<DaemonSupervisionRenewalDecision, SupervisionProgressRenewalError> {
        policy.validate().map_err(|error| {
            SupervisionProgressRenewalError::Authority(
                SupervisionLeaseAuthorityError::Configuration(format!(
                    "supervision renewal policy rejected: {error}"
                )),
            )
        })?;
        if progress.stale_renewal_expired(policy, now_ms) {
            return Err(DaemonSupervisionHeartbeatError::SupervisionLeaseExpired.into());
        }
        if request.observation.validate().is_ok() {
            progress.admit_boot_session_binding(&request.observation);
            progress.advance_monotonic_ms(request.observation.observed_monotonic_ms);
        }
        let decision = match evaluate_daemon_supervision_renewal(request, current, policy, now_ms) {
            Ok(decision) => decision,
            Err(error) => {
                progress.note_missed_renewal();
                if progress.stale_renewal_expired(policy, now_ms) {
                    return Err(DaemonSupervisionHeartbeatError::SupervisionLeaseExpired.into());
                }
                return Err(error.into());
            }
        };
        match decision.outcome {
            DaemonSupervisionRenewalOutcome::Renewed
            | DaemonSupervisionRenewalOutcome::ExactReplay
            | DaemonSupervisionRenewalOutcome::NotDue => {}
            DaemonSupervisionRenewalOutcome::DegradedNoRenewal => {
                progress.note_missed_renewal();
                if progress.stale_renewal_expired(policy, now_ms) {
                    return Err(DaemonSupervisionHeartbeatError::SupervisionLeaseExpired.into());
                }
            }
            DaemonSupervisionRenewalOutcome::ReconciliationRequired => {
                progress.note_reconciliation_pending();
            }
        }
        Ok(decision)
    }

    /// Typed progress renewal entry (issue #88, wave 3): renews the current
    /// supervision lease from an observed daemon progress request, not from
    /// `StoreHealth`.
    ///
    /// The entry loads the exact ORS predecessor, surfaces natural expiry
    /// with the typed refusal before signature work, checks the contour
    /// binding, builds the join state from the exact predecessor plus
    /// Kernel-owned continuity, decides through the single timing owner,
    /// and commits exactly one successor on `Renewed` (resuming the exact
    /// staged ticket when one is already staged, i.e. reconcile-by-identity).
    /// A failed commit latches reconciliation-pending and propagates, so an
    /// unknown durable outcome never mints a second successor. Non-renewing
    /// decisions return the unchanged head with their complete receipt and no
    /// commit. On `Renewed` the receipt is `None` by construction: the caller
    /// completes it with the committed successor receipt digest plus the
    /// published live-receipt digest via `daemon_renewal_receipt_for_decision`
    /// after live-receipt publication, so a renewal can never ship without
    /// its publication evidence.
    #[cfg(windows)]
    fn renew_current_supervision_with_progress(
        authority: &KernelSupervisionLeaseAuthority,
        contour: &DaemonSupervisionContour,
        request: &DaemonSupervisionRenewalRequest,
        progress: &mut DaemonSupervisionProgressState,
        policy: &DaemonSupervisionRenewalPolicy,
        now_ms: u64,
    ) -> Result<
        (
            SupervisionLeaseSnapshot,
            DaemonSupervisionRenewalDecision,
            Option<DaemonSupervisionRenewalReceipt>,
        ),
        SupervisionProgressRenewalError,
    > {
        let lease_id = contour.incarnation.supervision_lease_id.as_str();
        let current_snapshot =
            authority
                .current_snapshot(lease_id)?
                .ok_or(SupervisionLeaseAuthorityError::Ors(
                    OrsError::SupervisionLeaseBindingMismatch,
                ))?;
        if now_ms >= current_snapshot.record.binding.expires_at_ms {
            return Err(DaemonSupervisionHeartbeatError::SupervisionLeaseExpired.into());
        }
        authority.verify_active_snapshot(&current_snapshot, lease_id, now_ms)?;
        if !supervision_binding_matches_contour(&current_snapshot.record.binding, contour)? {
            return Err(SupervisionLeaseAuthorityError::Ors(
                OrsError::SupervisionLeaseBindingMismatch,
            )
            .into());
        }
        let current = daemon_supervision_current_state(&current_snapshot, contour, progress)?;
        let decision = Self::decide_daemon_supervision_progress_renewal(
            request, &current, progress, policy, now_ms,
        )?;
        if decision.outcome != DaemonSupervisionRenewalOutcome::Renewed {
            let receipt = daemon_renewal_receipt_for_decision(&decision, None, None)?;
            return Ok((current_snapshot, decision, Some(receipt)));
        }
        let successor_revision =
            decision
                .successor_revision
                .ok_or(SupervisionLeaseAuthorityError::Configuration(
                    "renewed progress decision is missing its successor revision".to_owned(),
                ))?;
        let observation_sha256 = request
            .observation
            .digest()
            .map_err(SupervisionProgressRenewalError::Heartbeat)?;
        let stage = if let Some(stage) = authority.staged_snapshot(lease_id)? {
            if stage.ticket.operation != SupervisionLeaseOperation::Renew
                || stage.ticket.expected_revision != Some(current_snapshot.record.revision)
                || stage.ticket.previous_receipt_sha256.as_deref()
                    != Some(current_snapshot.receipt.receipt_sha256.as_str())
                || stage.ticket.binding.state != LeaseState::Active
                || !supervision_binding_matches_contour(&stage.ticket.binding, contour)?
                || now_ms >= stage.ticket.binding.expires_at_ms
            {
                return Err(SupervisionLeaseAuthorityError::Ors(
                    OrsError::SupervisionLeaseTicketConflict,
                )
                .into());
            }
            stage
        } else {
            let binding = Self::active_supervision_binding(contour, now_ms, policy)?;
            authority.prepare(SupervisionLeasePrepareRequest {
                ticket_id: supervision_operation_identity(
                    "renew-ticket",
                    lease_id,
                    Some(&current_snapshot.receipt.receipt_sha256),
                )?,
                operation_id: supervision_operation_identity(
                    "renew-operation",
                    lease_id,
                    Some(&current_snapshot.receipt.receipt_sha256),
                )?,
                lease_id: OperationIdentity::new(lease_id.to_owned())?,
                expected_revision: Some(current_snapshot.record.revision),
                operation: SupervisionLeaseOperation::Renew,
                binding,
            })?
        };
        let renewed = match authority.commit_active(&stage.ticket) {
            Ok(renewed) => renewed,
            Err(error) => {
                progress.note_reconciliation_pending();
                return Err(error.into());
            }
        };
        authority.verify_active_snapshot(&renewed, lease_id, now_ms)?;
        if renewed.record.revision != successor_revision
            || renewed.record.revision <= current_snapshot.record.revision
            || !supervision_binding_matches_contour(&renewed.record.binding, contour)?
        {
            progress.note_reconciliation_pending();
            return Err(SupervisionLeaseAuthorityError::Ors(
                OrsError::SupervisionLeaseBindingMismatch,
            )
            .into());
        }
        progress.record_renewed(
            &request.observation,
            observation_sha256,
            successor_revision,
            now_ms,
        );
        Ok((renewed, decision, None))
    }

    #[cfg(windows)]
    fn establish_daemon_supervision(
        &self,
        session: &Session,
        process: &ProcessStartReceipt,
    ) -> Result<(DaemonSupervisionContour, SupervisionLeaseSnapshot), KernelServiceError> {
        let contour = self.daemon_supervision_contour(session, process)?;
        let authority = self
            .supervision_lease_authority
            .as_ref()
            .ok_or(KernelServiceError::ReadinessNotProven)?;
        let snapshot = Self::commit_or_replay_active_supervision(authority, &contour, unix_ms())
            .map_err(|_| KernelServiceError::ReadinessNotProven)?;
        Ok((contour, snapshot))
    }

    // Issue #88, wave 3: the ProbeReady path uses the latest retained
    // per-tick observation when it is bound to the current durable head (or
    // is the exact observation that produced its immediately preceding
    // successor). A missing or refused progress observation falls back only to
    // lease continuity for front-door responsiveness; that fallback never
    // records I1.11 step 11 or grants Material authority.
    // `StoreHealth` (`health_view::daemon_health`) stays evidence-only and
    // must never be passed as renewal evidence.
    #[cfg(windows)]
    #[allow(
        clippy::too_many_lines,
        reason = "probe renewal threads the exact launch, process, ready, contour, and head identities explicitly"
    )]
    fn progress_renewal_for_probe(
        &self,
        authority: &KernelSupervisionLeaseAuthority,
        contour: &DaemonSupervisionContour,
        launch: &EliotdLaunchDescriptor,
        process: &ProcessStartReceipt,
        ready: &EliotdLiveReadyEvidence,
        head: &SupervisionLeaseSnapshot,
    ) -> Result<Option<(SupervisionLeaseSnapshot, EliotdLiveReceipt)>, KernelServiceError> {
        let (observation, progress_state) = self
            .daemon_runtime
            .lock()
            .map_err(|_| KernelServiceError::Platform("daemon runtime lock poisoned".to_owned()))
            .map(|state| {
                (
                    state.last_progress_observation.clone(),
                    state.supervision_progress.clone(),
                )
            })?;
        if progress_state.reconciliation_pending {
            // A staged ticket with an unresolved publication is reconciled by
            // identity only; never fall through to process-continuity renewal.
            return Err(KernelServiceError::ReadinessNotProven);
        }
        let Some(observation) = observation else {
            return Ok(None);
        };
        if !Self::progress_observation_matches_current_head(&observation, head, &progress_state) {
            return Ok(None);
        }
        let now_ms = unix_ms();
        if observation.observed_wall_ms > now_ms.saturating_add(5_000)
            || now_ms.saturating_sub(observation.observed_wall_ms) > 10_000
        {
            return Ok(None);
        }
        // A successful renewal retains the observation that was evaluated
        // against the predecessor head. When that exact observation is
        // recorded as the producer of the current successor, ProbeReady can
        // reconcile the publication from that successor; it must not submit the
        // predecessor again as a new renewal request.
        if observation.predecessor_receipt_sha256 != head.receipt.receipt_sha256 {
            let published =
                self.publish_eliotd_live_receipt(launch, process, ready, contour, Some(head))?;
            return Ok(Some((head.clone(), published)));
        }
        let predecessor = eliot_runtime_contracts::SupervisionLeasePredecessorProof {
            lease_id: head.record.lease_id.as_str().to_owned(),
            record_id: head.record.record_id.as_str().to_owned(),
            lease_revision: head.record.revision,
            receipt_sha256: head.receipt.receipt_sha256.clone(),
            envelope_sha256: head
                .record
                .artifact
                .envelope_digest()
                .map_err(|_| KernelServiceError::ReadinessNotProven)?,
        };
        let request = DaemonSupervisionRenewalRequest {
            request_id: observation.observation_id.clone(),
            observation: observation.clone(),
            predecessor,
        };
        request
            .validate()
            .map_err(|_| KernelServiceError::ReadinessNotProven)?;
        let mut progress = {
            let mut state = self.daemon_runtime.lock().map_err(|_| {
                KernelServiceError::Platform("daemon runtime lock poisoned".to_owned())
            })?;
            std::mem::replace(
                &mut state.supervision_progress,
                DaemonSupervisionProgressState::unbound(),
            )
        };
        let renewal = Self::renew_current_supervision_with_progress(
            authority,
            contour,
            &request,
            &mut progress,
            &SUPERVISION_LEASE_RENEWAL_POLICY,
            unix_ms(),
        );
        let put_back = |progress: DaemonSupervisionProgressState,
                        expired: Option<bool>|
         -> Result<(), KernelServiceError> {
            let mut state = self.daemon_runtime.lock().map_err(|_| {
                KernelServiceError::Platform("daemon runtime lock poisoned".to_owned())
            })?;
            state.supervision_progress = progress;
            state.last_progress_observation = Some(request.observation.clone());
            if let Some(expired) = expired {
                state.supervision_expired = expired;
            }
            Ok(())
        };
        let (snapshot, decision, receipt) = match renewal {
            Ok(value) => value,
            Err(error) => {
                let expired = matches!(
                    error,
                    SupervisionProgressRenewalError::Heartbeat(
                        DaemonSupervisionHeartbeatError::SupervisionLeaseExpired
                    )
                );
                put_back(progress, Some(expired))?;
                if expired {
                    self.promote_agent_bridge_profile(None)
                        .map_err(|error| KernelServiceError::Platform(error.to_string()))?;
                }
                // A failed renewal must not fall through to process-only
                // continuity. Otherwise a terminal lease expiry could be
                // revived by a later ProbeReady without a new generation.
                return Err(KernelServiceError::ReadinessNotProven);
            }
        };
        put_back(progress, Some(false))?;
        // A non-renewing decision still publishes the unchanged head
        // so the live receipt tracks the durable revision.
        let published =
            self.publish_eliotd_live_receipt(launch, process, ready, contour, Some(&snapshot))?;
        if decision.outcome == DaemonSupervisionRenewalOutcome::Renewed {
            let live_sha256 = sha256_hex(
                &eliot_contracts::canonical_json_bytes(&published)
                    .map_err(|_| KernelServiceError::ReadinessNotProven)?,
            );
            // The renewal receipt is validated for coherence here and
            // then stays with the ORS/live-receipt evidence; ProbeReady
            // returns the head pair like the legacy path.
            let _ = daemon_renewal_receipt_for_decision(
                &decision,
                Some(snapshot.receipt.receipt_sha256.clone()),
                Some(live_sha256),
            )
            .map_err(|_| KernelServiceError::ReadinessNotProven)?;
        } else {
            let _ = receipt.ok_or(KernelServiceError::ReadinessNotProven)?;
        }
        Ok(Some((snapshot, published)))
    }

    #[cfg(windows)]
    fn renew_daemon_supervision_for_probe(
        &self,
        request: &KernelControlRequest,
    ) -> Result<(SupervisionLeaseSnapshot, EliotdLiveReceipt), KernelServiceError> {
        let (contour, process, ready) = {
            let state = self.daemon_runtime.lock().map_err(|_| {
                KernelServiceError::Platform("daemon runtime lock poisoned".to_owned())
            })?;
            if state.status != DaemonRuntimeStatus::Ready {
                return Err(KernelServiceError::ReadinessNotProven);
            }
            if state.supervision_expired {
                // Issue #88, A6: the progress route already reported terminal
                // lease expiry for this contour. Fail readiness closed on the
                // expired marker until a new admitted generation rebinds (the
                // rebind clears the marker); the durable-head verify below
                // would fail identically on the expired binding. A terminal
                // progress expiry therefore fences this contour until a newly
                // admitted generation rebinds: a live lease snapshot or a later
                // ProbeReady cannot revive the expired claim.
                return Err(KernelServiceError::ReadinessNotProven);
            }
            (
                state
                    .supervision
                    .clone()
                    .ok_or(KernelServiceError::ReadinessNotProven)?,
                state
                    .receipt
                    .clone()
                    .ok_or(KernelServiceError::ReadinessNotProven)?,
                state
                    .live_ready
                    .clone()
                    .ok_or(KernelServiceError::ReadinessNotProven)?,
            )
        };
        let candidate_digest = request
            .candidate
            .compute_digest()
            .map_err(|_| KernelServiceError::ReadinessNotProven)?;
        let activation = self
            .service
            .lock()
            .map_err(|_| KernelServiceError::Platform("service lock poisoned".to_owned()))?
            .activation_receipt()
            .cloned()
            .ok_or(KernelServiceError::ReadinessNotProven)?;
        if contour.candidate_digest != candidate_digest
            || contour.incarnation != request.candidate.supervision_incarnation
            || contour.activation != activation
        {
            return Err(KernelServiceError::ReadinessNotProven);
        }
        let authority = self
            .supervision_lease_authority
            .as_ref()
            .ok_or(KernelServiceError::ReadinessNotProven)?;
        let launch = self
            .active_daemon_launch()?
            .ok_or(KernelServiceError::ReadinessNotProven)?;
        let lease_id = &contour.incarnation.supervision_lease_id;
        let before = authority
            .current_snapshot(lease_id)
            .map_err(|_| KernelServiceError::ReadinessNotProven)?
            .ok_or(KernelServiceError::ReadinessNotProven)?;
        authority
            .verify_active_snapshot(&before, lease_id, unix_ms())
            .map_err(|_| KernelServiceError::ReadinessNotProven)?;
        if !supervision_binding_matches_contour(&before.record.binding, &contour)
            .map_err(|_| KernelServiceError::ReadinessNotProven)?
        {
            return Err(KernelServiceError::ReadinessNotProven);
        }
        // A retry first reconciles any exact current ORS successor left by an
        // earlier ambiguous publication. This prevents a second Renew from
        // skipping over the receipt that still names the older ORS head.
        let _ =
            self.publish_eliotd_live_receipt(&launch, &process, &ready, &contour, Some(&before))?;
        let (renewed, published) = if let Some(pair) = self
            .progress_renewal_for_probe(authority, &contour, &launch, &process, &ready, &before)?
        {
            pair
        } else {
            // Front-door continuity only. This fallback cannot satisfy I1.11
            // step 11 and therefore cannot admit Material/Critical authority.
            let renewed = Self::renew_current_supervision(authority, &contour, unix_ms())
                .map_err(|_| KernelServiceError::ReadinessNotProven)?;
            let published = self.publish_eliotd_live_receipt(
                &launch,
                &process,
                &ready,
                &contour,
                Some(&renewed),
            )?;
            (renewed, published)
        };
        Ok((renewed, published))
    }

    #[cfg(windows)]
    fn rollback_store_rebind_if_exact_query(
        &self,
        query: &StoreRebindQuery,
    ) -> Result<(), TransportError> {
        let mut service = self
            .service
            .lock()
            .map_err(|_| TransportError::SessionFenced)?;
        match service.reconcile_store_rebind(query) {
            Ok(Some(receipt))
                if service.state() == KernelServiceState::Degraded
                    && service.store_rebind_receipt() == Some(&receipt)
                    && service.failure().is_some_and(|failure| {
                        matches!(
                            failure,
                            eliot_kernel_service::ServiceFailure::Contract(reason)
                                if reason == "store-rebind:degraded-for-fence"
                        )
                    }) =>
            {
                // A service-first receipt is volatile until ORS readback. If
                // exact ORS reconciliation proves the operation absent, put
                // the same in-memory service back on its pre-rebind contour
                // before Host is allowed to persist Aborted.
                service.rollback_store_rebind_for_recovery_failure();
                Ok(())
            }
            Ok(Some(_)) => Ok(()),
            Ok(None) | Err(eliot_kernel_service::KernelServiceError::HandshakeMismatch { .. }) => {
                Ok(())
            }
            Err(_) => Err(TransportError::SessionFenced),
        }
    }

    #[cfg(windows)]
    fn validate_store_rebind_admission(
        &self,
        request: &KernelControlRequest,
    ) -> Result<(), TransportError> {
        if matches!(
            &request.command,
            KernelControlCommand::ReconcileRebindStore(_)
        ) {
            return Ok(());
        }
        let receipt = self
            .service
            .lock()
            .map_err(|_| TransportError::SessionFenced)?
            .store_rebind_receipt()
            .cloned();
        let Some(receipt) = receipt else {
            return Ok(());
        };
        self.validate_store_rebind_receipt_admission(request, &receipt)
    }

    #[cfg(windows)]
    fn validate_store_rebind_receipt_admission(
        &self,
        request: &KernelControlRequest,
        receipt: &eliot_kernel_service::StoreRebindReceipt,
    ) -> Result<(), TransportError> {
        let candidate_digest = request
            .candidate
            .compute_digest()
            .map_err(|_| TransportError::SessionFenced)?;
        if receipt.candidate_binding_digest != candidate_digest
            || receipt.generation != request.generation
            || receipt.authority_epoch != request.candidate.kernel_epoch
        {
            return Err(TransportError::SessionFenced);
        }
        let handoff = self
            .store_handoff
            .lock()
            .map_err(|_| TransportError::SessionFenced)?
            .clone()
            .ok_or(TransportError::SessionFenced)?;
        if receipt.process_binding != handoff.process_binding {
            return Err(TransportError::SessionFenced);
        }
        let expected_requirement_digest = serde_json::to_vec(&handoff.requirement)
            .map(|bytes| format!("{:x}", Sha256::digest(bytes)))
            .map_err(|_| TransportError::SessionFenced)?;
        if receipt.requirement_digest != expected_requirement_digest {
            return Err(TransportError::SessionFenced);
        }
        let mut hasher = Sha256::new();
        hasher.update(
            serde_json::to_vec(&handoff.requirement.state_fence)
                .map_err(|_| TransportError::SessionFenced)?,
        );
        hasher.update(receipt.generation.value().to_le_bytes());
        hasher.update(receipt.authority_epoch.sequence.get().to_le_bytes());
        hasher.update(
            handoff
                .requirement
                .approved_artifact_hash
                .as_str()
                .as_bytes(),
        );
        hasher.update(handoff.requirement.approved_config_hash.as_str().as_bytes());
        hasher.update(receipt.process_binding.process.process_id.to_le_bytes());
        hasher.update(
            receipt
                .process_binding
                .process
                .start_time_100ns
                .to_le_bytes(),
        );
        hasher.update(receipt.process_binding.process.image_path.as_bytes());
        hasher.update(receipt.process_binding.job.as_str().as_bytes());
        hasher.update(candidate_digest.as_bytes());
        if receipt.store_fence != format!("{:x}", hasher.finalize()) {
            return Err(TransportError::SessionFenced);
        }
        Ok(())
    }

    #[cfg(windows)]
    fn validate_store_rebind_ors_record_admission(
        request: &KernelControlRequest,
        query: &eliot_kernel_service::StoreRebindQuery,
        record: &eliot_ors::StoreRebindReplayRecord,
    ) -> Result<(), TransportError> {
        let receipt = store_rebind_receipt_from_ors_record(record, &request.candidate.kernel_epoch)
            .map_err(|_| TransportError::SessionFenced)?;
        let candidate_digest = request
            .candidate
            .compute_digest()
            .map_err(|_| TransportError::SessionFenced)?;
        if receipt.operation_id.as_str() != query.operation_id.as_str()
            || receipt.request_digest != query.request_digest
            || receipt.candidate_binding_digest != candidate_digest
            || receipt.generation != request.generation
            || receipt.authority_epoch != request.candidate.kernel_epoch
            || receipt.requirement_digest != record.requirement_digest
            || receipt.store_fence != record.store_fence
            || receipt.process_binding.process.process_id != record.process_id
            || receipt.process_binding.process.start_time_100ns != record.process_start_time_100ns
            || receipt.process_binding.process.image_path != record.process_image_path
            || receipt.process_binding.job.as_str() != record.job_name
        {
            return Err(TransportError::SessionFenced);
        }
        Ok(())
    }

    #[cfg(windows)]
    fn verify_store_rebind_publication_complete(
        &self,
        receipt: &eliot_kernel_service::StoreRebindReceipt,
    ) -> Result<(), TransportError> {
        let service_receipt = self
            .service
            .lock()
            .map_err(|_| TransportError::SessionFenced)?
            .store_rebind_receipt()
            .cloned();
        if service_receipt.as_ref() != Some(receipt) {
            return Err(TransportError::SessionFenced);
        }
        let handoff = self
            .store_handoff
            .lock()
            .map_err(|_| TransportError::SessionFenced)?
            .clone()
            .ok_or(TransportError::SessionFenced)?;
        if handoff.process_binding != receipt.process_binding {
            return Err(TransportError::SessionFenced);
        }
        let expected_requirement_digest = serde_json::to_vec(&handoff.requirement)
            .map(|b| format!("{:x}", Sha256::digest(b)))
            .map_err(|_| TransportError::SessionFenced)?;
        if receipt.requirement_digest != expected_requirement_digest {
            return Err(TransportError::SessionFenced);
        }
        let gateway = self
            .canonical_store_gateway
            .lock()
            .map_err(|_| TransportError::SessionFenced)?
            .clone()
            .ok_or(TransportError::SessionFenced)?;
        if gateway.is_fenced() {
            return Err(TransportError::SessionFenced);
        }
        Ok(())
    }

    /// Completes the ordered I14.23 safe-shutdown sequence through the
    /// Kernel-owned persisted drain state machine.
    ///
    /// Phases run in order: close admissions (`Draining`), revoke authority,
    /// checkpoint jobs, reconcile canonical-write receipts against a bounded
    /// deadline, flush ORS staged rows, quiesce modules in reverse dependency
    /// order, prove the canonical-data lease-zero precondition, linearize the
    /// `DrainCommit` decision, stop the service, poison the generation
    /// gateway, and publish the terminal. Any gate failure — including
    /// deadline expiry with pending work — records an incomplete-shutdown
    /// terminal retaining the pending work instead of discarding it, while
    /// runtime shutdown still proceeds. Host carries the linearized decision
    /// into `DrainCommitRecord`; Watchdog observes it through the journal.
    pub async fn shutdown(&self) -> Result<ShutdownOutcome, ProcessExecutionError> {
        let coordinator = coordinator_for(&self.work_root);
        coordinator.request_shutdown();
        let drain = self.run_shutdown_drain(&coordinator).await;
        let process_result = self
            .process_gateway
            .as_ref()
            .map_or(Ok(()), |gateway| gateway.executor.shutdown());
        let runtime_outcome = self.runtime.shutdown().await;
        let mut pending = drain
            .as_ref()
            .err()
            .map_or(Vec::new(), |halt| halt.pending.clone());
        if process_result.is_err() {
            pending.push("process-gateway-shutdown-failed".to_owned());
        }
        if !runtime_outcome.no_orphans {
            pending.push("runtime-orphans-retained".to_owned());
        }
        if drain.is_ok() && pending.is_empty() {
            coordinator.complete_terminal(ShutdownTerminal::Intentional);
        } else {
            if pending.is_empty() {
                pending.push(
                    drain
                        .as_ref()
                        .err()
                        .map_or("shutdown-incomplete", |halt| halt.reason)
                        .to_owned(),
                );
            }
            coordinator.complete_terminal(ShutdownTerminal::Incomplete { pending });
        }
        coordinator.observe_published_state();
        process_result?;
        Ok(runtime_outcome)
    }

    /// Runs the ordered pre-terminal drain phases and returns the linearized
    /// `DrainCommit` decision. Every failure retains its pending work in the
    /// returned halt for the incomplete-shutdown terminal.
    #[allow(
        clippy::too_many_lines,
        reason = "the ordered I14.23 drain phases keep one visible admission-to-linearization boundary"
    )]
    async fn run_shutdown_drain(
        &self,
        coordinator: &Arc<shutdown_drain::ShutdownDrainCoordinator>,
    ) -> Result<DrainCommitDecision, DrainHalt> {
        let generation = coordinator.drain_generation();
        let resumed_note = coordinator
            .recovery_interrupted()
            .then_some(":resumed-interrupted");
        let record = |phase: ShutdownPhase, evidence: String| {
            coordinator
                .record_phase(phase, evidence)
                .map_err(|_| DrainHalt::new("phase-record-rejected"))
        };

        // AdmissionsClosed: the service gate closes normal admission; the
        // frame-dispatch Ready gate denies new work from `Draining` on.
        match self.apply_control(KernelControlCommand::Drain) {
            Ok(state) => record(
                ShutdownPhase::AdmissionsClosed,
                format!(
                    "service-drain-admitted:{state}{}",
                    resumed_note.unwrap_or("")
                ),
            )?,
            Err(_) => match self.service_state() {
                Ok(KernelServiceState::Draining | KernelServiceState::Stopped) => record(
                    ShutdownPhase::AdmissionsClosed,
                    format!("service-already-draining{}", resumed_note.unwrap_or("")),
                )?,
                _ => return Err(DrainHalt::new("admissions-close-rejected")),
            },
        }

        // AuthorityRevoked: with the service `Draining`, no new action
        // authority is admitted; post-linearization control/cutover authority
        // is revoked through the generation poison below.
        match self.service_state() {
            Ok(KernelServiceState::Draining) => record(
                ShutdownPhase::AuthorityRevoked,
                "service-draining:ready-gate-denies-new-admissions;control-revoked-at-commit-via-generation-poison"
                    .to_owned(),
            )?,
            _ => return Err(DrainHalt::new("authority-revoke-unproven")),
        }

        // JobsCheckpointed: observe the daemon contour under drain. Job
        // checkpoint/cancel semantics stay Governor-owned (handoff); Kernel
        // admits no new daemon launches while `Draining`.
        let daemon_status = self
            .daemon_runtime
            .lock()
            .map(|guard| format!("daemon-status:{:?}", guard.status))
            .map_err(|_| DrainHalt::new("daemon-contour-unavailable"))?;
        record(
            ShutdownPhase::JobsCheckpointed,
            format!(
                "{daemon_status};no-new-daemon-launches-while-draining;job-checkpoint-owned-by-eliotd-governor-handoff"
            ),
        )?;

        // CanonicalDrainReceiptsReconciled: every pending canonical-write
        // receipt (ORS store-rebind rows) must resolve before the
        // linearization point; the bounded wait retains the remainder.
        for identity in self
            .pending_rebind_receipts()
            .map_err(|_| DrainHalt::new("ors-rebind-scan-failed"))?
        {
            coordinator.register_pending_receipt(identity);
        }
        let remainder = coordinator
            .reconcile_pending_to_deadline(DRAIN_RECEIPT_DEADLINE, || {
                self.pending_rebind_receipts().unwrap_or_default()
            })
            .await;
        if !remainder.is_empty() {
            return Err(DrainHalt::with_pending(
                "receipt-reconciliation-incomplete",
                remainder,
            ));
        }
        record(
            ShutdownPhase::CanonicalDrainReceiptsReconciled,
            "store-rebind-pending-reconciled-empty;supervision-lease-staging-owned-by-lease-authority-handoff;host-request-staging-owned-by-governor-handoff"
                .to_owned(),
        )?;

        // FlushesCompleted: reconcile staged ORS generation cutovers.
        // Audit/outbox flush stays Governor-owned (handoff); Kernel never
        // fabricates Governor flush evidence.
        match self
            .generation_gateway
            .ors
            .reconcile_staged_generation_cutovers(eliot_ors::MAX_RECOVERY_PAGE)
        {
            Ok(snapshots) => record(
                ShutdownPhase::FlushesCompleted,
                format!(
                    "ors-staged-cutovers-reconciled:{};audit-outbox-flush-owned-by-eliotd-governor-handoff",
                    snapshots.len()
                ),
            )?,
            Err(_) => return Err(DrainHalt::new("ors-flush-failed")),
        }

        // ModulesQuiescedReverse: dependents stop before the stores and
        // bridges they depend on. The contour is the live composition state:
        // the store bridge (dependency) ordered before the daemon
        // (dependent), then reversed for quiescence.
        let mut dependency_order = Vec::new();
        #[cfg(windows)]
        match self.canonical_store_gateway.lock() {
            Ok(gateway) => {
                if gateway.is_some() {
                    dependency_order.push("store-bridge".to_owned());
                }
            }
            Err(_) => return Err(DrainHalt::new("store-contour-unavailable")),
        }
        match self.daemon_active_launch.lock() {
            Ok(launch) => {
                if launch.is_some() {
                    dependency_order.push("daemon".to_owned());
                }
            }
            Err(_) => return Err(DrainHalt::new("daemon-contour-unavailable")),
        }
        let quiescence = reverse_quiescence_order(&dependency_order)
            .map_err(|_| DrainHalt::new("module-contour-ambiguous"))?;
        record(
            ShutdownPhase::ModulesQuiescedReverse,
            format!("quiescence-order:{}", quiescence.join(">")),
        )?;

        // StoreStopLeaseZero: the store-stop request below is admitted only
        // with no outstanding lease. I1.5 widens the existing I14.23
        // canonical-data precondition to the full Kernel-owned lease census:
        // a live supervision lease, a live authenticated front-door Session,
        // or an outstanding host-request operation each keeps an obligation
        // that shutdown may not abandon.
        //
        // The census samples several owners independently, so a zero from one
        // is not evidence that the others stood still. Take the admission
        // coherence sample the census is taken under, and revalidate exactly
        // that sample after the census: independently sampled zeros are not
        // treated as atomic (issue #2625, I1.5 DrainCommitRecord).
        let admission = self
            .drain_admission_coherence(coordinator)
            .map_err(DrainHalt::new)?;
        let census = self.idle_lease_census();
        health_view::observe_shutdown_observation(
            "kernel.shutdown.lease_census_observed",
            census.observation_code(),
        );
        if !census.admits_drain() {
            return Err(DrainHalt::with_pending(
                "runtime-or-supervision-lease-outstanding",
                vec![census.observation_code().to_owned()],
            ));
        }
        #[cfg(windows)]
        let store_evidence = match self.canonical_store_gateway.lock() {
            Ok(gateway) => match gateway.as_ref() {
                Some(gateway) if gateway.is_fenced() => "store-gateway-fenced",
                Some(_) => "store-gateway-attached-unclaimed",
                None => "store-gateway-absent",
            },
            Err(_) => return Err(DrainHalt::new("store-gateway-unavailable")),
        };
        #[cfg(not(windows))]
        let store_evidence = "store-gateway-absent";
        record(
            ShutdownPhase::StoreStopLeaseZero,
            format!(
                "lease-census:{};{store_evidence}",
                census.observation_code()
            ),
        )?;

        // Revalidate the admission frontier the final census was taken under
        // before the linearization point consumes it. Work that raced the
        // snapshot is refused here rather than left unaccounted: an admission
        // still in flight, a fresh drain generation, a re-fenced State Fence,
        // a reopened service admission, or a front-door session/operation that
        // appeared after the census all block the commit. A poisoned owner
        // guard blocks it too, because a fenced read is not a stable frontier.
        let revalidated = self
            .drain_admission_coherence(coordinator)
            .map_err(|reason| {
                DrainHalt::with_pending(reason, vec![census.observation_code().to_owned()])
            })?;
        if revalidated != admission {
            return Err(DrainHalt::with_pending(
                "drain-admission-raced-final-census",
                vec![census.observation_code().to_owned()],
            ));
        }

        // DrainCommit linearization point. The committed State Fence is the
        // revalidated one, so the authority the commit fences is the same
        // authority the final census was proven under.
        let authority_epochs_fenced = vec![revalidated.state_fence];
        let decision = DrainCommitDecision {
            generation: generation.clone(),
            lease_and_pending_snapshot: Vec::new(),
            authority_epochs_fenced,
            branches_to_stop: quiescence,
            wake_disposition: DrainWakeDisposition::QueueNextGeneration,
            irreversible_stage: "authority-fenced".to_owned(),
            recovery_owner: "kernel-composition".to_owned(),
        };
        coordinator.commit_drain(decision.clone()).map_err(|_| {
            DrainHalt::with_pending("drain-commit-rejected", coordinator.pending_receipts())
        })?;

        // Service stop follows linearization; a committed drain without a
        // clean stop is incomplete recovery state, never a silent success.
        if self.apply_control(KernelControlCommand::Stop).is_err() {
            return Err(DrainHalt::with_pending(
                "service-stop-rejected",
                coordinator.pending_receipts(),
            ));
        }

        // Post-linearization revocation: no further control or cutover
        // authority is admitted through the poisoned generation gateway.
        match self.generation_poison.lock() {
            Ok(mut poison) => {
                *poison = Some(format!("shutdown-drain:{generation}"));
            }
            Err(_) => return Err(DrainHalt::new("authority-revoke-failed")),
        }
        record(
            ShutdownPhase::IntentionalPublished,
            format!("generation-poisoned;service-stopped;drain-commit-linearized:{generation}"),
        )?;
        Ok(decision)
    }

    /// Samples the exact drain/admission frontier the final lease census is
    /// taken under and revalidated against.
    ///
    /// The census reads several independent owners, so each zero it observes
    /// is only a statement about the instant that owner was sampled. This
    /// sample is the cross-owner coherence check: the drain authorization is
    /// consumed only when the drain generation, the front-door State Fence,
    /// the service admission state, and both front-door indexes are identical
    /// before and after the census.
    ///
    /// Every owner is read under its own guard, and each guard is released
    /// before the next owner is touched: no global mutex is held across an
    /// RPC, an ORS read, or an await point, and no two of these owners are
    /// ever held at once. A poisoned guard is fenced state, so it is reported
    /// as a reason rather than recovered with `into_inner` and treated as a
    /// stable frontier.
    fn drain_admission_coherence(
        &self,
        coordinator: &Arc<shutdown_drain::ShutdownDrainCoordinator>,
    ) -> Result<DrainAdmissionCoherence, &'static str> {
        let drain_generation = coordinator.drain_generation();
        let state_fence = match self.front_door_policy.lock() {
            Ok(policy) => {
                let fence = &policy.module_generation.state_fence;
                format!(
                    "{}:{}@{}",
                    fence.authority_epoch.lineage_id,
                    fence.authority_epoch.sequence,
                    fence.resource_generation.value()
                )
            }
            Err(_) => return Err("authority-fence-unavailable"),
        };
        let service_state = self
            .service_state()
            .map_err(|_| "service-state-unavailable")?;
        #[cfg(windows)]
        let (bridge_sessions, host_request_operations) = {
            let bridge_sessions = match self.agent_bridge_connections.lock() {
                Ok(connections) => connections.len(),
                Err(_) => return Err("bridge-session-index-unreadable"),
            };
            let host_request_operations = match self.host_request_connection_index.lock() {
                Ok(index) => index.values().map(Vec::len).sum::<usize>(),
                Err(_) => return Err("host-request-index-unreadable"),
            };
            (bridge_sessions, host_request_operations)
        };
        // I1.7: the non-Windows Kernel has no authenticated front-door
        // Session, so there is no front-door index to sample and nothing can
        // race it.
        #[cfg(not(windows))]
        let (bridge_sessions, host_request_operations) = (0usize, 0usize);
        Ok(DrainAdmissionCoherence {
            drain_generation,
            state_fence,
            service_state,
            bridge_sessions,
            host_request_operations,
        })
    }

    /// Lists pending canonical-write receipts (ORS store-rebind rows) as
    /// drain-gate identities. Read-only: shutdown never mutates staged rows.
    fn pending_rebind_receipts(&self) -> Result<Vec<String>, String> {
        let records = self
            .generation_gateway
            .ors
            .load_all_store_rebinds()
            .map_err(|_| "ors-rebind-scan-failed".to_owned())?;
        Ok(records
            .iter()
            .filter(|record| record.state == eliot_ors::StoreRebindReplayState::Pending)
            .map(|record| format!("store-rebind:{}", record.operation_id.as_str()))
            .collect())
    }
}

/// Bounded cross-owner drain/admission coherence sample.
///
/// Taken immediately before the final Kernel lease census and revalidated
/// immediately after it: `DrainCommit` consumes the authorization only when
/// both samples are identical. Every field is an existing owner's current
/// value or a count of it — no lease identity, digest, or owner error text
/// crosses this boundary.
#[derive(Clone, Debug, Eq, PartialEq)]
struct DrainAdmissionCoherence {
    /// The drain generation the census is taken under and the commit is
    /// consumed for.
    drain_generation: String,
    /// The front-door `StateFence` binding (`lineage:sequence@resource`).
    state_fence: String,
    /// The service admission state the census was taken under.
    service_state: KernelServiceState,
    /// Admitted front-door bridge Session count.
    bridge_sessions: usize,
    /// Admitted front-door host-request operation count.
    host_request_operations: usize,
}

fn status_frame(
    session: &Session,
    kind: FrameKind,
    message_type: MessageType,
    payload: serde_json::Value,
) -> Result<Frame, TransportError> {
    let frame = Frame {
        protocol_version: session.protocol_version,
        encoding_profile: EncodingProfile::JsonV1,
        connection_id: session.connection_id.clone(),
        request_id: None,
        kind,
        message_type,
        request_identity: None,
        payload: ProtocolPayload::Json(payload),
        trace_context: std::collections::BTreeMap::new(),
    };
    frame.validate()?;
    Ok(frame)
}

fn dispatch_key(work_root: &Path) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(work_root.as_os_str().to_string_lossy().as_bytes());
    hasher.update(std::process::id().to_le_bytes());
    hasher.update(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |duration| duration.as_nanos())
            .to_le_bytes(),
    );
    hasher.finalize().into()
}

#[allow(dead_code)]
fn is_lower_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

#[allow(dead_code)]
pub(crate) fn sha256_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let digest = Sha256::digest(bytes);
    let mut output = String::with_capacity(64);
    for byte in digest {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}

#[allow(dead_code)]
fn sha256_json<T: Serialize>(value: &T) -> Result<String, serde_json::Error> {
    Ok(sha256_hex(&serde_json::to_vec(value)?))
}

/// Resolves and validates the default `WorkScope` root for the binary entrypoint.
pub fn default_work_root() -> Result<PathBuf, std::io::Error> {
    let root = std::env::var_os("ELIOT_WORK_ROOT").map_or(std::env::current_dir()?, PathBuf::from);
    std::fs::canonicalize(Path::new(&root))
}

#[cfg(windows)]
const _: () = {
    let _ = AGENT_BRIDGE_MODULE_ID;
    let _ = AGENT_BRIDGE_PEER_CHALLENGE_WIRE_ID;
    let _ = AGENT_BRIDGE_PEER_CHALLENGE_WIRE_VERSION;
    let _ = AGENT_BRIDGE_ACTIVATION_OPERATION;
    let _: Option<AgentBridgeActivationDenialCode> = None;
    let _: Option<AgentBridgeActivationDisposition> = None;
    let _: Option<AgentBridgeActivationFence> = None;
    let _: Option<AgentBridgeActivationResponse> = None;
    let _: Option<AgentBridgeAuthenticatedBinding> = None;
    let _: Option<AgentBridgePeerAdmissionReceipt> = None;
};

#[cfg(test)]
mod tests;

#[cfg(test)]
#[path = "tests/local_read_claim.rs"]
mod local_read_claim_tests;

// Store implementation E2E belongs to the Store/Host boundary. Kernel tests
// exercise only the neutral descriptor and route/fence behavior.
