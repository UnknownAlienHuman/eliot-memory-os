//! P-07 Kernel service boundary.
//!
//! This crate composes the Kernel decision core into the long-lived service
//! boundary described by Implementation I1.2-I1.5 and I14.16.  It owns the
//! provider-neutral lifecycle, Host handoff contract, readiness admission and
//! drain/recovery decisions.  Host remains responsible for physical process
//! containment and the platform adapter remains responsible for OS effects.
//!
//! A service is never considered ready because a process exists.  The Host
//! handshake, exact activation identity, process observation, health vector,
//! and supervision evidence must all agree before normal admission opens.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use std::future::Future;
use std::pin::Pin;

#[cfg(windows)]
mod commit_recovery;
#[cfg(windows)]
pub use commit_recovery::{
    CheckedPauseObservation, CommitRecoveryClass, CommitRecoveryError, MAX_OBSERVED_OPEN_COMMITS,
    PauseLedgerBinding, PauseReleaseOutcome, PauseScopeView, PausedScopeEntry, PausedScopeMirror,
    PausedScopeSnapshot, classify_commit_receipt, paused_ordering_scope_view,
    paused_scopes_snapshot, receipt_evidence_digest, recover_commit,
};
mod capacity_evidence;
mod contract_rejection_gate;
mod doctor;
mod doctor_front_door;
mod host_request_binding;
mod lifecycle;
mod lifecycle_persist;
#[cfg(test)]
mod lifecycle_persist_tests;
mod notification_state;
#[cfg(test)]
mod notification_state_tests;
mod notify_grant;
mod owner_history;
mod process_execution_client;
mod protocol;
mod reactive_state;
#[cfg(test)]
mod reactive_state_tests;
mod store_client;
#[cfg(windows)]
mod store_gateway;
mod store_write_reservation;
#[cfg(test)]
mod store_write_reservation_tests;
mod testd_front_door;
mod user_automation;
mod user_automation_execution;
mod user_automation_execution_client;
mod user_automation_failure_history;
#[cfg(test)]
mod user_automation_failure_history_tests;
mod user_automation_runtime_handoff;
mod user_automation_store;
#[cfg(test)]
mod user_automation_store_tests;
mod wasm_dispatch;
mod write_coordinator;

pub use capacity_evidence::{
    BoundaryOptimizationProposal, CAPACITY_EVIDENCE_SCHEMA_VERSION, CanonicalWriteLatencyProfile,
    CapacityEnvelope, CapacityEvidenceError, CorpusScaleProfile, EvidenceClass,
    LatencyDistribution, MIN_PERCENTILE_SAMPLES, OptimizationQualification, UnqualifiedReason,
};
pub use contract_rejection_gate::{
    PRE_STAGE_RETRY_RULE, PreStageDecision, PreStageIdentityCache, PreStageRejection,
    PreStageState, derive_rejection_id, pre_stage_check,
};
pub use doctor::{
    ComposedDoctorFrontDoor, DOCTOR_CONFLICT_MAX_FIELDS, DOCTOR_MAX_ENVELOPE_BYTES,
    DOCTOR_MAX_LEASE_DURATION_NANOS, DOCTOR_RECOVERY_LEASE_OWNER, DOCTOR_REPAIR_ADVERTISED,
    DOCTOR_REPAIR_WIRE_ID, DOCTOR_REPAIR_WIRE_VERSION, DoctorAdmissionContext,
    DoctorRecipeRegistry, DoctorRegistryError, DoctorRepairAdmission, DoctorRepairAttemptRequest,
    DoctorRepairConflict, DoctorRepairRejection, DoctorRepairRejectionReason, DoctorRepairResponse,
    RegisteredDoctorRecipe, admit_doctor_repair, advertise_doctor_repair,
    reconcile_doctor_repair_admission, route_doctor_repair,
};
pub use doctor_front_door::{
    AuthenticatedDoctorSession, handle_doctor_repair_attempt, handle_doctor_repair_cancellation,
    is_doctor_diagnosis_only_envelope, reconcile_doctor_repair_delivery,
};
pub use eliot_kernel_core::user_automation::AutomationExecutionReference;
pub use eliot_process::ProcessExecutionAdmissionRequest;
pub use eliot_protocol::{
    AGENT_BRIDGE_CLIENT_DECLARATION_WIRE_ID, AGENT_BRIDGE_CLIENT_DECLARATION_WIRE_VERSION,
    AgentBridgeClientDeclaration,
};
pub use host_request_binding::{AuthenticatedHostSession, KernelHostRequestBinder};
pub use lifecycle::{
    AdmissionLease, KernelService, KernelServiceError, KernelServiceState, ServiceFailure,
};
pub use lifecycle_persist::{
    AuthenticatedLifecycleSession, BuiltLeg, BuiltLegKind, HopMutation, HopMutationInput,
    LifecyclePersistError, LifecyclePersistRequest, LifecyclePersistResponse,
    LifecycleServiceContext, LinkAuditBinding, PersistedHop, PersistedMutation,
    build_persist_transitions, handle_lifecycle_persist_request,
};
pub use notification_state::{
    AuthenticatedNotificationSession, NotificationMetrics, NotificationServiceContext,
    NotificationServiceError, NotificationStateMutation, NotificationStateReadRequest,
    NotificationStateReadResponse, NotificationStateRequest, NotificationStateResponse,
    handle_notification_state_read, handle_notification_state_request,
    reconcile_notification_state,
};
pub use notify_grant::{
    NOTIFY_GRANT_OPERATION_PREFIX, NOTIFY_IMAGE_FILE_NAME, NotifyGrantInputs,
    NotifyLaunchAuthorization, bind_notify_launch_grant,
};
pub use owner_history::{
    GRANT_CLOSURE_CANONICAL_LINKS_VERSION, GrantClosureCanonicalLink, GrantClosureCanonicalLinks,
    GrantClosureCanonicalLinksQuery, grant_closure_canonical_links,
    serve_authority_revocation_history,
};
pub use process_execution_client::{
    KernelProcessExecutionClient, ProcessOperationFuture, ProcessOperationPort, ProcessStarter,
    ProcessStarterFuture,
};
pub use protocol::{
    AGENT_BRIDGE_ADMISSION_DESCRIPTOR_WIRE_ID, AGENT_BRIDGE_ADMISSION_DESCRIPTOR_WIRE_VERSION,
    AGENT_BRIDGE_MODULE_ID, AgentBridgeAdmissionDescriptor, AgentBridgeCallerSessionPolicy,
    AgentBridgeProcessPolicy, ContainmentAction, DAEMON_STARTUP_EVIDENCE_OPERATION,
    DaemonStartupEvidence, EliotdLaunchDescriptor, HostFileIdentity, HostJobBinding,
    HostJobIdentity, HostJobRoot, HostKernelCandidateBinding, HostProcessBinding,
    HostStartupEvidence, HostStoreBootstrapRequirement, IntroductionReadbackQuery, IntroductionRow,
    KERNEL_CONTROL_PIPE, KERNEL_CONTROL_WIRE_ID, KERNEL_CONTROL_WIRE_VERSION,
    KernelActivationPermit, KernelActivationQuery, KernelActivationReceipt, KernelControlCommand,
    KernelControlRequest, KernelControlResponse, KernelReadyReceipt, NATIVE_WORKER_CLAIM_WIRE_ID,
    NATIVE_WORKER_CLAIM_WIRE_VERSION, NATIVE_WORKER_CLAIM_WIRE_VERSION_V1,
    NATIVE_WORKER_EXECUTABLE_BINDING_EXPECTED_WIRE_VERSION,
    NATIVE_WORKER_EXECUTION_UNIT_SCHEMA_VERSION, NATIVE_WORKER_PROTOCOL_VERSION,
    NATIVE_WORKER_REPLAY_MAX_EVENT_BYTES, NATIVE_WORKER_REPLAY_MAX_EVENT_REFS,
    NATIVE_WORKER_REPLAY_MAX_PAGE, NATIVE_WORKER_REPLAY_MAX_TRACE_ENTRIES,
    NATIVE_WORKER_REPLAY_WIRE_ID, NATIVE_WORKER_REPLAY_WIRE_VERSION, NativeWorkerClaimBudget,
    NativeWorkerClaimConflict, NativeWorkerClaimReceipt, NativeWorkerClaimRejection,
    NativeWorkerClaimRejectionReason, NativeWorkerClaimRequest, NativeWorkerClaimResponse,
    NativeWorkerExecutableBinding, NativeWorkerExecutableExpectation, NativeWorkerReplayAckPhase,
    NativeWorkerReplayAckReceipt, NativeWorkerReplayAcknowledgeReply,
    NativeWorkerReplayAcknowledgeRequest, NativeWorkerReplayAppendReply,
    NativeWorkerReplayAppendRequest, NativeWorkerReplayAuthority, NativeWorkerReplayBeginReply,
    NativeWorkerReplayBeginRequest, NativeWorkerReplayConflict, NativeWorkerReplayDecision,
    NativeWorkerReplayDeliveryClass, NativeWorkerReplayEnvelope, NativeWorkerReplayEventDraft,
    NativeWorkerReplayExpectation, NativeWorkerReplayLookupReply, NativeWorkerReplayLookupRequest,
    NativeWorkerReplayOperation, NativeWorkerReplayPage, NativeWorkerReplayReplayReply,
    NativeWorkerReplayReplayRequest, NativeWorkerReplayStreamBinding,
    NativeWorkerReplayStreamPosition, PROVIDER_CAPABILITY_WIRE_VERSION,
    ProcessAuthorityHandoffDescriptor, ProcessExecutionRejection, ProcessExecutionRequest,
    ProcessExecutionResponse, ProcessObservation, ProviderCapabilityError,
    ProviderCapabilityExpectation, ProviderCapabilityRequest, ProviderProofKind,
    REASON_CANCELLATION_UNCONFIRMED, REASON_CAPABILITY_UNAVAILABLE, REASON_DEADLINE_EXCEEDED,
    REASON_IDENTITY_CONFLICT, REASON_INSTRUMENT_EVIDENCE_INCOMPLETE, REASON_INVALID_ARGUMENT,
    REASON_POLICY_DENIED, REASON_PROTOCOL_INCOMPATIBLE, REASON_RESEARCH_SOURCE_UNAVAILABLE,
    REASON_RUNTIME_FAILED, REASON_STALE_AUTHORITY_EPOCH, REASON_STALE_STATE_FENCE,
    REASON_UNKNOWN_OUTCOME, RESEARCH_PROVIDER_CANCEL_OPERATION,
    RESEARCH_PROVIDER_DISPATCH_OPERATION, RESEARCH_PROVIDER_DISPATCH_WIRE_VERSION,
    RESEARCH_PROVIDER_MAX_TEXT, RESEARCH_PROVIDER_OPERATIONS,
    RESEARCH_PROVIDER_RECONCILE_OPERATION, RESEARCH_PROVIDER_STATUS_OPERATION,
    RESEARCH_PROVIDER_WIRE_ID, ResearchProviderDispatch, ResearchProviderDispatchReceipt,
    ResearchProviderDisposition, ResearchProviderError, RestartBudget, RuntimeLeaseCensus,
    RuntimeLeaseCensusQuery, StoreBootstrapDescriptor, StoreBootstrapHandoff, StoreProcessBinding,
    StoreRebindHandoff, StoreRebindQuery, StoreRebindReceipt, admit_replay_request,
    control_request_frame, control_response_frame, daemon_capability_registry_digest,
    decode_control_request_frame, decode_control_response_frame, replay_stream_id,
    semantic_store_config_hash_from_json, verify_provider_capability,
};
pub use reactive_state::{
    AuthenticatedReactiveSession, ReactiveLedgerReadRequest, ReactiveLedgerReadResponse,
    ReactiveLedgerRequest, ReactiveLedgerResponse, ReactiveServiceContext, ReactiveServiceError,
    ResourceSnapshotReadRequest, ResourceSnapshotReadResponse, ResourceSnapshotRequest,
    ResourceSnapshotResponse, handle_reactive_ledger_read, handle_reactive_ledger_request,
    handle_resource_snapshot_read, handle_resource_snapshot_request, reconcile_reactive_state,
};
pub use store_client::{
    EbpCanonicalStoreClient, EbpStoreTransport, StoreClientError, StoreClientFault,
    StoreClientFaultHarness,
};
#[cfg(windows)]
pub use store_gateway::KernelStoreGateway;
pub use store_write_reservation::{
    CompositionReservation, ObservedHead, RESERVATION_KEY_NAME, RESERVATION_KEY_PROVIDER,
    RESERVATION_VISIBILITY, ReservationSeed, ReservationWriteError, ReservedSubmission,
    ResolvedSendOutcome, SealedReservation, StartupPendingOperation, StartupReconciliation,
    StartupReconciliationReadiness, StartupUnknownOperation, UNKNOWN_OUTCOME_REASON,
    begin_execute_after_send, cancel_before_send, ensure_eligible, finalize_reservation,
    gateway_seed, mark_unknown_outcome, project_reserved_write, reconcile_pending_at_startup,
    reconcile_receipt, recovery_page, reserve_for_transition, unresolved_reservations,
    writer_epoch_for_fence, writer_epoch_for_fence_from_epoch,
};
pub use testd_front_door::{
    AuthenticatedTestdSession, TESTD_ADMISSION_ADVERTISED, TESTD_ADMISSION_WIRE_ID,
    TESTD_ADMISSION_WIRE_VERSION, TESTD_CONFLICT_MAX_FIELDS, TESTD_MAX_ENVELOPE_BYTES,
    TestdAdmission, TestdAdmissionAttemptRequest, TestdAdmissionConflict, TestdAdmissionContext,
    TestdAdmissionEnvelope, TestdAdmissionRejection, TestdAdmissionRejectionReason,
    TestdAdmissionResponse, advertise_testd_admission, advertise_testd_admission_when_composed,
    handle_testd_admission_attempt, handle_testd_cancellation, is_testd_diagnosis_only_envelope,
    reconcile_testd_admission, reconcile_testd_delivery, route_testd_admission,
};
pub use user_automation::{
    USER_AUTOMATION_SERVICE_CONTRACT_NAME, USER_AUTOMATION_SERVICE_CONTRACT_VERSION,
    UserAutomationMutationResult, UserAutomationReadResult, UserAutomationService,
    UserAutomationServiceError, UserAutomationServiceRequest, UserAutomationStoreOutcome,
    UserAutomationStorePort, UserAutomationStoreRequest, UserAutomationStoreResponse,
};
pub use user_automation_execution::{
    UserAutomationDueWakeRejection, UserAutomationDueWakeRejectionCause,
    UserAutomationDueWakeResolution, UserAutomationDurableJobPort, UserAutomationExecutionError,
    UserAutomationExecutionOutcome, UserAutomationExecutionRequest, UserAutomationFailureHistory,
    UserAutomationFailureHistoryPort, UserAutomationFailurePublication,
    UserAutomationFailureRecord, UserAutomationHorizonTrigger, UserAutomationNotificationDelivery,
    UserAutomationNotificationPort, UserAutomationRemovalResult, UserAutomationRuntimeAdmission,
    UserAutomationRuntimeComposition, UserAutomationRuntimeError, UserAutomationRuntimePort,
    UserAutomationWakeCancellation, UserAutomationWakeCancellationTarget,
    UserAutomationWakeHorizonEntry, UserAutomationWakeHorizonPublication, UserAutomationWakePort,
    UserAutomationWakePublication, UserAutomationWakeReadRequest, UserAutomationWakeReadback,
    UserAutomationWakeTargetSnapshot, UserAutomationWakeTargetSnapshotDisposition,
    UserAutomationWakeTargetSnapshotEntry, UserAutomationWakeTargetSnapshotRequest,
    advance_wake_horizon, compile_wake_horizon, horizon_retry_handle, refuse_consumed_wake,
    resolve_due_wake,
};
#[cfg(windows)]
pub use user_automation_execution_client::AuthenticatedUserAutomationHostExecutionTransport;
pub use user_automation_execution_client::{
    USER_AUTOMATION_HOST_EXECUTION_PIPE, USER_AUTOMATION_HOST_EXECUTION_WIRE_ID,
    USER_AUTOMATION_HOST_EXECUTION_WIRE_VERSION, USER_AUTOMATION_KERNEL_CAPABILITY,
    USER_AUTOMATION_KERNEL_MODULE_ID, USER_AUTOMATION_KERNEL_OPERATION,
    USER_AUTOMATION_KERNEL_PRINCIPAL_BINDING, USER_AUTOMATION_KERNEL_PRIVACY_CLASS,
    UserAutomationHostChannelBinding, UserAutomationHostExecutionClient,
    UserAutomationHostExecutionFailure, UserAutomationHostExecutionOperation,
    UserAutomationHostExecutionRequest, UserAutomationHostExecutionResponse,
    UserAutomationHostExecutionSession, UserAutomationHostExecutionTransport,
    UserAutomationHostOwnerBinding, decode_user_automation_host_execution_open_frame,
    decode_user_automation_host_execution_open_response_frame,
    decode_user_automation_host_execution_request_frame,
    decode_user_automation_host_execution_response_frame,
    user_automation_host_execution_open_frame, user_automation_host_execution_open_response_frame,
    user_automation_host_execution_request_frame, user_automation_host_execution_response_frame,
};
pub use user_automation_failure_history::{
    StoreUserAutomationFailureHistory, build_failure_transition,
};
pub use user_automation_runtime_handoff::{
    USER_AUTOMATION_TRANSITION_WIRE_ID, USER_AUTOMATION_TRANSITION_WIRE_VERSION,
    UserAutomationConfigurationPhase, UserAutomationExecutionPhase, UserAutomationHorizonOutcome,
    UserAutomationHorizonPhase, UserAutomationOperatorRuntime, UserAutomationOperatorTransition,
    UserAutomationRecoveryPhase, UserAutomationWakePhase, committed_configuration_state,
    run_now_wake_read_request,
};
pub use user_automation_store::{
    CanonicalUserAutomationStore, UserAutomationNamedReadProvenance, UserAutomationOwnerLookup,
    UserAutomationOwnerReadProvenance, UserAutomationOwnerSnapshot,
};
pub use wasm_dispatch::{
    DeliveryReclaimOutcome, JoinDeny, MAX_DELIVERY_PAYLOAD_BYTES, MAX_DELIVERY_SLOTS,
    WASM_DELIVERY_IDENTITY_VERSION, WASM_DELIVERY_SLOT_DIR_NAME, WASM_DISPATCH_AUTHORITY_PREFIX,
    WASM_DISPATCH_DERIVATION_DOMAIN, WASM_DISPATCH_GRANT_WINDOW_MS,
    WASM_DISPATCH_LAUNCH_GRANT_HEAD, WASM_DISPATCH_MATERIAL_WIRE_ID,
    WASM_DISPATCH_MATERIAL_WIRE_VERSION, WASM_HOST_GUEST_ARTIFACT_FILE_NAME,
    WASM_HOST_GUEST_INPUT_FILE_NAME, WASM_HOST_MATERIAL_FILE_NAME, WasmAssuranceRecord,
    WasmDeliveryBackpressure, WasmDeliveryIdentity, WasmDeliveryReclamation,
    WasmDispatchDerivation, WasmDispatchError, WasmDispatchGrant, WasmDispatchMaterial,
    WasmGuestCeilings, WasmJoinGate, WasmJoinTable, WasmManifestRecord, WasmOwnerClaim,
    WasmPromotionRecord, WasmPublicationState, WasmPublishedBundle, WasmSnapshotRecord,
    WasmWorkRecord, discover_delivery_publications, material_bytes, publish_wasm_dispatch_bundle,
    publish_wasm_dispatch_material, wasm_dispatch_derivation,
    wasm_dispatch_derivation_from_epoch_json, wasm_dispatch_grant_for, wasm_join_gate,
};
pub use write_coordinator::{
    CoordinatorError, ScopeExecutionGuard, WriteCoordinator, WriteCoordinatorConfig,
    default_executor_lanes,
};

/// Boxed future for provider-neutral Kernel process operations.
pub type ProcessExecutionFuture<'a> =
    Pin<Box<dyn Future<Output = ProcessExecutionResponse> + Send + 'a>>;

/// Production client/port used by authenticated testd/native callers.
///
/// Implementations exchange only inert request and response projections. A
/// port never receives [`eliot_process::ProcessRequest`] or a dispatch permit.
pub trait ProcessExecutionClient: Send + Sync {
    /// Submits one closed process operation to the Kernel front door.
    fn execute(&self, request: ProcessExecutionRequest) -> ProcessExecutionFuture<'_>;
}

use eliot_contracts::{
    ContractIdentity, ContractVersion, contract_identity as make_contract_identity,
};
use thiserror::Error;

/// Stable wire name for the Kernel service boundary.
pub const CONTRACT_NAME: &str = "eliot.kernel.service";
/// Current wire revision for the Kernel service boundary.
pub const CONTRACT_VERSION: ContractVersion = ContractVersion::new(1, 0, 0);
/// Stable neutral route identity for the canonical Store bridge.
pub const STORE_ROUTE_IDENTITY: &str = "store_bridge";
/// Stable neutral module identity used by the Store EBP contract.
pub const STORE_MODULE_IDENTITY: &str = "eliot-store";

/// Errors produced while deriving the service contract identity.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum ContractIdentityError {
    /// The canonical contract shape could not be encoded.
    #[error("kernel service contract shape could not be serialized")]
    Serialization,
    /// A foundation contract rejected the identity.
    #[error("foundation contract: {0}")]
    Foundation(#[from] eliot_contracts::ContractError),
}

/// Returns the stable identity used by Host/Kernel protocol handshakes.
pub fn contract_identity() -> Result<ContractIdentity, ContractIdentityError> {
    #[derive(serde::Serialize)]
    struct Shape {
        surface: &'static str,
        version: ContractVersion,
        admission_rule: &'static str,
        handoff_rule: &'static str,
        unknown_rule: &'static str,
    }

    make_contract_identity(
        CONTRACT_NAME,
        CONTRACT_VERSION,
        &Shape {
            surface: "host_handoff_lifecycle_readiness_admission",
            version: CONTRACT_VERSION,
            admission_rule: "ready_requires_exact_handshake_process_health_and_supervision",
            handoff_rule: "candidate_starts_without_authority_and_consumes_one_nonce_once",
            unknown_rule: "unknown_external_state_closes_admission_and_requires_recovery",
        },
    )
    .map_err(ContractIdentityError::Foundation)
}

/// Validates an identity without carrying platform or secret material.
pub(crate) fn validate_text(value: &str, field: &'static str) -> Result<(), KernelServiceError> {
    if value.trim().is_empty() {
        return Err(KernelServiceError::InvalidField {
            field,
            reason: "must be non-blank",
        });
    }
    if value.chars().any(char::is_control) {
        return Err(KernelServiceError::InvalidField {
            field,
            reason: "must not contain control characters",
        });
    }
    if value.len() > 1024 {
        return Err(KernelServiceError::InvalidField {
            field,
            reason: "must not exceed 1024 UTF-8 bytes",
        });
    }
    Ok(())
}
