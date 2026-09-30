//! Production N4 Governor daemon composition root.
//!
//! `eliotd` owns application scheduling and the pure Governor projections. It
//! does not own a Kernel, a canonical store client, a store adapter, or a
//! physical process executor. Canonical transitions leave this process only
//! through the neutral authenticated [`KernelTransitionPort`].

#![forbid(unsafe_code)]

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use eliot_contracts::{EpochId, OperationId, ResourceGeneration, StateFence};
use eliot_governor::{
    CompositionError, CompositionReadiness, FinishAttemptDraft, FinishAttemptError,
    GovernorActivationOutcome, GovernorComposition, GovernorLaunchConfig, KernelGenerationPort,
    KernelGenerationSnapshotProvider, PreparedFinishDecision, PreparedKernelExchange, QueueLimits,
};
use eliot_kernel_core::Notification;
use eliot_platform_windows::{ProtectedPathError, ProtectedRuntimePathLease};
use eliot_protocol::{
    AgentActivationOwnerEvidence, AgentActivationOwnerReadback, AgentActivationResolutionResult,
    AgentActivationResolutionTicket, AgentActivationResolvedBinding, RequestIdentity,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[cfg(test)]
use eliot_contracts::RequestId;
#[cfg(test)]
use eliot_platform_windows::{KernelFrontDoorAclMode, KernelFrontDoorServerExpectation};
#[cfg(test)]
use eliot_protocol::{ProtocolVersion, ServerHello};
#[cfg(test)]
use std::sync::atomic::Ordering;

mod activation_projection;
pub mod agent_fabric;
pub mod campaign_context_owner;
pub mod campaign_evaluation_owner;
pub mod campaign_owner_matrix;
pub mod campaign_packet;
pub mod campaign_task_controller;

pub use campaign_context_owner::build_context_owner_publications;
pub use campaign_evaluation_owner::build_product_evaluation_publications;
pub use campaign_owner_matrix::assemble_authenticated_campaign_owner_publications;
pub use daemon_kernel_client::FinishSubmitOutcome;
pub use finish_attempt::serve_finish_claim;
pub mod canonical_config_precedence;
mod capability_admission;
mod capability_evidence_wiring;
pub mod capability_outcome;
/// Issue #2857 W1/W2/W4: the live `eliot.query` `ContextReconstruction`
/// route. This is the one production edge that resolves the closed selector set
/// from the admitted envelope plus the authenticated Task Controller owner and
/// calls `KernelContextReadClient::reconstruct_context_inputs`, the existing
/// Governor composition edge over `GovernorContextInputs`.
pub mod context_reconstruction_route;
mod controlboard_adapters;
mod daemon_config;
mod daemon_kernel_client;
mod daemon_kernel_port_adapters;
pub mod diagnostics;
mod dreamer_admission;
mod dreamer_materials;
mod dreamer_model_adapter;
/// Execution-path `OpenMetrics` wiring (issue #1841, I16.1/I16.2/I16.5): the
/// bounded schema, labels, registry and exporter stay owned by
/// `eliot-observability-runtime`; this module only installs that stack and maps
/// observations the daemon's own owners already hold onto its catalogue.
pub mod execution_metrics;
mod experience_runtime;
pub mod external_attach_reconciliation;
pub mod finish_attempt;
mod first_run_wiring;
mod freshness_admission;
/// Issue #1948: the governed source owner readback edge. Reopens the exact
/// admitted owner document through the authenticated `GetCampaignSourceRevision`
/// read and projects a citation only after the citation gate verifies the
/// reopened bytes against the owner-recorded digest, byte length and excerpt
/// digest. Called from the live `eliot.packet` retrieval-to-projection path.
pub mod governed_source_readback;
mod governor_authority_feed;
mod governor_local_read;
mod governor_observe_serve;
pub mod improvement_candidate_route;
pub mod improvement_intake;
/// Issue #1867 W1: the production improvement-intake dispatch. This is the
/// live call site that reaches `eliot-improvement` from the daemon run loop
/// over a real maintenance observation and commits the owner-actionable
/// artifact durably through the Governor `RecordLearningRecord` seam.
pub mod improvement_intake_dispatch;
mod kernel_authority_client;
mod kernel_context_read_client;
mod kernel_recovery_client;
mod kernel_transition_client;
pub mod maintenance_family_catalog;
mod maintenance_trigger_evaluator;
pub mod notification_acknowledge_emit;
pub mod notification_board_attach;
pub mod notification_state_emit;
mod observation_adapters;
mod owner_feed;
mod process_origin;
pub mod provider_transport_policy;
mod reactive_feed;
mod route_execution_identity;
mod route_receipts;
mod skill_acceptance_read;
mod skill_bridge_adapter;
pub mod skill_dispatch;
mod skill_evidence_read;
mod skill_lifecycle_adapters;
mod skill_surface_adapters;
pub mod solo_agent_driver;
pub mod staffing_policy;
pub mod startup_capability_bindings;
pub mod startup_evidence_producer;
pub mod startup_readiness;
mod store_failure_projection;
pub mod supervision_progress;
pub mod swarm_composition;
pub mod task_binding_admission;
mod task_lifecycle_adapters;
pub mod testd_terminal_completion;

pub use activation_projection::AgentActivationResolver;
pub use activation_projection::{
    ActivationClaim, classify_claimed_ticket_value, terminal_for_invalid_ticket,
};
#[cfg(test)]
use agent_fabric::build_admitted_provider_capability;
pub use agent_fabric::{
    ActivationAuthorityPort, ActivationEvidence, AdmissionAuthorityPort, AgentFabric,
    AgentFabricDescriptor, AttemptLifecycle, AttemptResultRecord, COORDINATOR_CRATE,
    CancellationLifecycle, DAEMON_CRATE, DispatchAck, DispatchEgressPort, DispatchIntent,
    FABRIC_CAPACITY_IDENTITY, FABRIC_CAPACITY_REVISION, FABRIC_PLAN_GAP_REASON, FabricAdmission,
    FabricError, FabricPorts, FabricSnapshot, LedgerEntry, ModelRegistryPort, PREREQ_PORTS,
    PeerChannelPort, PeerMessage, PeerReceipt, Reservation, RouteRequirements, SwarmControlPort,
    SwarmDefinition, SwarmEntryReceipt, VerifiedProviderMaterial, WorkerAck,
    daemon_coordinator_config, plan_candidate, prepare_swarm_definition_admission_candidate,
    prereq_ports,
};
use agent_fabric::{FabricOperation, FabricPortId, MissingPortResidual, PortBindingState};

use controlboard_adapters::SharedOperatorReplay;

pub use canonical_config_precedence::{
    ALL_LAYERS, CANONICAL_SETTING_KEY, ConfigLayer, LayerInput, PrecedenceError, ResolvedChain,
    ResolvedContribution, canonical_layer_json_schema, canonical_layer_json_schema_pretty,
    classify_policy_input, parse_canonical_layer_json, parse_canonical_layer_toml,
    resolve_canonical_chain,
};
pub use capability_admission::{
    AdmissionDisposition, AdmissionOutcome, CapabilityEvidenceRecord, CapabilityEvidenceStatus,
    DynamicCapabilityPulse, ProductionAdmissionRequest, ProductionEvidenceBundle,
    RouteAdmissionDecision, StaticCapabilityAttestation, admit_production_route,
    canonical_required_set, evaluate_production_admission,
};
pub use capability_evidence_wiring::{
    CapabilityHydrationReport, EvidenceBridgeError, EvidenceRecordPage,
    GovernorCapabilityAdmission, ObservedLifecycleSummary, ScopeChangeRestrictionReport,
    commit_scope_change_restriction, drain_capability_evidence_records,
};
pub use capability_outcome::{
    AttemptReceipt, CapabilityOutcome, CapabilityRegistryView, DegradationProjection,
    DegradationScope, FallbackOutcomeRequest, GenerationChallengeOutcomeRequest,
    OutcomeDisposition, OutcomeError, SURVIVING_OPERATION_PREFIX, fallback_outcome,
    generation_challenge_outcome, project_degradation, removed_promise, surviving_operation,
};
pub use context_reconstruction_route::{
    ReconstructionPrerequisite, is_context_reconstruction_query, serve_context_reconstruction,
};
pub use controlboard_adapters::{
    CONTROLBOARD_READ_CAPABILITY, ControlBoardReadOutcome, ControlBoardRefusal,
    controlboard_notification_refresh_refusal_body, controlboard_result_body,
    is_controlboard_read_tool, serve_controlboard_view,
};
pub use daemon_config::{DaemonConfig, admit_daemon_module_manifest};
#[cfg(windows)]
pub use daemon_kernel_client::admitted_daemon_module_contract;
pub(crate) use daemon_kernel_client::kernel_port_error;
pub use daemon_kernel_client::{
    ActivationSubmitError, DaemonKernelClient, LocalReadSubmitOutcome, ObserveDeferOutcome,
    ObserveSubmitOutcome, OwnerSessionFacts, TaskControllerSubmitOutcome,
};
#[cfg(test)]
pub(crate) use daemon_kernel_client::{KernelClientError, WireOutcome, operation_payload};
#[cfg(all(test, windows))]
pub(crate) use daemon_kernel_client::{
    is_pre_admission_pending_rejection, retry_pre_admission, validate_server_hello,
};
pub use daemon_kernel_client::{parse_local_read_claimed_pair, parse_local_read_submit_outcome};
pub use daemon_kernel_client::{
    parse_observe_claimed_pair, parse_observe_defer_outcome, parse_observe_submit_outcome,
};
pub(crate) use daemon_kernel_port_adapters::kind_value;
pub use dreamer_admission::{
    DREAMER_JOB_WIRE_ID, DreamerJobQueue, GovernorDreamerAdapter, KernelDreamerJobQueue,
    OrientationSubmitInput,
};
pub use dreamer_materials::{
    AdmittedSourceClaim, DreamerMaterialsError, FrozenOrientationManifest,
    ORIENTATION_EVIDENCE_MAX_RECORDS, ORIENTATION_MATERIAL_MAX_SOURCE_BYTES,
    ORIENTATION_MATERIAL_MAX_SOURCES, ORIENTATION_MATERIAL_MAX_TOTAL_BYTES,
    ORIENTATION_MATERIAL_PRIVACY_ADMITTED, ORIENTATION_MATERIAL_ROUTE_ADMITTED,
    OrientationMaterialBudget, freeze_orientation_manifest, resolve_source_claim,
    verify_resolved_bytes,
};
pub use dreamer_model_adapter::{
    DAEMON_GENERATION_PROJECTION_OPERATION, DreamerModelExecution, GovernedDreamerModelAdapter,
    KernelGenerationProjection, ModelInvokeInput, query_kernel_generation,
};
pub use experience_runtime::{
    CommonGroundEventInputs, ExperienceCommitOutput, ExperienceDriverError,
    ExperienceJournalDriverInputs, ExperienceQualityEvent, ExperienceQualityEventOutput,
    UnderstandingEventInputs, commit_experience_event_records, derive_commit_ingress,
    produce_journal_projection, propose_memory_extinction_candidate, read_current_position,
    run_experience_quality_event, run_experience_quality_event_with_revision,
};
pub use external_attach_reconciliation::{
    AutomaticLaunchRefusal, ContinuationKind, CredentialDisposition,
    EXTERNAL_ATTACH_RECONCILIATION_REQUIRED, ExternalAttachBindingView, ExternalAttachBridgeClaim,
    ExternalAttachIngressRecord, ExternalAttachObservation, ExternalAttachReconciliationReceipt,
    ExternalEffectDisposition, ImportedPreAttachCoverage, ObservedAttachCandidates,
    PendingAttachAction, PreAttachBlindInterval, PreAttachStanding, ScopeAuthorityDisposition,
    UnownedContinuation, WorkspaceArtifactDelta, admit_automatic_agent_launch,
    admit_material_continuation, admit_material_continuation_for_record, binding_view,
    claim_bridge_attach, reconcile_external_attach, replay_bridge_external_attach,
    serve_bridge_external_attach,
};
pub use first_run_wiring::{
    DisabledAutomationOutcome, FirstRunWiringError, inspect_first_run_defaults,
    recommend_for_disabled_automation, resolve_first_run_routes,
};
pub use freshness_admission::{
    CANDIDATE_COMMITTED_PROJECTION_PENDING, CandidateFetchOutcome, CommittedCandidate,
    FreshnessAdmission, FreshnessDisposition, FreshnessError, FreshnessEvaluation,
    ObservedPublication, ProvenanceStanding, RequestedEffect, ReusableCandidateView, RevisionHead,
    TaskCompatibility, evaluate_freshness_admission, fetch_committed_candidate, normalize_heads,
    observed_publication, publication_serves_candidate,
};
pub use governor_authority_feed::{
    maintain_governor_authority_feed, maintain_governor_authority_route_mismatch,
};
pub use governor_local_read::{
    answer_evidence_query, answer_projection_inputs, forward_admitted_local_read,
    serve_admitted_local_read,
};
pub use governor_observe_serve::{
    ObserveDeferral, ObserveOwnerRoute, ObserveSuboperation, decode_observe_suboperation,
    observe_suboperation_owner, serve_admitted_observe,
};
pub use improvement_candidate_route::{
    ImprovementRouteRequest, assess_improvement_repeat, improvement_candidate_retry_permitted,
    improvement_operation_owners, improvement_route_owner, reconcile_improvement_unknown,
    route_improvement_candidate,
};
pub(crate) use kernel_authority_client::KernelAuthorityClient;
pub use kernel_context_read_client::{KernelContextReadClient, ReconstructionReadComposition};
pub use maintenance_trigger_evaluator::{
    MaintenanceObservation, MaintenanceTriggerOrigin, SELF_OBSERVED_FAMILY, UNRESOLVED_AUTHORITIES,
};
pub use notification_acknowledge_emit::emit_notification_acknowledgement;
pub use notification_state_emit::{
    AutomationFailureKey, NotificationStateEmit, automation_failure_key,
    emit_blocked_automation_notification, notification_already_recorded,
    read_notification_ordering_head,
};
pub use owner_feed::{
    KernelOwnerPublishPort, OwnerFeedPlan, OwnerFeedTrigger, capture_owner_feed_plan,
    maintain_owner_feed,
};
pub use process_origin::{
    CapabilityEvidenceSource, Generation, OperationDisposition, OriginChallenge,
    OriginChallengeAuthority, OriginChallengeRequest, OriginControlGrant, OriginControlOperation,
    OriginControlPresentation, PROCESS_ORIGIN_CAPABILITY, PhysicalProcessBinding,
    ProcessCapabilityEvidence, ProcessControlOperation, ProcessOriginError, ProcessOriginEvidence,
    ProcessStatusReceipt, canonical_origin_digest, gate_process_control, request_origin_control,
};
pub use reactive_feed::{ReactiveFeedError, ReactiveFeedOutcome, drive_reactive_delivery_once};
pub use route_execution_identity::{
    DeclaredRoute, ExecutionIdentity, LaunchAuthority, RouteIdentityError, admit_declared_launch,
    declared_continuity, declared_route_key,
};
pub use route_receipts::{
    GovernorRouteAttempt, RouteAdmissionVisibility, RouteCapabilityIndex, RouteReceiptError,
    RuntimeObservedFacts, UNKNOWN_ROUTE_FACT, effective_route_key,
};
pub use startup_evidence_producer::{
    DAEMON_STARTUP_EVIDENCE_OPERATION, EliotdStartupEvidence, MAX_CAPABILITY_OUTCOMES,
    MAX_EVIDENCE_REFS, MAX_REQUIRED_CAPABILITIES, MirrorObservation, RetainedCapabilitySummary,
    StartupEvidenceError, StartupEvidenceRequest, build_startup_evidence,
    publish_daemon_startup_evidence, summarize_retained_capabilities,
};
pub use store_failure_projection::{GovernorStoreFailureProjection, GovernorStoreProjectionError};
pub use supervision_progress::{
    DAEMON_SUPERVISION_PROGRESS_OPERATION, DaemonReadySupervision, STORE_DEPENDENCY_WAIT_NAME,
    SupervisionProducerDeps, SupervisionProgressAnswer, SupervisionProgressHead,
    SupervisionProgressLineage, SupervisionProgressProducer, SupervisionTickInputs,
    parse_daemon_ready_supervision, parse_progress_answer, progress_submit_payload,
    store_dependency_dimension,
};

/// Builds the production P-07 authority adapter over an already-connected
/// authenticated Kernel client.
///
/// The adapter type stays private to this crate; only the port object crosses
/// into the daemon runtime wiring, which passes it to
/// [`DaemonComposition::start`]. Until the Kernel front-door grant route lands
/// (T6/#15) the adapter fails closed on every presentation — honest diagnosed
/// degradation, never invented rights.
pub fn kernel_authority_port(
    kernel: &Arc<DaemonKernelClient>,
) -> Arc<dyn eliot_authority::P07AuthorityPort> {
    Arc::new(KernelAuthorityClient::new(Arc::clone(kernel)))
}

/// Stable daemon identity.
pub const SERVICE_NAME: &str = "eliotd";
/// Stable daemon protocol revision.
pub const PROTOCOL_VERSION: &str = "eliot.daemon.v1";
/// Protected Host-approved launch configuration relative to `ProgramData`.
pub const PROTECTED_CONFIG_RELATIVE: &str = r"Eliot\governor\eliotd.json";
/// Protected daemon state directory relative to `ProgramData`.
pub const PROTECTED_STATE_RELATIVE: &str = r"Eliot\governor\state";
/// Maximum accepted launch-config bytes.
pub const MAX_CONFIG_BYTES: u64 = 128 * 1024;
/// Host-approved Kernel front-door identity. The pipe name is fixed; the
/// account SID/session expectation is observed from the current installed
/// service token and then checked against the live authenticated peer.
const KERNEL_PIPE_NAME: &str = r"\\.\pipe\eliot\kernel\frontdoor";
const KERNEL_OPERATION_TIMEOUT: Duration = Duration::from_secs(30);
const PRE_ADMISSION_RETRY_DELAY: Duration = Duration::from_millis(25);
const ELIOTD_RECEIPT_PENDING_REJECTION: &str = "required lower-layer adapter is unavailable: eliotd-process-receipt (exact launched process receipt publication is pending)";

#[derive(Clone, Debug)]
struct KernelLaunchBinding {
    kernel_pipe_name: String,
    expected_kernel_sid: String,
    expected_kernel_session_id: u32,
    module_generation: ResourceGeneration,
    authority_epoch: EpochId,
    state_fence: StateFence,
    launch_nonce: String,
    kernel_artifact_sha256: String,
    daemon_artifact_sha256: String,
}

/// Errors raised while loading or composing the daemon.
#[derive(Debug, Error)]
pub enum DaemonError {
    /// Protected `ProgramData` path policy rejected the requested object.
    #[error("protected daemon path: {0}")]
    Protected(#[from] ProtectedPathError),
    /// The protected launch file was not a valid typed config.
    #[error("launch configuration: {0}")]
    LaunchConfig(String),
    /// Exact Kernel/provider or Governor recovery admission failed.
    #[error("Governor composition: {0}")]
    Composition(#[from] CompositionError),
    /// Governor-owned FinishAttempt evaluation or canonical persistence
    /// rejected the candidate.
    #[error("Governor FinishAttempt: {0}")]
    Finish(#[from] FinishAttemptError),
    /// Authenticated Kernel B1 transport or admission failed.
    #[error("Kernel B1 transport: {0}")]
    Kernel(String),
    /// The Kernel durably linearized deadline expiry before result admission.
    /// This is a settled result-less outcome, not a lost acknowledgement.
    #[error("Kernel activation result deadline expired before admission")]
    ActivationExpired,
    /// A second daemon owner cannot be admitted in this process.
    #[error("daemon lifecycle: {0}")]
    Lifecycle(String),
    /// Verified provider admission (issue #1108) failed fail-closed. The
    /// coordinator/owner rejection is preserved unchanged, never
    /// stringified, so the driver distinguishes blocked evidence from
    /// retryable transport without collapsing the typed failure.
    #[error(transparent)]
    ProviderAdmission(#[from] FabricError),
    /// Governor-owned maintenance trigger evaluation or Durable Job
    /// admission (I14.22, issue #1688) failed fail-closed. The owner's own
    /// [`eliot_maintenance::MaintenanceError`] is preserved unchanged and
    /// never stringified, so a driver can still tell an unresolved trigger
    /// identity from a stale fence, a missing evidence set, or an exhausted
    /// attempt budget instead of collapsing them into one lifecycle message.
    #[error("Governor maintenance: {0}")]
    Maintenance(#[from] eliot_maintenance::MaintenanceError),
    /// Task-binding admission at the daemon ingress edge rejected the
    /// transition (issue #1929, I5.5/I5.6).
    ///
    /// The typed code travels unchanged: the wrapped error renders the stable
    /// wire token (`TASK_SELECTION_REQUIRED` or `TASK_SCOPE_INCOMPATIBLE`)
    /// ahead of the bounded detail, so no code is collapsed into prose between
    /// the admission edge and the caller. The rejection happens before the
    /// Governor commit, so neither the task nor the store is touched.
    #[error(transparent)]
    TaskBinding(#[from] crate::task_binding_admission::TaskBindingError),
}

/// Typed revision-fence match failure for the daemon cache gate (issue #18
/// W6/A5).
///
/// Daemon caches and hot mirrors are revision-keyed and rebuildable. This
/// gate guards cache refresh/admission only: it never swallows or
/// reinterprets a durable store receipt. No `HeadMismatch` arm exists here
/// by intent — [`eliot_governor::KernelGenerationSnapshot`] carries no
/// revision heads, so head comparison stays with the #15 port.
#[derive(Clone, Debug, Eq, PartialEq, Error)]
pub enum RevisionFenceMismatch {
    /// No fence was ever cached (the composition never admitted one).
    #[error("daemon revision fence was never built")]
    NeverBuilt,
    /// The dependent view is already stale/pending: the caller drops this
    /// composition and re-runs authenticated connect+start.
    #[error("daemon view is stale; drop and re-run authenticated connect+start")]
    StaleView,
    /// The cached fence no longer equals the live Kernel fence.
    ///
    /// Both fences are boxed: [`StateFence`] carries epoch/revision
    /// identity and would otherwise push this `Err` variant past the
    /// `result_large_err` bound (and inflate every future holding it).
    #[error("daemon cached revision fence does not match the live Kernel fence")]
    FenceMismatch {
        /// Fence the cache was built against.
        expected: Box<StateFence>,
        /// Fence observed on the live snapshot.
        observed: Box<StateFence>,
    },
}

fn unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(1, |duration| {
            u64::try_from(duration.as_millis().min(u128::from(u64::MAX))).unwrap_or(u64::MAX)
        })
}

fn unix_ms_i64() -> i64 {
    i64::try_from(unix_ms()).unwrap_or(i64::MAX)
}

/// Reports whether a finish may carry pending learning-closure debt.
///
/// Thin composition-root tag only (issue #1866 W1/W4/A1/A2, I12.24): the
/// named closure owner and review condition come from Governor policy, never
/// from this crate. `terminal` is supplied by the caller owning finish
/// semantics; this helper only forwards it so the finish hook stays honest
/// and non-blocking.
#[must_use]
pub fn closure_debt_pending(terminal: bool) -> bool {
    terminal
}

/// Returns the Governor maintenance owner for the improvement candidate route.
///
/// Production caller of [`improvement_candidate_route::improvement_route_owner`];
/// keeps the candidate → experiment → evaluation → admission path rooted in the
/// daemon composition root without adding policy semantics here.
#[must_use]
pub fn governed_improvement_pipeline_owner() -> &'static str {
    improvement_candidate_route::improvement_route_owner()
}

/// Routes one improvement candidate through the Governor-owned pipeline.
///
/// #2703: this function IS a caller of
/// [`improvement_candidate_route::route_improvement_candidate`] (and
/// transitively of `eliot_maintenance::run_improvement_candidate_pipeline` and
/// `admit_improvement_candidate`), but it is NOT itself called from any live
/// request path: `ImprovementRouteRequest` is never constructed in `bins/` or
/// `crates/`. The typed result mapping behind this call is exhaustive and
/// correct; the missing link is a production request source, which is #1145's
/// owner scope. Do not cite this function as evidence that the improvement
/// pipeline is wired into the daemon.
///
/// It remains a pure thin forwarder for the candidate → experiment → independent
/// evaluation → rejected-or-canary-admitted path (#1100/#18/#20); Kernel
/// activation (#11) stays a handoff, never executed here.
pub fn govern_improvement_candidate(
    request: improvement_candidate_route::ImprovementRouteRequest<'_>,
) -> Result<eliot_maintenance::ImprovementTerminalDisposition, eliot_maintenance::PipelineError> {
    improvement_candidate_route::route_improvement_candidate(request)
}

/// Readiness/status projection emitted by the daemon. It is derived only
/// after exact Kernel and recovery admission.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DaemonStatus {
    /// Service identity.
    pub service: String,
    /// Daemon protocol revision.
    pub protocol: String,
    /// Active Kernel resource generation.
    pub generation: u64,
    /// Active authority epoch.
    pub authority_epoch: u64,
    /// Whether the owner set is admitted and accepting work.
    pub ready: bool,
    /// Bounded health projection for operators and the control loop.
    pub health: String,
    /// Whether normal admission is closed while the process remains observable.
    pub degraded: bool,
}

/// Versioned canonical tool view the tool owner supplies for a versioned
/// Skill install (issue #1882).
///
/// Bundles the live tool-owner source, the Skill-owned alias table, and the
/// Governor-admitted definition version so the composition seam
/// ([`DaemonComposition::skill_install_package_versioned`]) carries every
/// owner term explicitly without exceeding the arity lint. The admitted
/// version must equal the install context's recorded version; drift fails
/// closed inside the shared handle before any catalogue write. The view is
/// `Copy` so the by-value seam parameter introduces no pass-by-value lint.
#[derive(Clone, Copy)]
pub struct VersionedToolView<'a> {
    /// Live tool-owner source reporting the definition version it binds.
    pub source: &'a dyn eliot_skill::CanonicalToolSource,
    /// Skill-owned alias table resolving provider renames to canonical names.
    pub aliases: &'a eliot_skill::ToolAliasTable,
    /// Governor-admitted definition version the install records.
    pub admitted_definition_version: &'a str,
}

/// The one production daemon composition. Application scheduling belongs here;
/// physical process execution and canonical persistence remain outside it.
pub struct DaemonComposition {
    governor: GovernorComposition<dyn KernelGenerationPort>,
    config_lease: ProtectedRuntimePathLease,
    state_lease: ProtectedRuntimePathLease,
    config_path: PathBuf,
    state_root: PathBuf,
    started: bool,
    /// Process-retained operator replay handle shared by every board built
    /// through [`DaemonComposition::controlboard`].
    ///
    /// Volatile fast path only, never durability: a newly created board
    /// replays an already-admitted operation without a second effecting-port
    /// call while the process lives. Cross-restart durability is NOT owned by
    /// Kernel ORS through an async Governor operator borrow: the borrow reaches
    /// only `KernelTransitionPort::receipt`, whose `eliot_store_api::WriteReceipt`
    /// carries neither the `session_id` nor the `access_digest` a reconciled
    /// board receipt must carry, so the contract this would need is a
    /// command-receipt projection read for the exact `OperationId` that no
    /// reachable port returns. Post-commit refreshes retain this handle without
    /// ever clearing it.
    operator_replay: SharedOperatorReplay,
    /// Set when a post-commit refresh fails after the write receipt was
    /// already durable. The dependent view is stale/pending until the caller
    /// drops this composition and re-runs authenticated connect+start.
    view_stale: bool,
    /// Revision fence the daemon cache was built against (issue #18 W6/A5).
    ///
    /// Caches and hot mirrors are revision-keyed and rebuildable: this
    /// cached fence never creates freshness or authority, it only keys the
    /// dependent view so a fence move surfaces as an exact mismatch instead
    /// of silent divergence. Admitted at [`Self::start`] from the Kernel
    /// snapshot, re-keyed only when
    /// [`Self::require_revision_fence_match`] observes an exact match after
    /// a store commit, and never cleared by a refresh. Daemon loss leaves
    /// the Kernel able to fence, cancel, and reconcile: durable truth stays
    /// downstream, never here.
    ///
    /// Boxed so the composition stays small for futures holding it.
    cached_revision_fence: Option<Box<StateFence>>,
    /// Owner receipts for experience-bank/feedback records this composition
    /// already committed, keyed by deterministic idempotency key (P1-1,
    /// issue #1942).
    ///
    /// The store idempotency rule matches on the operation+key+hash triple:
    /// re-submitting a committed key under freshly derived expected heads
    /// builds a different hash and wedges permanently in `IdentityConflict`.
    /// The commit entry therefore consults this map first and reuses the
    /// retained receipt instead of re-deriving expectations for an
    /// already-attempted key, so retry converges by construction without
    /// weakening the triple rule and without minting new operation
    /// identities. Volatile fast path only, like `operator_replay`: durable
    /// truth stays with the owner receipts, never with this map.
    committed_experience: BTreeMap<String, eliot_store_api::WriteReceipt>,
    /// Already-validated Kernel-issued owner session facts threaded once by
    /// the daemon runtime where the concrete client and this composition meet
    /// (AUD-C02-B, Implements #1187). Facts only, never the client itself:
    /// [`DaemonComposition::controlboard`] builds at most one admitted owner
    /// binding from them. `None` until the runtime notes a live session, so
    /// boards keep the empty (unadmitted) behaviour without one.
    owner_session: Option<OwnerSessionFacts>,
    /// Canonical notification records hydrated from the closed
    /// `GetNotificationState` read (issue #1780).
    ///
    /// Mirrors `capability_admission`: constructed empty at
    /// [`DaemonComposition::start`], hydrated by the daemon runtime attach
    /// where the concrete client and this composition meet (see
    /// `notification_board_attach`), and consumed by
    /// [`DaemonComposition::controlboard`]. An empty supply reads as an
    /// empty inbox, never as resolved or suppressed state.
    notification_snapshot: Vec<Notification>,
    /// Shared Governor Skill catalogue handle for catalogue-guarded skill
    /// promotion. Empty until catalogue installation wiring lands; absent
    /// entries forward open-world.
    skill_catalogue: skill_lifecycle_adapters::CatalogueHandle,
    /// Daemon-held Governor capability admission view (issue #1957).
    ///
    /// Constructed empty at [`DaemonComposition::start`], hydrated from the
    /// canonical `GetCapabilityEvidenceState` read and the legacy importer,
    /// and consulted by the daemon route gate before a resolved route may
    /// execute. Semantics stay in the Governor registry; this is the
    /// composition root's handle on that view.
    capability_admission: GovernorCapabilityAdmission,
    /// Daemon-held Governor outcome registry view (issue #1961, I3.4).
    ///
    /// Constructed empty at [`DaemonComposition::start`] and owned here for
    /// the daemon's lifetime, so a broad degradation outcome recorded by one
    /// model-invoke attempt applies to later attempts instead of dying with
    /// the call that observed it. Only evidence-backed broad scopes are
    /// stored (installation blocks, generation blocks keyed by exact
    /// fingerprint, session blocks keyed by session owner); item-, call- and
    /// attempt-scoped outcomes are never stored here and stay visible on the
    /// attempt receipt that produced them.
    ///
    /// Interior mutability is the established pattern on this composition
    /// root (see `skill_catalogue`): the governed model adapter borrows
    /// `&DaemonComposition`, so a held view it must record into cannot be
    /// reached through a `&mut` accessor without changing that lifetime.
    /// Semantics stay in [`CapabilityRegistryView`]; this field is only its
    /// owner. It is in-process state: a restart re-derives from evidence
    /// rather than reading a durable record back, and no canonical-store
    /// persistence is claimed for it here.
    capability_outcomes: std::sync::Mutex<CapabilityRegistryView>,
    /// Governor-owned durable learning-closure owner (issue #1863, I12.24).
    ///
    /// Constructed empty at [`DaemonComposition::start`] and owned by the
    /// single [`eliot_governor::LearningClosureService`]. The live finish
    /// ceremony commits one durable `AttemptLearningDelta` edge per
    /// consequential attempt through it (see
    /// [`DaemonComposition::close_attempt_learning`]). It holds no authority,
    /// performs no transport, and is never read on the readiness path: closure
    /// must not block or fail the finish ceremony.
    learning_closure: eliot_governor::LearningClosureService,
    /// The single live Governor-owned coverage-to-authority derivation
    /// instance for this daemon (issue #1935 AUD1, I7.16).
    ///
    /// Constructed empty at [`DaemonComposition::start`] and owned here for
    /// the daemon's lifetime, so every projection published across the
    /// authenticated `publish_governor_authority` boundary derives from one
    /// revision sequence: a degraded re-derivation publishes a new revision
    /// that revokes everything issued under the old one. Fed only from
    /// threaded live host/Watchdog/trace observation through
    /// [`maintain_governor_authority_feed`](crate::maintain_governor_authority_feed);
    /// nothing is derived here and no coverage is synthesized.
    governor_authority: eliot_governor::LiveGovernorAuthority,
    /// Retained ingress record for an attach of an already-running
    /// external agent (issue #1782, I11.11 lines 27-42).
    ///
    /// `None` until an ingress installs a caller-observed receipt, which is
    /// what an empty supply honestly means: no external agent has attached,
    /// so there is nothing to reconcile. It is never defaulted to a
    /// reconciled attach and never derived from this process's own
    /// config/state directories, which are not a user `WorkScope`. The
    /// record joins the compiled receipt to the exact Bridge
    /// request/session/task/fence binding it was compiled under plus the
    /// live Governor fence and Kernel-issued owner session observed at
    /// ingest. Read by [`Self::admit_material_continuation_after_attach`]
    /// and [`Self::admit_material_continuation_for_attach`], which refuse a
    /// stale, substituted, or unattributed continuation, and by
    /// [`Self::replay_bridge_external_attach`], which reads back the exact
    /// retained binding on replay.
    external_attach: Option<Box<ExternalAttachIngressRecord>>,
    /// Retained solo-agent driver state (issue #2567).
    ///
    /// Holds the bounded solo intake queue plus the single live attempt
    /// operation: at most one unsettled solo attempt exists, so a second
    /// drive refuses instead of overlapping ownership. Interior mutability
    /// follows the established `skill_catalogue` pattern: the runtime poll
    /// hook and the direct drive entry borrow `&DaemonComposition`, so the
    /// slot cannot be reached through a `&mut` accessor. Semantics stay in
    /// [`solo_agent_driver`](crate::solo_agent_driver); this field is only
    /// its owner. The durable truth is the state-root projection the driver
    /// persists before emit, never this slot.
    solo_state: std::sync::Mutex<solo_agent_driver::SoloDriverState>,
    /// The single Governor-owned durable swarm-plan attachment composition
    /// (issue #1126 W1/A1).
    ///
    /// Owns exactly one [`eliot_governor::SwarmPlanAttachmentService`] over
    /// its canonical store image, so every swarm consumer vended through
    /// [`DaemonComposition::swarm_composition`] converges on one durable-job
    /// owner: the first job commits, an identical replay is idempotent, and
    /// a second job observes the canonical winner. Cross-process durability
    /// of the store image itself follows the canonical-write envelope wiring
    /// (remainder, #1699); this field never claims it.
    swarm_attachment: eliot_governor::SwarmAttachmentComposition,
}

/// Production B-MOD model registry port (issue #1108 W4/A2).
///
/// Closed over the retained composition: the registry owner (B-MOD #694) has
/// no accepted interface revision on this base, so the port honestly reports
/// [`PortBindingState::Missing`] and every resolution attempt raises the
/// typed [`FabricOperation::ResolveModelRoute`] residual instead of inventing
/// a route. Route ranking stays with the owner; owner delegation lands with
/// #694.
struct ProductionModelRegistryPort;

impl ModelRegistryPort for ProductionModelRegistryPort {
    fn resolve_route(
        &self,
        requirements: &RouteRequirements,
    ) -> Result<Option<eliot_agent_api::RouteFingerprint>, FabricError> {
        Err(blocked_port(
            FabricPortId::ModelRegistry,
            FabricOperation::ResolveModelRoute,
            requirements.role.clone(),
            None,
            None,
        ))
    }

    fn interface_binding(&self) -> PortBindingState {
        PortBindingState::Missing
    }
}

/// Production B-PEER coordination channel port (issue #1108 W4/A2).
///
/// Closed over the retained composition: the channel owner (B-PEER #696) has
/// no accepted interface revision on this base, so the port honestly reports
/// [`PortBindingState::Missing`] and every delivery attempt raises the typed
/// [`FabricOperation::DeliverPeer`] residual instead of emitting an
/// unverified delivery. Delivery stays with the owner; owner delegation
/// lands with #696.
pub(crate) struct ProductionPeerChannelPort;

impl PeerChannelPort for ProductionPeerChannelPort {
    fn deliver(&self, message: &PeerMessage) -> Result<PeerReceipt, FabricError> {
        Err(blocked_port(
            FabricPortId::PeerChannel,
            FabricOperation::DeliverPeer,
            message.message_id.clone(),
            None,
            None,
        ))
    }

    fn interface_binding(&self) -> PortBindingState {
        PortBindingState::Missing
    }
}

/// Production B-SWARM durable swarm control port (issue #1108 W4/A2).
///
/// Closed over the retained composition: the swarm control owner (B-SWARM
/// #698) has no accepted interface revision on this base, so the port
/// honestly reports [`PortBindingState::Missing`] and every plan entry
/// raises the typed [`FabricOperation::EnterSwarm`] residual instead of
/// entering an unadmitted plan. Plan ownership stays with the Task
/// Controller/Governor; owner delegation lands with #698.
pub(crate) struct ProductionSwarmControlPort;

impl SwarmControlPort for ProductionSwarmControlPort {
    fn enter_plan(
        &self,
        candidate: &eliot_agent_coordinator::StaffingPlanCandidate,
    ) -> Result<SwarmEntryReceipt, FabricError> {
        Err(blocked_port(
            FabricPortId::SwarmControl,
            FabricOperation::EnterSwarm,
            candidate.candidate_id.as_str().to_owned(),
            Some(candidate.state_fence.clone()),
            None,
        ))
    }

    fn interface_binding(&self) -> PortBindingState {
        PortBindingState::Missing
    }
}

/// Production Governor admission authority port (issue #1108 W4/A2).
///
/// Closed over the retained composition: no accepted swarm
/// reservation/admission interface revision exists on the retained Governor
/// composition on this base, so the port honestly reports
/// [`PortBindingState::Missing`] and every staging/commit attempt raises the
/// typed [`FabricOperation::StageReservation`]/[`FabricOperation::CommitAdmission`]
/// residual instead of minting a reservation or admission. Kernel staging
/// and Governor admission stay with their owners; owner delegation lands
/// with the Governor swarm-admission owner.
struct ProductionAdmissionAuthorityPort;

impl AdmissionAuthorityPort for ProductionAdmissionAuthorityPort {
    fn stage_reservation(&self, definition: &SwarmDefinition) -> Result<Reservation, FabricError> {
        Err(blocked_port(
            FabricPortId::AdmissionAuthority,
            FabricOperation::StageReservation,
            definition.definition_id.as_str().to_owned(),
            Some(definition.fence.clone()),
            None,
        ))
    }

    fn commit_admission(&self, reservation: &Reservation) -> Result<FabricAdmission, FabricError> {
        Err(blocked_port(
            FabricPortId::AdmissionAuthority,
            FabricOperation::CommitAdmission,
            reservation.reservation_id.clone(),
            Some(reservation.fence.clone()),
            None,
        ))
    }

    fn interface_binding(&self) -> PortBindingState {
        PortBindingState::Missing
    }
}

/// Production Kernel activation authority port (issue #1108 W4/A2).
///
/// Closed over the retained composition: the activation projection owner
/// (B-ACTIVATION-PROJECTION #839) has no accepted interface revision on this
/// base, so the port honestly reports [`PortBindingState::Missing`] and
/// every activation attempt raises the typed [`FabricOperation::Activate`]
/// residual instead of fabricating launch authority. Activation stays with
/// the Kernel owner; owner delegation lands with #839.
struct ProductionActivationAuthorityPort;

impl ActivationAuthorityPort for ProductionActivationAuthorityPort {
    fn activate(
        &self,
        admission: &FabricAdmission,
        attempt_id: &eliot_agent_api::AttemptId,
    ) -> Result<ActivationEvidence, FabricError> {
        Err(blocked_port(
            FabricPortId::ActivationAuthority,
            FabricOperation::Activate,
            attempt_id.as_str().to_owned(),
            Some(admission.fence.clone()),
            Some(admission.epoch.clone()),
        ))
    }

    fn interface_binding(&self) -> PortBindingState {
        PortBindingState::Missing
    }
}

/// Production dispatch egress port (issue #1108 W4/A2).
///
/// Closed over the retained composition: concrete execution remains #874 in
/// a separate binary with no compile-time symbol consumable here, so the
/// port honestly reports [`PortBindingState::Missing`] and every emission
/// raises the typed [`FabricOperation::Emit`] residual instead of launching
/// an unretained dispatch. Execution stays with the executor owner; owner
/// delegation lands with the executor-daemon bind.
struct ProductionDispatchEgressPort;

impl DispatchEgressPort for ProductionDispatchEgressPort {
    fn emit(&self, intent: &DispatchIntent) -> Result<DispatchAck, FabricError> {
        Err(blocked_port(
            FabricPortId::DispatchEgress,
            FabricOperation::Emit,
            intent.dispatch_id.clone(),
            Some(intent.fence.clone()),
            Some(intent.epoch.clone()),
        ))
    }

    fn interface_binding(&self) -> PortBindingState {
        PortBindingState::Missing
    }
}

/// Builds the typed missing-prerequisite residual for a production port whose
/// owner has no accepted interface revision (issue #1700).
///
/// A blank or control-bearing `work` identity fails closed as
/// [`FabricError::Contract`] inside the residual builder, so input shape is
/// enforced here even though the fabric pre-validates before the owner call.
fn blocked_port(
    port: FabricPortId,
    operation: FabricOperation,
    work: String,
    fence: Option<StateFence>,
    epoch: Option<EpochId>,
) -> FabricError {
    match MissingPortResidual::new(
        port,
        PortBindingState::Missing,
        operation,
        work,
        fence,
        epoch,
    ) {
        Ok(residual) => FabricError::MissingPrerequisite(Box::new(residual)),
        Err(error) => error,
    }
}

/// Polls the shared solo queue without retaining the composition mutex during
/// authenticated Kernel verification. The queue helper clones one intake
/// under a short synchronous lock, then awaits with only owned inputs.
pub async fn solo_poll_queue_async(
    composition: &Arc<tokio::sync::Mutex<DaemonComposition>>,
    kernel: &Arc<DaemonKernelClient>,
) -> Result<solo_agent_driver::SoloPollOutcome, DaemonError> {
    solo_agent_driver::solo_poll_queue_async(composition, kernel).await
}

impl DaemonComposition {
    /// Composes the daemon only from a Host-approved authenticated Kernel port.
    ///
    /// The port is retained exactly once. Its snapshot and the recovered owner
    /// set are checked before this method returns a composition marked ready.
    ///
    /// The P-07 authority port is retained alongside the Kernel port and
    /// forwarded to the Governor composition: pending grants become effective
    /// only after the exact Kernel activation receipt, and revocation runs
    /// Kernel-first. `None` means diagnosed degradation (reads/degraded
    /// status only) and never issues rights.
    pub fn start(
        mut config: DaemonConfig,
        kernel: Arc<dyn KernelGenerationPort>,
        authority_activation: Option<Arc<dyn eliot_authority::P07AuthorityPort>>,
    ) -> Result<Self, DaemonError> {
        let config_lease = config.config_lease.take().ok_or_else(|| {
            DaemonError::Lifecycle(
                "production start requires the retained Host-approved config lease".to_owned(),
            )
        })?;
        config_lease.verify_stable_identity()?;
        let retained_bytes = config_lease.read_bounded(MAX_CONFIG_BYTES)?;
        let retained_launch: GovernorLaunchConfig = serde_json::from_slice(&retained_bytes)
            .map_err(|error| DaemonError::LaunchConfig(error.to_string()))?;
        if retained_launch != config.launch {
            return Err(DaemonError::Lifecycle(
                "retained config bytes changed before composition".to_owned(),
            ));
        }
        let state_file = config.state_root().join("daemon.lifecycle");
        let state_lease = ProtectedRuntimePathLease::open_or_create_absolute(&state_file)?;
        if state_lease.path() != state_file {
            return Err(DaemonError::Lifecycle(
                "protected lifecycle identity changed during composition".to_owned(),
            ));
        }
        let governor = GovernorComposition::new(
            kernel,
            authority_activation,
            &config.launch().kernel,
            QueueLimits::default(),
        )?;
        let cached_revision_fence = Some(Box::new(governor.kernel_snapshot().state_fence()));
        Ok(Self {
            governor,
            config_lease,
            state_lease,
            config_path: config.config_path,
            state_root: config.state_root,
            started: true,
            view_stale: false,
            cached_revision_fence,
            committed_experience: BTreeMap::new(),
            operator_replay: SharedOperatorReplay::new(),
            owner_session: None,
            notification_snapshot: Vec::new(),
            skill_catalogue: Arc::new(
                std::sync::Mutex::new(eliot_skill::SkillCatalogue::default()),
            ),
            capability_admission: GovernorCapabilityAdmission::new(),
            capability_outcomes: std::sync::Mutex::new(CapabilityRegistryView::default()),
            learning_closure: eliot_governor::LearningClosureService::new(),
            governor_authority: eliot_governor::LiveGovernorAuthority::new(),
            external_attach: None,
            solo_state: std::sync::Mutex::new(solo_agent_driver::SoloDriverState::new()),
            swarm_attachment: eliot_governor::SwarmAttachmentComposition::new(
                eliot_governor::SwarmPlanAttachmentService::new(),
            ),
        })
    }

    /// Commits one Canonical-admitted transition under the exact admitted
    /// request identity, then publishes the resulting owner change.
    ///
    /// The identity comes from admitted ingress and must agree with the
    /// envelope; substitution fails closed inside `commit_canonical` without
    /// a local rehash. No Store client or second ledger is involved: the
    /// only write path is the retained neutral Kernel port.
    ///
    /// The write is material-readiness gated (issue #1789): `readiness`
    /// carries the presented onboarding facts and this method commits through
    /// the Governor readiness-gated path instead of `commit_canonical`
    /// directly, so a typed denial (`TASK_SELECTION_REQUIRED`,
    /// `AMBIGUOUS_RESULT`, `GOVERNING_CONTEXT_REQUIRED`,
    /// `READINESS_REEVALUATION_REQUIRED`) fails the write before any commit.
    /// A denial propagates as [`DaemonError::Composition`] and never reaches
    /// the refresh below.
    ///
    /// Post-commit behavior:
    /// - The refresh runs before a receipt is returned. A failed refresh
    ///   keeps the already durable receipt, marks this composition's
    ///   dependent view stale/pending (see `status`), and still returns the
    ///   receipt: a committed operation is never reported as non-executed.
    /// - The retained volatile operator replay handle is preserved across the
    ///   refresh, never cleared; durable operator identity is unaffected
    ///   because it lives in Kernel ORS, not in this handle.
    /// - Any `Err` from `commit_canonical` — including epoch/generation
    ///   `Recovery` — propagates unchanged so the caller drops this
    ///   composition and re-runs authenticated connect+start. A stale view
    ///   observed after a returned receipt requires the same drop and
    ///   reconnect before the projections can be trusted again.
    pub async fn commit_canonical_and_refresh(
        &mut self,
        identity: &eliot_protocol::RequestIdentity,
        envelope: eliot_governor::CanonicalWriteEnvelope,
        readiness: &eliot_workscope::MaterialReadinessInputs<'_>,
        observed_work_scope: &eliot_governor::ScopeBinding,
        source_closure: Option<(
            &eliot_governor::GoverningSourceSet,
            &eliot_governor::PrivacyProfile,
        )>,
    ) -> Result<eliot_store_api::WriteReceipt, DaemonError> {
        // #740: request/result span over the neutral handoff boundary. The
        // handoff (prepared envelope submitted) and the commitment (validated
        // owner receipt) stay distinguishable in the sink.
        let _span = tracing::info_span!("eliotd.canonical_commit").entered();
        // Issue #1929 (I5.5 capture/promotion split, I5.6 step 4): the daemon
        // ingress is the admission edge, not a bypass around the store gate.
        // The caller's compiled readiness receipt is the only place the exact
        // `TaskSelectionEvidence` exists, so it is resolved and applied here —
        // before any commit. A capture with no unique task selection stays a
        // cold unbound candidate with no task memory/support/influence/finish
        // effect; a task-relative write without current exact evidence is
        // rejected with `TASK_SELECTION_REQUIRED`, and one whose evidence names
        // another task, `WorkScope`, or a moved fence with
        // `TASK_SCOPE_INCOMPATIBLE`. Neither rejection changes a task or
        // reaches the store, and no task is ever silently selected.
        //
        // This method has zero production call sites, so the typed evidence
        // leg is not yet on a live path: the daemon runtime driver never calls
        // it. The blocking symbol is the compiled receipt — the repository's
        // only production constructor of it,
        // `eliot_workscope::ColdStartController::compile`, is reached only
        // through `eliot_workscope::OnboardingSingleFlight::compile_and_publish`
        // and therefore only through
        // `eliot_governor::GovernorComposition::compile_cold_start_at_trigger`,
        // which also has zero call sites. See `task_binding_admission`'s
        // "Measured reachability" section for the full measurement.
        // Issue #1782 (I11.11 line 42): a Material canonical write is refused
        // while a retained external-attach receipt has no attributed
        // continuation, so an unreconciled attach of an already-running
        // external agent cannot be laundered into a write. The refusal keeps
        // the existing `EXTERNAL_ATTACH_RECONCILIATION_REQUIRED` identity and
        // changes nothing else: the retained binding, task state, and project
        // memory are untouched and the write never reaches the store.
        self.admit_material_continuation_after_attach(
            eliot_workscope::RequestedEffect::CanonicalWrite,
        )
        .map_err(|error| DaemonError::Composition(CompositionError::Recovery(error.to_string())))?;
        let admission = crate::task_binding_admission::admit_canonical_write(
            envelope.operation_id.as_str().to_owned(),
            &identity.request.metadata,
            &envelope,
            readiness.receipt,
            readiness.fence,
        )?;
        // Issue #1929: the durable retention of a cold unbound capture is NOT
        // this log line, and not this daemon. `ColdUnbound` here records only
        // the admission decision. The retention owner is the store, which
        // admits the same capture as `GateDisposition::ColdUnbound` in
        // `eliot_store_surreal::task_binding_gate::gate_apply` so the write
        // proceeds instead of being rejected, and whose adapter builds one
        // `EvidenceRecord` per `CaptureObservation` regardless of task binding
        // (`eliot_store_surreal_adapter` `plan::evidence_records`, bound into
        // the `write_receipt` row by `apply::atomic_write`). A later governed
        // binding transition reads those bytes back through the `GetEvidencePack`
        // named read. Until then they are inert for task memory, support,
        // influence, and finish, and this line is only the operator-visible
        // projection of that fact.
        if let crate::task_binding_admission::TaskBindingAdmission::ColdUnbound(candidate) =
            &admission
        {
            tracing::info!(
                candidate_id = %crate::diagnostics::sanitize_identity(&candidate.candidate_id),
                reason_ref = %candidate.reason_ref,
                "cold unbound observation candidate admitted at the daemon edge: durably retained by the store evidence record, no task activation, support/influence promotion, or finish relevance"
            );
        }
        // Issue #1787: the scope-sensitive canonical-write trigger runs before
        // any commit. The caller must supply the actual observed `WorkScope` and
        // source closure; the Governor never reconstructs identity from the
        // retained binding or the write's claimed scope label. A missing
        // binding or MATCHED receipt withholds the write.
        self.governor
            .check_canonical_write_work_scope(
                envelope.scope_id.as_str(),
                observed_work_scope,
                source_closure,
            )
            .map_err(DaemonError::Composition)?;
        let (sources, privacy) = source_closure.ok_or_else(|| {
            DaemonError::Composition(CompositionError::Recovery(
                "canonical write has no governing-source closure".to_owned(),
            ))
        })?;
        let receipt = self
            .governor
            .commit_canonical_with_readiness(
                identity,
                envelope,
                readiness,
                observed_work_scope,
                sources,
                privacy,
            )
            .await
            .map_err(DaemonError::Composition)?;
        if self.governor.refresh_from_kernel().is_err() {
            self.view_stale = true;
        }
        // Revision-fence match gate (issue #18 W6/A5): the cache is
        // revision-keyed, so a fence move must surface as stale instead of
        // silent divergence. A gate rejection marks the dependent view
        // stale/pending but never swallows the already durable receipt.
        if let Err(mismatch) = self.require_revision_fence_match() {
            self.view_stale = true;
            let _ = crate::diagnostics::ErrorRecord::of(
                crate::diagnostics::OwningComponent::DaemonRuntime,
                "revision-fence",
                &mismatch.to_string(),
            )
            .emit();
        } else {
            self.cached_revision_fence =
                Some(Box::new(self.governor.kernel_snapshot().state_fence()));
        }
        Ok(receipt)
    }

    /// Requires the cached revision fence to match the live Kernel fence
    /// exactly (issue #18 W6/A5).
    ///
    /// Rejects [`RevisionFenceMismatch::NeverBuilt`] when no fence was ever
    /// cached, [`RevisionFenceMismatch::StaleView`] when the dependent view
    /// is already stale/pending, and
    /// [`RevisionFenceMismatch::FenceMismatch`] when the cached fence no
    /// longer exactly equals the live snapshot fence. Called from
    /// [`Self::commit_canonical_and_refresh`] after the store commit: the
    /// caller marks the view stale on rejection and still returns the
    /// durable receipt, so this gate guards cache refresh/admission without
    /// creating freshness or authority.
    fn require_revision_fence_match(&self) -> Result<(), RevisionFenceMismatch> {
        if self.view_stale {
            return Err(RevisionFenceMismatch::StaleView);
        }
        let cached = self
            .cached_revision_fence
            .as_ref()
            .ok_or(RevisionFenceMismatch::NeverBuilt)?;
        let live = self.governor.kernel_snapshot().state_fence();
        if !eliot_contracts::fences_match_exact(cached, &live) {
            return Err(RevisionFenceMismatch::FenceMismatch {
                expected: cached.clone(),
                observed: Box::new(live),
            });
        }
        Ok(())
    }

    /// Commits one ledger-sequenced experience-bank record through the
    /// canonical Governor experience-commit caller, then publishes the
    /// resulting owner change.
    ///
    /// Same refresh/stale discipline as
    /// [`Self::commit_canonical_and_refresh`]: the receipt is returned
    /// unmodified and a failed refresh marks the dependent view
    /// stale/pending instead of hiding divergence. The identity must be
    /// admitted ingress agreeing with the record (fence, scope,
    /// idempotency); the owner re-validates everything downstream.
    pub async fn commit_experience_bank_record(
        &mut self,
        identity: &eliot_protocol::RequestIdentity,
        ledger: &eliot_observation::bank_admission::ExperienceRevisionLedger,
        record: &eliot_observation_contracts::ExperienceBankRecord,
        scope_id: eliot_store_api::ScopeId,
        proof_refs: Vec<String>,
        expected_revision_heads: Vec<eliot_store_api::RevisionHeadExpectation>,
        expected_ordering_heads: Vec<eliot_store_api::OrderingHeadExpectation>,
    ) -> Result<eliot_store_api::WriteReceipt, DaemonError> {
        let receipt = eliot_governor::commit_experience_bank(
            &self.governor,
            identity,
            ledger,
            record,
            scope_id,
            proof_refs,
            expected_revision_heads,
            expected_ordering_heads,
        )
        .await
        .map_err(DaemonError::Composition)?;
        if self.governor.refresh_from_kernel().is_err() {
            self.view_stale = true;
        }
        Ok(receipt)
    }

    /// Commits one ledger-sequenced agent-feedback record through the
    /// canonical Governor experience-commit caller. Same refresh/stale
    /// rule as [`Self::commit_experience_bank_record`].
    pub async fn commit_experience_feedback_record(
        &mut self,
        identity: &eliot_protocol::RequestIdentity,
        ledger: &eliot_observation::bank_admission::ExperienceRevisionLedger,
        record: &eliot_observation_contracts::AgentFeedbackRecord,
        scope_id: eliot_store_api::ScopeId,
        proof_refs: Vec<String>,
        expected_revision_heads: Vec<eliot_store_api::RevisionHeadExpectation>,
        expected_ordering_heads: Vec<eliot_store_api::OrderingHeadExpectation>,
    ) -> Result<eliot_store_api::WriteReceipt, DaemonError> {
        let receipt = eliot_governor::commit_experience_feedback(
            &self.governor,
            identity,
            ledger,
            record,
            scope_id,
            proof_refs,
            expected_revision_heads,
            expected_ordering_heads,
        )
        .await
        .map_err(DaemonError::Composition)?;
        if self.governor.refresh_from_kernel().is_err() {
            self.view_stale = true;
        }
        Ok(receipt)
    }

    /// Applies one narrowed dependency change to the held capability-admission
    /// view and commits every record it limited, then publishes the resulting
    /// owner change (issue #1773, I3.4, W2).
    ///
    /// Outbound-only and the same shape as
    /// [`Self::commit_experience_bank_record`]: this method owns no Store
    /// client and opens no second durability path. The only write path is the
    /// retained neutral Kernel port, reached through
    /// [`eliot_governor::commit_capability_evidence_record`], and the resulting
    /// owner change is published with the same refresh/stale discipline — the
    /// receipts are returned unmodified and a failed refresh marks the
    /// dependent view stale/pending instead of hiding divergence.
    ///
    /// `observed` is the scope this daemon can attribute to ITSELF; `changed`
    /// must name only dimensions that observation actually observed, because
    /// the registry stales every record differing from `observed` on a selected
    /// dimension. The blocking reference is the observed scope's own
    /// [`reference_digest`](eliot_governor::RouteScopeFingerprint::reference_digest),
    /// so it is a digest over an admitted observation rather than a probe
    /// result.
    ///
    /// The two borrows are split by field precisely so the composition guard is
    /// never held across a Kernel exchange: `governor` and
    /// `capability_admission` are disjoint fields, and `refresh_from_kernel`
    /// runs only after the exchange has settled.
    ///
    /// # Errors
    ///
    /// Returns [`DaemonError::Composition`] when the composition is not ready,
    /// or the bridge refusal unchanged — which names how many of the restricted
    /// records reached the store, so an in-process-only residual restriction is
    /// observable rather than silently narrower than the applied change.
    pub async fn commit_scope_change_restriction(
        &mut self,
        observed: &eliot_governor::RouteScopeFingerprint,
        changed: eliot_governor::ScopeDependencySelector,
    ) -> Result<crate::ScopeChangeRestrictionReport, DaemonError> {
        // Same readiness gate as `capability_admission_mut`, taken and released
        // before the write so the borrow below is unconditional.
        if self.readiness() != CompositionReadiness::Ready {
            return Err(DaemonError::Composition(CompositionError::NotReady));
        }
        let fence = self.governor.kernel_snapshot().state_fence();
        let scope =
            eliot_store_api::ScopeId::new(eliot_governor::GOVERNOR_SCOPE_ID).map_err(|error| {
                DaemonError::Composition(CompositionError::Owner(error.to_string()))
            })?;
        // Disjoint field borrows: the exchange below needs the Governor
        // composition immutably and the held view mutably at the same time, and
        // neither is a second owner. The block is what releases both borrows
        // before `refresh_from_kernel` takes the composition again, so no guard
        // is ever held across a Kernel exchange.
        let report = {
            let DaemonComposition {
                governor,
                capability_admission,
                ..
            } = self;
            crate::capability_evidence_wiring::commit_scope_change_restriction(
                governor,
                capability_admission,
                observed,
                changed,
                &scope,
                &fence,
            )
            .await
            .map_err(|error| DaemonError::Composition(CompositionError::Owner(error.to_string())))?
        };
        if self.governor.refresh_from_kernel().is_err() {
            self.view_stale = true;
        }
        Ok(report)
    }

    /// Commits one prebuilt named learning-record request through the
    /// Governor learning-record commit caller, then publishes the resulting
    /// owner change.
    ///
    /// Outbound-only: this method owns no Store client and opens no second
    /// durability path. The only write path is the retained neutral Kernel
    /// port, reached through
    /// [`eliot_governor::commit_learning_record`](eliot_governor::commit_learning_record).
    /// Same refresh/stale discipline as
    /// [`Self::commit_experience_bank_record`]: the receipt is returned
    /// unmodified and a failed refresh marks the dependent view
    /// stale/pending instead of hiding divergence. Durability never implies
    /// effectiveness: the returned flag comes only from
    /// [`eliot_governor::learning_effective_under_admission`](eliot_governor::learning_effective_under_admission)
    /// against the live fence, and a durable-but-unadmitted record stays
    /// non-effective.
    #[allow(clippy::too_many_arguments)]
    pub async fn commit_learning_record(
        &mut self,
        identity: &eliot_protocol::RequestIdentity,
        request: eliot_store_api::NamedMutationRequest,
        scope_id: eliot_store_api::ScopeId,
        proof_refs: Vec<String>,
        permit: Option<&eliot_governor::LearningAdmissionPermit>,
        admitted: bool,
        admission_receipt_present: bool,
        expected_revision_heads: Vec<eliot_store_api::RevisionHeadExpectation>,
        expected_ordering_heads: Vec<eliot_store_api::OrderingHeadExpectation>,
    ) -> Result<(eliot_store_api::WriteReceipt, bool), DaemonError> {
        eliot_store_api::reject_direct_learning_write(&request).map_err(|error| {
            DaemonError::Composition(CompositionError::Owner(format!(
                "learning commit guard: {error}"
            )))
        })?;
        let receipt = eliot_governor::commit_learning_record(
            &self.governor,
            identity,
            request,
            scope_id,
            proof_refs,
            expected_revision_heads,
            expected_ordering_heads,
        )
        .await
        .map_err(DaemonError::Composition)?;
        if self.governor.refresh_from_kernel().is_err() {
            self.view_stale = true;
        }
        let live_fence = self.governor.kernel_snapshot().state_fence();
        let effective = eliot_governor::learning_effective_under_admission(
            self.governor.governor(),
            permit,
            &live_fence,
            admitted,
            admission_receipt_present,
        );
        Ok((receipt, effective))
    }
    /// Returns the retained owner receipt for an already-committed
    /// experience record, if this composition committed its idempotency
    /// key (P1-1, issue #1942).
    ///
    /// The commit entry consults this map before deriving ingress: a hit
    /// means the record is durable under its deterministic key, so the
    /// caller must reuse the receipt instead of re-submitting under fresh
    /// expected heads (which would build a different request hash and
    /// wedge in `IdentityConflict`). A miss carries no opinion — including
    /// no claim that the record is absent downstream.
    #[must_use]
    pub fn committed_experience_receipt(
        &self,
        idempotency_key: &str,
    ) -> Option<eliot_store_api::WriteReceipt> {
        self.committed_experience.get(idempotency_key).cloned()
    }

    /// Retains the owner receipt for a newly committed experience record
    /// under its deterministic idempotency key (P1-1, issue #1942).
    ///
    /// Called by the commit entry immediately after the owner returns the
    /// receipt, before any later record in the batch is attempted, so a
    /// mid-batch failure followed by retry skips exactly the durable
    /// prefix. Keys and receipts are owner-derived; nothing here mints
    /// identity, heads, or proofs.
    pub fn note_experience_committed(
        &mut self,
        idempotency_key: String,
        receipt: eliot_store_api::WriteReceipt,
    ) {
        self.committed_experience.insert(idempotency_key, receipt);
    }

    // (DELETED, #18 N3) `DaemonComposition::finish_attempt`.
    //
    // Its own contract, for the record: it submitted one candidate finish
    // through the Governor owner, committed the derived decision through the
    // canonical `RecordFinishDecision` path, and rehydrated the daemon
    // projection before returning the decision receipt. The caller supplied
    // only a candidate draft; task completion, evidence binding and persistence
    // remained Governor/Canonical-owned. A committed receipt was preserved when
    // the post-commit refresh could not publish the new projection: the daemon
    // was marked stale, matching `commit_canonical_and_refresh`, and the
    // receipt still reported the durable operation rather than a false failure.
    //
    // This composed one-shot submitted the evidence leg and the finish decision
    // inside a single `&mut self` borrow, exchanging twice against the Kernel
    // while the borrow was live. On the daemon side `&mut DaemonComposition` is
    // obtainable only through `SharedComposition::lock()`, so every caller would
    // have held a `tokio::sync::MutexGuard` across two Kernel round trips -
    // the exact defect N3 exists to remove. It could not be repaired in place:
    // a `&mut self` method cannot release the borrow around the exchange, and
    // the method has no Kernel client of its own to exchange through.
    //
    // It is removed rather than kept because it had no production caller after
    // the TestD owner drain went phase-split, and on this side of that boundary
    // a `&mut` finish helper is structurally a re-introduction of the defect.
    //
    // The replacement seam is the phase pair, which the drain already uses and
    // which needs no composition borrow at all while it exchanges:
    // `eliot_governor::GovernorComposition::prepare_finish_evidence`,
    // `::prepare_finish_decision` and `::accept_prepared_exchange`, exchanged
    // through `testd_terminal_completion::exchange_testd_owner_finish_leg`
    // with the composition lock released.
    //
    // The closure-assessment observability record that followed the decision is
    // preserved on the phase path in
    // `testd_terminal_completion::plan_testd_terminal_owner_finish`. The
    // post-decision owner refresh the deleted body also performed
    // (`refresh_from_kernel`, marking `view_stale` on failure) is now performed
    // by phase (3) of the drain through the Governor's own synchronous
    // `prepare_finish_decision`, which refreshes before the decision is
    // derived, so the dependent view is still invalidated on a failed refresh.
    //
    // Doc preserved from main (#1929), so the rationale is not lost: this Finish
    // owner entry had no caller-presented readiness receipt, so the exact
    // `TaskSelectionEvidence` leg of issue #1929 runs at the composition-root
    // write intake (`Self::commit_canonical_and_refresh`) and again, from the
    // proof handles the transition actually carries, at the store gate. The
    // finish draft's own `task_id` + `expected_task_revision` are re-validated
    // against the canonical task owner by the Governor finish owner before the
    // commit; nothing on the phase path guesses a task. Both legs still run on
    // the surviving path: `plan_testd_terminal_owner_fact` prepares the fact
    // through the Governor finish owner, and `accept_prepared_exchange`
    // re-checks the pre-commit fence before the receipt is admitted.

    /// Prepares the Governor-owned finish-evidence exchange without transporting it.
    ///
    /// Runtime callers hold the composition lock only for this synchronous phase,
    /// then exchange the immutable plan through Kernel after releasing the lock.
    pub fn prepare_finish_evidence(
        &self,
        identity: &RequestIdentity,
        operation_id: &OperationId,
        draft: &FinishAttemptDraft,
    ) -> Result<Option<PreparedKernelExchange>, FinishAttemptError> {
        if self.readiness() != CompositionReadiness::Ready {
            return Err(FinishAttemptError::Composition(CompositionError::NotReady));
        }
        self.governor
            .prepare_finish_evidence(identity, operation_id, draft)
    }

    /// Revalidates one exchanged finish leg against the live Governor owner.
    pub fn accept_prepared_finish_exchange(
        &self,
        prepared: &PreparedKernelExchange,
    ) -> Result<(), FinishAttemptError> {
        self.governor.accept_prepared_exchange(prepared)
    }

    /// Refreshes canonical state and prepares the Governor-owned finish decision.
    ///
    /// The returned exchange is immutable and must be transported with the
    /// composition lock released; the decision is projected only after it is
    /// revalidated by [`Self::accept_prepared_finish_exchange`].
    pub fn prepare_finish_decision(
        &mut self,
        identity: &RequestIdentity,
        operation_id: &OperationId,
        draft: FinishAttemptDraft,
    ) -> Result<PreparedFinishDecision, FinishAttemptError> {
        if self.readiness() != CompositionReadiness::Ready {
            return Err(FinishAttemptError::Composition(CompositionError::NotReady));
        }
        self.governor
            .prepare_finish_decision(identity, operation_id, draft)
    }

    /// Returns the admitted Kernel snapshot.
    #[must_use]
    pub fn kernel_snapshot(&self) -> &eliot_governor::KernelGenerationSnapshot {
        self.governor.kernel_snapshot()
    }

    /// Returns the live Governor owner handle.
    ///
    /// This is the owner that mints and re-verifies learning admission permits,
    /// cross-task admissions, and learning-record admission receipts, and it is
    /// the reason an improvement candidate's bounded admission can be checked
    /// against a real issuance instead of a constant. It is a borrow of the
    /// composition's own Governor, not a second Governor and not a re-export of
    /// a projection: [`Self::commit_learning_record`] already reaches the same
    /// owner for the durable leg, so this exposes no new authority path.
    #[must_use]
    pub fn improvement_governor(&self) -> &eliot_governor::Governor {
        self.governor.governor()
    }

    /// The maintenance (`G-19`) improvement admission policy record for one
    /// exact operation, read from the live maintenance owner.
    ///
    /// This is the EXISTING maintenance admission path: the record comes from
    /// `GovernorOwners::maintenance` — the `G-19` owner that
    /// `crates/meta/eliot-improvement/module.toml:35` names as the sole
    /// admission owner for improvement candidates — and it carries the
    /// per-surface active-candidate bounds I12.24:297 requires. The daemon
    /// therefore reads its bound from the decision owner instead of choosing a
    /// number, and no scheduler, root record, or second policy source is
    /// introduced (I12.24:314).
    ///
    /// `operation_ref` and `idempotency_key` bind the exact observation the
    /// record is issued for, so two observations never share a policy record.
    /// Pure with respect to the Kernel: no exchange happens here.
    ///
    /// # Errors
    ///
    /// [`DaemonError::Composition`] with
    /// [`CompositionError::NotReady`] when the Governor is not ready; no
    /// other failure is possible, because the owner record is a pure value.
    pub fn maintenance_improvement_admission_policy(
        &self,
        operation_ref: &str,
        idempotency_key: &str,
    ) -> Result<eliot_maintenance::ImprovementAdmissionPolicy, DaemonError> {
        if self.readiness() != CompositionReadiness::Ready {
            return Err(DaemonError::Composition(CompositionError::NotReady));
        }
        Ok(self
            .governor
            .owners()
            .maintenance
            .improvement_admission_policy(operation_ref, idempotency_key, SERVICE_NAME))
    }

    /// Commits the durable learning-closure edge for one consequential attempt.
    ///
    /// This is the production caller of
    /// [`eliot_governor::GovernorComposition::close_attempt_learning`] on the
    /// live `TestD` terminal finish ceremony
    /// (`testd_terminal_completion::commit_testd_terminal_owner_fact`, phase 6).
    ///
    /// `activity_name` is the activity/tool identity the durable terminal job
    /// row recorded for the observed step, and it is the value the ordinary-read
    /// exclusion is applied to: a recorded `read_file`/`read`/`grep` derives no
    /// boundary and commits no record.
    ///
    /// `receipt` is the admission receipt presented for the stored record. No
    /// admission-receipt owner issues one at this seam, so the live caller
    /// presents `None` and the durable receipt records the gate refusal: an
    /// unadmitted proposed behavioral change is not delivered to the subsequent
    /// attempt.
    ///
    /// `promotion` is the owner-published candidate-only promotion boundary for
    /// this attempt together with the attribution and experiment lineage whose
    /// digests it consumed. The promotion verdict is produced on every committed
    /// record here. A caller that holds no boundary presents
    /// [`eliot_governor::PromotionBoundaryInput::absent`], and the committed
    /// receipt records the withheld verdict with its exact reason.
    ///
    /// `admissions` are the admission receipts this process holds for the
    /// campaign's already-committed learning records. The prior attempt of the
    /// campaign is the one proposed behavioural change that could reach this
    /// attempt, and the Governor admits it only through one of these receipts;
    /// an unadmitted one is not delivered, and the committed receipt records
    /// the typed refusal.
    ///
    /// The edge is non-blocking by construction: it reads retained owner
    /// images, performs no transport, and its result is returned to the caller
    /// instead of being propagated into the finish decision (I12.24 line 293).
    pub fn close_attempt_learning(
        &self,
        evidence: &eliot_testd_core::TestdTerminalCompletionEvidence,
        decision: &eliot_governor::FinishDecisionReceipt,
        activity_name: &str,
        receipt: Option<&eliot_governor::AdmissionReceipt>,
        admissions: &[eliot_governor::AdmissionReceipt],
        promotion: eliot_governor::PromotionBoundaryInput<'_>,
    ) -> Result<eliot_governor::LearningClosureOutcome, eliot_governor::LearningClosureError> {
        self.governor.close_attempt_learning(
            &self.learning_closure,
            evidence,
            decision,
            activity_name,
            None,
            receipt,
            admissions,
            promotion,
        )
    }

    /// Borrows the single Governor-owned durable learning-closure owner.
    #[must_use]
    pub const fn learning_closure(&self) -> &eliot_governor::LearningClosureService {
        &self.learning_closure
    }

    /// Borrows the single Governor-owned durable swarm attachment composition.
    #[must_use]
    pub const fn swarm_attachment_composition(
        &self,
    ) -> &eliot_governor::SwarmAttachmentComposition {
        &self.swarm_attachment
    }

    /// Binds the daemon swarm composition over the single Governor attachment
    /// owner (issue #1126 W1/A1 slice A: daemon composition).
    ///
    /// Production caller of [`swarm_composition::SwarmComposition::new`]: the
    /// attachment half is the daemon-owned durable-job owner above, so one
    /// Governor owner admits every swarm plan this daemon launches. The
    /// launch-intent ledger and child runner stay explicit caller ports
    /// because their production owners do not exist on this base: no non-test
    /// `LaunchIntentLedger`/`ChildRunner` or `DurableWorkStore` implementation
    /// exists (remainder #1699), and no daemon-reachable admitted
    /// `AdapterRegistry` or one-shot `DispatchPermit` runner binding exists
    /// without a new architecture-boundary edge (remainder #2866 items 2-4,
    /// #22). The returned composition enforces the owner order — persist
    /// intent before execution, reconcile before relaunch, unknown blocks
    /// terminal — for whatever owners the caller supplies.
    #[must_use]
    pub fn swarm_composition<'a, L, R>(
        &'a self,
        ledger: &'a L,
        runner: &'a R,
    ) -> swarm_composition::SwarmComposition<'a, L, R>
    where
        L: swarm_composition::LaunchIntentLedger,
        R: swarm_composition::ChildRunner,
    {
        swarm_composition::SwarmComposition::new(&self.swarm_attachment, ledger, runner)
    }

    /// Returns the retained protected config path, for diagnostics only.
    #[must_use]
    pub fn config_path(&self) -> &Path {
        &self.config_path
    }

    /// Returns the recovered Config projection digest admitted at Governor
    /// construction (I1.11 step 8 input). Read-only over the retained owner:
    /// the digest was bound to the protected launch digest by recovery and
    /// never recomputed here.
    #[must_use]
    pub fn config_snapshot_digest(&self) -> &str {
        self.governor.owners().config.snapshot_digest()
    }

    /// Returns the recovered Policy projection owner admitted at Governor
    /// construction (I1.11 step 8 input), or `None` while the Kernel does
    /// not serve the Policy named read. Read-only over the retained owner:
    /// policy content is consumed from the actual canonical snapshot, never
    /// defaulted and never a relabeled Config digest.
    #[must_use]
    pub fn policy_owner(&self) -> Option<&eliot_governor::PolicyOwner> {
        self.governor.owners().policy.as_ref()
    }

    /// Returns the retained protected daemon state root.
    #[must_use]
    pub fn state_root(&self) -> &Path {
        &self.state_root
    }

    /// Computes the digest of the provider-owned recovery snapshot admitted at
    /// startup. This is evidence only; Kernel remains the authority.
    pub fn recovery_digest(&self) -> Result<String, DaemonError> {
        let bytes = serde_json::to_vec(self.governor.recovery()).map_err(|error| {
            DaemonError::Composition(CompositionError::Recovery(error.to_string()))
        })?;
        Ok(eliot_contracts::sha256_hex(&bytes))
    }

    /// Returns the exact readiness state.
    #[must_use]
    pub const fn readiness(&self) -> CompositionReadiness {
        self.governor.readiness()
    }

    /// Returns a bounded status projection.
    ///
    /// #2703: this projection deliberately does NOT reference
    /// `governed_improvement_pipeline_owner`. A previous revision bound it to
    /// `let _improvement_owner = ...` and dropped it, which constructed a value
    /// and discarded it — the construct-and-drop shape that is not a
    /// production caller. The owner identity is reported for real, from
    /// `daemon_runtime`'s startup diagnostic, so nothing is lost by removing
    /// the dead reference here.
    #[must_use]
    pub fn status(&self) -> DaemonStatus {
        let snapshot = self.kernel_snapshot();
        DaemonStatus {
            service: SERVICE_NAME.to_owned(),
            protocol: PROTOCOL_VERSION.to_owned(),
            generation: snapshot.generation.value(),
            authority_epoch: snapshot.authority_epoch.sequence.get(),
            ready: self.started
                && !self.view_stale
                && self.readiness() == CompositionReadiness::Ready,
            health: if !self.started {
                "stopped".to_owned()
            } else if self.view_stale {
                "stale".to_owned()
            } else if self.readiness() == CompositionReadiness::Ready {
                "healthy".to_owned()
            } else {
                "degraded".to_owned()
            },
            degraded: !self.started
                || self.view_stale
                || self.readiness() != CompositionReadiness::Ready,
        }
    }

    /// Returns the current named activation dependency discriminator used by
    /// the pre-claim successor gate. The Governor remains the sole semantic
    /// owner; this is a bounded readback for the authenticated claim request.
    #[must_use]
    pub fn activation_dependency_revision(&self) -> String {
        self.governor.activation_dependency_revision()
    }

    /// Reads the current semantic owner projection for the exact owner
    /// readback carried with a Resolved result submission. This is a bounded
    /// readback of the same Governor owner, not a second Kernel resolver and
    /// not a replacement result computation.
    pub fn current_activation_owner_readback(
        &self,
        now: u64,
    ) -> Result<AgentActivationOwnerReadback, DaemonError> {
        let snapshot = self
            .governor
            .read_unique_agent_activation(now)
            .map_err(|error| DaemonError::Lifecycle(error.to_string()))?;
        let binding = AgentActivationResolvedBinding {
            principal_id: snapshot.principal_id,
            session_id: snapshot.session_id,
            task_id: snapshot.task_id.to_string(),
            work_unit_id: snapshot.work_unit_id,
            work_scope_id: snapshot.work_scope_id,
            task_revision: snapshot.task_revision.to_string(),
            plan_id: snapshot.plan_id,
            plan_revision: snapshot.plan_revision,
        };
        let evidence = AgentActivationOwnerEvidence::for_binding(
            &binding,
            snapshot.owner_revision,
            snapshot.state_fence,
        )
        .map_err(|error| DaemonError::Lifecycle(error.to_string()))?;
        AgentActivationOwnerReadback::from_evidence(evidence, now.max(1))
            .map_err(|error| DaemonError::Lifecycle(error.to_string()))
    }

    /// Single production resolver spine: resolves one Kernel-issued semantic
    /// ticket to the canonical v2 typed result. Every
    /// `GovernorActivationOutcome` variant maps 1:1 to its
    /// protocol disposition without coercion to success.
    ///
    /// Split note: activation resolution keeps readiness, fence, successor
    /// observation, and typed mapping together. The seam is still one ordered
    /// spine; each step is now a named private function, so every guard still
    /// runs in the same order over the same effects.
    pub fn resolve_agent_activation_v2(
        &self,
        ticket: &AgentActivationResolutionTicket,
        now: u64,
    ) -> Result<AgentActivationResolutionResult, DaemonError> {
        // #740: semantic-admission span. Records the ticket identity plus the
        // actual admitted/rejected disposition and digest once resolved.
        let _span = tracing::info_span!(
            "eliotd.activation_resolution",
            ticket = %crate::diagnostics::sanitize_identity(&ticket.ticket_id)
        )
        .entered();
        ticket
            .validate()
            .map_err(|error| DaemonError::Lifecycle(error.to_string()))?;
        let successor_observation = ticket.successor_of.as_ref().map(|_| {
            (
                self.governor.activation_owner_revision(),
                self.governor.activation_dependency_revision(),
            )
        });
        if self.readiness() != CompositionReadiness::Ready {
            // #204: an unready Governor is an internal failure for this exact
            // ticket, not a loop-fatal error; the typed terminal result and its
            // fail-closed fallback live in
            // [`unready_governor_activation_result`].
            return unready_governor_activation_result(ticket, now, successor_observation);
        }
        if activation_deadline_expired(now, ticket.kernel_deadline_unix_ms) {
            return Err(DaemonError::Lifecycle(
                "semantic activation ticket deadline has expired".to_owned(),
            ));
        }
        let outcome = self.map_activation_outcome(ticket, now, successor_observation.as_ref());
        emit_activation_admission_diagnostics(ticket, &outcome);
        outcome
    }

    /// Resolves this Governor's typed activation outcome for one already
    /// validated ticket and maps it to the canonical v2 result.
    ///
    /// The exact `successor_observation` captured before the readiness gate
    /// decides whether a mapping is a successor-fenced mapping, and the
    /// stale-fence and mapping-failure terminals keep the same class of
    /// evidence they carried inline.
    fn map_activation_outcome(
        &self,
        ticket: &AgentActivationResolutionTicket,
        now: u64,
        successor_observation: Option<&(u64, String)>,
    ) -> Result<AgentActivationResolutionResult, DaemonError> {
        match self.governor.resolve_activation_outcome(now) {
            GovernorActivationOutcome::Resolved(snapshot) => {
                if snapshot.state_fence == ticket.state_fence {
                    match map_governor_outcome_under_observation(
                        ticket,
                        GovernorActivationOutcome::Resolved(snapshot),
                        now.max(1),
                        successor_observation,
                    ) {
                        Ok(result) => Ok(result),
                        Err(error) => failed_internal_or_mapping_error(
                            ticket,
                            "RESOLVED",
                            now.max(1),
                            successor_observation.cloned(),
                            error,
                        ),
                    }
                } else {
                    // #66: a Resolved binding under a stale fence must not
                    // create a Session and must not kill the daemon loop.
                    // Submit a typed StaleFence terminal result carrying the
                    // observed fence instead of a hard error.
                    // #839: value flows through the shared outcome tail below
                    // so this terminal result emits the same admission/error
                    // diagnostics as every other v2 resolution instead of
                    // returning silently; the Ok/Err value is unchanged.
                    let observed = snapshot.state_fence.clone();
                    activation_projection::stale_fence_for_resolved_mismatch_with_observation(
                        ticket,
                        observed,
                        now.max(1),
                        successor_observation.cloned(),
                    )
                }
            }
            outcome => {
                let kind = outcome.kind_str();
                match map_governor_outcome_under_observation(
                    ticket,
                    outcome,
                    now.max(1),
                    successor_observation,
                ) {
                    Ok(result) => Ok(result),
                    Err(error) => failed_internal_or_mapping_error(
                        ticket,
                        kind,
                        now.max(1),
                        successor_observation.cloned(),
                        error,
                    ),
                }
            }
        }
    }

    /// Records the already-validated Kernel-issued owner session facts for
    /// the single live owner session (AUD-C02-B, Implements #1187).
    ///
    /// Called once by the daemon runtime at the single place holding both the
    /// concrete [`DaemonKernelClient`] and this composition. Stores facts
    /// only, never the client; no new thread, no new handshake.
    pub fn note_owner_session_binding(&mut self, facts: OwnerSessionFacts) {
        self.owner_session = Some(facts);
    }

    /// Notes verified canonical notification records into this composition.
    ///
    /// Called once by the daemon runtime attach holding both the concrete
    /// [`DaemonKernelClient`] and this composition, mirroring
    /// [`Self::note_owner_session_binding`]. Stores records only, never the
    /// client; no new thread, no new handshake. Until noted, boards built by
    /// [`Self::controlboard`] keep the empty inbox behaviour.
    pub fn note_notification_snapshot(&mut self, records: Vec<Notification>) {
        self.notification_snapshot = records;
    }

    /// Joins the owner-side canonical notification-state admission to this
    /// composition's live retained fact: material readiness plus the exact
    /// admitted State Fence the transition must be built and submitted under
    /// (issue #1780, I1.8).
    ///
    /// The fence is read from the retained Governor snapshot, never from a
    /// caller claim, so a transported or cached fence cannot substitute it.
    ///
    /// This is deliberately **not** a write intake and carries no commit. It
    /// performs no canonical write, never calls
    /// [`Self::commit_canonical_and_refresh`], and never calls
    /// `GovernorComposition::check_canonical_write_work_scope`: that gate
    /// withholds any write whose `scope_id` is not the bound `WorkScope`, and
    /// the fixed canonical notification scope
    /// (`eliot_store_api::NOTIFICATION_STATE_SCOPE`) is by contract never that
    /// `WorkScope` — a notification write routed through the gate would be
    /// silently withheld rather than refused. Submission therefore goes to the
    /// admitted Kernel `ApplyNotificationState` route over the retained daemon
    /// transport through [`crate::notification_state_emit`], which rechecks the
    /// fixed scope, ordering scope, transition class, and closed leg parameters
    /// itself and additionally requires a same-fence record read-back.
    pub fn notification_state_admission_fence(&self) -> Result<StateFence, DaemonError> {
        if self.readiness() != CompositionReadiness::Ready {
            return Err(DaemonError::Composition(CompositionError::NotReady));
        }
        Ok(self.governor.kernel_snapshot().state_fence().clone())
    }

    /// Builds one provider-neutral `ControlBoard` over the current Governor
    /// projection snapshot.
    ///
    /// This is the one production composition owner of the `ControlBoard` ports
    /// (Implements #1187 W1/A1). Its production caller is
    /// [`serve_controlboard_view`](crate::serve_controlboard_view), which the
    /// daemon runtime's local-read poller serves for one Kernel-admitted
    /// claimed pair; no other site builds a board.
    ///
    /// The board reads one immutable snapshot taken here; every port call in
    /// the returned value observes the same revision and fence, so one served
    /// read cannot mix two of either. Callers take a fresh board per operation,
    /// which means a Governor refresh is not observed by the board in flight:
    /// it appears at the next read as a newer, still internally consistent view,
    /// not as a mismatch. The board shares the retained volatile replay handle,
    /// so a newly created board replays an already-admitted operation instead
    /// of admitting it twice; cross-restart durability is not owned here — it
    /// needs the command-receipt projection read for the exact `OperationId`
    /// that the `operator_replay` field contract names and that no reachable
    /// port provides. Access resolution admits exactly the one live
    /// Kernel-issued owner session when the runtime threaded validated facts
    /// (AUD-C02-B), else the typed provider gap; the Swarm projection remains
    /// a typed provider gap until its owning slice lands. Reads serve a
    /// coherent empty-items view over real G-11/I-12 bindings and submission
    /// admits candidate-only intents.
    pub fn controlboard(&self) -> Result<eliot_controlboard::ControlBoard, DaemonError> {
        let snapshot = self.governor.controlboard_snapshot()?;
        // One admitted owner binding from the threaded Kernel-issued facts
        // when present, else the empty production behaviour (unadmitted typed
        // gap). Malformed held facts stay fail-closed to empty: no live
        // session is ever minted from a literal.
        let admitted = match &self.owner_session {
            Some(facts) => {
                match controlboard_adapters::AdmittedSessionAccess::from_kernel_owner_facts(facts) {
                    Ok(binding) => vec![binding],
                    Err(_) => Vec::new(),
                }
            }
            None => Vec::new(),
        };
        Ok(controlboard_adapters::controlboard_over_snapshot(
            snapshot,
            &self.operator_replay,
            admitted,
            // #1780: pre-fetched canonical records noted by the runtime
            // attach; empty until that attach lands, never fabricated.
            self.notification_snapshot.clone(),
        ))
    }

    /// Borrows the single Governor Skill lifecycle owner as a forwarding
    /// [`SkillLifecycleApi`](eliot_skill::SkillLifecycleApi).
    ///
    /// The adapter forwards the exact admitted identity, operation identity,
    /// candidate, gate and promoted view to the Governor canonical promotion
    /// path and returns only typed results. No policy, admission, or semantic
    /// rules live here; a stale fence or changed base fails closed in the
    /// Governor owner. Callers take a fresh adapter per operation so a
    /// Governor refresh surfaces as an exact-view mismatch instead of silent
    /// divergence.
    pub fn skill_lifecycle(&self) -> Result<impl eliot_skill::SkillLifecycleApi + '_, DaemonError> {
        if self.readiness() != eliot_governor::CompositionReadiness::Ready {
            return Err(DaemonError::Composition(
                eliot_governor::CompositionError::NotReady,
            ));
        }
        Ok(self.shared_skill_adapter())
    }

    /// Borrows the one Governor Skill lifecycle owner for a read-only
    /// owner-position probe (issue #2664).
    ///
    /// Narrow composition seam for the execute leg: the reconciliation must
    /// read what the lifecycle owner actually retains, and it must do so
    /// without taking a second authority or creating a Skill-private store.
    /// The borrow is in-process owner state only, is valid for the duration of
    /// the caller's expression, and can never be held across an await.
    pub fn skill_lifecycle_owner(&self) -> &eliot_skill::SkillRegistry {
        &self.governor.owners().skill
    }

    /// Builds the shared-catalogue skill adapter driven by the runtime
    /// population callers below.
    ///
    /// Single construction site for every composition-held adapter: the
    /// shared handle (not a fresh catalogue per call) is what makes
    /// installation visible to later promotion/delivery/display through any
    /// accessor. `skill_lifecycle()` above shares it.
    fn shared_skill_adapter(
        &self,
    ) -> skill_lifecycle_adapters::ForwardingSkillLifecycle<
        eliot_governor::GovernorSkillLifecycle<'_, dyn eliot_governor::KernelGenerationPort>,
    > {
        skill_lifecycle_adapters::ForwardingSkillLifecycle::with_catalogue(
            self.governor.skill_lifecycle(),
            Arc::clone(&self.skill_catalogue),
        )
    }

    /// Enforces the recovered Governor lifecycle standing before any
    /// catalogue write (issue #1191).
    ///
    /// Reads the Governor-recovered Skill registry — rebuilt from the
    /// canonical `Skill` named read at every recovery, advanced only through
    /// canonical promotion commits — and refuses installs the lifecycle
    /// owner revoked, superseded, drifted, or never fenced current. Covered
    /// Skills must stand fence-current with exact registration revision and
    /// material digest; uncovered Skills install provisional and the
    /// lifecycle follows through propose/promote. The fence is always the
    /// caller-observed live admitted fence, never a transported claim.
    ///
    /// The crate error travels by value here like every neighboring
    /// composition seam feeding the Governor lifecycle API, so the size
    /// lint is allowed for this seam.
    #[allow(clippy::result_large_err)]
    fn check_skill_lifecycle_standing(
        &self,
        package: &eliot_skill::SkillPackage,
        admitted_fence: &StateFence,
    ) -> Result<(), eliot_skill::SkillError> {
        eliot_skill::check_lifecycle_standing(
            &self.governor.owners().skill,
            &package.registration.skill_id,
            package,
            admitted_fence,
        )
    }

    /// Installs one canonical package source into the shared Governor Skill
    /// catalogue (population caller, issue #1882).
    ///
    /// Composition seam for the runtime population driver: the Governor
    /// owner hands over the accepted candidate, a validated package claim,
    /// its actual materialization inputs, the explicit install context, and
    /// the tool-owner view; the recovered lifecycle standing gates entry
    /// first, then the shared handle records the projected entry after the
    /// candidate binding. No readiness gate: the insert operates purely on
    /// daemon-held catalogue state (validated insert); promotion keeps the
    /// Governor canonical gates, and drivers call post-admission. Returns
    /// the installed Skill identity.
    pub fn skill_install_package(
        &self,
        candidate: &eliot_skill::PortableSkillPackageCandidate,
        package: &eliot_skill::SkillPackage,
        inputs: &eliot_skill::MaterializationInputs,
        context: &eliot_skill::CatalogueInstallContext,
        tools: &dyn eliot_skill::KnownTools,
    ) -> Result<String, eliot_skill::SkillError> {
        let admitted = self.governor.kernel_snapshot().state_fence().clone();
        self.check_skill_lifecycle_standing(package, &admitted)?;
        self.shared_skill_adapter()
            .install_package(candidate, package, inputs, context, tools)
    }

    /// Issues the Hotset delivery receipt the runtime injector carries
    /// (issue #1882).
    ///
    /// Same seam discipline as [`Self::skill_install_package`]: driven by the
    /// runtime Hotset injector caller with its own approval handle; operates
    /// on the shared catalogue only.
    pub fn skill_deliver_hotset(
        &self,
        hotset_id: String,
        skill_ids: Vec<String>,
        approval_ref: String,
        tools: &dyn eliot_skill::KnownTools,
    ) -> Result<eliot_skill::HotsetDeliveryReceipt, eliot_skill::SkillError> {
        self.shared_skill_adapter()
            .deliver_hotset(hotset_id, skill_ids, approval_ref, tools)
    }

    /// Binds the runtime receiver's ack to its exact receipt, then displays
    /// (issue #1882).
    ///
    /// Same seam discipline as [`Self::skill_install_package`]: only an
    /// applied ack for the exact receipt reaches the catalogue boundary.
    /// Receipt and ack travel by value, mirroring the owned display boundary.
    #[allow(
        clippy::needless_pass_by_value,
        reason = "receipt/ack cross by value like the owned display boundary"
    )]
    pub fn skill_acknowledge_and_display(
        &self,
        skill_id: &str,
        receipt: eliot_skill::HotsetDeliveryReceipt,
        ack: eliot_skill::HotsetDeliveryAck,
        tools: &dyn eliot_skill::KnownTools,
    ) -> Result<eliot_skill::ActivatedSkillDisplay, eliot_skill::SkillError> {
        self.shared_skill_adapter()
            .acknowledge_and_display(skill_id, receipt, ack, tools)
    }

    /// Binds the runtime receiver's ack to its exact receipt under the live
    /// canonical tool view, then displays (issue #1882).
    ///
    /// Same seam discipline as [`Self::skill_install_package`]: the driver
    /// supplies the receipt/ack pair the receiver acted on plus the LIVE
    /// tool-owner source, alias table, and admitted version, and the shared
    /// handle refuses the display when the live source drifted past the
    /// admitted definition version. Receipt and ack travel by value,
    /// mirroring the owned display boundary.
    #[allow(
        clippy::needless_pass_by_value,
        reason = "receipt/ack cross by value like the owned display boundary"
    )]
    pub fn skill_acknowledge_and_display_versioned(
        &self,
        skill_id: &str,
        receipt: eliot_skill::HotsetDeliveryReceipt,
        ack: eliot_skill::HotsetDeliveryAck,
        display_source: &dyn eliot_skill::CanonicalToolSource,
        aliases: &eliot_skill::ToolAliasTable,
        admitted_definition_version: &str,
    ) -> Result<eliot_skill::ActivatedSkillDisplay, eliot_skill::SkillError> {
        self.shared_skill_adapter()
            .acknowledge_and_display_versioned(
                skill_id,
                receipt,
                ack,
                display_source,
                aliases,
                admitted_definition_version,
            )
    }

    /// Installs one canonical package source under the versioned canonical
    /// tool view (issue #1882).
    ///
    /// Same seam discipline as [`Self::skill_install_package`], plus the
    /// admitted-definition-version gate: the source reports the version it
    /// binds (MCP canonical registry via its `CanonicalToolSource` impl),
    /// the driver states the Governor-admitted version, and drift fails
    /// closed before the shared handle is touched. The accepted candidate
    /// binds at the Skill boundary. The Skill never hardcodes
    /// the version; the composition never invents a registry. Drivers call
    /// post-admission with the injector's real inputs. The versioned tool
    /// view travels as one [`VersionedToolView`] so the seam keeps every
    /// owner term explicit within the arity lint.
    pub fn skill_install_package_versioned(
        &self,
        candidate: &eliot_skill::PortableSkillPackageCandidate,
        package: &eliot_skill::SkillPackage,
        inputs: &eliot_skill::MaterializationInputs,
        context: &eliot_skill::CatalogueInstallContext,
        view: VersionedToolView<'_>,
    ) -> Result<String, eliot_skill::SkillError> {
        let admitted = self.governor.kernel_snapshot().state_fence().clone();
        self.check_skill_lifecycle_standing(package, &admitted)?;
        self.shared_skill_adapter().install_package_versioned(
            candidate,
            package,
            inputs,
            context,
            view.source,
            view.aliases,
            view.admitted_definition_version,
        )
    }

    /// Runs versioned install, availability and sealed gates, and Hotset
    /// receipt issuance as one runtime delivery act (issue #1882).
    ///
    /// Same seam discipline as [`Self::skill_install_package`]: the driver
    /// supplies the accepted candidate plus the real package, inputs,
    /// context, provider readiness and materialization scope, versioned tool
    /// source plus alias table and admitted version, Hotset identity, and
    /// injector approval in one
    /// [`VersionedDeliveryAct`](skill_lifecycle_adapters::VersionedDeliveryAct);
    /// the shared handle records the act. The candidate rehydrates against
    /// owner issuance and the live scope/fence before install. The
    /// composition observes the live admitted Governor fence itself and the
    /// act's scope fence must equal it: a Governor refresh crossing the
    /// drive fails closed before any catalogue write or receipt mint. The
    /// receipt carries the provisional ceiling until evidence promotion; the
    /// receiver ack re-enters through [`Self::skill_acknowledge_and_display`].
    pub fn skill_run_install_to_receipt(
        &self,
        act: skill_lifecycle_adapters::VersionedDeliveryAct<'_>,
        record: &skill_acceptance_read::AcceptanceRecord,
    ) -> Result<(String, eliot_skill::HotsetDeliveryReceipt), eliot_skill::SkillError> {
        let admitted = self.governor.kernel_snapshot().state_fence().clone();
        self.check_skill_lifecycle_standing(act.package, &admitted)?;
        self.shared_skill_adapter()
            .run_install_to_receipt(act, &admitted, record)
    }

    /// Runs the Hotset injector call end to end through the composed
    /// delivery act (issue #1882).
    ///
    /// Production injector entry the Hotset transport lane calls with one
    /// injector-carried [`SkillHotsetRequest`](skill_lifecycle_adapters::SkillHotsetRequest):
    /// accepted candidate, package, inputs, Governor-owned install context,
    /// provider readiness, scope identities, Hotset identity, and injector
    /// approval — no literals, no defaults. The composition observes the
    /// live terms itself: the canonical tool source plus admitted definition
    /// version from the Governor hook
    /// ([`eliot_governor::canonical_skill_tool_source`]), the default-empty
    /// Skill-owned alias table (the frozen H-A composition call site), and
    /// the live admitted Governor fence. Returns the installed identity
    /// plus the receipt the injector carries to the receiver; the receiver
    /// ack re-enters through [`Self::skill_carry_receipt_to_display`].
    pub fn skill_inject_hotset(
        &self,
        request: skill_lifecycle_adapters::SkillHotsetRequest<'_>,
        record: &skill_acceptance_read::AcceptanceRecord,
    ) -> Result<(String, eliot_skill::HotsetDeliveryReceipt), eliot_skill::SkillError> {
        let (source, admitted_version) = eliot_governor::canonical_skill_tool_source()?;
        let aliases = eliot_skill::ToolAliasTable::new();
        let fence = self.governor.kernel_snapshot().state_fence().clone();
        self.check_skill_lifecycle_standing(request.package, &fence)?;
        self.shared_skill_adapter().inject_hotset(
            request,
            source.as_ref(),
            &aliases,
            &admitted_version,
            &fence,
            record,
        )
    }

    /// Drives one owner-accepted intake through the injector call end to end
    /// (issues #1882, #1191).
    ///
    /// Daemon-side handler for a decoded Hotset intake the poller drive
    /// already bound to its committed acceptance row: the
    /// [`SkillIntakePayload`](eliot_agent_bridge_core::SkillIntakePayload)
    /// arrives decoded (shape and package↔inputs binding verified from the
    /// bytes, driven as-is — never re-produced), and the
    /// [`AcceptanceRecord`](skill_acceptance_read::AcceptanceRecord) arrives
    /// from the store owner via the authenticated acceptance read. The
    /// composition observes every remaining authority term itself — the live
    /// admitted fence, the recovered lifecycle standing, and the canonical
    /// tool source plus Governor-admitted definition version — and drives
    /// the composed delivery act. Owner-issued install context and
    /// provider-signed readiness beyond shape/binding checks still arrive
    /// with the injector-carried handoff; acquiring them from their owners
    /// belongs to the external v2 producer/ack lanes.
    /// Returns the installed identity plus the receipt the injector carries
    /// to the receiver.
    ///
    /// The crate error travels by value here like every neighboring
    /// composition seam feeding the Governor lifecycle API, so the size
    /// lint is allowed for this seam.
    #[allow(clippy::result_large_err)]
    pub fn skill_ingest_accepted_intake(
        &self,
        payload: &eliot_agent_bridge_core::SkillIntakePayload,
        record: &skill_acceptance_read::AcceptanceRecord,
    ) -> Result<(String, eliot_skill::HotsetDeliveryReceipt), eliot_skill::SkillError> {
        let (source, admitted_version) = eliot_governor::canonical_skill_tool_source()?;
        let aliases = eliot_skill::ToolAliasTable::new();
        let fence = self.governor.kernel_snapshot().state_fence().clone();
        self.check_skill_lifecycle_standing(&payload.package, &fence)?;
        self.shared_skill_adapter().ingest_wire_intake(
            payload,
            record,
            source.as_ref(),
            &aliases,
            &admitted_version,
            &fence,
        )
    }

    /// Admits an observed Skill activation against the live catalogue and
    /// recovered Governor lifecycle before it can report Material use.
    ///
    /// The catalogue checks structural validation and live tool-basis drift,
    /// while the Governor owner binds the receipt to its exact
    /// promoted revision and package digest. A wire receipt alone is never
    /// enough to make an installed Skill usable.
    ///
    /// Dependency currency is bound across both records: the stored lifecycle
    /// view pins the dependency versions it was derived against, and the
    /// catalogue entry carries the currently admitted set. A host, tool, or
    /// contract version the two disagree on refuses the attempt, so a Skill
    /// whose declared dependencies changed after the view was derived cannot
    /// reach Material use until the view is revalidated or restored through
    /// the governed lifecycle path. The catalogue entry itself is the current
    /// record here, so it is never marked by this check; marking a drifted
    /// entry stale stays with the install, reconcile, and display paths.
    #[allow(clippy::result_large_err)]
    pub fn skill_admit_material_attempt(
        &self,
        receipt: &eliot_skill::SkillHarnessActivationReceipt,
    ) -> Result<eliot_skill::AttemptLifecycleSummary, eliot_skill::SkillError> {
        receipt.validate()?;
        if receipt.state_fence != self.governor.kernel_snapshot().state_fence() {
            return Err(eliot_skill::SkillError::FenceMismatch);
        }
        self.skill_reconcile_tool_basis()?;
        let current_dependencies = {
            let catalogue = self
                .skill_catalogue
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let entry = catalogue
                .get(&receipt.skill_id)
                .ok_or(eliot_skill::SkillError::NotFound)?;
            entry.validate()?;
            if entry.body.body_version != receipt.skill_revision {
                return Err(eliot_skill::SkillError::IdentityMismatch);
            }
            if !entry.is_usable() {
                return Err(eliot_skill::SkillError::InvalidField {
                    field: "entry.status",
                    reason: "unvalidated, stale, or retired Skills are blocked from Material use",
                });
            }
            entry.dependencies.clone()
        };
        if let Some(view) = self.governor.owners().skill.view(&receipt.skill_id)
            && eliot_skill::detect_dependency_staleness(&view.dependencies, &current_dependencies)
                .is_some()
        {
            return Err(eliot_skill::SkillError::InvalidField {
                field: "view.dependencies",
                reason: "declared host/tool/contract dependencies changed after the lifecycle view was derived; the Skill is blocked from Material use until revalidated",
            });
        }
        self.governor.owners().skill.admit_material_attempt(receipt)
    }

    /// Publishes one window of execution evidence through the existing
    /// Skill lifecycle/observation owner (issue #2663, I7.25).
    ///
    /// The daemon previously persisted only the outer host-response body and
    /// returned "accepted" on that basis, discarding the very
    /// [`SkillExecutionEvidence`](eliot_skill::SkillExecutionEvidence) slice
    /// the ingest was admitted to carry. This seam binds the evidence to the
    /// exact Skill identity the retained catalogue entry names and hands the
    /// updated view back, so the caller returns the OWNER's result verbatim: a
    /// claim never outruns persistence.
    ///
    /// Evidence is historical. It keeps the Skill revision, package digest and
    /// attempt it was observed at, so ingesting it now never reactivates a
    /// superseded Skill: the owner binds it to the stored view's exact
    /// revision and package and refuses a mismatch.
    ///
    /// The crate error travels by value here like every neighboring
    /// composition seam feeding the Governor lifecycle API, so the size
    /// lint is allowed for this seam.
    #[allow(clippy::result_large_err)]
    pub fn skill_publish_execution_evidence(
        &self,
        payload: &eliot_agent_bridge_core::SkillExecutionPayload,
    ) -> Result<eliot_skill::SkillLifecycleView, eliot_skill::SkillError> {
        self.skill_reconcile_tool_basis()?;
        let entry = {
            let catalogue = self
                .skill_catalogue
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let entry = catalogue
                .get(&payload.skill_id)
                .ok_or(eliot_skill::SkillError::NotFound)?;
            entry.validate()?;
            // The evidence is bound to the exact identity the retained
            // catalogue entry names, so a substituted revision or package
            // cannot be filed under the stored view's identity.
            if entry.body.body_version != payload.skill_revision {
                return Err(eliot_skill::SkillError::IdentityMismatch);
            }
            entry.clone()
        };
        self.governor.owners().skill.record_execution_evidence(
            &payload.skill_id,
            &payload.skill_revision,
            &payload.package_digest,
            &entry,
            &payload.executions,
        )
    }

    /// Carries the receiver ack back to the display boundary under a fresh
    /// tool-owner read (issue #1882).
    ///
    /// Receiver-ack transport wiring the Hotset lane calls once the receiver
    /// returns its ack for an issued receipt: the composition rebuilds the
    /// canonical tool source through the Governor hook (a FRESH registry
    /// value, so the display-time drift gate always reads live tool-owner
    /// state, never a stale source object) and binds the ack through
    /// [`Self::skill_acknowledge_and_display_versioned`]. Receipt and ack
    /// travel by value, mirroring the owned display boundary.
    #[allow(
        clippy::needless_pass_by_value,
        reason = "receipt/ack cross by value like the owned display boundary"
    )]
    pub fn skill_carry_receipt_to_display(
        &self,
        skill_id: &str,
        receipt: eliot_skill::HotsetDeliveryReceipt,
        ack: eliot_skill::HotsetDeliveryAck,
    ) -> Result<eliot_skill::ActivatedSkillDisplay, eliot_skill::SkillError> {
        let (source, admitted_version) = eliot_governor::canonical_skill_tool_source()?;
        let aliases = eliot_skill::ToolAliasTable::new();
        self.shared_skill_adapter()
            .acknowledge_and_display_versioned(
                skill_id,
                receipt,
                ack,
                source.as_ref(),
                &aliases,
                &admitted_version,
            )
    }

    /// Reconciles installed entries against the live canonical tool view,
    /// marking changed bases stale (issue #1882).
    ///
    /// Production startup/refresh driver: builds the canonical tool source
    /// through the Governor hook with the default-empty Skill-owned alias
    /// table (frozen H-A call site) and marks every installed entry whose
    /// declared tool references no longer resolve. Returns the count of
    /// newly staled entries. Entries installed under provider renames need
    /// their alias table at install time; this pass assumes the composed-act
    /// invariant (canonical references, see `inject_hotset`). Definition-
    /// version drift is NOT rechecked here: entries carry no admitted-version
    /// record, so standing version comparison needs the entry-schema seam
    /// (reported); version drift is caught at install and display time.
    pub fn skill_reconcile_tool_basis(&self) -> Result<usize, eliot_skill::SkillError> {
        let (source, _) = eliot_governor::canonical_skill_tool_source()?;
        let aliases = eliot_skill::ToolAliasTable::new();
        self.shared_skill_adapter()
            .reconcile_tool_basis(source.as_ref(), &aliases)
    }

    /// Borrows the single Governor task lifecycle owner as a forwarding
    /// adapter over the closed [`TaskCommand`](eliot_governor::TaskCommand) path.
    ///
    /// The adapter forwards the exact admitted identity, operation identity,
    /// proposal, context, and command to the Governor canonical task path
    /// and returns only typed results. Its recipe-bearing proposal/command
    /// methods publish the learning-state recipe atomically in that same
    /// Task Controller transition. No policy, admission, or semantic rules
    /// live here; duplicate, stale revision, stale fence, and illegal
    /// transitions fail closed in the Governor owner. Publication happens
    /// only via the Governor `refresh_from_kernel` at the returned receipt
    /// revision. Callers take a fresh adapter per operation so a Governor
    /// refresh surfaces as an exact-view mismatch instead of silent
    /// divergence.
    pub fn task_lifecycle(
        &self,
    ) -> Result<
        task_lifecycle_adapters::ForwardingTaskLifecycle<
            '_,
            dyn eliot_governor::KernelGenerationPort,
        >,
        DaemonError,
    > {
        if self.readiness() != eliot_governor::CompositionReadiness::Ready {
            return Err(DaemonError::Composition(
                eliot_governor::CompositionError::NotReady,
            ));
        }
        Ok(task_lifecycle_adapters::ForwardingTaskLifecycle::new(
            self.governor.task_lifecycle(),
        ))
    }

    /// Borrows the single Governor Skill lifecycle owner as the provider-neutral
    /// [`SkillLifecyclePort`](eliot_controlboard::SkillLifecyclePort) surface port.
    ///
    /// The port forwards the exact admitted identity and typed fields to the
    /// Governor canonical read/propose path (`skill_lifecycle` ->
    /// `ForwardingSkillLifecycle` -> `GovernorSkillLifecycle::view/propose`)
    /// and returns only typed results. No policy, admission, or semantic
    /// rules live here; a stale fence fails closed in the Governor owner.
    /// Callers take a fresh port per operation so a Governor refresh surfaces
    /// as an exact-view mismatch instead of silent divergence.
    pub fn skill_controlboard_port(
        &self,
    ) -> Result<impl eliot_controlboard::SkillLifecyclePort + '_, DaemonError> {
        if self.readiness() != eliot_governor::CompositionReadiness::Ready {
            return Err(DaemonError::Composition(
                eliot_governor::CompositionError::NotReady,
            ));
        }
        Ok(skill_surface_adapters::GovernorSkillForwarder::new(
            self.skill_lifecycle()?,
        ))
    }

    /// Borrows the single Governor Skill lifecycle owner as the agent-bridge
    /// [`SkillLifecyclePort`](eliot_agent_bridge_core::SkillLifecyclePort).
    ///
    /// In-process binding for bridge cores running in the same process as
    /// this composition: reads and proposals forward to the Governor
    /// canonical path, and receiver-ack display resolves the live canonical
    /// tool source per call through the Governor hook. No policy, admission,
    /// or semantic rules live here; a stale fence fails closed in the
    /// Governor owner, and tool-authority verdicts stay with the Skill owner.
    /// A remote bridge process MUST NOT hold this forwarder — cross-process
    /// Skill traffic crosses the authenticated transport as messages. Callers
    /// take a fresh port per operation so a Governor refresh surfaces as an
    /// exact-view mismatch instead of silent divergence.
    pub fn skill_bridge_port(
        &self,
    ) -> Result<impl eliot_agent_bridge_core::SkillLifecyclePort + '_, DaemonError> {
        if self.readiness() != eliot_governor::CompositionReadiness::Ready {
            return Err(DaemonError::Composition(
                eliot_governor::CompositionError::NotReady,
            ));
        }
        Ok(skill_bridge_adapter::BridgeSkillForwarder::new(
            self.shared_skill_adapter(),
        ))
    }

    /// Borrows the single Governor observation/verified-repair reconciliation
    /// owner as a forwarding adapter.
    ///
    /// The adapter forwards the exact admitted identity, operation identity,
    /// and verification report to the Governor canonical path and returns
    /// only typed results. No policy, admission, or semantic rules live here;
    /// fence agreement, verifier endorsement, problem binding, and the two
    /// canonical commits stay with the Governor owner. Watchdog export
    /// acknowledgement mapping is pure and terminal-only: canonical receipts
    /// map to cursor-advancing sink dispositions while unknown outcomes never
    /// advance the cursor. Callers take a fresh adapter per operation so a
    /// Governor refresh surfaces as an exact-view mismatch instead of silent
    /// divergence.
    pub fn observation_reconciliation(
        &self,
    ) -> Result<
        observation_adapters::ForwardingObservationReconciliation<'_, dyn KernelGenerationPort>,
        DaemonError,
    > {
        if self.readiness() != eliot_governor::CompositionReadiness::Ready {
            return Err(DaemonError::Composition(
                eliot_governor::CompositionError::NotReady,
            ));
        }
        Ok(
            observation_adapters::ForwardingObservationReconciliation::new(
                self.governor.observation_reconciliation(),
            ),
        )
    }

    /// Borrows the Kernel-backed read-only context client over the retained
    /// authenticated route (T11.1).
    ///
    /// Mirrors [`Self::observation_reconciliation`]: readiness is checked
    /// first, then a fresh forwarding adapter is built over the caller-held
    /// [`DaemonKernelClient`]. The composition retains no client and no
    /// thread — the caller (the single daemon runtime holding both the
    /// concrete client and this composition, as with
    /// [`Self::note_owner_session_binding`]) passes the already-connected
    /// client per call, so a Governor refresh surfaces as an exact fence
    /// mismatch instead of silent divergence. The returned
    /// [`KernelContextReadClient`] implements `CanonicalReadClient` for
    /// `GetEvidencePack` and `GetCurrentEpistemicPosition` and composes with
    /// the Governor `ReadService` consistency algorithm or the Governor
    /// epistemic position CAS; no second consistency implementation lives here.
    ///
    /// Wiring decision (recorded per brief §4.1): post-`start` attach-style
    /// accessor, not a `start()` signature change — `start()` keeps its exact
    /// `(config, kernel: Arc<dyn KernelGenerationPort>, authority_activation)`
    /// contour.
    pub fn context_read_client(
        &self,
        kernel: &Arc<DaemonKernelClient>,
    ) -> Result<KernelContextReadClient, DaemonError> {
        if self.readiness() != eliot_governor::CompositionReadiness::Ready {
            return Err(DaemonError::Composition(
                eliot_governor::CompositionError::NotReady,
            ));
        }
        Ok(KernelContextReadClient::new(Arc::clone(kernel)))
    }

    /// Borrows the Governor epistemic composition over the retained owners
    /// plus daemon-held Kernel and read clients (T11.2).
    ///
    /// Mirrors [`Self::context_read_client`]: readiness is checked first,
    /// then the activation snapshot is read via the public
    /// `GovernorComposition::read_unique_agent_activation(now)`, and a fresh
    /// [`eliot_governor::GovernorEpistemicComposition`] is borrowed from the
    /// public `owners().canonical`, the activation snapshot, the daemon-held
    /// [`DaemonKernelClient`] (as `&impl KernelTransitionPort`), the
    /// caller-held [`KernelContextReadClient`] (as `&impl CanonicalReadClient`),
    /// and `readiness()`. The composition retains no client and no thread —
    /// the caller (the single daemon runtime holding both the concrete client
    /// and this composition) passes the already-connected clients per call,
    /// so a Governor refresh surfaces as an exact fence mismatch instead of
    /// silent divergence. No `composition.rs` change is involved: this uses
    /// only the public `owners()`/`read_unique_agent_activation()`/`readiness()`
    /// surface plus the associated `borrow` constructor inside
    /// `epistemic_composition.rs`.
    pub fn epistemic_composition<'a>(
        &'a self,
        kernel: &'a Arc<DaemonKernelClient>,
        reads: &'a KernelContextReadClient,
        now: u64,
    ) -> Result<
        eliot_governor::GovernorEpistemicComposition<
            'a,
            DaemonKernelClient,
            KernelContextReadClient,
        >,
        DaemonError,
    > {
        if self.readiness() != eliot_governor::CompositionReadiness::Ready {
            return Err(DaemonError::Composition(
                eliot_governor::CompositionError::NotReady,
            ));
        }
        let activation = self.governor.read_unique_agent_activation(now)?;
        Ok(eliot_governor::GovernorEpistemicComposition::borrow(
            &self.governor.owners().canonical,
            activation,
            kernel.as_ref(),
            reads,
            self.readiness(),
        ))
    }

    /// Borrows the Governor Dreamer orientation intake adapter over the retained owners plus
    /// the daemon-held Kernel client (T12-06, integration #702, semantic #18).
    ///
    /// Mirrors [`Self::context_read_client`]: readiness is checked first, then a fresh
    /// [`GovernorDreamerAdapter`] is built over the composition and the caller-held
    /// [`DaemonKernelClient`]. The composition retains no client and no thread — the caller
    /// (the single daemon runtime holding both the concrete client and this composition, as
    /// with [`Self::note_owner_session_binding`]) passes the already-connected client per
    /// call, so a Governor refresh surfaces as an exact fence mismatch instead of silent
    /// divergence. Intake itself stays fail-closed: without a ready Governor, an exact fence,
    /// and digest-matching sources, nothing queues and no model edge is touched.
    ///
    /// Wiring decision (recorded per brief §5 T12-06): post-`start` attach-style accessor, not
    /// a `start()` signature change — `start()` keeps its exact `(config, kernel:
    /// Arc<dyn KernelGenerationPort>, authority_activation)` contour.
    pub fn dreamer_admission<'a>(
        &'a self,
        kernel: &'a Arc<DaemonKernelClient>,
    ) -> Result<GovernorDreamerAdapter<'a>, DaemonError> {
        if self.readiness() != CompositionReadiness::Ready {
            return Err(DaemonError::Composition(CompositionError::NotReady));
        }
        Ok(GovernorDreamerAdapter::new(self, kernel))
    }

    /// Borrows the Governor Dreamer model-call adapter over the retained owners (T12-07,
    /// integration #702, semantic #18).
    ///
    /// Mirrors [`Self::dreamer_admission`]: readiness is checked first, then a fresh
    /// [`GovernedDreamerModelAdapter`] is built over the composition. Unlike the T12-06
    /// intake adapter this slice performs no Kernel reads — the current account catalogue,
    /// explicit Human policy, admission, and binding arrive threaded per call and execution
    /// leaves through the caller-supplied [`DreamerModelExecution`] port — so no Kernel
    /// client is retained here.
    ///
    /// Wiring decision (recorded per brief §5 T12-07): post-`start` attach-style accessor,
    /// not a `start()` signature change — `start()` keeps its exact `(config, kernel:
    /// Arc<dyn KernelGenerationPort>, authority_activation)` contour.
    pub fn dreamer_model(&self) -> Result<GovernedDreamerModelAdapter<'_>, DaemonError> {
        if self.readiness() != CompositionReadiness::Ready {
            return Err(DaemonError::Composition(CompositionError::NotReady));
        }
        Ok(GovernedDreamerModelAdapter::new(self))
    }

    /// Proves the admitted daemon ingress reaches the durable agent fabric
    /// (issue #872).
    ///
    /// Post-`start` attach-style descriptor, mirroring
    /// [`Self::dreamer_model`]: readiness is checked first, then the admitted
    /// fence snapshot binds the descriptor. No coordinator is constructed here
    /// and no `start()` contour changes; the daemon runtime calls this once
    /// before reporting readiness so the wiring is exercised on the production
    /// path.
    pub fn agent_fabric_descriptor(&self) -> Result<AgentFabricDescriptor, DaemonError> {
        // #740: #872 integrated-path span over the admitted fence binding.
        let _span = tracing::info_span!("eliotd.fabric_descriptor").entered();
        if self.readiness() != CompositionReadiness::Ready {
            return Err(DaemonError::Composition(CompositionError::NotReady));
        }
        let fence = self.governor.kernel_snapshot().state_fence().clone();
        fence.validate().map_err(|error| {
            DaemonError::Lifecycle(format!("agent fabric admitted fence: {error}"))
        })?;
        let config = daemon_coordinator_config()
            .map_err(|error| DaemonError::Lifecycle(error.to_string()))?;
        let descriptor = AgentFabricDescriptor {
            service: SERVICE_NAME.to_owned(),
            generation: fence.resource_generation.value(),
            authority_epoch: fence.authority_epoch.sequence.get(),
            capacity_identity: config.capacity_identity,
        };
        let _ = crate::diagnostics::emit_fabric_attached(
            &descriptor.service,
            descriptor.generation,
            descriptor.authority_epoch,
        );
        Ok(descriptor)
    }

    /// Plans one Task-Controller staffing request through the real coordinator
    /// owner on the admitted daemon path (issue #872).
    ///
    /// Readiness plus exact-fence agreement gate the call; candidate planning
    /// delegates to [`plan_candidate`], so the production caller and the wired
    /// tests share one implementation. No admission, reservation, attempt, or
    /// dispatch occurs here.
    pub fn agent_fabric_plan(
        &self,
        request: eliot_agent_coordinator::StaffingPlanRequest,
    ) -> Result<eliot_agent_coordinator::StaffingPlanCandidate, DaemonError> {
        // #740: #872 planning span. Candidate planning is not admission: the
        // record keeps the candidate disposition distinct from admitted.
        let _span = tracing::info_span!("eliotd.fabric_plan").entered();
        if self.readiness() != CompositionReadiness::Ready {
            return Err(DaemonError::Composition(CompositionError::NotReady));
        }
        let admitted = self.governor.kernel_snapshot().state_fence().clone();
        if request.state_fence != admitted {
            return Err(DaemonError::Lifecycle(
                "agent fabric request fence is stale".to_owned(),
            ));
        }
        let config = daemon_coordinator_config()
            .map_err(|error| DaemonError::Lifecycle(error.to_string()))?;
        plan_candidate(&config, request).map_err(|error| DaemonError::Lifecycle(error.to_string()))
    }

    /// Prepares one Task Controller-authored swarm definition for Governor
    /// admission through the real coordinator owner on the admitted daemon
    /// path (issue #1699).
    ///
    /// Readiness gates the call; preparation delegates to
    /// [`prepare_swarm_definition_admission_candidate`], so the production
    /// caller and the wired tests share one implementation. The prep is
    /// candidate-only: no Governor receipt is minted, no durable write
    /// occurs, and nothing is launched. Launch stays with the existing
    /// injected admission/activation/dispatch ports.
    pub fn agent_fabric_prepare_swarm_definition_admission(
        &self,
        proposal: &eliot_swarm::SwarmPlanProposal,
        maps: &eliot_swarm::SealedIndependentMaps,
    ) -> Result<eliot_agent_coordinator::SwarmDefinitionAdmissionPrep, DaemonError> {
        let _span =
            tracing::info_span!("eliotd.fabric_prepare_swarm_definition_admission").entered();
        if self.readiness() != CompositionReadiness::Ready {
            return Err(DaemonError::Composition(CompositionError::NotReady));
        }
        let config = daemon_coordinator_config()
            .map_err(|error| DaemonError::Lifecycle(error.to_string()))?;
        prepare_swarm_definition_admission_candidate(&config, proposal, maps)
            .map_err(|error| DaemonError::Lifecycle(error.to_string()))
    }

    /// Resolves one admitted provider capability from live session-observed
    /// owner currentness (issue #1108, production composition caller for
    /// W4/A1/A2).
    ///
    /// Per-operation resolution, mirroring [`Self::agent_fabric_plan`]:
    /// Test-only pure composition helper; it does not call the Kernel
    /// provider-capability route. Production remains blocked until that owner
    /// receipt is validated for every claim leg. Readiness is checked first,
    /// then the owner half is resolved
    /// exclusively from the live authenticated session — the freshly
    /// observed live fence from the caller-held [`DaemonKernelClient`] plus
    /// the validated Kernel-issued session binding threaded once via
    /// [`Self::note_owner_session_binding`]. Caller-supplied session halves
    /// in `material` are unconditionally overwritten, never trusted; the
    /// threaded Governor expectation is epoch-bound to the live session
    /// fence (a stale or foreign expectation fails closed here, never at
    /// first effect). This is the sole cross-crate capability construction
    /// path: the material-to-capability builder is crate-internal, so no
    /// external caller can bypass the session-half overwrite. The
    /// composition retains no client, no capability, and no owner half: the
    /// driver re-resolves per admitted operation, so a fence move surfaces
    /// as an exact mismatch instead of silent divergence, and currency is
    /// re-checked on every coordinator `verify` call. Without a validated
    /// handshake the composition has no live session and resolution fails
    /// closed — the daemon stays plan-only.
    ///
    /// # Errors
    ///
    /// Returns [`DaemonError::Composition`] when the Governor is not ready,
    /// [`DaemonError::Kernel`] when no validated session binding exists, or
    /// [`DaemonError::ProviderAdmission`] carrying the fabric/coordinator
    /// owner rejection unchanged (stale, revoked, foreign, or conflicting
    /// evidence).
    #[cfg(test)]
    pub fn agent_fabric_verified_capability(
        &self,
        kernel: &Arc<DaemonKernelClient>,
        material: VerifiedProviderMaterial,
    ) -> Result<eliot_agent_coordinator::AdmittedProviderCapability, DaemonError> {
        // #1108: verified-admission span over the admitted resolution. The
        // presented halves travel by identity only; digests and revisions
        // never enter the sink.
        let _span = tracing::info_span!("eliotd.fabric_verified_capability").entered();
        let material = self.resolve_verified_material(kernel, material)?;
        Ok(build_admitted_provider_capability(material)?)
    }

    /// Constructs the one verified coordinator fabric on freshly resolved
    /// owner material (issue #1108, W5 production composition).
    ///
    /// Production constructor requiring the admitted provider capability:
    /// the capability is admitted through the coordinator owner boundary
    /// (`AdmittedProviderCapability::new`) over the presented half from the
    /// operation at hand plus the owner half resolved exclusively from the
    /// live authenticated session — the freshly observed live fence from the
    /// caller-held [`DaemonKernelClient`] plus the validated Kernel-issued
    /// session binding threaded once via [`Self::note_owner_session_binding`].
    /// Caller-supplied session halves in `material` are unconditionally
    /// overwritten, never trusted; the threaded Governor expectation must be
    /// current under the live session epoch (`is_same_authority`, the same
    /// rule the coordinator enforces), so a stale or foreign expectation
    /// fails closed here, never at first effect. The fabric is then
    /// constructed through
    /// [`AgentFabric::new_with_admitted_provider`](crate::agent_fabric::AgentFabric::new_with_admitted_provider)
    /// under the deterministic [`daemon_coordinator_config`]. The injected
    /// `ports` stay driver-supplied (prerequisite owner ports #694/#696/
    /// #698/#839/#837 remain OPEN): this composition invents no port
    /// implementation and reimplements no owner. Without a validated
    /// handshake the composition has no live session and construction fails
    /// closed — the daemon stays plan-only.
    ///
    /// No second verification scheme: the presented/owner halves are judged
    /// by the same T9-04 owner constructors the coordinator re-runs on every
    /// `verify` call, so currency is re-checked per operation, never cached.
    ///
    /// # Errors
    ///
    /// Returns [`DaemonError::Composition`] when the Governor is not ready,
    /// [`DaemonError::Kernel`] when no validated session binding exists, or
    /// [`DaemonError::ProviderAdmission`] carrying the fabric/coordinator
    /// owner rejection unchanged (malformed presentation, stale expectation
    /// epoch, stale/revoked/foreign/conflicting evidence, or the
    /// verified-construction rejection).
    pub fn agent_fabric_new_verified(
        &self,
        kernel: &Arc<DaemonKernelClient>,
        ports: FabricPorts,
        mut material: VerifiedProviderMaterial,
    ) -> Result<AgentFabric, DaemonError> {
        // #1108: verified-admission span over the admitted construction. The
        // presented halves travel by identity only; digests and revisions
        // never enter the sink.
        let _span = tracing::info_span!("eliotd.fabric_new_verified").entered();
        if self.readiness() != CompositionReadiness::Ready {
            return Err(DaemonError::Composition(CompositionError::NotReady));
        }
        let live_fence = kernel.kernel_fence();
        let session_binding = self
            .owner_session
            .as_ref()
            .map(|facts| facts.session_binding().to_owned())
            .ok_or_else(|| {
                DaemonError::Kernel(
                    "daemon has no validated Kernel session binding; verified provider admission stays plan-only"
                        .to_owned(),
                )
            })?;
        if !material
            .expectation
            .live_authority_epoch
            .is_same_authority(&live_fence.authority_epoch)
        {
            return Err(FabricError::StaleEpoch(
                "provider expectation epoch is not current under the live Kernel session"
                    .to_owned(),
            )
            .into());
        }
        material.live_fence = live_fence;
        material.session_binding = session_binding;
        let presented = eliot_agent_coordinator::PresentedClaimMaterial::new(
            material.claim_id,
            material.attempt_id,
            material.operation_id,
            material.binding_digest,
            material.executable_digest,
            material.route_revision,
            material.capacity_revision,
            material.worker_generation,
            material.presented_fence,
        )
        .map_err(FabricError::Coordinator)?;
        let currentness = eliot_agent_coordinator::OwnerCurrentness::new(
            material.expectation,
            material.live_fence,
            material.session_binding,
        )
        .map_err(FabricError::Coordinator)?;
        let capability = eliot_agent_coordinator::AdmittedProviderCapability::new(
            material.identity,
            presented,
            currentness,
            material.health,
            material.minimum_event_sequence,
        )
        .map_err(FabricError::Coordinator)?;
        let config = daemon_coordinator_config()?;
        Ok(AgentFabric::new_with_admitted_provider(
            config, ports, capability,
        )?)
    }

    /// Restores the fabric on freshly resolved owner material in one call
    /// (issue #1108, A6 production verified restore).
    ///
    /// Production restore requiring a freshly admitted provider capability:
    /// the owner halves are re-resolved over the live authenticated session
    /// exactly like construction (readiness, freshly re-queried live fence,
    /// validated session binding, current expectation epoch; caller-supplied
    /// session halves overwritten, never trusted), the capability is admitted
    /// through the coordinator owner boundary
    /// (`AdmittedProviderCapability::new`), and the fabric is restored through
    /// [`AgentFabric::restore_with_admitted_provider`](crate::agent_fabric::AgentFabric::restore_with_admitted_provider).
    /// Callers pass freshly resolved material on every restore: a stored
    /// capability is never reused across restarts, and a stored `Verified`
    /// label alone restores nothing. Missing, stale, or revoked evidence
    /// propagates typed and stays blocked: the restore never downgrades
    /// silently to plan-only and never resumes effecting operations without
    /// current owner evidence.
    ///
    /// # Errors
    ///
    /// Returns the session-resolution rejection (not ready, no live session,
    /// stale expectation epoch), the capability construction rejection, the
    /// coordinator owner restore rejection, or a stale-config conflict
    /// unchanged.
    pub fn agent_fabric_restore_verified(
        &self,
        kernel: &Arc<DaemonKernelClient>,
        snapshot: FabricSnapshot,
        ports: FabricPorts,
        mut material: VerifiedProviderMaterial,
    ) -> Result<AgentFabric, DaemonError> {
        let _span = tracing::info_span!("eliotd.fabric_restore_verified").entered();
        if self.readiness() != CompositionReadiness::Ready {
            return Err(DaemonError::Composition(CompositionError::NotReady));
        }
        let live_fence = kernel.kernel_fence();
        let session_binding = self
            .owner_session
            .as_ref()
            .map(|facts| facts.session_binding().to_owned())
            .ok_or_else(|| {
                DaemonError::Kernel(
                    "daemon has no validated Kernel session binding; verified provider restore stays blocked"
                        .to_owned(),
                )
            })?;
        if !material
            .expectation
            .live_authority_epoch
            .is_same_authority(&live_fence.authority_epoch)
        {
            return Err(FabricError::StaleEpoch(
                "provider expectation epoch is not current under the live Kernel session"
                    .to_owned(),
            )
            .into());
        }
        material.live_fence = live_fence;
        material.session_binding = session_binding;
        let presented = eliot_agent_coordinator::PresentedClaimMaterial::new(
            material.claim_id,
            material.attempt_id,
            material.operation_id,
            material.binding_digest,
            material.executable_digest,
            material.route_revision,
            material.capacity_revision,
            material.worker_generation,
            material.presented_fence,
        )
        .map_err(FabricError::Coordinator)?;
        let currentness = eliot_agent_coordinator::OwnerCurrentness::new(
            material.expectation,
            material.live_fence,
            material.session_binding,
        )
        .map_err(FabricError::Coordinator)?;
        let capability = eliot_agent_coordinator::AdmittedProviderCapability::new(
            material.identity,
            presented,
            currentness,
            material.health,
            material.minimum_event_sequence,
        )
        .map_err(FabricError::Coordinator)?;
        let config = daemon_coordinator_config()?;
        Ok(AgentFabric::restore_with_admitted_provider(
            snapshot, config, ports, capability,
        )?)
    }

    /// Builds the production fabric ports from retained composition state
    /// (issue #1108 W4/A2).
    ///
    /// Non-test construction of [`FabricPorts`]: every seam is bound to the
    /// closed production port above, so the verified fabric path is
    /// reachable without the test-only fakes in
    /// `bins/eliotd/tests/agent_fabric_wiring.rs`. Each port reports
    /// [`PortBindingState::Missing`] until its prerequisite owner (B-MOD
    /// #694, B-PEER #696, B-SWARM #698, governor-admission,
    /// B-ACTIVATION-PROJECTION #839, dispatch-egress) binds an accepted
    /// interface revision; dependent operations block with the typed
    /// missing-prerequisite residual instead of inventing authority.
    /// Readiness gates the construction exactly like
    /// [`Self::agent_fabric_descriptor`].
    ///
    /// # Errors
    ///
    /// Returns [`DaemonError::Composition`] when the Governor is not ready.
    pub fn production_fabric_ports(&self) -> Result<FabricPorts, DaemonError> {
        if self.readiness() != CompositionReadiness::Ready {
            return Err(DaemonError::Composition(CompositionError::NotReady));
        }
        Ok(FabricPorts {
            model_registry: Arc::new(ProductionModelRegistryPort),
            peer_channel: Arc::new(ProductionPeerChannelPort),
            swarm_control: Arc::new(ProductionSwarmControlPort),
            admission_authority: Arc::new(ProductionAdmissionAuthorityPort),
            activation_authority: Arc::new(ProductionActivationAuthorityPort),
            dispatch_egress: Arc::new(ProductionDispatchEgressPort),
        })
    }

    /// Test-only driver through the production fabric ports (issue #1108).
    ///
    /// Per-operation entry into the verified path: builds the production
    /// ports through [`Self::production_fabric_ports`], then constructs the
    /// fabric through [`Self::agent_fabric_new_verified`], which resolves
    /// the capability over the live authenticated session (caller-supplied
    /// session halves overwritten, expectation epoch-bound to the live
    /// fence) and constructs the coordinator through
    /// `AgentFabric::new_with_admitted_provider`. The per-operation driver
    /// (executor) binds this seam per admitted operation without changing
    /// executor semantics here; without a validated handshake the
    /// resolution fails closed and the daemon stays plan-only. This is the
    /// non-test production caller the verified seam requires: the
    /// composition invents no port implementation beyond the closed ports
    /// above and reimplements no owner.
    ///
    /// #1957 (I3.4): the constructed fabric is not returned until the required
    /// model route passes [`Self::require_admitted_model_route`] — the observed
    /// route scope is applied as a scope change, and every competence item must
    /// hold fresh exact-fingerprint production admission in the daemon-held
    /// view. A refusal is the typed [`FabricError::NoRoute`] residual and no
    /// fabric is returned, so an unevidenced route can never reach an executor.
    ///
    /// # Errors
    ///
    /// Returns the [`Self::production_fabric_ports`] readiness rejection, the
    /// [`Self::agent_fabric_new_verified`] rejection, or the route-gate
    /// rejection, each unchanged.
    #[cfg(test)]
    pub fn drive_verified_agent_fabric(
        &mut self,
        kernel: &Arc<DaemonKernelClient>,
        material: VerifiedProviderMaterial,
        requirements: &RouteRequirements,
        observed_scope: &eliot_governor::RouteScopeFingerprint,
        now: u64,
    ) -> Result<AgentFabric, DaemonError> {
        let _span = tracing::info_span!("eliotd.fabric_drive_verified").entered();
        let ports = self.production_fabric_ports()?;
        let mut fabric = self.agent_fabric_new_verified(kernel, ports, material)?;
        self.require_admitted_model_route(&mut fabric, requirements, observed_scope, now)?;
        Ok(fabric)
    }

    /// Enqueues one validated solo delegate intake for the runtime poll hook
    /// (issue #2567).
    ///
    /// Thin wrapper over
    /// [`solo_agent_driver::solo_enqueue`](crate::solo_agent_driver::solo_enqueue):
    /// the intake is validated and queued bounded; driving happens on the
    /// runtime tick or through [`Self::solo_drive_once`].
    ///
    /// # Errors
    ///
    /// Returns the intake validation, solo-shape, readiness, or queue-bound
    /// rejection unchanged.
    pub fn solo_enqueue(
        &self,
        intake: solo_agent_driver::SoloDelegateIntake,
    ) -> Result<(), DaemonError> {
        solo_agent_driver::solo_enqueue(self, intake, unix_ms())
    }

    /// Synchronous compatibility entry for one solo delegate intake
    /// (issue #2567). Production returns a fail-closed async-required error;
    /// use [`Self::solo_drive_once_async`] for Kernel-backed verification.
    ///
    /// Thin synchronous compatibility wrapper. Production refuses this path
    /// because authenticated Kernel verification requires an async call.
    ///
    /// # Errors
    ///
    /// Production returns [`DaemonError::Kernel`] because the synchronous
    /// path cannot perform authenticated owner verification.
    pub fn solo_drive_once(
        &self,
        kernel: &Arc<DaemonKernelClient>,
        intake: solo_agent_driver::SoloDelegateIntake,
    ) -> Result<solo_agent_driver::SoloDriveOutcome, DaemonError> {
        solo_agent_driver::drive_solo_delegate(self, kernel, intake, unix_ms())
    }

    /// Drives one solo delegate through the nonblocking authenticated Kernel
    /// provider-binding check (issue #1108). Until native-worker claim records
    /// retain an independently owner-verified executable-binding digest, this
    /// entry fails closed before admitted capability construction or dispatch.
    pub async fn solo_drive_once_async(
        &self,
        kernel: &Arc<DaemonKernelClient>,
        intake: solo_agent_driver::SoloDelegateIntake,
    ) -> Result<solo_agent_driver::SoloDriveOutcome, DaemonError> {
        if self.readiness() != CompositionReadiness::Ready {
            return Err(DaemonError::Composition(CompositionError::NotReady));
        }
        solo_agent_driver::drive_solo_delegate_async(kernel, intake, unix_ms()).await
    }

    /// Drives at most one queued solo intake; the runtime poll hook
    /// (issue #2567).
    ///
    /// Thin synchronous compatibility wrapper. Production refuses this path;
    /// use [`crate::solo_poll_queue_async`] from an async cadence.
    ///
    /// # Errors
    ///
    /// Production returns [`DaemonError::Kernel`] and retains the queued item
    /// for the asynchronous poll path.
    pub fn solo_poll_queue(
        &self,
        kernel: &Arc<DaemonKernelClient>,
    ) -> Result<solo_agent_driver::SoloPollOutcome, DaemonError> {
        solo_agent_driver::solo_poll_queue(self, kernel)
    }

    /// Reads one solo attempt status under its durable identity
    /// (issue #2567).
    ///
    /// Thin wrapper over
    /// [`solo_agent_driver::solo_status`](crate::solo_agent_driver::solo_status).
    ///
    /// # Errors
    ///
    /// Returns the readiness or readback rejection unchanged.
    pub fn solo_status(
        &self,
        operation_id: &str,
    ) -> Result<solo_agent_driver::SoloAttemptStatus, DaemonError> {
        solo_agent_driver::solo_status(self, operation_id)
    }

    /// Requests cancellation of one solo attempt (issue #2567).
    ///
    /// Thin wrapper over
    /// [`solo_agent_driver::solo_request_cancel`](crate::solo_agent_driver::solo_request_cancel):
    /// records the request; possible effects remain reconciling.
    ///
    /// # Errors
    ///
    /// Returns the readiness or cancellation rejection unchanged.
    pub fn solo_request_cancel(
        &self,
        kernel: &Arc<DaemonKernelClient>,
        operation_id: &str,
    ) -> Result<solo_agent_driver::SoloAttemptStatus, DaemonError> {
        solo_agent_driver::solo_request_cancel(self, kernel, operation_id)
    }

    /// Reconciles an observed terminal solo cancellation (issue #2567).
    ///
    /// Thin wrapper over
    /// [`solo_agent_driver::solo_reconcile_cancel`](crate::solo_agent_driver::solo_reconcile_cancel).
    ///
    /// # Errors
    ///
    /// Returns the readiness or reconciliation rejection unchanged.
    pub fn solo_reconcile_cancel(
        &self,
        kernel: &Arc<DaemonKernelClient>,
        operation_id: &str,
        terminal_evidence: &str,
    ) -> Result<solo_agent_driver::SoloAttemptStatus, DaemonError> {
        solo_agent_driver::solo_reconcile_cancel(self, kernel, operation_id, terminal_evidence)
    }

    /// Ingests one worker observation as the correlated candidate result
    /// (issue #2567).
    ///
    /// Thin wrapper over
    /// [`solo_agent_driver::solo_ingest_result`](crate::solo_agent_driver::solo_ingest_result):
    /// acknowledgement first (never success), then the candidate result
    /// (never Finish).
    ///
    /// # Errors
    ///
    /// Returns the readiness or ingestion rejection unchanged.
    pub fn solo_ingest_result(
        &self,
        kernel: &Arc<DaemonKernelClient>,
        operation_id: &str,
        worker_id: &str,
        result_digest: &str,
        observed_via: &str,
    ) -> Result<solo_agent_driver::SoloAttemptStatus, DaemonError> {
        solo_agent_driver::solo_ingest_result(
            self,
            kernel,
            operation_id,
            worker_id,
            result_digest,
            observed_via,
        )
    }

    /// Restores one solo attempt after a restart without relaunching
    /// (issue #2567).
    ///
    /// Thin wrapper over
    /// [`solo_agent_driver::solo_restore`](crate::solo_agent_driver::solo_restore).
    ///
    /// # Errors
    ///
    /// Returns the readiness, readback, restore, or reconciliation rejection
    /// unchanged.
    pub fn solo_restore(
        &self,
        kernel: &Arc<DaemonKernelClient>,
        operation_id: &str,
    ) -> Result<solo_agent_driver::SoloAttemptStatus, DaemonError> {
        solo_agent_driver::solo_restore(self, kernel, operation_id)
    }

    /// Resolves the session-observed owner half of one verified provider
    /// material over the live authenticated session.
    ///
    /// Readiness plus the exact live fence and the validated session binding
    /// gate the resolution: the threaded expectation must be current under
    /// the live session epoch (`is_same_authority`, the same rule the
    /// coordinator enforces), and caller-supplied `live_fence` /
    /// `session_binding` values are replaced with the session-observed
    /// ones. Presented halves and the Governor expectation travel through
    /// untouched for the coherence gates downstream to judge.
    #[cfg(test)]
    fn resolve_verified_material(
        &self,
        kernel: &Arc<DaemonKernelClient>,
        mut material: VerifiedProviderMaterial,
    ) -> Result<VerifiedProviderMaterial, DaemonError> {
        if self.readiness() != CompositionReadiness::Ready {
            return Err(DaemonError::Composition(CompositionError::NotReady));
        }
        let live_fence = kernel.kernel_fence();
        let session_binding = self
            .owner_session
            .as_ref()
            .map(|facts| facts.session_binding().to_owned())
            .ok_or_else(|| {
                DaemonError::Kernel(
                    "daemon has no validated Kernel session binding; verified provider admission stays plan-only"
                        .to_owned(),
                )
            })?;
        if !material
            .expectation
            .live_authority_epoch
            .is_same_authority(&live_fence.authority_epoch)
        {
            return Err(FabricError::StaleEpoch(
                "provider expectation epoch is not current under the live Kernel session"
                    .to_owned(),
            )
            .into());
        }
        material.live_fence = live_fence;
        material.session_binding = session_binding;
        Ok(material)
    }

    /// Borrows the daemon-held Governor capability admission view (#1957).
    ///
    /// Post-`start` attach-style accessor, mirroring
    /// [`Self::context_read_client`]: readiness is checked first so callers
    /// observe the view only on the admitted path. Hydration (evidence
    /// inserts, legacy imports, scope changes) goes through the mutable
    /// accessor; route execution gates through
    /// [`Self::admit_production_route`].
    pub fn capability_admission(&self) -> Result<&GovernorCapabilityAdmission, DaemonError> {
        if self.readiness() != CompositionReadiness::Ready {
            return Err(DaemonError::Composition(CompositionError::NotReady));
        }
        Ok(&self.capability_admission)
    }

    /// Mutably borrows the daemon-held capability admission view (#1957).
    ///
    /// Mirrors [`Self::capability_admission`]: readiness is checked first.
    /// Callers hydrate the held view from the closed
    /// `GetCapabilityEvidenceState` read (see
    /// [`GovernorCapabilityAdmission::plan_evidence_read`] and
    /// [`GovernorCapabilityAdmission::ingest_evidence_response`]) and the
    /// legacy importer; admission semantics stay in the Governor registry.
    pub fn capability_admission_mut(
        &mut self,
    ) -> Result<&mut GovernorCapabilityAdmission, DaemonError> {
        if self.readiness() != CompositionReadiness::Ready {
            return Err(DaemonError::Composition(CompositionError::NotReady));
        }
        Ok(&mut self.capability_admission)
    }

    /// Mutably borrows the single live Governor-owned derivation instance
    /// (issue #1935 AUD1, I7.16).
    ///
    /// Mirrors [`Self::capability_admission_mut`]: readiness is checked
    /// first. Callers feed the held instance from threaded live
    /// host/Watchdog/trace observation and publish the projection (see
    /// [`maintain_governor_authority_feed`](crate::maintain_governor_authority_feed));
    /// derivation semantics stay in the Governor owner.
    pub fn governor_authority_mut(
        &mut self,
    ) -> Result<&mut eliot_governor::LiveGovernorAuthority, DaemonError> {
        if self.readiness() != CompositionReadiness::Ready {
            return Err(DaemonError::Composition(CompositionError::NotReady));
        }
        Ok(&mut self.governor_authority)
    }

    /// Borrows the daemon-held Governor outcome registry view (#1961, I3.4).
    ///
    /// Post-`start` attach-style accessor, mirroring
    /// [`Self::capability_admission`]: readiness is checked first so a
    /// refused view is never observed on the unadmitted path. The governed
    /// model gate records a broad outcome into this held view and reads
    /// eligibility back from it, which is what makes a generation-scope block
    /// outlive the attempt that observed the reproduced failure: the block is
    /// dropped by the owner's own expiry, never by the end of a call.
    ///
    /// The handle is borrowed rather than a guard handed out on purpose. The
    /// gate is reached from an `async fn` that then awaits the provider
    /// execution port, and a `std::sync::MutexGuard` held across an await would
    /// make that future `!Send` and would serialise every model invoke for the
    /// duration of a provider call. Locking is therefore scoped to the gate's
    /// own synchronous body, and poisoning is recovered the same way the
    /// `skill_catalogue` handle recovers it.
    pub fn capability_outcomes(
        &self,
    ) -> Result<&std::sync::Mutex<CapabilityRegistryView>, DaemonError> {
        if self.readiness() != CompositionReadiness::Ready {
            return Err(DaemonError::Composition(CompositionError::NotReady));
        }
        Ok(&self.capability_outcomes)
    }

    /// Consults the held capability admission before route execution (#1957).
    ///
    /// Returns whether `skill_id` holds fresh exact-fingerprint
    /// `probe_passed` or `observed` evidence from an admissible source at
    /// `now`, with no restricting `broken`/`unsupported`/`degraded`
    /// evidence. Declared/imported records alone never admit. Callers gate
    /// route execution on `Ok(true)`; `Ok(false)` and `Err` both fail
    /// closed.
    pub fn admit_production_route(
        &self,
        skill_id: &str,
        scope: &eliot_governor::RouteScopeFingerprint,
        now: u64,
    ) -> Result<bool, DaemonError> {
        Ok(self
            .capability_admission()?
            .admit_production_route(skill_id, scope, now))
    }

    /// Requires one production model route through the daemon route gate
    /// (#1957, I3.4).
    ///
    /// This is the daemon's production call into
    /// [`AgentFabric::require_model_route`]. Order is load-bearing: the
    /// caller-observed route scope is first applied as an I3.4 scope change, so
    /// a runtime, adapter, provider, or serializer change stops authorizing the
    /// production work it used to authorize; only then does the gate require
    /// every competence item of `requirements` to hold fresh exact-fingerprint
    /// `probe_passed` or `observed` evidence in the held view at `now`.
    ///
    /// The observed scope is the same observation the gate gates on, never one
    /// re-derived from the resolved route.
    /// [`ScopeDependencySelector::all`](eliot_governor::ScopeDependencySelector::all)
    /// is its own documented coarse whole-scope selection for a caller that
    /// observes one scope and cannot attribute the move to a narrower dimension;
    /// the comparison still runs dimension by dimension, so an exactly matching
    /// retained record is never staled.
    ///
    /// Absence of evidence refuses. An empty held view, a `declared` /
    /// `imported_legacy` record, and a stale or expired record all fail closed
    /// to the typed [`FabricError::NoRoute`] the gate raises, which crosses
    /// unchanged as [`DaemonError::ProviderAdmission`]. There is no local
    /// fallback route and no swallowed refusal.
    ///
    /// # Errors
    ///
    /// Returns [`DaemonError::Composition`] when the composition is not ready,
    /// or the gate's rejection unchanged.
    pub fn require_admitted_model_route(
        &mut self,
        fabric: &mut AgentFabric,
        requirements: &RouteRequirements,
        observed_scope: &eliot_governor::RouteScopeFingerprint,
        now: u64,
    ) -> Result<eliot_agent_api::RouteFingerprint, DaemonError> {
        let view = self.capability_admission_mut()?;
        // NO `apply_scope_change` CALL HERE, and the reason is the whole point
        // of issue #1957's W4. That method stales a record whenever its
        // fingerprint DIFFERS from the scope supplied as `current` on a selected
        // dimension, and a scope once invalidated is not revived by a later
        // matching record. Handing it an OBSERVED route as `current` with
        // `ScopeDependencySelector::all()` therefore invalidates every other
        // account's and route's still-valid evidence, on every call, and
        // permanently — so admitting one route destroyed the evidence for the
        // rest. I3.4 requires capability to be route/account-specific, so that
        // call erased exactly the dimension the document protects. A documented
        // coarse selector does not make a wrong direction right.
        //
        // Staleness is therefore DERIVED at the gate and needs no mutation:
        // `admit_production_route` already requires each retained record's
        // `scope_fingerprint` to equal the observed scope by EXACT value, so a
        // changed adapter hash, serializer fingerprint, or any other dimension
        // stops admitting on its own. That is the simplest correct mechanism for
        // "runtime/adapter/provider/serializer change makes dependent evidence
        // stale", and it is the one the document describes.
        //
        // `GovernorCapabilityAdmission::apply_scope_change` is therefore NOT
        // called here. Its production caller is the startup attach's
        // [`Self::commit_scope_change_restriction`], which passes a narrower
        // selector — the two dimensions the Host admitted about the daemon's own
        // served bytes — and never an observed per-call route.
        // The intake path's durable leg
        // (`capability_evidence_wiring::hydrate_capability_admission_view`)
        // re-derives the invalidation index from each served record's own
        // persisted `limitations_and_negative_evidence`, so a committed
        // restriction still survives a restart.
        Ok(fabric.require_model_route(requirements, view, observed_scope, now)?)
    }

    /// Runs the retained `WorkScope` guard at one I4.2.1 use boundary from a
    /// real workspace observation (issue #1746, W3).
    ///
    /// This is the daemon's use-boundary entry for the guard, and it owns
    /// exactly one step: it reads the caller's explicit absolute root
    /// mechanically through
    /// [`task_binding_admission::observe_explicit_workspace`] — filesystem,
    /// VCS, and project facts, never a caller cwd or a normalized path string
    /// — and hands that live observation to the Governor's real guard owner,
    /// [`eliot_governor::GovernorComposition::check_work_scope_at_use_boundary`].
    /// The Governor derives the observed `ScopeBinding` against the scope it
    /// actually retains, runs the guard at the supplied trigger, and returns
    /// the fresh `MATCHED` report or a typed refusal that preserves the exact
    /// disposition.
    ///
    /// Boundaries: session attach/resume, first tool/process event for a task,
    /// agent/process launch, a root/worktree/cwd/editor-workspace change, and a
    /// scope-sensitive canonical write or Material effect. The trigger is
    /// supplied by the boundary and never guessed here.
    ///
    /// A withheld or quarantined outcome changes nothing: the retained
    /// binding, task state, and every scope's project memory are untouched, a
    /// mismatching observation never silently moves a historical task, and
    /// relocation still requires its explicit owner receipt through
    /// [`Self::admit_scope_attach`]. Scope uncertainty therefore permits only
    /// the already-defined quarantined capture route
    /// ([`task_binding_admission::admit_capture`]), never a task-bound write.
    ///
    /// # Scope-revision limit
    ///
    /// The current retained snapshot exposes `owner_revision`, while its
    /// `ScopeBinding` and guard receipt carry no `WorkScopeDescriptor` revision;
    /// `ObservedScopeResources` likewise has no observed descriptor revision.
    /// This entry therefore revalidates actual instance, lineage, resource
    /// generation, privacy, source closure, and the current Kernel fence, but
    /// cannot compare expected and observed scope revisions. It does not
    /// reinterpret `owner_revision` as a descriptor revision.
    ///
    /// # Live status
    ///
    /// `caller: STITCH`. The admission boundary implementation is present but
    /// has no production callers. The attach/resume, launch, and write
    /// ingresses that would supply an
    /// explicit workspace root, the admitted privacy class, the retained source
    /// generation, and the source closure are owned by the attach-transport and
    /// operation-wiring issues, so nothing in `eliotd` can call this yet. A
    /// startup attach was deliberately not added to manufacture a caller.
    #[allow(
        clippy::too_many_arguments,
        reason = "use-boundary driver joins the explicit root, privacy, source generation, closure, and trigger"
    )]
    pub fn run_work_scope_guard_at_use_boundary(
        &mut self,
        explicit_root: &std::path::Path,
        observed_privacy_class: eliot_security_contracts::PrivacyClass,
        governing_source_generation: u64,
        source_closure: Option<(
            &eliot_governor::GoverningSourceSet,
            &eliot_governor::PrivacyProfile,
        )>,
        trigger: eliot_workscope::GuardTrigger,
    ) -> Result<eliot_workscope::TriggerReport, DaemonError> {
        if self.readiness() != CompositionReadiness::Ready {
            return Err(DaemonError::Composition(CompositionError::NotReady));
        }
        let fence = self.governor.kernel_snapshot().state_fence();
        let observed = task_binding_admission::observe_explicit_workspace(explicit_root, &fence)?;
        self.governor
            .check_work_scope_at_use_boundary(
                &observed,
                observed_privacy_class,
                governing_source_generation,
                source_closure,
                trigger,
            )
            .map_err(DaemonError::Composition)
    }

    /// Re-reads one compiled cold-start surface at the authenticated attach
    /// boundary (issue #1746 W5; #8 W1).
    ///
    /// This is an owner readback adapter, not a second cold-start compiler:
    /// the input must carry the Governor-issued lease and its complete prior
    /// surface. The method checks the full lease key/epoch/deadline/terminal
    /// state, compares the supplied fence to the Governor's current snapshot, then
    /// asks the Governor for the exact terminal under that key. It returns the
    /// surface only if every projected frozen field is equal to the expected
    /// owner projection. Expiry uses the daemon's internal Unix-millisecond
    /// clock, so the caller cannot extend a lease by supplying an older tick. A moved fence, changed receipt,
    /// session, scope/task/source/profile revision, or projection fails closed.
    /// The bridge activation ticket is not an input because it carries only
    /// correlation identity.
    ///
    /// `caller: STITCH`. The authenticated Kernel/attach producer must supply
    /// the actual lease/surface pair and observed fence; the current activation
    /// route does not carry those semantic owner values. This method never
    /// derives them from host fields or creates a replacement receipt.
    pub fn read_cold_start_surface_for_attach(
        &self,
        input: &task_binding_admission::ColdStartAttachInput,
    ) -> Result<eliot_governor::ColdStartSurfaceView, DaemonError> {
        if self.readiness() != CompositionReadiness::Ready {
            return Err(DaemonError::Composition(CompositionError::NotReady));
        }
        input.lease.validate().map_err(|error| {
            DaemonError::Composition(CompositionError::Recovery(format!(
                "cold-start attach lease is invalid: {error}"
            )))
        })?;
        if !matches!(
            input.lease.state,
            eliot_workscope::OnboardingLeaseState::Ready
                | eliot_workscope::OnboardingLeaseState::Ambiguous
                | eliot_workscope::OnboardingLeaseState::Failed
        ) || !input.matches_lease()
        {
            return Err(DaemonError::Composition(
                CompositionError::ActivationStaleFence,
            ));
        }

        let live_fence = self.governor.kernel_snapshot().state_fence();
        if input.state_fence != live_fence
            || input.expected_surface.state_fence != live_fence
            || input.expected_surface.lease_deadline < unix_ms()
        {
            return Err(DaemonError::Composition(
                CompositionError::ActivationStaleFence,
            ));
        }

        let (current_lease, current_surface) = self.governor.cold_start_owner_readback_for_lease(
            &input.lease.lineage_candidate_ref,
            &input.lease.workspace_instance_candidate_ref,
            input.lease.privacy_class,
            input.lease.governing_source_generation,
        )?;
        if current_lease != input.lease || current_surface != input.expected_surface {
            return Err(DaemonError::Composition(
                CompositionError::ActivationStaleFence,
            ));
        }
        Ok(current_surface)
    }

    /// Admits one explicit workspace instance as an attach to the retained
    /// `WorkScope` binding (issue #1929, I04.4 attach trigger).
    ///
    /// The daemon owns exactly one step here and owns no other: it observes
    /// the caller's explicit absolute root mechanically through
    /// [`task_binding_admission::observe_explicit_workspace`] and then hands
    /// that live observation to the Governor's real attach/receipt owner,
    /// [`eliot_governor::GovernorComposition::admit_observed_scope_attach`],
    /// together with the retained descriptor, the trigger-authenticated
    /// authorization reference, the privacy boundary, and the onboarding-
    /// retained source closure. The Governor produces the owner-issued
    /// relocation/attach receipt, rebinds with it, requires a fresh `MATCHED`
    /// source-closure check for the observed instance, and only then is the
    /// admitted owner installed into the live composition by
    /// [`eliot_governor::GovernorComposition::install_admitted_work_scope_owner`].
    ///
    /// The installed binding is immediately effective: every later
    /// [`Self::commit_canonical_and_refresh`] runs
    /// `check_canonical_write_work_scope` against it, so a write addressing a
    /// different instance, root, or generation quarantines instead of
    /// committing. Shape failures (non-absolute root, blank reference, zero
    /// counter, invalid descriptor or privacy boundary) and a root that cannot
    /// be observed fail closed as [`DaemonError::TaskBinding`] carrying
    /// `TASK_SELECTION_REQUIRED` or `TASK_SCOPE_INCOMPATIBLE`, and the
    /// retained binding, task state, and project memory stay untouched.
    ///
    /// The daemon never infers a workspace from cwd, proximity, or recency, and
    /// never mints a receipt of its own: `ScopeAttachIngress` is the only
    /// accepted input and its `receipt_ref` is a reference the Governor binds,
    /// not an authority the daemon asserts.
    ///
    /// # Not yet reached (issue #1929)
    ///
    /// This method currently has zero call sites, and it cannot acquire one
    /// without inventing authority, so it is reported here rather than wired to
    /// a synthetic caller. Three measured reasons:
    ///
    /// - it is **circular** — `GovernorComposition::admit_observed_scope_attach`
    ///   fails closed unless a `WorkScope` owner is already retained, and this
    ///   method is the only daemon path that installs one;
    /// - the daemon holds no `WorkScopeDescriptor`, no `GoverningSourceSet`, and
    ///   no authenticated authorization reference, so three of the nine
    ///   `ScopeAttachIngress` fields would have to be fabricated;
    /// - the daemon knows only its own config and state directories, which are
    ///   not a user `WorkScope`. Attaching one of them as a scope would create
    ///   a `WorkScope` binding the user never declared.
    ///
    /// The legitimate owner is the attach-transport ingress
    /// `eliot_governor::GovernorComposition` already documents as blocked
    /// ("attach-transport: `bins/eliotd` `ScopeAttachIngress` carries no
    /// discovery or onboarding lease"). A startup attach was deliberately not
    /// added to manufacture a caller.
    pub fn admit_scope_attach(
        &mut self,
        ingress: &task_binding_admission::ScopeAttachIngress,
    ) -> Result<
        (
            eliot_governor::ScopeRelocationOrAttachReceipt,
            eliot_governor::WorkScopeBindingSnapshot,
        ),
        DaemonError,
    > {
        if self.readiness() != CompositionReadiness::Ready {
            return Err(DaemonError::Composition(CompositionError::NotReady));
        }
        ingress.validate()?;
        let fence = self.governor.kernel_snapshot().state_fence();
        let observed = task_binding_admission::observe_explicit_workspace(
            ingress.explicit_root.as_path(),
            &fence,
        )?;
        let (receipt, owner) = self.governor.admit_observed_scope_attach(
            ingress.receipt_ref.as_str(),
            &observed,
            &ingress.descriptor,
            ingress.authorizing_ref.as_str(),
            ingress.privacy_class,
            ingress.governing_source_generation,
            &ingress.sources,
            &ingress.privacy,
            ingress.owner_revision,
        )?;
        let snapshot = self
            .governor
            .install_admitted_work_scope_owner(owner)
            .map_err(DaemonError::Composition)?;
        Ok((receipt, snapshot))
    }

    /// Resolves the current, applicable task selection for admission from the
    /// Governor's own state (issue #1746, W4).
    ///
    /// The daemon adds no resolver of its own: it asks the Governor for the
    /// activation snapshot and the owner-compiled readiness receipt through
    /// [`eliot_governor::GovernorComposition::current_task_selection`] — the
    /// unique live work lease, the live owner session, the durable
    /// `TaskContract` revision, the installed `MATCHED` `WorkScope`, and the
    /// receipt whose `task_binding` carries the acceptance digest and the
    /// selection source — and then applies the applicability recheck through
    /// [`task_binding_admission::bind_current_task_selection`]. A request that
    /// supplies its own `TaskSelectionEvidence` is never read.
    ///
    /// The typed answer is preserved exactly: `Current` with the exact
    /// evidence, `Absent` with the retained scope's task-intake shape when no
    /// task is selected, `Exploratory` with the exact read-only binding,
    /// `Stale` with the exact old task/revision for owner refresh/rebind, or
    /// `Ambiguous` with the owner-issued bounded candidate handles when
    /// several survived task selection. Task-candidate ambiguity remains
    /// distinct from active-work scope ambiguity, which the Governor's
    /// activation route returns through its existing typed error.
    /// No task is created to remove ambiguity and no cold capture is attached
    /// retroactively here; that remains a separate admitted binding
    /// transition.
    ///
    /// # Live status
    ///
    /// `caller: STITCH`. The dispatch ingresses that would supply the lease
    /// key terms are owned by the attach-transport and operation-wiring issues
    /// (`GovernorComposition::current_task_selection` is reached from no live
    /// path because the retained cold-start lease itself has no producer yet).
    /// No synthetic caller was added.
    #[allow(
        clippy::too_many_arguments,
        reason = "selection resolution joins the activation route, the compiled receipt, and the live fence in one fail-closed entry"
    )]
    pub fn resolve_current_task_selection(
        &self,
        now: u64,
        lineage_candidate_ref: &str,
        workspace_instance_candidate_ref: &str,
        privacy_class: eliot_security_contracts::PrivacyClass,
        governing_source_generation: u64,
    ) -> Result<task_binding_admission::TaskSelectionResponse, DaemonError> {
        if self.readiness() != CompositionReadiness::Ready {
            return Err(DaemonError::Composition(CompositionError::NotReady));
        }
        let (activation, receipt) = self.governor.current_task_selection(
            now,
            lineage_candidate_ref,
            workspace_instance_candidate_ref,
            privacy_class,
            governing_source_generation,
        )?;
        let live_fence = self.governor.kernel_snapshot().state_fence();
        match task_binding_admission::bind_current_task_selection(
            activation.as_ref(),
            &receipt,
            &live_fence,
        )
        .map_err(DaemonError::from)?
        {
            task_binding_admission::TaskSelectionDisposition::Absent => {
                let intake =
                    GovernorComposition::<dyn KernelGenerationPort>::task_selection_intake_shape(
                        receipt.scope.scope_ref.as_str(),
                    )
                    .map_err(DaemonError::Composition)?;
                Ok(task_binding_admission::TaskSelectionResponse::Absent(
                    Box::new(intake),
                ))
            }
            task_binding_admission::TaskSelectionDisposition::Exploratory {
                task_ref,
                task_revision,
                acceptance_digest,
            } => Ok(task_binding_admission::TaskSelectionResponse::Exploratory {
                task_ref,
                task_revision,
                acceptance_digest,
            }),
            task_binding_admission::TaskSelectionDisposition::Ambiguous(candidate_handles) => Ok(
                task_binding_admission::TaskSelectionResponse::Ambiguous(candidate_handles),
            ),
            task_binding_admission::TaskSelectionDisposition::Stale {
                task_ref,
                task_revision,
            } => Ok(task_binding_admission::TaskSelectionResponse::Stale {
                task_ref,
                task_revision,
            }),
            task_binding_admission::TaskSelectionDisposition::Current(evidence) => Ok(
                task_binding_admission::TaskSelectionResponse::Current(evidence),
            ),
        }
    }

    /// Compiles and retains the reconciliation receipt for one attach of an
    /// already-running external agent (issue #1782, I11.11 lines 27-42).
    ///
    /// I11.11 line 27: "Attaching an already-running external agent does not
    /// retroactively make its earlier activity observed or authorized. ELIOT
    /// creates an `ExternalAttachReconciliationReceipt`." The composition owns
    /// only the retention of the already-compiled receipt: it validates it
    /// through [`ExternalAttachReconciliationReceipt::validate`] and installs
    /// it as this composition's single retained attach state. It mints no
    /// receipt, adopts no pre-attach effect, and derives nothing from a process
    /// name, PID, executable path, current directory or discovery order.
    ///
    /// # Not yet reached by a transport caller (issue #1782)
    ///
    /// This method currently has zero call sites. It validates the presented
    /// receipt through [`ExternalAttachReconciliationReceipt::validate`] and
    /// installs it as this composition's single retained attach state together
    /// with the live Governor fence and the noted owner session, so even the
    /// receipt-only path carries the applicability snapshots the continuation
    /// recheck compares. It mints no receipt, adopts no pre-attach effect,
    /// and derives nothing from a process name, PID, executable path, current
    /// directory or discovery order. The Bridge ingress that binds a receipt
    /// to its exact request/session/task/fence/attempt binding is
    /// [`Self::serve_bridge_external_attach`].
    ///
    /// # Errors
    ///
    /// Returns the exact [`eliot_agent_bridge_core::BridgeError`] from
    /// [`ExternalAttachReconciliationReceipt::validate`] when the presented
    /// receipt does not validate, leaving the previously retained record
    /// untouched.
    pub fn record_external_attach_reconciliation(
        &mut self,
        receipt: &ExternalAttachReconciliationReceipt,
    ) -> Result<(), Box<eliot_agent_bridge_core::BridgeError>> {
        receipt.validate()?;
        let live_fence = self.governor.kernel_snapshot().state_fence();
        let live_session = self
            .owner_session
            .as_ref()
            .map(|facts| facts.session_binding().to_owned());
        self.external_attach = Some(Box::new(ExternalAttachIngressRecord {
            claim: None,
            receipt: receipt.clone(),
            admitted_fence: live_fence,
            owner_session_binding: live_session,
        }));
        Ok(())
    }

    /// Serves one live Bridge external-attach request (issue #1782 audit
    /// repair).
    ///
    /// This is the daemon side of the `eliot-agent-bridge-core` external
    /// attach transport: `binding` is the exact
    /// [`AttachBinding`](eliot_agent_bridge_core::AttachBinding) the trusted
    /// host activation boundary sealed, `request` is the
    /// [`AttachRequest`](eliot_agent_bridge_core::AttachRequest) that carried
    /// it, and `observation` is what the authenticated platform/peer and
    /// `WorkScope` owners actually observed for that attach. The binding
    /// claim is copied and checked first, the owner observations are fed into
    /// [`reconcile_external_attach`](crate::reconcile_external_attach)
    /// unchanged, and the resulting record is retained before the returned
    /// view is read back from that retention: the Bridge clears its own
    /// reconciliation flag only after this method reports success, never
    /// before the receipt is persisted here. A startup attach was
    /// deliberately not added to manufacture a caller, and the daemon's own
    /// config/state directories were never used as a stand-in `WorkScope`.
    ///
    /// # Errors
    ///
    /// Returns the exact [`eliot_agent_bridge_core::BridgeError`] from the
    /// binding-claim, compiler, or receipt-validation leg, leaving any
    /// previously retained record untouched.
    pub fn serve_bridge_external_attach(
        &mut self,
        binding: &eliot_agent_bridge_core::AttachBinding,
        request: &eliot_agent_bridge_core::AttachRequest,
        observation: &ExternalAttachObservation,
    ) -> Result<ExternalAttachBindingView, Box<eliot_agent_bridge_core::BridgeError>> {
        let claim = claim_bridge_attach(binding, request)?;
        let live_fence = self.governor.kernel_snapshot().state_fence();
        let live_session = self
            .owner_session
            .as_ref()
            .map(|facts| facts.session_binding().to_owned());
        let record =
            serve_bridge_external_attach(claim, observation, &live_fence, live_session.as_deref())?;
        self.external_attach = Some(Box::new(record));
        let retained = self
            .external_attach
            .as_deref()
            .ok_or_else(|| Box::new(eliot_agent_bridge_core::BridgeError::NotAttached))?;
        binding_view(retained)
    }

    /// Replays the retained disposition for a lost Bridge response (issue
    /// #1782 audit repair).
    ///
    /// The presenting binding must equal the retained claim field for field:
    /// an exact match reads back the same disposition with the same
    /// continuation and the same attempt identity, minting nothing, while
    /// any other binding fails closed without touching the retained record.
    /// A lost response therefore recovers the same disposition instead of
    /// creating another continuation or silently resetting the
    /// reconciliation state.
    ///
    /// # Errors
    ///
    /// Returns the exact [`eliot_agent_bridge_core::BridgeError`] from the
    /// binding-claim, replay-match, or receipt-validation leg.
    pub fn replay_bridge_external_attach(
        &self,
        binding: &eliot_agent_bridge_core::AttachBinding,
        request: &eliot_agent_bridge_core::AttachRequest,
    ) -> Result<ExternalAttachBindingView, Box<eliot_agent_bridge_core::BridgeError>> {
        let presenting = claim_bridge_attach(binding, request)?;
        let record = self.external_attach.as_deref();
        replay_bridge_external_attach(record, &presenting)?;
        let retained =
            record.ok_or_else(|| Box::new(eliot_agent_bridge_core::BridgeError::NotAttached))?;
        binding_view(retained)
    }

    /// Borrows the retained external-attach reconciliation receipt, if any.
    ///
    /// `None` means no external agent has attached: not "reconciled", and never
    /// a synthesized read-only or attributed disposition.
    #[must_use]
    pub fn external_attach_reconciliation(&self) -> Option<&ExternalAttachReconciliationReceipt> {
        self.external_attach
            .as_deref()
            .map(|record| &record.receipt)
    }

    /// Admits one requested effect against the retained external-attach
    /// disposition (issue #1782, I11.11 line 42).
    ///
    /// I11.11 line 42: "Any request to continue Material work before that
    /// disposition returns `EXTERNAL_ATTACH_RECONCILIATION_REQUIRED`." I14.24
    /// line 23: "read-only inspection and unrelated tasks continue". A
    /// non-Material effect is therefore always admitted, and a Material effect
    /// is admitted only when the retained record reached an attributed
    /// continuation. Before that disposition gate, applicability is rechecked
    /// against the live owners: the live Governor fence must still equal the
    /// admitted fence and the live owner session must still equal the
    /// recorded one, so workspace movement, source/task revision drift,
    /// logout, or session replacement invalidates dependent use with a
    /// typed stale-authority refusal instead of silently continuing.
    ///
    /// Live callers: the `eliot.finish` claim path through
    /// [`serve_finish_claim`](crate::serve_finish_claim), which the daemon
    /// runtime drives, and [`Self::commit_canonical_and_refresh`].
    ///
    /// # Errors
    ///
    /// Returns [`eliot_agent_bridge_core::BridgeError::InvalidContract`] when
    /// the retained receipt does not validate,
    /// [`eliot_agent_bridge_core::BridgeError::StaleAuthority`] when the live
    /// fence or owner session no longer matches the retained record, and
    /// [`eliot_agent_bridge_core::BridgeError::ExternalAttachReconciliationRequired`]
    /// when a Material effect is requested before an attributed continuation.
    pub fn admit_material_continuation_after_attach(
        &self,
        effect: eliot_workscope::RequestedEffect,
    ) -> Result<(), Box<eliot_agent_bridge_core::BridgeError>> {
        let live_fence = self.governor.kernel_snapshot().state_fence();
        let live_session = self
            .owner_session
            .as_ref()
            .map(|facts| facts.session_binding().to_owned());
        admit_material_continuation_for_record(
            effect,
            self.external_attach.as_deref(),
            None,
            &live_fence,
            live_session.as_deref(),
        )
    }

    /// Admits one requested effect for a caller presenting its live Bridge
    /// binding (issue #1782 audit repair).
    ///
    /// This is the same rechecking gate as
    /// [`Self::admit_material_continuation_after_attach`], plus the exact
    /// presenting-binding match: the request/session/task/fence binding the
    /// caller presents must equal the retained claim field for field,
    /// including direct calls that bypass the finish path. A stale or
    /// substituted binding fails closed with a typed stale-authority refusal
    /// and can never clear the gate.
    ///
    /// # Errors
    ///
    /// Returns [`eliot_agent_bridge_core::BridgeError::InvalidContract`] for
    /// a malformed presenting binding or a retained receipt that does not
    /// validate, [`eliot_agent_bridge_core::BridgeError::StaleAuthority`]
    /// for a stale or substituted binding, fence, or session, and
    /// [`eliot_agent_bridge_core::BridgeError::ExternalAttachReconciliationRequired`]
    /// when a Material effect is requested before an attributed continuation.
    pub fn admit_material_continuation_for_attach(
        &self,
        effect: eliot_workscope::RequestedEffect,
        binding: &eliot_agent_bridge_core::AttachBinding,
        request: &eliot_agent_bridge_core::AttachRequest,
    ) -> Result<(), Box<eliot_agent_bridge_core::BridgeError>> {
        let presenting = claim_bridge_attach(binding, request)?;
        let live_fence = self.governor.kernel_snapshot().state_fence();
        let live_session = self
            .owner_session
            .as_ref()
            .map(|facts| facts.session_binding().to_owned());
        admit_material_continuation_for_record(
            effect,
            self.external_attach.as_deref(),
            Some(&presenting),
            &live_fence,
            live_session.as_deref(),
        )
    }

    /// Borrows the Governor reconstruction read composition over the retained
    /// owners plus daemon-held Kernel and read clients (T11.3).
    ///
    /// Mirrors [`Self::epistemic_composition`]: readiness is checked first,
    /// then the exact admitted fence is snapshotted from the retained Kernel
    /// client, and a fresh [`ReconstructionReadComposition`] is borrowed over
    /// the caller-held [`DaemonKernelClient`] and [`KernelContextReadClient`]
    /// with the task-bound scope. The composition retains no client and no
    /// thread — the caller (the single daemon runtime holding both the
    /// concrete client and this composition, as with
    /// [`Self::note_owner_session_binding`]) passes the already-connected
    /// clients per call, so a Governor refresh surfaces as an exact fence
    /// mismatch instead of silent divergence. No `composition.rs` change is
    /// involved: this uses only the retained snapshot fence plus the two
    /// borrowed clients.
    ///
    /// Wiring decision (mirroring `context_read_client` §4.1): post-`start`
    /// attach-style accessor, not a `start()` signature change — `start()`
    /// keeps its exact `(config, kernel: Arc<dyn KernelGenerationPort>,
    /// authority_activation)` contour.
    pub fn reconstruction_composition<'a>(
        &'a self,
        kernel: &'a Arc<DaemonKernelClient>,
        reads: &'a KernelContextReadClient,
        scope: eliot_store_api::ScopeId,
    ) -> Result<
        ReconstructionReadComposition<'a, DaemonKernelClient, KernelContextReadClient>,
        DaemonError,
    > {
        if self.readiness() != eliot_governor::CompositionReadiness::Ready {
            return Err(DaemonError::Composition(
                eliot_governor::CompositionError::NotReady,
            ));
        }
        let admitted_fence = kernel.snapshot().state_fence();
        Ok(ReconstructionReadComposition::borrow(
            kernel.as_ref(),
            reads,
            admitted_fence,
            scope,
        ))
    }

    /// Stops the one daemon owner and releases protected handles together.
    pub fn shutdown(mut self) -> Result<(), DaemonError> {
        if !self.started {
            return Err(DaemonError::Lifecycle(
                "daemon shutdown was already completed".to_owned(),
            ));
        }
        self.governor.stop();
        self.started = false;
        let _ = (&self.config_lease, &self.state_lease);
        Ok(())
    }
}

fn activation_deadline_expired(now: u64, deadline: u64) -> bool {
    now >= deadline
}

/// Falls back to a typed `FailedInternal` terminal result when the
/// Governor→protocol mapping rejects a classified outcome (#202).
///
/// A mapping rejection means the Governor classified the ticket but the data
/// cannot bind it (e.g. a `NotReady` window at or past the Kernel deadline).
/// Killing the daemon loop would leave the ticket unanswered; answering with
/// `FailedInternal` keeps the failure terminal for the ticket revision and
/// the daemon alive for the next claim. The original mapping error is
/// preserved as diagnostics evidence when the fallback binds. If the fallback
/// itself cannot bind, the original mapping error returns unchanged: fail
/// closed, never silence.
fn failed_internal_or_mapping_error(
    ticket: &AgentActivationResolutionTicket,
    outcome_kind: &str,
    resolved_at_unix_ms: u64,
    successor_observation: Option<(u64, String)>,
    error: DaemonError,
) -> Result<AgentActivationResolutionResult, DaemonError> {
    match activation_projection::failed_internal_for_mapping_failure_with_observation(
        ticket,
        outcome_kind,
        resolved_at_unix_ms,
        successor_observation,
    ) {
        Ok(result) => {
            let _ = crate::diagnostics::ErrorRecord::of_daemon_error(&error).emit();
            Ok(result)
        }
        Err(_) => Err(error),
    }
}

/// Answers one already validated ticket for an unready Governor with the typed
/// `FailedInternal` terminal result.
///
/// #204: an unready Governor is an internal failure for this exact ticket, not
/// a loop-fatal error. The typed result keeps the disposition distinct from
/// every other negative and from the result-less deadline outcome, and the
/// daemon stays alive for the next claim. The ticket is validated before this
/// seam is reached, so the fallback binds; if it cannot bind, the original
/// readiness error returns unchanged: fail closed, never silence.
fn unready_governor_activation_result(
    ticket: &AgentActivationResolutionTicket,
    now: u64,
    successor_observation: Option<(u64, String)>,
) -> Result<AgentActivationResolutionResult, DaemonError> {
    let unready = DaemonError::Lifecycle(
        "semantic activation resolution requires a ready Governor".to_owned(),
    );
    match activation_projection::failed_internal_for_unready_governor_with_observation(
        ticket,
        now.max(1),
        successor_observation,
    ) {
        Ok(result) => {
            let _ = crate::diagnostics::ErrorRecord::of_daemon_error(&unready).emit();
            Ok(result)
        }
        Err(_) => Err(unready),
    }
}

/// Maps one Governor outcome to the wire v2 result under the exact successor
/// observation captured before the readiness gate.
///
/// The observation is taken from the same coherent Governor read as the
/// outcome, so a successor claim is only published when the owner and
/// dependency revisions really moved.
fn map_governor_outcome_under_observation(
    ticket: &AgentActivationResolutionTicket,
    outcome: GovernorActivationOutcome,
    now: u64,
    successor_observation: Option<&(u64, String)>,
) -> Result<AgentActivationResolutionResult, DaemonError> {
    match successor_observation {
        Some((owner_revision, dependency_revision)) => {
            activation_projection::map_governor_outcome_to_protocol_for_successor(
                ticket,
                outcome,
                now,
                *owner_revision,
                dependency_revision.clone(),
            )
        }
        None => activation_projection::map_governor_outcome_to_protocol(ticket, outcome, now),
    }
}

/// Emits the one admission or error record that every v2 resolution terminal
/// shares, so a typed success, a typed rejection and a fallback all report
/// through the same diagnostics seam.
fn emit_activation_admission_diagnostics(
    ticket: &AgentActivationResolutionTicket,
    outcome: &Result<AgentActivationResolutionResult, DaemonError>,
) {
    match outcome {
        Ok(result) => {
            let _ = crate::diagnostics::AdmissionRecord::of(
                crate::diagnostics::disposition_of_resolution(&result.disposition),
                &ticket.ticket_id,
                &result.result_sha256,
            )
            .emit();
        }
        Err(error) => {
            let _ = crate::diagnostics::ErrorRecord::of_daemon_error(error).emit();
        }
    }
}

impl AgentActivationResolver for DaemonComposition {
    fn resolve_agent_activation_v2(
        &self,
        ticket: &AgentActivationResolutionTicket,
        now: u64,
    ) -> Result<AgentActivationResolutionResult, DaemonError> {
        DaemonComposition::resolve_agent_activation_v2(self, ticket, now)
    }
}

#[cfg(test)]
mod tests;
