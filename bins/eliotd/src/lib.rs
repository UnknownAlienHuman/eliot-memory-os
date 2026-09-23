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

use eliot_agent_api::{
    AdmittedRouteReceipt, AgentResult, EffectCeiling, ProviderExecutionBinding, ResultDisposition,
};
use eliot_contracts::{EpochId, OperationId, ResourceGeneration, StateFence};
use eliot_governor::{
    CompositionError, CompositionReadiness, FinishAttemptDraft, FinishAttemptError,
    FinishDecisionReceipt, GovernorActivationOutcome, GovernorComposition, GovernorLaunchConfig,
    KernelGenerationPort, KernelGenerationSnapshotProvider, QueueLimits,
};
use eliot_kernel_core::Notification;
use eliot_platform_windows::{ProtectedPathError, ProtectedRuntimePathLease};
use eliot_protocol::{
    AgentActivationResolutionDecision, AgentActivationResolutionResult,
    AgentActivationResolutionTicket,
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
pub mod canonical_config_precedence;
mod capability_admission;
mod capability_evidence_wiring;
pub mod capability_outcome;
mod controlboard_adapters;
mod daemon_config;
mod daemon_kernel_client;
mod daemon_kernel_port_adapters;
pub mod diagnostics;
mod dreamer_admission;
mod dreamer_materials;
mod dreamer_model_adapter;
mod experience_runtime;
mod first_run_wiring;
mod freshness_admission;
mod governor_local_read;
mod kernel_authority_client;
mod kernel_context_read_client;
mod kernel_recovery_client;
mod kernel_transition_client;
pub mod notification_board_attach;
mod observation_adapters;
mod owner_feed;
mod process_origin;
mod reactive_feed;
mod route_receipts;
mod skill_bridge_adapter;
pub mod skill_dispatch;
mod skill_lifecycle_adapters;
mod skill_surface_adapters;
pub mod staffing_policy;
pub mod startup_evidence_producer;
mod store_failure_projection;
pub mod testd_terminal_completion;
pub mod task_binding_admission;
mod task_lifecycle_adapters;

pub use activation_projection::AgentActivationResolver;
pub use activation_projection::{
    ActivationClaim, classify_claimed_ticket_value, terminal_for_invalid_ticket,
};
pub use agent_fabric::{
    ActivationAuthorityPort, ActivationEvidence, AdmissionAuthorityPort, AgentFabric,
    AgentFabricDescriptor, AttemptLifecycle, AttemptResultRecord, COORDINATOR_CRATE,
    CancellationLifecycle, DAEMON_CRATE, DispatchAck, DispatchEgressPort, DispatchIntent,
    FABRIC_CAPACITY_IDENTITY, FABRIC_CAPACITY_REVISION, FABRIC_PLAN_GAP_REASON, FabricAdmission,
    FabricError, FabricPorts, FabricSnapshot, LedgerEntry, ModelRegistryPort, PREREQ_PORTS,
    PeerChannelPort, PeerMessage, PeerReceipt, Reservation, RouteRequirements, SwarmControlPort,
    SwarmDefinition, SwarmEntryReceipt, WorkerAck, daemon_coordinator_config, plan_candidate,
    prereq_ports,
};

use controlboard_adapters::SharedOperatorReplay;

#[cfg(test)]
use activation_projection::map_activation_snapshot;

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
    EvidenceBridgeError, GovernorCapabilityAdmission, ObservedLifecycleSummary,
};
pub use capability_outcome::{
    AttemptReceipt, CapabilityOutcome, CapabilityRegistryView, DegradationScope,
    FallbackOutcomeRequest, OutcomeDisposition, OutcomeError, fallback_outcome,
};
pub use daemon_config::DaemonConfig;
pub(crate) use daemon_kernel_client::kernel_port_error;
pub use daemon_kernel_client::{DaemonKernelClient, LocalReadSubmitOutcome, OwnerSessionFacts};
#[cfg(test)]
pub(crate) use daemon_kernel_client::{KernelClientError, WireOutcome, operation_payload};
#[cfg(all(test, windows))]
pub(crate) use daemon_kernel_client::{
    is_pre_admission_pending_rejection, retry_pre_admission, validate_server_hello,
};
pub use daemon_kernel_client::{parse_local_read_claimed_pair, parse_local_read_submit_outcome};
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
pub use first_run_wiring::{
    DisabledAutomationOutcome, FirstRunWiringError, inspect_first_run_defaults,
    recommend_for_disabled_automation, resolve_first_run_routes,
};
pub use freshness_admission::{
    CANDIDATE_COMMITTED_PROJECTION_PENDING, CandidateFetchOutcome, CommittedCandidate,
    FreshnessAdmission, FreshnessDisposition, FreshnessError, FreshnessEvaluation,
    ProjectionPublicationRecord, ProjectionPublicationStatus, ProvenanceStanding, PublicationMode,
    RequestedEffect, ReusableCandidateView, RevisionHead, TaskCompatibility,
    evaluate_freshness_admission, fetch_committed_candidate, normalize_heads,
};
pub use governor_local_read::{
    answer_evidence_query, answer_projection_inputs, forward_admitted_local_read,
    serve_admitted_local_read,
};
pub use experience_runtime::{
    CommonGroundEventInputs, ExperienceCommitOutput, ExperienceDriverError,
    ExperienceJournalDriverInputs, ExperienceQualityEvent, ExperienceQualityEventOutput,
    UnderstandingEventInputs, commit_experience_event_records, derive_commit_ingress,
    produce_journal_projection, propose_memory_extinction_candidate, read_current_position,
    run_experience_quality_event, run_experience_quality_event_with_revision,
};
pub(crate) use kernel_authority_client::KernelAuthorityClient;
pub use kernel_context_read_client::{KernelContextReadClient, ReconstructionReadComposition};
pub use owner_feed::{KernelOwnerPublishPort, OwnerFeedTrigger, maintain_owner_feed};
pub use process_origin::{
    CapabilityEvidenceSource, Generation, OperationDisposition,
    OriginChallenge, OriginChallengeAuthority, OriginChallengeRequest, OriginControlGrant,
    OriginControlOperation, OriginControlPresentation, PROCESS_ORIGIN_CAPABILITY,
    PhysicalProcessBinding, ProcessCapabilityEvidence, ProcessControlOperation, ProcessOriginError,
    ProcessOriginEvidence, ProcessStatusReceipt, canonical_origin_digest, gate_process_control,
    request_origin_control,
};
pub use reactive_feed::{ReactiveFeedError, ReactiveFeedOutcome, drive_reactive_delivery_once};
pub use route_receipts::{
    ActualRouteReceipt, GovernorRouteAttempt, RouteCapabilityIndex, RouteReceiptError,
    RuntimeObservedFacts, UNKNOWN_ROUTE_FACT, effective_route_key,
};
pub(crate) use skill_lifecycle_adapters::SkillHotsetRequest;
pub use startup_evidence_producer::{
    DAEMON_STARTUP_EVIDENCE_OPERATION, EliotdStartupEvidence, MAX_CAPABILITY_OUTCOMES,
    MAX_EVIDENCE_REFS, MAX_REQUIRED_CAPABILITIES, MirrorObservation, RetainedCapabilitySummary,
    StartupEvidenceError, StartupEvidenceRequest, build_startup_evidence,
    publish_daemon_startup_evidence, summarize_retained_capabilities,
};
pub use store_failure_projection::{GovernorStoreFailureProjection, GovernorStoreProjectionError};

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
    /// A second daemon owner cannot be admitted in this process.
    #[error("daemon lifecycle: {0}")]
    Lifecycle(String),
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
    /// call while the process lives. Durable operator identity lives in
    /// Kernel ORS through the async Governor operator borrow; post-commit
    /// refreshes retain this handle without ever clearing it.
    operator_replay: SharedOperatorReplay,
    /// Set when a post-commit refresh fails after the write receipt was
    /// already durable. The dependent view is stale/pending until the caller
    /// drops this composition and re-runs authenticated connect+start.
    view_stale: bool,
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
        Ok(Self {
            governor,
            config_lease,
            state_lease,
            config_path: config.config_path,
            state_root: config.state_root,
            started: true,
            view_stale: false,
            committed_experience: BTreeMap::new(),
            operator_replay: SharedOperatorReplay::new(),
            owner_session: None,
            notification_snapshot: Vec::new(),
            skill_catalogue: Arc::new(
                std::sync::Mutex::new(eliot_skill::SkillCatalogue::default()),
            ),
            capability_admission: GovernorCapabilityAdmission::new(),
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
    ) -> Result<eliot_store_api::WriteReceipt, DaemonError> {
        // #740: request/result span over the neutral handoff boundary. The
        // handoff (prepared envelope submitted) and the commitment (validated
        // owner receipt) stay distinguishable in the sink.
        let _span = tracing::info_span!("eliotd.canonical_commit").entered();
        let receipt = self
            .governor
            .commit_canonical(identity, envelope)
            .await
            .map_err(DaemonError::Composition)?;
        if self.governor.refresh_from_kernel().is_err() {
            self.view_stale = true;
        }
        Ok(receipt)
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

    /// Submits one candidate finish through the Governor owner, commits the
    /// derived decision through the canonical `RecordFinishDecision` path,
    /// and rehydrates the daemon projection before returning the decision
    /// receipt. The caller supplies only a candidate draft; task completion,
    /// evidence binding, and persistence remain Governor/Canonical-owned.
    ///
    /// A committed receipt is preserved when the post-commit refresh cannot
    /// publish the new projection. In that case the daemon is marked stale,
    /// matching [`Self::commit_canonical_and_refresh`], and the receipt still
    /// reports the durable operation rather than a false failure.
    pub async fn finish_attempt(
        &mut self,
        identity: &eliot_protocol::RequestIdentity,
        operation_id: OperationId,
        draft: FinishAttemptDraft,
    ) -> Result<FinishDecisionReceipt, DaemonError> {
        let _span = tracing::info_span!("eliotd.finish_attempt").entered();
        let decision = self
            .governor
            .finish_attempt(identity, operation_id, draft)
            .await
            .map_err(DaemonError::Finish)?;
        if self.governor.refresh_from_kernel().is_err() {
            self.view_stale = true;
        }
        Ok(decision)
    }

    /// Submits a validated API v7 candidate result to the Governor Finish owner.
    ///
    /// API v7 is candidate-only: this adapter validates the result against its
    /// admitted route and execution binding, then copies only candidate handles
    /// and declared unknowns into a [`FinishAttemptDraft`].  It never copies a
    /// provider disposition into a completion decision, supplies no proof, and
    /// does not close the task; [`Self::finish_attempt`] rehydrates canonical
    /// evidence and lets the Governor derive and persist the outcome.
    pub async fn finish_agent_api_v7_result(
        &mut self,
        identity: &eliot_protocol::RequestIdentity,
        operation_id: OperationId,
        task_id: String,
        expected_task_revision: u64,
        result: &AgentResult,
        binding: &ProviderExecutionBinding,
        admission: &AdmittedRouteReceipt,
        effect_ceiling: &EffectCeiling,
    ) -> Result<FinishDecisionReceipt, DaemonError> {
        result
            .validate_for_binding(binding, admission, effect_ceiling)
            .map_err(|error| {
                DaemonError::Lifecycle(format!(
                    "API v7 candidate result is not bound to the admitted execution: {error}"
                ))
            })?;
        let draft = finish_draft_from_agent_api_v7(task_id, expected_task_revision, result);
        self.finish_attempt(identity, operation_id, draft).await
    }

    /// Returns the admitted Kernel snapshot.
    #[must_use]
    pub fn kernel_snapshot(&self) -> &eliot_governor::KernelGenerationSnapshot {
        self.governor.kernel_snapshot()
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

    /// v1 compatibility projection: resolves one Kernel-issued semantic ticket
    /// to the legacy decision shape through the sole Governor.
    ///
    /// v1-compat only. This method must not consume v2 typed-result data;
    /// `resolve_agent_activation_v2` is the single production resolver spine.
    /// Behavior is preserved (only `Resolved` maps; every other outcome is an
    /// error, never coerced to success) so existing compatibility consumers keep
    /// working. The runtime production path already resolves through v2 (the
    /// `daemon_runtime` claim arm); this v1 method has no production caller.
    ///
    /// Final v1 retirement is tracked by #66 (#204 removes the success-only
    /// compatibility path after the complete migration passes); this method is
    /// not removed as opportunistic cleanup.
    ///
    /// The Governor typed outcome is the sole discriminator: only `Resolved`
    /// produces a decision. Every other outcome is surfaced as an error and is
    /// never coerced to success.
    pub fn resolve_agent_activation(
        &self,
        ticket: &AgentActivationResolutionTicket,
        now: u64,
    ) -> Result<AgentActivationResolutionDecision, DaemonError> {
        ticket
            .validate()
            .map_err(|error| DaemonError::Lifecycle(error.to_string()))?;
        if self.readiness() != CompositionReadiness::Ready {
            return Err(DaemonError::Lifecycle(
                "semantic activation resolution requires a ready Governor".to_owned(),
            ));
        }
        if activation_deadline_expired(now, ticket.kernel_deadline_unix_ms) {
            return Err(DaemonError::Lifecycle(
                "semantic activation ticket deadline has expired".to_owned(),
            ));
        }
        match self.governor.resolve_activation_outcome(now) {
            GovernorActivationOutcome::Resolved(snapshot) => {
                if snapshot.state_fence != ticket.state_fence {
                    return Err(DaemonError::Lifecycle(
                        "semantic activation ticket fence does not match the Governor snapshot"
                            .to_owned(),
                    ));
                }
                activation_projection::map_activation_snapshot(ticket, snapshot)
            }
            outcome => Err(DaemonError::Lifecycle(format!(
                "semantic activation did not resolve: {}",
                outcome.kind_str()
            ))),
        }
    }

    /// Single production resolver spine: resolves one Kernel-issued semantic
    /// ticket to the canonical v2 typed result. Every
    /// `GovernorActivationOutcome` variant maps 1:1 to its
    /// protocol disposition without coercion to success.
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
        if self.readiness() != CompositionReadiness::Ready {
            // #204: an unready Governor is an internal failure for this exact
            // ticket, not a loop-fatal error. Answer with a typed
            // FailedInternal terminal result so the Kernel records a
            // disposition that stays distinct from every other negative and
            // from the result-less deadline outcome, and the daemon stays
            // alive for the next claim. The ticket is already validated
            // above, so the fallback binds; if it cannot bind, the original
            // readiness error returns unchanged: fail closed, never silence.
            let unready = DaemonError::Lifecycle(
                "semantic activation resolution requires a ready Governor".to_owned(),
            );
            return match activation_projection::failed_internal_for_unready_governor(
                ticket,
                now.max(1),
            ) {
                Ok(result) => {
                    let _ = crate::diagnostics::ErrorRecord::of_daemon_error(&unready).emit();
                    Ok(result)
                }
                Err(_) => Err(unready),
            };
        }
        if activation_deadline_expired(now, ticket.kernel_deadline_unix_ms) {
            return Err(DaemonError::Lifecycle(
                "semantic activation ticket deadline has expired".to_owned(),
            ));
        }
        let outcome = match self.governor.resolve_activation_outcome(now) {
            GovernorActivationOutcome::Resolved(snapshot) => {
                if snapshot.state_fence == ticket.state_fence {
                    match activation_projection::map_governor_outcome_to_protocol(
                        ticket,
                        GovernorActivationOutcome::Resolved(snapshot),
                        now.max(1),
                    ) {
                        Ok(result) => Ok(result),
                        Err(error) => {
                            failed_internal_or_mapping_error(ticket, "RESOLVED", now.max(1), error)
                        }
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
                    activation_projection::stale_fence_for_resolved_mismatch(
                        ticket,
                        observed,
                        now.max(1),
                    )
                }
            }
            outcome => {
                let kind = outcome.kind_str();
                match activation_projection::map_governor_outcome_to_protocol(
                    ticket,
                    outcome,
                    now.max(1),
                ) {
                    Ok(result) => Ok(result),
                    Err(error) => failed_internal_or_mapping_error(ticket, kind, now.max(1), error),
                }
            }
        };
        match &outcome {
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
        outcome
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

    /// Builds one provider-neutral `ControlBoard` over the current Governor
    /// projection snapshot.
    ///
    /// The board reads one immutable snapshot taken here; every port call in
    /// the returned value observes the same revision and fence. Callers take
    /// a fresh board per operation so a Governor refresh surfaces as an
    /// exact-view mismatch instead of silent divergence. The board shares the
    /// retained volatile replay handle, so a newly created board replays an
    /// already-admitted operation instead of admitting it twice; durable
    /// operator identity stays in Kernel ORS through the async Governor
    /// operator borrow. Access resolution admits exactly the one live
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

    /// Installs one canonical package source into the shared Governor Skill
    /// catalogue (population caller, issue #1882).
    ///
    /// Composition seam for the runtime population driver: the Governor
    /// owner hands over a validated package claim, its actual materialization
    /// inputs, the explicit install context, and the tool-owner view; the
    /// shared handle records the projected entry. No readiness gate: this
    /// operates purely on daemon-held catalogue state (validated insert),
    /// never on Governor recovery owners; promotion keeps the Governor
    /// canonical gates, and drivers call post-admission. Returns the
    /// installed Skill identity.
    pub fn skill_install_package(
        &self,
        package: &eliot_skill::SkillPackage,
        inputs: &eliot_skill::MaterializationInputs,
        context: &eliot_skill::CatalogueInstallContext,
        tools: &dyn eliot_skill::KnownTools,
    ) -> Result<String, eliot_skill::SkillError> {
        self.shared_skill_adapter()
            .install_package(package, inputs, context, tools)
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
    /// closed before the shared handle is touched. The Skill never hardcodes
    /// the version; the composition never invents a registry. Drivers call
    /// post-admission with the injector's real inputs.
    pub fn skill_install_package_versioned(
        &self,
        package: &eliot_skill::SkillPackage,
        inputs: &eliot_skill::MaterializationInputs,
        context: &eliot_skill::CatalogueInstallContext,
        source: &dyn eliot_skill::CanonicalToolSource,
        aliases: &eliot_skill::ToolAliasTable,
        admitted_definition_version: &str,
    ) -> Result<String, eliot_skill::SkillError> {
        self.shared_skill_adapter().install_package_versioned(
            package,
            inputs,
            context,
            source,
            aliases,
            admitted_definition_version,
        )
    }

    /// Runs versioned install, availability and sealed gates, and Hotset
    /// receipt issuance as one runtime delivery act (issue #1882).
    ///
    /// Same seam discipline as [`Self::skill_install_package`]: the driver
    /// supplies the real package, inputs, context, provider readiness and
    /// materialization scope, versioned tool source plus alias table and
    /// admitted version, Hotset identity, and injector approval in one
    /// [`VersionedDeliveryAct`](skill_lifecycle_adapters::VersionedDeliveryAct);
    /// the shared handle records the act. The composition observes the live
    /// admitted Governor fence itself and the act's scope fence must equal
    /// it: a Governor refresh crossing the drive fails closed before any
    /// catalogue write or receipt mint. The receipt carries the provisional
    /// ceiling until evidence promotion; the receiver ack re-enters through
    /// [`Self::skill_acknowledge_and_display`].
    pub fn skill_run_install_to_receipt(
        &self,
        act: skill_lifecycle_adapters::VersionedDeliveryAct<'_>,
    ) -> Result<(String, eliot_skill::HotsetDeliveryReceipt), eliot_skill::SkillError> {
        let admitted = self.governor.kernel_snapshot().state_fence().clone();
        self.shared_skill_adapter()
            .run_install_to_receipt(act, &admitted)
    }

    /// Runs the Hotset injector call end to end through the composed
    /// delivery act (issue #1882).
    ///
    /// Production injector entry the Hotset transport lane calls with one
    /// injector-carried [`SkillHotsetRequest`](skill_lifecycle_adapters::SkillHotsetRequest):
    /// package, inputs, Governor-owned install context, provider readiness,
    /// scope identities, Hotset identity, and injector approval — no
    /// literals, no defaults. The composition observes the live terms
    /// itself: the canonical tool source plus admitted definition version
    /// from the Governor hook
    /// ([`eliot_governor::canonical_skill_tool_source`]), the default-empty
    /// Skill-owned alias table (the frozen H-A composition call site), and
    /// the live admitted Governor fence. Returns the installed identity
    /// plus the receipt the injector carries to the receiver; the receiver
    /// ack re-enters through [`Self::skill_carry_receipt_to_display`].
    pub fn skill_inject_hotset(
        &self,
        request: skill_lifecycle_adapters::SkillHotsetRequest<'_>,
    ) -> Result<(String, eliot_skill::HotsetDeliveryReceipt), eliot_skill::SkillError> {
        let (source, admitted_version) = eliot_governor::canonical_skill_tool_source()?;
        let aliases = eliot_skill::ToolAliasTable::new();
        let fence = self.governor.kernel_snapshot().state_fence().clone();
        self.shared_skill_adapter().inject_hotset(
            request,
            source.as_ref(),
            &aliases,
            &admitted_version,
            &fence,
        )
    }

    /// Drives one wire intake through the injector call end to end (issue
    /// #1882).
    ///
    /// Daemon-side handler for Hotset intake bytes arriving over the
    /// transport: decodes the
    /// [`SkillIntakePayload`](eliot_agent_bridge_core::SkillIntakePayload)
    /// (decode failures map to a surface contract error), observes the live
    /// canonical source, default alias table, and admitted fence, and drives
    /// the composed delivery act with the admitted version read from the
    /// payload's install context. Every delivery gate below runs unchanged.
    /// Returns the installed identity plus the receipt the injector carries
    /// to the receiver.
    pub fn skill_ingest_wire_intake(
        &self,
        bytes: &[u8],
    ) -> Result<(String, eliot_skill::HotsetDeliveryReceipt), eliot_skill::SkillError> {
        let payload = eliot_agent_bridge_core::SkillIntakePayload::decode(bytes)
            .map_err(|error| eliot_skill::SkillError::Surface(error.to_string()))?;
        let (source, _) = eliot_governor::canonical_skill_tool_source()?;
        let aliases = eliot_skill::ToolAliasTable::new();
        let fence = self.governor.kernel_snapshot().state_fence().clone();
        self.shared_skill_adapter()
            .ingest_wire_intake(payload, source.as_ref(), &aliases, &fence)
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
    /// and returns only typed results. No policy, admission, or semantic
    /// rules live here; a duplicate, stale revision, stale fence, or illegal
    /// transition fails closed in the Governor owner. Publication happens
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

fn finish_draft_from_agent_api_v7(
    task_id: String,
    expected_task_revision: u64,
    result: &AgentResult,
) -> FinishAttemptDraft {
    let mut remaining_unknowns_declared_by_caller = result.unresolved_questions.clone();
    if let Some(reason) = &result.unknown_reason {
        remaining_unknowns_declared_by_caller.push(reason.clone());
    }
    FinishAttemptDraft {
        task_id,
        expected_task_revision,
        requested_outcome: match result.disposition {
            ResultDisposition::CandidateSucceeded => {
                eliot_governor::RequestedFinishOutcome::CompleteCandidate
            }
            ResultDisposition::Partial => eliot_governor::RequestedFinishOutcome::Partial,
            ResultDisposition::Blocked => eliot_governor::RequestedFinishOutcome::Blocked,
            ResultDisposition::FailedVerification => {
                eliot_governor::RequestedFinishOutcome::FailedVerification
            }
            ResultDisposition::DegradedNoProof | ResultDisposition::UnknownOutcome => {
                eliot_governor::RequestedFinishOutcome::DegradedNoProof
            }
            ResultDisposition::Unsafe => eliot_governor::RequestedFinishOutcome::UnsafeToFinish,
            ResultDisposition::CancelledObserved => {
                eliot_governor::RequestedFinishOutcome::Cancelled
            }
            ResultDisposition::Superseded => eliot_governor::RequestedFinishOutcome::Superseded,
        },
        artifact_refs: result.artifacts.iter().map(ToString::to_string).collect(),
        observation_refs: result.evidence_refs.clone(),
        // Verifier ownership remains in the canonical evidence projection;
        // an API v7 candidate result cannot assert a verifier run.
        verifier_run_refs: Vec::new(),
        remaining_unknowns_declared_by_caller,
        rationale_candidate: format!("api-v7-candidate:{}", result.attempt_id.as_str()),
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
    error: DaemonError,
) -> Result<AgentActivationResolutionResult, DaemonError> {
    match activation_projection::failed_internal_for_mapping_failure(
        ticket,
        outcome_kind,
        resolved_at_unix_ms,
    ) {
        Ok(result) => {
            let _ = crate::diagnostics::ErrorRecord::of_daemon_error(&error).emit();
            Ok(result)
        }
        Err(_) => Err(error),
    }
}

impl AgentActivationResolver for DaemonComposition {
    fn resolve_agent_activation(
        &self,
        ticket: &AgentActivationResolutionTicket,
        now: u64,
    ) -> Result<AgentActivationResolutionDecision, DaemonError> {
        DaemonComposition::resolve_agent_activation(self, ticket, now)
    }

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
