//! Thin durable swarm-control composition for `eliotd` (issue #872).
//!
//! Architecture: I10.15 places deterministic planning plus Ready Queue admission
//! inside the daemon-owned [`AgentCoordinator`](eliot_agent_coordinator::AgentCoordinator);
//! this module is wiring, not a second scheduler, store, attempt journal,
//! authority source, or provider executor. It connects one admitted ingress
//! (`DaemonComposition::start` / `run_loop`) to exactly one injected
//! coordinator (definition validation, admission tracking, activation gating,
//! provider-neutral dispatch) and leaves every owner policy where it lives:
//! Task-Controller definitions, Governor admission, Kernel reservation and
//! activation, B-MOD route registry (#694), B-PEER coordination channel (#696),
//! and B-SWARM durable control (#698 / #839).
//!
//! The six injected ports are seams only. This module never reimplements route
//! ranking, peer delivery, swarm entry, reservation, admission, or activation;
//! each seam records its call in the daemon-owned call ledger so the 28-case
//! wiring proof can assert exact call order without inventing authority. Where
//! a prerequisite owner port has no accepted revision on this base (prereqs
//! #694 / #696 / #698 / #839 / #837 remain OPEN), the fabric stays generic
//! over the injected port and the inventory case freezes the missing-port
//! expectation as a `ContractChallenge` residual instead of a local substitute.

use std::collections::BTreeMap;
use std::sync::Arc;

use eliot_agent_api::{AttemptId, RouteFingerprint};
use eliot_agent_contracts::RevisionId;
use eliot_agent_coordinator::{
    AdmissionId, AgentCoordinator, CandidateId, CoordinatorConfig, CoordinatorError,
    CoordinatorSnapshot, PlanGap, StaffingPlanCandidate, StaffingPlanRequest,
};
use eliot_contracts::{EpochId, StateFence, fences_match_exact};
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Crate that owns the coordinated execution projection.
pub const COORDINATOR_CRATE: &str = "eliot-agent-coordinator";
/// Daemon composition root that owns this wiring.
pub const DAEMON_CRATE: &str = "eliotd";
/// Explicit plan-only gap reason: candidate planning stays available while live
/// provider admission remains unavailable outside the sealed verifier path.
pub const FABRIC_PLAN_GAP_REASON: &str = "eliotd agent fabric plans candidates only; live provider admission arrives through the sealed owner path";
/// Capacity identity threaded by the daemon fabric composition.
pub const FABRIC_CAPACITY_IDENTITY: &str = "eliotd-fabric-capacity";
/// Capacity revision threaded by the daemon fabric composition.
pub const FABRIC_CAPACITY_REVISION: &str = "fabric-capacity-rev-1";
/// Prerequisite owner ports consumed read-only at accepted seams. All remain
/// OPEN on the base revision; the fabric injects them and never reimplements
/// them. See case 1 inventory.
pub const PREREQ_PORTS: [&str; 5] = [
    "B-MOD #694 model registry",
    "B-PEER #696 coordination channel",
    "B-SWARM #698 durable swarm control",
    "B-ACTIVATION-PROJECTION #839 activation projection",
    "D-WU-FINAL #837 assignment gate",
];

/// Returns the prerequisite owner ports consumed read-only at accepted seams.
#[must_use]
pub fn prereq_ports() -> Vec<String> {
    PREREQ_PORTS.iter().map(|port| (*port).to_owned()).collect()
}

fn validate_text(value: &str, _field: &'static str) -> Result<(), FabricError> {
    if value.trim().is_empty() || value.chars().any(char::is_control) {
        return Err(FabricError::Contract(
            "blank or control-bearing text".to_owned(),
        ));
    }
    Ok(())
}

fn digest_json<T: Serialize>(value: &T) -> Result<String, FabricError> {
    let bytes = eliot_contracts::canonical_json_bytes(value)
        .map_err(|error| FabricError::Contract(format!("canonical bytes: {error}")))?;
    Ok(eliot_contracts::sha256_hex(&bytes))
}

/// Deterministic daemon coordinator configuration for this composition.
///
/// # Errors
///
/// Returns [`FabricError::Contract`] when the static capacity revision is
/// rejected by its owner.
pub fn daemon_coordinator_config() -> Result<CoordinatorConfig, FabricError> {
    let capacity_revision = RevisionId::new(FABRIC_CAPACITY_REVISION)
        .map_err(|error| FabricError::Contract(format!("fabric capacity revision: {error}")))?;
    Ok(CoordinatorConfig {
        max_ready_items: 32,
        max_admitted_attempts: 8,
        max_active_per_route: 4,
        capacity_identity: FABRIC_CAPACITY_IDENTITY.to_owned(),
        capacity_revision,
    })
}

/// Plans one candidate through the real coordinator owner.
///
/// Load-bearing order is preserved here: the caller supplies an already-frozen
/// Task-Controller request and this function only compiles the deterministic
/// candidate via [`AgentCoordinator::plan`]. No admission, reservation,
/// attempt, or dispatch occurs here.
pub fn plan_candidate(
    config: &CoordinatorConfig,
    request: StaffingPlanRequest,
) -> Result<StaffingPlanCandidate, FabricError> {
    // #740: candidate-planning span over the existing #872 control path.
    // Planning compiles a candidate only; admission happens exclusively
    // through the staged reservation + committed admission below.
    let _span = tracing::info_span!(
        "eliotd.fabric_plan_candidate",
        candidate = %crate::diagnostics::sanitize_identity(request.candidate_id.as_str())
    )
    .entered();
    let mut coordinator = AgentCoordinator::new(
        config.clone(),
        PlanGap::G11Unavailable {
            reason: FABRIC_PLAN_GAP_REASON.to_owned(),
        },
    )?;
    Ok(coordinator.plan(request)?)
}

/// Frozen Task-Controller definition as accepted at the admitted boundary.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SwarmDefinition {
    /// Candidate identity minted by the Task Controller owner.
    pub definition_id: CandidateId,
    /// Digest of the exact frozen request bytes.
    pub definition_digest: String,
    /// I14.1 work class carried verbatim from the admitted request (issue
    /// #1698). Bound into every reservation, admission and dispatch built
    /// from this definition; never defaulted.
    pub work_class: String,
    /// Task identity preserved verbatim.
    pub task_id: String,
    /// Task revision preserved verbatim.
    pub task_revision: String,
    /// Plan revision preserved verbatim.
    pub plan_revision: String,
    /// Admitted fence preserved verbatim.
    pub fence: StateFence,
}

/// Kernel-staged inactive reservation for the exact definition.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Reservation {
    /// Reservation identity minted by the Kernel owner.
    pub reservation_id: String,
    /// Definition this reservation stages.
    pub definition_id: CandidateId,
    /// Digest of the staged definition; must equal the frozen digest.
    pub definition_digest: String,
    /// I14.1 work class echoed from the staged definition (issue #1698);
    /// the fabric rejects a reservation that does not bind the exact class.
    pub work_class: String,
    /// Fence at staging time.
    pub fence: StateFence,
}

/// Governor canonical admission referencing the staged reservation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FabricAdmission {
    /// Admission identity minted by the Governor owner.
    pub admission_id: AdmissionId,
    /// Admitted definition identity.
    pub definition_id: CandidateId,
    /// Exact frozen definition digest bound by this admission.
    pub definition_digest: String,
    /// I14.1 work class bound by this admission (issue #1698); echoes the
    /// staged reservation and frozen definition exactly.
    pub work_class: String,
    /// Reservation identity this admission commits.
    pub reservation_id: String,
    /// Fence at admission time.
    pub fence: StateFence,
    /// Authority epoch at admission time.
    pub epoch: EpochId,
    /// Registered attempt identities for this admission.
    pub attempt_ids: Vec<AttemptId>,
}

/// Kernel activation evidence for one admitted attempt.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActivationEvidence {
    /// Activated admission identity.
    pub admission_id: AdmissionId,
    /// Activated attempt identity.
    pub attempt_id: AttemptId,
    /// Digest binding the admission plus the Kernel activation receipt.
    pub activation_digest: String,
    /// Fence at activation time; must match admission exactly.
    pub fence: StateFence,
    /// Epoch at activation time; must match admission exactly.
    pub epoch: EpochId,
}

/// Provider-neutral externally dispatchable intent.
///
/// Carries the exact attempt plus activated launch evidence. It names no
/// provider SDK, process, credential, or effect commit; concrete execution
/// remains #874.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DispatchIntent {
    /// Dispatch operation identity minted by this composition.
    pub dispatch_id: String,
    /// Admitted admission identity.
    pub admission_id: AdmissionId,
    /// Registered attempt identity.
    pub attempt_id: AttemptId,
    /// I14.1 work class carried verbatim from the admission (issue #1698),
    /// so the dispatch record identifies the same class.
    pub work_class: String,
    /// Activated launch evidence digest.
    pub activation_digest: String,
    /// Fence carried verbatim from activation.
    pub fence: StateFence,
    /// Epoch carried verbatim from activation.
    pub epoch: EpochId,
}

/// Closed acknowledgement of an emitted dispatch intent. It advances no
/// attempt and decides no task Finish.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DispatchAck {
    /// Dispatch operation acknowledged.
    pub dispatch_id: String,
    /// Whether the egress retained the exact intent bytes.
    pub retained: bool,
}

/// Worker acknowledgement. Never attempt success.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkerAck {
    /// Attempt acknowledged.
    pub attempt_id: AttemptId,
    /// Worker identity presenting the acknowledgement.
    pub worker_id: String,
}

/// Candidate attempt result. Never task Finish.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AttemptResultRecord {
    /// Attempt this candidate result belongs to.
    pub attempt_id: AttemptId,
    /// Candidate output digest.
    pub result_digest: String,
}

/// Route requirements resolved through the injected B-MOD registry.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RouteRequirements {
    /// Role requesting a route.
    pub role: String,
    /// Required competence items.
    pub competence: Vec<String>,
}

impl RouteRequirements {
    fn validate(&self) -> Result<(), FabricError> {
        validate_text(&self.role, "route_role")?;
        if self.competence.is_empty() {
            return Err(FabricError::Contract(
                "route competence must not be empty".to_owned(),
            ));
        }
        for item in &self.competence {
            validate_text(item, "route_competence")?;
        }
        Ok(())
    }
}

/// Live peer message delivered through the injected B-PEER channel.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PeerMessage {
    /// Message identity.
    pub message_id: String,
    /// Sending attempt.
    pub sender_attempt: AttemptId,
    /// Recipient attempt.
    pub recipient_attempt: AttemptId,
}

/// Peer delivery receipt from the owning channel.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PeerReceipt {
    /// Delivered message identity.
    pub message_id: String,
    /// Channel sequence assigned by the owner.
    pub channel_sequence: u64,
}

/// Swarm entry receipt from the owning B-SWARM control.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SwarmEntryReceipt {
    /// Candidate identity entered.
    pub candidate_id: CandidateId,
    /// Digest of the entered candidate bytes; must equal the planned digest.
    pub entered_digest: String,
}

/// One ordered call-ledger entry for this composition.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LedgerEntry {
    /// Monotone sequence within this fabric instance.
    pub seq: u64,
    /// Stable event name (e.g. `coordinator_constructed`).
    pub event: String,
    /// Operation identity carried by the event.
    pub operation: String,
}

/// Typed dispositions. Every variant is load-bearing and distinct: collapsing
/// any two (e.g. narrowed vs needs-*, ack vs result, requested vs terminal
/// cancellation) is a composition error.
#[derive(Clone, Debug, Eq, PartialEq, Error)]
pub enum FabricError {
    /// Daemon is not ready for swarm control.
    #[error("fabric not ready: {0}")]
    NotReady(String),
    /// Owner contract violation carrying the owner message.
    #[error("fabric contract: {0}")]
    Contract(String),
    /// Coordinator owner rejection, surfaced unchanged.
    #[error(transparent)]
    Coordinator(#[from] CoordinatorError),
    /// Same identity presented with different bytes.
    #[error("fabric definition conflict: {0}")]
    DefinitionConflict(String),
    /// Identity or revision interchange between definition, admission, and
    /// execution owners.
    #[error("fabric identity conflict: {0}")]
    IdentityConflict(String),
    /// Governor denied admission.
    #[error("fabric admission denied: {0}")]
    AdmissionDenied(String),
    /// Admission arrived incomplete and cannot run.
    #[error("fabric admission incomplete: {0}")]
    AdmissionIncomplete(String),
    /// Governor narrowed the proposal; the old definition cannot be rewritten
    /// or started.
    #[error("fabric narrowed: {0}")]
    Narrowed(String),
    /// Admission needs a revised task proposal from its owner.
    #[error("fabric needs task: {0}")]
    NeedsTask(String),
    /// Admission needs a revised scope proposal from its owner.
    #[error("fabric needs scope: {0}")]
    NeedsScope(String),
    /// Admission needs a revised source proposal from its owner.
    #[error("fabric needs source: {0}")]
    NeedsSource(String),
    /// Admission needs a revised capability proposal from its owner.
    #[error("fabric needs capability: {0}")]
    NeedsCapability(String),
    /// Admission needs a revised supervision proposal from its owner.
    #[error("fabric needs supervision: {0}")]
    NeedsSupervision(String),
    /// Presented fence is stale or mismatched.
    #[error("fabric stale fence: {0}")]
    StaleFence(String),
    /// Presented epoch is stale or mismatched.
    #[error("fabric stale epoch: {0}")]
    StaleEpoch(String),
    /// Reservation is stale, unknown, or already consumed.
    #[error("fabric stale reservation: {0}")]
    StaleReservation(String),
    /// Admission is stale, cancelled, or superseded.
    #[error("fabric stale admission: {0}")]
    StaleAdmission(String),
    /// Admission was cancelled before activation.
    #[error("fabric cancelled: {0}")]
    Cancelled(String),
    /// Admission was superseded by a newer revision.
    #[error("fabric superseded: {0}")]
    Superseded(String),
    /// No eligible route; typed outcome, never a local fallback.
    #[error("fabric no route: {0}")]
    NoRoute(String),
    /// Coordinator is unavailable for this operation.
    #[error("fabric coordinator unavailable: {0}")]
    CoordinatorUnavailable(String),
    /// Dispatch egress is unavailable; the registered operation is retained
    /// without duplicate launch or false success.
    #[error("fabric dispatch unavailable: {0}")]
    DispatchUnavailable(String),
    /// Dispatch was lost without retention; the original operation is
    /// preserved as unknown, never recomputed.
    #[error("fabric dispatch lost: {0}")]
    DispatchLost(String),
    /// Unknown child outcome; remains unknown and cannot satisfy Finish.
    #[error("fabric unknown child outcome: {0}")]
    UnknownChild(String),
    /// Orphan, foreign, or stale worker observation quarantined through
    /// existing supervision; it publishes no proof or effect.
    #[error("fabric quarantined: {0}")]
    Quarantined(String),
    /// A worker acknowledgement was presented where an attempt result was
    /// required; ack is never success.
    #[error("fabric ack is not result: {0}")]
    AckNotResult(String),
    /// An attempt result was presented where a task Finish decision was
    /// required; result is never Finish.
    #[error("fabric result is not finish: {0}")]
    ResultNotFinish(String),
    /// No activation evidence exists for this admission/attempt.
    #[error("fabric not activated: {0}")]
    NotActivated(String),
    /// A second initialization was attempted; exactly one coordinator exists.
    #[error("fabric already initialized: {0}")]
    AlreadyInitialized(String),
    /// Admission receipt does not bind the exact definition digest and
    /// reservation identity.
    #[error("fabric receipt binding: {0}")]
    ReceiptBinding(String),
    /// A second launch was attempted for an already-registered operation.
    #[error("fabric duplicate launch: {0}")]
    DuplicateLaunch(String),
    /// Cancellation was requested but its terminal reconciliation has not been
    /// observed; the two remain distinct.
    #[error("fabric cancellation requested: {0}")]
    CancellationRequested(String),
    /// Terminal cancellation was observed for a previously requested
    /// operation.
    #[error("fabric terminal cancellation: {0}")]
    TerminalCancellation(String),
}

/// B-MOD model registry seam (#694). The fabric resolves routes only through
/// this injected port; ranking stays with the owner.
pub trait ModelRegistryPort: Send + Sync {
    /// Resolves one route for the given requirements, or `None` when no route
    /// is eligible. Never falls back locally.
    fn resolve_route(
        &self,
        requirements: &RouteRequirements,
    ) -> Result<Option<RouteFingerprint>, FabricError>;
}

/// B-PEER coordination channel seam (#696). The fabric delivers only through
/// this injected port; delivery stays with the owner.
pub trait PeerChannelPort: Send + Sync {
    /// Delivers one peer message through the owning channel.
    fn deliver(&self, message: &PeerMessage) -> Result<PeerReceipt, FabricError>;
}

/// B-SWARM durable swarm control seam (#698). The fabric enters the admitted
/// plan only through this injected port; the plan crosses unchanged.
pub trait SwarmControlPort: Send + Sync {
    /// Enters one planned candidate without semantic rewrite.
    fn enter_plan(
        &self,
        candidate: &StaffingPlanCandidate,
    ) -> Result<SwarmEntryReceipt, FabricError>;
}

/// Governor admission authority seam. Kernel stages the inactive reservation;
/// Governor commits the canonical admission. The fabric composes both results
/// and implements neither store.
pub trait AdmissionAuthorityPort: Send + Sync {
    /// Stages one inactive reservation for the exact definition.
    fn stage_reservation(&self, definition: &SwarmDefinition) -> Result<Reservation, FabricError>;
    /// Commits one canonical admission referencing the staged reservation.
    fn commit_admission(&self, reservation: &Reservation) -> Result<FabricAdmission, FabricError>;
}

/// Kernel activation authority seam (#839). Activation is granted only after
/// the matching canonical receipt under an unchanged fence and epoch.
pub trait ActivationAuthorityPort: Send + Sync {
    /// Activates launch authority for one admitted attempt.
    fn activate(
        &self,
        admission: &FabricAdmission,
        attempt_id: &AttemptId,
    ) -> Result<ActivationEvidence, FabricError>;
}

/// Dispatch egress seam. The provider-neutral intent leaves the control
/// boundary only post-activation through this port.
pub trait DispatchEgressPort: Send + Sync {
    /// Emits one activated dispatch intent.
    fn emit(&self, intent: &DispatchIntent) -> Result<DispatchAck, FabricError>;
}

/// Injected owner ports for one fabric instance.
#[derive(Clone)]
pub struct FabricPorts {
    /// B-MOD model registry (#694).
    pub model_registry: Arc<dyn ModelRegistryPort>,
    /// B-PEER coordination channel (#696).
    pub peer_channel: Arc<dyn PeerChannelPort>,
    /// B-SWARM durable swarm control (#698).
    pub swarm_control: Arc<dyn SwarmControlPort>,
    /// Governor admission authority.
    pub admission_authority: Arc<dyn AdmissionAuthorityPort>,
    /// Kernel activation authority (#839).
    pub activation_authority: Arc<dyn ActivationAuthorityPort>,
    /// Dispatch egress.
    pub dispatch_egress: Arc<dyn DispatchEgressPort>,
}

/// Durable snapshot of one fabric instance. Restart reconstructs exactly one
/// execution owner from this value plus live owner projections; unresolved
/// reservations stay unresolved and no second coordinator is created.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FabricSnapshot {
    /// Coordinator owner snapshot.
    pub coordinator_snapshot: CoordinatorSnapshot,
    /// Frozen definitions by definition identity.
    pub definitions: BTreeMap<String, SwarmDefinition>,
    /// Staged reservations by reservation identity.
    pub reservations: BTreeMap<String, Reservation>,
    /// Committed admissions by admission identity.
    pub admissions: BTreeMap<String, FabricAdmission>,
    /// Activation evidence by `admission_id/attempt_id`.
    pub activations: BTreeMap<String, ActivationEvidence>,
    /// Emitted dispatch intents by dispatch identity.
    pub intents: BTreeMap<String, DispatchIntent>,
    /// Ordered call ledger.
    pub ledger: Vec<LedgerEntry>,
    /// Attempt states by attempt identity.
    pub attempt_states: BTreeMap<String, AttemptLifecycle>,
    /// Cancellation states by attempt identity.
    pub cancellations: BTreeMap<String, CancellationLifecycle>,
}

/// Attempt lifecycle tracked by this composition. Terminal states never
/// advance silently; unknown remains unknown.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AttemptLifecycle {
    /// Admitted and registered, not yet activated.
    Admitted,
    /// Activated by the Kernel owner.
    Activated,
    /// Dispatched post-activation.
    Dispatched,
    /// Candidate result submitted; not task Finish.
    ResultSubmitted,
    /// Outcome unknown; requires authenticated reconciliation.
    UnknownOutcome,
}

/// Cancellation lifecycle. Request and terminal observation remain distinct.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CancellationLifecycle {
    /// Cancellation requested, terminal not yet observed.
    Requested,
    /// Terminal cancellation observed.
    Terminal,
}

/// Thin durable swarm-control composition.
///
/// Owns exactly one [`AgentCoordinator`] plus the saga maps above it. All
/// owner policy stays with the owners; this type only threads admitted values,
/// verifies exact bindings at each boundary, and records the call ledger.
pub struct AgentFabric {
    config: CoordinatorConfig,
    coordinator: AgentCoordinator,
    ports: FabricPorts,
    ledger: Vec<LedgerEntry>,
    definitions: BTreeMap<String, SwarmDefinition>,
    definition_bytes: BTreeMap<String, String>,
    reservations: BTreeMap<String, Reservation>,
    admissions: BTreeMap<String, FabricAdmission>,
    admission_by_definition: BTreeMap<String, String>,
    activations: BTreeMap<String, ActivationEvidence>,
    intents: BTreeMap<String, DispatchIntent>,
    intent_by_operation: BTreeMap<String, String>,
    attempt_states: BTreeMap<String, AttemptLifecycle>,
    cancellations: BTreeMap<String, CancellationLifecycle>,
    initialized: bool,
}

impl AgentFabric {
    /// Constructs the one coordinator for this composition.
    ///
    /// # Errors
    ///
    /// Returns [`FabricError::Contract`] when the config is invalid.
    pub fn new(config: CoordinatorConfig, ports: FabricPorts) -> Result<Self, FabricError> {
        config
            .validate()
            .map_err(|error| FabricError::Contract(format!("coordinator config: {error}")))?;
        let coordinator = AgentCoordinator::new(
            config.clone(),
            PlanGap::G11Unavailable {
                reason: FABRIC_PLAN_GAP_REASON.to_owned(),
            },
        )?;
        let mut fabric = Self {
            config,
            coordinator,
            ports,
            ledger: Vec::new(),
            definitions: BTreeMap::new(),
            definition_bytes: BTreeMap::new(),
            reservations: BTreeMap::new(),
            admissions: BTreeMap::new(),
            admission_by_definition: BTreeMap::new(),
            activations: BTreeMap::new(),
            intents: BTreeMap::new(),
            intent_by_operation: BTreeMap::new(),
            attempt_states: BTreeMap::new(),
            cancellations: BTreeMap::new(),
            initialized: true,
        };
        fabric.record("coordinator_constructed", "coordinator");
        Ok(fabric)
    }

    /// Rejects a second initialization on the same instance.
    ///
    /// # Errors
    ///
    /// Always returns [`FabricError::AlreadyInitialized`].
    pub fn try_initialize_again(&self) -> Result<(), FabricError> {
        if self.initialized {
            return Err(FabricError::AlreadyInitialized(
                "exactly one coordinator per fabric instance".to_owned(),
            ));
        }
        Ok(())
    }

    /// Returns the number of coordinators owned by this instance. Always one.
    #[must_use]
    pub const fn coordinator_count(&self) -> usize {
        1
    }

    /// Borrows the coordinator configuration threaded by this composition.
    #[must_use]
    pub const fn config(&self) -> &CoordinatorConfig {
        &self.config
    }

    /// Returns the ordered call ledger.
    #[must_use]
    pub fn ledger(&self) -> &[LedgerEntry] {
        &self.ledger
    }

    /// Returns the event names in ledger order.
    #[must_use]
    pub fn ledger_events(&self) -> Vec<String> {
        self.ledger
            .iter()
            .map(|entry| entry.event.clone())
            .collect()
    }

    fn record(&mut self, event: &str, operation: &str) {
        let seq = u64::try_from(self.ledger.len()).unwrap_or(u64::MAX);
        self.ledger.push(LedgerEntry {
            seq,
            event: event.to_owned(),
            operation: operation.to_owned(),
        });
    }

    /// Validates and freezes one Task-Controller definition, then compiles its
    /// deterministic candidate through the real coordinator owner.
    ///
    /// The definition bytes are frozen before planning; planning never rewrites
    /// them. Identity reuse with different bytes is a conflict.
    ///
    /// # Errors
    ///
    /// Returns the coordinator owner rejection or [`FabricError::DefinitionConflict`].
    pub fn define_and_plan(
        &mut self,
        request: StaffingPlanRequest,
    ) -> Result<(SwarmDefinition, StaffingPlanCandidate), FabricError> {
        self.record("definition_validated", request.candidate_id.as_str());
        // Freeze bytes before planning: identity reuse with different bytes is
        // a definition conflict, surfaced in fabric vocabulary before the
        // coordinator owner sees the replay.
        let digest = digest_json(&request)?;
        let key = request.candidate_id.as_str().to_owned();
        if let Some(stored_bytes) = self.definition_bytes.get(&key) {
            if *stored_bytes != digest {
                return Err(FabricError::DefinitionConflict(format!(
                    "definition {key} reused with different bytes"
                )));
            }
            let candidate = self.coordinator.plan(request)?;
            let stored = self.definitions.get(&key).cloned().ok_or_else(|| {
                FabricError::Contract(format!("definition {key} bytes without record"))
            })?;
            self.record("plan_replayed", &key);
            return Ok((stored, candidate));
        }
        let candidate = self.coordinator.plan(request.clone())?;
        let definition = SwarmDefinition {
            definition_id: request.candidate_id.clone(),
            definition_digest: digest.clone(),
            work_class: request.work_class.clone(),
            task_id: request.launch.task_id.as_str().to_owned(),
            task_revision: request.task_revision.clone(),
            plan_revision: request.plan_revision.as_str().to_owned(),
            fence: request.state_fence.clone(),
        };
        self.definitions.insert(key.clone(), definition.clone());
        self.definition_bytes.insert(key.clone(), digest);
        self.record("plan_compiled", &key);
        Ok((definition, candidate))
    }

    /// Resolves one model route through the injected B-MOD registry.
    ///
    /// # Errors
    ///
    /// Returns [`FabricError::NoRoute`] when no route is eligible. Never falls
    /// back locally.
    pub fn resolve_model_route(
        &mut self,
        requirements: &RouteRequirements,
    ) -> Result<Option<RouteFingerprint>, FabricError> {
        requirements.validate()?;
        let route = self.ports.model_registry.resolve_route(requirements)?;
        self.record("model_route_resolved", &requirements.role);
        Ok(route)
    }

    /// Requires one resolved route through the injected B-MOD registry.
    ///
    /// # Errors
    ///
    /// Returns [`FabricError::NoRoute`] when no route is eligible.
    pub fn require_model_route(
        &mut self,
        requirements: &RouteRequirements,
    ) -> Result<RouteFingerprint, FabricError> {
        match self.resolve_model_route(requirements)? {
            Some(route) => Ok(route),
            None => Err(FabricError::NoRoute(format!(
                "no eligible route for role {}",
                requirements.role
            ))),
        }
    }

    /// Delivers one peer message through the injected B-PEER channel.
    ///
    /// # Errors
    ///
    /// Returns the channel owner rejection.
    pub fn deliver_peer(&mut self, message: &PeerMessage) -> Result<PeerReceipt, FabricError> {
        validate_text(&message.message_id, "peer_message_id")?;
        let receipt = self.ports.peer_channel.deliver(message)?;
        self.record("peer_delivered", &message.message_id);
        Ok(receipt)
    }

    /// Enters one planned candidate through the injected B-SWARM control
    /// without semantic rewrite.
    ///
    /// # Errors
    ///
    /// Returns [`FabricError::IdentityConflict`] when the entered digest does
    /// not match the planned digest.
    pub fn enter_swarm(
        &mut self,
        candidate: &StaffingPlanCandidate,
    ) -> Result<SwarmEntryReceipt, FabricError> {
        let planned_digest = digest_json(candidate)?;
        let receipt = self.ports.swarm_control.enter_plan(candidate)?;
        if receipt.entered_digest != planned_digest
            || receipt.candidate_id != candidate.candidate_id
        {
            return Err(FabricError::IdentityConflict(
                "swarm entry changed the admitted plan".to_owned(),
            ));
        }
        self.record("swarm_entered", candidate.candidate_id.as_str());
        Ok(receipt)
    }

    /// Stages one Kernel reservation for the exact frozen definition.
    ///
    /// # Errors
    ///
    /// Returns the reservation owner rejection.
    pub fn stage_reservation(
        &mut self,
        definition_id: &CandidateId,
    ) -> Result<Reservation, FabricError> {
        // #740: staged-reservation span over the existing control path.
        let _span = tracing::info_span!(
            "eliotd.fabric_stage",
            definition = %crate::diagnostics::sanitize_identity(definition_id.as_str())
        )
        .entered();
        let key = definition_id.as_str().to_owned();
        let definition = self
            .definitions
            .get(&key)
            .cloned()
            .ok_or_else(|| FabricError::Contract(format!("unknown definition {key}")))?;
        let reservation = self
            .ports
            .admission_authority
            .stage_reservation(&definition)?;
        if reservation.definition_id != *definition_id
            || reservation.definition_digest != definition.definition_digest
        {
            return Err(FabricError::ReceiptBinding(
                "reservation does not bind the exact definition".to_owned(),
            ));
        }
        // I14.1 work class (issue #1698): the staged reservation must echo
        // the frozen definition class exactly; a class mismatch is a binding
        // failure, never a silent downgrade.
        if reservation.work_class != definition.work_class {
            return Err(FabricError::ReceiptBinding(
                "reservation does not bind the exact definition work class".to_owned(),
            ));
        }
        validate_text(&reservation.reservation_id, "reservation_id")?;
        self.reservations
            .insert(reservation.reservation_id.clone(), reservation.clone());
        self.record("reservation_staged", &reservation.reservation_id);
        Ok(reservation)
    }

    /// Commits one Governor admission for a staged reservation. Fresh requests
    /// admit once; exact replay returns the same receipt without a second
    /// owner call.
    ///
    /// # Errors
    ///
    /// Returns the admission owner rejection, or [`FabricError::ReceiptBinding`]
    /// when the receipt does not bind the exact definition digest and
    /// reservation identity.
    pub fn commit_admission(
        &mut self,
        reservation_id: &str,
    ) -> Result<FabricAdmission, FabricError> {
        // #740: admission span over the existing control path. The committed
        // receipt binds the exact definition digest and reservation; every
        // rejection records its typed reason plus the exact owner.
        let _span = tracing::info_span!(
            "eliotd.fabric_commit",
            reservation = %crate::diagnostics::sanitize_identity(reservation_id)
        )
        .entered();
        let outcome = self.commit_admission_checked(reservation_id);
        match &outcome {
            Ok(admission) => {
                let _ = crate::diagnostics::AdmissionRecord::of(
                    crate::diagnostics::disposition_of_admission(admission),
                    &admission.reservation_id,
                    admission.admission_id.as_str(),
                )
                .emit();
            }
            Err(error) => {
                let _ = crate::diagnostics::RejectionRecord::of_fabric_error(error).emit();
            }
        }
        outcome
    }

    fn commit_admission_checked(
        &mut self,
        reservation_id: &str,
    ) -> Result<FabricAdmission, FabricError> {
        let reservation = self
            .reservations
            .get(reservation_id)
            .cloned()
            .ok_or_else(|| {
                FabricError::StaleReservation(format!("unknown reservation {reservation_id}"))
            })?;
        let definition_key = reservation.definition_id.as_str().to_owned();
        if let Some(existing) = self
            .admission_by_definition
            .get(&definition_key)
            .and_then(|existing_id| self.admissions.get(existing_id))
            .cloned()
        {
            if existing.reservation_id == reservation_id {
                self.record("admission_replayed", existing.admission_id.as_str());
                return Ok(existing);
            }
            return Err(FabricError::DefinitionConflict(format!(
                "definition {definition_key} already admitted under a different reservation"
            )));
        }
        let receipt = self
            .ports
            .admission_authority
            .commit_admission(&reservation)?;
        if receipt.definition_digest
            != self
                .definitions
                .get(&definition_key)
                .map(|definition| definition.definition_digest.clone())
                .unwrap_or_default()
            || receipt.reservation_id != reservation_id
            || receipt.definition_id != reservation.definition_id
            || receipt.work_class != reservation.work_class
        {
            return Err(FabricError::ReceiptBinding(
                "admission receipt does not bind the exact definition digest and reservation"
                    .to_owned(),
            ));
        }
        if receipt.fence != reservation.fence {
            return Err(FabricError::StaleFence(
                "admission fence does not match the staged reservation".to_owned(),
            ));
        }
        let admission_key = receipt.admission_id.as_str().to_owned();
        for attempt in &receipt.attempt_ids {
            let attempt_key = attempt.as_str().to_owned();
            if self.attempt_states.contains_key(&attempt_key) {
                return Err(FabricError::DuplicateLaunch(format!(
                    "attempt {attempt_key} already registered"
                )));
            }
        }
        for attempt in &receipt.attempt_ids {
            self.attempt_states
                .insert(attempt.as_str().to_owned(), AttemptLifecycle::Admitted);
        }
        self.admissions
            .insert(admission_key.clone(), receipt.clone());
        self.admission_by_definition
            .insert(definition_key, admission_key);
        self.record("admission_committed", receipt.admission_id.as_str());
        Ok(receipt)
    }

    /// Activates launch authority for one admitted attempt after the matching
    /// canonical receipt under an unchanged fence and epoch.
    ///
    /// # Errors
    ///
    /// Returns [`FabricError::StaleFence`], [`FabricError::StaleEpoch`], or the
    /// activation owner rejection.
    pub fn activate(
        &mut self,
        admission_id: &AdmissionId,
        attempt_id: &AttemptId,
    ) -> Result<ActivationEvidence, FabricError> {
        let admission_key = admission_id.as_str().to_owned();
        let admission = self
            .admissions
            .get(&admission_key)
            .cloned()
            .ok_or_else(|| {
                FabricError::StaleAdmission(format!("unknown admission {admission_key}"))
            })?;
        if !admission.attempt_ids.contains(attempt_id) {
            return Err(FabricError::IdentityConflict(
                "attempt does not belong to this admission".to_owned(),
            ));
        }
        let key = format!("{admission_key}/{}", attempt_id.as_str());
        if let Some(existing) = self.activations.get(&key).cloned() {
            self.record("activation_replayed", &key);
            return Ok(existing);
        }
        let evidence = self
            .ports
            .activation_authority
            .activate(&admission, attempt_id)?;
        if evidence.admission_id != *admission_id || evidence.attempt_id != *attempt_id {
            return Err(FabricError::IdentityConflict(
                "activation evidence identity does not match the admission".to_owned(),
            ));
        }
        if !fences_match_exact(&evidence.fence, &admission.fence) {
            return Err(FabricError::StaleFence(
                "activation fence does not match the admission".to_owned(),
            ));
        }
        if !evidence.epoch.is_same_authority(&admission.epoch) {
            return Err(FabricError::StaleEpoch(
                "activation epoch does not match the admission".to_owned(),
            ));
        }
        validate_text(&evidence.activation_digest, "activation_digest")?;
        self.activations.insert(key.clone(), evidence.clone());
        self.attempt_states
            .insert(attempt_id.as_str().to_owned(), AttemptLifecycle::Activated);
        self.record("activation_committed", &key);
        Ok(evidence)
    }

    /// Builds the provider-neutral dispatch intent for one activated attempt.
    /// The intent leaves the control boundary only through the egress port.
    ///
    /// # Errors
    ///
    /// Returns [`FabricError::NotActivated`] when no activation evidence
    /// exists, or [`FabricError::DuplicateLaunch`] for a replayed operation
    /// with different bytes.
    pub fn dispatch(
        &mut self,
        admission_id: &AdmissionId,
        attempt_id: &AttemptId,
        dispatch_id: &str,
    ) -> Result<DispatchIntent, FabricError> {
        validate_text(dispatch_id, "dispatch_id")?;
        let admission_key = admission_id.as_str().to_owned();
        let admission = self
            .admissions
            .get(&admission_key)
            .cloned()
            .ok_or_else(|| {
                FabricError::StaleAdmission(format!("unknown admission {admission_key}"))
            })?;
        let activation_key = format!("{admission_key}/{}", attempt_id.as_str());
        let evidence = self
            .activations
            .get(&activation_key)
            .cloned()
            .ok_or_else(|| {
                FabricError::NotActivated(format!("no activation for {activation_key}"))
            })?;
        if let Some(existing) = self.intents.get(dispatch_id).cloned() {
            if existing.admission_id == *admission_id
                && existing.attempt_id == *attempt_id
                && existing.activation_digest == evidence.activation_digest
                && existing.work_class == admission.work_class
            {
                self.record("dispatch_replayed", dispatch_id);
                return Ok(existing);
            }
            return Err(FabricError::DuplicateLaunch(format!(
                "dispatch {dispatch_id} reused with different bytes"
            )));
        }
        if self
            .intent_by_operation
            .values()
            .any(|operation| operation == &activation_key)
        {
            return Err(FabricError::DuplicateLaunch(format!(
                "operation {activation_key} already dispatched"
            )));
        }
        let intent = DispatchIntent {
            dispatch_id: dispatch_id.to_owned(),
            admission_id: admission_id.clone(),
            attempt_id: attempt_id.clone(),
            work_class: admission.work_class.clone(),
            activation_digest: evidence.activation_digest.clone(),
            fence: evidence.fence.clone(),
            epoch: evidence.epoch.clone(),
        };
        self.intents.insert(dispatch_id.to_owned(), intent.clone());
        self.intent_by_operation
            .insert(dispatch_id.to_owned(), activation_key.clone());
        self.attempt_states
            .insert(attempt_id.as_str().to_owned(), AttemptLifecycle::Dispatched);
        self.record("dispatch_built", dispatch_id);
        Ok(intent)
    }

    /// Emits one built dispatch intent through the egress port.
    ///
    /// # Errors
    ///
    /// Returns the egress owner outcome, including typed unavailability and
    /// loss. Loss retains the original operation without false success.
    pub fn emit(&mut self, dispatch_id: &str) -> Result<DispatchAck, FabricError> {
        let intent = self
            .intents
            .get(dispatch_id)
            .cloned()
            .ok_or_else(|| FabricError::Contract(format!("unknown dispatch {dispatch_id}")))?;
        let ack = self.ports.dispatch_egress.emit(&intent)?;
        if ack.dispatch_id != dispatch_id {
            return Err(FabricError::IdentityConflict(
                "dispatch ack identity does not match the intent".to_owned(),
            ));
        }
        self.record("dispatch_emitted", dispatch_id);
        Ok(ack)
    }

    /// Records a worker acknowledgement. An ack never becomes attempt success.
    ///
    /// # Errors
    ///
    /// Returns [`FabricError::AckNotResult`] when the caller treats the ack as
    /// a result, and [`FabricError::Quarantined`] for unknown attempts.
    pub fn observe_worker_ack(&mut self, ack: &WorkerAck) -> Result<(), FabricError> {
        // #740: ack span. A worker acknowledgement is never completed work;
        // the record keeps `completed='false'` even on success.
        let _span = tracing::info_span!(
            "eliotd.fabric_ack",
            attempt = %crate::diagnostics::sanitize_identity(ack.attempt_id.as_str())
        )
        .entered();
        let outcome = self.observe_worker_ack_checked(ack);
        if outcome.is_ok() {
            let _ = crate::diagnostics::emit_worker_ack(
                ack.attempt_id.as_str(),
                ack.worker_id.as_str(),
            );
        }
        outcome
    }

    fn observe_worker_ack_checked(&mut self, ack: &WorkerAck) -> Result<(), FabricError> {
        validate_text(&ack.worker_id, "worker_id")?;
        let key = ack.attempt_id.as_str().to_owned();
        if !self.attempt_states.contains_key(&key) {
            return Err(FabricError::Quarantined(format!(
                "orphan ack for unknown attempt {key}"
            )));
        }
        self.record("worker_ack_observed", &key);
        Ok(())
    }

    /// Submits one candidate attempt result. A result never becomes task
    /// Finish; unknown outcomes remain unknown.
    ///
    /// # Errors
    ///
    /// Returns [`FabricError::ResultNotFinish`] when the caller treats the
    /// candidate as Finish, or [`FabricError::Quarantined`] for unknown or
    /// undispatched attempts.
    pub fn submit_attempt_result(
        &mut self,
        result: &AttemptResultRecord,
    ) -> Result<(), FabricError> {
        // #740: result span. An attempt result is never task Finish; only the
        // authoritative Finish result can complete work.
        let _span = tracing::info_span!(
            "eliotd.fabric_result",
            attempt = %crate::diagnostics::sanitize_identity(result.attempt_id.as_str())
        )
        .entered();
        let outcome = self.submit_attempt_result_checked(result);
        if let Err(error) = &outcome {
            let _ = crate::diagnostics::RejectionRecord::of_fabric_error(error).emit();
        }
        outcome
    }

    fn submit_attempt_result_checked(
        &mut self,
        result: &AttemptResultRecord,
    ) -> Result<(), FabricError> {
        validate_text(&result.result_digest, "result_digest")?;
        let key = result.attempt_id.as_str().to_owned();
        match self.attempt_states.get(&key) {
            Some(AttemptLifecycle::Dispatched) => {
                self.attempt_states
                    .insert(key.clone(), AttemptLifecycle::ResultSubmitted);
                self.record("attempt_result_submitted", &key);
                Ok(())
            }
            Some(_) => Err(FabricError::ResultNotFinish(format!(
                "attempt {key} result is a candidate artifact, not task Finish"
            ))),
            None => Err(FabricError::Quarantined(format!(
                "orphan result for unknown attempt {key}"
            ))),
        }
    }

    /// Observes one worker result line. Orphan, foreign, or stale observations
    /// are quarantined and publish no proof or effect.
    ///
    /// # Errors
    ///
    /// Returns [`FabricError::Quarantined`] for unknown attempts.
    pub fn observe_worker_result(
        &mut self,
        attempt_id: &AttemptId,
        worker_id: &str,
    ) -> Result<(), FabricError> {
        validate_text(worker_id, "worker_id")?;
        let key = attempt_id.as_str().to_owned();
        if !self.attempt_states.contains_key(&key) {
            self.record("observation_quarantined", &key);
            return Err(FabricError::Quarantined(format!(
                "orphan observation for unknown attempt {key}"
            )));
        }
        self.record("observation_accepted", &key);
        Ok(())
    }

    /// Marks one attempt outcome unknown. Unknown remains unknown and cannot
    /// satisfy Finish.
    ///
    /// # Errors
    ///
    /// Returns [`FabricError::Quarantined`] for unknown attempts.
    pub fn mark_unknown_outcome(&mut self, attempt_id: &AttemptId) -> Result<(), FabricError> {
        // #740: unknown-outcome span. The original identity is preserved
        // verbatim; diagnostics never trigger a resend or recompute.
        let _span = tracing::info_span!(
            "eliotd.fabric_unknown",
            attempt = %crate::diagnostics::sanitize_identity(attempt_id.as_str())
        )
        .entered();
        let key = attempt_id.as_str().to_owned();
        if !self.attempt_states.contains_key(&key) {
            return Err(FabricError::Quarantined(format!(
                "unknown outcome for unregistered attempt {key}"
            )));
        }
        self.attempt_states
            .insert(key.clone(), AttemptLifecycle::UnknownOutcome);
        self.record("outcome_unknown", &key);
        Ok(())
    }

    /// Asserts that an unknown outcome cannot satisfy Finish.
    ///
    /// # Errors
    ///
    /// Returns [`FabricError::UnknownChild`] when the attempt is unknown, and
    /// [`FabricError::ResultNotFinish`] otherwise: no fabric state is task
    /// Finish.
    pub fn require_finish(&self, attempt_id: &AttemptId) -> Result<(), FabricError> {
        // #740: strict-Finish span. Refusal records refusal without
        // fabricated completion; success is impossible here by owner design
        // (attempt results are never Finish) and stays unlogged as finished.
        let _span = tracing::info_span!(
            "eliotd.fabric_finish",
            attempt = %crate::diagnostics::sanitize_identity(attempt_id.as_str())
        )
        .entered();
        let outcome = self.require_finish_checked(attempt_id);
        if let Err(error) = &outcome {
            let (reason, owner) = crate::diagnostics::fabric_rejection_of(error);
            let _ = crate::diagnostics::emit_finish_refusal(attempt_id.as_str(), reason, owner);
        }
        outcome
    }

    fn require_finish_checked(&self, attempt_id: &AttemptId) -> Result<(), FabricError> {
        let key = attempt_id.as_str().to_owned();
        match self.attempt_states.get(&key) {
            Some(AttemptLifecycle::UnknownOutcome) => Err(FabricError::UnknownChild(format!(
                "attempt {key} outcome is unknown and cannot satisfy Finish"
            ))),
            Some(_) => Err(FabricError::ResultNotFinish(format!(
                "attempt {key} candidate state is not task Finish"
            ))),
            None => Err(FabricError::Quarantined(format!(
                "finish requested for unknown attempt {key}"
            ))),
        }
    }

    /// Requests cancellation for one attempt. Request and terminal observation
    /// remain distinct.
    ///
    /// # Errors
    ///
    /// Returns [`FabricError::Quarantined`] for unknown attempts.
    pub fn request_cancellation(
        &mut self,
        attempt_id: &AttemptId,
        operation: &str,
    ) -> Result<(), FabricError> {
        validate_text(operation, "cancellation_operation")?;
        let key = attempt_id.as_str().to_owned();
        if !self.attempt_states.contains_key(&key) {
            return Err(FabricError::Quarantined(format!(
                "cancellation for unknown attempt {key}"
            )));
        }
        self.cancellations
            .insert(key.clone(), CancellationLifecycle::Requested);
        self.record("cancellation_requested", &key);
        Ok(())
    }

    /// Reconciles the observed terminal cancellation for a previously
    /// requested operation.
    ///
    /// # Errors
    ///
    /// Returns [`FabricError::Cancelled`] when no request exists, keeping
    /// request and terminal distinct.
    pub fn reconcile_terminal_cancellation(
        &mut self,
        attempt_id: &AttemptId,
    ) -> Result<(), FabricError> {
        let key = attempt_id.as_str().to_owned();
        match self.cancellations.get(&key) {
            Some(CancellationLifecycle::Requested) => {
                self.cancellations
                    .insert(key.clone(), CancellationLifecycle::Terminal);
                self.record("cancellation_terminal", &key);
                Ok(())
            }
            _ => Err(FabricError::Cancelled(format!(
                "no requested cancellation reconciles attempt {key}"
            ))),
        }
    }

    /// Returns the cancellation lifecycle for one attempt, if any.
    #[must_use]
    pub fn cancellation_of(&self, attempt_id: &AttemptId) -> Option<CancellationLifecycle> {
        self.cancellations.get(attempt_id.as_str()).copied()
    }

    /// Returns the attempt lifecycle for one attempt, if any.
    #[must_use]
    pub fn attempt_of(&self, attempt_id: &AttemptId) -> Option<AttemptLifecycle> {
        self.attempt_states.get(attempt_id.as_str()).copied()
    }

    /// Snapshots this instance for durable restart.
    ///
    /// # Errors
    ///
    /// Returns the coordinator owner snapshot rejection.
    pub fn snapshot(&self) -> Result<FabricSnapshot, FabricError> {
        Ok(FabricSnapshot {
            coordinator_snapshot: self.coordinator.snapshot()?,
            definitions: self.definitions.clone(),
            reservations: self.reservations.clone(),
            admissions: self.admissions.clone(),
            activations: self.activations.clone(),
            intents: self.intents.clone(),
            ledger: self.ledger.clone(),
            attempt_states: self.attempt_states.clone(),
            cancellations: self.cancellations.clone(),
        })
    }

    /// Restores exactly one execution owner from a durable snapshot.
    ///
    /// Definition, admission, lease, and epoch revisions are preserved;
    /// unresolved reservations stay unresolved and no second coordinator is
    /// created.
    ///
    /// # Errors
    ///
    /// Returns the coordinator owner restore rejection or a stale-config
    /// conflict.
    pub fn restore(
        snapshot: FabricSnapshot,
        config: CoordinatorConfig,
        ports: FabricPorts,
    ) -> Result<Self, FabricError> {
        if snapshot.coordinator_snapshot.config != config {
            return Err(FabricError::IdentityConflict(
                "restore config does not match the snapshotted coordinator config".to_owned(),
            ));
        }
        let coordinator = AgentCoordinator::restore(
            snapshot.coordinator_snapshot.clone(),
            config.clone(),
            PlanGap::G11Unavailable {
                reason: FABRIC_PLAN_GAP_REASON.to_owned(),
            },
        )?;
        let mut definition_bytes = BTreeMap::new();
        for (key, definition) in &snapshot.definitions {
            definition_bytes.insert(key.clone(), definition.definition_digest.clone());
        }
        let mut admission_by_definition = BTreeMap::new();
        for (admission_key, admission) in &snapshot.admissions {
            admission_by_definition.insert(
                admission.definition_id.as_str().to_owned(),
                admission_key.clone(),
            );
        }
        let mut intent_by_operation = BTreeMap::new();
        for (dispatch_id, intent) in &snapshot.intents {
            intent_by_operation.insert(
                dispatch_id.clone(),
                format!(
                    "{}/{}",
                    intent.admission_id.as_str(),
                    intent.attempt_id.as_str()
                ),
            );
        }
        let mut fabric = Self {
            config,
            coordinator,
            ports,
            ledger: snapshot.ledger.clone(),
            definitions: snapshot.definitions,
            definition_bytes,
            reservations: snapshot.reservations,
            admissions: snapshot.admissions,
            admission_by_definition,
            activations: snapshot.activations,
            intents: snapshot.intents,
            intent_by_operation,
            attempt_states: snapshot.attempt_states,
            cancellations: snapshot.cancellations,
            initialized: true,
        };
        fabric.record("fabric_restored", "fabric");
        Ok(fabric)
    }
}

/// Readiness-gated descriptor proving the production daemon caller reaches
/// this composition. Built by `DaemonComposition` from its admitted snapshot;
/// it carries evidence only, never authority.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentFabricDescriptor {
    /// Daemon service identity.
    pub service: String,
    /// Admitted resource generation.
    pub generation: u64,
    /// Admitted authority epoch sequence.
    pub authority_epoch: u64,
    /// Coordinator capacity identity threaded for this composition.
    pub capacity_identity: String,
}
