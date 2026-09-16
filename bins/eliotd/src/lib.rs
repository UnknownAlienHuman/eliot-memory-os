//! Production N4 Governor daemon composition root.
//!
//! `eliotd` owns application scheduling and the pure Governor projections. It
//! does not own a Kernel, a canonical store client, a store adapter, or a
//! physical process executor. Canonical transitions leave this process only
//! through the neutral authenticated [`KernelTransitionPort`].

#![forbid(unsafe_code)]

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use eliot_contracts::{EpochId, ResourceGeneration, StateFence};
use eliot_governor::{
    CompositionError, CompositionReadiness, GovernorActivationOutcome, GovernorComposition,
    GovernorLaunchConfig, KernelGenerationPort, KernelGenerationSnapshotProvider, QueueLimits,
};
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
mod controlboard_adapters;
mod daemon_config;
mod daemon_kernel_client;
mod daemon_kernel_port_adapters;
mod dreamer_admission;
mod dreamer_materials;
mod dreamer_model_adapter;
mod governor_local_read;
mod kernel_authority_client;
mod kernel_context_read_client;
mod kernel_recovery_client;
mod kernel_transition_client;
mod observation_adapters;
mod skill_lifecycle_adapters;
mod skill_surface_adapters;
mod store_failure_projection;
mod task_lifecycle_adapters;

pub use activation_projection::AgentActivationResolver;
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
    DreamerModelExecution, GovernedDreamerModelAdapter, ModelInvokeInput,
};
pub use governor_local_read::{
    answer_evidence_query, answer_projection_inputs, forward_admitted_local_read,
    serve_admitted_local_read,
};
pub(crate) use kernel_authority_client::KernelAuthorityClient;
pub use kernel_context_read_client::{KernelContextReadClient, ReconstructionReadComposition};
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
    /// Already-validated Kernel-issued owner session facts threaded once by
    /// the daemon runtime where the concrete client and this composition meet
    /// (AUD-C02-B, Implements #1187). Facts only, never the client itself:
    /// [`DaemonComposition::controlboard`] builds at most one admitted owner
    /// binding from them. `None` until the runtime notes a live session, so
    /// boards keep the empty (unadmitted) behaviour without one.
    owner_session: Option<OwnerSessionFacts>,
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
            operator_replay: SharedOperatorReplay::new(),
            owner_session: None,
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
    /// error, never coerced to success) so the current runtime call site keeps
    /// working until Slice 2 migrates it to v2.
    ///
    /// Removal is owned separately by the #839 follow-up (Slice 2 migrates the
    /// daemon runtime call site to v2) with final v1 retirement tracked by #66;
    /// this method is not removed as opportunistic cleanup.
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
                activation_projection::map_governor_outcome_to_protocol(
                    ticket,
                    GovernorActivationOutcome::Resolved(snapshot),
                    now.max(1),
                )
            }
            outcome => {
                activation_projection::map_governor_outcome_to_protocol(ticket, outcome, now.max(1))
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
        Ok(skill_lifecycle_adapters::ForwardingSkillLifecycle::new(
            self.governor.skill_lifecycle(),
        ))
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
    ) -> Result<task_lifecycle_adapters::ForwardingTaskLifecycle<'_, dyn eliot_governor::KernelGenerationPort>, DaemonError>
    {
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
        eliot_governor::GovernorEpistemicComposition<'a, DaemonKernelClient, KernelContextReadClient>,
        DaemonError,
    > {
        if self.readiness() != eliot_governor::CompositionReadiness::Ready {
            return Err(DaemonError::Composition(
                eliot_governor::CompositionError::NotReady,
            ));
        }
        let activation = self.governor.read_unique_agent_activation(now)?;
        Ok(
            eliot_governor::GovernorEpistemicComposition::borrow(
                &self.governor.owners().canonical,
                activation,
                kernel.as_ref(),
                reads,
                self.readiness(),
            ),
        )
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
        if self.readiness() != CompositionReadiness::Ready {
            return Err(DaemonError::Composition(CompositionError::NotReady));
        }
        let fence = self.governor.kernel_snapshot().state_fence().clone();
        fence.validate().map_err(|error| {
            DaemonError::Lifecycle(format!("agent fabric admitted fence: {error}"))
        })?;
        let config = daemon_coordinator_config()
            .map_err(|error| DaemonError::Lifecycle(error.to_string()))?;
        Ok(AgentFabricDescriptor {
            service: SERVICE_NAME.to_owned(),
            generation: fence.resource_generation.value(),
            authority_epoch: fence.authority_epoch.sequence.get(),
            capacity_identity: config.capacity_identity,
        })
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
        plan_candidate(&config, request)
            .map_err(|error| DaemonError::Lifecycle(error.to_string()))
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
