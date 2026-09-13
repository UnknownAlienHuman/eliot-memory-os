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

use eliot_contracts::{AuthorityEpoch, ResourceGeneration, StateFence};
use eliot_governor::{
    CompositionError, CompositionReadiness, GovernorActivationOutcome, GovernorComposition,
    GovernorLaunchConfig, KernelGenerationPort, QueueLimits,
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
mod controlboard_adapters;
mod daemon_config;
mod daemon_kernel_client;
mod daemon_kernel_port_adapters;
mod kernel_authority_client;
mod kernel_recovery_client;
mod kernel_transition_client;
mod store_failure_projection;

pub use activation_projection::AgentActivationResolver;

#[cfg(test)]
use activation_projection::map_activation_snapshot;

pub use daemon_config::DaemonConfig;
pub use daemon_kernel_client::DaemonKernelClient;
pub(crate) use daemon_kernel_client::kernel_port_error;
#[cfg(test)]
pub(crate) use daemon_kernel_client::{KernelClientError, WireOutcome, operation_payload};
#[cfg(all(test, windows))]
pub(crate) use daemon_kernel_client::{
    is_pre_admission_pending_rejection, retry_pre_admission, validate_server_hello,
};
pub(crate) use daemon_kernel_port_adapters::kind_value;
pub(crate) use kernel_authority_client::KernelAuthorityClient;
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
    authority_epoch: AuthorityEpoch,
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
    /// Set when a post-commit refresh fails after the write receipt was
    /// already durable. The dependent view is stale/pending until the caller
    /// drops this composition and re-runs authenticated connect+start.
    view_stale: bool,
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
            authority_epoch: snapshot.authority_epoch.value(),
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

    /// Builds one provider-neutral ControlBoard over the current Governor
    /// projection snapshot.
    ///
    /// The board reads one immutable snapshot taken here; every port call in
    /// the returned value observes the same revision and fence. Callers take
    /// a fresh board per operation so a Governor refresh surfaces as an
    /// exact-view mismatch instead of silent divergence. Access resolution
    /// and the Swarm projection remain typed provider gaps until their
    /// owning slices land; reads serve a coherent empty-items view over real
    /// G-11/I-12 bindings and submission admits candidate-only intents.
    pub fn controlboard(&self) -> Result<eliot_controlboard::ControlBoard, DaemonError> {
        let snapshot = self.governor.controlboard_snapshot()?;
        Ok(controlboard_adapters::controlboard_over_snapshot(snapshot))
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
