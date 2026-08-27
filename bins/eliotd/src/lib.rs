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

use eliot_contracts::{AuthorityEpoch, ResourceGeneration, StateFence, sha256_hex};
use eliot_governor::{
    CompositionError, CompositionReadiness, GovernorComposition, GovernorLaunchConfig,
    KernelDurableJobPort, KernelGenerationPort, KernelGenerationSnapshot,
    KernelGenerationSnapshotProvider, KernelPortError, KernelServiceObservationPort,
    KernelServiceRecovery, QueueLimits,
};
use eliot_maintenance::MaintenanceJob;
use eliot_platform_windows::{
    ProtectedPathError, ProtectedRuntimePathLease, current_process_named_pipe_expectation,
    protected_program_data_path,
};
use eliot_protocol::{AgentActivationResolutionDecision, AgentActivationResolutionTicket};
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

mod daemon_kernel_client;
mod kernel_recovery_client;
mod kernel_transition_client;

pub use daemon_kernel_client::DaemonKernelClient;
pub(crate) use daemon_kernel_client::kernel_port_error;
#[cfg(test)]
pub(crate) use daemon_kernel_client::{KernelClientError, WireOutcome, operation_payload};
#[cfg(all(test, windows))]
pub(crate) use daemon_kernel_client::{
    is_pre_admission_pending_rejection, retry_pre_admission, validate_server_hello,
};

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

fn observed_runtime_identity() -> Result<(String, u32), DaemonError> {
    let expectation = current_process_named_pipe_expectation()
        .map_err(|error| DaemonError::Kernel(format!("observe LocalService identity: {error}")))?;
    Ok((
        expectation.expected_sid().to_owned(),
        expectation.expected_session_id(),
    ))
}
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

/// Typed protected launch inputs. Production values are read from the exact
/// Host-approved runtime path and retained by a protected lease; environment
/// variables, current directory and arbitrary caller paths are not authority
/// sources.
#[derive(Debug)]
pub struct DaemonConfig {
    launch: GovernorLaunchConfig,
    config_path: PathBuf,
    state_root: PathBuf,
    config_lease: Option<ProtectedRuntimePathLease>,
    kernel_binding: KernelLaunchBinding,
}

impl DaemonConfig {
    /// Loads the Host-approved launch file through a bounded protected read.
    pub fn load_protected() -> Result<Self, DaemonError> {
        let config_path = protected_program_data_path(PROTECTED_CONFIG_RELATIVE)?;
        let config_lease = ProtectedRuntimePathLease::open_existing_absolute(&config_path)?;
        if config_lease.path() != config_path {
            return Err(DaemonError::LaunchConfig(
                "launch config path is not the retained canonical runtime identity".to_owned(),
            ));
        }
        let bytes = config_lease.read_bounded(MAX_CONFIG_BYTES)?;
        let launch: GovernorLaunchConfig = serde_json::from_slice(&bytes)
            .map_err(|error| DaemonError::LaunchConfig(error.to_string()))?;
        let mut config = Self::from_launch(launch, config_path)?;
        config.config_lease = Some(config_lease);
        Ok(config)
    }

    /// Loads the exact Host-approved daemon descriptor binding. The path,
    /// bytes, public launch correlation, and module artifact are all checked
    /// before the config can become a Kernel client binding.
    pub fn load_protected_bound(
        config_path: impl AsRef<Path>,
        expected_config_sha256: &str,
        launch_nonce: &str,
        expected_artifact_sha256: &str,
    ) -> Result<Self, DaemonError> {
        let config_path = config_path.as_ref().to_path_buf();
        if !config_path.is_absolute() {
            return Err(DaemonError::LaunchConfig(
                "launch config path must be an absolute approved runtime identity".to_owned(),
            ));
        }
        validate_sha256(expected_config_sha256, "config descriptor digest")?;
        validate_sha256(expected_artifact_sha256, "executable digest")?;
        validate_launch_nonce(launch_nonce)?;
        let config_lease = ProtectedRuntimePathLease::open_existing_absolute(&config_path)?;
        if config_lease.path() != config_path {
            return Err(DaemonError::LaunchConfig(
                "launch config path is not the retained canonical runtime identity".to_owned(),
            ));
        }
        let bytes = config_lease.read_bounded(MAX_CONFIG_BYTES)?;
        if sha256_hex(&bytes) != expected_config_sha256 {
            return Err(DaemonError::LaunchConfig(
                "launch config digest does not match the retained bytes".to_owned(),
            ));
        }
        let launch: GovernorLaunchConfig = serde_json::from_slice(&bytes)
            .map_err(|error| DaemonError::LaunchConfig(error.to_string()))?;
        let mut config = Self::from_launch_with_binding(
            launch,
            config_path,
            launch_nonce,
            expected_artifact_sha256,
        )?;
        config.config_lease = Some(config_lease);
        Ok(config)
    }

    /// Creates a config only for the exact protected path used by production.
    /// This constructor is also useful to tests that provide a protected
    /// fixture; it rejects arbitrary roots before composition.
    pub fn from_launch(
        launch: GovernorLaunchConfig,
        config_path: PathBuf,
    ) -> Result<Self, DaemonError> {
        launch.validate()?;
        if !config_path.is_absolute() {
            return Err(DaemonError::LaunchConfig(
                "launch config path must be an absolute approved runtime identity".to_owned(),
            ));
        }
        let state_root = config_path
            .parent()
            .ok_or_else(|| {
                DaemonError::LaunchConfig(
                    "launch config path has no approved runtime parent".to_owned(),
                )
            })?
            .join("state");
        let (expected_kernel_sid, expected_kernel_session_id) = observed_runtime_identity()?;
        let kernel_binding = KernelLaunchBinding {
            kernel_pipe_name: KERNEL_PIPE_NAME.to_owned(),
            expected_kernel_sid,
            expected_kernel_session_id,
            module_generation: launch.kernel.generation,
            authority_epoch: launch.kernel.authority_epoch,
            state_fence: StateFence::new(launch.kernel.authority_epoch, launch.kernel.generation),
            launch_nonce: format!("eliotd:{}", launch.instance_id),
            kernel_artifact_sha256: launch.kernel.artifact_digest.clone(),
            daemon_artifact_sha256: launch.kernel.artifact_digest.clone(),
        };
        Ok(Self {
            launch,
            config_path,
            state_root,
            config_lease: None,
            kernel_binding,
        })
    }

    fn from_launch_with_binding(
        launch: GovernorLaunchConfig,
        config_path: PathBuf,
        launch_nonce: &str,
        expected_artifact_sha256: &str,
    ) -> Result<Self, DaemonError> {
        launch.validate()?;
        validate_launch_nonce(launch_nonce)?;
        validate_sha256(expected_artifact_sha256, "executable digest")?;
        let state_root = config_path
            .parent()
            .ok_or_else(|| {
                DaemonError::LaunchConfig(
                    "launch config path has no approved runtime parent".to_owned(),
                )
            })?
            .join("state");
        let (expected_kernel_sid, expected_kernel_session_id) = observed_runtime_identity()?;
        let kernel_binding = KernelLaunchBinding {
            kernel_pipe_name: KERNEL_PIPE_NAME.to_owned(),
            expected_kernel_sid,
            expected_kernel_session_id,
            module_generation: launch.kernel.generation,
            authority_epoch: launch.kernel.authority_epoch,
            state_fence: StateFence::new(launch.kernel.authority_epoch, launch.kernel.generation),
            launch_nonce: launch_nonce.to_owned(),
            // The daemon child artifact is a separate domain from the
            // KernelGenerationExpectation artifact. The former is supplied by
            // the exact launch descriptor; the latter remains the Kernel
            // peer/generation snapshot identity.
            kernel_artifact_sha256: launch.kernel.artifact_digest.clone(),
            daemon_artifact_sha256: expected_artifact_sha256.to_owned(),
        };
        Ok(Self {
            launch,
            config_path,
            state_root,
            config_lease: None,
            kernel_binding,
        })
    }

    /// Returns the immutable Host-approved launch config.
    #[must_use]
    pub const fn launch(&self) -> &GovernorLaunchConfig {
        &self.launch
    }

    /// Returns the retained protected config identity path.
    #[must_use]
    pub fn config_path(&self) -> &Path {
        &self.config_path
    }

    /// Returns the protected daemon state root.
    #[must_use]
    pub fn state_root(&self) -> &Path {
        &self.state_root
    }
}

fn kind_value(
    value: &serde_json::Value,
    expected_kind: &str,
) -> Result<serde_json::Value, KernelPortError> {
    let object = value.as_object().ok_or_else(|| {
        KernelPortError::Contract("Kernel typed application value is not an object".to_owned())
    })?;
    if object.get("kind").and_then(serde_json::Value::as_str) != Some(expected_kind) {
        return Err(KernelPortError::Contract(format!(
            "Kernel returned unexpected application kind; expected {expected_kind}"
        )));
    }
    object.get("value").cloned().ok_or_else(|| {
        KernelPortError::Contract("Kernel typed value is missing payload".to_owned())
    })
}

impl KernelGenerationSnapshotProvider for DaemonKernelClient {
    fn snapshot(&self) -> &KernelGenerationSnapshot {
        &self.snapshot
    }
}

impl KernelServiceObservationPort for DaemonKernelClient {
    fn services(
        &self,
        state_fence: &StateFence,
        protected_snapshot_digest: &str,
    ) -> Result<Vec<KernelServiceRecovery>, KernelPortError> {
        let value = self.request_blocking(
            "services",
            serde_json::json!({
                "state_fence": state_fence,
                "protected_snapshot_digest": protected_snapshot_digest,
            }),
        )?;
        let value = kind_value(&value, "services")?;
        serde_json::from_value(value).map_err(|error| KernelPortError::Contract(error.to_string()))
    }
}

impl KernelDurableJobPort for DaemonKernelClient {
    fn load_durable_job(
        &self,
        job_id: &str,
        state_fence: &StateFence,
    ) -> Result<Option<MaintenanceJob>, KernelPortError> {
        let value = self.request_blocking(
            "load_durable_job",
            serde_json::json!({ "job_id": job_id, "state_fence": state_fence }),
        )?;
        let value = kind_value(&value, "durable_job")?;
        serde_json::from_value(value).map_err(|error| KernelPortError::Contract(error.to_string()))
    }

    fn save_durable_job(&self, job: &MaintenanceJob) -> Result<(), KernelPortError> {
        let _ = self.request_blocking("save_durable_job", serde_json::json!({ "job": job }))?;
        Ok(())
    }
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

fn validate_sha256(value: &str, label: &str) -> Result<(), DaemonError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(DaemonError::LaunchConfig(format!(
            "{label} must be a lowercase SHA-256 digest"
        )));
    }
    Ok(())
}

fn validate_launch_nonce(value: &str) -> Result<(), DaemonError> {
    let Some(suffix) = value.strip_prefix("eliotd:") else {
        return Err(DaemonError::LaunchConfig(
            "launch nonce must use the opaque eliotd correlation format".to_owned(),
        ));
    };
    if suffix.len() < 32
        || suffix.len() > 120
        || suffix
            .bytes()
            .any(|byte| !(byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b':')))
    {
        return Err(DaemonError::LaunchConfig(
            "launch nonce must be bounded opaque text with at least 32 safe bytes".to_owned(),
        ));
    }
    Ok(())
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
}

/// Read-only semantic-resolution boundary owned by eliotd.
///
/// The boundary accepts only a Kernel-issued correlation ticket. It does not
/// accept caller-selected semantic IDs and does not issue transport sessions,
/// fences, capabilities, or effects.
pub trait AgentActivationResolver {
    /// Resolves one exact ticket against the current Governor owner set.
    fn resolve_agent_activation(
        &self,
        ticket: &AgentActivationResolutionTicket,
        now: u64,
    ) -> Result<AgentActivationResolutionDecision, DaemonError>;
}

fn map_activation_snapshot(
    ticket: &AgentActivationResolutionTicket,
    snapshot: eliot_governor::GovernorActivationSnapshot,
) -> Result<AgentActivationResolutionDecision, DaemonError> {
    AgentActivationResolutionDecision {
        wire_id: eliot_protocol::AGENT_ACTIVATION_RESOLUTION_DECISION_WIRE_ID.to_owned(),
        wire_version: AgentActivationResolutionDecision::CONTRACT_VERSION,
        ticket_id: ticket.ticket_id.clone(),
        ticket_sha256: ticket.ticket_sha256.clone(),
        state_fence: snapshot.state_fence,
        principal_id: snapshot.principal_id,
        session_id: snapshot.session_id,
        task_id: snapshot.task_id.to_string(),
        work_unit_id: snapshot.work_unit_id,
        work_scope_id: snapshot.work_scope_id,
        task_revision: snapshot.task_revision.to_string(),
        plan_id: snapshot.plan_id,
        plan_revision: snapshot.plan_revision,
        decision_sha256: String::new(),
    }
    .with_computed_digest()
    .map_err(|error| DaemonError::Lifecycle(error.to_string()))
}

impl DaemonComposition {
    /// Composes the daemon only from a Host-approved authenticated Kernel port.
    ///
    /// The port is retained exactly once. Its snapshot and the recovered owner
    /// set are checked before this method returns a composition marked ready.
    pub fn start(
        mut config: DaemonConfig,
        kernel: Arc<dyn KernelGenerationPort>,
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
        let governor =
            GovernorComposition::new(kernel, &config.launch().kernel, QueueLimits::default())?;
        Ok(Self {
            governor,
            config_lease,
            state_lease,
            config_path: config.config_path,
            state_root: config.state_root,
            started: true,
        })
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
            ready: self.started && self.readiness() == CompositionReadiness::Ready,
            health: if !self.started {
                "stopped".to_owned()
            } else if self.readiness() == CompositionReadiness::Ready {
                "healthy".to_owned()
            } else {
                "degraded".to_owned()
            },
            degraded: !self.started || self.readiness() != CompositionReadiness::Ready,
        }
    }

    /// Resolves one Kernel-issued semantic ticket through the sole Governor.
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
        let snapshot = self.governor.read_unique_agent_activation(now)?;
        if snapshot.state_fence != ticket.state_fence {
            return Err(DaemonError::Lifecycle(
                "semantic activation ticket fence does not match the Governor snapshot".to_owned(),
            ));
        }
        map_activation_snapshot(ticket, snapshot)
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
}

#[cfg(test)]
mod tests;
