//! Stable C0 runtime contracts for process and replaceable capability lifecycles.
//!
//! This crate contains schemas and pure legality checks only.  It does not
//! start processes, persist ORS, select an authority owner, or perform a
//! cutover.  Those operations remain with the admitted Host/Kernel owners.

#![forbid(unsafe_code)]

use std::fmt;

use eliot_contracts::{
    ArtifactId, AuthorityEpoch, ContractError, ContractId, ContractIdentity, ContractVersion,
    ResourceGeneration, StateFence,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use thiserror::Error;

mod installation_activation;
mod runtime_live;
mod supervision_authority;
mod supervision_incarnation;
mod supervision_lease;
mod watchdog_admission;

pub use installation_activation::{
    Ed25519InstallationActivationApprovalSigner, INSTALLATION_ACTIVATION_CONTRACT_NAME,
    INSTALLATION_ACTIVATION_CONTRACT_VERSION, INSTALLATION_ACTIVATION_PUBLIC_KEY_BYTES,
    INSTALLATION_ACTIVATION_SCHEMA, INSTALLATION_ACTIVATION_SIGNATURE_ALGORITHM,
    INSTALLATION_ACTIVATION_SIGNATURE_BYTES, INSTALLATION_REGISTRATION_NONCE_BYTES,
    InstallationActivationApprovalSigner, InstallationActivationApprovalTrustAnchor,
    InstallationActivationApprovalVerifier, InstallationActivationError,
    InstallationActivationPayload, InstallationActivationSigner, InstallationActivationTrustAnchor,
    InstallationActivationVerificationContext, InstallationActivationVerifier,
    InstallationDigestBinding, InstallationScmReadback, InstallationScmRole,
    SignedInstallationActivation, SignedInstallationActivationApproval,
    VerifiedInstallationActivationApproval,
};
pub use runtime_live::{
    RUNTIME_LIVE_STORE_BIND, RUNTIME_LIVE_STORE_ENDPOINT, RUNTIME_LIVE_STORE_NAMESPACE,
    RuntimeLiveStoreIdentity, RuntimeLiveStoreIdentityError,
};

pub use supervision_authority::{
    ProvisionedSupervisionAuthority, SUPERVISION_AUTHORITY_HOST_SERVICE,
    SUPERVISION_AUTHORITY_SERVICE_SID_TYPE, SupervisionSealedKeyFileIdentity,
    SupervisionSealedKeyReference, WINDOWS_SERVICE_SID_DPAPI_NG_PROVIDER,
};

pub use supervision_incarnation::{
    SUPERVISION_LEASE_ID_DOMAIN, SUPERVISION_LEASE_ID_PREFIX, SUPERVISION_SCOPE_REF_DOMAIN,
    SUPERVISION_SCOPE_REF_PREFIX, SupervisionJournalEpoch, SupervisionLeaseIncarnationBinding,
    SupervisionLeasePredecessorIdentity, canonical_observation_scope, canonical_wake_policy,
};
pub use supervision_lease::{
    Ed25519SupervisionLeaseSigner, RegisteredActivityWakePolicy, SUPERVISION_LEASE_CONTRACT_NAME,
    SUPERVISION_LEASE_CONTRACT_VERSION, SUPERVISION_LEASE_PUBLIC_KEY_BYTES,
    SUPERVISION_LEASE_SCHEMA, SUPERVISION_LEASE_SIGNATURE_ALGORITHM,
    SUPERVISION_LEASE_SIGNATURE_BYTES, SignedSupervisionLease, SupervisionGenerationBinding,
    SupervisionLease, SupervisionLeaseActiveStateBinding, SupervisionLeaseError,
    SupervisionLeasePredecessorProof, SupervisionLeaseSigner, SupervisionLeaseTerminalDisposition,
    SupervisionLeaseVerificationContext, SupervisionLeaseVerifier, SupervisionObservationScope,
    SupervisionOrsMirrorBinding, SupervisionTrustAnchor, VerifiedSupervisionLease,
    VerifiedSupervisionLeaseTerminalTransition,
};
pub use watchdog_admission::{
    SUPERVISION_LEASE_FILE_NAME, WATCHDOG_ADMISSION_FILE_NAME, WATCHDOG_ADMISSION_SCHEMA,
    WATCHDOG_PUBLICATION_DIRECTORY_PREFIX, WATCHDOG_PUBLICATION_FILE_NAME,
    WATCHDOG_PUBLICATION_RETAINED_LIMIT, WATCHDOG_PUBLICATION_SCHEMA, WatchdogAdmissionTemplate,
    WatchdogPublicationBundle, WatchdogPublicationError, WatchdogPublicationRetentionPlan,
};

/// Stable wire name for this contract family.
pub const CONTRACT_NAME: &str = "eliot.foundation.runtime-contracts";
/// Current wire revision for this contract family.
pub const CONTRACT_VERSION: ContractVersion = ContractVersion::new(1, 0, 0);

/// A runtime contract validation failure.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum RuntimeContractError {
    /// A shared C0-01 primitive rejected its value.
    #[error("foundation contract: {0}")]
    Foundation(#[from] ContractError),
    /// A required textual field is blank.
    #[error("{field} must be non-blank")]
    Blank { field: &'static str },
    /// A lifecycle transition is not in the normative transition set.
    #[error("{machine} cannot transition from {from} to {to}")]
    IllegalTransition {
        machine: &'static str,
        from: String,
        to: String,
    },
    /// A record is internally inconsistent.
    #[error("{field} is invalid: {reason}")]
    InvalidField {
        field: &'static str,
        reason: &'static str,
    },
    /// A receipt was presented for a state that cannot produce it.
    #[error("{receipt} is not valid for state {state}")]
    InvalidReceipt {
        receipt: &'static str,
        state: String,
    },
}

fn text(value: &str, field: &'static str) -> Result<(), RuntimeContractError> {
    if value.trim().is_empty() {
        return Err(RuntimeContractError::Blank { field });
    }
    if value.chars().any(char::is_control) {
        return Err(RuntimeContractError::InvalidField {
            field,
            reason: "must not contain control characters",
        });
    }
    Ok(())
}

fn transition<T>(
    machine: &'static str,
    from: T,
    to: T,
    legal: bool,
) -> Result<(), RuntimeContractError>
where
    T: fmt::Display,
{
    legal
        .then_some(())
        .ok_or_else(|| RuntimeContractError::IllegalTransition {
            machine,
            from: from.to_string(),
            to: to.to_string(),
        })
}

/// Process lifecycle from I14.20.  Process liveness is separate from module
/// generation authority.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ServiceProcessState {
    Stopped,
    Starting,
    Recovering,
    Ready,
    Degraded,
    Quiescing,
    Failed,
    RestartWait,
    Quarantined,
    ManualRecovery,
}

impl ServiceProcessState {
    /// Returns whether this state is terminal for the current process lineage.
    pub const fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::Stopped | Self::Quarantined | Self::ManualRecovery
        )
    }

    /// Checks one transition against the canonical process machine.
    pub fn transition_to(self, next: Self) -> Result<Self, RuntimeContractError> {
        let legal = matches!(
            (self, next),
            (Self::Stopped, Self::Starting)
                | (
                    Self::Starting,
                    Self::Recovering | Self::Ready | Self::Failed
                )
                | (
                    Self::Recovering,
                    Self::Ready | Self::Degraded | Self::Failed
                )
                | (Self::Ready, Self::Degraded | Self::Quiescing | Self::Failed)
                | (Self::Degraded, Self::Ready | Self::Quiescing | Self::Failed)
                | (Self::Quiescing, Self::Stopped | Self::Failed)
                | (
                    Self::Failed,
                    Self::Stopped | Self::RestartWait | Self::Quarantined | Self::ManualRecovery,
                )
                | (
                    Self::RestartWait,
                    Self::Starting | Self::Quarantined | Self::ManualRecovery
                )
        );
        transition("ServiceProcessState", self, next, legal).map(|()| next)
    }
}

impl fmt::Display for ServiceProcessState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Stopped => "STOPPED",
            Self::Starting => "STARTING",
            Self::Recovering => "RECOVERING",
            Self::Ready => "READY",
            Self::Degraded => "DEGRADED",
            Self::Quiescing => "QUIESCING",
            Self::Failed => "FAILED",
            Self::RestartWait => "RESTART_WAIT",
            Self::Quarantined => "QUARANTINED",
            Self::ManualRecovery => "MANUAL_RECOVERY",
        })
    }
}

/// One health dimension used by process and generation observers.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum HealthDimension {
    Unknown,
    Healthy,
    Degraded,
    Failed,
}

/// The six-dimensional health vector defined by the Runtime appendix.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HealthVector {
    /// Process responds.
    pub liveness: HealthDimension,
    /// The capability may accept the declared work class.
    pub readiness: HealthDimension,
    /// Derived state is current enough for the declared use.
    pub freshness: HealthDimension,
    /// Protocol and contract compatibility.
    pub compatibility: HealthDimension,
    /// Artifact/config/state integrity.
    pub integrity: HealthDimension,
    /// Resource budget is available.
    pub capacity: HealthDimension,
}

impl HealthVector {
    /// A healthy vector is required before advertising full readiness.
    pub const fn healthy() -> Self {
        Self {
            liveness: HealthDimension::Healthy,
            readiness: HealthDimension::Healthy,
            freshness: HealthDimension::Healthy,
            compatibility: HealthDimension::Healthy,
            integrity: HealthDimension::Healthy,
            capacity: HealthDimension::Healthy,
        }
    }

    /// Returns true only when no dimension is unknown, degraded or failed.
    pub const fn is_fully_healthy(self) -> bool {
        matches!(self.liveness, HealthDimension::Healthy)
            && matches!(self.readiness, HealthDimension::Healthy)
            && matches!(self.freshness, HealthDimension::Healthy)
            && matches!(self.compatibility, HealthDimension::Healthy)
            && matches!(self.integrity, HealthDimension::Healthy)
            && matches!(self.capacity, HealthDimension::Healthy)
    }
}

/// Replaceable capability-generation lifecycle from I14.20.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ModuleGenerationState {
    Discovered,
    Staged,
    Starting,
    Recovering,
    Ready,
    Active,
    Degraded,
    Quiescing,
    Drained,
    Stopped,
    Retired,
    Failed,
    RestartWait,
    Quarantined,
    ManualRecovery,
}

impl fmt::Display for ModuleGenerationState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Discovered => "DISCOVERED",
            Self::Staged => "STAGED",
            Self::Starting => "STARTING",
            Self::Recovering => "RECOVERING",
            Self::Ready => "READY",
            Self::Active => "ACTIVE",
            Self::Degraded => "DEGRADED",
            Self::Quiescing => "QUIESCING",
            Self::Drained => "DRAINED",
            Self::Stopped => "STOPPED",
            Self::Retired => "RETIRED",
            Self::Failed => "FAILED",
            Self::RestartWait => "RESTART_WAIT",
            Self::Quarantined => "QUARANTINED",
            Self::ManualRecovery => "MANUAL_RECOVERY",
        })
    }
}

impl ModuleGenerationState {
    /// Checks one generation transition against I14.20.
    pub fn transition_to(self, next: Self) -> Result<Self, RuntimeContractError> {
        let legal = matches!(
            (self, next),
            (Self::Discovered, Self::Staged)
                | (
                    Self::Staged,
                    Self::Starting | Self::Retired | Self::Quarantined
                )
                | (
                    Self::Starting,
                    Self::Recovering | Self::Ready | Self::Failed
                )
                | (
                    Self::Recovering,
                    Self::Ready | Self::Degraded | Self::Failed
                )
                | (Self::Ready, Self::Active | Self::Degraded | Self::Quiescing)
                | (Self::Active, Self::Degraded | Self::Quiescing)
                | (Self::Degraded, Self::Active | Self::Quiescing)
                | (Self::Quiescing, Self::Drained)
                | (Self::Drained, Self::Stopped)
                | (Self::Stopped, Self::Retired)
                | (
                    Self::Failed,
                    Self::RestartWait | Self::Quarantined | Self::ManualRecovery
                )
                | (
                    Self::RestartWait,
                    Self::Starting | Self::Quarantined | Self::ManualRecovery
                )
        );
        transition("ModuleGenerationState", self, next, legal).map(|()| next)
    }
}

/// Generation cutover lifecycle from I14.20.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum GenerationCutoverState {
    Preparing,
    Armed,
    Committed,
    Reconciling,
    Completed,
    Failed,
    FailedRequiresForwardCutover,
}

impl fmt::Display for GenerationCutoverState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Preparing => "PREPARING",
            Self::Armed => "ARMED",
            Self::Committed => "COMMITTED",
            Self::Reconciling => "RECONCILING",
            Self::Completed => "COMPLETED",
            Self::Failed => "FAILED",
            Self::FailedRequiresForwardCutover => "FAILED_REQUIRES_FORWARD_CUTOVER",
        })
    }
}

impl GenerationCutoverState {
    /// Checks a cutover transition.  Rollback is represented by a new record.
    pub fn transition_to(self, next: Self) -> Result<Self, RuntimeContractError> {
        let legal = matches!(
            (self, next),
            (Self::Preparing, Self::Armed | Self::Failed)
                | (
                    Self::Armed,
                    Self::Committed | Self::Failed | Self::Reconciling
                )
                | (Self::Committed, Self::Reconciling)
                | (
                    Self::Reconciling,
                    Self::Completed | Self::FailedRequiresForwardCutover
                )
        );
        transition("GenerationCutover", self, next, legal).map(|()| next)
    }
}

/// Kernel activation state for a side-by-side process handoff.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum KernelActivationState {
    Idle,
    ShadowNoAuthority,
    HandoffPrepared,
    OldTerminated,
    NonceIssued,
    Activating,
    Active,
    Failed,
    ManualRecovery,
}

/// Authority activation projection.  A token without this receipt is not active authority.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AuthorityState {
    Proposed,
    PendingKernelActivation,
    Active,
    Expired,
    Revoked,
    Superseded,
    Rejected,
    Cancelled,
    Stale,
}

/// A validated process observation contract.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServiceProcessRecord {
    /// Stable process lineage identity.
    pub process_id: String,
    /// Owning branch, such as Host, Kernel or User Broker.
    pub owner: String,
    /// Current process lifecycle state.
    pub state: ServiceProcessState,
    /// Health vector for this process only.
    pub health: HealthVector,
    /// Authority epoch observed at process start.
    pub authority_epoch: AuthorityEpoch,
}

impl ServiceProcessRecord {
    /// Validates identity and the required epoch binding.
    pub fn validate(&self) -> Result<(), RuntimeContractError> {
        text(&self.process_id, "process_id")?;
        text(&self.owner, "owner")?;
        AuthorityEpoch::new(self.authority_epoch.value()).map_err(|_| {
            RuntimeContractError::InvalidField {
                field: "authority_epoch",
                reason: "must be non-zero",
            }
        })?;
        let fully_healthy = self.health.is_fully_healthy();
        if matches!(self.state, ServiceProcessState::Ready) && !fully_healthy {
            return Err(RuntimeContractError::InvalidField {
                field: "health",
                reason: "READY process must be fully healthy",
            });
        }
        if matches!(self.state, ServiceProcessState::Degraded) && fully_healthy {
            return Err(RuntimeContractError::InvalidField {
                field: "health",
                reason: "DEGRADED process must expose a non-healthy dimension",
            });
        }
        if self.state.is_terminal() && fully_healthy {
            return Err(RuntimeContractError::InvalidField {
                field: "health",
                reason: "terminal process must not claim full health",
            });
        }
        Ok(())
    }
}

/// A module contract surface consumed by generation registration.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ModuleContract {
    /// Stable module identity.
    pub module_id: ContractId,
    /// Immutable module revision.
    pub version: ContractVersion,
    /// Content-addressed artifact.
    pub artifact_id: ArtifactId,
    /// Protocol names supported by this module.
    pub protocols: Vec<String>,
    /// Required capability dependencies.
    pub required_capabilities: Vec<String>,
    /// Optional capability dependencies.
    pub optional_capabilities: Vec<String>,
    /// Advisory dependencies are never liveness prerequisites.
    pub advisory_capabilities: Vec<String>,
    /// Owning mutable/derived-state boundary.
    pub state_owner: String,
    /// Failure domain identifier.
    pub failure_domain: String,
    /// Whether side-by-side replacement is admitted.
    pub hot_replace: bool,
}

impl ModuleContract {
    /// Validates the contract surface without probing or starting the module.
    pub fn validate(&self) -> Result<(), RuntimeContractError> {
        text(self.module_id.as_str(), "module_id")?;
        text(self.artifact_id.as_str(), "artifact_id")?;
        text(&self.state_owner, "state_owner")?;
        text(&self.failure_domain, "failure_domain")?;
        if self.protocols.is_empty() {
            return Err(RuntimeContractError::InvalidField {
                field: "protocols",
                reason: "at least one protocol is required",
            });
        }
        for protocol in &self.protocols {
            text(protocol, "protocols")?;
        }
        Ok(())
    }
}

/// Registered immutable module generation.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ModuleGeneration {
    /// Module contract identity.
    pub module_id: ContractId,
    /// Monotonic generation identity in the module lineage.
    pub generation: ResourceGeneration,
    /// Artifact selected for this generation.
    pub artifact_id: ArtifactId,
    /// Current generation state.
    pub state: ModuleGenerationState,
    /// Current health dimensions.
    pub health: HealthVector,
    /// Fence captured at registration.
    pub state_fence: StateFence,
}

impl ModuleGeneration {
    /// Validates identity, fence and the separation of health from generation state.
    pub fn validate(&self) -> Result<(), RuntimeContractError> {
        text(self.module_id.as_str(), "module_id")?;
        text(self.artifact_id.as_str(), "artifact_id")?;
        self.state_fence.validate()?;
        Ok(())
    }
}

/// Candidate proof produced before Kernel activation.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GenerationCandidateReceipt {
    /// Candidate generation identity.
    pub module_id: ContractId,
    /// Candidate generation number.
    pub generation: ResourceGeneration,
    /// Artifact proven by the builder.
    pub artifact_id: ArtifactId,
    /// Contract digest used for compatibility.
    pub contract_digest: String,
    /// Candidate remains inactive until an activation receipt exists.
    pub state: ModuleGenerationState,
}

impl GenerationCandidateReceipt {
    /// Validates the pre-activation boundary.
    pub fn validate(&self) -> Result<(), RuntimeContractError> {
        text(self.module_id.as_str(), "module_id")?;
        text(self.artifact_id.as_str(), "artifact_id")?;
        text(&self.contract_digest, "contract_digest")?;
        if !matches!(
            self.state,
            ModuleGenerationState::Discovered
                | ModuleGenerationState::Staged
                | ModuleGenerationState::Ready
        ) {
            return Err(RuntimeContractError::InvalidField {
                field: "state",
                reason: "candidate receipt must remain pre-active",
            });
        }
        Ok(())
    }
}

/// Durable ORS cutover record and its linearization state.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GenerationCutoverRecord {
    /// Cutover identity.
    pub cutover_id: String,
    /// Capability route scope being switched.
    pub route_scope: String,
    /// Previously active generation, if any.
    pub old_generation: Option<ResourceGeneration>,
    /// Candidate generation becoming active.
    pub new_generation: ResourceGeneration,
    /// Epoch before the switch.
    pub old_epoch: AuthorityEpoch,
    /// New epoch reserved for the switch.
    pub new_epoch: AuthorityEpoch,
    /// Current ORS cutover state.
    pub state: GenerationCutoverState,
}

impl GenerationCutoverRecord {
    /// Validates the cutover identity and monotonic epoch boundary.
    pub fn validate(&self) -> Result<(), RuntimeContractError> {
        text(&self.cutover_id, "cutover_id")?;
        text(&self.route_scope, "route_scope")?;
        if self.old_generation == Some(self.new_generation) {
            return Err(RuntimeContractError::InvalidField {
                field: "new_generation",
                reason: "cutover must select a distinct generation",
            });
        }
        if self.new_epoch <= self.old_epoch {
            return Err(RuntimeContractError::InvalidField {
                field: "new_epoch",
                reason: "cutover must raise the authority epoch",
            });
        }
        Ok(())
    }
}

/// Durable proof emitted after the ORS cutover linearization point.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GenerationCutoverReceipt {
    /// The exact cutover record identity.
    pub cutover_id: String,
    /// Old generation and new generation.
    pub old_generation: Option<ResourceGeneration>,
    /// New active generation.
    pub new_generation: ResourceGeneration,
    /// Epoch after cutover.
    pub authority_epoch: AuthorityEpoch,
    /// Final cutover state.
    pub state: GenerationCutoverState,
    /// Unresolved operation scopes retained for reconciliation.
    pub unresolved_scopes: Vec<String>,
}

impl GenerationCutoverReceipt {
    /// Validates that a receipt is only emitted after `COMMITTED`.
    pub fn validate(&self) -> Result<(), RuntimeContractError> {
        text(&self.cutover_id, "cutover_id")?;
        if !matches!(
            self.state,
            GenerationCutoverState::Completed
                | GenerationCutoverState::FailedRequiresForwardCutover
        ) {
            return Err(RuntimeContractError::InvalidReceipt {
                receipt: "GenerationCutoverReceipt",
                state: self.state.to_string(),
            });
        }
        Ok(())
    }
}

/// Kernel's current route and authority projection.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KernelAuthoritySnapshot {
    /// Snapshot revision.
    pub snapshot_id: String,
    /// Current authority epoch.
    pub authority_epoch: AuthorityEpoch,
    /// Active generation routes.
    pub active_generations: Vec<ModuleGeneration>,
    /// Snapshot state fence.
    pub state_fence: StateFence,
}

impl KernelAuthoritySnapshot {
    /// Validates the snapshot's identity and all generation records.
    pub fn validate(&self) -> Result<(), RuntimeContractError> {
        text(&self.snapshot_id, "snapshot_id")?;
        self.state_fence.validate()?;
        for generation in &self.active_generations {
            generation.validate()?;
            if generation.state != ModuleGenerationState::Active {
                return Err(RuntimeContractError::InvalidField {
                    field: "active_generations",
                    reason: "snapshot entries must be ACTIVE generations",
                });
            }
        }
        Ok(())
    }
}

/// Receipt that makes an exact authority projection active.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorityActivationReceipt {
    /// Activation identity.
    pub activation_id: String,
    /// Snapshot activated by Kernel.
    pub snapshot_id: String,
    /// Epoch activated.
    pub authority_epoch: AuthorityEpoch,
    /// Activation state.
    pub state: AuthorityState,
}

impl AuthorityActivationReceipt {
    /// Validates that only an explicit ACTIVE receipt grants active authority.
    pub fn validate(&self) -> Result<(), RuntimeContractError> {
        text(&self.activation_id, "activation_id")?;
        text(&self.snapshot_id, "snapshot_id")?;
        if self.state != AuthorityState::Active {
            return Err(RuntimeContractError::InvalidReceipt {
                receipt: "AuthorityActivationReceipt",
                state: format!("{:?}", self.state),
            });
        }
        Ok(())
    }
}

/// Receipt that fences an authority projection before canonical reconciliation.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorityRevocationReceipt {
    /// Revocation identity.
    pub revocation_id: String,
    /// Snapshot fenced by Kernel.
    pub snapshot_id: String,
    /// Epoch at which revocation took effect.
    pub authority_epoch: AuthorityEpoch,
    /// Revocation state.
    pub state: AuthorityState,
}

impl AuthorityRevocationReceipt {
    /// Validates the revocation boundary.
    pub fn validate(&self) -> Result<(), RuntimeContractError> {
        text(&self.revocation_id, "revocation_id")?;
        text(&self.snapshot_id, "snapshot_id")?;
        if !matches!(
            self.state,
            AuthorityState::Revoked | AuthorityState::Expired | AuthorityState::Superseded
        ) {
            return Err(RuntimeContractError::InvalidReceipt {
                receipt: "AuthorityRevocationReceipt",
                state: format!("{:?}", self.state),
            });
        }
        Ok(())
    }
}

/// Kernel-owned runtime lease.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum LeaseState {
    Requested,
    Active,
    Expiring,
    Released,
    Expired,
    Revoked,
    Superseded,
    Reconciling,
    Closed,
}

impl fmt::Display for LeaseState {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Requested => "REQUESTED",
            Self::Active => "ACTIVE",
            Self::Expiring => "EXPIRING",
            Self::Released => "RELEASED",
            Self::Expired => "EXPIRED",
            Self::Revoked => "REVOKED",
            Self::Superseded => "SUPERSEDED",
            Self::Reconciling => "RECONCILING",
            Self::Closed => "CLOSED",
        })
    }
}

/// Non-semantic runtime liveness lease stored in ORS.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeLease {
    /// Stable lease identity.
    pub lease_id: String,
    /// Opaque reason/scope reference.
    pub scope_ref: String,
    /// Authority epoch and fence at issue.
    pub authority_epoch: AuthorityEpoch,
    pub state_fence: StateFence,
    /// Current lifecycle state.
    pub state: LeaseState,
}

impl RuntimeLease {
    /// Checks the lease lifecycle.  Terminal revisions cannot be resurrected.
    pub fn transition_to(&self, next: LeaseState) -> Result<Self, RuntimeContractError> {
        let legal = matches!(
            (self.state, next),
            (
                LeaseState::Requested,
                LeaseState::Active
                    | LeaseState::Released
                    | LeaseState::Expired
                    | LeaseState::Revoked,
            ) | (
                LeaseState::Active,
                LeaseState::Expiring
                    | LeaseState::Released
                    | LeaseState::Expired
                    | LeaseState::Revoked
                    | LeaseState::Superseded
                    | LeaseState::Reconciling,
            ) | (
                LeaseState::Expiring,
                LeaseState::Active | LeaseState::Expired | LeaseState::Revoked | LeaseState::Closed,
            ) | (
                LeaseState::Reconciling,
                LeaseState::Closed
                    | LeaseState::Released
                    | LeaseState::Expired
                    | LeaseState::Revoked,
            )
        );
        transition("RuntimeLease", self.state, next, legal).map(|()| Self {
            state: next,
            ..self.clone()
        })
    }

    /// Validates the non-semantic lease binding.
    pub fn validate(&self) -> Result<(), RuntimeContractError> {
        text(&self.lease_id, "lease_id")?;
        text(&self.scope_ref, "scope_ref")?;
        self.state_fence.validate()?;
        Ok(())
    }
}

/// Demand-start instruction.  A wake intent never grants authority.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WakeIntent {
    /// Idempotency identity.
    pub wake_id: String,
    /// Why demand-start is requested.
    pub reason: String,
    /// Current fence that must be revalidated on wake.
    pub state_fence: StateFence,
    /// Current lifecycle state.
    pub state: WakeIntentState,
}

/// Wake intent lifecycle from the `HostStateJournal` contract.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum WakeIntentState {
    Pending,
    Claimed,
    Started,
    Satisfied,
    Cancelled,
    Expired,
    Failed,
}

impl WakeIntent {
    /// Validates the wake intent without treating it as authority.
    pub fn validate(&self) -> Result<(), RuntimeContractError> {
        text(&self.wake_id, "wake_id")?;
        text(&self.reason, "reason")?;
        self.state_fence.validate()?;
        Ok(())
    }
}

/// Minimal operational recovery state projection owned by Kernel/ORS.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OperationalRecoveryState {
    /// ORS schema/revision identity.
    pub ors_revision: String,
    /// Integrity status of the ORS itself.
    pub integrity: HealthDimension,
    /// Active authority epoch.
    pub authority_epoch: AuthorityEpoch,
    /// Pending opaque operation handles.
    pub pending_operation_refs: Vec<String>,
    /// Current generation/cutover references.
    pub active_generation_refs: Vec<String>,
    /// Recovery intents waiting for reconciliation.
    pub recovery_intent_refs: Vec<String>,
}

impl OperationalRecoveryState {
    /// Validates that ORS has a stable identity and never claims healthy integrity as unknown.
    pub fn validate(&self) -> Result<(), RuntimeContractError> {
        text(&self.ors_revision, "ors_revision")?;
        Ok(())
    }
}

/// A typed next step exposed by the recovery boundary.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryDirective {
    /// Why normal control is unavailable or degraded.
    pub reason: String,
    /// Exact next action permitted by the recovery owner.
    pub next_action: String,
    /// Authority required to perform that action.
    pub required_authority: String,
    /// Evidence/receipt handles supporting the directive.
    pub evidence_refs: Vec<String>,
}

impl RecoveryDirective {
    /// Validates that a directive is explicit and non-empty.
    pub fn validate(&self) -> Result<(), RuntimeContractError> {
        text(&self.reason, "reason")?;
        text(&self.next_action, "next_action")?;
        text(&self.required_authority, "required_authority")?;
        Ok(())
    }
}

/// Role-filtered non-semantic recovery inspection surface.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryView {
    /// Revision of the view and source freshness marker.
    pub view_revision: String,
    pub source_freshness: String,
    /// Current process/generation/ORS projections.
    pub processes: Vec<ServiceProcessRecord>,
    pub generations: Vec<ModuleGeneration>,
    pub ors: OperationalRecoveryState,
    /// Current recovery instructions, never semantic task truth.
    pub directives: Vec<RecoveryDirective>,
}

impl RecoveryView {
    /// Validates each independent source projection.
    pub fn validate(&self) -> Result<(), RuntimeContractError> {
        text(&self.view_revision, "view_revision")?;
        text(&self.source_freshness, "source_freshness")?;
        for process in &self.processes {
            process.validate()?;
        }
        for generation in &self.generations {
            generation.validate()?;
        }
        self.ors.validate()?;
        for directive in &self.directives {
            directive.validate()?;
        }
        Ok(())
    }
}

/// Returns the stable contract identity for schema/provenance handshakes.
pub fn contract_identity() -> Result<ContractIdentity, RuntimeContractError> {
    eliot_contracts::contract_identity(
        CONTRACT_NAME,
        CONTRACT_VERSION,
        &serde_json::json!({
            "service_process_state": schemars::schema_for!(ServiceProcessState),
            "module_generation_state": schemars::schema_for!(ModuleGenerationState),
            "generation_cutover_state": schemars::schema_for!(GenerationCutoverState),
            "installation_activation_payload": schemars::schema_for!(InstallationActivationPayload),
            "signed_installation_activation_approval":
                schemars::schema_for!(SignedInstallationActivationApproval),
            "recovery_view": schemars::schema_for!(RecoveryView),
        }),
    )
    .map_err(RuntimeContractError::from)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn process_machine_rejects_skipping_start() {
        assert!(
            ServiceProcessState::Stopped
                .transition_to(ServiceProcessState::Ready)
                .is_err()
        );
        assert_eq!(
            ServiceProcessState::Stopped.transition_to(ServiceProcessState::Starting),
            Ok(ServiceProcessState::Starting)
        );
    }

    #[test]
    fn generation_machine_requires_drain_before_retirement() {
        assert!(
            ModuleGenerationState::Active
                .transition_to(ModuleGenerationState::Retired)
                .is_err()
        );
        assert!(
            ModuleGenerationState::Active
                .transition_to(ModuleGenerationState::Quiescing)
                .is_ok()
        );
        assert!(
            ModuleGenerationState::Drained
                .transition_to(ModuleGenerationState::Stopped)
                .is_ok()
        );
    }

    #[test]
    fn cutover_failure_cannot_roll_back_as_a_backward_transition() {
        assert!(
            GenerationCutoverState::Committed
                .transition_to(GenerationCutoverState::Preparing)
                .is_err()
        );
        assert!(
            GenerationCutoverState::Reconciling
                .transition_to(GenerationCutoverState::FailedRequiresForwardCutover)
                .is_ok()
        );
    }

    #[test]
    fn health_vector_does_not_overclaim_green() {
        let mut health = HealthVector::healthy();
        health.freshness = HealthDimension::Unknown;
        assert!(!health.is_fully_healthy());
    }

    #[test]
    fn service_process_rejects_ready_with_degraded_health() {
        let mut health = HealthVector::healthy();
        health.integrity = HealthDimension::Degraded;
        let record = ServiceProcessRecord {
            process_id: "123:456".to_owned(),
            owner: "Kernel".to_owned(),
            state: ServiceProcessState::Ready,
            health,
            authority_epoch: AuthorityEpoch::genesis(),
        };
        assert!(record.validate().is_err());
    }

    #[test]
    fn service_process_rejects_malformed_authority_epoch_fixture() {
        let malformed = serde_json::json!({
            "process_id": "123:456",
            "owner": "Kernel",
            "state": "READY",
            "health": {
                "liveness": "HEALTHY",
                "readiness": "HEALTHY",
                "freshness": "HEALTHY",
                "compatibility": "HEALTHY",
                "integrity": "HEALTHY",
                "capacity": "HEALTHY"
            },
            "authority_epoch": 0
        });
        assert!(serde_json::from_value::<ServiceProcessRecord>(malformed).is_err());
    }

    #[test]
    fn roundtrip_and_schema_are_available() -> Result<(), Box<dyn std::error::Error>> {
        let value = RecoveryDirective {
            reason: "ors unavailable".to_owned(),
            next_action: "inspect authenticated recovery channel".to_owned(),
            required_authority: "recovery_principal".to_owned(),
            evidence_refs: vec!["evidence-1".to_owned()],
        };
        value.validate()?;
        let encoded = serde_json::to_string(&value)?;
        assert_eq!(serde_json::from_str::<RecoveryDirective>(&encoded)?, value);
        assert!(!serde_json::to_vec(&schemars::schema_for!(RecoveryView))?.is_empty());
        assert!(!contract_identity()?.shape_sha256.is_empty());
        Ok(())
    }

    #[test]
    fn malformed_consumer_fixture_fails_closed() {
        let malformed = serde_json::json!({
            "reason": "ors unavailable",
            "next_action": "inspect",
            "required_authority": "recovery_principal",
            "evidence_refs": [],
            "unexpected": true
        });
        assert!(serde_json::from_value::<RecoveryDirective>(malformed).is_err());
    }

    #[test]
    fn active_authority_requires_explicit_activation_receipt() {
        let receipt = AuthorityActivationReceipt {
            activation_id: "activation-1".to_owned(),
            snapshot_id: "snapshot-1".to_owned(),
            authority_epoch: AuthorityEpoch::genesis(),
            state: AuthorityState::PendingKernelActivation,
        };
        assert!(receipt.validate().is_err());
    }
}
