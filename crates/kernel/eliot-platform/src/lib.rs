//! P-01 provider-neutral platform contracts.
//!
//! This crate describes bounded effects only. It does not access an operating
//! system, own an executor, persist state, spawn processes, or carry secret
//! bytes. Platform adapters implement the ports and the owning control plane
//! supplies request identity and fences.

#![forbid(unsafe_code)]

use std::cmp::Ordering;
use std::collections::BTreeSet;
use std::fmt;
use std::hash::{Hash, Hasher};
use std::sync::Mutex;

use eliot_contracts::{ClockReading, RequestId, RequestMetadata, SessionId};
use eliot_runtime_contracts::ServiceProcessRecord;
/// Canonical C0-12 ceiling for source-derived consumers; P-01 neither redefines nor grants it.
pub use eliot_security_contracts::EffectCeiling as SourceEffectCeiling;
use schemars::JsonSchema;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use thiserror::Error;

pub const CONTRACT_NAME: &str = "eliot.kernel.platform";
pub const CONTRACT_VERSION: &str = "p-01-v1";

/// A validated opaque provider/resource handle.
#[derive(
    Clone, Debug, Eq, Hash, JsonSchema, Ord, PartialEq, PartialOrd, Serialize, Deserialize,
)]
#[serde(transparent)]
pub struct PlatformHandle(String);

impl PlatformHandle {
    pub fn new(value: impl Into<String>) -> Result<Self, PortError> {
        let value = value.into();
        validate_text(&value, "handle")?;
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A reference to provider-held secret material. The contract contains no bytes.
#[derive(
    Clone, Debug, Eq, Hash, JsonSchema, Ord, PartialEq, PartialOrd, Serialize, Deserialize,
)]
#[serde(deny_unknown_fields)]
pub struct SecretReference {
    pub provider: PlatformHandle,
    pub key: PlatformHandle,
}

impl SecretReference {
    pub fn new(provider: impl Into<String>, key: impl Into<String>) -> Result<Self, PortError> {
        Ok(Self {
            provider: PlatformHandle::new(provider)?,
            key: PlatformHandle::new(key)?,
        })
    }
}

/// A typed result that distinguishes absence, incomplete observation and failure.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
pub enum PortOutcome<T> {
    Known(T),
    Unknown(UnknownReason),
    Partial {
        value: T,
        missing: Vec<PlatformHandle>,
    },
    Error(PortError),
}

impl<T> PortOutcome<T> {
    pub fn known(value: T) -> Self {
        Self::Known(value)
    }
}

/// Why a provider cannot establish a value.
#[derive(Clone, Debug, Eq, Error, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum UnknownReason {
    #[error("provider does not expose this capability")]
    Unsupported,
    #[error("provider has no observation for this identity")]
    NotObserved,
    #[error("provider could not establish current state")]
    Indeterminate,
}

/// Non-secret provider failure classification.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ProviderErrorCode {
    Unavailable,
    PermissionDenied,
    InvalidRequest,
    Timeout,
    Failed,
}

/// Provider failure metadata; protected payload bytes are not representable.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderError {
    pub code: ProviderErrorCode,
    pub retryable: bool,
}

/// Contract-level rejection. No variant contains protected payload bytes.
#[derive(Clone, Debug, Eq, Error, JsonSchema, PartialEq, Serialize, Deserialize)]
pub enum PortError {
    #[error("{field} must be non-blank and free of control characters")]
    InvalidText { field: String },
    #[error("{field} contains a duplicate identity")]
    Duplicate { field: String },
    #[error("{field} is ambiguous")]
    Ambiguous { field: String },
    #[error("request fence is invalid")]
    InvalidFence,
    #[error("request metadata is invalid")]
    InvalidRequestMetadata,
    #[error("request identity was reused with a different canonical request hash")]
    IdentityConflict,
    #[error("service process record is invalid")]
    InvalidServiceProcessRecord,
    #[error("path must be WorkScope-relative and contain no parent traversal")]
    InvalidPath,
    #[error("provider error: {0:?}")]
    Provider(ProviderError),
}

fn validate_text(value: &str, field: &'static str) -> Result<(), PortError> {
    if value.trim().is_empty() || value.chars().any(char::is_control) {
        Err(PortError::InvalidText {
            field: field.to_owned(),
        })
    } else {
        Ok(())
    }
}

fn unique(values: &[PlatformHandle], field: &'static str) -> Result<(), PortError> {
    let mut seen = BTreeSet::new();
    if values.iter().any(|value| !seen.insert(value)) {
        Err(PortError::Duplicate {
            field: field.to_owned(),
        })
    } else {
        Ok(())
    }
}

fn validate_context(context: &RequestMetadata) -> Result<(), PortError> {
    context
        .validate()
        .map_err(|_| PortError::InvalidRequestMetadata)
}

/// A validated lexical path relative to the authenticated `WorkScope` root.
///
/// The original spelling is retained for display while equality, ordering and
/// hashing use the canonical separator-normalized identity.
#[derive(Clone, Debug, JsonSchema)]
#[schemars(with = "String")]
pub struct WorkScopePath {
    display: String,
    normalized_identity: String,
}

/// Typed input that makes the adapter's reparse-point containment obligation explicit.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdapterPathInput {
    pub display: String,
    pub normalized_identity: String,
    pub containment: AdapterContainment,
}

#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AdapterContainment {
    ReparseAndProveWithinWorkScope,
}

impl WorkScopePath {
    pub fn new(value: impl Into<String>) -> Result<Self, PortError> {
        let value = value.into();
        validate_text(&value, "path")?;
        let rooted = value.starts_with('/')
            || value.starts_with('\\')
            || (value.len() >= 2 && value.as_bytes()[1] == b':')
            || value.starts_with("//")
            || value.starts_with("\\\\");
        if rooted {
            return Err(PortError::InvalidPath);
        }
        let mut components = Vec::new();
        for component in value.split(['/', '\\']) {
            match component {
                "" | "." => {}
                ".." => return Err(PortError::InvalidPath),
                component => components.push(component.to_owned()),
            }
        }
        if components.is_empty() {
            return Err(PortError::InvalidPath);
        }
        Ok(Self {
            display: value,
            normalized_identity: components.join("/"),
        })
    }

    pub fn as_str(&self) -> &str {
        &self.display
    }

    pub fn normalized_identity(&self) -> &str {
        &self.normalized_identity
    }

    pub fn adapter_input(&self) -> AdapterPathInput {
        AdapterPathInput {
            display: self.display.clone(),
            normalized_identity: self.normalized_identity.clone(),
            containment: AdapterContainment::ReparseAndProveWithinWorkScope,
        }
    }
}

impl PartialEq for WorkScopePath {
    fn eq(&self, other: &Self) -> bool {
        self.normalized_identity == other.normalized_identity
    }
}
impl Eq for WorkScopePath {}
impl PartialOrd for WorkScopePath {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}
impl Ord for WorkScopePath {
    fn cmp(&self, other: &Self) -> Ordering {
        self.normalized_identity.cmp(&other.normalized_identity)
    }
}
impl Hash for WorkScopePath {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.normalized_identity.hash(state);
    }
}
impl Serialize for WorkScopePath {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.display)
    }
}
impl<'de> Deserialize<'de> for WorkScopePath {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let display = String::deserialize(deserializer)?;
        Self::new(display).map_err(serde::de::Error::custom)
    }
}

/// An immutable filesystem operation.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FilesystemRequest {
    pub context: RequestMetadata,
    pub path: WorkScopePath,
    pub operation: FilesystemOperation,
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum FilesystemOperation {
    Stat,
    Read,
    Write { content_digest: PlatformHandle },
    Remove,
}

impl FilesystemRequest {
    pub fn validate(&self) -> Result<(), PortError> {
        validate_context(&self.context)?;
        validate_text(self.path.as_str(), "path")?;
        match self.operation {
            FilesystemOperation::Stat | FilesystemOperation::Read | FilesystemOperation::Remove => {
                Ok(())
            }
            FilesystemOperation::Write { ref content_digest } => {
                validate_text(content_digest.as_str(), "content_digest")
            }
        }
    }
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FilesystemObservation {
    pub path: WorkScopePath,
    pub kind: FileKind,
    pub size: Option<u64>,
    pub content_digest: Option<PlatformHandle>,
}

#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum FileKind {
    File,
    Directory,
    Symlink,
    Missing,
    Other,
}

/// Filesystem access without path traversal or implementation assumptions.
pub trait FilesystemPort {
    fn execute(&mut self, request: &FilesystemRequest) -> PortOutcome<FilesystemObservation>;
}

/// A service lifecycle request; registration and process control are separate effects.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServiceRequest {
    pub context: RequestMetadata,
    pub service: PlatformHandle,
    pub operation: ServiceOperation,
}

#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ServiceOperation {
    Inspect,
    Register,
    Unregister,
    Start,
    Stop,
}

#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ServiceState {
    Unknown,
    Absent,
    Stopped,
    Starting,
    Running,
    Stopping,
    Failed,
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServiceObservation {
    pub service: PlatformHandle,
    pub state: ServiceState,
    pub generation: Option<u64>,
    pub process: Option<ServiceProcessRecord>,
}

impl ServiceObservation {
    pub fn validate(&self) -> Result<(), PortError> {
        validate_text(self.service.as_str(), "service")?;
        if let Some(process) = &self.process {
            process
                .validate()
                .map_err(|_| PortError::InvalidServiceProcessRecord)?;
        }
        Ok(())
    }
}

impl ServiceRequest {
    pub fn validate(&self) -> Result<(), PortError> {
        validate_context(&self.context)?;
        validate_text(self.service.as_str(), "service")
    }
}
pub trait ServicePort {
    fn execute(&mut self, request: &ServiceRequest) -> PortOutcome<ServiceObservation>;
}

/// A point-in-time clock request. Wall time is never treated as causal order.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClockRequest {
    pub context: RequestMetadata,
}

impl ClockRequest {
    pub fn validate(&self) -> Result<(), PortError> {
        validate_context(&self.context)
    }
}

/// Canonical C0-04 clock shape; external time remains observation, not causal order.
pub type ClockObservation = ClockReading;

pub trait ClockPort {
    fn read(&mut self, request: &ClockRequest) -> PortOutcome<ClockObservation>;
}

/// Secret metadata is observable; secret material is intentionally not a port result.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SecretRequest {
    pub context: RequestMetadata,
    pub reference: SecretReference,
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SecretObservation {
    pub reference: SecretReference,
    pub present: bool,
    pub version: Option<PlatformHandle>,
}

impl SecretRequest {
    pub fn validate(&self) -> Result<(), PortError> {
        validate_context(&self.context)
    }
}
pub trait SecretPort {
    fn inspect(&mut self, request: &SecretRequest) -> PortOutcome<SecretObservation>;
}

/// A notification request has no acknowledgement or resolution authority.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NotificationRequest {
    pub context: RequestMetadata,
    /// Hash of the complete canonical request bytes, supplied by the owning boundary.
    pub canonical_request_hash: PlatformHandle,
    pub notification: PlatformHandle,
    pub audience: PlatformHandle,
    pub body_digest: PlatformHandle,
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NotificationObservation {
    pub notification: PlatformHandle,
    pub delivered: bool,
}

impl NotificationRequest {
    pub fn validate(&self) -> Result<(), PortError> {
        validate_context(&self.context)?;
        validate_text(
            self.canonical_request_hash.as_str(),
            "canonical_request_hash",
        )?;
        validate_text(self.notification.as_str(), "notification")?;
        validate_text(self.audience.as_str(), "audience")?;
        validate_text(self.body_digest.as_str(), "body_digest")
    }
}
pub trait NotificationPort {
    fn deliver(&mut self, request: &NotificationRequest) -> PortOutcome<NotificationObservation>;
}

/// A user-session observation, with no login, elevation or impersonation effect.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionRequest {
    pub context: RequestMetadata,
    pub session: SessionId,
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionObservation {
    pub session: SessionId,
    pub user: Option<PlatformHandle>,
    pub interactive: bool,
}

impl SessionRequest {
    pub fn validate(&self) -> Result<(), PortError> {
        validate_context(&self.context)?;
        validate_text(self.session.as_str(), "session")
    }
}
pub trait SessionPort {
    fn inspect(&mut self, request: &SessionRequest) -> PortOutcome<SessionObservation>;
}

/// Installation metadata/reconciliation request. It does not install or decide release authority.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InstallationRequest {
    pub context: RequestMetadata,
    pub installation: PlatformHandle,
    pub operation: InstallationOperation,
    pub components: Vec<PlatformHandle>,
}

#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum InstallationOperation {
    Inspect,
    Stage,
    Reconcile,
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InstallationObservation {
    pub installation: PlatformHandle,
    pub state: InstallationState,
    pub components: Vec<PlatformHandle>,
}

#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum InstallationState {
    Unknown,
    Absent,
    Staged,
    Present,
    Inconsistent,
}

impl InstallationRequest {
    pub fn validate(&self) -> Result<(), PortError> {
        validate_context(&self.context)?;
        validate_text(self.installation.as_str(), "installation")?;
        unique(&self.components, "components")?;
        if self.components.is_empty() {
            return Err(PortError::Ambiguous {
                field: "components".to_owned(),
            });
        }
        Ok(())
    }
}
pub trait InstallationPort {
    fn execute(&mut self, request: &InstallationRequest) -> PortOutcome<InstallationObservation>;
}

/// Host-local operational installation/process lineage. It carries no project semantics.
/// Exact Host epoch identity persisted alongside the operational projection.
///
/// This deliberately carries the installation, lineage, sequence and nonce
/// that an offline recovery decision must match.  A sequence alone is never
/// sufficient to identify a Host process lineage.
#[derive(
    Clone, Debug, Eq, Hash, JsonSchema, Ord, PartialEq, PartialOrd, Serialize, Deserialize,
)]
#[serde(deny_unknown_fields)]
pub struct HostEpochBinding {
    pub installation: PlatformHandle,
    pub lineage: PlatformHandle,
    pub sequence: u64,
    pub nonce: PlatformHandle,
}

impl HostEpochBinding {
    pub fn validate(&self) -> Result<(), HostStateError> {
        validate_text(self.installation.as_str(), "host_epoch.installation")
            .map_err(|_| HostStateError::InvalidRecord)?;
        validate_text(self.lineage.as_str(), "host_epoch.lineage")
            .map_err(|_| HostStateError::InvalidRecord)?;
        if self.sequence == 0 {
            return Err(HostStateError::InvalidRecord);
        }
        validate_text(self.nonce.as_str(), "host_epoch.nonce")
            .map_err(|_| HostStateError::InvalidRecord)
    }
}

/// Exact disposition of the process's Host Job Object boundary at recovery.
#[derive(
    Clone, Debug, Eq, Hash, JsonSchema, Ord, PartialEq, PartialOrd, Serialize, Deserialize,
)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum HostJobDisposition {
    NotAssigned,
    Assigned { job: PlatformHandle },
    Terminated { job: PlatformHandle },
}

impl HostJobDisposition {
    pub fn validate(&self) -> Result<(), HostStateError> {
        match self {
            Self::NotAssigned => Ok(()),
            Self::Assigned { job } | Self::Terminated { job } => {
                validate_text(job.as_str(), "process_recovery.job")
                    .map_err(|_| HostStateError::InvalidRecord)
            }
        }
    }
}

/// Process identity required to clear a stale Host projection.
#[derive(
    Clone, Debug, Eq, Hash, JsonSchema, Ord, PartialEq, PartialOrd, Serialize, Deserialize,
)]
#[serde(deny_unknown_fields)]
pub struct HostProcessRecoveryBinding {
    pub process_generation: PlatformHandle,
    pub process_id: u32,
    pub image_path: PlatformHandle,
    pub job: HostJobDisposition,
}

impl HostProcessRecoveryBinding {
    pub fn validate(&self) -> Result<(), HostStateError> {
        validate_text(
            self.process_generation.as_str(),
            "process_recovery.process_generation",
        )
        .map_err(|_| HostStateError::InvalidRecord)?;
        if self.process_id == 0 {
            return Err(HostStateError::InvalidRecord);
        }
        validate_text(self.image_path.as_str(), "process_recovery.image_path")
            .map_err(|_| HostStateError::InvalidRecord)?;
        self.job.validate()
    }
}

/// Explicit reason supplied by an operator or an installation authority for
/// clearing a stale Host projection.
#[derive(
    Clone, Copy, Debug, Eq, Hash, JsonSchema, Ord, PartialEq, PartialOrd, Serialize, Deserialize,
)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum HostRecoveryReason {
    UncleanExit,
    OwnerReleaseFailure,
    ReleaseFinalizationFailure,
    OperatorApproved,
}

/// Typed evidence for one exact stale Host projection.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostRecoveryEvidence {
    pub installation: PlatformHandle,
    pub host_epoch: HostEpochBinding,
    pub stale_active_process: ServiceProcessRecord,
    pub process: HostProcessRecoveryBinding,
    pub observed_disposition: HostShutdownDisposition,
    pub reason: HostRecoveryReason,
    pub operator_identity: PlatformHandle,
    pub authority_identity: PlatformHandle,
    pub evidence_refs: Vec<PlatformHandle>,
}

impl HostRecoveryEvidence {
    pub fn validate(&self) -> Result<(), HostStateError> {
        validate_text(self.installation.as_str(), "recovery.installation")
            .map_err(|_| HostStateError::InvalidRecord)?;
        self.host_epoch.validate()?;
        if self.host_epoch.installation != self.installation {
            return Err(HostStateError::InstallationMismatch);
        }
        self.stale_active_process
            .validate()
            .map_err(|_| HostStateError::InvalidRecord)?;
        self.process.validate()?;
        self.observed_disposition.validate()?;
        validate_text(
            self.operator_identity.as_str(),
            "recovery.operator_identity",
        )
        .map_err(|_| HostStateError::InvalidRecord)?;
        validate_text(
            self.authority_identity.as_str(),
            "recovery.authority_identity",
        )
        .map_err(|_| HostStateError::InvalidRecord)?;
        if self.evidence_refs.is_empty()
            || self.evidence_refs.iter().any(|reference| {
                validate_text(reference.as_str(), "recovery.evidence_refs").is_err()
            })
        {
            return Err(HostStateError::InvalidRecord);
        }
        Ok(())
    }
}

/// Durable Host shutdown disposition. `ReleasePending` is intentionally not
/// admission-clean: it remains a recovery gate until release and finalization
/// both succeed.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum HostShutdownDisposition {
    Clean,
    ReleasePending { marker: HostShutdownMarker },
}

impl Default for HostShutdownDisposition {
    fn default() -> Self {
        Self::Clean
    }
}

impl HostShutdownDisposition {
    pub fn validate(&self) -> Result<(), HostStateError> {
        match self {
            Self::Clean => Ok(()),
            Self::ReleasePending { marker } => marker.validate(),
        }
    }

    #[must_use]
    pub const fn is_release_pending(&self) -> bool {
        matches!(self, Self::ReleasePending { .. })
    }
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostInstallationState {
    pub installation: PlatformHandle,
    pub active_process: Option<ServiceProcessRecord>,
    pub managed_dependencies: Vec<ServiceProcessRecord>,
    pub last_clean_shutdown: Option<HostShutdownMarker>,
    #[serde(default)]
    pub disposition: HostShutdownDisposition,
    #[serde(default)]
    pub active_process_recovery: Option<HostProcessRecoveryBinding>,
    #[serde(default)]
    pub last_recovery_evidence: Option<HostRecoveryEvidence>,
}

impl HostInstallationState {
    pub fn validate(&self) -> Result<(), HostStateError> {
        validate_text(self.installation.as_str(), "installation")
            .map_err(|_| HostStateError::InvalidRecord)?;
        if let Some(process) = &self.active_process {
            process
                .validate()
                .map_err(|_| HostStateError::InvalidRecord)?;
        }
        for dependency in &self.managed_dependencies {
            dependency
                .validate()
                .map_err(|_| HostStateError::InvalidRecord)?;
        }
        if let Some(marker) = &self.last_clean_shutdown {
            marker.validate()?;
        }
        self.disposition.validate()?;
        match (&self.active_process, &self.active_process_recovery) {
            (Some(_), Some(recovery)) => recovery.validate()?,
            // Activation is committed before the platform-specific process
            // identity is attached. If the process dies in that narrow
            // window, admission remains recovery-required because the
            // projection is deliberately incomplete rather than guessed.
            (Some(_), None) => {}
            (None, None) => {}
            _ => return Err(HostStateError::InvalidRecord),
        }
        if let Some(evidence) = &self.last_recovery_evidence {
            evidence.validate()?;
            if evidence.installation != self.installation {
                return Err(HostStateError::InstallationMismatch);
            }
        }
        if let HostShutdownDisposition::ReleasePending { marker } = &self.disposition {
            if marker.installation != self.installation
                || self.active_process.as_ref() != Some(&marker.process)
            {
                return Err(HostStateError::InvalidRecord);
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostActivationTransition {
    pub context: RequestMetadata,
    pub installation: PlatformHandle,
    pub process: ServiceProcessRecord,
}

impl HostActivationTransition {
    fn validate(&self) -> Result<(), HostStateError> {
        validate_context(&self.context).map_err(|_| HostStateError::InvalidRecord)?;
        validate_text(self.installation.as_str(), "installation")
            .map_err(|_| HostStateError::InvalidRecord)?;
        self.process
            .validate()
            .map_err(|_| HostStateError::InvalidRecord)
    }
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostActivationReceipt {
    pub request_id: RequestId,
    pub installation: PlatformHandle,
    pub process: ServiceProcessRecord,
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManagedDependencyTransition {
    pub context: RequestMetadata,
    pub installation: PlatformHandle,
    pub dependency: ServiceProcessRecord,
}

impl ManagedDependencyTransition {
    fn validate(&self) -> Result<(), HostStateError> {
        validate_context(&self.context).map_err(|_| HostStateError::InvalidRecord)?;
        validate_text(self.installation.as_str(), "installation")
            .map_err(|_| HostStateError::InvalidRecord)?;
        self.dependency
            .validate()
            .map_err(|_| HostStateError::InvalidRecord)
    }
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManagedDependencyReceipt {
    pub request_id: RequestId,
    pub installation: PlatformHandle,
    pub dependency: ServiceProcessRecord,
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostShutdownMarker {
    pub context: RequestMetadata,
    pub installation: PlatformHandle,
    pub process: ServiceProcessRecord,
}

impl HostShutdownMarker {
    pub fn validate(&self) -> Result<(), HostStateError> {
        validate_context(&self.context).map_err(|_| HostStateError::InvalidRecord)?;
        validate_text(self.installation.as_str(), "installation")
            .map_err(|_| HostStateError::InvalidRecord)?;
        self.process
            .validate()
            .map_err(|_| HostStateError::InvalidRecord)
    }
}

#[derive(Clone, Debug, Eq, Error, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum HostStateError {
    #[error("host installation state is unavailable")]
    Unavailable,
    #[error("host state transition is invalid")]
    InvalidRecord,
    #[error("host state transition targets another installation")]
    InstallationMismatch,
    #[error("host state store synchronization failed")]
    Synchronization,
}

/// Exact Host-only operational state boundary from Implementation P.2.
pub trait HostStateStore: Send + Sync {
    fn load_installation(&self) -> Result<HostInstallationState, HostStateError>;
    fn commit_activation(
        &self,
        transition: HostActivationTransition,
    ) -> Result<HostActivationReceipt, HostStateError>;
    fn record_dependency(
        &self,
        transition: ManagedDependencyTransition,
    ) -> Result<ManagedDependencyReceipt, HostStateError>;
    fn mark_clean_shutdown(&self, marker: HostShutdownMarker) -> Result<(), HostStateError>;
}

/// A deterministic collection of fake ports for contract consumers and negative tests.
#[derive(Default)]
pub struct FakePorts {
    pub filesystem: FakeFilesystem,
    pub service: FakeService,
    pub clock: FakeClock,
    pub secret: FakeSecret,
    pub notification_effects: Vec<NotificationEffectLedger>,
    pub sessions: Vec<SessionObservation>,
    pub installations: Vec<InstallationObservation>,
    pub installation_effects: Vec<RequestId>,
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NotificationEffectLedger {
    pub request_id: RequestId,
    pub canonical_request_hash: PlatformHandle,
    pub observation: NotificationObservation,
}

#[derive(Default)]
pub struct FakeFilesystem {
    pub observations: Vec<FilesystemObservation>,
}
#[derive(Default)]
pub struct FakeService {
    pub observations: Vec<ServiceObservation>,
    pub effects: Vec<RequestId>,
}
#[derive(Default)]
pub struct FakeClock {
    pub reading: Option<ClockObservation>,
}
#[derive(Default)]
pub struct FakeSecret {
    pub observations: Vec<SecretObservation>,
}

fn find<T, F>(items: &[T], matches: F) -> PortOutcome<T>
where
    T: Clone,
    F: Fn(&T) -> bool,
{
    items.iter().find(|item| matches(item)).cloned().map_or(
        PortOutcome::Unknown(UnknownReason::NotObserved),
        PortOutcome::Known,
    )
}

impl FilesystemPort for FakeFilesystem {
    fn execute(&mut self, request: &FilesystemRequest) -> PortOutcome<FilesystemObservation> {
        if let Err(error) = request.validate() {
            return PortOutcome::Error(error);
        }
        find(&self.observations, |item| item.path == request.path)
    }
}
impl ServicePort for FakeService {
    fn execute(&mut self, request: &ServiceRequest) -> PortOutcome<ServiceObservation> {
        if let Err(error) = request.validate() {
            return PortOutcome::Error(error);
        }
        let outcome = find(&self.observations, |item| item.service == request.service);
        if let PortOutcome::Known(observation) = &outcome
            && let Err(error) = observation.validate()
        {
            return PortOutcome::Error(error);
        }
        if request.operation != ServiceOperation::Inspect {
            self.effects.push(request.context.request_id.clone());
        }
        outcome
    }
}
impl ClockPort for FakeClock {
    fn read(&mut self, request: &ClockRequest) -> PortOutcome<ClockObservation> {
        if let Err(error) = request.validate() {
            return PortOutcome::Error(error);
        }
        match self.reading {
            None => PortOutcome::Unknown(UnknownReason::NotObserved),
            Some(reading)
                if reading.valid_time_ms.is_none()
                    && reading.known_time_ms.is_none()
                    && reading.transaction_sequence.is_none()
                    && reading.monotonic_ns.is_none() =>
            {
                PortOutcome::Unknown(UnknownReason::Indeterminate)
            }
            Some(reading) => PortOutcome::Known(reading),
        }
    }
}
impl SecretPort for FakeSecret {
    fn inspect(&mut self, request: &SecretRequest) -> PortOutcome<SecretObservation> {
        if let Err(error) = request.validate() {
            return PortOutcome::Error(error);
        }
        find(&self.observations, |item| {
            item.reference == request.reference
        })
    }
}
impl NotificationPort for FakePorts {
    fn deliver(&mut self, request: &NotificationRequest) -> PortOutcome<NotificationObservation> {
        if let Err(error) = request.validate() {
            return PortOutcome::Error(error);
        }
        let request_id = request.context.request_id.clone();
        if let Some(effect) = self
            .notification_effects
            .iter()
            .find(|effect| effect.request_id == request_id)
        {
            if effect.canonical_request_hash != request.canonical_request_hash {
                return PortOutcome::Error(PortError::IdentityConflict);
            }
            return PortOutcome::Known(effect.observation.clone());
        }
        let observation = NotificationObservation {
            notification: request.notification.clone(),
            delivered: true,
        };
        self.notification_effects.push(NotificationEffectLedger {
            request_id,
            canonical_request_hash: request.canonical_request_hash.clone(),
            observation: observation.clone(),
        });
        PortOutcome::Known(observation)
    }
}
impl SessionPort for FakePorts {
    fn inspect(&mut self, request: &SessionRequest) -> PortOutcome<SessionObservation> {
        if let Err(error) = request.validate() {
            return PortOutcome::Error(error);
        }
        find(&self.sessions, |item| item.session == request.session)
    }
}
impl InstallationPort for FakePorts {
    fn execute(&mut self, request: &InstallationRequest) -> PortOutcome<InstallationObservation> {
        if let Err(error) = request.validate() {
            return PortOutcome::Error(error);
        }
        let outcome = find(&self.installations, |item| {
            item.installation == request.installation
        });
        if request.operation != InstallationOperation::Inspect {
            self.installation_effects
                .push(request.context.request_id.clone());
        }
        outcome
    }
}

pub struct FakeHostStateStore {
    state: Mutex<HostInstallationState>,
}

impl FakeHostStateStore {
    pub fn new(state: HostInstallationState) -> Result<Self, HostStateError> {
        state.validate()?;
        Ok(Self {
            state: Mutex::new(state),
        })
    }
}

impl HostStateStore for FakeHostStateStore {
    fn load_installation(&self) -> Result<HostInstallationState, HostStateError> {
        self.state
            .lock()
            .map_err(|_| HostStateError::Synchronization)
            .map(|state| state.clone())
    }

    fn commit_activation(
        &self,
        transition: HostActivationTransition,
    ) -> Result<HostActivationReceipt, HostStateError> {
        transition.validate()?;
        let mut state = self
            .state
            .lock()
            .map_err(|_| HostStateError::Synchronization)?;
        if state.installation != transition.installation {
            return Err(HostStateError::InstallationMismatch);
        }
        state.active_process = Some(transition.process.clone());
        state.last_clean_shutdown = None;
        state.last_recovery_evidence = None;
        state.disposition = HostShutdownDisposition::Clean;
        state.active_process_recovery = None;
        Ok(HostActivationReceipt {
            request_id: transition.context.request_id,
            installation: transition.installation,
            process: transition.process,
        })
    }

    fn record_dependency(
        &self,
        transition: ManagedDependencyTransition,
    ) -> Result<ManagedDependencyReceipt, HostStateError> {
        transition.validate()?;
        let mut state = self
            .state
            .lock()
            .map_err(|_| HostStateError::Synchronization)?;
        if state.installation != transition.installation {
            return Err(HostStateError::InstallationMismatch);
        }
        if let Some(existing) = state
            .managed_dependencies
            .iter_mut()
            .find(|record| record.process_id == transition.dependency.process_id)
        {
            *existing = transition.dependency.clone();
        } else {
            state
                .managed_dependencies
                .push(transition.dependency.clone());
        }
        Ok(ManagedDependencyReceipt {
            request_id: transition.context.request_id,
            installation: transition.installation,
            dependency: transition.dependency,
        })
    }

    fn mark_clean_shutdown(&self, marker: HostShutdownMarker) -> Result<(), HostStateError> {
        marker.validate()?;
        let mut state = self
            .state
            .lock()
            .map_err(|_| HostStateError::Synchronization)?;
        if state.installation != marker.installation {
            return Err(HostStateError::InstallationMismatch);
        }
        state.active_process = None;
        state.active_process_recovery = None;
        state.disposition = HostShutdownDisposition::Clean;
        state.last_clean_shutdown = Some(marker);
        state.last_recovery_evidence = None;
        Ok(())
    }
}

impl fmt::Display for PlatformHandle {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use eliot_contracts::{AuthorityEpoch, ProductId, ResourceGeneration, SourceId, StateFence};
    use eliot_runtime_contracts::{HealthVector, ServiceProcessState};

    fn context(request_id: &str) -> RequestMetadata {
        RequestMetadata {
            request_id: RequestId::new(request_id).unwrap_or_else(|_| unreachable!()),
            session_id: None,
            task_id: None,
            product_id: ProductId::new("product-1").unwrap_or_else(|_| unreachable!()),
            source_id: SourceId::new("source-1").unwrap_or_else(|_| unreachable!()),
            state_fence: StateFence::new(AuthorityEpoch::genesis(), ResourceGeneration::genesis()),
            clock: ClockReading::default(),
        }
    }

    fn handle(value: &str) -> PlatformHandle {
        PlatformHandle::new(value).unwrap_or_else(|_| unreachable!())
    }

    fn process(process_id: &str, owner: &str, state: ServiceProcessState) -> ServiceProcessRecord {
        ServiceProcessRecord {
            process_id: process_id.to_owned(),
            owner: owner.to_owned(),
            state,
            health: HealthVector::healthy(),
            authority_epoch: AuthorityEpoch::genesis(),
        }
    }

    fn notification(request_id: &str, hash: &str, body: &str) -> NotificationRequest {
        NotificationRequest {
            context: context(request_id),
            canonical_request_hash: handle(hash),
            notification: handle("notice-1"),
            audience: handle("user-1"),
            body_digest: handle(body),
        }
    }

    #[test]
    fn rejects_blank_duplicate_and_ambiguous_inputs() {
        assert!(PlatformHandle::new(" ").is_err());
        let request = InstallationRequest {
            context: context("request-1"),
            installation: handle("install"),
            operation: InstallationOperation::Stage,
            components: vec![handle("a"), handle("a")],
        };
        assert!(matches!(
            request.validate(),
            Err(PortError::Duplicate { .. })
        ));
        let request = InstallationRequest {
            context: context("request-2"),
            installation: handle("install"),
            operation: InstallationOperation::Inspect,
            components: Vec::new(),
        };
        assert!(matches!(
            request.validate(),
            Err(PortError::Ambiguous { .. })
        ));
    }

    #[test]
    fn path_deserialization_validates_and_binds_display_to_normalized_identity() {
        for value in [
            "",
            "/root",
            "C:\\root",
            "\\\\server\\share",
            "a/../b",
            "..\\b",
        ] {
            assert!(WorkScopePath::new(value).is_err(), "accepted {value}");
            let encoded = serde_json::to_string(value).unwrap_or_else(|_| unreachable!());
            assert!(serde_json::from_str::<WorkScopePath>(&encoded).is_err());
        }
        let windows = WorkScopePath::new(".\\src\\main.rs").unwrap_or_else(|_| unreachable!());
        let portable = WorkScopePath::new("src/main.rs").unwrap_or_else(|_| unreachable!());
        assert_eq!(windows.as_str(), ".\\src\\main.rs");
        assert_eq!(windows.normalized_identity(), "src/main.rs");
        assert_eq!(windows, portable);
        let encoded = serde_json::to_string(&windows).unwrap_or_else(|_| unreachable!());
        let decoded: WorkScopePath =
            serde_json::from_str(&encoded).unwrap_or_else(|_| unreachable!());
        assert_eq!(decoded.as_str(), windows.as_str());
        assert_eq!(decoded, windows);
        assert_eq!(
            windows.adapter_input().containment,
            AdapterContainment::ReparseAndProveWithinWorkScope
        );
    }

    #[test]
    fn empty_clock_observation_is_not_known() {
        let request = ClockRequest {
            context: context("clock"),
        };
        let mut fake = FakeClock {
            reading: Some(ClockReading::default()),
        };
        assert!(matches!(
            fake.read(&request),
            PortOutcome::Unknown(UnknownReason::Indeterminate)
        ));
        fake.reading = Some(ClockReading {
            monotonic_ns: Some(1),
            ..ClockReading::default()
        });
        assert!(matches!(fake.read(&request), PortOutcome::Known(_)));
    }

    #[test]
    fn public_outcomes_errors_and_canonical_context_roundtrip() {
        let outcome = PortOutcome::<PlatformHandle>::Error(PortError::Provider(ProviderError {
            code: ProviderErrorCode::Unavailable,
            retryable: true,
        }));
        assert!(matches!(
            outcome,
            PortOutcome::Error(PortError::Provider(_))
        ));
        assert!(!format!("{:?}", schemars::schema_for!(PortOutcome<PlatformHandle>)).is_empty());
        assert!(!format!("{:?}", schemars::schema_for!(SourceEffectCeiling)).is_empty());
        assert!(context("canonical-context").validate().is_ok());
    }

    #[test]
    fn all_seven_fakes_bind_requested_identity_and_record_effects() {
        let mut ports = FakePorts::default();
        let path = WorkScopePath::new("a.txt").unwrap_or_else(|_| unreachable!());
        ports.filesystem.observations.push(FilesystemObservation {
            path: path.clone(),
            kind: FileKind::File,
            size: Some(3),
            content_digest: Some(handle("file-hash")),
        });
        ports.service.observations.push(ServiceObservation {
            service: handle("svc"),
            state: ServiceState::Running,
            generation: Some(1),
            process: Some(process("pid-1", "Host", ServiceProcessState::Ready)),
        });
        ports.clock.reading = Some(ClockReading {
            known_time_ms: Some(10),
            ..ClockReading::default()
        });
        let secret = SecretReference::new("vault", "key").unwrap_or_else(|_| unreachable!());
        ports.secret.observations.push(SecretObservation {
            reference: secret.clone(),
            present: true,
            version: Some(handle("v1")),
        });
        let session = SessionId::new("session-1").unwrap_or_else(|_| unreachable!());
        ports.sessions.push(SessionObservation {
            session: session.clone(),
            user: Some(handle("user-1")),
            interactive: true,
        });
        ports.installations.push(InstallationObservation {
            installation: handle("install-1"),
            state: InstallationState::Present,
            components: vec![handle("component-1")],
        });

        assert!(matches!(
            ports.filesystem.execute(&FilesystemRequest {
                context: context("filesystem"),
                path,
                operation: FilesystemOperation::Stat
            }),
            PortOutcome::Known(_)
        ));
        assert!(matches!(
            ports.service.execute(&ServiceRequest {
                context: context("service"),
                service: handle("svc"),
                operation: ServiceOperation::Start
            }),
            PortOutcome::Known(_)
        ));
        assert_eq!(ports.service.effects.len(), 1);
        assert!(matches!(
            ports.clock.read(&ClockRequest {
                context: context("clock")
            }),
            PortOutcome::Known(_)
        ));
        assert!(matches!(
            ports.secret.inspect(&SecretRequest {
                context: context("secret"),
                reference: secret
            }),
            PortOutcome::Known(_)
        ));
        assert!(matches!(
            ports.deliver(&notification("notification", "hash-1", "body-1")),
            PortOutcome::Known(_)
        ));
        assert!(matches!(
            ports.inspect(&SessionRequest {
                context: context("session"),
                session
            }),
            PortOutcome::Known(_)
        ));
        assert!(matches!(
            ports.execute(&InstallationRequest {
                context: context("installation"),
                installation: handle("install-1"),
                operation: InstallationOperation::Reconcile,
                components: vec![handle("component-1")]
            }),
            PortOutcome::Known(_)
        ));
        assert_eq!(ports.installation_effects.len(), 1);
        assert!(matches!(
            PortOutcome::Partial {
                value: handle("v"),
                missing: vec![handle("m")]
            },
            PortOutcome::Partial { .. }
        ));
        assert!(matches!(
            PortOutcome::<PlatformHandle>::Unknown(UnknownReason::Unsupported),
            PortOutcome::Unknown(UnknownReason::Unsupported)
        ));
    }

    #[test]
    fn notification_ledger_replays_same_hash_and_rejects_identity_conflict() {
        let mut fake = FakePorts::default();
        let request = notification("delivery", "hash-1", "digest-1");
        assert!(matches!(fake.deliver(&request), PortOutcome::Known(_)));
        assert!(matches!(fake.deliver(&request), PortOutcome::Known(_)));
        assert_eq!(fake.notification_effects.len(), 1);
        let changed = notification("delivery", "hash-2", "digest-2");
        assert!(matches!(
            fake.deliver(&changed),
            PortOutcome::Error(PortError::IdentityConflict)
        ));
        assert_eq!(fake.notification_effects.len(), 1);
    }

    #[test]
    fn session_and_installation_fakes_do_not_return_another_identity() {
        let mut ports = FakePorts::default();
        ports.sessions.push(SessionObservation {
            session: SessionId::new("session-a").unwrap_or_else(|_| unreachable!()),
            user: None,
            interactive: false,
        });
        ports.installations.push(InstallationObservation {
            installation: handle("installation-a"),
            state: InstallationState::Present,
            components: vec![handle("component")],
        });
        assert!(matches!(
            ports.inspect(&SessionRequest {
                context: context("session-miss"),
                session: SessionId::new("session-b").unwrap_or_else(|_| unreachable!()),
            }),
            PortOutcome::Unknown(UnknownReason::NotObserved)
        ));
        assert!(matches!(
            ports.execute(&InstallationRequest {
                context: context("installation-miss"),
                installation: handle("installation-b"),
                operation: InstallationOperation::Inspect,
                components: vec![handle("component")],
            }),
            PortOutcome::Unknown(UnknownReason::NotObserved)
        ));
    }

    #[test]
    fn host_state_store_exposes_exact_operational_methods_and_rejects_cross_installation() {
        let installation = handle("installation-1");
        let store = FakeHostStateStore::new(HostInstallationState {
            installation: installation.clone(),
            active_process: None,
            managed_dependencies: Vec::new(),
            last_clean_shutdown: None,
            disposition: HostShutdownDisposition::Clean,
            active_process_recovery: None,
            last_recovery_evidence: None,
        })
        .unwrap_or_else(|_| unreachable!());
        let host = process("host-1", "Host", ServiceProcessState::Ready);
        let activation = store
            .commit_activation(HostActivationTransition {
                context: context("activation"),
                installation: installation.clone(),
                process: host.clone(),
            })
            .unwrap_or_else(|_| unreachable!());
        assert_eq!(activation.process, host);
        let dependency = process("store-1", "CanonicalStore", ServiceProcessState::Ready);
        store
            .record_dependency(ManagedDependencyTransition {
                context: context("dependency"),
                installation: installation.clone(),
                dependency: dependency.clone(),
            })
            .unwrap_or_else(|_| unreachable!());
        assert_eq!(
            store
                .load_installation()
                .unwrap_or_else(|_| unreachable!())
                .managed_dependencies,
            vec![dependency]
        );
        assert!(matches!(
            store.commit_activation(HostActivationTransition {
                context: context("wrong-installation"),
                installation: handle("installation-2"),
                process: host.clone(),
            }),
            Err(HostStateError::InstallationMismatch)
        ));
        store
            .mark_clean_shutdown(HostShutdownMarker {
                context: context("shutdown"),
                installation,
                process: host,
            })
            .unwrap_or_else(|_| unreachable!());
        let final_state = store.load_installation().unwrap_or_else(|_| unreachable!());
        assert!(final_state.active_process.is_none());
        assert!(final_state.last_clean_shutdown.is_some());
    }

    #[test]
    fn malformed_service_process_is_typed_error() {
        let mut fake = FakeService {
            observations: vec![ServiceObservation {
                service: handle("svc"),
                state: ServiceState::Running,
                generation: Some(1),
                process: Some(process(" ", "Host", ServiceProcessState::Ready)),
            }],
            effects: Vec::new(),
        };
        assert!(matches!(
            fake.execute(&ServiceRequest {
                context: context("service-invalid"),
                service: handle("svc"),
                operation: ServiceOperation::Inspect,
            }),
            PortOutcome::Error(PortError::InvalidServiceProcessRecord)
        ));
    }
}
