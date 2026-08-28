//! Generic platform port contracts and passive observations.
//!
//! Architecture A2.3 keeps functional, source, runtime, and deployment
//! boundaries from transferring authority. Implementation I1.8 keeps
//! ownership and call paths explicit while adapters expose bounded platform
//! effects. Implementation I2.1 means module/crate packaging transfers no
//! lifecycle, mutable-state, or authority.
//!
//! This module owns passive port contracts and errors only. It performs no
//! provider execution, external effect, lifecycle, durable state, or admission
//! authority; concrete adapters and the control plane retain those concerns.

use std::collections::BTreeSet;

use eliot_contracts::{ClockReading, RequestMetadata, SessionId};
use eliot_runtime_contracts::ServiceProcessRecord;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use super::{PlatformHandle, WorkScopePath};

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
    #[error("provider error at {reference}: {error:?}")]
    ProviderReference {
        error: ProviderError,
        reference: PlatformHandle,
    },
}

pub(super) fn validate_text(value: &str, field: &'static str) -> Result<(), PortError> {
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

pub(super) fn validate_context(context: &RequestMetadata) -> Result<(), PortError> {
    context
        .validate()
        .map_err(|_| PortError::InvalidRequestMetadata)
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
