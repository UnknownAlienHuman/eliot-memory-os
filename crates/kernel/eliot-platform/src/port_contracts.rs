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

use super::guard_outcome::GuardOutcomeError;
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

/// Carries a rejected guard-revert composite through the neutral typed
/// observation without a second error registry.
///
/// A package-staging/installation caller that receives a `GuardRevertOutcome`
/// it cannot accept validates the composite first: the composite itself
/// travels to the durable transaction record before any dependent retry or
/// rollback, and only the typed rejection travels through `PortOutcome::Error`
/// via this conversion. Each arm maps one `GuardOutcomeError` variant onto
/// the one existing `PortError` shape that already means the same thing, so
/// no new variant, crate, or error-code registry is introduced.
///
/// I2.6 requires that "An error preserves: operation identity; ...
/// known/unknown effect status; raw evidence handle" together with
/// retryability semantics. The operation identity and the raw evidence handle
/// stay with the retained composite; this conversion preserves the effect
/// status as a typed error and carries explicit retryability on each
/// provider arm. I7.20 requires a stable disposition plus an exact
/// machine-readable cause on every non-success response: the stable
/// `ProviderErrorCode` below is the disposition callers switch on, while the
/// originating `GuardOutcomeError` variant named on each arm is the exact
/// cause. I5.19 states "Unknown commit is never retried blindly" and forbids
/// fabricating a final receipt while an effect is unknown, and A13.2 turns
/// repeated failure into a Problem State "rather than an endless restart
/// loop"; both provider arms are therefore `retryable: false`, and #1148
/// step 3 authorizes no new automatic retry from this payload. In
/// particular an unproven-safe OS state surfaces as `Failed`, never as a
/// success observation, and must reconcile retained evidence.
///
/// This is a pure stack mapping: it performs no IO, acquires no resource,
/// spawns nothing, and carries no secret or protected payload bytes.
impl From<GuardOutcomeError> for PortError {
    fn from(error: GuardOutcomeError) -> Self {
        match error {
            GuardOutcomeError::InvalidOperationContext => PortError::InvalidRequestMetadata,
            GuardOutcomeError::InvalidReference => PortError::InvalidText {
                field: "guard_outcome.reference".to_owned(),
            },
            GuardOutcomeError::InvalidRestorationAttempt => PortError::Provider(ProviderError {
                code: ProviderErrorCode::InvalidRequest,
                retryable: false,
            }),
            GuardOutcomeError::UnsafeContinuation => PortError::Provider(ProviderError {
                code: ProviderErrorCode::Failed,
                retryable: false,
            }),
        }
    }
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

/// A scheduled provider timer: an identity, one operation, and the bounded
/// trigger reference and arguments the provider needs to arm it.
///
/// The contract carries no command, executable path, account, logon token,
/// credential, cadence, or durable schedule. I1.7 names Task Scheduler and its
/// future `systemd` timer equivalent as one row, so the identity and the
/// effect are the only things both providers have to agree on.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TimerRequest {
    pub context: RequestMetadata,
    /// Opaque bounded reference to the timer identity in the provider.
    pub timer: PlatformHandle,
    pub operation: TimerOperation,
    /// Opaque bounded reference to the trigger to arm. The provider owns its
    /// own trigger vocabulary; this contract names no trigger, interval, or
    /// start time and never derives one.
    pub trigger: Option<PlatformHandle>,
    /// Bounded opaque references the provider passes to the timer action.
    /// This is an opaque argument list, not a command line.
    pub arguments: Vec<PlatformHandle>,
}

/// The three bounded scheduler effects: observe a timer, arm it, remove it.
///
/// There is deliberately no "run now" operation. A trigger owns when a timer
/// fires, and granting a separate manual start here would be a second
/// authority over the same effect.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum TimerOperation {
    /// Observe the current state without changing the timer.
    Inspect,
    /// Establish the named timer with the supplied trigger and arguments.
    Schedule,
    /// Remove the timer from the provider and disarm its trigger.
    Unregister,
}

/// The provider-observed state of one scheduled timer.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum TimerState {
    /// The provider could not classify the timer.
    Unknown,
    /// The provider has no timer for this identity.
    Absent,
    /// The timer is registered and the provider will trigger it.
    Registered,
    /// The provider has an active invocation of the timer right now.
    Running,
    /// The timer is registered but the provider will not trigger it.
    Disabled,
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TimerObservation {
    /// The timer this observation is about, echoed as the request named it.
    pub timer: PlatformHandle,
    pub state: TimerState,
    /// The provider-established generation of the timer, when the provider
    /// can establish one. Absent is not zero and never means "unchanged".
    pub generation: Option<u64>,
}

impl TimerRequest {
    pub fn validate(&self) -> Result<(), PortError> {
        validate_context(&self.context)?;
        validate_text(self.timer.as_str(), "timer")?;
        if let Some(trigger) = &self.trigger {
            validate_text(trigger.as_str(), "trigger")?;
        }
        unique(&self.arguments, "arguments")
    }
}

/// Timer registration, observation and removal as one bounded effect.
///
/// The trait names the effect and the observation; it does not own a
/// scheduler, a recurring horizon, a retry, a durable schedule, or the
/// authority to start a process when a trigger fires. `Known` means the
/// provider established the reported state, not that the timer is correct.
pub trait TimerPort {
    fn execute(&mut self, request: &TimerRequest) -> PortOutcome<TimerObservation>;
}

/// The bounded resource ceilings installed on a containment.
///
/// Every field is optional and absent means the provider installs no such
/// ceiling. No default, fallback, or substitute ceiling is implied anywhere.
/// I1.6 requires that "CPU, memory, and process limits are set by Module
/// Manifest", so the values arrive from the owning manifest; this contract
/// derives none.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProcessResourceLimits {
    pub cpu_time_ms: Option<u64>,
    pub memory_bytes: Option<u64>,
    pub active_process_limit: Option<u32>,
}

/// A named process containment and its resource ceilings, as one bounded
/// effect.
///
/// I1.6 keeps "a separate Job Object is created for each failure domain and
/// Module generation" and requires that "all child processes enter the
/// applicable Windows Job Object". This request is the provider-neutral shape
/// of exactly that effect, so a future cgroup or process-group implementation
/// substitutes into it rather than inventing one.
///
/// `Inspect` observes; `Create` establishes the named containment and installs
/// its limits; `Assign` places one process under the established containment;
/// `Terminate` ends the processes currently inside it. The contract carries no
/// process identifier, handle, or path, and it grants no termination or
/// resource authority of its own.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProcessContainmentRequest {
    pub context: RequestMetadata,
    /// Opaque bounded reference to the named containment identity.
    pub containment: PlatformHandle,
    pub operation: ProcessContainmentOperation,
    /// Opaque bounded reference to the one process to place under the
    /// containment. Used by `Assign`.
    pub process: Option<PlatformHandle>,
    /// The ceilings to install. Used by `Create`.
    pub limits: Option<ProcessResourceLimits>,
}

/// The four bounded containment effects: observe a containment, establish it,
/// place a process in it, end what is inside it.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ProcessContainmentOperation {
    /// Observe the containment without changing membership or ceilings.
    Inspect,
    /// Establish the named containment and install the supplied ceilings
    /// before any process is assigned.
    Create,
    /// Place one already-running process under the established containment.
    Assign,
    /// End every process currently inside the containment.
    Terminate,
}

/// The provider-observed state of one containment.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ProcessContainmentState {
    /// The provider could not classify the containment.
    Unknown,
    /// The provider has no containment for this identity.
    Absent,
    /// The containment exists with at least one live process inside it.
    Active,
    /// The containment exists and was observed with no live process inside it.
    Empty,
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProcessContainmentObservation {
    /// The containment this observation is about, echoed as the request named
    /// it.
    pub containment: PlatformHandle,
    pub state: ProcessContainmentState,
    /// The ceilings the provider actually installed, not the ceilings that
    /// were requested. Absent means none was installed or none is observable.
    pub limits: Option<ProcessResourceLimits>,
    /// The live process count the provider observed inside the containment.
    /// It is an observation at one moment and is never a membership claim
    /// about processes the provider did not see.
    pub active_processes: u32,
}

impl ProcessContainmentRequest {
    pub fn validate(&self) -> Result<(), PortError> {
        validate_context(&self.context)?;
        validate_text(self.containment.as_str(), "containment")?;
        if let Some(process) = &self.process {
            validate_text(process.as_str(), "process")?;
        }
        Ok(())
    }
}

/// A named containment, its resource ceilings, and its process membership as
/// one bounded effect.
///
/// The trait names the effect and the observation. It creates no containment,
/// holds no handle, and cannot itself terminate a process; the adapter and
/// the owning control plane retain that authority.
///
/// This is deliberately distinct from the fault-guard `ContainmentRequest` and
/// `ContainmentObservation` in this crate: those record what a guard owner
/// requested and what an independent reader observed after the fact, and
/// neither of them requests this effect.
pub trait ContainmentPort {
    fn execute(
        &mut self,
        request: &ProcessContainmentRequest,
    ) -> PortOutcome<ProcessContainmentObservation>;
}
