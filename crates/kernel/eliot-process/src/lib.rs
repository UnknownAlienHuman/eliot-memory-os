//! P-03: the provider-neutral process contract.
//!
//! This crate is deliberately pure.  It does not spawn, inspect OS handles,
//! read credentials, or choose an authority owner.  P-04 supplies the
//! Windows implementation and the branch owner supplies the effect permit.

use blake3::Hash;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::sync::Arc;
use thiserror::Error;

pub const PROCESS_CONTRACT_SCHEMA_VERSION: &str = "eliot-process-contract-v1";
pub const PROCESS_IMPLEMENTATION_ID: &str = "eliot.process.windows.v1";

const MAX_ID_BYTES: usize = 256;
const MAX_ARGUMENTS: usize = 4096;
const MAX_ENVIRONMENT_ENTRIES: usize = 512;
const MAX_DESCENDANTS: usize = 4096;

/// An opaque, non-secret operation identity.
#[derive(
    Clone, Debug, Eq, Hash, JsonSchema, Ord, PartialEq, PartialOrd, Serialize, Deserialize,
)]
#[serde(transparent)]
pub struct OperationId(String);

/// An opaque process-tree identity owned by the caller of the contract.
#[derive(
    Clone, Debug, Eq, Hash, JsonSchema, Ord, PartialEq, PartialOrd, Serialize, Deserialize,
)]
#[serde(transparent)]
pub struct ProcessTreeId(String);

/// The identity of one physical process generation.
#[derive(
    Clone, Debug, Eq, Hash, JsonSchema, Ord, PartialEq, PartialOrd, Serialize, Deserialize,
)]
#[serde(transparent)]
pub struct ProcessId(String);

/// A reference to a secret provider entry.  It never contains the secret.
#[derive(Clone, Debug, Eq, JsonSchema, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SecretRef {
    provider: String,
    key: String,
}

impl OperationId {
    /// Creates an opaque operation identity.
    pub fn new(value: impl Into<String>) -> Result<Self, ContractError> {
        validate_opaque_id("operation_id", value.into()).map(Self)
    }

    /// Returns the wire value.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl ProcessTreeId {
    /// Creates an opaque process-tree identity.
    pub fn new(value: impl Into<String>) -> Result<Self, ContractError> {
        validate_opaque_id("process_tree_id", value.into()).map(Self)
    }

    /// Returns the wire value.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl ProcessId {
    /// Creates an opaque physical process identity.
    pub fn new(value: impl Into<String>) -> Result<Self, ContractError> {
        validate_opaque_id("process_id", value.into()).map(Self)
    }

    /// Returns the wire value.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl SecretRef {
    /// Creates a provider/key reference without materialising the secret.
    pub fn new(provider: impl Into<String>, key: impl Into<String>) -> Result<Self, ContractError> {
        let provider = validate_opaque_id("secret_provider", provider.into())?;
        let key = validate_opaque_id("secret_key", key.into())?;
        Ok(Self { provider, key })
    }

    /// Returns the provider identifier.
    pub fn provider(&self) -> &str {
        &self.provider
    }

    /// Returns the non-secret key identifier.
    pub fn key(&self) -> &str {
        &self.key
    }
}

/// A monotonically increasing execution generation.
#[derive(
    Clone, Copy, Debug, Default, Eq, JsonSchema, Ord, PartialEq, PartialOrd, Serialize, Deserialize,
)]
#[serde(transparent)]
pub struct Generation(u64);

impl Generation {
    /// Creates a non-zero generation.
    pub const fn new(value: u64) -> Result<Self, ContractError> {
        if value == 0 {
            Err(ContractError::InvalidValue {
                field: "generation",
                reason: "must be non-zero",
            })
        } else {
            Ok(Self(value))
        }
    }

    /// Returns the generation number.
    pub const fn get(self) -> u64 {
        self.0
    }
}

/// An authority/fence snapshot supplied by the owning control plane.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FencingToken {
    authority_epoch: u64,
    generation: Generation,
    nonce: String,
}

impl FencingToken {
    /// Creates a fence token.  The nonce is an opaque non-secret correlation value.
    pub fn new(
        authority_epoch: u64,
        generation: Generation,
        nonce: impl Into<String>,
    ) -> Result<Self, ContractError> {
        if authority_epoch == 0 {
            return Err(ContractError::InvalidValue {
                field: "authority_epoch",
                reason: "must be non-zero",
            });
        }
        Ok(Self {
            authority_epoch,
            generation,
            nonce: validate_opaque_id("fence_nonce", nonce.into())?,
        })
    }

    /// Returns the authority epoch.
    pub const fn authority_epoch(&self) -> u64 {
        self.authority_epoch
    }

    /// Returns the generation covered by this fence.
    pub const fn generation(&self) -> Generation {
        self.generation
    }

    /// Returns the opaque nonce.
    pub fn nonce(&self) -> &str {
        &self.nonce
    }

    /// Checks exact equality with another fence.
    pub fn matches(&self, other: &Self) -> bool {
        self == other
    }
}

/// How the child receives environment values.
#[derive(Clone, Copy, Debug, Default, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EnvironmentInheritance {
    /// The child receives only values explicitly present in `non_secret`.
    #[default]
    None,
    /// The executor may merge a platform allowlist; it may not inherit secrets.
    Allowlisted,
}

/// A secret-safe environment projection.  Secret material is never serialised here.
#[derive(Clone, Debug, Default, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnvironmentProjection {
    #[serde(default)]
    non_secret: BTreeMap<String, String>,
    #[serde(default)]
    secret_refs: Vec<SecretRef>,
    #[serde(default)]
    inheritance: EnvironmentInheritance,
}

impl EnvironmentProjection {
    /// Builds a projection and rejects secret-like names in the non-secret map.
    pub fn new(
        non_secret: BTreeMap<String, String>,
        secret_refs: Vec<SecretRef>,
        inheritance: EnvironmentInheritance,
    ) -> Result<Self, ContractError> {
        if non_secret.len() > MAX_ENVIRONMENT_ENTRIES {
            return Err(ContractError::LimitExceeded {
                field: "non_secret_environment",
                limit: MAX_ENVIRONMENT_ENTRIES,
            });
        }
        for (name, value) in &non_secret {
            validate_environment_name(name)?;
            if is_secret_like(name) || looks_like_secret_value(value) {
                return Err(ContractError::SecretBoundary {
                    field: "non_secret_environment",
                });
            }
        }
        let mut refs = BTreeSet::new();
        for reference in &secret_refs {
            if !refs.insert((reference.provider.clone(), reference.key.clone())) {
                return Err(ContractError::DuplicateValue {
                    field: "secret_refs",
                });
            }
        }
        Ok(Self {
            non_secret,
            secret_refs,
            inheritance,
        })
    }

    /// Returns non-secret values.
    pub fn non_secret(&self) -> &BTreeMap<String, String> {
        &self.non_secret
    }

    /// Returns opaque secret references, never values.
    pub fn secret_refs(&self) -> &[SecretRef] {
        &self.secret_refs
    }

    /// Returns the inheritance policy.
    pub const fn inheritance(&self) -> EnvironmentInheritance {
        self.inheritance
    }

    fn validate(&self) -> Result<(), ContractError> {
        Self::new(
            self.non_secret.clone(),
            self.secret_refs.clone(),
            self.inheritance,
        )
        .map(|_| ())
    }
}

/// Resource ceilings passed to the physical implementation.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResourceLimits {
    wall_timeout_ms: u64,
    cpu_time_ms: Option<u64>,
    memory_bytes: Option<u64>,
    stdout_bytes: u64,
    stderr_bytes: u64,
    max_descendants: u32,
}

impl ResourceLimits {
    /// Creates bounded resource limits.  Output limits are mandatory and non-zero.
    pub const fn new(
        wall_timeout_ms: u64,
        cpu_time_ms: Option<u64>,
        memory_bytes: Option<u64>,
        stdout_bytes: u64,
        stderr_bytes: u64,
        max_descendants: u32,
    ) -> Result<Self, ContractError> {
        if wall_timeout_ms == 0 || stdout_bytes == 0 || stderr_bytes == 0 {
            return Err(ContractError::InvalidValue {
                field: "resource_limits",
                reason: "timeouts and stream limits must be non-zero",
            });
        }
        if let Some(value) = cpu_time_ms
            && value == 0
        {
            return Err(ContractError::InvalidValue {
                field: "cpu_time_ms",
                reason: "must be non-zero when present",
            });
        }
        if let Some(value) = memory_bytes
            && value == 0
        {
            return Err(ContractError::InvalidValue {
                field: "memory_bytes",
                reason: "must be non-zero when present",
            });
        }
        Ok(Self {
            wall_timeout_ms,
            cpu_time_ms,
            memory_bytes,
            stdout_bytes,
            stderr_bytes,
            max_descendants,
        })
    }

    /// Returns the wall-clock ceiling.
    pub const fn wall_timeout_ms(&self) -> u64 {
        self.wall_timeout_ms
    }

    /// Returns the CPU ceiling, if one was supplied.
    pub const fn cpu_time_ms(&self) -> Option<u64> {
        self.cpu_time_ms
    }

    /// Returns the memory ceiling, if one was supplied.
    pub const fn memory_bytes(&self) -> Option<u64> {
        self.memory_bytes
    }

    /// Returns the stdout ceiling.
    pub const fn stdout_bytes(&self) -> u64 {
        self.stdout_bytes
    }

    /// Returns the stderr ceiling.
    pub const fn stderr_bytes(&self) -> u64 {
        self.stderr_bytes
    }

    /// Returns the descendant ceiling.
    pub const fn max_descendants(&self) -> u32 {
        self.max_descendants
    }
}

/// Immutable invocation contract consumed by P-04.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProcessRequest {
    schema_version: String,
    operation_id: OperationId,
    process_tree_id: ProcessTreeId,
    generation: Generation,
    executable: String,
    executable_sha256: String,
    argv: Vec<String>,
    working_directory: String,
    environment: EnvironmentProjection,
    resource_limits: ResourceLimits,
    fence: FencingToken,
    invocation_digest: String,
}

impl ProcessRequest {
    /// Creates and seals an immutable process invocation.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        operation_id: OperationId,
        process_tree_id: ProcessTreeId,
        generation: Generation,
        executable: impl Into<String>,
        executable_sha256: impl Into<String>,
        argv: Vec<String>,
        working_directory: impl Into<String>,
        environment: EnvironmentProjection,
        resource_limits: ResourceLimits,
        fence: FencingToken,
    ) -> Result<Self, ContractError> {
        let request = Self {
            schema_version: PROCESS_CONTRACT_SCHEMA_VERSION.to_owned(),
            operation_id,
            process_tree_id,
            generation,
            executable: executable.into(),
            executable_sha256: executable_sha256.into(),
            argv,
            working_directory: working_directory.into(),
            environment,
            resource_limits,
            fence,
            invocation_digest: String::new(),
        };
        request.seal()
    }

    fn seal(mut self) -> Result<Self, ContractError> {
        self.validate_without_digest()?;
        self.invocation_digest = self.compute_digest()?;
        Ok(self)
    }

    /// Validates the request and its immutable digest.
    pub fn validate(&self) -> Result<(), ContractError> {
        self.validate_without_digest()?;
        let expected = self.compute_digest()?;
        if self.invocation_digest != expected {
            return Err(ContractError::DigestMismatch {
                expected,
                observed: self.invocation_digest.clone(),
            });
        }
        Ok(())
    }

    fn validate_without_digest(&self) -> Result<(), ContractError> {
        if self.schema_version != PROCESS_CONTRACT_SCHEMA_VERSION {
            return Err(ContractError::SchemaVersion {
                expected: PROCESS_CONTRACT_SCHEMA_VERSION,
                observed: self.schema_version.clone(),
            });
        }
        if self.executable.trim().is_empty() {
            return Err(ContractError::InvalidValue {
                field: "executable",
                reason: "must not be empty",
            });
        }
        if self.working_directory.trim().is_empty() {
            return Err(ContractError::InvalidValue {
                field: "working_directory",
                reason: "must not be empty",
            });
        }
        if self.argv.len() > MAX_ARGUMENTS {
            return Err(ContractError::LimitExceeded {
                field: "argv",
                limit: MAX_ARGUMENTS,
            });
        }
        if self.executable_sha256.len() != 64
            || !self
                .executable_sha256
                .bytes()
                .all(|b| b.is_ascii_hexdigit())
        {
            return Err(ContractError::InvalidValue {
                field: "executable_sha256",
                reason: "must be a 64-character hexadecimal digest",
            });
        }
        if self.fence.generation != self.generation {
            return Err(ContractError::FenceMismatch);
        }
        self.environment.validate()?;
        Ok(())
    }

    fn compute_digest(&self) -> Result<String, ContractError> {
        let unsigned = UnsignedRequest {
            schema_version: &self.schema_version,
            operation_id: &self.operation_id,
            process_tree_id: &self.process_tree_id,
            generation: self.generation,
            executable: &self.executable,
            executable_sha256: &self.executable_sha256,
            argv: &self.argv,
            working_directory: &self.working_directory,
            environment: &self.environment,
            resource_limits: self.resource_limits,
            fence: &self.fence,
        };
        let bytes = serde_json::to_vec(&unsigned)
            .map_err(|error| ContractError::Serialization(error.to_string()))?;
        Ok(hash_bytes(&bytes))
    }

    /// Returns the sealed invocation digest.
    pub fn invocation_digest(&self) -> &str {
        &self.invocation_digest
    }

    /// Returns the operation identity.
    pub fn operation_id(&self) -> &OperationId {
        &self.operation_id
    }

    /// Returns the process tree identity.
    pub fn process_tree_id(&self) -> &ProcessTreeId {
        &self.process_tree_id
    }

    /// Returns the requested generation.
    pub const fn generation(&self) -> Generation {
        self.generation
    }

    /// Returns the executable path as an opaque string.
    pub fn executable(&self) -> &str {
        &self.executable
    }

    /// Returns the executable digest.
    pub fn executable_sha256(&self) -> &str {
        &self.executable_sha256
    }

    /// Returns argv without any secret substitution.
    pub fn argv(&self) -> &[String] {
        &self.argv
    }

    /// Returns the working directory.
    pub fn working_directory(&self) -> &str {
        &self.working_directory
    }

    /// Returns the environment projection.
    pub const fn environment(&self) -> &EnvironmentProjection {
        &self.environment
    }

    /// Returns the resource limits.
    pub const fn resource_limits(&self) -> &ResourceLimits {
        &self.resource_limits
    }

    /// Returns the exact fence supplied by the authority owner.
    pub const fn fence(&self) -> &FencingToken {
        &self.fence
    }
}

/// Compatibility name used by process-plan consumers for the immutable request.
pub type ProcessSpec = ProcessRequest;

#[derive(Serialize)]
struct UnsignedRequest<'a> {
    schema_version: &'a str,
    operation_id: &'a OperationId,
    process_tree_id: &'a ProcessTreeId,
    generation: Generation,
    executable: &'a str,
    executable_sha256: &'a str,
    argv: &'a [String],
    working_directory: &'a str,
    environment: &'a EnvironmentProjection,
    resource_limits: ResourceLimits,
    fence: &'a FencingToken,
}

/// A process identity observed after physical launch.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProcessIdentity {
    process_id: ProcessId,
    process_tree_id: ProcessTreeId,
    generation: Generation,
    pid: u32,
    started_at_unix_ms: u64,
    executable_sha256: String,
}

impl ProcessIdentity {
    /// Creates an observed identity.  PID zero is never a valid child identity.
    pub fn new(
        process_id: ProcessId,
        process_tree_id: ProcessTreeId,
        generation: Generation,
        pid: u32,
        started_at_unix_ms: u64,
        executable_sha256: impl Into<String>,
    ) -> Result<Self, ContractError> {
        if pid == 0 {
            return Err(ContractError::InvalidValue {
                field: "pid",
                reason: "must be non-zero",
            });
        }
        let executable_sha256 = executable_sha256.into();
        if executable_sha256.len() != 64
            || !executable_sha256.bytes().all(|b| b.is_ascii_hexdigit())
        {
            return Err(ContractError::InvalidValue {
                field: "executable_sha256",
                reason: "must be a 64-character hexadecimal digest",
            });
        }
        Ok(Self {
            process_id,
            process_tree_id,
            generation,
            pid,
            started_at_unix_ms,
            executable_sha256,
        })
    }

    /// Returns the opaque process identity.
    pub const fn process_id(&self) -> &ProcessId {
        &self.process_id
    }

    /// Returns the owning tree.
    pub const fn process_tree_id(&self) -> &ProcessTreeId {
        &self.process_tree_id
    }

    /// Returns the process generation.
    pub const fn generation(&self) -> Generation {
        self.generation
    }

    /// Returns the observed PID.
    pub const fn pid(&self) -> u32 {
        self.pid
    }

    /// Returns the launch timestamp supplied by the platform adapter.
    pub const fn started_at_unix_ms(&self) -> u64 {
        self.started_at_unix_ms
    }

    /// Returns the observed executable digest.
    pub fn executable_sha256(&self) -> &str {
        &self.executable_sha256
    }
}

/// Canonical process lifecycle.  It is intentionally separate from capability readiness.
#[derive(Clone, Copy, Debug, Default, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProcessLifecycle {
    #[default]
    Created,
    Starting,
    Running,
    Cancelling,
    Exited,
    Failed,
    UnknownOutcome,
    Reconciled,
    Quarantined,
}

impl ProcessLifecycle {
    /// Returns whether this lifecycle is terminal.
    pub const fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::Exited | Self::Failed | Self::Reconciled | Self::Quarantined
        )
    }

    /// Checks one exact state transition.
    pub const fn can_transition_to(self, next: Self) -> bool {
        matches!(
            (self, next),
            (
                Self::Created,
                Self::Starting | Self::Cancelling | Self::Failed
            ) | (
                Self::Starting,
                Self::Running | Self::Cancelling | Self::Failed | Self::UnknownOutcome
            ) | (
                Self::Running,
                Self::Cancelling | Self::Exited | Self::Failed | Self::UnknownOutcome
            ) | (
                Self::Cancelling,
                Self::Exited | Self::Failed | Self::UnknownOutcome
            ) | (Self::UnknownOutcome, Self::Reconciled | Self::Quarantined)
        )
    }
}

/// Compatibility name for consumers that call the lifecycle projection a status.
pub type ProcessStatus = ProcessLifecycle;

/// The health axis is not inferred from process liveness.
#[derive(Clone, Copy, Debug, Default, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProcessHealthStatus {
    #[default]
    Unknown,
    Healthy,
    Degraded,
    Failed,
}

/// A bounded health observation.
#[derive(Clone, Debug, Default, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProcessHealth {
    status: ProcessHealthStatus,
    ready: bool,
    observed_at_unix_ms: u64,
    detail: Option<String>,
}

impl ProcessHealth {
    /// Creates an observation.  `detail` is diagnostic text, never a secret channel.
    pub fn new(
        status: ProcessHealthStatus,
        ready: bool,
        observed_at_unix_ms: u64,
        detail: Option<String>,
    ) -> Result<Self, ContractError> {
        if detail.as_deref().is_some_and(contains_secret_like_text) {
            return Err(ContractError::SecretBoundary {
                field: "health.detail",
            });
        }
        Ok(Self {
            status,
            ready,
            observed_at_unix_ms,
            detail,
        })
    }

    /// Returns the health status.
    pub const fn status(&self) -> ProcessHealthStatus {
        self.status
    }

    /// Returns whether the process passed its readiness observation.
    pub const fn ready(&self) -> bool {
        self.ready
    }

    /// Returns the observation timestamp.
    pub const fn observed_at_unix_ms(&self) -> u64 {
        self.observed_at_unix_ms
    }

    /// Returns the optional diagnostic detail.
    pub fn detail(&self) -> Option<&str> {
        self.detail.as_deref()
    }
}

/// Why a process terminated.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExitDisposition {
    Completed,
    NonZeroExit,
    Signalled,
    Cancelled,
    TimedOut,
    Killed,
    NeverStarted,
    Unknown,
}

/// Immutable observed exit information.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExitStatus {
    disposition: ExitDisposition,
    code: Option<i32>,
    signal: Option<i32>,
    observed_at_unix_ms: u64,
}

impl ExitStatus {
    /// Creates an exit observation and checks its discriminated fields.
    pub fn new(
        disposition: ExitDisposition,
        code: Option<i32>,
        signal: Option<i32>,
        observed_at_unix_ms: u64,
    ) -> Result<Self, ContractError> {
        if matches!(
            disposition,
            ExitDisposition::Completed | ExitDisposition::NonZeroExit
        ) && signal.is_some()
        {
            return Err(ContractError::InvalidValue {
                field: "exit.signal",
                reason: "signal is not valid for a normal exit",
            });
        }
        if matches!(disposition, ExitDisposition::Signalled) && signal.is_none() {
            return Err(ContractError::InvalidValue {
                field: "exit.signal",
                reason: "signal is required for signalled exit",
            });
        }
        Ok(Self {
            disposition,
            code,
            signal,
            observed_at_unix_ms,
        })
    }

    /// Returns the termination disposition.
    pub const fn disposition(&self) -> ExitDisposition {
        self.disposition
    }

    /// Returns the process exit code.
    pub const fn code(&self) -> Option<i32> {
        self.code
    }

    /// Returns the platform signal number, when applicable.
    pub const fn signal(&self) -> Option<i32> {
        self.signal
    }

    /// Returns the observation timestamp.
    pub const fn observed_at_unix_ms(&self) -> u64 {
        self.observed_at_unix_ms
    }
}

/// Cancellation disposition, independent from process liveness.
#[derive(Clone, Copy, Debug, Default, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CancellationStatus {
    #[default]
    NotRequested,
    Requested,
    InProgress,
    Completed,
    RejectedStaleFence,
    UnknownOutcome,
}

/// Evidence that the complete descendant tree was observed and contained.
#[derive(Clone, Debug, Default, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DescendantEvidence {
    process_ids: Vec<ProcessId>,
    complete: bool,
    tree_terminated: bool,
    evidence_ref: Option<String>,
}

impl DescendantEvidence {
    /// Creates a tree observation and rejects duplicate process identities.
    pub fn new(
        process_ids: Vec<ProcessId>,
        complete: bool,
        tree_terminated: bool,
        evidence_ref: Option<String>,
    ) -> Result<Self, ContractError> {
        if process_ids.len() > MAX_DESCENDANTS {
            return Err(ContractError::LimitExceeded {
                field: "descendant_evidence.process_ids",
                limit: MAX_DESCENDANTS,
            });
        }
        let unique = process_ids.iter().collect::<BTreeSet<_>>();
        if unique.len() != process_ids.len() {
            return Err(ContractError::DuplicateValue {
                field: "process_ids",
            });
        }
        if tree_terminated && !complete {
            return Err(ContractError::InvalidValue {
                field: "descendant_evidence",
                reason: "tree_terminated requires complete observation",
            });
        }
        Ok(Self {
            process_ids,
            complete,
            tree_terminated,
            evidence_ref,
        })
    }

    /// Returns all observed process identities.
    pub fn process_ids(&self) -> &[ProcessId] {
        &self.process_ids
    }

    /// Returns whether the tree observation is complete.
    pub const fn complete(&self) -> bool {
        self.complete
    }

    /// Returns whether all descendants were terminated.
    pub const fn tree_terminated(&self) -> bool {
        self.tree_terminated
    }

    /// Returns the raw evidence handle.
    pub fn evidence_ref(&self) -> Option<&str> {
        self.evidence_ref.as_deref()
    }
}

/// A typed process status view.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProcessExecutionView {
    operation_id: OperationId,
    process_tree_id: ProcessTreeId,
    generation: Generation,
    request_digest: String,
    lifecycle: ProcessLifecycle,
    health: ProcessHealth,
    cancellation: CancellationStatus,
    identity: Option<ProcessIdentity>,
    exit: Option<ExitStatus>,
    descendants: DescendantEvidence,
    fence: FencingToken,
}

impl ProcessExecutionView {
    /// Returns the current lifecycle.
    pub const fn lifecycle(&self) -> ProcessLifecycle {
        self.lifecycle
    }

    /// Returns the current health axis.
    pub const fn health(&self) -> &ProcessHealth {
        &self.health
    }

    /// Returns the cancellation axis.
    pub const fn cancellation(&self) -> CancellationStatus {
        self.cancellation
    }

    /// Returns the observed process identity.
    pub const fn identity(&self) -> Option<&ProcessIdentity> {
        self.identity.as_ref()
    }

    /// Returns the immutable exit observation.
    pub const fn exit(&self) -> Option<&ExitStatus> {
        self.exit.as_ref()
    }

    /// Returns descendant evidence.
    pub const fn descendants(&self) -> &DescendantEvidence {
        &self.descendants
    }

    /// Returns the operation identity.
    pub const fn operation_id(&self) -> &OperationId {
        &self.operation_id
    }

    /// Returns the request digest.
    pub fn request_digest(&self) -> &str {
        &self.request_digest
    }

    /// Returns the fence snapshot.
    pub const fn fence(&self) -> &FencingToken {
        &self.fence
    }
}

/// Reconciliation evidence emitted by a physical implementation.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProcessEvidence {
    operation_id: OperationId,
    request_digest: String,
    view: ProcessExecutionView,
    stdout_ref: Option<String>,
    stderr_ref: Option<String>,
}

impl ProcessEvidence {
    /// Creates evidence only when the view belongs to the same request.
    pub fn new(
        operation_id: OperationId,
        request_digest: impl Into<String>,
        view: ProcessExecutionView,
        stdout_ref: Option<String>,
        stderr_ref: Option<String>,
    ) -> Result<Self, ContractError> {
        let request_digest = request_digest.into();
        if view.operation_id != operation_id || view.request_digest != request_digest {
            return Err(ContractError::EvidenceBindingMismatch);
        }
        Ok(Self {
            operation_id,
            request_digest,
            view,
            stdout_ref,
            stderr_ref,
        })
    }

    /// Returns the operation identity.
    pub const fn operation_id(&self) -> &OperationId {
        &self.operation_id
    }

    /// Returns the request digest.
    pub fn request_digest(&self) -> &str {
        &self.request_digest
    }

    /// Returns the process view.
    pub const fn view(&self) -> &ProcessExecutionView {
        &self.view
    }

    /// Returns the stdout evidence handle.
    pub fn stdout_ref(&self) -> Option<&str> {
        self.stdout_ref.as_deref()
    }

    /// Returns the stderr evidence handle.
    pub fn stderr_ref(&self) -> Option<&str> {
        self.stderr_ref.as_deref()
    }
}

/// Cancellation receipt from the implementation.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CancellationReceipt {
    operation_id: OperationId,
    request_digest: String,
    status: CancellationStatus,
    lifecycle: ProcessLifecycle,
    no_effect_proven: bool,
    descendants: DescendantEvidence,
}

impl CancellationReceipt {
    /// Returns the cancellation status.
    pub const fn status(&self) -> CancellationStatus {
        self.status
    }

    /// Returns whether no external effect was proven.
    pub const fn no_effect_proven(&self) -> bool {
        self.no_effect_proven
    }

    /// Returns descendant cleanup evidence.
    pub const fn descendants(&self) -> &DescendantEvidence {
        &self.descendants
    }
}

/// A pure in-memory process state machine used by contract implementations and tests.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProcessState {
    request: ProcessRequest,
    lifecycle: ProcessLifecycle,
    health: ProcessHealth,
    cancellation: CancellationStatus,
    identity: Option<ProcessIdentity>,
    exit: Option<ExitStatus>,
    descendants: DescendantEvidence,
}

impl ProcessState {
    /// Starts a state machine in `Created` without any physical side effect.
    pub fn new(request: ProcessRequest) -> Result<Self, ContractError> {
        request.validate()?;
        Ok(Self {
            request,
            lifecycle: ProcessLifecycle::Created,
            health: ProcessHealth::default(),
            cancellation: CancellationStatus::NotRequested,
            identity: None,
            exit: None,
            descendants: DescendantEvidence::default(),
        })
    }

    /// Returns the current view.
    pub fn view(&self) -> ProcessExecutionView {
        ProcessExecutionView {
            operation_id: self.request.operation_id.clone(),
            process_tree_id: self.request.process_tree_id.clone(),
            generation: self.request.generation,
            request_digest: self.request.invocation_digest.clone(),
            lifecycle: self.lifecycle,
            health: self.health.clone(),
            cancellation: self.cancellation,
            identity: self.identity.clone(),
            exit: self.exit.clone(),
            descendants: self.descendants.clone(),
            fence: self.request.fence.clone(),
        }
    }

    /// Returns the immutable request.
    pub const fn request(&self) -> &ProcessRequest {
        &self.request
    }

    /// Advances to a valid lifecycle state.
    pub fn transition(&mut self, next: ProcessLifecycle) -> Result<(), ContractError> {
        if !self.lifecycle.can_transition_to(next) {
            return Err(ContractError::InvalidTransition {
                from: self.lifecycle,
                to: next,
            });
        }
        self.lifecycle = next;
        Ok(())
    }

    /// Records a launch identity and enters `Starting`.
    pub fn start(&mut self, identity: ProcessIdentity) -> Result<(), ContractError> {
        if identity.process_tree_id != self.request.process_tree_id
            || identity.generation != self.request.generation
            || identity.executable_sha256 != self.request.executable_sha256
        {
            return Err(ContractError::IdentityMismatch);
        }
        self.transition(ProcessLifecycle::Starting)?;
        self.identity = Some(identity);
        Ok(())
    }

    /// Marks the process as running after an identity has been recorded.
    pub fn mark_running(&mut self, health: ProcessHealth) -> Result<(), ContractError> {
        if self.identity.is_none() {
            return Err(ContractError::MissingIdentity);
        }
        self.transition(ProcessLifecycle::Running)?;
        self.health = health;
        Ok(())
    }

    /// Records an exit and closes the process lifecycle.
    pub fn exit(
        &mut self,
        exit: ExitStatus,
        descendants: DescendantEvidence,
    ) -> Result<(), ContractError> {
        if self.identity.is_none() {
            return Err(ContractError::MissingIdentity);
        }
        if matches!(exit.disposition, ExitDisposition::Unknown) {
            self.transition(ProcessLifecycle::UnknownOutcome)?;
        } else {
            self.transition(ProcessLifecycle::Exited)?;
        }
        self.exit = Some(exit);
        self.descendants = descendants;
        Ok(())
    }

    /// Requests cancellation under the exact request fence.
    pub fn cancel(&mut self, fence: &FencingToken) -> Result<CancellationReceipt, ContractError> {
        if !self.request.fence.matches(fence) {
            self.cancellation = CancellationStatus::RejectedStaleFence;
            return Err(ContractError::StaleFence);
        }
        if self.lifecycle.is_terminal() {
            return Ok(CancellationReceipt {
                operation_id: self.request.operation_id.clone(),
                request_digest: self.request.invocation_digest.clone(),
                status: self.cancellation,
                lifecycle: self.lifecycle,
                no_effect_proven: matches!(self.lifecycle, ProcessLifecycle::Created),
                descendants: self.descendants.clone(),
            });
        }
        self.cancellation = CancellationStatus::Requested;
        self.transition(ProcessLifecycle::Cancelling)?;
        self.cancellation = CancellationStatus::InProgress;
        Ok(CancellationReceipt {
            operation_id: self.request.operation_id.clone(),
            request_digest: self.request.invocation_digest.clone(),
            status: self.cancellation,
            lifecycle: self.lifecycle,
            no_effect_proven: false,
            descendants: self.descendants.clone(),
        })
    }

    /// Marks an unknown external effect reconciled with complete tree evidence.
    pub fn reconcile(&mut self, descendants: DescendantEvidence) -> Result<(), ContractError> {
        if self.lifecycle != ProcessLifecycle::UnknownOutcome {
            return Err(ContractError::InvalidValue {
                field: "lifecycle",
                reason: "only unknown outcomes require reconciliation",
            });
        }
        if !descendants.complete() {
            return Err(ContractError::IncompleteDescendantEvidence);
        }
        self.descendants = descendants;
        self.lifecycle = ProcessLifecycle::Reconciled;
        if matches!(
            self.cancellation,
            CancellationStatus::InProgress | CancellationStatus::UnknownOutcome
        ) {
            self.cancellation = CancellationStatus::Completed;
        }
        Ok(())
    }
}

/// Receives immutable evidence from a physical executor.
pub trait ProcessEvidenceSink: Send + Sync {
    /// Persists or forwards one evidence record without granting authority.
    fn record(&self, evidence: ProcessEvidence) -> Result<(), EvidenceSinkError>;
}

/// Provider-neutral executor boundary.  P-04 owns the physical implementation.
#[allow(async_fn_in_trait)]
pub trait ProcessExecutor: Send + Sync {
    /// Launches one immutable request through the implementation.
    async fn start(
        &self,
        request: ProcessRequest,
        sink: Arc<dyn ProcessEvidenceSink>,
    ) -> Result<ProcessStartReceipt, ProcessExecutionError>;

    /// Inspects one operation without changing its request identity.
    async fn inspect(
        &self,
        operation_id: OperationId,
    ) -> Result<ProcessExecutionView, ProcessExecutionError>;

    /// Requests cancellation under the implementation's current fence.
    async fn cancel(
        &self,
        operation_id: OperationId,
    ) -> Result<CancellationReceipt, ProcessExecutionError>;

    /// Reconciles an operation after an unknown external result.
    async fn reconcile(
        &self,
        operation_id: OperationId,
    ) -> Result<ProcessEvidence, ProcessExecutionError>;
}

/// Receipt returned after the physical implementation accepts a start.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProcessStartReceipt {
    operation_id: OperationId,
    request_digest: String,
    accepted_generation: Generation,
    lifecycle: ProcessLifecycle,
}

impl ProcessStartReceipt {
    /// Creates a receipt bound to the exact request.
    pub fn new(
        request: &ProcessRequest,
        lifecycle: ProcessLifecycle,
    ) -> Result<Self, ContractError> {
        request.validate()?;
        if !matches!(
            lifecycle,
            ProcessLifecycle::Starting | ProcessLifecycle::Running
        ) {
            return Err(ContractError::InvalidValue {
                field: "lifecycle",
                reason: "start receipt must be starting or running",
            });
        }
        Ok(Self {
            operation_id: request.operation_id.clone(),
            request_digest: request.invocation_digest.clone(),
            accepted_generation: request.generation,
            lifecycle,
        })
    }

    /// Returns the operation identity.
    pub const fn operation_id(&self) -> &OperationId {
        &self.operation_id
    }

    /// Returns the request digest.
    pub fn request_digest(&self) -> &str {
        &self.request_digest
    }

    /// Returns the accepted generation.
    pub const fn accepted_generation(&self) -> Generation {
        self.accepted_generation
    }

    /// Returns the observed start lifecycle.
    pub const fn lifecycle(&self) -> ProcessLifecycle {
        self.lifecycle
    }
}

/// Errors that belong to the process contract itself.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum ContractError {
    /// A field failed a structural or semantic constraint.
    #[error("invalid {field}: {reason}")]
    InvalidValue {
        /// Field name.
        field: &'static str,
        /// Stable reason.
        reason: &'static str,
    },
    /// An opaque value was empty, oversized or contained control bytes.
    #[error("invalid opaque value in {field}")]
    InvalidOpaqueValue {
        /// Field name.
        field: &'static str,
    },
    /// A configured bound was exceeded.
    #[error("{field} exceeds limit {limit}")]
    LimitExceeded {
        /// Field name.
        field: &'static str,
        /// Maximum accepted count.
        limit: usize,
    },
    /// A duplicate value would make evidence ambiguous.
    #[error("duplicate value in {field}")]
    DuplicateValue {
        /// Field name.
        field: &'static str,
    },
    /// Secret material or a secret-like projection crossed the boundary.
    #[error("secret boundary rejected {field}")]
    SecretBoundary {
        /// Field name.
        field: &'static str,
    },
    /// The contract schema version is not supported.
    #[error("schema version mismatch: expected {expected}, observed {observed}")]
    SchemaVersion {
        /// Expected version.
        expected: &'static str,
        /// Observed version.
        observed: String,
    },
    /// The immutable request digest does not match its projection.
    #[error("invocation digest mismatch: expected {expected}, observed {observed}")]
    DigestMismatch {
        /// Recomputed digest.
        expected: String,
        /// Stored digest.
        observed: String,
    },
    /// Fencing fields disagree.
    #[error("fencing token does not match request generation")]
    FenceMismatch,
    /// The lifecycle transition is not admitted.
    #[error("invalid lifecycle transition from {from:?} to {to:?}")]
    InvalidTransition {
        /// Current state.
        from: ProcessLifecycle,
        /// Requested state.
        to: ProcessLifecycle,
    },
    /// The identity is not compatible with the request.
    #[error("process identity does not match request")]
    IdentityMismatch,
    /// A physical identity was required but not observed.
    #[error("process identity is missing")]
    MissingIdentity,
    /// Cancellation was attempted under a stale fence.
    #[error("stale fencing token")]
    StaleFence,
    /// Reconciliation did not prove complete descendant observation.
    #[error("descendant evidence is incomplete")]
    IncompleteDescendantEvidence,
    /// Evidence was attributed to a different operation/request.
    #[error("evidence binding mismatch")]
    EvidenceBindingMismatch,
    /// Stable JSON serialisation failed.
    #[error("contract serialisation failed: {0}")]
    Serialization(String),
}

/// Sink failures are intentionally opaque to the process contract.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
#[error("evidence sink rejected record: {message}")]
pub struct EvidenceSinkError {
    /// Stable category/message without raw process output.
    pub message: String,
}

/// Errors exposed by a physical `ProcessExecutor` implementation.
#[derive(Debug, Error)]
pub enum ProcessExecutionError {
    /// Request failed contract validation before any side effect.
    #[error(transparent)]
    Contract(#[from] ContractError),
    /// The operation is not known to the implementation.
    #[error("operation not found")]
    NotFound,
    /// A physical executor is unavailable.
    #[error("process executor unavailable: {0}")]
    Unavailable(String),
    /// The evidence sink rejected an otherwise valid record.
    #[error(transparent)]
    EvidenceSink(#[from] EvidenceSinkError),
    /// The external effect cannot yet be classified.
    #[error("process outcome is unknown and requires reconciliation")]
    UnknownOutcome,
}

fn validate_opaque_id(field: &'static str, value: String) -> Result<String, ContractError> {
    if value.is_empty() || value.len() > MAX_ID_BYTES || value.chars().any(char::is_control) {
        return Err(ContractError::InvalidOpaqueValue { field });
    }
    Ok(value)
}

fn validate_environment_name(name: &str) -> Result<(), ContractError> {
    if name.is_empty() || name.len() > 128 || name.chars().any(|c| c.is_control() || c == '=') {
        return Err(ContractError::InvalidOpaqueValue {
            field: "environment_name",
        });
    }
    Ok(())
}

fn is_secret_like(name: &str) -> bool {
    let upper = name.to_ascii_uppercase();
    [
        "PASSWORD",
        "PASSWD",
        "TOKEN",
        "SECRET",
        "PRIVATE_KEY",
        "API_KEY",
        "CREDENTIAL",
    ]
    .iter()
    .any(|marker| upper.contains(marker))
}

fn looks_like_secret_value(value: &str) -> bool {
    let lower = value.to_ascii_lowercase();
    lower.contains("bearer ") || lower.contains("sk-") || lower.contains("-----begin ")
}

fn contains_secret_like_text(value: &str) -> bool {
    let lower = value.to_ascii_lowercase();
    lower.contains("password=") || lower.contains("token=") || lower.contains("secret=")
}

fn hash_bytes(bytes: &[u8]) -> String {
    let digest: Hash = blake3::hash(bytes);
    digest.to_hex().to_string()
}

impl fmt::Display for Generation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::error::Error;

    fn request() -> Result<ProcessRequest, ContractError> {
        let operation = OperationId::new("op-1")?;
        let tree = ProcessTreeId::new("tree-1")?;
        let generation = Generation::new(1)?;
        let fence = FencingToken::new(1, generation, "nonce-1")?;
        let environment = EnvironmentProjection::new(
            BTreeMap::from([(String::from("PATH"), String::from("C:\\Windows"))]),
            vec![SecretRef::new("credential_manager", "provider/token")?],
            EnvironmentInheritance::None,
        )?;
        ProcessRequest::new(
            operation,
            tree,
            generation,
            "C:\\tools\\worker.exe",
            "a".repeat(64),
            vec!["--check".to_owned()],
            "C:\\work",
            environment,
            ResourceLimits::new(10_000, Some(5_000), Some(1024 * 1024), 4096, 4096, 4)?,
            fence,
        )
    }

    fn identity(request: &ProcessRequest) -> Result<ProcessIdentity, ContractError> {
        ProcessIdentity::new(
            ProcessId::new("pid-1")?,
            request.process_tree_id.clone(),
            request.generation,
            42,
            10,
            request.executable_sha256.clone(),
        )
    }

    #[test]
    fn request_roundtrips_and_digest_is_stable() -> Result<(), Box<dyn Error>> {
        let request = request()?;
        request.validate()?;
        let json = serde_json::to_string(&request)?;
        let decoded: ProcessRequest = serde_json::from_str(&json)?;
        assert_eq!(request, decoded);
        assert_eq!(request.invocation_digest(), decoded.invocation_digest());
        Ok(())
    }

    #[test]
    fn tampered_request_digest_is_rejected() -> Result<(), Box<dyn Error>> {
        let request = request()?;
        let mut value = serde_json::to_value(request)?;
        value["argv"] = serde_json::json!(["--tampered"]);
        let decoded: ProcessRequest = serde_json::from_value(value)?;
        assert!(matches!(
            decoded.validate(),
            Err(ContractError::DigestMismatch { .. })
        ));
        Ok(())
    }

    #[test]
    fn secret_like_environment_is_rejected() {
        let result = EnvironmentProjection::new(
            BTreeMap::from([(String::from("ACCESS_TOKEN"), String::from("hidden"))]),
            Vec::new(),
            EnvironmentInheritance::None,
        );
        assert!(matches!(result, Err(ContractError::SecretBoundary { .. })));
    }

    #[test]
    fn lifecycle_and_cancellation_are_fenced() -> Result<(), Box<dyn Error>> {
        let mut state = ProcessState::new(request()?)?;
        let identity = identity(state.request())?;
        state.start(identity)?;
        state.mark_running(ProcessHealth::new(
            ProcessHealthStatus::Healthy,
            true,
            11,
            None,
        )?)?;
        let stale_fence = FencingToken::new(2, state.request().generation, "nonce-2")?;
        assert!(matches!(
            state.cancel(&stale_fence),
            Err(ContractError::StaleFence)
        ));
        let fence = state.request().fence().clone();
        let receipt = state.cancel(&fence)?;
        assert_eq!(receipt.status(), CancellationStatus::InProgress);
        assert_eq!(state.view().lifecycle(), ProcessLifecycle::Cancelling);
        Ok(())
    }

    #[test]
    fn invalid_transition_is_rejected() -> Result<(), Box<dyn Error>> {
        let mut state = ProcessState::new(request()?)?;
        assert!(matches!(
            state.transition(ProcessLifecycle::Exited),
            Err(ContractError::InvalidTransition { .. })
        ));
        Ok(())
    }

    #[test]
    fn unknown_exit_requires_complete_reconciliation() -> Result<(), Box<dyn Error>> {
        let mut state = ProcessState::new(request()?)?;
        let process_identity = identity(state.request())?;
        state.start(process_identity)?;
        state.mark_running(ProcessHealth::default())?;
        let exit = ExitStatus::new(ExitDisposition::Unknown, None, None, 20)?;
        state.exit(exit, DescendantEvidence::default())?;
        assert!(matches!(
            state.reconcile(DescendantEvidence::default()),
            Err(ContractError::IncompleteDescendantEvidence)
        ));
        let evidence =
            DescendantEvidence::new(Vec::new(), true, true, Some("evidence:1".to_owned()))?;
        state.reconcile(evidence)?;
        assert_eq!(state.view().lifecycle(), ProcessLifecycle::Reconciled);
        Ok(())
    }

    #[test]
    fn unknown_wire_fields_fail_closed() -> Result<(), Box<dyn Error>> {
        let mut value = serde_json::to_value(request()?)?;
        value["secret_value"] = serde_json::json!("must-not-be-accepted");
        let result = serde_json::from_value::<ProcessRequest>(value);
        assert!(result.is_err());
        Ok(())
    }

    #[test]
    fn duplicate_descendant_and_invalid_exit_are_rejected() -> Result<(), Box<dyn Error>> {
        let process_id = ProcessId::new("pid-1")?;
        assert!(matches!(
            DescendantEvidence::new(vec![process_id.clone(), process_id], true, true, None),
            Err(ContractError::DuplicateValue { .. })
        ));
        assert!(matches!(
            ExitStatus::new(ExitDisposition::Signalled, Some(1), None, 1),
            Err(ContractError::InvalidValue { .. })
        ));
        assert!(ResourceLimits::new(0, None, None, 1, 1, 0).is_err());
        Ok(())
    }
}
