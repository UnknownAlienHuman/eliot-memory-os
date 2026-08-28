//! P-03: the provider-neutral governed process contract.
//!
//! P-03 owns immutable invocation, dispatch-permit validation, exact process
//! identity, lifecycle, cancellation, reconciliation, and evidence binding.
//! P-04 owns Windows mechanics. In particular, P-02's suspended-launch
//! typestate carries [`ValidatedDispatch`] only as opaque caller-policy output;
//! P-02 never issues or validates authority.

#![forbid(unsafe_code)]

use blake3::Hash;
use eliot_contracts::{canonical_json_bytes, sha256_hex};
use eliot_instrument_api::{Assertability, EvidenceAxes, EvidenceStatus};
use eliot_platform::ClockObservation;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::sync::Arc;
use thiserror::Error;

mod physical_identity;
pub use physical_identity::{
    PhysicalProcessBinding, ProcessIdentity, SuspendedLaunchEvidence, SuspendedProcessIdentity,
};

mod dispatch_permit;
pub use dispatch_permit::{
    DispatchPermit, DispatchPermitAuthority, DispatchPermitReplaySnapshot, KernelDispatchKey,
};

/// Current provider-neutral process contract revision.
pub const PROCESS_CONTRACT_SCHEMA_VERSION: &str = "eliot-process-contract-v3";
/// The sole admitted Windows semantic implementation identifier.
pub const PROCESS_IMPLEMENTATION_ID: &str = "eliot.process.windows.v1";

const MAX_ID_BYTES: usize = 256;
const MAX_EXECUTOR_JOB_NAME_UTF16: usize = 240;
const MAX_PROCESS_IMAGE_PATH_UTF16: usize = 32_767;
const MAX_ARGUMENTS: usize = 4096;
const MAX_ENVIRONMENT_ENTRIES: usize = 512;
const MAX_DESCENDANTS: usize = 4096;
const MAX_REVISION_HEADS: usize = 128;
const MAX_RECOVERY_OBSERVATION_AGE_MS: u64 = 60_000;

macro_rules! opaque_id {
    ($name:ident, $field:literal, $doc:literal) => {
        #[doc = $doc]
        #[derive(
            Clone, Debug, Eq, Hash, JsonSchema, Ord, PartialEq, PartialOrd, Serialize, Deserialize,
        )]
        #[serde(transparent)]
        pub struct $name(String);

        impl $name {
            /// Creates a validated opaque identity.
            pub fn new(value: impl Into<String>) -> Result<Self, ContractError> {
                validate_opaque_id($field, value.into()).map(Self)
            }

            /// Returns the wire value.
            pub fn as_str(&self) -> &str {
                &self.0
            }

            fn validate(&self) -> Result<(), ContractError> {
                validate_opaque_id($field, self.0.clone()).map(|_| ())
            }
        }
    };
}

opaque_id!(
    OperationId,
    "operation_id",
    "One exact external-effect operation."
);
opaque_id!(
    ProcessTreeId,
    "process_tree_id",
    "One caller-owned process-tree lineage."
);
opaque_id!(ProcessId, "process_id", "One physical process generation.");
opaque_id!(
    JobId,
    "job_id",
    "One logical caller-owned Job/container identity, never an OS Job object name."
);
opaque_id!(
    ImageId,
    "image_id",
    "One exact pinned executable image identity."
);
opaque_id!(
    SessionId,
    "session_id",
    "One exact host or interactive session identity."
);
opaque_id!(
    ActionLeaseRef,
    "action_lease_ref",
    "The Kernel-visible action lease that authorizes one dispatch."
);
opaque_id!(
    DispatchAuthorityId,
    "dispatch_authority_id",
    "One activated Kernel dispatch-authority instance."
);

/// A reference to a secret provider entry. It never contains the secret.
#[derive(Clone, Debug, Eq, JsonSchema, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SecretRef {
    provider: String,
    key: String,
}

impl SecretRef {
    /// Creates a provider/key reference without materialising the secret.
    pub fn new(provider: impl Into<String>, key: impl Into<String>) -> Result<Self, ContractError> {
        Ok(Self {
            provider: validate_opaque_id("secret_provider", provider.into())?,
            key: validate_opaque_id("secret_key", key.into())?,
        })
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

/// A state-fence snapshot. It is inert data and never grants dispatch authority.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FencingToken {
    authority_epoch: u64,
    generation: Generation,
    nonce: String,
}

impl FencingToken {
    /// Creates inert fence data. A valid [`DispatchPermit`] must authenticate it.
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

    /// Checks exact fence equality.
    pub fn matches(&self, other: &Self) -> bool {
        self == other
    }
}

/// How the child receives environment values.
#[derive(Clone, Copy, Debug, Default, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EnvironmentInheritance {
    /// The child receives only explicitly supplied values.
    #[default]
    None,
    /// The executor may merge a platform allowlist, never secrets.
    Allowlisted,
}

/// A secret-safe environment projection.
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
    /// Builds a projection and rejects secret-like material in the plain map.
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
        let mut unique = BTreeSet::new();
        for reference in &secret_refs {
            if !unique.insert((reference.provider.clone(), reference.key.clone())) {
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

    /// Returns opaque secret references.
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
    /// Creates bounded resource limits.
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
        if matches!(cpu_time_ms, Some(0)) {
            return Err(ContractError::InvalidValue {
                field: "cpu_time_ms",
                reason: "must be non-zero when present",
            });
        }
        if matches!(memory_bytes, Some(0)) {
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

    /// Returns the CPU ceiling.
    pub const fn cpu_time_ms(&self) -> Option<u64> {
        self.cpu_time_ms
    }

    /// Returns the memory ceiling.
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

/// Immutable dispatch material before Kernel authority is attached.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProcessIntent {
    operation_id: OperationId,
    process_tree_id: ProcessTreeId,
    job_id: JobId,
    image_id: ImageId,
    session_id: SessionId,
    generation: Generation,
    executable: String,
    executable_sha256: String,
    argv: Vec<String>,
    working_directory: String,
    environment: EnvironmentProjection,
    resource_limits: ResourceLimits,
    effect_digest: String,
}

impl ProcessIntent {
    /// Creates and seals exact launch material without granting authority.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        operation_id: OperationId,
        process_tree_id: ProcessTreeId,
        job_id: JobId,
        image_id: ImageId,
        session_id: SessionId,
        generation: Generation,
        executable: impl Into<String>,
        executable_sha256: impl Into<String>,
        argv: Vec<String>,
        working_directory: impl Into<String>,
        environment: EnvironmentProjection,
        resource_limits: ResourceLimits,
    ) -> Result<Self, ContractError> {
        let mut intent = Self {
            operation_id,
            process_tree_id,
            job_id,
            image_id,
            session_id,
            generation,
            executable: executable.into(),
            executable_sha256: executable_sha256.into(),
            argv,
            working_directory: working_directory.into(),
            environment,
            resource_limits,
            effect_digest: String::new(),
        };
        intent.validate_without_digest()?;
        intent.effect_digest = intent.compute_effect_digest()?;
        Ok(intent)
    }

    /// Validates exact launch material and its digest.
    pub fn validate(&self) -> Result<(), ContractError> {
        self.validate_without_digest()?;
        validate_stored_digest(
            "effect_digest",
            &self.effect_digest,
            self.compute_effect_digest()?,
        )
    }

    fn validate_without_digest(&self) -> Result<(), ContractError> {
        if self.executable.trim().is_empty() || self.working_directory.trim().is_empty() {
            return Err(ContractError::InvalidValue {
                field: "launch_path",
                reason: "executable and working_directory must be non-blank",
            });
        }
        validate_hex_digest("executable_sha256", &self.executable_sha256)?;
        if self.argv.len() > MAX_ARGUMENTS {
            return Err(ContractError::LimitExceeded {
                field: "argv",
                limit: MAX_ARGUMENTS,
            });
        }
        if self
            .argv
            .iter()
            .any(|value| value.chars().any(char::is_control))
        {
            return Err(ContractError::InvalidValue {
                field: "argv",
                reason: "arguments must not contain control characters",
            });
        }
        self.environment.validate()
    }

    fn compute_effect_digest(&self) -> Result<String, ContractError> {
        #[derive(Serialize)]
        struct EffectMaterial<'a> {
            operation_id: &'a OperationId,
            process_tree_id: &'a ProcessTreeId,
            job_id: &'a JobId,
            image_id: &'a ImageId,
            session_id: &'a SessionId,
            generation: Generation,
            executable: &'a str,
            executable_sha256: &'a str,
            argv: &'a [String],
            working_directory: &'a str,
            environment: &'a EnvironmentProjection,
            resource_limits: ResourceLimits,
        }
        hash_serialized(&EffectMaterial {
            operation_id: &self.operation_id,
            process_tree_id: &self.process_tree_id,
            job_id: &self.job_id,
            image_id: &self.image_id,
            session_id: &self.session_id,
            generation: self.generation,
            executable: &self.executable,
            executable_sha256: &self.executable_sha256,
            argv: &self.argv,
            working_directory: &self.working_directory,
            environment: &self.environment,
            resource_limits: self.resource_limits,
        })
    }

    /// Returns the operation identity.
    pub const fn operation_id(&self) -> &OperationId {
        &self.operation_id
    }

    /// Returns the process-tree identity.
    pub const fn process_tree_id(&self) -> &ProcessTreeId {
        &self.process_tree_id
    }

    /// Returns the Job identity.
    pub const fn job_id(&self) -> &JobId {
        &self.job_id
    }

    /// Returns the pinned image identity.
    pub const fn image_id(&self) -> &ImageId {
        &self.image_id
    }

    /// Returns the session identity.
    pub const fn session_id(&self) -> &SessionId {
        &self.session_id
    }

    /// Returns the execution generation.
    pub const fn generation(&self) -> Generation {
        self.generation
    }

    /// Returns the executable path.
    pub fn executable(&self) -> &str {
        &self.executable
    }

    /// Returns the expected executable digest.
    pub fn executable_sha256(&self) -> &str {
        &self.executable_sha256
    }

    /// Returns argv.
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

    /// Returns the exact executable/environment/effect digest.
    pub fn effect_digest(&self) -> &str {
        &self.effect_digest
    }
}

/// Inert cross-process request accepted by the Kernel execution front door.
///
/// This is deliberately not a [`ProcessRequest`]: it carries no permit and
/// cannot grant execution authority. Kernel validates the exact caller/fence,
/// creates the one-shot permit and immediately moves the unique request into
/// the sole [`ProcessExecutor`].
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProcessExecutionAdmissionRequest {
    recipient_module_id: String,
    intent: ProcessIntent,
    action_lease_ref: ActionLeaseRef,
    state_fence: FencingToken,
    deadline_unix_ms: u64,
}

/// Stable authenticated owner projection retained with a process operation.
///
/// This deliberately excludes transport connection and session nonce data so
/// a fresh authenticated session for the same principal can reconcile an
/// unknown operation after reconnect.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProcessOwnerBinding {
    module_id: String,
    principal_digest: String,
    authority_epoch: u64,
    generation: Generation,
}

impl ProcessOwnerBinding {
    /// Creates a validated stable owner binding.
    pub fn new(
        module_id: impl Into<String>,
        principal_digest: impl Into<String>,
        authority_epoch: u64,
        generation: Generation,
    ) -> Result<Self, ContractError> {
        if authority_epoch == 0 {
            return Err(ContractError::InvalidValue {
                field: "owner_authority_epoch",
                reason: "authority epoch must be non-zero",
            });
        }
        let binding = Self {
            module_id: validate_opaque_id("owner_module_id", module_id.into())?,
            principal_digest: principal_digest.into(),
            authority_epoch,
            generation,
        };
        validate_hex_digest("owner_principal_digest", &binding.principal_digest)?;
        Ok(binding)
    }

    /// Returns the authenticated module identity.
    pub fn module_id(&self) -> &str {
        &self.module_id
    }
    /// Returns the opaque principal digest.
    pub fn principal_digest(&self) -> &str {
        &self.principal_digest
    }
    /// Returns the bound authority epoch.
    pub const fn authority_epoch(&self) -> u64 {
        self.authority_epoch
    }
    /// Returns the bound generation.
    pub const fn generation(&self) -> Generation {
        self.generation
    }
}

/// Ephemeral binding derived from the currently authenticated transport
/// session. It is never persisted as process ownership.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProcessSessionBinding {
    connection_id: String,
    session_epoch: u64,
}

impl ProcessSessionBinding {
    /// Creates a validated transport-session binding.
    pub fn new(
        connection_id: impl Into<String>,
        session_epoch: u64,
    ) -> Result<Self, ContractError> {
        if session_epoch == 0 {
            return Err(ContractError::InvalidValue {
                field: "session_epoch",
                reason: "session epoch must be non-zero",
            });
        }
        Ok(Self {
            connection_id: validate_opaque_id("connection_id", connection_id.into())?,
            session_epoch,
        })
    }

    /// Returns the established connection identity.
    pub fn connection_id(&self) -> &str {
        &self.connection_id
    }

    /// Returns the transport session epoch.
    pub const fn session_epoch(&self) -> u64 {
        self.session_epoch
    }
}

impl ProcessExecutionAdmissionRequest {
    /// Creates an inert, bounded admission request.
    pub fn new(
        recipient_module_id: impl Into<String>,
        intent: ProcessIntent,
        action_lease_ref: ActionLeaseRef,
        state_fence: FencingToken,
        deadline_unix_ms: u64,
    ) -> Result<Self, ContractError> {
        let request = Self {
            recipient_module_id: validate_opaque_id(
                "recipient_module_id",
                recipient_module_id.into(),
            )?,
            intent,
            action_lease_ref,
            state_fence,
            deadline_unix_ms,
        };
        request.validate()?;
        Ok(request)
    }

    /// Validates the inert request without issuing authority.
    pub fn validate(&self) -> Result<(), ContractError> {
        validate_opaque_id("recipient_module_id", self.recipient_module_id.clone())?;
        self.intent.validate()?;
        self.action_lease_ref.validate()?;
        if self.state_fence.generation != self.intent.generation {
            return Err(ContractError::FenceMismatch);
        }
        if self.deadline_unix_ms == 0 {
            return Err(ContractError::InvalidValue {
                field: "deadline_unix_ms",
                reason: "must be non-zero",
            });
        }
        Ok(())
    }

    /// Returns the authenticated recipient module identity.
    pub fn recipient_module_id(&self) -> &str {
        &self.recipient_module_id
    }

    /// Returns the immutable intent.
    pub const fn intent(&self) -> &ProcessIntent {
        &self.intent
    }

    /// Returns the Kernel-visible lease reference.
    pub const fn action_lease_ref(&self) -> &ActionLeaseRef {
        &self.action_lease_ref
    }

    /// Returns the requested state fence.
    pub const fn state_fence(&self) -> &FencingToken {
        &self.state_fence
    }

    /// Returns the absolute deadline.
    pub const fn deadline_unix_ms(&self) -> u64 {
        self.deadline_unix_ms
    }
}

/// Freshness, lease, fence, and revision material supplied by Kernel at issue time.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PermitIssuance {
    action_lease_ref: ActionLeaseRef,
    state_fence: FencingToken,
    expected_revision_heads: BTreeMap<String, String>,
    issued_at_unix_ms: u64,
    expires_at_unix_ms: u64,
    one_shot_nonce: String,
    validation_revision: Option<u64>,
}

impl PermitIssuance {
    /// Creates bounded one-shot permit material.
    pub fn new(
        action_lease_ref: ActionLeaseRef,
        state_fence: FencingToken,
        expected_revision_heads: BTreeMap<String, String>,
        issued_at_unix_ms: u64,
        expires_at_unix_ms: u64,
        one_shot_nonce: impl Into<String>,
    ) -> Result<Self, ContractError> {
        if issued_at_unix_ms == 0 || expires_at_unix_ms <= issued_at_unix_ms {
            return Err(ContractError::InvalidValue {
                field: "permit_freshness",
                reason: "issue time must be non-zero and precede expiry",
            });
        }
        validate_revision_heads(&expected_revision_heads)?;
        Ok(Self {
            action_lease_ref,
            state_fence,
            expected_revision_heads,
            issued_at_unix_ms,
            expires_at_unix_ms,
            one_shot_nonce: validate_opaque_id("one_shot_nonce", one_shot_nonce.into())?,
            validation_revision: None,
        })
    }

    /// Creates Store-bound permit material with an exact validation revision.
    pub fn new_with_validation_revision(
        action_lease_ref: ActionLeaseRef,
        state_fence: FencingToken,
        expected_revision_heads: BTreeMap<String, String>,
        issued_at_unix_ms: u64,
        expires_at_unix_ms: u64,
        one_shot_nonce: impl Into<String>,
        validation_revision: u64,
    ) -> Result<Self, ContractError> {
        if validation_revision == 0 {
            return Err(ContractError::InvalidValue {
                field: "validation_revision",
                reason: "must be non-zero",
            });
        }
        let mut issuance = Self::new(
            action_lease_ref,
            state_fence,
            expected_revision_heads,
            issued_at_unix_ms,
            expires_at_unix_ms,
            one_shot_nonce,
        )?;
        issuance.validation_revision = Some(validation_revision);
        Ok(issuance)
    }
}

/// Immutable process request consumed by [`ProcessExecutor::start`].
///
/// The request cannot be cloned or deserialized. A caller must first obtain an
/// authenticated [`DispatchPermit`] from the active Kernel authority.
#[derive(Debug, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProcessRequest {
    schema_version: String,
    intent: ProcessIntent,
    permit: DispatchPermit,
    invocation_digest: String,
}

impl ProcessRequest {
    /// Seals an intent and its consuming Kernel-issued permit.
    pub fn new(intent: ProcessIntent, permit: DispatchPermit) -> Result<Self, ContractError> {
        intent.validate()?;
        permit.validate_shape()?;
        if !permit.matches_intent(&intent) {
            return Err(ContractError::DispatchBindingMismatch);
        }
        let mut request = Self {
            schema_version: PROCESS_CONTRACT_SCHEMA_VERSION.to_owned(),
            intent,
            permit,
            invocation_digest: String::new(),
        };
        request.invocation_digest = request.compute_digest()?;
        Ok(request)
    }

    /// Validates request, intent, permit shape, and immutable digest.
    pub fn validate(&self) -> Result<(), ContractError> {
        if self.schema_version != PROCESS_CONTRACT_SCHEMA_VERSION {
            return Err(ContractError::SchemaVersion {
                expected: PROCESS_CONTRACT_SCHEMA_VERSION,
                observed: self.schema_version.clone(),
            });
        }
        self.intent.validate()?;
        self.permit.validate_shape()?;
        if !self.permit.matches_intent(&self.intent) {
            return Err(ContractError::DispatchBindingMismatch);
        }
        validate_stored_digest(
            "invocation_digest",
            &self.invocation_digest,
            self.compute_digest()?,
        )
    }

    fn compute_digest(&self) -> Result<String, ContractError> {
        #[derive(Serialize)]
        struct UnsignedRequest<'a> {
            schema_version: &'a str,
            intent: &'a ProcessIntent,
            permit_digest: &'a str,
        }
        hash_serialized(&UnsignedRequest {
            schema_version: &self.schema_version,
            intent: &self.intent,
            permit_digest: &self.permit.permit_digest,
        })
    }

    /// Returns the sealed invocation digest.
    pub fn invocation_digest(&self) -> &str {
        &self.invocation_digest
    }

    /// Returns the permit digest without exposing permit authority material.
    pub fn permit_digest(&self) -> &str {
        self.permit.digest()
    }

    /// Returns the immutable non-authoritative intent.
    pub const fn intent(&self) -> &ProcessIntent {
        &self.intent
    }

    /// Returns the operation identity.
    pub const fn operation_id(&self) -> &OperationId {
        self.intent.operation_id()
    }

    /// Returns the process-tree identity.
    pub const fn process_tree_id(&self) -> &ProcessTreeId {
        self.intent.process_tree_id()
    }

    /// Returns the Job identity.
    pub const fn job_id(&self) -> &JobId {
        self.intent.job_id()
    }

    /// Returns the image identity.
    pub const fn image_id(&self) -> &ImageId {
        self.intent.image_id()
    }

    /// Returns the session identity.
    pub const fn session_id(&self) -> &SessionId {
        self.intent.session_id()
    }

    /// Returns the execution generation.
    pub const fn generation(&self) -> Generation {
        self.intent.generation()
    }

    /// Returns the executable named by the non-authoritative intent.
    pub fn executable(&self) -> &str {
        self.intent.executable()
    }

    /// Returns the executable digest named by the non-authoritative intent.
    pub fn executable_sha256(&self) -> &str {
        self.intent.executable_sha256()
    }

    /// Returns the argument vector named by the non-authoritative intent.
    pub fn argv(&self) -> &[String] {
        self.intent.argv()
    }

    /// Returns the working directory named by the non-authoritative intent.
    pub fn working_directory(&self) -> &str {
        self.intent.working_directory()
    }

    /// Returns the environment projection named by the non-authoritative intent.
    pub const fn environment(&self) -> &EnvironmentProjection {
        self.intent.environment()
    }

    /// Returns the resource limits named by the non-authoritative intent.
    pub const fn resource_limits(&self) -> &ResourceLimits {
        self.intent.resource_limits()
    }

    /// Returns the effect digest named by the non-authoritative intent.
    pub fn effect_digest(&self) -> &str {
        self.intent.effect_digest()
    }

    /// Returns the authenticated fence.
    pub const fn fence(&self) -> &FencingToken {
        &self.permit.state_fence
    }

    /// Returns the authenticated ordering/revision heads without exposing
    /// dispatch authority material.
    pub const fn expected_revision_heads(&self) -> &BTreeMap<String, String> {
        &self.permit.expected_revision_heads
    }
}

/// Compatibility name for immutable process requests.
pub type ProcessSpec = ProcessRequest;

/// Current Kernel state used for one freshness-fenced validation round trip.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DispatchValidationContext {
    clock: ClockObservation,
    state_fence: FencingToken,
    authority_epoch: u64,
    revision_heads: BTreeMap<String, String>,
    validation_revision: u64,
}

impl DispatchValidationContext {
    /// Creates one current Kernel validation snapshot.
    pub fn new(
        clock: ClockObservation,
        state_fence: FencingToken,
        authority_epoch: u64,
        revision_heads: BTreeMap<String, String>,
        validation_revision: u64,
    ) -> Result<Self, ContractError> {
        let context = Self {
            clock,
            state_fence,
            authority_epoch,
            revision_heads,
            validation_revision,
        };
        context.validate()?;
        Ok(context)
    }

    fn validate(&self) -> Result<(), ContractError> {
        self.clock
            .validate()
            .map_err(|_| ContractError::InvalidValue {
                field: "validation_clock",
                reason: "P-01 clock observation is invalid",
            })?;
        let _ = self.now_unix_ms()?;
        if self.authority_epoch == 0 || self.validation_revision == 0 {
            return Err(ContractError::InvalidValue {
                field: "validation_context",
                reason: "authority epoch and validation revision must be non-zero",
            });
        }
        if self.state_fence.authority_epoch != self.authority_epoch {
            return Err(ContractError::FenceMismatch);
        }
        validate_revision_heads(&self.revision_heads)
    }

    fn now_unix_ms(&self) -> Result<u64, ContractError> {
        let value = self
            .clock
            .valid_time_ms
            .ok_or(ContractError::InvalidValue {
                field: "validation_clock.valid_time_ms",
                reason: "wall time is required for permit freshness",
            })?;
        u64::try_from(value).map_err(|_| ContractError::InvalidValue {
            field: "validation_clock.valid_time_ms",
            reason: "must be non-negative",
        })
    }
}

/// Exact authority and physical-contour binding repeated in every receipt/evidence path.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProcessExecutionBinding {
    operation_id: OperationId,
    process_tree_id: ProcessTreeId,
    job_id: JobId,
    image_id: ImageId,
    session_id: SessionId,
    generation: Generation,
    action_lease_ref: ActionLeaseRef,
    authority_id: DispatchAuthorityId,
    authority_epoch: u64,
    state_fence: FencingToken,
    request_digest: String,
    permit_digest: String,
    effect_digest: String,
    validation_revision: u64,
}

impl ProcessExecutionBinding {
    fn validate(&self) -> Result<(), ContractError> {
        self.operation_id.validate()?;
        self.process_tree_id.validate()?;
        self.job_id.validate()?;
        self.image_id.validate()?;
        self.session_id.validate()?;
        self.action_lease_ref.validate()?;
        self.authority_id.validate()?;
        if self.authority_epoch == 0 || self.validation_revision == 0 {
            return Err(ContractError::InvalidValue {
                field: "process_execution_binding",
                reason: "authority epoch and validation revision must be non-zero",
            });
        }
        validate_hex_digest("request_digest", &self.request_digest)?;
        validate_hex_digest("permit_digest", &self.permit_digest)?;
        validate_hex_digest("effect_digest", &self.effect_digest)?;
        if self.state_fence.authority_epoch != self.authority_epoch
            || self.state_fence.generation != self.generation
        {
            return Err(ContractError::FenceMismatch);
        }
        Ok(())
    }

    /// Returns the operation identity.
    pub const fn operation_id(&self) -> &OperationId {
        &self.operation_id
    }

    /// Returns the process-tree identity.
    pub const fn process_tree_id(&self) -> &ProcessTreeId {
        &self.process_tree_id
    }

    /// Returns the Job identity.
    pub const fn job_id(&self) -> &JobId {
        &self.job_id
    }

    /// Returns the image identity.
    pub const fn image_id(&self) -> &ImageId {
        &self.image_id
    }

    /// Returns the session identity.
    pub const fn session_id(&self) -> &SessionId {
        &self.session_id
    }

    /// Returns the authenticated state fence.
    pub const fn state_fence(&self) -> &FencingToken {
        &self.state_fence
    }

    /// Returns the permit digest.
    pub fn permit_digest(&self) -> &str {
        &self.permit_digest
    }

    /// Returns the request digest.
    pub fn request_digest(&self) -> &str {
        &self.request_digest
    }

    /// Returns the validation revision.
    pub const fn validation_revision(&self) -> u64 {
        self.validation_revision
    }

    fn matches_identity(&self, identity: &ProcessIdentity) -> bool {
        self.process_tree_id == *identity.process_tree_id()
            && self.job_id == *identity.job_id()
            && self.image_id == *identity.image_id()
            && self.session_id == *identity.session_id()
            && self.generation == identity.generation()
    }
}

/// Opaque proof produced only by a successful consuming authority validation.
///
/// This type has no public constructor, `Clone`, serialization, or
/// deserialization. P-02 may carry it as policy output but cannot inspect it to
/// create authority.
pub struct ValidatedDispatch {
    binding: ProcessExecutionBinding,
    suspended_identity: SuspendedProcessIdentity,
    validated_at_unix_ms: u64,
}

impl ValidatedDispatch {
    /// Returns the exact validated binding.
    pub const fn binding(&self) -> &ProcessExecutionBinding {
        &self.binding
    }

    /// Returns fresh pre-resume identity evidence.
    pub const fn suspended_identity(&self) -> &SuspendedProcessIdentity {
        &self.suspended_identity
    }

    /// Returns the Kernel validation time.
    pub const fn validated_at_unix_ms(&self) -> u64 {
        self.validated_at_unix_ms
    }
}

/// Fresh P-02 observation used by the P-07/P-03 recovery seam.
///
/// A persisted receipt or process view is not sufficient: recovery must carry
/// a newly observed suspended identity and the exact current state fence.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryObservation {
    suspended_identity: SuspendedProcessIdentity,
    state_fence: FencingToken,
    observed_at_unix_ms: u64,
}

impl RecoveryObservation {
    /// Creates a bounded observation retained from a fresh P-02 probe.
    pub fn new(
        suspended_identity: SuspendedProcessIdentity,
        state_fence: FencingToken,
        observed_at_unix_ms: u64,
    ) -> Result<Self, ContractError> {
        suspended_identity.validate()?;
        if observed_at_unix_ms == 0 {
            return Err(ContractError::InvalidValue {
                field: "recovery_observation.observed_at_unix_ms",
                reason: "must be non-zero",
            });
        }
        if state_fence.generation != suspended_identity.generation {
            return Err(ContractError::FenceMismatch);
        }
        Ok(Self {
            suspended_identity,
            state_fence,
            observed_at_unix_ms,
        })
    }

    /// Returns the fresh suspended-child identity.
    pub const fn suspended_identity(&self) -> &SuspendedProcessIdentity {
        &self.suspended_identity
    }

    /// Returns the fence observed by P-02.
    pub const fn state_fence(&self) -> &FencingToken {
        &self.state_fence
    }

    /// Returns the observation time.
    pub const fn observed_at_unix_ms(&self) -> u64 {
        self.observed_at_unix_ms
    }
}

/// P-03 capability minted after P-07 has selected a durable recovery record.
///
/// The fields and constructor remain private. P-07 obtains this value only
/// from [`DispatchPermitAuthority::issue_recovery_capability`], so a receipt,
/// replay snapshot, or deserialised view cannot stand in for recovery authority.
#[derive(Debug, Eq, PartialEq)]
pub struct RecoveryCapability {
    binding: ProcessExecutionBinding,
    capability_id: String,
    state_fence: FencingToken,
    validation_revision: u64,
}

impl RecoveryCapability {
    fn validate(
        &self,
        binding: &ProcessExecutionBinding,
        current: &DispatchValidationContext,
    ) -> Result<(), ContractError> {
        current.validate()?;
        if self.binding != *binding
            || self.state_fence != current.state_fence
            || self.state_fence != binding.state_fence
            || self.validation_revision != current.validation_revision
        {
            return Err(ContractError::RecoveryCapabilityMismatch);
        }
        Ok(())
    }

    /// Returns the durable P-07 capability reference without exposing authority.
    pub fn capability_id(&self) -> &str {
        &self.capability_id
    }
}

/// Canonical process lifecycle, separate from semantic readiness.
#[derive(Clone, Copy, Debug, Default, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProcessLifecycle {
    /// No physical launch has been validated.
    #[default]
    Created,
    /// A suspended child was validated and awaits/has just completed resume.
    Starting,
    /// The exact validated child is running.
    Running,
    /// Tree cancellation is in progress.
    Cancelling,
    /// Exit and tree closure are proven.
    Exited,
    /// A known failure is terminal.
    Failed,
    /// External disposition or tree closure is unknown.
    UnknownOutcome,
    /// Unknown outcome was reconciled with exact tree closure.
    Reconciled,
    /// The lineage was fenced for manual recovery.
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
            (Self::Created, Self::Starting | Self::Failed)
                | (
                    Self::Starting,
                    Self::Running | Self::Cancelling | Self::Failed | Self::UnknownOutcome
                )
                | (
                    Self::Running,
                    Self::Cancelling | Self::Exited | Self::Failed | Self::UnknownOutcome
                )
                | (
                    Self::Cancelling,
                    Self::Exited | Self::Failed | Self::UnknownOutcome
                )
                | (Self::UnknownOutcome, Self::Reconciled | Self::Quarantined)
        )
    }
}

/// Compatibility name for lifecycle projections.
pub type ProcessStatus = ProcessLifecycle;

/// Process health is not inferred from liveness.
#[derive(Clone, Copy, Debug, Default, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProcessHealthStatus {
    /// Health is not yet observed.
    #[default]
    Unknown,
    /// The process is healthy.
    Healthy,
    /// The process is degraded.
    Degraded,
}

/// One bounded process-health observation.
#[derive(Clone, Debug, Default, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProcessHealth {
    status: ProcessHealthStatus,
    ready: bool,
    observed_at_unix_ms: u64,
    detail: Option<String>,
}

impl ProcessHealth {
    /// Creates a bounded health observation.
    pub fn new(
        status: ProcessHealthStatus,
        ready: bool,
        observed_at_unix_ms: u64,
        detail: Option<String>,
    ) -> Result<Self, ContractError> {
        if let Some(value) = &detail {
            validate_opaque_id("health_detail", value.clone())?;
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

    /// Returns the readiness observation.
    pub const fn ready(&self) -> bool {
        self.ready
    }
}

/// Physical exit disposition, never a semantic verdict.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExitDisposition {
    /// A normal exit code was observed.
    Completed,
    /// A signal/exception termination was observed.
    Signalled,
    /// A resource limit stopped the tree.
    ResourceLimit,
    /// Cancellation stopped the tree.
    Cancelled,
    /// The external outcome cannot be classified.
    Unknown,
}

/// Immutable root-process exit observation.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExitStatus {
    disposition: ExitDisposition,
    code: Option<i32>,
    signal: Option<i32>,
    observed_at_unix_ms: u64,
}

impl ExitStatus {
    /// Creates a structurally valid exit observation.
    pub fn new(
        disposition: ExitDisposition,
        code: Option<i32>,
        signal: Option<i32>,
        observed_at_unix_ms: u64,
    ) -> Result<Self, ContractError> {
        let valid = match disposition {
            ExitDisposition::Completed => code.is_some() && signal.is_none(),
            ExitDisposition::Signalled => code.is_none() && signal.is_some(),
            ExitDisposition::ResourceLimit | ExitDisposition::Cancelled => signal.is_none(),
            ExitDisposition::Unknown => code.is_none() && signal.is_none(),
        };
        if !valid || observed_at_unix_ms == 0 {
            return Err(ContractError::InvalidValue {
                field: "exit_status",
                reason: "disposition fields or observation time are invalid",
            });
        }
        Ok(Self {
            disposition,
            code,
            signal,
            observed_at_unix_ms,
        })
    }

    /// Returns the physical disposition.
    pub const fn disposition(&self) -> ExitDisposition {
        self.disposition
    }
}

/// Cancellation progress independent of lifecycle.
#[derive(Clone, Copy, Debug, Default, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CancellationStatus {
    /// No cancellation was requested.
    #[default]
    NotRequested,
    /// Cancellation was admitted.
    Requested,
    /// Tree cancellation is executing.
    InProgress,
    /// Exact tree closure is proven.
    Completed,
    /// The request fence was stale.
    RejectedStaleFence,
    /// External cancellation disposition is unknown.
    UnknownOutcome,
}

/// Exact descendant-tree observation bound to permit and authority identity.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DescendantEvidence {
    binding: ProcessExecutionBinding,
    root_process_id: ProcessId,
    process_ids: Vec<ProcessId>,
    complete: bool,
    tree_terminated: bool,
    evidence_ref: Option<String>,
}

impl DescendantEvidence {
    /// Creates an exact tree observation.
    pub fn new(
        binding: ProcessExecutionBinding,
        root_process_id: ProcessId,
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
        if process_ids.iter().collect::<BTreeSet<_>>().len() != process_ids.len() {
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
        if (complete || tree_terminated) && evidence_ref.as_deref().is_none_or(str::is_empty) {
            return Err(ContractError::InvalidValue {
                field: "descendant_evidence.evidence_ref",
                reason: "closure claims require a raw evidence handle",
            });
        }
        Ok(Self {
            binding,
            root_process_id,
            process_ids,
            complete,
            tree_terminated,
            evidence_ref,
        })
    }

    /// Returns the exact authority/process binding.
    pub const fn binding(&self) -> &ProcessExecutionBinding {
        &self.binding
    }

    /// Returns observed descendant identities.
    pub fn process_ids(&self) -> &[ProcessId] {
        &self.process_ids
    }

    /// Returns whether observation is complete.
    pub const fn complete(&self) -> bool {
        self.complete
    }

    /// Returns whether every Job member was terminated/reaped.
    pub const fn tree_terminated(&self) -> bool {
        self.tree_terminated
    }

    /// Returns the raw evidence handle.
    pub fn evidence_ref(&self) -> Option<&str> {
        self.evidence_ref.as_deref()
    }

    fn matches(&self, binding: &ProcessExecutionBinding, identity: &ProcessIdentity) -> bool {
        self.binding == *binding && self.root_process_id == *identity.process_id()
    }
}

/// Typed process execution view.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProcessExecutionView {
    binding: ProcessExecutionBinding,
    lifecycle: ProcessLifecycle,
    health: ProcessHealth,
    cancellation: CancellationStatus,
    identity: Option<ProcessIdentity>,
    exit: Option<ExitStatus>,
    descendants: Option<DescendantEvidence>,
}

impl ProcessExecutionView {
    /// Returns the exact permit/authority/process contour binding.
    pub const fn binding(&self) -> &ProcessExecutionBinding {
        &self.binding
    }

    /// Returns lifecycle.
    pub const fn lifecycle(&self) -> ProcessLifecycle {
        self.lifecycle
    }

    /// Returns health.
    pub const fn health(&self) -> &ProcessHealth {
        &self.health
    }

    /// Returns cancellation status.
    pub const fn cancellation(&self) -> CancellationStatus {
        self.cancellation
    }

    /// Returns resumed process identity when available.
    pub const fn identity(&self) -> Option<&ProcessIdentity> {
        self.identity.as_ref()
    }

    /// Returns exit observation.
    pub const fn exit(&self) -> Option<&ExitStatus> {
        self.exit.as_ref()
    }

    /// Returns descendant evidence.
    pub const fn descendants(&self) -> Option<&DescendantEvidence> {
        self.descendants.as_ref()
    }

    /// Returns operation identity.
    pub const fn operation_id(&self) -> &OperationId {
        self.binding.operation_id()
    }

    /// Returns request digest.
    pub fn request_digest(&self) -> &str {
        self.binding.request_digest()
    }

    /// Returns the authenticated fence.
    pub const fn fence(&self) -> &FencingToken {
        self.binding.state_fence()
    }

    fn validate_internal(&self) -> Result<(), ContractError> {
        if let Some(identity) = &self.identity
            && !self.binding.matches_identity(identity)
        {
            return Err(ContractError::EvidenceBindingMismatch);
        }
        if let (Some(identity), Some(descendants)) = (&self.identity, &self.descendants)
            && !descendants.matches(&self.binding, identity)
        {
            return Err(ContractError::EvidenceBindingMismatch);
        }
        Ok(())
    }
}

/// Reconciliation evidence emitted by a physical implementation.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProcessEvidence {
    view: ProcessExecutionView,
    stdout_ref: Option<String>,
    stderr_ref: Option<String>,
    axes: EvidenceAxes,
}

impl ProcessEvidence {
    /// Creates raw process evidence with C0-05 observation-only axes.
    pub fn new(
        view: ProcessExecutionView,
        stdout_ref: Option<String>,
        stderr_ref: Option<String>,
        axes: EvidenceAxes,
    ) -> Result<Self, ContractError> {
        view.validate_internal()?;
        axes.validate().map_err(|_| ContractError::InvalidValue {
            field: "evidence_axes",
            reason: "C0-05 evidence axes are invalid",
        })?;
        if axes.status != EvidenceStatus::Observed
            || axes.assertability != Assertability::NonAssertableUnverified
        {
            return Err(ContractError::EvidenceAuthorityEscalation);
        }
        Ok(Self {
            view,
            stdout_ref,
            stderr_ref,
            axes,
        })
    }

    /// Returns the exact binding through the view.
    pub const fn binding(&self) -> &ProcessExecutionBinding {
        self.view.binding()
    }

    /// Returns operation identity.
    pub const fn operation_id(&self) -> &OperationId {
        self.view.operation_id()
    }

    /// Returns request digest.
    pub fn request_digest(&self) -> &str {
        self.view.request_digest()
    }

    /// Returns the process view.
    pub const fn view(&self) -> &ProcessExecutionView {
        &self.view
    }

    /// Returns stdout evidence handle.
    pub fn stdout_ref(&self) -> Option<&str> {
        self.stdout_ref.as_deref()
    }

    /// Returns stderr evidence handle.
    pub fn stderr_ref(&self) -> Option<&str> {
        self.stderr_ref.as_deref()
    }

    /// Returns C0-05 evidence axes.
    pub const fn axes(&self) -> EvidenceAxes {
        self.axes
    }
}

/// Exact cancellation command binding.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CancellationRequest {
    binding: ProcessExecutionBinding,
}

impl CancellationRequest {
    /// Binds cancellation to the exact validated dispatch.
    pub fn new(binding: ProcessExecutionBinding) -> Self {
        Self { binding }
    }

    /// Returns the exact binding.
    pub const fn binding(&self) -> &ProcessExecutionBinding {
        &self.binding
    }
}

/// Cancellation receipt bound to exact permit, authority, process, Job, image, and session.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CancellationReceipt {
    binding: ProcessExecutionBinding,
    identity: Option<ProcessIdentity>,
    status: CancellationStatus,
    lifecycle: ProcessLifecycle,
    no_effect_proven: bool,
    descendants: Option<DescendantEvidence>,
}

impl CancellationReceipt {
    /// Returns the exact authority/process binding.
    pub const fn binding(&self) -> &ProcessExecutionBinding {
        &self.binding
    }

    /// Returns cancellation status.
    pub const fn status(&self) -> CancellationStatus {
        self.status
    }

    /// Returns lifecycle.
    pub const fn lifecycle(&self) -> ProcessLifecycle {
        self.lifecycle
    }

    /// Returns whether no physical effect was proven.
    pub const fn no_effect_proven(&self) -> bool {
        self.no_effect_proven
    }

    /// Returns descendant cleanup evidence.
    pub const fn descendants(&self) -> Option<&DescendantEvidence> {
        self.descendants.as_ref()
    }
}

/// Pure process transition model after successful pre-resume validation.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProcessState {
    binding: ProcessExecutionBinding,
    suspended_identity: SuspendedProcessIdentity,
    lifecycle: ProcessLifecycle,
    health: ProcessHealth,
    cancellation: CancellationStatus,
    identity: Option<ProcessIdentity>,
    exit: Option<ExitStatus>,
    descendants: Option<DescendantEvidence>,
}

impl ProcessState {
    /// Starts in `Starting` only from an opaque consumed validation result.
    pub fn from_validated(validated: &ValidatedDispatch) -> Self {
        Self {
            binding: validated.binding.clone(),
            suspended_identity: validated.suspended_identity.clone(),
            lifecycle: ProcessLifecycle::Starting,
            health: ProcessHealth::default(),
            cancellation: CancellationStatus::NotRequested,
            identity: None,
            exit: None,
            descendants: None,
        }
    }

    /// Returns a detached exact view.
    pub fn view(&self) -> ProcessExecutionView {
        ProcessExecutionView {
            binding: self.binding.clone(),
            lifecycle: self.lifecycle,
            health: self.health.clone(),
            cancellation: self.cancellation,
            identity: self.identity.clone(),
            exit: self.exit.clone(),
            descendants: self.descendants.clone(),
        }
    }

    /// Returns the exact validated binding.
    pub const fn binding(&self) -> &ProcessExecutionBinding {
        &self.binding
    }

    /// Completes recovery start only from fresh P-02 evidence and a current
    /// P-07/P-03 capability. A persisted [`ProcessStartReceipt`] is never
    /// accepted as a substitute for these inputs.
    pub fn recover_start(
        &mut self,
        observation: &RecoveryObservation,
        capability: &RecoveryCapability,
        current: &DispatchValidationContext,
        health: ProcessHealth,
    ) -> Result<ProcessStartReceipt, ContractError> {
        if self.lifecycle != ProcessLifecycle::Starting {
            return Err(ContractError::InvalidTransition {
                from: self.lifecycle,
                to: ProcessLifecycle::Running,
            });
        }
        current.validate()?;
        capability.validate(&self.binding, current)?;
        let now = current.now_unix_ms()?;
        if observation.observed_at_unix_ms > now
            || now.saturating_sub(observation.observed_at_unix_ms) > MAX_RECOVERY_OBSERVATION_AGE_MS
        {
            return Err(ContractError::StaleRecoveryObservation);
        }
        if observation.state_fence != current.state_fence
            || observation.state_fence != self.binding.state_fence
            || observation.suspended_identity != self.suspended_identity
        {
            return Err(ContractError::RecoveryObservationMismatch);
        }
        self.mark_resumed(observation.observed_at_unix_ms, health)?;
        ProcessStartReceipt::new(self)
    }

    /// Records that P-02 resumed the validated child.
    pub fn mark_resumed(
        &mut self,
        resumed_at_unix_ms: u64,
        health: ProcessHealth,
    ) -> Result<(), ContractError> {
        self.ensure_transition(ProcessLifecycle::Running)?;
        let identity =
            ProcessIdentity::after_resume(self.suspended_identity.clone(), resumed_at_unix_ms)?;
        if !self.binding.matches_identity(&identity) {
            return Err(ContractError::IdentityMismatch);
        }
        self.lifecycle = ProcessLifecycle::Running;
        self.identity = Some(identity);
        self.health = health;
        Ok(())
    }

    /// Records a physical exit without overclaiming missing tree closure.
    pub fn exit(
        &mut self,
        exit: ExitStatus,
        descendants: DescendantEvidence,
    ) -> Result<(), ContractError> {
        let identity = self
            .identity
            .as_ref()
            .ok_or(ContractError::MissingIdentity)?;
        if !descendants.matches(&self.binding, identity) {
            return Err(ContractError::EvidenceBindingMismatch);
        }
        let next = if exit.disposition == ExitDisposition::Unknown
            || !descendants.complete
            || !descendants.tree_terminated
        {
            ProcessLifecycle::UnknownOutcome
        } else {
            ProcessLifecycle::Exited
        };
        self.ensure_transition(next)?;
        let cancellation = match (self.cancellation, next) {
            (CancellationStatus::InProgress, ProcessLifecycle::Exited) => {
                CancellationStatus::Completed
            }
            (CancellationStatus::InProgress, ProcessLifecycle::UnknownOutcome) => {
                CancellationStatus::UnknownOutcome
            }
            (status, _) => status,
        };
        self.lifecycle = next;
        self.exit = Some(exit);
        self.descendants = Some(descendants);
        self.cancellation = cancellation;
        Ok(())
    }

    /// Requests cancellation under the exact validated binding.
    ///
    /// Unknown and invalid paths return before any state mutation.
    pub fn cancel(
        &mut self,
        request: &CancellationRequest,
    ) -> Result<CancellationReceipt, ContractError> {
        if request.binding != self.binding {
            return Err(ContractError::StaleStateFence);
        }
        if self.lifecycle == ProcessLifecycle::UnknownOutcome {
            return Err(ContractError::UnknownOutcomeRequiresReconciliation);
        }
        if self.lifecycle.is_terminal() || self.lifecycle == ProcessLifecycle::Cancelling {
            return Ok(self.cancellation_receipt());
        }
        self.ensure_transition(ProcessLifecycle::Cancelling)?;
        self.lifecycle = ProcessLifecycle::Cancelling;
        self.cancellation = CancellationStatus::InProgress;
        Ok(self.cancellation_receipt())
    }

    /// Reconciles an unknown outcome only with exact, complete tree termination.
    pub fn reconcile(&mut self, descendants: DescendantEvidence) -> Result<(), ContractError> {
        if self.lifecycle != ProcessLifecycle::UnknownOutcome {
            return Err(ContractError::UnknownOutcomeRequiresReconciliation);
        }
        let identity = self
            .identity
            .as_ref()
            .ok_or(ContractError::MissingIdentity)?;
        if !descendants.matches(&self.binding, identity) {
            return Err(ContractError::EvidenceBindingMismatch);
        }
        if !descendants.complete || !descendants.tree_terminated {
            return Err(ContractError::IncompleteDescendantEvidence);
        }
        self.ensure_transition(ProcessLifecycle::Reconciled)?;
        let cancellation = if matches!(
            self.cancellation,
            CancellationStatus::InProgress | CancellationStatus::UnknownOutcome
        ) {
            CancellationStatus::Completed
        } else {
            self.cancellation
        };
        self.lifecycle = ProcessLifecycle::Reconciled;
        self.descendants = Some(descendants);
        self.cancellation = cancellation;
        Ok(())
    }

    fn ensure_transition(&self, next: ProcessLifecycle) -> Result<(), ContractError> {
        if self.lifecycle.can_transition_to(next) {
            Ok(())
        } else {
            Err(ContractError::InvalidTransition {
                from: self.lifecycle,
                to: next,
            })
        }
    }

    fn cancellation_receipt(&self) -> CancellationReceipt {
        CancellationReceipt {
            binding: self.binding.clone(),
            identity: self.identity.clone(),
            status: self.cancellation,
            lifecycle: self.lifecycle,
            no_effect_proven: self.lifecycle == ProcessLifecycle::Created,
            descendants: self.descendants.clone(),
        }
    }
}

/// Receipt returned only after the validated suspended child was resumed.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProcessStartReceipt {
    binding: ProcessExecutionBinding,
    identity: ProcessIdentity,
    lifecycle: ProcessLifecycle,
}

impl ProcessStartReceipt {
    /// Creates a receipt from an exact running state.
    pub fn new(state: &ProcessState) -> Result<Self, ContractError> {
        if state.lifecycle != ProcessLifecycle::Running {
            return Err(ContractError::ResumeNotObserved);
        }
        let identity = state
            .identity
            .clone()
            .ok_or(ContractError::ResumeNotObserved)?;
        if !state.binding.matches_identity(&identity) {
            return Err(ContractError::IdentityMismatch);
        }
        let receipt = Self {
            binding: state.binding.clone(),
            identity,
            lifecycle: state.lifecycle,
        };
        receipt.validate()?;
        Ok(receipt)
    }

    /// Revalidates a deserialized durable receipt before replay admission.
    ///
    /// A receipt is inert historical data until the physical executor also
    /// proves the exact process is still Running.
    pub fn validate(&self) -> Result<(), ContractError> {
        self.binding.validate()?;
        self.identity.suspended.validate()?;
        if self.lifecycle != ProcessLifecycle::Running
            || !self.binding.matches_identity(&self.identity)
        {
            return Err(ContractError::IdentityMismatch);
        }
        Ok(())
    }

    /// Returns the exact authority/process binding.
    pub const fn binding(&self) -> &ProcessExecutionBinding {
        &self.binding
    }

    /// Returns the operation identity.
    pub const fn operation_id(&self) -> &OperationId {
        self.binding.operation_id()
    }

    /// Returns the request digest.
    pub fn request_digest(&self) -> &str {
        self.binding.request_digest()
    }

    /// Returns the permit digest.
    pub fn permit_digest(&self) -> &str {
        self.binding.permit_digest()
    }

    /// Returns the accepted generation.
    pub const fn accepted_generation(&self) -> Generation {
        self.binding.generation
    }

    /// Returns lifecycle.
    pub const fn lifecycle(&self) -> ProcessLifecycle {
        self.lifecycle
    }

    /// Returns exact resumed identity and resume time.
    pub const fn identity(&self) -> &ProcessIdentity {
        &self.identity
    }
}

/// Stable wire identity for the Kernel-owned durable eliotd live receipt.
pub const ELIOTD_LIVE_RECEIPT_WIRE_ID: &str = "eliot.eliotd-live-receipt";
/// Current durable eliotd live receipt revision.
pub const ELIOTD_LIVE_RECEIPT_WIRE_VERSION: u16 = 2;

/// Exact current supervision authority evidence copied from the verified ORS
/// snapshot.  These values are evidence references, not a second authority
/// envelope; consumers must still read the selected ORS record and compare all
/// references before treating the process as live.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EliotdLiveSupervisionEvidence {
    /// Current ORS lease identity.
    pub lease_id: String,
    /// Current ORS record identity.
    pub record_id: String,
    /// Current ORS revision.
    pub revision: u64,
    /// Canonical ORS receipt digest.
    pub receipt_sha256: String,
    /// Signed supervision envelope digest.
    pub envelope_sha256: String,
    /// Signed supervision payload digest.
    pub payload_sha256: String,
    /// Installation-pinned trust-anchor fingerprint.
    pub public_key_fingerprint: String,
}

impl EliotdLiveSupervisionEvidence {
    /// Validates the bounded evidence references without granting authority.
    pub fn validate(&self) -> Result<(), ContractError> {
        validate_opaque_id("eliotd_supervision_lease_id", self.lease_id.clone())?;
        validate_opaque_id("eliotd_supervision_record_id", self.record_id.clone())?;
        if self.revision == 0 {
            return Err(ContractError::InvalidValue {
                field: "eliotd_supervision_revision",
                reason: "must be non-zero",
            });
        }
        for (field, digest) in [
            ("eliotd_supervision_receipt_sha256", &self.receipt_sha256),
            ("eliotd_supervision_envelope_sha256", &self.envelope_sha256),
            ("eliotd_supervision_payload_sha256", &self.payload_sha256),
            (
                "eliotd_supervision_public_key_fingerprint",
                &self.public_key_fingerprint,
            ),
        ] {
            validate_hex_digest(field, digest)?;
        }
        Ok(())
    }
}

/// Exact request/session evidence attached to one authenticated `daemon_ready`
/// publication.  The request payload is represented by its canonical digest;
/// the raw request remains on the authenticated transport only.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EliotdLiveReadyEvidence {
    /// Authenticated request identity.
    pub request_id: String,
    /// Canonical digest of the ready request payload.
    pub request_payload_sha256: String,
    /// Authenticated transport connection identity.
    pub connection_id: String,
    /// Monotonic authenticated session fence.
    pub session_epoch: u64,
    /// Session authority epoch.
    pub authority_epoch: u64,
    /// Session resource generation.
    pub generation: u64,
    /// Digest of the authenticated launch nonce.
    pub launch_nonce_sha256: String,
}

impl EliotdLiveReadyEvidence {
    /// Validates the bounded request/session evidence.
    pub fn validate(&self) -> Result<(), ContractError> {
        validate_opaque_id("eliotd_ready_request_id", self.request_id.clone())?;
        validate_hex_digest(
            "eliotd_ready_request_payload_sha256",
            &self.request_payload_sha256,
        )?;
        validate_opaque_id("eliotd_ready_connection_id", self.connection_id.clone())?;
        if self.session_epoch == 0 || self.authority_epoch == 0 || self.generation == 0 {
            return Err(ContractError::InvalidValue {
                field: "eliotd_ready_session_fence",
                reason: "session epoch, authority epoch, and generation must be non-zero",
            });
        }
        validate_hex_digest(
            "eliotd_ready_launch_nonce_sha256",
            &self.launch_nonce_sha256,
        )?;
        Ok(())
    }
}

/// Kernel-owned durable receipt proving that the exact eliotd process passed
/// authenticated readiness and was observed in its executor Job.  This is an
/// inert evidence record: status consumers must independently re-read the
/// manifest, receipt file, ORS, and live process contour.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EliotdLiveReceipt {
    /// Stable wire discriminator.
    pub wire_id: String,
    /// Durable receipt wire revision.
    pub wire_version: u16,
    /// Manifest-selected Host state root that owns this receipt.
    pub receipt_root: String,
    /// Stable identity digest of the selected Host state root.
    pub receipt_root_identity_sha256: String,
    /// Installer-owned digest of the complete `RuntimeStateRoots` topology.
    pub runtime_state_roots_digest: String,
    /// Exact installation identity selected by the active manifest.
    pub installation_id: String,
    /// Exact active manifest generation identity.
    pub approved_generation: String,
    /// Approved resource generation.
    pub generation: u64,
    /// Approved authority epoch.
    pub authority_epoch: u64,
    /// Approved eliotd Governor configuration digest.
    pub config_descriptor_sha256: String,
    /// Approved eliotd launch descriptor digest.
    pub descriptor_sha256: String,
    /// Approved Kernel executable digest that authorizes this writer domain.
    pub kernel_artifact_sha256: String,
    /// Exact physical process-start receipt returned by the executor.
    pub process: ProcessStartReceipt,
    /// Exact current supervision/ORS references.
    pub supervision: EliotdLiveSupervisionEvidence,
    /// Exact authenticated ready request/session references.
    pub ready: EliotdLiveReadyEvidence,
    /// Kernel-observed publication time.
    pub published_at_unix_ms: u64,
    /// Digest of the canonical receipt with this field omitted.
    pub receipt_sha256: String,
}

#[derive(Serialize)]
struct EliotdLiveReceiptUnsigned<'a> {
    wire_id: &'a str,
    wire_version: u16,
    receipt_root: &'a str,
    receipt_root_identity_sha256: &'a str,
    runtime_state_roots_digest: &'a str,
    installation_id: &'a str,
    approved_generation: &'a str,
    generation: u64,
    authority_epoch: u64,
    config_descriptor_sha256: &'a str,
    descriptor_sha256: &'a str,
    kernel_artifact_sha256: &'a str,
    process: &'a ProcessStartReceipt,
    supervision: &'a EliotdLiveSupervisionEvidence,
    ready: &'a EliotdLiveReadyEvidence,
    published_at_unix_ms: u64,
}

impl EliotdLiveReceipt {
    /// Computes one receipt from exact validated evidence.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        receipt_root: impl Into<String>,
        receipt_root_identity_sha256: impl Into<String>,
        runtime_state_roots_digest: impl Into<String>,
        installation_id: impl Into<String>,
        approved_generation: impl Into<String>,
        generation: u64,
        authority_epoch: u64,
        config_descriptor_sha256: impl Into<String>,
        descriptor_sha256: impl Into<String>,
        kernel_artifact_sha256: impl Into<String>,
        process: ProcessStartReceipt,
        supervision: EliotdLiveSupervisionEvidence,
        ready: EliotdLiveReadyEvidence,
        published_at_unix_ms: u64,
    ) -> Result<Self, ContractError> {
        let mut receipt = Self {
            wire_id: ELIOTD_LIVE_RECEIPT_WIRE_ID.to_owned(),
            wire_version: ELIOTD_LIVE_RECEIPT_WIRE_VERSION,
            receipt_root: receipt_root.into(),
            receipt_root_identity_sha256: receipt_root_identity_sha256.into(),
            runtime_state_roots_digest: runtime_state_roots_digest.into(),
            installation_id: installation_id.into(),
            approved_generation: approved_generation.into(),
            generation,
            authority_epoch,
            config_descriptor_sha256: config_descriptor_sha256.into(),
            descriptor_sha256: descriptor_sha256.into(),
            kernel_artifact_sha256: kernel_artifact_sha256.into(),
            process,
            supervision,
            ready,
            published_at_unix_ms,
            receipt_sha256: String::new(),
        };
        receipt.validate_shape()?;
        receipt.receipt_sha256 = receipt.compute_digest()?;
        Ok(receipt)
    }

    fn unsigned(&self) -> EliotdLiveReceiptUnsigned<'_> {
        EliotdLiveReceiptUnsigned {
            wire_id: &self.wire_id,
            wire_version: self.wire_version,
            receipt_root: &self.receipt_root,
            receipt_root_identity_sha256: &self.receipt_root_identity_sha256,
            runtime_state_roots_digest: &self.runtime_state_roots_digest,
            installation_id: &self.installation_id,
            approved_generation: &self.approved_generation,
            generation: self.generation,
            authority_epoch: self.authority_epoch,
            config_descriptor_sha256: &self.config_descriptor_sha256,
            descriptor_sha256: &self.descriptor_sha256,
            kernel_artifact_sha256: &self.kernel_artifact_sha256,
            process: &self.process,
            supervision: &self.supervision,
            ready: &self.ready,
            published_at_unix_ms: self.published_at_unix_ms,
        }
    }

    fn validate_shape(&self) -> Result<(), ContractError> {
        if self.wire_id != ELIOTD_LIVE_RECEIPT_WIRE_ID {
            return Err(ContractError::SchemaVersion {
                expected: ELIOTD_LIVE_RECEIPT_WIRE_ID,
                observed: self.wire_id.clone(),
            });
        }
        if self.wire_version != ELIOTD_LIVE_RECEIPT_WIRE_VERSION {
            return Err(ContractError::SchemaVersion {
                expected: "eliotd-live-receipt-v2",
                observed: self.wire_version.to_string(),
            });
        }
        if self.receipt_root.trim().is_empty()
            || !std::path::Path::new(&self.receipt_root).is_absolute()
            || self.receipt_root.chars().any(char::is_control)
        {
            return Err(ContractError::InvalidValue {
                field: "eliotd_receipt_root",
                reason: "must be an absolute control-free path",
            });
        }
        if self.generation == 0 || self.authority_epoch == 0 || self.published_at_unix_ms == 0 {
            return Err(ContractError::InvalidValue {
                field: "eliotd_receipt_fence",
                reason: "generation, authority epoch, and publication time must be non-zero",
            });
        }
        validate_opaque_id(
            "eliotd_receipt_installation_id",
            self.installation_id.clone(),
        )?;
        validate_opaque_id(
            "eliotd_receipt_approved_generation",
            self.approved_generation.clone(),
        )?;
        for (field, digest) in [
            (
                "eliotd_receipt_root_identity_sha256",
                &self.receipt_root_identity_sha256,
            ),
            (
                "eliotd_runtime_state_roots_digest",
                &self.runtime_state_roots_digest,
            ),
            (
                "eliotd_config_descriptor_sha256",
                &self.config_descriptor_sha256,
            ),
            ("eliotd_descriptor_sha256", &self.descriptor_sha256),
            (
                "eliotd_kernel_artifact_sha256",
                &self.kernel_artifact_sha256,
            ),
        ] {
            validate_hex_digest(field, digest)?;
        }
        self.process.validate()?;
        self.supervision.validate()?;
        self.ready.validate()?;
        if self.ready.generation != self.generation
            || self.ready.authority_epoch != self.authority_epoch
        {
            return Err(ContractError::FenceMismatch);
        }
        Ok(())
    }

    fn compute_digest(&self) -> Result<String, ContractError> {
        let bytes =
            canonical_json_bytes(&self.unsigned()).map_err(|_| ContractError::InvalidValue {
                field: "eliotd_receipt",
                reason: "canonical serialization failed",
            })?;
        Ok(sha256_hex(&bytes))
    }

    /// Revalidates structure and the canonical receipt digest.
    pub fn validate(&self) -> Result<(), ContractError> {
        self.validate_shape()?;
        let expected = self.compute_digest()?;
        if expected != self.receipt_sha256 {
            return Err(ContractError::DigestMismatch {
                field: "eliotd_receipt_sha256",
                expected,
                observed: self.receipt_sha256.clone(),
            });
        }
        validate_hex_digest("eliotd_receipt_sha256", &self.receipt_sha256)
    }

    /// Returns the canonical receipt digest.
    pub fn receipt_sha256(&self) -> &str {
        &self.receipt_sha256
    }
}

/// Receives immutable evidence from a physical executor.
pub trait ProcessEvidenceSink: Send + Sync {
    /// Persists or forwards one evidence record without granting authority.
    fn record(&self, evidence: ProcessEvidence) -> Result<(), EvidenceSinkError>;
}

/// Provider-neutral executor boundary. P-04 owns the sole Windows implementation.
#[allow(async_fn_in_trait)]
pub trait ProcessExecutor: Send + Sync {
    /// Launches one consuming request through pre-resume Kernel validation.
    async fn start(
        &self,
        request: ProcessRequest,
        sink: Arc<dyn ProcessEvidenceSink>,
    ) -> Result<ProcessStartReceipt, ProcessExecutionError>;

    /// Inspects one operation.
    async fn inspect(
        &self,
        operation_id: OperationId,
    ) -> Result<ProcessExecutionView, ProcessExecutionError>;

    /// Requests cancellation of one exact stored operation.
    async fn cancel(
        &self,
        operation_id: OperationId,
    ) -> Result<CancellationReceipt, ProcessExecutionError>;

    /// Reconciles one unknown external result.
    async fn reconcile(
        &self,
        operation_id: OperationId,
    ) -> Result<ProcessEvidence, ProcessExecutionError>;
}

/// Kernel-owned launch proof checked after suspension and immediately before
/// the physical child is resumed.
pub trait ProcessLaunchAdmission: Send + Sync {
    /// Revalidates retained path/identity material for one exact request.
    fn validate_launch(
        &self,
        request: &ProcessRequest,
        observed: &SuspendedProcessIdentity,
        launch: &SuspendedLaunchEvidence,
    ) -> Result<(), ContractError>;
}

/// Errors belonging to the P-03 process contract.
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
    /// An opaque value was invalid.
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
    /// A duplicate value would make identity ambiguous.
    #[error("duplicate value in {field}")]
    DuplicateValue {
        /// Field name.
        field: &'static str,
    },
    /// Secret-like material crossed the plain boundary.
    #[error("secret boundary rejected {field}")]
    SecretBoundary {
        /// Field name.
        field: &'static str,
    },
    /// Contract schema mismatch.
    #[error("schema version mismatch: expected {expected}, observed {observed}")]
    SchemaVersion {
        /// Expected version.
        expected: &'static str,
        /// Observed version.
        observed: String,
    },
    /// Immutable digest mismatch.
    #[error("{field} mismatch: expected {expected}, observed {observed}")]
    DigestMismatch {
        /// Digest field.
        field: &'static str,
        /// Recomputed digest.
        expected: String,
        /// Stored digest.
        observed: String,
    },
    /// Fence fields disagree.
    #[error("state fence does not match generation or authority")]
    FenceMismatch,
    /// A Kernel-issued permit is required.
    #[error("DISPATCH_PERMIT_REQUIRED")]
    DispatchPermitRequired,
    /// Permit authentication failed.
    #[error("dispatch permit authentication failed")]
    DispatchAuthenticationFailed,
    /// A replay snapshot was recovered under the wrong authority identity.
    #[error("dispatch authority identity mismatch")]
    DispatchAuthorityMismatch,
    /// Permit and immutable request do not bind the same effect.
    #[error("dispatch permit binding mismatch")]
    DispatchBindingMismatch,
    /// A one-shot permit was already consumed.
    #[error("dispatch permit was already consumed")]
    DispatchPermitConsumed,
    /// Permit freshness expired.
    #[error("dispatch permit expired")]
    ExpiredDispatchPermit,
    /// The active State Fence changed.
    #[error("STALE_STATE_FENCE")]
    StaleStateFence,
    /// The active authority epoch changed.
    #[error("STALE_AUTHORITY_EPOCH")]
    StaleAuthorityEpoch,
    /// A required revision head changed.
    #[error("dispatch permit revision heads are stale")]
    StaleRevisionHeads,
    /// Lifecycle transition is not admitted.
    #[error("invalid lifecycle transition from {from:?} to {to:?}")]
    InvalidTransition {
        /// Current state.
        from: ProcessLifecycle,
        /// Requested state.
        to: ProcessLifecycle,
    },
    /// Physical identity differs from the permitted contour.
    #[error("process, Job, image, session, or generation identity mismatch")]
    IdentityMismatch,
    /// A resumed identity was required.
    #[error("process identity is missing")]
    MissingIdentity,
    /// Resume has not been observed.
    #[error("validated child resume has not been observed")]
    ResumeNotObserved,
    /// Recovery capability did not bind to the current P-03 state.
    #[error("recovery capability does not bind to current process authority")]
    RecoveryCapabilityMismatch,
    /// Recovery observation did not bind to the current fence/identity.
    #[error("recovery observation does not bind to current process state")]
    RecoveryObservationMismatch,
    /// Recovery observation is too old or from the future.
    #[error("recovery observation is stale")]
    StaleRecoveryObservation,
    /// Reconciliation lacks complete terminated-tree evidence.
    #[error("descendant evidence is incomplete or tree termination is unproven")]
    IncompleteDescendantEvidence,
    /// Evidence belongs to another exact binding.
    #[error("evidence binding mismatch")]
    EvidenceBindingMismatch,
    /// Raw evidence attempted to claim semantic authority.
    #[error("process evidence must remain observation-only")]
    EvidenceAuthorityEscalation,
    /// Unknown outcomes must be reconciled before another transition.
    #[error("unknown outcome requires reconciliation")]
    UnknownOutcomeRequiresReconciliation,
    /// Stable serialization failed.
    #[error("contract serialization failed: {0}")]
    Serialization(String),
}

/// Sink failures are opaque to the process contract.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
#[error("evidence sink rejected record: {message}")]
pub struct EvidenceSinkError {
    /// Stable category/message without raw output.
    pub message: String,
}

/// Errors exposed by a physical executor.
#[derive(Debug, Error)]
pub enum ProcessExecutionError {
    /// Contract validation failed before resume.
    #[error(transparent)]
    Contract(#[from] ContractError),
    /// Operation is unknown.
    #[error("operation not found")]
    NotFound,
    /// Physical executor is unavailable.
    #[error("process executor unavailable: {0}")]
    Unavailable(String),
    /// Evidence sink rejected a record.
    #[error(transparent)]
    EvidenceSink(#[from] EvidenceSinkError),
    /// External outcome requires reconciliation.
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

fn validate_revision_heads(heads: &BTreeMap<String, String>) -> Result<(), ContractError> {
    if heads.is_empty() || heads.len() > MAX_REVISION_HEADS {
        return Err(ContractError::InvalidValue {
            field: "revision_heads",
            reason: "must be non-empty and bounded",
        });
    }
    for (name, digest) in heads {
        validate_opaque_id("revision_head_name", name.clone())?;
        validate_hex_digest("revision_head_digest", digest)?;
    }
    Ok(())
}

fn validate_hex_digest(field: &'static str, value: &str) -> Result<(), ContractError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
    {
        return Err(ContractError::InvalidValue {
            field,
            reason: "must be a 64-character hexadecimal digest",
        });
    }
    Ok(())
}

fn validate_stored_digest(
    field: &'static str,
    observed: &str,
    expected: String,
) -> Result<(), ContractError> {
    if observed == expected {
        Ok(())
    } else {
        Err(ContractError::DigestMismatch {
            field,
            expected,
            observed: observed.to_owned(),
        })
    }
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

fn hash_serialized<T: Serialize>(value: &T) -> Result<String, ContractError> {
    let bytes = serde_json::to_vec(value)
        .map_err(|error| ContractError::Serialization(error.to_string()))?;
    Ok(hash_bytes(&bytes))
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
    use eliot_instrument_api::{Accessibility, Influence, PhysicalState, TaintState};
    use std::error::Error;

    type TestResult<T = ()> = Result<T, Box<dyn Error>>;

    fn revisions() -> BTreeMap<String, String> {
        BTreeMap::from([
            ("authority".to_owned(), "a".repeat(64)),
            ("state".to_owned(), "b".repeat(64)),
        ])
    }

    fn intent() -> Result<ProcessIntent, ContractError> {
        ProcessIntent::new(
            OperationId::new("op-1")?,
            ProcessTreeId::new("tree-1")?,
            JobId::new("job-1")?,
            ImageId::new("image-file-id-1")?,
            SessionId::new("session-1")?,
            Generation::new(1)?,
            "C:\\tools\\worker.exe",
            "c".repeat(64),
            vec!["--check".to_owned()],
            "C:\\work",
            EnvironmentProjection::new(
                BTreeMap::from([("PATH".to_owned(), "C:\\Windows".to_owned())]),
                vec![SecretRef::new("credential_manager", "provider/token")?],
                EnvironmentInheritance::None,
            )?,
            ResourceLimits::new(10_000, Some(5_000), Some(1_048_576), 4096, 4096, 4)?,
        )
    }

    fn fence() -> Result<FencingToken, ContractError> {
        FencingToken::new(7, Generation::new(1)?, "fence-7-1")
    }

    fn authority() -> Result<DispatchPermitAuthority, ContractError> {
        Ok(DispatchPermitAuthority::activate(
            DispatchAuthorityId::new("kernel-authority-7")?,
            KernelDispatchKey::from_secret_bytes([0x5a; 32])?,
        ))
    }

    fn issuance(nonce: &str) -> Result<PermitIssuance, ContractError> {
        PermitIssuance::new(
            ActionLeaseRef::new("lease-1")?,
            fence()?,
            revisions(),
            100,
            200,
            nonce,
        )
    }

    fn context(now: i64) -> Result<DispatchValidationContext, ContractError> {
        DispatchValidationContext::new(
            ClockObservation {
                valid_time_ms: Some(now),
                known_time_ms: Some(now),
                transaction_sequence: None,
                monotonic_ns: Some(1),
            },
            fence()?,
            7,
            revisions(),
            41,
        )
    }

    fn observed(intent: &ProcessIntent) -> Result<SuspendedProcessIdentity, ContractError> {
        SuspendedProcessIdentity::new(
            ProcessId::new("process-1")?,
            intent.process_tree_id.clone(),
            intent.job_id.clone(),
            intent.image_id.clone(),
            intent.session_id.clone(),
            intent.generation,
            PhysicalProcessBinding::new(
                4242,
                11,
                intent.executable.clone(),
                r"Local\Eliot-Process-Test",
            )?,
            120,
            intent.executable_sha256.clone(),
        )
    }

    fn replay(permit: &DispatchPermit) -> DispatchPermit {
        DispatchPermit {
            schema_version: permit.schema_version.clone(),
            authority_id: permit.authority_id.clone(),
            operation_id: permit.operation_id.clone(),
            process_tree_id: permit.process_tree_id.clone(),
            job_id: permit.job_id.clone(),
            image_id: permit.image_id.clone(),
            session_id: permit.session_id.clone(),
            generation: permit.generation,
            action_lease_ref: permit.action_lease_ref.clone(),
            state_fence: permit.state_fence.clone(),
            expected_revision_heads: permit.expected_revision_heads.clone(),
            effect_digest: permit.effect_digest.clone(),
            issued_at_unix_ms: permit.issued_at_unix_ms,
            expires_at_unix_ms: permit.expires_at_unix_ms,
            one_shot_nonce: permit.one_shot_nonce.clone(),
            validation_revision: permit.validation_revision,
            authentication_tag: permit.authentication_tag.clone(),
            permit_digest: permit.permit_digest.clone(),
        }
    }

    fn validated() -> Result<(DispatchPermitAuthority, ValidatedDispatch), ContractError> {
        let mut authority = authority()?;
        let intent = intent()?;
        let permit = authority.issue(&intent, issuance("nonce-1")?)?;
        let request = ProcessRequest::new(intent.clone(), permit)?;
        let validated =
            authority.validate_and_consume(request, observed(&intent)?, &context(150)?)?;
        Ok((authority, validated))
    }

    #[test]
    fn cross_process_admission_round_trips_without_dispatch_authority() -> TestResult {
        let request = ProcessExecutionAdmissionRequest::new(
            "eliotd",
            intent()?,
            ActionLeaseRef::new("lease-1")?,
            fence()?,
            200,
        )?;
        let wire = serde_json::to_vec(&request)?;
        let restored: ProcessExecutionAdmissionRequest = serde_json::from_slice(&wire)?;
        assert_eq!(request, restored);
        assert_eq!(restored.recipient_module_id(), "eliotd");
        let wire = serde_json::to_value(&request)?;
        assert!(wire.get("expected_revision_heads").is_none());
        let mut legacy = wire;
        legacy["expected_revision_heads"] = serde_json::json!({"legacy": "a".repeat(64)});
        assert!(serde_json::from_value::<ProcessExecutionAdmissionRequest>(legacy).is_err());
        Ok(())
    }

    #[test]
    fn cross_process_admission_rejects_stale_generation_fence() -> TestResult {
        let stale = FencingToken::new(7, Generation::new(2)?, "fence-7-2")?;
        let Err(error) = ProcessExecutionAdmissionRequest::new(
            "eliotd",
            intent()?,
            ActionLeaseRef::new("lease-1")?,
            stale,
            200,
        ) else {
            return Err("a generation-substituted fence must fail closed".into());
        };
        assert_eq!(error, ContractError::FenceMismatch);
        Ok(())
    }

    #[test]
    fn revision_heads_remain_strict_lowercase_sha256_bindings() -> TestResult {
        for value in ["1", "01", &"A".repeat(64), &"g".repeat(64)] {
            let mut heads = BTreeMap::new();
            heads.insert("store:revision".to_owned(), value.to_string());
            assert!(matches!(
                PermitIssuance::new(
                    ActionLeaseRef::new("lease-1")?,
                    fence()?,
                    heads,
                    100,
                    200,
                    "strict-revision-test",
                ),
                Err(ContractError::InvalidValue {
                    field: "revision_head_digest",
                    ..
                })
            ));
        }
        Ok(())
    }

    fn running_state() -> Result<ProcessState, ContractError> {
        let (_, validated) = validated()?;
        let mut state = ProcessState::from_validated(&validated);
        state.mark_resumed(
            151,
            ProcessHealth::new(ProcessHealthStatus::Healthy, true, 151, None)?,
        )?;
        Ok(state)
    }

    fn descendants(
        state: &ProcessState,
        complete: bool,
        tree_terminated: bool,
    ) -> Result<DescendantEvidence, ContractError> {
        let identity = state
            .identity
            .as_ref()
            .ok_or(ContractError::MissingIdentity)?;
        DescendantEvidence::new(
            state.binding.clone(),
            identity.process_id().clone(),
            vec![ProcessId::new("descendant-1")?],
            complete,
            tree_terminated,
            Some("raw-evidence:tree-1".to_owned()),
        )
    }

    #[test]
    fn permit_is_authenticated_consuming_and_single_use() -> TestResult {
        let mut authority = authority()?;
        let intent = intent()?;
        let permit = authority.issue(&intent, issuance("single-use")?)?;
        let replay = replay(&permit);
        let first = ProcessRequest::new(intent.clone(), permit)?;
        let second = ProcessRequest::new(intent.clone(), replay)?;
        let accepted = authority.validate_and_consume(first, observed(&intent)?, &context(150)?)?;
        assert_eq!(accepted.binding().validation_revision(), 41);
        assert_eq!(authority.consumed_permit_count(), 1);
        assert!(matches!(
            authority.validate_and_consume(second, observed(&intent)?, &context(150)?),
            Err(ContractError::DispatchPermitConsumed)
        ));
        assert_eq!(authority.consumed_permit_count(), 1);
        Ok(())
    }

    #[test]
    fn stale_and_tampered_permits_fail_before_nonce_mutation() -> TestResult {
        let mut authority = authority()?;
        let intent = intent()?;
        let mut permit = authority.issue(&intent, issuance("tampered")?)?;
        let replacement = if permit.authentication_tag.starts_with('0') {
            "1"
        } else {
            "0"
        };
        permit.authentication_tag.replace_range(..1, replacement);
        assert!(matches!(
            ProcessRequest::new(intent.clone(), permit),
            Err(ContractError::DigestMismatch {
                field: "permit_digest",
                ..
            })
        ));
        assert_eq!(authority.consumed_permit_count(), 0);

        let permit = authority.issue(&intent, issuance("expired")?)?;
        let request = ProcessRequest::new(intent.clone(), permit)?;
        assert!(matches!(
            authority.validate_and_consume(request, observed(&intent)?, &context(200)?),
            Err(ContractError::ExpiredDispatchPermit)
        ));
        assert_eq!(authority.consumed_permit_count(), 0);
        Ok(())
    }

    #[test]
    fn store_bound_permit_rejects_changed_fence_heads_or_revision_before_consumption() -> TestResult
    {
        let intent = intent()?;

        let mut authority_revision = authority()?;
        let permit = authority_revision.issue(
            &intent,
            PermitIssuance::new_with_validation_revision(
                ActionLeaseRef::new("lease-1")?,
                fence()?,
                revisions(),
                100,
                200,
                "store-revision",
                41,
            )?,
        )?;
        let request = ProcessRequest::new(intent.clone(), permit)?;
        let mut changed_revision = context(150)?;
        changed_revision.validation_revision = 42;
        assert!(matches!(
            authority_revision.validate_and_consume(request, observed(&intent)?, &changed_revision),
            Err(ContractError::StaleRevisionHeads)
        ));
        assert_eq!(authority_revision.consumed_permit_count(), 0);

        let mut authority_heads = authority()?;
        let permit = authority_heads.issue(
            &intent,
            PermitIssuance::new_with_validation_revision(
                ActionLeaseRef::new("lease-1")?,
                fence()?,
                revisions(),
                100,
                200,
                "store-heads",
                41,
            )?,
        )?;
        let request = ProcessRequest::new(intent.clone(), permit)?;
        let mut changed_heads = context(150)?;
        changed_heads
            .revision_heads
            .insert("scope:one".to_owned(), "c".repeat(64));
        assert!(matches!(
            authority_heads.validate_and_consume(request, observed(&intent)?, &changed_heads),
            Err(ContractError::StaleRevisionHeads)
        ));
        assert_eq!(authority_heads.consumed_permit_count(), 0);

        let mut authority_fence = authority()?;
        let permit = authority_fence.issue(
            &intent,
            PermitIssuance::new_with_validation_revision(
                ActionLeaseRef::new("lease-1")?,
                fence()?,
                revisions(),
                100,
                200,
                "store-fence",
                41,
            )?,
        )?;
        let request = ProcessRequest::new(intent.clone(), permit)?;
        let changed_fence = FencingToken::new(8, Generation::new(1)?, "other-fence")?;
        let changed_context = DispatchValidationContext::new(
            ClockObservation {
                valid_time_ms: Some(150),
                known_time_ms: Some(150),
                transaction_sequence: None,
                monotonic_ns: Some(1),
            },
            changed_fence,
            8,
            revisions(),
            41,
        )?;
        assert!(matches!(
            authority_fence.validate_and_consume(request, observed(&intent)?, &changed_context),
            Err(ContractError::StaleStateFence)
        ));
        assert_eq!(authority_fence.consumed_permit_count(), 0);
        Ok(())
    }

    #[test]
    fn consumed_nonce_survives_authority_recovery() -> TestResult {
        let mut authority = authority()?;
        let intent = intent()?;
        let permit = authority.issue(&intent, issuance("recoverable")?)?;
        let replay = replay(&permit);
        let request = ProcessRequest::new(intent.clone(), permit)?;
        let _ = authority.validate_and_consume(request, observed(&intent)?, &context(150)?)?;
        let snapshot = authority.replay_snapshot();
        drop(authority);

        let mut recovered = DispatchPermitAuthority::recover(
            DispatchAuthorityId::new("kernel-authority-7")?,
            KernelDispatchKey::from_secret_bytes([0x5a; 32])?,
            snapshot,
        )?;
        let replay_request = ProcessRequest::new(intent.clone(), replay)?;
        assert!(matches!(
            recovered.validate_and_consume(replay_request, observed(&intent)?, &context(150)?),
            Err(ContractError::DispatchPermitConsumed)
        ));
        assert_eq!(recovered.consumed_permit_count(), 1);
        Ok(())
    }

    #[test]
    fn replay_snapshot_rejects_duplicate_or_invalid_wire_entries() -> TestResult {
        let authority = authority()?;
        let snapshot = authority.replay_snapshot();
        let mut value = serde_json::to_value(snapshot)?;
        value["issued_nonces"] = serde_json::json!(["nonce-1", "nonce-1"]);
        let duplicate: DispatchPermitReplaySnapshot = serde_json::from_value(value)?;
        assert!(matches!(
            duplicate.validate(),
            Err(ContractError::DuplicateValue {
                field: "issued_nonces"
            })
        ));

        let invalid = DispatchPermitReplaySnapshot {
            authority_id: DispatchAuthorityId("bad\n authority".to_owned()),
            issued_nonces: vec!["nonce-1".to_owned()],
            consumed_nonces: vec!["nonce-2".to_owned()],
            replay_revision: 0,
        };
        assert!(matches!(
            invalid.validate(),
            Err(ContractError::InvalidOpaqueValue {
                field: "dispatch_authority_id"
            })
        ));
        Ok(())
    }

    #[test]
    fn recovery_start_requires_current_capability_fence_and_fresh_p02_observation() -> TestResult {
        let (authority, validated) = validated()?;
        let mut state = ProcessState::from_validated(&validated);
        let current = context(151)?;
        let capability = authority.issue_recovery_capability(
            validated.binding().clone(),
            "p07-recovery-1",
            &current,
        )?;
        let observation = RecoveryObservation::new(
            validated.suspended_identity().clone(),
            current.state_fence.clone(),
            151,
        )?;
        let receipt = state.recover_start(
            &observation,
            &capability,
            &current,
            ProcessHealth::new(ProcessHealthStatus::Healthy, true, 151, None)?,
        )?;
        assert_eq!(receipt.lifecycle(), ProcessLifecycle::Running);
        Ok(())
    }

    #[test]
    fn identity_mismatch_fails_closed_before_resume() -> TestResult {
        let mut authority = authority()?;
        let intent = intent()?;
        let permit = authority.issue(&intent, issuance("identity")?)?;
        let request = ProcessRequest::new(intent.clone(), permit)?;
        let mut wrong = observed(&intent)?;
        wrong.job_id = JobId::new("other-job")?;
        assert!(matches!(
            authority.validate_and_consume(request, wrong, &context(150)?),
            Err(ContractError::IdentityMismatch)
        ));
        assert_eq!(authority.consumed_permit_count(), 0);
        Ok(())
    }

    #[test]
    fn start_receipt_binds_permit_revision_and_all_physical_identities() -> TestResult {
        let (_, validated) = validated()?;
        let mut state = ProcessState::from_validated(&validated);
        assert!(matches!(
            ProcessStartReceipt::new(&state),
            Err(ContractError::ResumeNotObserved)
        ));
        state.mark_resumed(
            151,
            ProcessHealth::new(ProcessHealthStatus::Healthy, true, 151, None)?,
        )?;
        let receipt = ProcessStartReceipt::new(&state)?;
        assert_eq!(receipt.binding(), validated.binding());
        assert_eq!(receipt.identity().job_id(), validated.binding().job_id());
        assert_eq!(
            receipt.identity().image_id(),
            validated.binding().image_id()
        );
        assert_eq!(
            receipt.identity().session_id(),
            validated.binding().session_id()
        );
        assert_eq!(receipt.identity().resumed_at_unix_ms(), 151);
        assert_eq!(receipt.binding().validation_revision(), 41);
        Ok(())
    }

    #[test]
    fn eliotd_live_receipt_round_trips_and_rejects_fence_substitution() -> TestResult {
        let process = ProcessStartReceipt::new(&running_state()?)?;
        let supervision = EliotdLiveSupervisionEvidence {
            lease_id: "supervision-lease-1".to_owned(),
            record_id: "supervision-record-1".to_owned(),
            revision: 1,
            receipt_sha256: "a".repeat(64),
            envelope_sha256: "b".repeat(64),
            payload_sha256: "c".repeat(64),
            public_key_fingerprint: "d".repeat(64),
        };
        let ready = EliotdLiveReadyEvidence {
            request_id: "daemon-ready-1".to_owned(),
            request_payload_sha256: "e".repeat(64),
            connection_id: "connection-1".to_owned(),
            session_epoch: 2,
            authority_epoch: 3,
            generation: 1,
            launch_nonce_sha256: "f".repeat(64),
        };
        let root = std::env::temp_dir().join("eliot-live-receipt-test");
        let receipt = EliotdLiveReceipt::new(
            root.to_string_lossy(),
            "1".repeat(64),
            "0".repeat(64),
            "installation-1",
            "generation-1",
            1,
            3,
            "2".repeat(64),
            "3".repeat(64),
            "4".repeat(64),
            process,
            supervision,
            ready,
            4,
        )?;
        let bytes = eliot_contracts::canonical_json_bytes(&receipt)?;
        let restored: EliotdLiveReceipt = serde_json::from_slice(&bytes)?;
        assert_eq!(restored, receipt);
        restored.validate()?;

        let mut substituted = restored;
        substituted.generation = 2;
        assert!(matches!(
            substituted.validate(),
            Err(ContractError::FenceMismatch | ContractError::DigestMismatch { .. })
        ));
        Ok(())
    }

    #[test]
    fn reconcile_requires_complete_terminated_exact_tree() -> TestResult {
        let mut state = running_state()?;
        state.exit(
            ExitStatus::new(ExitDisposition::Unknown, None, None, 160)?,
            descendants(&state, false, false)?,
        )?;
        let before = state.view();
        assert!(matches!(
            state.reconcile(descendants(&state, true, false)?),
            Err(ContractError::IncompleteDescendantEvidence)
        ));
        assert_eq!(state.view(), before);
        state.reconcile(descendants(&state, true, true)?)?;
        assert_eq!(state.view().lifecycle(), ProcessLifecycle::Reconciled);
        Ok(())
    }

    #[test]
    fn cancel_unknown_outcome_has_no_partial_state() -> TestResult {
        let mut state = running_state()?;
        state.exit(
            ExitStatus::new(ExitDisposition::Unknown, None, None, 160)?,
            descendants(&state, false, false)?,
        )?;
        let before = state.view();
        let cancel = CancellationRequest::new(state.binding.clone());
        assert!(matches!(
            state.cancel(&cancel),
            Err(ContractError::UnknownOutcomeRequiresReconciliation)
        ));
        assert_eq!(state.view(), before);
        Ok(())
    }

    #[test]
    fn exact_tree_exit_completes_in_progress_cancellation() -> TestResult {
        let mut state = running_state()?;
        let request = CancellationRequest::new(state.binding.clone());
        assert_eq!(
            state.cancel(&request)?.status(),
            CancellationStatus::InProgress
        );
        state.exit(
            ExitStatus::new(ExitDisposition::Cancelled, None, None, 160)?,
            descendants(&state, true, true)?,
        )?;
        assert_eq!(state.view().lifecycle(), ProcessLifecycle::Exited);
        assert_eq!(state.view().cancellation(), CancellationStatus::Completed);
        Ok(())
    }

    #[test]
    fn incomplete_cancel_exit_becomes_unknown_until_exact_reconciliation() -> TestResult {
        let mut state = running_state()?;
        let request = CancellationRequest::new(state.binding.clone());
        state.cancel(&request)?;
        state.exit(
            ExitStatus::new(ExitDisposition::Unknown, None, None, 160)?,
            descendants(&state, false, false)?,
        )?;
        assert_eq!(state.view().lifecycle(), ProcessLifecycle::UnknownOutcome);
        assert_eq!(
            state.view().cancellation(),
            CancellationStatus::UnknownOutcome
        );
        state.reconcile(descendants(&state, true, true)?)?;
        assert_eq!(state.view().lifecycle(), ProcessLifecycle::Reconciled);
        assert_eq!(state.view().cancellation(), CancellationStatus::Completed);
        Ok(())
    }

    #[test]
    fn mismatched_cancel_and_evidence_fail_without_state_change() -> TestResult {
        let mut state = running_state()?;
        let before = state.view();
        let mut wrong = state.binding.clone();
        wrong.session_id = SessionId::new("wrong-session")?;
        assert!(matches!(
            state.cancel(&CancellationRequest::new(wrong)),
            Err(ContractError::StaleStateFence)
        ));
        assert_eq!(state.view(), before);

        let mut mismatched_view = state.view();
        mismatched_view.binding.job_id = JobId::new("wrong-job")?;
        assert!(matches!(
            ProcessEvidence::new(mismatched_view, None, None, EvidenceAxes::observed()),
            Err(ContractError::EvidenceBindingMismatch)
        ));
        Ok(())
    }

    #[test]
    fn process_evidence_cannot_promote_itself() -> TestResult {
        let state = running_state()?;
        let mut axes = EvidenceAxes::observed();
        axes.status = EvidenceStatus::Verified;
        axes.assertability = Assertability::Assertable;
        assert!(matches!(
            ProcessEvidence::new(state.view(), None, None, axes),
            Err(ContractError::EvidenceAuthorityEscalation)
        ));
        let evidence = ProcessEvidence::new(
            state.view(),
            Some("raw:stdout".to_owned()),
            Some("raw:stderr".to_owned()),
            EvidenceAxes {
                status: EvidenceStatus::Observed,
                assertability: Assertability::NonAssertableUnverified,
                accessibility: Accessibility::Available,
                influence: Influence::Allowed,
                physical: PhysicalState::Present,
                taint: TaintState::Clear,
            },
        )?;
        assert_eq!(evidence.binding(), state.binding());
        Ok(())
    }

    #[test]
    fn secret_and_duplicate_boundaries_remain_fail_closed() -> TestResult {
        assert!(matches!(
            EnvironmentProjection::new(
                BTreeMap::from([("ACCESS_TOKEN".to_owned(), "hidden".to_owned())]),
                Vec::new(),
                EnvironmentInheritance::None,
            ),
            Err(ContractError::SecretBoundary { .. })
        ));
        let mut authority = authority()?;
        let intent = intent()?;
        let _ = authority.issue(&intent, issuance("duplicate")?)?;
        assert!(matches!(
            authority.issue(&intent, issuance("duplicate")?),
            Err(ContractError::DuplicateValue { .. })
        ));
        Ok(())
    }
}
