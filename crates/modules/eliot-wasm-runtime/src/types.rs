use std::collections::BTreeSet;

use eliot_observation_contracts::{ObservationError, ObservationScope};
use eliot_process::{
    FencingToken, Generation, OperationId, ProcessRequest, ProcessStartReceipt, ProcessTreeId,
};
use eliot_runtime_contracts::{ModuleGeneration, RuntimeContractError, RuntimeLease};
use eliot_security_contracts::{PrivacyClass, SecurityContractError, SourceAssurance};
use schemars::JsonSchema;
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::{Map, Value};
use sha2::{Digest as _, Sha256};
use thiserror::Error;

use crate::DEFAULT_GUEST_TARGET;

const MAX_TEXT_BYTES: usize = 512;

pub(crate) fn validate_text(value: &str, field: &'static str) -> Result<(), RuntimeError> {
    if value.trim().is_empty()
        || value.len() > MAX_TEXT_BYTES
        || value.chars().any(char::is_control)
    {
        return Err(RuntimeError::InvalidField(field.to_owned()));
    }
    Ok(())
}

macro_rules! opaque_id {
    ($name:ident, $field:literal) => {
        #[derive(Clone, Debug, Eq, Hash, JsonSchema, Ord, PartialEq, PartialOrd, Serialize)]
        #[serde(transparent)]
        pub struct $name(String);

        impl $name {
            /// Constructs a validated, non-secret identity.
            pub fn new(value: impl Into<String>) -> Result<Self, RuntimeError> {
                let value = value.into();
                validate_text(&value, $field)?;
                Ok(Self(value))
            }

            /// Returns the stable wire value.
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: Deserializer<'de>,
            {
                let value = String::deserialize(deserializer)?;
                Self::new(value).map_err(serde::de::Error::custom)
            }
        }
    };
}

opaque_id!(InvocationId, "invocation_id");
opaque_id!(WorkUnitId, "work_unit_id");
opaque_id!(WorkScopeRef, "work_scope_ref");
opaque_id!(OwnerId, "owner_id");
opaque_id!(CapabilityId, "capability_id");

/// Lowercase SHA-256 identity that validates on every ingress path.
#[derive(Clone, Debug, Eq, Hash, JsonSchema, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct Sha256Digest(String);

impl Sha256Digest {
    /// Parses an exact lowercase SHA-256 digest.
    pub fn new(value: impl Into<String>) -> Result<Self, RuntimeError> {
        let value = value.into();
        if value.len() != 64
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        {
            return Err(RuntimeError::InvalidDigest);
        }
        Ok(Self(value))
    }

    pub fn of_bytes(bytes: &[u8]) -> Self {
        Self(format!("{:x}", Sha256::digest(bytes)))
    }

    fn sealing_placeholder() -> Self {
        Self("0".repeat(64))
    }

    /// Returns lowercase hexadecimal bytes.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl<'de> Deserialize<'de> for Sha256Digest {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::new(value).map_err(serde::de::Error::custom)
    }
}

/// Non-zero revision assigned by an external owner.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct Revision(u64);

impl Revision {
    /// Creates a non-zero revision.
    pub const fn new(value: u64) -> Result<Self, RuntimeError> {
        if value == 0 {
            Err(RuntimeError::InvalidRevision)
        } else {
            Ok(Self(value))
        }
    }

    /// Returns the numeric revision.
    pub const fn get(self) -> u64 {
        self.0
    }
}

impl<'de> Deserialize<'de> for Revision {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Self::new(u64::deserialize(deserializer)?).map_err(serde::de::Error::custom)
    }
}

/// Exact provider identity selected by composition, never by A-12.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EngineBinding {
    pub implementation_id: String,
    pub exact_version: String,
    pub engine_artifact_digest: Sha256Digest,
    pub engine_configuration_digest: Sha256Digest,
    pub wit_interface_digest: Sha256Digest,
}

impl EngineBinding {
    pub(crate) fn validate(&self) -> Result<(), RuntimeError> {
        validate_text(&self.implementation_id, "engine.implementation_id")?;
        validate_text(&self.exact_version, "engine.exact_version")
    }
}

/// ELIOT-owned versioned WIT/component declaration resolved by the Governor.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ComponentManifest {
    pub component_id: CapabilityId,
    pub world: CapabilityId,
    pub wit_version: String,
    pub guest_target: String,
    pub artifact_digest: Sha256Digest,
    pub interface_digest: Sha256Digest,
    pub source_digest: Sha256Digest,
    pub configuration_digest: Sha256Digest,
    pub state_contract_digest: Sha256Digest,
    pub imports: BTreeSet<CapabilityId>,
    pub exports: BTreeSet<CapabilityId>,
    pub admitted_privacy_classes: Vec<PrivacyClass>,
    pub required_verifier: String,
    pub engine: EngineBinding,
}

impl ComponentManifest {
    pub(crate) fn validate(&self) -> Result<(), RuntimeError> {
        validate_text(&self.wit_version, "manifest.wit_version")?;
        validate_text(&self.required_verifier, "manifest.required_verifier")?;
        self.engine.validate()?;
        if self.guest_target != DEFAULT_GUEST_TARGET {
            return Err(RuntimeError::UnsupportedGuestTarget);
        }
        if self.exports.is_empty() || self.admitted_privacy_classes.is_empty() {
            return Err(RuntimeError::InvalidManifest);
        }
        if self
            .admitted_privacy_classes
            .iter()
            .enumerate()
            .any(|(index, value)| self.admitted_privacy_classes[index + 1..].contains(value))
        {
            return Err(RuntimeError::InvalidManifest);
        }
        if self.engine.wit_interface_digest != self.interface_digest {
            return Err(RuntimeError::EngineBindingMismatch);
        }
        Ok(())
    }
}

/// Requested contour. It grants no promotion authority by itself.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ExecutionContour {
    Conformance,
    Shadow,
    Canary,
    Active,
}

/// Exact interruption mechanism required of the injected engine adapter.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CancellationPolicy {
    EpochInterruption,
    EpochAndFuel,
}

/// Maximum epoch deadline admitted by this runtime-contract revision.
///
/// The current production provider supports no negotiation path. A larger
/// value therefore requires a contract/configuration revision instead of a
/// provider-local clamp after admission.
pub const MAX_EPOCH_DEADLINE_TICKS: u64 = 1024;

/// Bounded epoch/cancellation contract.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EpochPolicy {
    pub deadline_ticks: u64,
    pub cancellation: CancellationPolicy,
}

/// Artifact-read ceilings; absence of a digest is denial.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactAccessLimits {
    pub allowed_digests: BTreeSet<Sha256Digest>,
    pub max_reads: u32,
    pub max_bytes: u64,
}

/// Full per-invocation limit envelope resolved by the Governor.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InvocationLimits {
    pub max_input_bytes: u64,
    pub max_output_bytes: u64,
    pub max_host_calls: u32,
    pub max_fuel: u64,
    pub max_memory_bytes: u64,
    pub max_table_elements: u32,
    pub max_instances: u32,
    pub max_stack_bytes: u64,
    pub wall_deadline_ms: u64,
    pub epoch: EpochPolicy,
    pub artifact_access: ArtifactAccessLimits,
}

impl InvocationLimits {
    pub(crate) fn validate(&self, artifact: &Sha256Digest) -> Result<(), RuntimeError> {
        if [
            self.max_input_bytes,
            self.max_output_bytes,
            self.max_fuel,
            self.max_memory_bytes,
            self.max_stack_bytes,
            self.wall_deadline_ms,
            self.epoch.deadline_ticks,
            self.artifact_access.max_bytes,
        ]
        .contains(&0)
            || self.epoch.deadline_ticks > MAX_EPOCH_DEADLINE_TICKS
            || self.max_host_calls == 0
            || self.max_table_elements == 0
            || self.max_instances == 0
            || self.artifact_access.max_reads == 0
            || !self.artifact_access.allowed_digests.contains(artifact)
        {
            return Err(RuntimeError::InvalidLimits);
        }
        Ok(())
    }
}

/// Public caller request. It contains intent and payload, but no accepted facts.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InvocationRequest {
    pub invocation_id: InvocationId,
    pub component_id: CapabilityId,
    pub work_unit: WorkUnitId,
    pub work_scope_ref: WorkScopeRef,
    pub requested_contour: ExecutionContour,
    pub input: Vec<u8>,
    pub deterministic_seed: u64,
    pub cancellation_requested: bool,
    request_digest: Sha256Digest,
}

#[derive(Serialize)]
struct UnsignedInvocation<'a> {
    invocation_id: &'a InvocationId,
    component_id: &'a CapabilityId,
    work_unit: &'a WorkUnitId,
    work_scope_ref: &'a WorkScopeRef,
    requested_contour: ExecutionContour,
    input: &'a [u8],
    deterministic_seed: u64,
    cancellation_requested: bool,
}

impl InvocationRequest {
    /// Creates and seals inert caller intent.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        invocation_id: InvocationId,
        component_id: CapabilityId,
        work_unit: WorkUnitId,
        work_scope_ref: WorkScopeRef,
        requested_contour: ExecutionContour,
        input: Vec<u8>,
        deterministic_seed: u64,
        cancellation_requested: bool,
    ) -> Result<Self, RuntimeError> {
        let mut request = Self {
            invocation_id,
            component_id,
            work_unit,
            work_scope_ref,
            requested_contour,
            input,
            deterministic_seed,
            cancellation_requested,
            request_digest: Sha256Digest::sealing_placeholder(),
        };
        request.refresh_digest()?;
        request.validate()?;
        Ok(request)
    }

    /// Returns the idempotency digest.
    pub const fn request_digest(&self) -> &Sha256Digest {
        &self.request_digest
    }

    /// Validates only inert request structure and its digest.
    pub fn validate(&self) -> Result<(), RuntimeError> {
        if self.compute_digest()? != self.request_digest {
            return Err(RuntimeError::RequestDigestMismatch);
        }
        Ok(())
    }

    fn unsigned(&self) -> UnsignedInvocation<'_> {
        UnsignedInvocation {
            invocation_id: &self.invocation_id,
            component_id: &self.component_id,
            work_unit: &self.work_unit,
            work_scope_ref: &self.work_scope_ref,
            requested_contour: self.requested_contour,
            input: &self.input,
            deterministic_seed: self.deterministic_seed,
            cancellation_requested: self.cancellation_requested,
        }
    }

    fn compute_digest(&self) -> Result<Sha256Digest, RuntimeError> {
        canonical_digest(&self.unsigned())
    }

    pub(crate) fn refresh_digest(&mut self) -> Result<(), RuntimeError> {
        self.request_digest = self.compute_digest()?;
        Ok(())
    }
}

/// Governor-owned manifest, generation, lease, revision, and limit resolution.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GovernorResolution {
    pub manifest: ComponentManifest,
    pub generation: ModuleGeneration,
    pub lease: RuntimeLease,
    pub authority_revision: Revision,
    pub lifecycle_revision: Revision,
    pub limits: InvocationLimits,
    pub resolution_receipt_digest: Sha256Digest,
}

/// Authority-owner resolution of owner, `WorkScope`, work unit, and ceilings.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthorityResolution {
    pub owner: OwnerId,
    pub work_unit: WorkUnitId,
    pub work_scope: ObservationScope,
    pub allowed_host_calls: BTreeSet<CapabilityId>,
    pub allowed_effect_proposals: BTreeSet<CapabilityId>,
    pub resolution_receipt_digest: Sha256Digest,
}

/// Source-verifier result. Caller-supplied source records are never accepted.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SourceVerification {
    pub assurance: SourceAssurance,
    pub verification_revision: Revision,
    pub verification_receipt_digest: Sha256Digest,
}

/// Verified differential/promotion reference outcomes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PromotionVerification {
    pub corpus_digest: Sha256Digest,
    pub expected_result_digest: Sha256Digest,
    pub expected_effect_digest: Sha256Digest,
    pub expected_state_delta_digest: Sha256Digest,
    pub verification_revision: Revision,
    pub shadow: VerificationVerdict,
    pub canary: VerificationVerdict,
    pub rollback: VerificationVerdict,
    pub cutover: VerificationVerdict,
    pub verification_receipt_digest: Sha256Digest,
}

/// A sealed verifier outcome; callers cannot replace the verifier port with a flag.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VerificationVerdict {
    Verified,
    Rejected,
}

impl VerificationVerdict {
    pub(crate) const fn is_verified(self) -> bool {
        matches!(self, Self::Verified)
    }
}

/// Read-only query delivered to the promotion verifier after other resolutions.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PromotionQuery {
    pub request_digest: Sha256Digest,
    pub component_id: CapabilityId,
    pub generation: ModuleGeneration,
    pub contour: ExecutionContour,
    pub artifact_digest: Sha256Digest,
    pub interface_digest: Sha256Digest,
    pub state_contract_digest: Sha256Digest,
}

/// Inert post-start identity retained after P-03 consumes its one-shot request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProcessBinding {
    operation_id: OperationId,
    process_tree_id: ProcessTreeId,
    generation: Generation,
    fence: FencingToken,
    request_digest: String,
}

impl ProcessBinding {
    pub(crate) fn from_request(request: &ProcessRequest) -> Self {
        Self {
            operation_id: request.operation_id().clone(),
            process_tree_id: request.process_tree_id().clone(),
            generation: request.generation(),
            fence: request.fence().clone(),
            request_digest: request.invocation_digest().to_owned(),
        }
    }

    #[must_use]
    pub const fn operation_id(&self) -> &OperationId {
        &self.operation_id
    }

    #[must_use]
    pub const fn process_tree_id(&self) -> &ProcessTreeId {
        &self.process_tree_id
    }

    #[must_use]
    pub const fn generation(&self) -> Generation {
        self.generation
    }

    #[must_use]
    pub const fn fence(&self) -> &FencingToken {
        &self.fence
    }

    #[must_use]
    pub fn request_digest(&self) -> &str {
        &self.request_digest
    }
}

/// Exact authorized envelope used to request a P-03 process binding.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProcessLaunchEnvelope {
    pub invocation_id: InvocationId,
    pub request_digest: Sha256Digest,
    pub owner: OwnerId,
    pub work_unit: WorkUnitId,
    pub work_scope: ObservationScope,
    pub manifest: ComponentManifest,
    pub generation: ModuleGeneration,
    pub lease: RuntimeLease,
    pub authority_revision: Revision,
    pub lifecycle_revision: Revision,
    pub limits: InvocationLimits,
}

/// Effect proposed by the guest; it is never an authorization or commit.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EffectProposal {
    pub effect_kind: CapabilityId,
    pub payload_digest: Sha256Digest,
}

/// Exact sealed input passed to the engine only after P-03 start verification.
#[derive(Clone, Debug)]
pub struct EngineInvocation {
    pub invocation_id: InvocationId,
    pub request_digest: Sha256Digest,
    pub component_id: CapabilityId,
    pub contour: ExecutionContour,
    pub manifest: ComponentManifest,
    pub imports: BTreeSet<CapabilityId>,
    pub exports: BTreeSet<CapabilityId>,
    pub allowed_host_calls: BTreeSet<CapabilityId>,
    pub allowed_effect_proposals: BTreeSet<CapabilityId>,
    pub generation: ModuleGeneration,
    pub lease: RuntimeLease,
    pub owner: OwnerId,
    pub work_unit: WorkUnitId,
    pub work_scope: ObservationScope,
    pub authority_revision: Revision,
    pub lifecycle_revision: Revision,
    pub source_assurance: SourceAssurance,
    pub source_verification_revision: Revision,
    pub promotion_verification_revision: Revision,
    pub conformance_corpus_digest: Sha256Digest,
    pub governor_resolution_receipt_digest: Sha256Digest,
    pub authority_resolution_receipt_digest: Sha256Digest,
    pub source_verification_receipt_digest: Sha256Digest,
    pub promotion_verification_receipt_digest: Sha256Digest,
    pub state_contract_digest: Sha256Digest,
    pub limits: InvocationLimits,
    pub input: Vec<u8>,
    pub deterministic_seed: u64,
    pub process_binding: ProcessBinding,
    pub process_start_receipt: ProcessStartReceipt,
}

/// Actual metering observed by the exact engine adapter.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EngineUsage {
    /// Bytes observed from the guest result before the output ceiling was applied.
    pub attempted_output_bytes: u64,
    pub output_bytes: u64,
    pub host_calls: u32,
    pub fuel_consumed: u64,
    pub peak_memory_bytes: Option<u64>,
    pub table_elements: Option<u32>,
    pub instances: u32,
    pub stack_bytes: Option<u64>,
    /// The exact per-invocation stack ceiling enforced by the adapter when
    /// Wasmtime cannot expose observed stack usage.
    pub enforced_stack_limit_bytes: Option<u64>,
    pub elapsed_ms: u64,
    /// Exact epoch deadline and cancellation mechanism reported as installed
    /// by the engine adapter. This is execution evidence, not caller intent.
    pub effective_epoch_policy: EpochPolicy,
    pub epoch_ticks: Option<u64>,
    pub artifact_reads: u32,
    pub artifact_bytes: u64,
    pub accessed_artifact_digests: Vec<Sha256Digest>,
}

/// Stable trap class; provider strings do not cross the facade.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum TrapClass {
    GuestTrap,
    InvalidComponent,
    HostContractViolation,
}

/// Exact termination fact from the engine adapter.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum EngineTermination {
    Completed,
    Trap(TrapClass),
    OutputLimit,
    HostCallLimit,
    FuelExhausted,
    MemoryLimit,
    TableLimit,
    InstanceLimit,
    StackLimit,
    Deadline,
    EpochDeadline,
    ArtifactAccessDenied,
    Cancelled,
    Partial,
    PostCommitUnknown,
}

/// Engine output contains actual values only; A-12 derives all digests.
#[derive(Clone, Debug)]
pub struct EngineReport {
    pub request_digest: Sha256Digest,
    pub termination: EngineTermination,
    pub usage: EngineUsage,
    pub output: Vec<u8>,
    pub host_calls: Vec<CapabilityId>,
    pub proposed_effects: Vec<EffectProposal>,
    pub observed_state_delta: Vec<u8>,
    pub post_commit_known: bool,
}

/// Digests derived by A-12 from actual engine values, never supplied by engine.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DerivedExecutionEvidence {
    pub result_digest: Sha256Digest,
    pub effect_digest: Sha256Digest,
    pub state_delta_digest: Sha256Digest,
}

/// Stable result classification; unknown is never collapsed into failure.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum InvocationDisposition {
    Succeeded,
    Rejected,
    Unavailable,
    Unknown,
}

/// Typed A-12 errors safe for persisted receipts.
#[derive(Clone, Debug, Eq, Error, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE", tag = "code", content = "detail")]
pub enum RuntimeError {
    #[error("invalid field: {0}")]
    InvalidField(String),
    #[error("invalid lowercase SHA-256 digest")]
    InvalidDigest,
    #[error("revision must be non-zero")]
    InvalidRevision,
    #[error("manifest is malformed")]
    InvalidManifest,
    #[error("only wasm32-wasip2 is admitted")]
    UnsupportedGuestTarget,
    #[error("engine binding disagrees with manifest")]
    EngineBindingMismatch,
    #[error("resolved generation disagrees with manifest")]
    GenerationBindingMismatch,
    #[error("resolved generation is not admitted for the contour")]
    GenerationNotReady,
    #[error("authority/work scope/work unit binding mismatch")]
    AuthorityBindingMismatch,
    #[error("runtime lease is not active")]
    LeaseNotActive,
    #[error("stale or inconsistent state fence/revision")]
    StaleFence,
    #[error("source verifier did not admit the source")]
    SourceNotAdmitted,
    #[error("promotion verifier did not admit the contour")]
    PromotionDenied,
    #[error("authority resolution denied the request")]
    AuthorityDenied,
    #[error("invocation limits are invalid")]
    InvalidLimits,
    #[error("input ceiling exceeded")]
    InputLimitExceeded,
    #[error("effect or host call exceeds the admitted ceiling")]
    ForbiddenEffect,
    #[error("request digest mismatch")]
    RequestDigestMismatch,
    #[error("P-03 process binding is invalid")]
    InvalidProcessBinding,
    #[error("P-03 receipt verification failed")]
    InvalidProcessReceipt,
    #[error("replay key was reused for different request bytes")]
    ReplayConflict,
    #[error("replay capacity is full; new invocation rejected")]
    ReplayCapacityExceeded,
    #[error("terminal result cannot be overwritten by cancellation")]
    TerminalCancellationConflict,
    #[error("cancelled")]
    Cancelled,
    #[error("component trapped: {0:?}")]
    Trap(TrapClass),
    #[error("output limit reached")]
    OutputLimit,
    #[error("host-call limit reached")]
    HostCallLimit,
    #[error("fuel exhausted")]
    FuelExhausted,
    #[error("memory limit reached")]
    MemoryLimit,
    #[error("table limit reached")]
    TableLimit,
    #[error("instance limit reached")]
    InstanceLimit,
    #[error("stack limit reached")]
    StackLimit,
    #[error("deadline reached")]
    Deadline,
    #[error("epoch deadline reached")]
    EpochDeadline,
    #[error("artifact access denied")]
    ArtifactAccessDenied,
    #[error("derived differential result/effect/state mismatch")]
    DifferentialMismatch,
    #[error("engine report violated its exact envelope")]
    EngineContractViolation,
    #[error("PLAN_GAP: required authority, verifier, engine, or P-03 port unavailable")]
    PlanGap,
    #[error("partial or post-commit outcome requires reconciliation")]
    UnknownOutcome,
    #[error("canonical serialization failed: {0}")]
    Serialization(String),
    #[error("runtime contract: {0}")]
    RuntimeContract(String),
    #[error("observation contract: {0}")]
    ObservationContract(String),
    #[error("security contract: {0}")]
    SecurityContract(String),
    #[error("process contract: {0}")]
    ProcessContract(String),
}

impl From<RuntimeContractError> for RuntimeError {
    fn from(error: RuntimeContractError) -> Self {
        Self::RuntimeContract(error.to_string())
    }
}

impl From<ObservationError> for RuntimeError {
    fn from(error: ObservationError) -> Self {
        Self::ObservationContract(error.to_string())
    }
}

impl From<SecurityContractError> for RuntimeError {
    fn from(error: SecurityContractError) -> Self {
        Self::SecurityContract(error.to_string())
    }
}

impl From<eliot_process::ContractError> for RuntimeError {
    fn from(error: eliot_process::ContractError) -> Self {
        Self::ProcessContract(error.to_string())
    }
}

/// Immutable replay receipt with digests derived by A-12 from actual values.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InvocationReceipt {
    pub invocation_id: InvocationId,
    pub request_digest: Sha256Digest,
    pub disposition: InvocationDisposition,
    pub error: Option<RuntimeError>,
    pub output_digest: Option<Sha256Digest>,
    pub effect_digest: Option<Sha256Digest>,
    pub state_delta_digest: Option<Sha256Digest>,
    pub engine_binding: Option<EngineBinding>,
    pub usage: Option<EngineUsage>,
    pub reconciliation_required: bool,
}

/// Exact replayable result.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InvocationResult {
    pub receipt: InvocationReceipt,
    pub output: Option<Vec<u8>>,
    pub proposed_effects: Vec<EffectProposal>,
    pub observed_state_delta: Option<Vec<u8>>,
}

impl InvocationResult {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn classified(
        request: &InvocationRequest,
        disposition: InvocationDisposition,
        error: Option<RuntimeError>,
        output: Option<Vec<u8>>,
        proposed_effects: Vec<EffectProposal>,
        observed_state_delta: Option<Vec<u8>>,
        engine_binding: Option<EngineBinding>,
        usage: Option<EngineUsage>,
    ) -> Self {
        let output_digest = output.as_deref().map(Sha256Digest::of_bytes);
        let effect_digest = (engine_binding.is_some() || usage.is_some())
            .then(|| canonical_digest(&proposed_effects).ok())
            .flatten();
        let state_delta_digest = observed_state_delta.as_deref().map(Sha256Digest::of_bytes);
        Self {
            receipt: InvocationReceipt {
                invocation_id: request.invocation_id.clone(),
                request_digest: request.request_digest.clone(),
                disposition,
                error,
                output_digest,
                effect_digest,
                state_delta_digest,
                engine_binding,
                usage,
                reconciliation_required: matches!(disposition, InvocationDisposition::Unknown),
            },
            output,
            proposed_effects,
            observed_state_delta,
        }
    }
}

pub(crate) fn canonical_digest<T: Serialize>(value: &T) -> Result<Sha256Digest, RuntimeError> {
    let value = serde_json::to_value(value)
        .map_err(|error| RuntimeError::Serialization(error.to_string()))?;
    let bytes = serde_json::to_vec(&canonicalize(value))
        .map_err(|error| RuntimeError::Serialization(error.to_string()))?;
    Ok(Sha256Digest::of_bytes(&bytes))
}

fn canonicalize(value: Value) -> Value {
    match value {
        Value::Array(items) => Value::Array(items.into_iter().map(canonicalize).collect()),
        Value::Object(object) => {
            let mut entries: Vec<_> = object.into_iter().collect();
            entries.sort_by(|left, right| left.0.cmp(&right.0));
            let mut sorted = Map::new();
            for (key, value) in entries {
                sorted.insert(key, canonicalize(value));
            }
            Value::Object(sorted)
        }
        scalar => scalar,
    }
}

#[cfg(test)]
mod epoch_limit_tests {
    use super::*;

    fn limits(artifact: Sha256Digest, deadline_ticks: u64) -> InvocationLimits {
        InvocationLimits {
            max_input_bytes: 1,
            max_output_bytes: 1,
            max_host_calls: 1,
            max_fuel: 1,
            max_memory_bytes: 1,
            max_table_elements: 1,
            max_instances: 1,
            max_stack_bytes: 1,
            wall_deadline_ms: 1,
            epoch: EpochPolicy {
                deadline_ticks,
                cancellation: CancellationPolicy::EpochInterruption,
            },
            artifact_access: ArtifactAccessLimits {
                allowed_digests: [artifact].into_iter().collect(),
                max_reads: 1,
                max_bytes: 1,
            },
        }
    }

    #[test]
    fn epoch_deadline_ceiling_is_exact_before_process_admission() {
        let artifact = Sha256Digest::of_bytes(b"artifact");
        assert!(
            limits(artifact.clone(), MAX_EPOCH_DEADLINE_TICKS)
                .validate(&artifact)
                .is_ok()
        );
        assert_eq!(
            limits(artifact.clone(), MAX_EPOCH_DEADLINE_TICKS + 1).validate(&artifact),
            Err(RuntimeError::InvalidLimits)
        );
    }
}
