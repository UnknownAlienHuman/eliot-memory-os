//! Typed sandboxed execution for the six frozen worlds.
//!
//! Default governed mode refuses without actual Kernel admission
//! (`KERNEL_ADMISSION_REQUIRED`). An explicitly selected local-experimental
//! path instantiates and executes a typed component through the frozen WIT
//! world with deny-by-default Wasmtime policy and zero ambient imports.
//!
//! Both the `describe` descriptor and the admitted typed domain operation
//! (`admit`/`assemble`/`activate`/`handle`/`screen`/`step`) execute here. The
//! domain leg uses the generated `wit::*Request`/`wit::*Result` types produced
//! by the single `bindgen!` owner in [`crate::typed_bindings`]; it does not
//! import a domain crate to manufacture a result, and the neutral
//! `eliot-wasm-runtime` crate keeps no Wasmtime dependency.

use std::fmt;
use std::path::Path;
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use std::thread;
use std::time::{Duration, Instant};

use eliot_wasm_runtime::capsule::{ModuleContractKit, ModuleTestCapsule};
use eliot_wasm_runtime::component_contract::{
    ProofCeiling, TYPED_ABI_REVISION, TypedContractError,
};
use eliot_wasm_runtime::{
    CancellationPolicy, EngineTermination, EpochPolicy, InvocationLimits, MAX_EPOCH_DEADLINE_TICKS,
    Sha256Digest, TrapClass,
};

use crate::artifact_preflight::{PreflightError, preflight_bytes};
use crate::contour::CAPABILITY_INTRODUCTION_REQUIRED;
use crate::typed_bindings::{TypedWorld, typed_wit_digest};
use crate::wasmtime_provider::{
    WasmtimeBuildError, WasmtimeComponentEngine, is_instance_limit_error,
};

const ENGINE_VERSION: &str = "47.0.4";
const PROVIDER_STACK_SIZE: u64 = 8 * 1024;
const MAX_DESCRIPTOR_STRING_BYTES: usize = 512;
/// Per-string ceiling for lifted typed input and output. On the input side it
/// is enforced before the host lowers any of the request into guest memory. On
/// the output side the pinned typed API lifts the whole result into host
/// memory first (its only length check is the guest's linear-memory bounds),
/// so this ceiling is consulted leaf by leaf only after the complete lifted
/// value exists. What bounds the lift itself is the store memory ceiling built
/// in [`new_store`].
const MAX_TYPED_STRING_BYTES: usize = 4_096;
/// Per-list ceiling for lifted typed input and output, counted in items.
const MAX_TYPED_LIST_ITEMS: usize = 256;
/// Memory-COUNT ceiling. `InvocationLimits` bounds memory bytes and instance
/// count but carries no memory count, so the Host fixes it here.
const MAX_TYPED_MEMORIES: usize = 1;
/// Table-COUNT ceiling. `InvocationLimits` bounds table elements and instance
/// count but carries no table count, so the Host fixes it here.
const MAX_TYPED_TABLES: usize = 1;
/// Approximate per-item lift cost used to convert a list into a byte bound.
const TYPED_ITEM_LIFT_BYTES: u64 = 8;

/// Caller-selected execution mode. Governed is the default; experimental
/// and legacy must be explicitly selected and never auto-probed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExecutionMode {
    /// Default governed path. Requires actual Kernel admission.
    Governed,
    /// Explicitly selected local experiment. Receipt is non-governed.
    LocalExperimental,
    /// Explicitly selected legacy-only path (`eliot:wasm/guest`).
    LegacyOnly,
}

impl ExecutionMode {
    /// Proof string recorded in receipts. Experimental proof can never
    /// satisfy governed/release proof.
    #[must_use]
    pub const fn proof(self) -> &'static str {
        match self {
            Self::Governed => "GOVERNED_ADMISSION",
            Self::LocalExperimental => "NON_GOVERNED_EXPERIMENTAL",
            Self::LegacyOnly => "LEGACY_ONLY",
        }
    }
}

/// Validated `describe` descriptor returned by a typed component.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TypedDescriptor {
    /// World name reported by the guest.
    pub world_name: String,
    /// Package id reported by the guest.
    pub package_id: String,
    /// ABI revision reported by the guest.
    pub abi_revision: u32,
    /// Native contract reported by the guest.
    pub native_contract: String,
    /// Native revision reported by the guest.
    pub native_revision: String,
    /// ABI digest reported by the guest.
    pub abi_digest: String,
}

/// One pipeline stage the single typed call actually reached. Compilation in
/// this Host is synchronous, so `Compile` names a stage that finished before
/// any deadline could be applied; no compile-cancellation or compile-abort
/// guarantee is claimed from it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TypedStage {
    /// Synchronous component compilation from the same bounded buffer.
    Compile,
    /// Component instantiation on the empty linker.
    Instantiate,
    /// Registered typed `describe` descriptor call.
    Descriptor,
    /// The one admitted typed domain export call.
    Invoke,
    /// Lifted output bound, identity, and ceiling checks.
    Output,
    /// Store/epoch-driver teardown after the single call.
    Cleanup,
}

impl TypedStage {
    /// Stable stage code recorded in receipts and failures.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Compile => "compile",
            Self::Instantiate => "instantiate",
            Self::Descriptor => "descriptor",
            Self::Invoke => "invoke",
            Self::Output => "output",
            Self::Cleanup => "cleanup",
        }
    }
}

impl fmt::Display for TypedStage {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Admitted operation identity and ceiling one typed domain result is compared
/// against. A guest that reports a foreign operation, task, scope or fence, or
/// a proof ceiling above the admitted one, is rejected instead of trusted.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TypedDomainAdmission {
    /// Admitted operation id the guest must echo.
    pub operation_id: String,
    /// Admitted task id the guest must echo.
    pub task_id: String,
    /// Admitted scope id the guest must echo.
    pub scope_id: String,
    /// Admitted state fence epoch the guest must echo.
    pub fence_epoch: String,
    /// Admitted policy identity recorded in the receipt.
    pub policy_id: String,
    /// Highest proof ceiling this operation may claim.
    pub proof_ceiling: ProofCeiling,
}

impl TypedDomainAdmission {
    /// Rejects an admitted identity that is itself unbounded or malformed,
    /// before any component is compiled.
    pub fn validate(&self) -> Result<(), TypedExecutionError> {
        for value in [
            self.operation_id.as_str(),
            self.task_id.as_str(),
            self.scope_id.as_str(),
            self.fence_epoch.as_str(),
            self.policy_id.as_str(),
        ] {
            if value.is_empty()
                || value.len() > MAX_DESCRIPTOR_STRING_BYTES
                || value.chars().any(char::is_control)
            {
                return Err(TypedExecutionError::LimitDenied(
                    "admission-field".to_owned(),
                ));
            }
        }
        Ok(())
    }
}

/// Bounded engine/run receipt for one typed call. No raw payload, path,
/// secret, or backtrace. Observation timing is separate from the
/// deterministic semantic digest: wall time, fuel, and peak resource
/// measurements are recorded but excluded from [`semantic_digest`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TypedReceipt {
    /// Selected execution mode proof.
    pub proof: String,
    /// Executed world.
    pub world: String,
    /// Frozen package identity.
    pub package_id: String,
    /// Canonical artifact hash (same buffer that was compiled).
    pub artifact_digest: Sha256Digest,
    /// Exact artifact length.
    pub artifact_bytes: u64,
    /// Engine implementation version.
    pub engine_version: String,
    /// Digest of the frozen WIT bytes.
    pub wit_digest: Sha256Digest,
    /// Digest of the cache identity revalidated before compile: engine
    /// version/config/target, artifact digest/length, ABI world/revision,
    /// and admitted policy. Digests only: no raw payload, path, or secret.
    pub cache_identity: Sha256Digest,
    /// Actual component imports observed (must be empty).
    pub actual_imports: Vec<String>,
    /// Actual component exports observed (exactly one interface).
    pub actual_exports: Vec<String>,
    /// Digest of the exact typed input bound to this call. The descriptor path
    /// has no input; the domain path digests the admitted operation envelope
    /// and its measured request bound, because the request is a typed
    /// structure that is never serialized into an opaque escape.
    pub input_digest: Sha256Digest,
    /// Measured typed input bytes bound for this call.
    pub input_bytes: u64,
    /// Digest of the validated descriptor fields.
    pub output_digest: Sha256Digest,
    /// Measured descriptor output bytes (sum of reported string bytes).
    pub output_bytes: u64,
    /// Fuel consumed by describe execution.
    pub fuel_consumed: u64,
    /// Peak memory bytes observed, when reported.
    pub peak_memory_bytes: Option<u64>,
    /// Table elements observed, when reported.
    pub table_elements: Option<u32>,
    /// Component instances created (always 1 on success).
    pub instances: u32,
    /// Admitted operation id, absent on the descriptor-only path.
    pub operation_id: Option<String>,
    /// Admitted task id, absent on the descriptor-only path.
    pub task_id: Option<String>,
    /// Admitted state fence epoch, absent on the descriptor-only path.
    pub fence_epoch: Option<String>,
    /// Admitted policy identity, absent on the descriptor-only path.
    pub policy_id: Option<String>,
    /// Pipeline stage this receipt was produced at.
    pub stage: String,
    /// Observation-only wall time in milliseconds.
    pub elapsed_ms: u64,
    /// Terminal cause for the single invocation.
    pub terminal: String,
    /// Deterministic semantic digest (excludes timing).
    pub semantic_digest: Sha256Digest,
}

/// Fail-closed typed execution errors with stable codes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TypedExecutionError {
    /// Default governed refusal without Kernel admission.
    GovernedAdmissionRequired,
    /// Governed or capsule admission binding disagrees with the attempted
    /// call (world, operation, artifact digest, kit/capsule binding). An
    /// exact owned typed denial, distinct from the unadmitted default.
    AdmissionMismatch(String),
    /// Unknown world selection.
    WorldUnknown(String),
    /// Component exports do not select exactly one registered world.
    WorldSelection {
        /// Stable reason code.
        reason: String,
    },
    /// A selected interface or one of its descriptor/domain functions has
    /// the wrong generated Wasmtime type.
    ExportTypeMismatch(String),
    /// Missing or wrongly typed descriptor/domain export: the admitted
    /// method is absent, the single exported interface does not declare the
    /// registered world, or a capsule declares an export its kit does not
    /// (canonical introduction-required denial). An instantiation failure
    /// whose message names an export is mapped here too.
    MissingExport(String),
    /// Forbidden import: the closed-world component-type preflight found a
    /// declared import before instantiation, a compile failure whose message
    /// names an unknown import or an instantiation failure whose message
    /// names an import, or a capsule declared an import its kit does not
    /// (canonical introduction-required denial). The empty linker itself
    /// introduces nothing on the typed legs.
    ForbiddenImport(String),
    /// Legacy component presented for a typed world (or reverse).
    LegacyMismatch,
    /// Artifact preflight failure.
    Artifact(PreflightError),
    /// Limit policy violation before execution.
    LimitDenied(String),
    /// Engine failure (compile/instantiate/trap/resource/output).
    Engine(String),
    /// Validated output violates size/schema/identity bounds.
    OutputViolation(String),
    /// Failure annotated with the pipeline stage actually reached. A guest's
    /// own typed error is NOT reported here: it is returned as the retained
    /// terminal result in [`TypedDomainResult::GuestError`], while a trap,
    /// fuel, epoch, stack or resource fault arrives here.
    Staged {
        /// Stage the single call had actually reached.
        stage: TypedStage,
        /// The fail-closed cause observed at that stage.
        cause: Box<TypedExecutionError>,
    },
}

impl fmt::Display for TypedExecutionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::GovernedAdmissionRequired => formatter.write_str("KERNEL_ADMISSION_REQUIRED"),
            Self::AdmissionMismatch(reason) => write!(formatter, "ADMISSION_MISMATCH:{reason}"),
            Self::WorldUnknown(world) => write!(formatter, "WORLD_UNKNOWN:{world}"),
            Self::WorldSelection { reason } => write!(formatter, "WORLD_SELECTION:{reason}"),
            Self::ExportTypeMismatch(name) => write!(formatter, "EXPORT_TYPE_MISMATCH:{name}"),
            Self::MissingExport(name) | Self::ForbiddenImport(name) => {
                write!(formatter, "{CAPABILITY_INTRODUCTION_REQUIRED}:{name}")
            }
            Self::LegacyMismatch => formatter.write_str("LEGACY_MISMATCH"),
            Self::Artifact(error) => write!(formatter, "{error}"),
            Self::LimitDenied(reason) => write!(formatter, "LIMIT_DENIED:{reason}"),
            Self::Engine(reason) => write!(formatter, "ENGINE:{reason}"),
            Self::OutputViolation(reason) => write!(formatter, "OUTPUT_VIOLATION:{reason}"),
            Self::Staged { stage, cause } => write!(formatter, "STAGE:{stage}:{cause}"),
        }
    }
}

impl std::error::Error for TypedExecutionError {}

impl From<PreflightError> for TypedExecutionError {
    fn from(error: PreflightError) -> Self {
        Self::Artifact(error)
    }
}

/// Default governed refusal. No Kernel admission is bound in this host,
/// so governed execution always fails closed before compile/instantiate.
/// The refusal is enforced through [`check_governed_admission`]: the closed
/// unadmitted record below is well-formed but carries no Kernel issuance, so
/// the gate reaches its documented staleness denial and that typed denial
/// propagates unchanged (`KERNEL_ADMISSION_REQUIRED`).
pub fn execute_governed_refusal() -> Result<(), TypedExecutionError> {
    let unadmitted = GovernedAdmission {
        world: TypedWorld::ContextAdmission,
        operation_id: "unadmitted-operation".to_owned(),
        task_id: "unadmitted-task".to_owned(),
        scope_id: "unadmitted-scope".to_owned(),
        fence_epoch: "unadmitted-fence".to_owned(),
        policy_id: "unadmitted-policy".to_owned(),
        artifact_digest: Sha256Digest::of_bytes(b"unadmitted-governed-attempt"),
        proof_ceiling: ProofCeiling::Observation,
    };
    check_governed_admission(
        unadmitted.world,
        Some(&unadmitted.artifact_digest),
        None,
        Some(&unadmitted),
    )
}

/// Governed admission bindings the default path requires: exact world,
/// operation/task/scope/fence/policy identity, artifact hash, and effect
/// ceiling. This is the host-side record of the Kernel/module admission;
/// it carries no trust flag and grants nothing by itself.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GovernedAdmission {
    /// World the admission was issued for.
    pub world: TypedWorld,
    /// Admitted operation id.
    pub operation_id: String,
    /// Admitted task id.
    pub task_id: String,
    /// Admitted scope id.
    pub scope_id: String,
    /// Admitted state fence epoch.
    pub fence_epoch: String,
    /// Admitted policy identity.
    pub policy_id: String,
    /// Admitted artifact digest the call must hash to.
    pub artifact_digest: Sha256Digest,
    /// Highest proof ceiling this admission may claim.
    pub proof_ceiling: ProofCeiling,
}

impl GovernedAdmission {
    /// Rejects an admission record that is itself unbounded or malformed,
    /// before any component is acquired, compiled, or instantiated.
    /// Locator-shaped identities (the `://` authority marker the artifact
    /// path layer also rejects) are malformed here: an admitted identity is
    /// a plain bounded local name, never a remote/registry/discovery source.
    pub fn validate(&self) -> Result<(), TypedExecutionError> {
        for value in [
            self.operation_id.as_str(),
            self.task_id.as_str(),
            self.scope_id.as_str(),
            self.fence_epoch.as_str(),
            self.policy_id.as_str(),
        ] {
            if value.is_empty()
                || value.len() > MAX_DESCRIPTOR_STRING_BYTES
                || value.contains("://")
                || value.chars().any(char::is_control)
            {
                return Err(TypedExecutionError::LimitDenied(
                    "admission-field".to_owned(),
                ));
            }
        }
        Ok(())
    }
}

/// Default-governed admission gate. Denies before any artifact acquisition,
/// compilation, or instantiation: this function takes no artifact bytes,
/// performs no filesystem access, and builds no engine.
///
/// The artifact digest is the digest the caller bound under policy before the
/// call, or `None` when no digest was bound: an explicit governed attempt
/// carries no admission channel, so the gate denies before any acquisition
/// could consult a digest.
///
/// Denial order: a caller-supplied artifact path on the governed lane is
/// denied first with `KERNEL_ADMISSION_REQUIRED` (no arbitrary path/URL
/// acquisition, no fallback to the experimental mode), before any admission
/// record is consulted; absent admission yields `KERNEL_ADMISSION_REQUIRED`;
/// a malformed record yields the owned `LIMIT_DENIED` denial (empty,
/// over-long, control-character, or locator-shaped `://` identity); a
/// world disagreement or a missing/mismatched artifact-digest binding yields
/// the owned `ADMISSION_MISMATCH` denial. A well-formed record is still
/// denied with `KERNEL_ADMISSION_REQUIRED`: this host binds no live Kernel
/// admission channel to re-anchor freshness against, so staleness cannot be
/// proven fresh (an old request not listed in a committed record is stale).
pub fn check_governed_admission(
    world: TypedWorld,
    artifact_digest: Option<&Sha256Digest>,
    artifact_source: Option<&Path>,
    admission: Option<&GovernedAdmission>,
) -> Result<(), TypedExecutionError> {
    // P1.3 (#758): no arbitrary path/URL or fallback to experimental mode.
    // The untrusted path is refused before any admission record is read,
    // so a governed path attempt denies even alongside a presented record.
    if artifact_source.is_some() {
        return Err(TypedExecutionError::GovernedAdmissionRequired);
    }
    let admitted = admission.ok_or(TypedExecutionError::GovernedAdmissionRequired)?;
    admitted.validate()?;
    if admitted.world != world {
        return Err(TypedExecutionError::AdmissionMismatch("world".to_owned()));
    }
    match artifact_digest {
        Some(digest) if *digest == admitted.artifact_digest => {}
        _ => {
            return Err(TypedExecutionError::AdmissionMismatch(
                "artifact-digest".to_owned(),
            ));
        }
    }
    Err(TypedExecutionError::GovernedAdmissionRequired)
}

/// Bounded default limits for the local-experimental path. The caller
/// supplies the exact artifact digest allow-listed for this invocation.
#[must_use]
pub fn default_experimental_limits(artifact_digest: Sha256Digest) -> InvocationLimits {
    InvocationLimits {
        max_input_bytes: 64,
        max_output_bytes: 16_384,
        max_host_calls: 1,
        max_fuel: 50_000,
        max_memory_bytes: 65_536,
        max_table_elements: 8,
        max_instances: 2,
        max_stack_bytes: PROVIDER_STACK_SIZE,
        wall_deadline_ms: 500,
        epoch: EpochPolicy {
            deadline_ticks: 100,
            cancellation: CancellationPolicy::EpochAndFuel,
        },
        artifact_access: eliot_wasm_runtime::ArtifactAccessLimits {
            allowed_digests: [artifact_digest].into_iter().collect(),
            max_reads: 1,
            max_bytes: crate::artifact_preflight::MAX_ARTIFACT_BYTES,
        },
    }
}

fn validate_limits(
    limits: &InvocationLimits,
    digest: &Sha256Digest,
) -> Result<(), TypedExecutionError> {
    if limits.max_stack_bytes != PROVIDER_STACK_SIZE {
        return Err(TypedExecutionError::LimitDenied("stack".to_owned()));
    }
    if limits.epoch.deadline_ticks == 0 || limits.epoch.deadline_ticks > MAX_EPOCH_DEADLINE_TICKS {
        return Err(TypedExecutionError::LimitDenied("epoch".to_owned()));
    }
    // Zero `max_host_calls` is an explicit closed-world declaration (issue
    // #21): the empty-linker provider admits no host calls, so a
    // no-host-call component states zero instead of carrying a nonzero
    // budget that implies a hidden capability. Usage enforcement still
    // denies any actual host call above the budget.
    //
    // Item 10 (#758): the artifact-digest allow-list is admission identity,
    // not a tuning ceiling, so a buffer that hashes outside it is the owned
    // typed `ADMISSION_MISMATCH`, never a limit denial.
    if !limits.artifact_access.allowed_digests.contains(digest) {
        return Err(TypedExecutionError::AdmissionMismatch(
            "cache-artifact".to_owned(),
        ));
    }
    if [
        limits.max_input_bytes,
        limits.max_output_bytes,
        limits.max_fuel,
        limits.max_memory_bytes,
        limits.wall_deadline_ms,
    ]
    .contains(&0)
        || limits.max_table_elements == 0
        || limits.max_instances == 0
        || limits.artifact_access.max_reads == 0
    {
        return Err(TypedExecutionError::LimitDenied("envelope".to_owned()));
    }
    Ok(())
}

fn bounded_descriptor_string(value: &str, field: &str) -> Result<(), TypedExecutionError> {
    if value.is_empty()
        || value.len() > MAX_DESCRIPTOR_STRING_BYTES
        || value.chars().any(char::is_control)
    {
        return Err(TypedExecutionError::OutputViolation(field.to_owned()));
    }
    Ok(())
}

fn validate_descriptor(
    world: TypedWorld,
    descriptor: &TypedDescriptor,
    max_output_bytes: u64,
) -> Result<(Sha256Digest, u64), TypedExecutionError> {
    if descriptor.world_name != world.world_name() {
        return Err(TypedExecutionError::OutputViolation(
            "world-name".to_owned(),
        ));
    }
    if descriptor.package_id != crate::typed_bindings::TYPED_PACKAGE_ID {
        return Err(TypedExecutionError::OutputViolation(
            "package-id".to_owned(),
        ));
    }
    if descriptor.abi_revision != TYPED_ABI_REVISION {
        return Err(TypedExecutionError::OutputViolation(
            "abi-revision".to_owned(),
        ));
    }
    bounded_descriptor_string(&descriptor.world_name, "world-name")?;
    bounded_descriptor_string(&descriptor.package_id, "package-id")?;
    bounded_descriptor_string(&descriptor.native_contract, "native-contract")?;
    bounded_descriptor_string(&descriptor.native_revision, "native-revision")?;
    bounded_descriptor_string(&descriptor.abi_digest, "abi-digest")?;
    let output_bytes = (descriptor.world_name.len()
        + descriptor.package_id.len()
        + descriptor.native_contract.len()
        + descriptor.native_revision.len()
        + descriptor.abi_digest.len()) as u64
        + u64::from(u32::try_from(size_of::<u32>()).unwrap_or(4));
    if output_bytes > max_output_bytes {
        return Err(TypedExecutionError::Engine(format!(
            "{:?}",
            EngineTermination::OutputLimit
        )));
    }
    let mut canonical = b"eliot-typed-descriptor/v1\0".to_vec();
    for value in [
        descriptor.world_name.as_str(),
        descriptor.package_id.as_str(),
        descriptor.native_contract.as_str(),
        descriptor.native_revision.as_str(),
        descriptor.abi_digest.as_str(),
    ] {
        let value_len = u64::try_from(value.len())
            .map_err(|_| TypedExecutionError::OutputViolation("field-length".to_owned()))?;
        canonical.extend_from_slice(&value_len.to_be_bytes());
        canonical.extend_from_slice(value.as_bytes());
    }
    canonical.extend_from_slice(&descriptor.abi_revision.to_be_bytes());
    Ok((Sha256Digest::of_bytes(&canonical), output_bytes))
}

/// Digest-keyed cache identity for one typed compilation (items 22/P3.6).
/// The identity binds engine version/config/target, artifact digest/length,
/// ABI world/revision, and admitted policy — never a name, path, URL,
/// generation, epoch, fence, proof, or authority value. The typed lane keeps
/// no cross-invocation compiled cache: every call recompiles the same bounded
/// buffer on a fresh engine, so this identity is the revalidation gate each
/// compile passes and the value the receipt binds. A future cache entry would
/// be valid exactly under this key; a key mismatch is denied, never bypassed.
#[derive(Clone, Debug, Eq, PartialEq)]
struct TypedCacheIdentity {
    /// Digest of the exact immutable component bytes being compiled.
    artifact: Sha256Digest,
    /// Exact length of those bytes.
    artifact_bytes: u64,
    /// Digest of the typed engine configuration (version, target, fuel and
    /// epoch mode, stack and count ceilings).
    engine: Sha256Digest,
    /// Digest of the frozen ABI binding (world, package, revision, WIT).
    abi: Sha256Digest,
    /// Digest of the admitted per-invocation limit/policy envelope.
    policy: Sha256Digest,
}

impl TypedCacheIdentity {
    /// Canonical digest of the whole identity, recorded in the receipt.
    fn digest(&self) -> Sha256Digest {
        let canonical = format!(
            "758-typed-cache-identity|{}|{}|{}|{}|{}",
            self.artifact.as_str(),
            self.artifact_bytes,
            self.engine.as_str(),
            self.abi.as_str(),
            self.policy.as_str(),
        );
        Sha256Digest::of_bytes(canonical.as_bytes())
    }
}

/// Canonical digest of the exact typed engine settings for one invocation:
/// the pinned engine version, the host compilation target, the component
/// model, the fuel/epoch mode from the admitted cancellation policy, the
/// provider stack ceiling, and this lane's own memory/table/instance
/// ceilings. The memory and table counts bound here are the lane's
/// `StoreLimits` counts from [`new_store`] (`MAX_TYPED_MEMORIES`,
/// `MAX_TYPED_TABLES`), not the engine's own pool slot counts, which the pool
/// derives from `max_instances`. Mirrors the pool
/// owner's descriptor-string mechanism for the typed lane.
fn typed_engine_configuration_digest(limits: &InvocationLimits) -> Sha256Digest {
    let descriptor = format!(
        "typed-engine/v1;wasmtime={ENGINE_VERSION};target={os}/{arch};component_model=true;consume_fuel={consume};epoch_interruption=true;max_wasm_stack={PROVIDER_STACK_SIZE};memories={MAX_TYPED_MEMORIES};tables={MAX_TYPED_TABLES};memory_bytes={memory};table_elements={tables};instances={instances}",
        os = std::env::consts::OS,
        arch = std::env::consts::ARCH,
        consume = typed_fuel_budget(limits).is_some(),
        memory = limits.max_memory_bytes,
        tables = limits.max_table_elements,
        instances = limits.max_instances,
    );
    Sha256Digest::of_bytes(descriptor.as_bytes())
}

/// Canonical digest of the admitted per-invocation limit/policy envelope.
/// Every scalar ceiling plus the allow-listed artifact digests is bound, so
/// a policy change is an identity change. Sorted iteration over the
/// allow-list keeps the digest deterministic.
fn typed_policy_digest(limits: &InvocationLimits) -> Sha256Digest {
    let mut canonical = format!(
        "typed-policy/v1;max_input_bytes={};max_output_bytes={};max_host_calls={};max_fuel={};max_memory_bytes={};max_table_elements={};max_instances={};max_stack_bytes={};wall_deadline_ms={};epoch_deadline_ticks={};epoch_cancellation={:?};artifact_max_reads={};artifact_max_bytes={}",
        limits.max_input_bytes,
        limits.max_output_bytes,
        limits.max_host_calls,
        limits.max_fuel,
        limits.max_memory_bytes,
        limits.max_table_elements,
        limits.max_instances,
        limits.max_stack_bytes,
        limits.wall_deadline_ms,
        limits.epoch.deadline_ticks,
        limits.epoch.cancellation,
        limits.artifact_access.max_reads,
        limits.artifact_access.max_bytes,
    );
    for digest in &limits.artifact_access.allowed_digests {
        canonical.push(';');
        canonical.push_str(digest.as_str());
    }
    Sha256Digest::of_bytes(canonical.as_bytes())
}

/// Canonical digest of the frozen ABI binding for one world: world name,
/// package identity, ABI revision, and the WIT digest the Host generated its
/// bindings from.
fn typed_abi_digest(world: TypedWorld) -> Sha256Digest {
    let canonical = format!(
        "typed-abi/v1;world={};package={};abi_revision={};wit={}",
        world.world_name(),
        crate::typed_bindings::TYPED_PACKAGE_ID,
        TYPED_ABI_REVISION,
        typed_wit_digest().as_str(),
    );
    Sha256Digest::of_bytes(canonical.as_bytes())
}

/// Builds the cache identity for one invocation from the preflighted digest
/// and the admitted limits.
fn typed_cache_identity(
    world: TypedWorld,
    artifact_digest: &Sha256Digest,
    artifact_bytes: u64,
    limits: &InvocationLimits,
) -> TypedCacheIdentity {
    TypedCacheIdentity {
        artifact: artifact_digest.clone(),
        artifact_bytes,
        engine: typed_engine_configuration_digest(limits),
        abi: typed_abi_digest(world),
        policy: typed_policy_digest(limits),
    }
}

/// Revalidates the cache identity before compile (no bypass): the same
/// bounded buffer is re-hashed independently of preflight — mirroring the
/// pool owner's key-versus-bytes revalidation — and the fresh hash must equal
/// the preflight digest the caller bound AND be allow-listed by the admitted
/// artifact policy. Item 10 (#758): hash and compile use the same buffer, not
/// a reread path, so a digest agreed by two independent hashes that still
/// disagrees is the owned typed `ADMISSION_MISMATCH`, never a stale entry.
/// Both typed lanes call this after limit validation and before any engine is
/// built; the capsule lane reaches it through its delegation to the domain
/// lane. A buffer that does not hash to an allow-listed digest is denied with
/// the owned typed `ADMISSION_MISMATCH`, never served from a stale entry.
fn check_cache_identity(
    world: TypedWorld,
    artifact: &[u8],
    expected: &Sha256Digest,
    limits: &InvocationLimits,
) -> Result<TypedCacheIdentity, TypedExecutionError> {
    let digest = Sha256Digest::of_bytes(artifact);
    if digest != *expected {
        return Err(TypedExecutionError::AdmissionMismatch(
            "artifact-digest".to_owned(),
        ));
    }
    if !limits.artifact_access.allowed_digests.contains(&digest) {
        return Err(TypedExecutionError::AdmissionMismatch(
            "cache-artifact".to_owned(),
        ));
    }
    let artifact_bytes = u64::try_from(artifact.len())
        .map_err(|_| TypedExecutionError::LimitDenied("artifact-length".to_owned()))?;
    Ok(typed_cache_identity(world, &digest, artifact_bytes, limits))
}

/// Deterministic semantic digest of one typed receipt: every fail-closed
/// semantic field is bound, every execution observation is excluded.
/// Excluded observations are `elapsed_ms` (wall clock), `fuel_consumed`,
/// `peak_memory_bytes`, and `table_elements`. Raw payloads, paths, secrets,
/// and backtraces are excluded by construction: the receipt carries only
/// digests, measured sizes, and bounded identity codes, so there is nothing
/// to redact. Two receipts for the same engine/config/target, artifact, ABI,
/// policy, input, output, and terminal agree here even when their wall-clock
/// observations differ.
fn semantic_digest(receipt: &TypedReceipt) -> Sha256Digest {
    fn push_field(canonical: &mut Vec<u8>, value: &[u8]) {
        canonical.extend_from_slice(&u64::try_from(value.len()).unwrap_or(u64::MAX).to_be_bytes());
        canonical.extend_from_slice(value);
    }

    let mut canonical = b"eliot-typed-semantic/v1\0".to_vec();
    push_field(&mut canonical, receipt.proof.as_bytes());
    push_field(&mut canonical, receipt.world.as_bytes());
    push_field(&mut canonical, receipt.package_id.as_bytes());
    push_field(&mut canonical, receipt.artifact_digest.as_str().as_bytes());
    push_field(&mut canonical, &receipt.artifact_bytes.to_be_bytes());
    push_field(&mut canonical, receipt.engine_version.as_bytes());
    push_field(&mut canonical, receipt.wit_digest.as_str().as_bytes());
    push_field(&mut canonical, receipt.cache_identity.as_str().as_bytes());
    for import in &receipt.actual_imports {
        push_field(&mut canonical, import.as_bytes());
    }
    for export in &receipt.actual_exports {
        push_field(&mut canonical, export.as_bytes());
    }
    push_field(&mut canonical, receipt.input_digest.as_str().as_bytes());
    push_field(&mut canonical, &receipt.input_bytes.to_be_bytes());
    push_field(&mut canonical, receipt.output_digest.as_str().as_bytes());
    push_field(&mut canonical, &receipt.output_bytes.to_be_bytes());
    push_field(&mut canonical, &receipt.instances.to_be_bytes());
    for identity in [
        &receipt.operation_id,
        &receipt.task_id,
        &receipt.fence_epoch,
        &receipt.policy_id,
    ] {
        match identity {
            Some(value) => push_field(&mut canonical, value.as_bytes()),
            None => push_field(&mut canonical, b"none"),
        }
    }
    push_field(&mut canonical, receipt.stage.as_bytes());
    push_field(&mut canonical, receipt.terminal.as_bytes());
    Sha256Digest::of_bytes(&canonical)
}

/// Annotates a fail-closed cause with the stage the single call had actually
/// reached. Nested annotation keeps the innermost stage.
fn staged(stage: TypedStage, cause: TypedExecutionError) -> TypedExecutionError {
    if matches!(cause, TypedExecutionError::Staged { .. }) {
        cause
    } else {
        TypedExecutionError::Staged {
            stage,
            cause: Box::new(cause),
        }
    }
}

/// Compares the descriptor's reported ABI digest with the digest of the exact
/// frozen WIT bytes this Host generated its bindings from. A guest whose
/// normalization differs is denied; the reported value is never accepted
/// because it is well formed.
fn validate_descriptor_abi_digest(descriptor: &TypedDescriptor) -> Result<(), TypedExecutionError> {
    if descriptor.abi_digest != typed_wit_digest().as_str() {
        return Err(TypedExecutionError::OutputViolation(
            "abi-digest".to_owned(),
        ));
    }
    Ok(())
}

/// Bounded pre-lift and post-lift measurement of one typed value. String and
/// list ceilings are checked as each leaf is visited, so a request is bounded
/// before the host lowers it into guest memory. A result is measured the same
/// way, leaf by leaf, but only after the pinned typed API has already lifted
/// the whole value into host memory: nothing here can pre-empt that lift.
/// Nested records are bounded transitively by the store
/// memory ceiling, which is the total host-allocation policy the pinned typed
/// API offers for a not-yet-lifted result. Accumulation itself is saturating:
/// a hostile sequence of individually bounded leaves saturates into the typed
/// `finish` denial instead of overflowing the counter.
///
/// Only `bytes` is accumulated. An earlier revision also carried an `items`
/// counter, incremented once per visited leaf and once per list element; it was
/// read by nothing — no receipt field, no digest, no denial string and no limit
/// consults it, because the per-leaf and per-list ceilings compare the leaf's
/// own length at `text` and `list` instead. Deleting it changed no observable
/// behaviour, and it survived review only because a self-accumulation reads its
/// own previous value, which rustc's `dead_code` pass counts as a use.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct TypedBound {
    bytes: u64,
}

impl TypedBound {
    fn text(&mut self, value: &str) -> Result<(), TypedExecutionError> {
        if value.len() > MAX_TYPED_STRING_BYTES {
            return Err(TypedExecutionError::LimitDenied("typed-string".to_owned()));
        }
        self.bytes = self
            .bytes
            .saturating_add(u64::try_from(value.len()).unwrap_or(u64::MAX));
        Ok(())
    }

    fn list<T>(&mut self, values: &[T]) -> Result<(), TypedExecutionError> {
        let count = values.len();
        if count > MAX_TYPED_LIST_ITEMS {
            return Err(TypedExecutionError::LimitDenied("typed-list".to_owned()));
        }
        let count = u64::try_from(count).unwrap_or(u64::MAX);
        self.bytes = self
            .bytes
            .saturating_add(count.saturating_mul(TYPED_ITEM_LIFT_BYTES));
        Ok(())
    }

    /// Bounds one list of strings: the item ceiling applies to the list
    /// itself, then every element is bounded as text. Item 9 (#758): a
    /// `list<string>` leaf is never counted without measuring its elements.
    fn texts(&mut self, values: &[String]) -> Result<(), TypedExecutionError> {
        self.list(values)?;
        for value in values {
            self.text(value)?;
        }
        Ok(())
    }

    /// Final total check against the admitted output ceiling.
    fn finish(self, max_output_bytes: u64) -> Result<u64, TypedExecutionError> {
        if self.bytes > max_output_bytes {
            return Err(TypedExecutionError::Engine(format!(
                "{:?}",
                EngineTermination::OutputLimit
            )));
        }
        Ok(self.bytes)
    }
}

/// Ordered rank of the closed proof-ceiling enum. `candidate-only` never
/// implies admission, so the wire order is the escalation order.
const fn proof_rank(ceiling: ProofCeiling) -> u8 {
    match ceiling {
        ProofCeiling::Observation => 0,
        ProofCeiling::CandidateOnly => 1,
        ProofCeiling::Admission => 2,
        ProofCeiling::Assembly => 3,
        ProofCeiling::Activation => 4,
        ProofCeiling::Screen => 5,
        ProofCeiling::Cycle => 6,
        ProofCeiling::Handler => 7,
    }
}

/// Rejects an echo that disagrees with the admitted operation identity. A
/// predictable name is not ownership: only the admitted value passes.
fn check_echo(
    observed: &str,
    admitted: &str,
    field: &'static str,
) -> Result<(), TypedExecutionError> {
    if observed != admitted {
        return Err(TypedExecutionError::OutputViolation(field.to_owned()));
    }
    Ok(())
}

/// Rejects a proof ceiling above the admitted one.
fn check_ceiling(
    observed: u8,
    admitted: ProofCeiling,
    field: &'static str,
) -> Result<(), TypedExecutionError> {
    if observed > proof_rank(admitted) {
        return Err(TypedExecutionError::OutputViolation(field.to_owned()));
    }
    Ok(())
}

/// Builds the typed lane's dispatch provider for the exact bounded buffer
/// (item 26 seam, #758): the buffer is compiled through the configured
/// provider (`WasmtimeComponentEngine::new_for_admitted_limits`) instead of a
/// locally-configured engine, and the caller dispatches via
/// `provider.dispatch_leg(limits)` — the same leg the provider itself invokes
/// under for the admitted cancellation policy. Both typed lanes (describe and
/// domain) build through this one seam so the typed provider construction
/// exists exactly once. `guest_exec` is untouched: the shared provider
/// constructor is reused, never modified, here.
///
/// The provider legs carry the exact typed settings the retired local seam
/// enforced: component model on, epoch interruption on, fuel accounting only
/// on the fuel leg (selected exactly when the admitted policy meters fuel),
/// and the provider stack ceiling. The legs additionally use the
/// provider-owned pooling allocator (a provider performance Default, not a
/// typed ceiling); Store/resource ceilings stay lane-owned in [`new_store`].
///
/// Failure vocabulary is unchanged: engine construction failure is the typed
/// `ENGINE:config:invalid`, compilation failure keeps the staged `Compile`
/// mapping of [`map_compile_error`], and binding/digest variants unreachable
/// through this constructor (every digest is recomputed from the presented
/// bytes; no caller binding is taken) map to the closest owned typed denial.
fn build_typed_dispatch_provider(
    world: TypedWorld,
    limits: &InvocationLimits,
    artifact: &[u8],
) -> Result<WasmtimeComponentEngine, TypedExecutionError> {
    WasmtimeComponentEngine::new_for_admitted_limits(
        artifact,
        &typed_component_configuration(world),
        limits,
    )
    .map_err(map_provider_build_error)
}

/// Component-configuration bytes bound into the typed dispatch provider
/// build. Computed per world from the lane's own generated selection — lane,
/// world, describe plus domain exports, closed imports — never pasted, never
/// a name/path/URL, and never the legacy guest descriptor.
fn typed_component_configuration(world: TypedWorld) -> Vec<u8> {
    format!(
        "component=typed-dispatch;world={};exports=describe+{};imports=closed",
        world.world_name(),
        world.domain_func(),
    )
    .into_bytes()
}

/// Maps a dispatch-provider build failure to the exact owned typed denial.
/// Typed failures stay typed: there is no stringly catch-all.
fn map_provider_build_error(error: WasmtimeBuildError) -> TypedExecutionError {
    match error {
        WasmtimeBuildError::Config(_) => TypedExecutionError::Engine("config:invalid".to_owned()),
        WasmtimeBuildError::Compile(error) => {
            staged(TypedStage::Compile, map_compile_error(&error))
        }
        WasmtimeBuildError::ArtifactDigestMismatch => {
            TypedExecutionError::AdmissionMismatch("artifact-digest".to_owned())
        }
        WasmtimeBuildError::VersionMismatch
        | WasmtimeBuildError::WitDigestMismatch
        | WasmtimeBuildError::ConfigurationDigestMismatch
        | WasmtimeBuildError::ComponentConfigurationDigestMismatch => {
            TypedExecutionError::AdmissionMismatch("engine-binding".to_owned())
        }
    }
}

/// Executes the typed `describe` descriptor for one world through the real
/// Wasmtime component engine under deny-by-default sandbox policy.
///
/// Reads nothing: the caller supplies the exact immutable buffer. The same
/// buffer is hashed (preflight) and compiled; the path is never reread.
/// Zero ambient imports, full resource limits, and output checks apply to
/// descriptor/initialization execution exactly like a domain call:
/// instantiation and the descriptor run inside the same guarded envelope, so
/// fuel exhaustion or the epoch deadline there is reported at the
/// `Instantiate`/`Descriptor` stage actually reached. The descriptor identity
/// (including the frozen WIT digest) is validated before the receipt is
/// produced. The admitted typed domain operation is executed by
/// [`execute_domain_experimental`], which reuses this same preflight,
/// envelope and limits.
pub fn execute_describe_experimental(
    world: TypedWorld,
    artifact: &[u8],
    limits: &InvocationLimits,
) -> Result<(TypedReceipt, TypedDescriptor), TypedExecutionError> {
    let start = Instant::now();
    // Same-buffer hash/compile: preflight once, compile the same slice.
    let preflight = preflight_bytes(artifact)?;
    validate_limits(limits, &preflight.digest)?;
    // Cache identity revalidation before any engine is built: no bypass.
    let cache_identity = check_cache_identity(world, artifact, &preflight.digest, limits)?;

    let provider = build_typed_dispatch_provider(world, limits, artifact)?;
    let (engine, component) = provider.dispatch_leg(limits);

    // Inspect the exact component type before any instance is created or any
    // guest function is called. Generated bindings provide the expected WIT
    // function signatures; the Wasmtime ComponentFunc type checker compares
    // them against the compiled component metadata.
    let (imports, exports) = preflight_component_type(world, engine, component)?;

    let (descriptor, usage) = dispatch_describe(world, engine, component, limits)?;
    let (output_digest, output_bytes) =
        validate_descriptor(world, &descriptor, limits.max_output_bytes)
            .map_err(|error| staged(TypedStage::Output, error))?;
    validate_descriptor_abi_digest(&descriptor)
        .map_err(|error| staged(TypedStage::Descriptor, error))?;

    let elapsed_ms = u64::try_from(start.elapsed().as_millis()).unwrap_or(u64::MAX);
    let input_digest = Sha256Digest::of_bytes(&[]);
    let terminal = format!("{:?}", EngineTermination::Completed);
    let mut receipt = TypedReceipt {
        proof: ExecutionMode::LocalExperimental.proof().to_owned(),
        world: world.world_name().to_owned(),
        package_id: crate::typed_bindings::TYPED_PACKAGE_ID.to_owned(),
        artifact_digest: preflight.digest.clone(),
        artifact_bytes: preflight.byte_len,
        engine_version: ENGINE_VERSION.to_owned(),
        wit_digest: typed_wit_digest(),
        cache_identity: cache_identity.digest(),
        actual_imports: imports,
        actual_exports: exports,
        input_digest,
        input_bytes: 0,
        output_digest: output_digest.clone(),
        output_bytes,
        fuel_consumed: usage.fuel_consumed,
        peak_memory_bytes: usage.peak_memory_bytes,
        table_elements: usage.table_elements,
        instances: 1,
        operation_id: None,
        task_id: None,
        fence_epoch: None,
        policy_id: None,
        stage: TypedStage::Cleanup.as_str().to_owned(),
        elapsed_ms,
        terminal: terminal.clone(),
        // Replaced immediately below: `semantic_digest` reads the receipt's
        // deterministic semantic fields and never this placeholder, the wall
        // time, fuel, or peak measurements.
        semantic_digest: Sha256Digest::of_bytes(b"typed-semantic-pending"),
    };
    receipt.semantic_digest = semantic_digest(&receipt);
    // P10.1 (#758): the describe-only lane is kit-less — no governing kit
    // binds this call, so no honest `kit_digest` source exists here. This site
    // stays on the host receipt and must not call the shared projection until a
    // kit owner binds one (see `crate::receipt_bridge`).
    Ok((receipt, descriptor))
}

fn preflight_component_type(
    world: TypedWorld,
    engine: &wasmtime::Engine,
    component: &wasmtime::component::Component,
) -> Result<(Vec<String>, Vec<String>), TypedExecutionError> {
    use wasmtime::component::types::ComponentItem;

    let component_type = component.component_type();
    let imports: Vec<String> = component_type
        .imports(engine)
        .map(|(name, _)| name.to_owned())
        .collect();
    if let Some(import) = imports.first() {
        let bounded: String = import.chars().take(96).collect();
        return Err(TypedExecutionError::ForbiddenImport(bounded));
    }

    let exports: Vec<_> = component_type.exports(engine).collect();
    if exports.is_empty() {
        return Err(TypedExecutionError::MissingExport(
            world.interface_name().to_owned(),
        ));
    }
    if exports.len() != 1 {
        return Err(TypedExecutionError::WorldSelection {
            reason: "ambiguous-exports".to_owned(),
        });
    }

    let (name, interface) = &exports[0];
    if *name == crate::typed_bindings::LEGACY_EXPORT || *name == "run" {
        return Err(TypedExecutionError::LegacyMismatch);
    }
    if !crate::typed_bindings::export_matches_interface(name, world.interface_name()) {
        return Err(TypedExecutionError::MissingExport(
            world.interface_name().to_owned(),
        ));
    }

    let ComponentItem::ComponentInstance(interface_type) = &interface.ty else {
        return Err(TypedExecutionError::ExportTypeMismatch(
            world.interface_name().to_owned(),
        ));
    };
    let expected_exports = [
        world.describe_func().to_owned(),
        world.domain_func().to_owned(),
    ];
    for (name, item) in interface_type.exports(engine) {
        if expected_exports.iter().any(|expected| expected == name) {
            continue;
        }
        // WIT interface types may be exported alongside functions. Permit
        // those generated type identities while rejecting extra callable or
        // structural exports that are outside the selected world's contract.
        if !matches!(item.ty, ComponentItem::Type(_) | ComponentItem::Resource(_)) {
            return Err(TypedExecutionError::WorldSelection {
                reason: "extra-interface-export".to_owned(),
            });
        }
    }

    let descriptor = component_function(interface_type, engine, world.describe_func())?;
    let domain = component_function(interface_type, engine, world.domain_func())?;
    typecheck_world_signatures(world, &descriptor, &domain, component)?;

    Ok((imports, vec![(*name).to_owned()]))
}

fn typecheck_world_signatures(
    world: TypedWorld,
    descriptor: &wasmtime::component::types::ComponentFunc,
    domain: &wasmtime::component::types::ComponentFunc,
    component: &wasmtime::component::Component,
) -> Result<(), TypedExecutionError> {
    let component_type = component.component_type();
    let type_context = &component_type.instance_type();
    match world {
        TypedWorld::ContextAdmission => {
            use crate::typed_bindings::context_admission::exports::eliot::current::admission as wit;
            descriptor
                .typecheck::<(), (wit::AbiDescriptor,)>(type_context)
                .map_err(|_| TypedExecutionError::ExportTypeMismatch("describe".to_owned()))?;
            domain
                .typecheck::<
                    (wit::AdmissionRequest,),
                    (Result<wit::AdmissionResult, wit::AdmissionError>,),
                >(type_context)
                .map_err(|_| TypedExecutionError::ExportTypeMismatch("admit".to_owned()))?;
        }
        TypedWorld::ContextAssembly => {
            use crate::typed_bindings::context_assembly::exports::eliot::current::assembly as wit;
            descriptor
                .typecheck::<(), (wit::AbiDescriptor,)>(type_context)
                .map_err(|_| TypedExecutionError::ExportTypeMismatch("describe".to_owned()))?;
            domain
                .typecheck::<
                    (wit::AssemblyRequest,),
                    (Result<wit::AssemblyResult, wit::AssemblyError>,),
                >(type_context)
                .map_err(|_| TypedExecutionError::ExportTypeMismatch("assemble".to_owned()))?;
        }
        TypedWorld::CueActivation => {
            use crate::typed_bindings::cue_activation::exports::eliot::current::activation as wit;
            descriptor
                .typecheck::<(), (wit::AbiDescriptor,)>(type_context)
                .map_err(|_| TypedExecutionError::ExportTypeMismatch("describe".to_owned()))?;
            domain
                .typecheck::<
                    (wit::ActivationRequest,),
                    (Result<wit::ActivationOutcome, wit::ActivationError>,),
                >(type_context)
                .map_err(|_| TypedExecutionError::ExportTypeMismatch("activate".to_owned()))?;
        }
        TypedWorld::DreamerHandler => {
            use crate::typed_bindings::dreamer_handler::exports::eliot::current::handler as wit;
            descriptor
                .typecheck::<(), (wit::AbiDescriptor,)>(type_context)
                .map_err(|_| TypedExecutionError::ExportTypeMismatch("describe".to_owned()))?;
            domain
                .typecheck::<
                    (wit::ValidatedCandidate,),
                    (Result<wit::HandlerOutcome, wit::HandlerError>,),
                >(type_context)
                .map_err(|_| TypedExecutionError::ExportTypeMismatch("handle".to_owned()))?;
        }
        TypedWorld::MemoryCurationScreen => {
            use crate::typed_bindings::memory_curation_screen::exports::eliot::current::screen as wit;
            descriptor
                .typecheck::<(), (wit::AbiDescriptor,)>(type_context)
                .map_err(|_| TypedExecutionError::ExportTypeMismatch("describe".to_owned()))?;
            domain
                .typecheck::<
                    (wit::ScreenRequest,),
                    (Result<wit::ScreenOutcome, wit::ScreenError>,),
                >(type_context)
                .map_err(|_| TypedExecutionError::ExportTypeMismatch("screen".to_owned()))?;
        }
        TypedWorld::DreamerCycle => {
            use crate::typed_bindings::dreamer_cycle::exports::eliot::current::cycle as wit;
            descriptor
                .typecheck::<(), (wit::AbiDescriptor,)>(type_context)
                .map_err(|_| TypedExecutionError::ExportTypeMismatch("describe".to_owned()))?;
            domain
                .typecheck::<(wit::CycleStepInput,), (Result<wit::CycleOutcome, wit::CycleError>,)>(
                    type_context,
                )
                .map_err(|_| TypedExecutionError::ExportTypeMismatch("step".to_owned()))?;
        }
    }

    Ok(())
}

fn component_function(
    interface: &wasmtime::component::types::ComponentInstance,
    engine: &wasmtime::Engine,
    name: &str,
) -> Result<wasmtime::component::types::ComponentFunc, TypedExecutionError> {
    use wasmtime::component::types::ComponentItem;

    let export = interface
        .get_export(engine, name)
        .ok_or_else(|| TypedExecutionError::MissingExport(name.to_owned()))?;
    match export.ty {
        ComponentItem::ComponentFunc(function) if !function.async_() => Ok(function),
        _ => Err(TypedExecutionError::ExportTypeMismatch(name.to_owned())),
    }
}

fn map_compile_error(error: &wasmtime::Error) -> TypedExecutionError {
    let message = error.to_string().to_ascii_lowercase();
    if message.contains("expected component") || message.contains("expected a component") {
        return TypedExecutionError::Artifact(PreflightError::CoreModuleRejected);
    }
    if message.contains("import") && message.contains("unknown") {
        TypedExecutionError::ForbiddenImport("unregistered-import".to_owned())
    } else {
        TypedExecutionError::Engine("compile:component-error".to_owned())
    }
}

#[derive(Clone, Copy)]
enum ResourceLimitHit {
    Memory,
    Table,
}

fn resource_limit_error(hit: ResourceLimitHit) -> TypedExecutionError {
    let termination = match hit {
        ResourceLimitHit::Memory => EngineTermination::MemoryLimit,
        ResourceLimitHit::Table => EngineTermination::TableLimit,
    };
    TypedExecutionError::Engine(format!("{termination:?}"))
}

/// Owner-typed terminal cause for one trapped guest execution, taken from the
/// real engine trap code and never from the engine message text. `None` means
/// the engine error is not a trap at all, so the caller keeps its own
/// untyped stage vocabulary.
///
/// `unreachable` — the instruction a guest panic lowers to — and every other
/// fault code are guest traps, never guest errors: the owner-typed
/// `Trap(GuestTrap)` cause keeps them distinct from
/// `TypedDomainResult::GuestError` and from fuel, deadline, stack, and resource
/// terminations.
///
/// One classifier, both untrusted-execution legs (issue #758 case 13): a
/// component's own initialization and the descriptor/domain call after it run
/// under the same guarded envelope, so a fuel or epoch termination on either
/// leg carries the same typed cause.
fn trap_termination(error: &wasmtime::Error) -> Option<EngineTermination> {
    let trap = error.downcast_ref::<wasmtime::Trap>()?;
    let termination = match *trap {
        wasmtime::Trap::OutOfFuel => EngineTermination::FuelExhausted,
        wasmtime::Trap::Interrupt => EngineTermination::EpochDeadline,
        wasmtime::Trap::StackOverflow => EngineTermination::StackLimit,
        wasmtime::Trap::UnreachableCodeReached | _ => EngineTermination::Trap(TrapClass::GuestTrap),
    };
    Some(termination)
}

fn map_call_error(
    call: &str,
    error: &wasmtime::Error,
    limit_hit: Option<ResourceLimitHit>,
) -> TypedExecutionError {
    if let Some(hit) = limit_hit {
        return resource_limit_error(hit);
    }
    // A trapped leg reports the owner-typed cause; only a non-trap engine error
    // falls back to this stage's untyped code. The staged `Invoke` wrapper
    // records the terminal stage without claiming success, and the single
    // invocation is never retried on another world.
    match trap_termination(error) {
        Some(termination) => TypedExecutionError::Engine(format!("{termination:?}")),
        None => TypedExecutionError::Engine(format!("{call}:component-call")),
    }
}

fn map_instantiate_error(
    error: &wasmtime::Error,
    limit_hit: Option<ResourceLimitHit>,
) -> TypedExecutionError {
    if let Some(hit) = limit_hit {
        return resource_limit_error(hit);
    }
    // Instance exhaustion surfaces as an instantiation error, never as a
    // growth callback: reuse the provider owner's classifier so the typed
    // lane reports the same typed `InstanceLimit` denial.
    if is_instance_limit_error(error) {
        return TypedExecutionError::Engine(format!("{:?}", EngineTermination::InstanceLimit));
    }
    // Component initialization is untrusted execution too, and it runs inside
    // the same guarded envelope as the descriptor call: an instantiation the
    // engine terminates with a real trap carries the same owner-typed fuel,
    // epoch, stack or guest-trap cause the domain leg already reports, instead
    // of the untyped `instantiate:component-error` string a pinned trap message
    // can never be told apart from any other unknown fault. The stage stays
    // `TypedStage::Instantiate`; only the cause becomes typed. The cause is
    // read from the real engine trap code, never from the message text.
    if let Some(termination) = trap_termination(error) {
        return TypedExecutionError::Engine(format!("{termination:?}"));
    }
    let lowered = error.to_string().to_ascii_lowercase();
    if lowered.contains("import") {
        TypedExecutionError::ForbiddenImport("component-import".to_owned())
    } else if lowered.contains("export") || lowered.contains("missing") || lowered.contains("type")
    {
        TypedExecutionError::MissingExport("component-export".to_owned())
    } else {
        TypedExecutionError::Engine("instantiate:component-error".to_owned())
    }
}

struct ObservedUsage {
    fuel_consumed: u64,
    peak_memory_bytes: Option<u64>,
    table_elements: Option<u32>,
}

/// Per-store resource state for one guarded typed invocation. Count bounds
/// (`memories`, `tables`, `instances`) are forwarded to the configured
/// [`wasmtime::StoreLimits`]; byte/element bounds are enforced in the growth
/// callbacks below. The pinned Wasmtime 47 `ResourceLimiter` offers no
/// resource/handle/module bound, so those classes are explicit unsupported
/// policy here: no field claims to enforce them, and receipts must never
/// claim they were bounded.
struct StoreState {
    limits: wasmtime::StoreLimits,
    peak_memory_bytes: Option<u64>,
    pending_memory_bytes: Option<u64>,
    table_elements: Option<u32>,
    pending_table_elements: Option<u32>,
    limit_hit: Option<ResourceLimitHit>,
}

impl StoreState {
    fn observe_memory(&mut self, bytes: u64) {
        self.peak_memory_bytes = Some(self.peak_memory_bytes.map_or(bytes, |peak| peak.max(bytes)));
    }

    fn observe_table(&mut self, elements: u32) {
        self.table_elements = Some(
            self.table_elements
                .map_or(elements, |peak| peak.max(elements)),
        );
    }

    fn finish_measurements(&mut self) -> (Option<u64>, Option<u32>) {
        if let Some(bytes) = self.pending_memory_bytes.take() {
            self.observe_memory(bytes);
        }
        if let Some(elements) = self.pending_table_elements.take() {
            self.observe_table(elements);
        }
        (self.peak_memory_bytes, self.table_elements)
    }
}

/// Fuel budget for one guarded invocation. `Some` only when the admitted
/// cancellation policy meters fuel (`EpochAndFuel`): epoch-only execution
/// leaves fuel disabled so the injected epoch/wall deadline alone decides
/// termination. Compilation and host-side bounding (preflight, lift checks,
/// receipts) never consume fuel either way.
fn typed_fuel_budget(limits: &InvocationLimits) -> Option<u64> {
    match limits.epoch.cancellation {
        CancellationPolicy::EpochAndFuel => Some(limits.max_fuel),
        CancellationPolicy::EpochInterruption => None,
    }
}

fn new_store(
    engine: &wasmtime::Engine,
    limits: &InvocationLimits,
) -> Result<wasmtime::Store<StoreState>, TypedExecutionError> {
    let mut store = wasmtime::Store::new(
        engine,
        StoreState {
            limits: wasmtime::StoreLimitsBuilder::new()
                .memory_size(usize::try_from(limits.max_memory_bytes).unwrap_or(usize::MAX))
                .memories(MAX_TYPED_MEMORIES)
                .table_elements(usize::try_from(limits.max_table_elements).unwrap_or(usize::MAX))
                .tables(MAX_TYPED_TABLES)
                .instances(usize::try_from(limits.max_instances).unwrap_or(usize::MAX))
                .build(),
            peak_memory_bytes: None,
            pending_memory_bytes: None,
            table_elements: None,
            pending_table_elements: None,
            limit_hit: None,
        },
    );
    store.limiter(|state| state);
    if let Some(budget) = typed_fuel_budget(limits) {
        store
            .set_fuel(budget)
            .map_err(|_| TypedExecutionError::LimitDenied("fuel".to_owned()))?;
    }
    store.set_epoch_deadline(limits.epoch.deadline_ticks);
    Ok(store)
}

impl wasmtime::ResourceLimiter for StoreState {
    fn memory_growing(
        &mut self,
        current: usize,
        desired: usize,
        maximum: Option<usize>,
    ) -> Result<bool, wasmtime::Error> {
        // The current value is an observed allocation. A requested value is
        // provisional until Wasmtime either reaches another growth callback
        // (whose `current` proves it landed) or the Store is inspected after
        // the invocation. Wasmtime calls `memory_grow_failed` on an allowed
        // request that still fails allocation/maximum checks.
        self.observe_memory(u64::try_from(current).unwrap_or(u64::MAX));
        self.pending_memory_bytes = None;
        let allowed = self.limits.memory_growing(current, desired, maximum)?;
        if allowed {
            self.pending_memory_bytes = Some(u64::try_from(desired).unwrap_or(u64::MAX));
        } else {
            self.limit_hit.get_or_insert(ResourceLimitHit::Memory);
        }
        Ok(allowed)
    }

    fn memory_grow_failed(&mut self, _error: wasmtime::Error) -> Result<(), wasmtime::Error> {
        self.pending_memory_bytes = None;
        self.limit_hit.get_or_insert(ResourceLimitHit::Memory);
        Ok(())
    }

    fn table_growing(
        &mut self,
        current: usize,
        desired: usize,
        maximum: Option<usize>,
    ) -> Result<bool, wasmtime::Error> {
        self.observe_table(u32::try_from(current).unwrap_or(u32::MAX));
        self.pending_table_elements = None;
        let allowed = self.limits.table_growing(current, desired, maximum)?;
        if allowed {
            self.pending_table_elements = Some(u32::try_from(desired).unwrap_or(u32::MAX));
        } else {
            self.limit_hit.get_or_insert(ResourceLimitHit::Table);
        }
        Ok(allowed)
    }

    fn table_grow_failed(&mut self, _error: wasmtime::Error) -> Result<(), wasmtime::Error> {
        self.pending_table_elements = None;
        self.limit_hit.get_or_insert(ResourceLimitHit::Table);
        Ok(())
    }

    fn instances(&self) -> usize {
        self.limits.instances()
    }

    fn tables(&self) -> usize {
        self.limits.tables()
    }

    fn memories(&self) -> usize {
        self.limits.memories()
    }
}

/// Epoch-driver lifetime guard for one guarded invocation (item 23).
/// Each invocation builds a fresh engine, component, store, and driver:
/// this module holds no `static`, so invocations share nothing and a failure
/// cannot poison a later call. Stopping the driver and joining its thread
/// happens in [`Drop`], so every exit path — success, staged failure, early
/// return, or panic — tears the driver down before the per-invocation engine
/// is dropped. The explicit `drop` in [`run_guarded`] keeps the original
/// ordering (driver joined before fuel and resource measurements are read);
/// the `Drop` impl is the backstop for exits that never reach it.
struct EpochDriver {
    stop: Arc<AtomicBool>,
    handle: Option<thread::JoinHandle<()>>,
}

impl EpochDriver {
    fn spawn(
        engine: &wasmtime::Engine,
        limits: &InvocationLimits,
    ) -> Result<Self, TypedExecutionError> {
        let wall_deadline = Instant::now() + Duration::from_millis(limits.wall_deadline_ms);
        let stop = Arc::new(AtomicBool::new(false));
        let engine_clone = engine.clone();
        let stop_clone = Arc::clone(&stop);
        let epoch_deadline = limits.epoch.deadline_ticks;
        // Same interruption mechanism as the legacy provider: a bounded driver
        // thread advances the epoch and forces the deadline once the wall
        // clock expires. Guests observe only interruption, never time.
        let handle = thread::Builder::new()
            .name("eliot-typed-epoch".to_owned())
            .spawn(move || {
                while !stop_clone.load(Ordering::Acquire) {
                    thread::sleep(Duration::from_millis(1));
                    if Instant::now() >= wall_deadline {
                        for _ in 0..epoch_deadline {
                            engine_clone.increment_epoch();
                        }
                        break;
                    }
                    engine_clone.increment_epoch();
                }
            })
            .map_err(|_| TypedExecutionError::Engine("epoch-driver-spawn".to_owned()))?;
        Ok(Self {
            stop,
            handle: Some(handle),
        })
    }
}

impl Drop for EpochDriver {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

/// Runs one descriptor closure with fuel, memory/table/instance limits,
/// and epoch interruption driven by both a tick pump and the wall
/// deadline. The wall deadline forces epoch ticks independent of remaining
/// fuel, so the epoch deadline fires even when fuel is plentiful. No clock,
/// randomness, or ambient capability reaches the guest. There is no
/// synchronous cancellation: dropping a caller future stops nothing; only
/// fuel exhaustion or the epoch/wall deadline traps below stop the guest.
/// A failed invocation retains nothing for the next one: the store, driver,
/// and per-invocation engine state all drop here, and the staged error keeps
/// the stage actually reached without retrying another world or invocation.
fn run_guarded<T>(
    engine: &wasmtime::Engine,
    limits: &InvocationLimits,
    invoke: impl FnOnce(&mut wasmtime::Store<StoreState>) -> Result<T, TypedExecutionError>,
) -> Result<(T, ObservedUsage), TypedExecutionError> {
    let mut store = new_store(engine, limits)?;
    let driver = EpochDriver::spawn(engine, limits)?;
    let outcome = invoke(&mut store);
    drop(driver);
    let fuel_consumed = match typed_fuel_budget(limits) {
        Some(budget) => budget.saturating_sub(store.get_fuel().unwrap_or(0)),
        None => 0,
    };
    let limit_hit = store.data().limit_hit;
    let (peak_memory_bytes, table_elements) = store.data_mut().finish_measurements();
    match outcome {
        Ok(value) => {
            if let Some(hit) = limit_hit {
                Err(staged(TypedStage::Cleanup, resource_limit_error(hit)))
            } else {
                Ok((
                    value,
                    ObservedUsage {
                        fuel_consumed,
                        peak_memory_bytes,
                        table_elements,
                    },
                ))
            }
        }
        Err(error) => Err(error),
    }
}

fn dispatch_describe(
    world: TypedWorld,
    engine: &wasmtime::Engine,
    component: &wasmtime::component::Component,
    limits: &InvocationLimits,
) -> Result<(TypedDescriptor, ObservedUsage), TypedExecutionError> {
    match world {
        TypedWorld::ContextAdmission => describe_context_admission(engine, component, limits),
        TypedWorld::ContextAssembly => describe_context_assembly(engine, component, limits),
        TypedWorld::CueActivation => describe_cue_activation(engine, component, limits),
        TypedWorld::DreamerHandler => describe_dreamer_handler(engine, component, limits),
        TypedWorld::MemoryCurationScreen => {
            describe_memory_curation_screen(engine, component, limits)
        }
        TypedWorld::DreamerCycle => describe_dreamer_cycle(engine, component, limits),
    }
}

// One typed binding per world. Each arm uses only its own generated module
// from the single `wit/typed` directory (no hand-copied schema).

fn describe_context_admission(
    engine: &wasmtime::Engine,
    component: &wasmtime::component::Component,
    limits: &InvocationLimits,
) -> Result<(TypedDescriptor, ObservedUsage), TypedExecutionError> {
    use crate::typed_bindings::context_admission::ContextAdmission;
    run_guarded(engine, limits, |store| {
        let linker = wasmtime::component::Linker::new(engine);
        let instance =
            ContextAdmission::instantiate(&mut *store, component, &linker).map_err(|error| {
                staged(
                    TypedStage::Instantiate,
                    map_instantiate_error(&error, store.data().limit_hit),
                )
            })?;
        let raw = instance
            .eliot_current_admission()
            .call_describe(&mut *store)
            .map_err(|error| {
                staged(
                    TypedStage::Descriptor,
                    map_call_error("describe", &error, store.data().limit_hit),
                )
            })?;
        Ok(TypedDescriptor {
            world_name: raw.world_name,
            package_id: raw.package_id,
            abi_revision: raw.abi_revision,
            native_contract: raw.native_contract,
            native_revision: raw.native_revision,
            abi_digest: raw.abi_digest,
        })
    })
}

fn describe_context_assembly(
    engine: &wasmtime::Engine,
    component: &wasmtime::component::Component,
    limits: &InvocationLimits,
) -> Result<(TypedDescriptor, ObservedUsage), TypedExecutionError> {
    use crate::typed_bindings::context_assembly::ContextAssembly;
    run_guarded(engine, limits, |store| {
        let linker = wasmtime::component::Linker::new(engine);
        let instance =
            ContextAssembly::instantiate(&mut *store, component, &linker).map_err(|error| {
                staged(
                    TypedStage::Instantiate,
                    map_instantiate_error(&error, store.data().limit_hit),
                )
            })?;
        let raw = instance
            .eliot_current_assembly()
            .call_describe(&mut *store)
            .map_err(|error| {
                staged(
                    TypedStage::Descriptor,
                    map_call_error("describe", &error, store.data().limit_hit),
                )
            })?;
        Ok(TypedDescriptor {
            world_name: raw.world_name,
            package_id: raw.package_id,
            abi_revision: raw.abi_revision,
            native_contract: raw.native_contract,
            native_revision: raw.native_revision,
            abi_digest: raw.abi_digest,
        })
    })
}

fn describe_cue_activation(
    engine: &wasmtime::Engine,
    component: &wasmtime::component::Component,
    limits: &InvocationLimits,
) -> Result<(TypedDescriptor, ObservedUsage), TypedExecutionError> {
    use crate::typed_bindings::cue_activation::CueActivation;
    run_guarded(engine, limits, |store| {
        let linker = wasmtime::component::Linker::new(engine);
        let instance =
            CueActivation::instantiate(&mut *store, component, &linker).map_err(|error| {
                staged(
                    TypedStage::Instantiate,
                    map_instantiate_error(&error, store.data().limit_hit),
                )
            })?;
        let raw = instance
            .eliot_current_activation()
            .call_describe(&mut *store)
            .map_err(|error| {
                staged(
                    TypedStage::Descriptor,
                    map_call_error("describe", &error, store.data().limit_hit),
                )
            })?;
        Ok(TypedDescriptor {
            world_name: raw.world_name,
            package_id: raw.package_id,
            abi_revision: raw.abi_revision,
            native_contract: raw.native_contract,
            native_revision: raw.native_revision,
            abi_digest: raw.abi_digest,
        })
    })
}

fn describe_dreamer_handler(
    engine: &wasmtime::Engine,
    component: &wasmtime::component::Component,
    limits: &InvocationLimits,
) -> Result<(TypedDescriptor, ObservedUsage), TypedExecutionError> {
    use crate::typed_bindings::dreamer_handler::DreamerHandler;
    run_guarded(engine, limits, |store| {
        let linker = wasmtime::component::Linker::new(engine);
        let instance =
            DreamerHandler::instantiate(&mut *store, component, &linker).map_err(|error| {
                staged(
                    TypedStage::Instantiate,
                    map_instantiate_error(&error, store.data().limit_hit),
                )
            })?;
        let raw = instance
            .eliot_current_handler()
            .call_describe(&mut *store)
            .map_err(|error| {
                staged(
                    TypedStage::Descriptor,
                    map_call_error("describe", &error, store.data().limit_hit),
                )
            })?;
        Ok(TypedDescriptor {
            world_name: raw.world_name,
            package_id: raw.package_id,
            abi_revision: raw.abi_revision,
            native_contract: raw.native_contract,
            native_revision: raw.native_revision,
            abi_digest: raw.abi_digest,
        })
    })
}

fn describe_memory_curation_screen(
    engine: &wasmtime::Engine,
    component: &wasmtime::component::Component,
    limits: &InvocationLimits,
) -> Result<(TypedDescriptor, ObservedUsage), TypedExecutionError> {
    use crate::typed_bindings::memory_curation_screen::MemoryCurationScreen;
    run_guarded(engine, limits, |store| {
        let linker = wasmtime::component::Linker::new(engine);
        let instance = MemoryCurationScreen::instantiate(&mut *store, component, &linker).map_err(
            |error| {
                staged(
                    TypedStage::Instantiate,
                    map_instantiate_error(&error, store.data().limit_hit),
                )
            },
        )?;
        let raw = instance
            .eliot_current_screen()
            .call_describe(&mut *store)
            .map_err(|error| {
                staged(
                    TypedStage::Descriptor,
                    map_call_error("describe", &error, store.data().limit_hit),
                )
            })?;
        Ok(TypedDescriptor {
            world_name: raw.world_name,
            package_id: raw.package_id,
            abi_revision: raw.abi_revision,
            native_contract: raw.native_contract,
            native_revision: raw.native_revision,
            abi_digest: raw.abi_digest,
        })
    })
}

fn describe_dreamer_cycle(
    engine: &wasmtime::Engine,
    component: &wasmtime::component::Component,
    limits: &InvocationLimits,
) -> Result<(TypedDescriptor, ObservedUsage), TypedExecutionError> {
    use crate::typed_bindings::dreamer_cycle::DreamerCycle;
    run_guarded(engine, limits, |store| {
        let linker = wasmtime::component::Linker::new(engine);
        let instance =
            DreamerCycle::instantiate(&mut *store, component, &linker).map_err(|error| {
                staged(
                    TypedStage::Instantiate,
                    map_instantiate_error(&error, store.data().limit_hit),
                )
            })?;
        let raw = instance
            .eliot_current_cycle()
            .call_describe(&mut *store)
            .map_err(|error| {
                staged(
                    TypedStage::Descriptor,
                    map_call_error("describe", &error, store.data().limit_hit),
                )
            })?;
        Ok(TypedDescriptor {
            world_name: raw.world_name,
            package_id: raw.package_id,
            abi_revision: raw.abi_revision,
            native_contract: raw.native_contract,
            native_revision: raw.native_revision,
            abi_digest: raw.abi_digest,
        })
    })
}

// One admitted typed domain operation per world.
//
// The request carrier is the generated WIT request type of the selected world
// itself, so the leg is typed end to end: no opaque `Vec<u8>`, no JSON, no
// hand-copied schema, and no domain crate imported to manufacture a result.
// The result carrier keeps the exact typed domain result, including the
// guest's own typed error, so a validly represented native error is never
// rewritten into Host success.

/// One admitted typed domain request, bound to its world's generated WIT
/// request type.
pub enum TypedDomainRequest {
    /// `context-admission` `admit` request.
    Admission(
        Box<
            crate::typed_bindings::context_admission::exports::eliot::current::admission::AdmissionRequest,
        >,
    ),
    /// `context-assembly` `assemble` request.
    Assembly(
        Box<
            crate::typed_bindings::context_assembly::exports::eliot::current::assembly::AssemblyRequest,
        >,
    ),
    /// `cue-activation` `activate` request.
    CueActivation(
        Box<
            crate::typed_bindings::cue_activation::exports::eliot::current::activation::ActivationRequest,
        >,
    ),
    /// `dreamer-handler` `handle` request.
    DreamerHandler(
        Box<
            crate::typed_bindings::dreamer_handler::exports::eliot::current::handler::ValidatedCandidate,
        >,
    ),
    /// `memory-curation-screen` `screen` request.
    MemoryCurationScreen(
        Box<
            crate::typed_bindings::memory_curation_screen::exports::eliot::current::screen::ScreenRequest,
        >,
    ),
    /// `dreamer-cycle` `step` request.
    DreamerCycle(
        Box<
            crate::typed_bindings::dreamer_cycle::exports::eliot::current::cycle::CycleStepInput,
        >,
    ),
}

impl TypedDomainRequest {
    /// The world whose generated request type this value carries.
    #[must_use]
    pub const fn world(&self) -> TypedWorld {
        match self {
            Self::Admission(_) => TypedWorld::ContextAdmission,
            Self::Assembly(_) => TypedWorld::ContextAssembly,
            Self::CueActivation(_) => TypedWorld::CueActivation,
            Self::DreamerHandler(_) => TypedWorld::DreamerHandler,
            Self::MemoryCurationScreen(_) => TypedWorld::MemoryCurationScreen,
            Self::DreamerCycle(_) => TypedWorld::DreamerCycle,
        }
    }
}

/// The exact typed result one domain export returned, retained verbatim.
pub enum TypedDomainOutcome {
    /// `admit` returned a typed `admission-result`.
    Admission(
        Box<
            crate::typed_bindings::context_admission::exports::eliot::current::admission::AdmissionResult,
        >,
    ),
    /// `assemble` returned a typed `assembly-result`.
    Assembly(
        Box<
            crate::typed_bindings::context_assembly::exports::eliot::current::assembly::AssemblyResult,
        >,
    ),
    /// `activate` returned a typed `activation-outcome`.
    CueActivation(
        Box<
            crate::typed_bindings::cue_activation::exports::eliot::current::activation::ActivationOutcome,
        >,
    ),
    /// `handle` returned a typed `handler-outcome`.
    DreamerHandler(
        Box<
            crate::typed_bindings::dreamer_handler::exports::eliot::current::handler::HandlerOutcome,
        >,
    ),
    /// `screen` returned a typed `screen-outcome`.
    MemoryCurationScreen(
        Box<
            crate::typed_bindings::memory_curation_screen::exports::eliot::current::screen::ScreenOutcome,
        >,
    ),
    /// `step` returned a typed `cycle-outcome`.
    DreamerCycle(
        Box<
            crate::typed_bindings::dreamer_cycle::exports::eliot::current::cycle::CycleOutcome,
        >,
    ),
}

/// The guest's own typed error, retained as the terminal domain result. This
/// is not a trap: a trap, fuel exhaustion, epoch deadline, stack limit or
/// resource fault is returned as [`TypedExecutionError`].
pub enum TypedDomainError {
    /// `admit` returned a typed `admission-error`.
    Admission(
        Box<
            crate::typed_bindings::context_admission::exports::eliot::current::admission::AdmissionError,
        >,
    ),
    /// `assemble` returned a typed `assembly-error`.
    Assembly(
        Box<
            crate::typed_bindings::context_assembly::exports::eliot::current::assembly::AssemblyError,
        >,
    ),
    /// `activate` returned a typed `activation-error`.
    CueActivation(
        Box<
            crate::typed_bindings::cue_activation::exports::eliot::current::activation::ActivationError,
        >,
    ),
    /// `handle` returned a typed `handler-error`.
    DreamerHandler(
        Box<
            crate::typed_bindings::dreamer_handler::exports::eliot::current::handler::HandlerError,
        >,
    ),
    /// `screen` returned a typed `screen-error`.
    MemoryCurationScreen(
        Box<
            crate::typed_bindings::memory_curation_screen::exports::eliot::current::screen::ScreenError,
        >,
    ),
    /// `step` returned a typed `cycle-error`.
    DreamerCycle(
        Box<
            crate::typed_bindings::dreamer_cycle::exports::eliot::current::cycle::CycleError,
        >,
    ),
}

/// Terminal result of the one domain call: a typed outcome, or the guest's own
/// typed error kept as-is.
pub enum TypedDomainResult {
    /// The guest returned a typed domain outcome.
    Outcome(Box<TypedDomainOutcome>),
    /// The guest returned its own typed error. Distinct from every trap.
    GuestError(Box<TypedDomainError>),
}

impl TypedDomainResult {
    /// Stable terminal code. A guest error never reads as a completed call.
    #[must_use]
    pub const fn terminal(&self) -> &'static str {
        match self {
            Self::Outcome(_) => "Completed",
            Self::GuestError(_) => "GuestError",
        }
    }
}

/// Executes the admitted typed domain operation for one world and returns the
/// host receipt, the retained typed domain result, and the projected #760
/// shared receipt for the same call when one can honestly exist.
///
/// Bound #760 capsule provenance selects the kit-owned lane. With provenance
/// the call runs [`execute_capsule_domain_experimental`], which validates the
/// kit and capsule, executes the one bounded typed call, and projects the host
/// receipt it produced onto the shared contract; this entry forwards that
/// projection unchanged. Without provenance the call runs the same bounded
/// typed call through the kit-less interior lane [`execute_domain_lane`] and
/// returns `None` for the shared receipt: `kit_digest` and `proof_ceiling` are
/// sourced only from a validated [`ModuleContractKit`], so a lane that holds no
/// kit reports `None` rather than inventing either value.
///
/// The caller's world selection is compared against the request's own world
/// here, before any preflight, engine, or delegation work: the capsule entry
/// derives its world from the request, so without this guard a caller could
/// select one world and execute another world's component. Both lanes are
/// covered, and the mismatch is the owned typed
/// [`TypedExecutionError::WorldSelection`] denial (`request-world`), the same
/// denial the kit-less interior applies to the same condition.
///
/// The host receipt stays the source of truth; the projection is additive
/// fail-closed evidence, never a replacement. Projected success still means one
/// bounded typed call, never candidate application, use, or task completion.
pub fn execute_domain_experimental(
    world: TypedWorld,
    artifact: &[u8],
    limits: &InvocationLimits,
    request: &TypedDomainRequest,
    admitted: &TypedDomainAdmission,
    provenance: Option<(&ModuleContractKit, &ModuleTestCapsule)>,
) -> Result<
    (
        TypedReceipt,
        TypedDomainResult,
        Option<eliot_wasm_runtime::TypedReceipt>,
    ),
    TypedExecutionError,
> {
    // P5.1/P5.3 (#758): the selected world is compared against the request's
    // own world before anything is acquired, compiled, or delegated, so no
    // caller can select one world and execute another world's component.
    if request.world() != world {
        return Err(TypedExecutionError::WorldSelection {
            reason: "request-world".to_owned(),
        });
    }
    let Some((kit, capsule)) = provenance else {
        // P10.1 (#758): the shared receipt binds the governing kit digest and
        // the admitted ceiling, and both are sourced only from a validated
        // `ModuleContractKit`. This kit-less lane holds no kit, so it executes
        // the one bounded typed call through the shared interior and reports
        // `None` for the shared receipt instead of synthesizing either value.
        let (receipt, result) = execute_domain_lane(world, artifact, limits, request, admitted)?;
        return Ok((receipt, result, None));
    };
    execute_capsule_domain_experimental(kit, capsule, artifact, limits, request, admitted)
}

/// Runs the one bounded typed domain call for one world through the real
/// Wasmtime component engine: the same bounded buffer is hashed and compiled,
/// the exact component type is inspected before instantiation, the component
/// is instantiated on the existing empty linker inside the existing guarded
/// envelope, the registered descriptor is called and its identity validated,
/// and the domain export is then called EXACTLY ONCE with the generated
/// request type of the selected world. That single invocation is terminal:
/// a staged failure or otherwise unknown outcome is returned as-is and never
/// retried on another world or second invocation.
///
/// This is the kit-less interior lane. It owns no kit and never projects: the
/// host receipt it returns is projected at the kit-owned call site in
/// [`execute_capsule_domain_experimental`], the only place that holds an
/// honest governing kit.
fn execute_domain_lane(
    world: TypedWorld,
    artifact: &[u8],
    limits: &InvocationLimits,
    request: &TypedDomainRequest,
    admitted: &TypedDomainAdmission,
) -> Result<(TypedReceipt, TypedDomainResult), TypedExecutionError> {
    let start = Instant::now();
    admitted.validate()?;
    // The same request/world agreement enforced at the public entry, re-checked
    // here as the execution-site invariant: this interior is private, so the
    // check is kept at the point where the selected world would otherwise be
    // compiled and invoked, and it runs before any preflight or engine work.
    if request.world() != world {
        return Err(TypedExecutionError::WorldSelection {
            reason: "request-world".to_owned(),
        });
    }

    // Pre-lift input bound: the typed request is measured and denied before
    // the host lowers any of it into guest memory.
    let mut input_bound = TypedBound::default();
    bound_request(world, request, admitted, &mut input_bound)?;
    let input_bytes = input_bound.finish(limits.max_input_bytes)?;
    let input_digest = input_digest(world, admitted, input_bytes);

    let preflight = preflight_bytes(artifact)?;
    validate_limits(limits, &preflight.digest)?;
    // Cache identity revalidation before any engine is built: no bypass.
    let cache_identity = check_cache_identity(world, artifact, &preflight.digest, limits)?;

    let provider = build_typed_dispatch_provider(world, limits, artifact)?;
    let (engine, component) = provider.dispatch_leg(limits);

    let (imports, exports) = preflight_component_type(world, engine, component)?;

    let (descriptor, result, usage) = dispatch_domain(world, engine, component, limits, request)?;

    let (descriptor_digest, descriptor_bytes) =
        validate_descriptor(world, &descriptor, limits.max_output_bytes)
            .map_err(|error| staged(TypedStage::Descriptor, error))?;
    validate_descriptor_abi_digest(&descriptor)
        .map_err(|error| staged(TypedStage::Descriptor, error))?;

    let mut output_bound = TypedBound::default();
    check_result(&result, admitted, &mut output_bound)
        .map_err(|error| staged(TypedStage::Output, error))?;
    // The result bound is still enforced fail-closed against the admitted
    // ceiling, but the receipt counts exactly what `output_digest` covers:
    // the validated descriptor fields from `validate_descriptor`. Folding
    // result bytes into this counter would pair a descriptor-only digest
    // with descriptor+result bytes.
    output_bound
        .finish(limits.max_output_bytes)
        .map_err(|error| staged(TypedStage::Output, error))?;
    let output_bytes = descriptor_bytes;

    let elapsed_ms = u64::try_from(start.elapsed().as_millis()).unwrap_or(u64::MAX);
    let terminal = result.terminal().to_owned();
    let mut receipt = TypedReceipt {
        proof: ExecutionMode::LocalExperimental.proof().to_owned(),
        world: world.world_name().to_owned(),
        package_id: crate::typed_bindings::TYPED_PACKAGE_ID.to_owned(),
        artifact_digest: preflight.digest.clone(),
        artifact_bytes: preflight.byte_len,
        engine_version: ENGINE_VERSION.to_owned(),
        wit_digest: typed_wit_digest(),
        cache_identity: cache_identity.digest(),
        actual_imports: imports,
        actual_exports: exports,
        input_digest,
        input_bytes,
        output_digest: descriptor_digest.clone(),
        output_bytes,
        fuel_consumed: usage.fuel_consumed,
        peak_memory_bytes: usage.peak_memory_bytes,
        table_elements: usage.table_elements,
        instances: 1,
        operation_id: Some(admitted.operation_id.clone()),
        task_id: Some(admitted.task_id.clone()),
        fence_epoch: Some(admitted.fence_epoch.clone()),
        policy_id: Some(admitted.policy_id.clone()),
        stage: TypedStage::Cleanup.as_str().to_owned(),
        elapsed_ms,
        terminal: terminal.clone(),
        // Replaced immediately below: `semantic_digest` reads the receipt's
        // deterministic semantic fields and never this placeholder, the wall
        // time, fuel, or peak measurements.
        semantic_digest: Sha256Digest::of_bytes(b"typed-semantic-pending"),
    };
    receipt.semantic_digest = semantic_digest(&receipt);
    // P10.1 (#758): this lane holds no kit and never synthesizes a
    // `kit_digest`. Its host receipt is projected onto #760's shared contract
    // at the kit-owned call site in `execute_capsule_domain_experimental`,
    // which is the only site that binds an honest governing kit digest and
    // admitted ceiling.
    Ok((receipt, result))
}

/// Maps a #760 neutral kit/capsule validation failure to the exact owned
/// typed denial. Neutral causes carry bounded field names only, so the
/// `InvalidKit`/`InvalidCapsule` tag passes through; every other cause maps
/// to the host denial with the same fail-closed meaning. Failures stay
/// typed: there is no stringly catch-all.
fn map_contract_error(error: TypedContractError) -> TypedExecutionError {
    match error {
        TypedContractError::UnknownWorld(_) | TypedContractError::WorldMismatch { .. } => {
            TypedExecutionError::WorldSelection {
                reason: "capsule-world".to_owned(),
            }
        }
        TypedContractError::LegacyRejected(_) => TypedExecutionError::LegacyMismatch,
        TypedContractError::PackageMismatch { .. } => {
            TypedExecutionError::AdmissionMismatch("package".to_owned())
        }
        TypedContractError::VersionMismatch { .. } => {
            TypedExecutionError::AdmissionMismatch("abi-version".to_owned())
        }
        TypedContractError::AbiMismatch { .. } => {
            TypedExecutionError::AdmissionMismatch("abi-revision".to_owned())
        }
        TypedContractError::DescriptorField(_) => {
            TypedExecutionError::AdmissionMismatch("abi-descriptor".to_owned())
        }
        TypedContractError::ImportMismatch => {
            TypedExecutionError::ForbiddenImport("capsule-import".to_owned())
        }
        TypedContractError::ExportMismatch => {
            TypedExecutionError::MissingExport("capsule-export".to_owned())
        }
        TypedContractError::EngineMismatch => {
            TypedExecutionError::AdmissionMismatch("engine-binding".to_owned())
        }
        TypedContractError::ArtifactMismatch | TypedContractError::InterfaceMismatch => {
            TypedExecutionError::AdmissionMismatch("capsule-artifact".to_owned())
        }
        TypedContractError::LimitDenied | TypedContractError::EnvelopeTooLarge => {
            TypedExecutionError::LimitDenied("capsule-bound".to_owned())
        }
        TypedContractError::ReportMismatch => {
            TypedExecutionError::AdmissionMismatch("capsule-report".to_owned())
        }
        TypedContractError::EngineDenied => {
            TypedExecutionError::Engine("capsule-engine-denied".to_owned())
        }
        TypedContractError::EngineUnavailable => {
            TypedExecutionError::Engine("capsule-engine-unavailable".to_owned())
        }
        TypedContractError::EngineUnknown => {
            TypedExecutionError::Engine("capsule-engine-unknown".to_owned())
        }
        TypedContractError::InvalidKit(detail) => TypedExecutionError::AdmissionMismatch(detail),
        TypedContractError::InvalidCapsule(detail) => {
            TypedExecutionError::AdmissionMismatch(detail)
        }
        TypedContractError::Serialization(_) => {
            TypedExecutionError::AdmissionMismatch("kit-digest".to_owned())
        }
    }
}

/// Executes the #760 neutral operation capsule's domain operation through
/// the real Wasmtime component engine on the local-experimental path.
///
/// The neutral [`ModuleContractKit`] and [`ModuleTestCapsule`] own the
/// world/operation/artifact/input/output bindings: the kit is validated,
/// the capsule is validated against the kit (exact world match, operation
/// equal to the world's domain export, kit-digest rebinding, fixture and
/// expected output inside the capsule's declared input/output bounds), the
/// capsule world and operation are rebound to the host's own generated
/// selection by canonical contract name (no cross-crate type bridge), and
/// the same artifact buffer is hashed and required to equal the kit-bound
/// digest and length. A governed kit is refused on this lane: the experimental receipt
/// is `NON_GOVERNED_EXPERIMENTAL` and can never satisfy governed proof.
///
/// The single invocation itself runs through the kit-less interior lane
/// (`execute_domain_lane`) with the
/// caller's typed request and admitted envelope: the same bounded
/// buffer is compiled, the exact component type is preflighted (including
/// the generated export-signature typecheck) before instantiation, the
/// descriptor and the domain export are each called exactly once under the
/// existing fuel/epoch/deadline/resource limits and cancellation policy,
/// and the typed terminal result (outcome or the guest's own typed error)
/// is retained verbatim. The typed request arrives as generated WIT types;
/// the capsule fixture bytes are bounds evidence only, never parsed into a
/// request, and there is no legacy byte-runner fallback.
///
/// The third returned element is `Some` of the projected #760 shared receipt
/// for this exact call, produced from the host receipt this function just
/// emitted: the host receipt remains the source of truth and the projection is
/// additive fail-closed evidence, never a replacement. A projection denial
/// fails the call with `?` instead of returning a receipt the shared contract
/// rejects. The projection is computed per call from this receipt alone —
/// nothing is cached across calls, so a failed invocation cannot poison an
/// independent later one — and its success still means one bounded typed call,
/// never candidate application, use, or task completion.
///
/// This kit-owned entry is the only place the shared receipt is projected:
/// `kit_digest` and `proof_ceiling` are taken here from the validated
/// [`ModuleContractKit`] above — the ceiling only after it has been proved
/// equal to the ceiling this call enforces — and a kit-less lane has no honest
/// source for either value, so it reports `None` rather than inventing them.
///
/// The projected output evidence covers exactly what the host receipt's
/// `output_digest` covers — the validated `describe` descriptor content from
/// `validate_descriptor` — and not the domain result's content, for which no
/// host-measured digest exists on this path. `execute_domain_lane` keeps that
/// receipt honest by counting the result separately and enforcing it against
/// the admitted ceiling without folding it into the descriptor digest; see
/// `crate::receipt_bridge` for the shared-side statement of the same coverage.
pub fn execute_capsule_domain_experimental(
    kit: &ModuleContractKit,
    capsule: &ModuleTestCapsule,
    artifact: &[u8],
    limits: &InvocationLimits,
    request: &TypedDomainRequest,
    admitted: &TypedDomainAdmission,
) -> Result<
    (
        TypedReceipt,
        TypedDomainResult,
        Option<eliot_wasm_runtime::TypedReceipt>,
    ),
    TypedExecutionError,
> {
    kit.validate().map_err(map_contract_error)?;
    capsule.validate(kit).map_err(map_contract_error)?;
    if kit.governed {
        return Err(TypedExecutionError::AdmissionMismatch(
            "kit-governed".to_owned(),
        ));
    }
    let world = request.world();
    if capsule.world.world_name() != world.world_name() {
        return Err(TypedExecutionError::AdmissionMismatch("world".to_owned()));
    }
    if capsule.operation.as_str() != world.domain_func() {
        return Err(TypedExecutionError::AdmissionMismatch(
            "operation".to_owned(),
        ));
    }
    let preflight = preflight_bytes(artifact)?;
    if kit.artifact_digest != preflight.digest {
        return Err(TypedExecutionError::AdmissionMismatch(
            "artifact-digest".to_owned(),
        ));
    }
    if kit.artifact_len != preflight.byte_len {
        return Err(TypedExecutionError::AdmissionMismatch(
            "artifact-length".to_owned(),
        ));
    }
    if capsule.max_input_bytes > limits.max_input_bytes {
        return Err(TypedExecutionError::LimitDenied("capsule-input".to_owned()));
    }
    if capsule.max_output_bytes > limits.max_output_bytes {
        return Err(TypedExecutionError::LimitDenied(
            "capsule-output".to_owned(),
        ));
    }
    // P10.1 (#758) receipt assembly inputs, bound at this kit-owned call
    // site only: the governing kit digest and the admitted ceiling come
    // from the validated `kit` above; nothing is synthesized. Bound before
    // delegation so a kit-digest failure denies before any engine work.
    let kit_digest = kit.digest().map_err(map_contract_error)?;
    // P10.1 (#758) proof/authority/effect escalation, rejected (item 20): the
    // shared receipt's `proof_ceiling` must be the ceiling this call actually
    // enforced, and the enforced ceiling is `admitted.proof_ceiling`, which
    // `check_ceiling` applies to the guest's echoed ceiling on every world
    // result. `ModuleContractKit::validate` binds package/ABI/artifact/import/
    // export identity but never bounds `kit.proof_ceiling` to the admitted
    // envelope, so a kit claiming a higher ceiling (for example `Handler` on a
    // `context-admission` call the host admitted at `Observation`) would
    // otherwise be projected verbatim into shared evidence the host never
    // enforced. The two are therefore bound to each other here, exactly like
    // the `kit.artifact_digest`/`kit.artifact_len` comparisons above: a
    // disagreement is the owned typed denial before delegation, so no engine
    // work runs. Neither value is preferred, clamped, or reconciled here — a
    // kit and an admission that disagree fail closed instead.
    if kit.proof_ceiling != admitted.proof_ceiling {
        return Err(TypedExecutionError::AdmissionMismatch(
            "proof-ceiling".to_owned(),
        ));
    }
    // Delegation re-enters the kit-less interior lane: capsule provenance is
    // consumed here and its receipt is projected at this call site below.
    let (receipt, result) = execute_domain_lane(world, artifact, limits, request, admitted)?;
    // Resolve the emitted host receipt through #760's shared contract and carry
    // it out with the host receipt it was computed from. The host receipt stays
    // the source of truth: the projection is additive fail-closed evidence,
    // never a replacement. A projection denial fails the call instead of
    // returning a receipt the shared contract rejects. The projected ceiling is
    // `kit.proof_ceiling`, which the check above proved equal to the ceiling
    // enforced on this call by `admitted.proof_ceiling`.
    let shared =
        crate::receipt_bridge::project_shared_receipt(&receipt, &kit_digest, kit.proof_ceiling)?;
    Ok((receipt, result, Some(shared)))
}

/// Digest of the admitted operation envelope plus the measured request bound.
/// The typed request is a structure, never a serialized opaque payload, so this
/// is the exact input identity the Host binds to the single call.
fn input_digest(
    world: TypedWorld,
    admitted: &TypedDomainAdmission,
    input_bytes: u64,
) -> Sha256Digest {
    let canonical = format!(
        "758-domain-input|{}|{}|{}|{}|{}|{}|{}|{input_bytes}",
        world.world_name(),
        admitted.operation_id,
        admitted.task_id,
        admitted.scope_id,
        admitted.fence_epoch,
        admitted.policy_id,
        proof_rank(admitted.proof_ceiling),
    );
    Sha256Digest::of_bytes(canonical.as_bytes())
}

/// Item-9 (#758) nested walkers for the raw typed input. One small function
/// per WIT record below the six request roots: every string leaf is bounded
/// with [`TypedBound::text`], every list (records, strings, or enums) with
/// [`TypedBound::list`], every `list<string>` with [`TypedBound::texts`].
/// Scalar, enum, and boolean fields are fixed-size and skipped. A field the
/// WIT shape does not carry cannot be observed and is not invented.
fn bound_provider_role(
    value: &crate::typed_bindings::context_admission::exports::eliot::current::admission::ProviderRole,
    bound: &mut TypedBound,
) -> Result<(), TypedExecutionError> {
    bound.text(&value.provider)?;
    bound.text(&value.role)?;
    Ok(())
}

fn bound_measurement_ref(
    value: &crate::typed_bindings::context_admission::exports::eliot::current::admission::MeasurementRef,
    bound: &mut TypedBound,
) -> Result<(), TypedExecutionError> {
    bound.text(&value.serializer)?;
    bound.text(&value.schema_revision)?;
    bound.text(&value.route)?;
    bound.text(&value.model)?;
    bound.text(&value.tokenizer)?;
    bound.text(&value.input_digest)?;
    Ok(())
}

fn bound_atom_representation(
    value: &crate::typed_bindings::context_admission::exports::eliot::current::admission::AtomRepresentation,
    bound: &mut TypedBound,
) -> Result<(), TypedExecutionError> {
    bound.text(&value.content)?;
    bound.texts(&value.manifest)?;
    bound.text(&value.source_digest)?;
    bound.text(&value.handle)?;
    Ok(())
}

fn bound_context_candidate(
    value: &crate::typed_bindings::context_admission::exports::eliot::current::admission::ContextCandidate,
    bound: &mut TypedBound,
) -> Result<(), TypedExecutionError> {
    bound.text(&value.atom_id)?;
    bound.text(&value.source_digest)?;
    bound.text(&value.source_revision)?;
    bound.text(&value.semantic_role)?;
    bound_provider_role(&value.provider_role, bound)?;
    bound_atom_representation(&value.representation, bound)?;
    bound_measurement_ref(&value.measurement, bound)?;
    bound.texts(&value.dependencies)?;
    if let Some(learning) = value.learning.as_ref() {
        bound_learning_provenance(learning, bound)?;
    }
    Ok(())
}

fn bound_learning_provenance(
    value: &crate::typed_bindings::context_admission::exports::eliot::current::admission::LearningProvenance,
    bound: &mut TypedBound,
) -> Result<(), TypedExecutionError> {
    bound.text(&value.campaign_id)?;
    if let Some(overlay) = value.overlay_id.as_ref() {
        bound.text(overlay)?;
    }
    if let Some(candidate) = value.candidate_id.as_ref() {
        bound.text(candidate)?;
    }
    if let Some(closure) = value.closure_ref.as_ref() {
        bound.text(closure)?;
    }
    if let Some(owner) = value.owner.as_ref() {
        bound.text(owner)?;
    }
    bound.text(&value.permit_digest)?;
    Ok(())
}

fn bound_context_binding(
    value: &crate::typed_bindings::context_admission::exports::eliot::current::admission::ContextBinding,
    bound: &mut TypedBound,
) -> Result<(), TypedExecutionError> {
    bound.text(&value.task_id)?;
    bound.text(&value.attempt_id)?;
    bound.text(&value.scope_id)?;
    bound.text(&value.fence_epoch)?;
    bound.text(&value.decision_id)?;
    if let Some(operation) = value.operation_id.as_ref() {
        bound.text(operation)?;
    }
    Ok(())
}

fn bound_decision_revision(
    value: &crate::typed_bindings::context_admission::exports::eliot::current::admission::DecisionRevision,
    bound: &mut TypedBound,
) -> Result<(), TypedExecutionError> {
    bound.text(&value.decision_id)?;
    bound.text(&value.recipe_revision)?;
    bound.text(&value.policy_sha256)?;
    Ok(())
}

fn bound_provider_disposition(
    value: &crate::typed_bindings::context_admission::exports::eliot::current::admission::ProviderDisposition,
    bound: &mut TypedBound,
) -> Result<(), TypedExecutionError> {
    bound_provider_role(&value.slot, bound)
}

fn bound_provider_denominator(
    value: &crate::typed_bindings::context_admission::exports::eliot::current::admission::ProviderDenominator,
    bound: &mut TypedBound,
) -> Result<(), TypedExecutionError> {
    bound.list(&value.requested)?;
    for slot in &value.requested {
        bound_provider_role(slot, bound)?;
    }
    bound.list(&value.dispositions)?;
    for disposition in &value.dispositions {
        bound_provider_disposition(disposition, bound)?;
    }
    Ok(())
}

fn bound_safety_floor_member(
    value: &crate::typed_bindings::context_admission::exports::eliot::current::admission::SafetyFloorMember,
    bound: &mut TypedBound,
) -> Result<(), TypedExecutionError> {
    bound.text(&value.atom_id)?;
    if let Some(measurement) = value.measurement.as_ref() {
        bound_measurement_ref(measurement, bound)?;
    }
    bound.texts(&value.required_dependencies)?;
    Ok(())
}

fn bound_safety_floor(
    value: &crate::typed_bindings::context_admission::exports::eliot::current::admission::SafetyFloor,
    bound: &mut TypedBound,
) -> Result<(), TypedExecutionError> {
    bound_context_binding(&value.binding, bound)?;
    bound.texts(&value.mandatory_atoms)?;
    bound.list(&value.mandatory_roles)?;
    bound_provider_denominator(&value.providers, bound)?;
    bound.list(&value.members)?;
    for member in &value.members {
        bound_safety_floor_member(member, bound)?;
    }
    bound.texts(&value.interpretation_dependencies)?;
    bound.text(&value.rule_evidence)?;
    Ok(())
}

fn bound_safety_floor_identity(
    value: &crate::typed_bindings::context_admission::exports::eliot::current::admission::SafetyFloorIdentity,
    bound: &mut TypedBound,
) -> Result<(), TypedExecutionError> {
    bound.text(&value.floor_id)?;
    bound_decision_revision(&value.decision, bound)?;
    bound_safety_floor(&value.floor, bound)?;
    Ok(())
}

fn bound_candidate_priority(
    value: &crate::typed_bindings::context_admission::exports::eliot::current::admission::CandidatePriority,
    bound: &mut TypedBound,
) -> Result<(), TypedExecutionError> {
    bound.text(&value.atom_id)?;
    Ok(())
}

fn bound_priority_policy(
    value: &crate::typed_bindings::context_admission::exports::eliot::current::admission::PriorityPolicy,
    bound: &mut TypedBound,
) -> Result<(), TypedExecutionError> {
    bound.text(&value.policy_id)?;
    bound_decision_revision(&value.decision, bound)?;
    bound.list(&value.priorities)?;
    for priority in &value.priorities {
        bound_candidate_priority(priority, bound)?;
    }
    Ok(())
}

fn bound_admission_rule(
    value: &crate::typed_bindings::context_admission::exports::eliot::current::admission::AdmissionRule,
    bound: &mut TypedBound,
) -> Result<(), TypedExecutionError> {
    bound.text(&value.rule_id)?;
    bound_decision_revision(&value.decision, bound)?;
    bound.text(&value.rule_sha256)?;
    Ok(())
}

fn bound_measurement_composition_profile(
    value: &crate::typed_bindings::context_admission::exports::eliot::current::admission::MeasurementCompositionProfile,
    bound: &mut TypedBound,
) -> Result<(), TypedExecutionError> {
    bound.text(&value.profile_id)?;
    bound.text(&value.serializer_id)?;
    bound.text(&value.serializer_version)?;
    bound.text(&value.serializer_options_digest)?;
    bound.text(&value.route_id)?;
    bound.text(&value.model_id)?;
    bound.text(&value.qualification)?;
    Ok(())
}

fn bound_tokenizer_observation(
    value: &crate::typed_bindings::context_admission::exports::eliot::current::admission::TokenizerObservation,
    bound: &mut TypedBound,
) -> Result<(), TypedExecutionError> {
    bound.text(&value.tokenizer_id)?;
    bound.text(&value.tokenizer_version)?;
    bound.text(&value.tokenizer_hash)?;
    Ok(())
}

fn bound_measured_cost(
    value: &crate::typed_bindings::context_admission::exports::eliot::current::admission::MeasuredCost,
    bound: &mut TypedBound,
) -> Result<(), TypedExecutionError> {
    use crate::typed_bindings::context_admission::exports::eliot::current::admission::MeasuredCost as C;
    // Exact bytes, the conservative estimate descriptor and the unknown /
    // unavailable markers carry no heap leaves; only a tokenizer observation
    // carries bounded strings. Zero stays the exact-bytes zero, never a
    // marker: the variants are distinct here exactly as in native
    // `AdmissionMeasuredCost`.
    match value {
        C::ExactUtf8Bytes(_) | C::ConservativeStu(_) | C::Unknown | C::Unavailable => Ok(()),
        C::ExactTokenizer(observation) => bound_tokenizer_observation(observation, bound),
    }
}

fn bound_measurement_binding(
    value: &crate::typed_bindings::context_admission::exports::eliot::current::admission::MeasurementBinding,
    bound: &mut TypedBound,
) -> Result<(), TypedExecutionError> {
    bound_context_binding(&value.context, bound)?;
    bound.text(&value.subject_digest)?;
    bound.text(&value.input_digest)?;
    bound.text(&value.output_digest)?;
    bound.text(&value.serializer_id)?;
    bound.text(&value.serializer_version)?;
    bound.text(&value.serializer_options_digest)?;
    bound.text(&value.route_id)?;
    bound.text(&value.model_id)?;
    Ok(())
}

fn bound_admission_measurement(
    value: &crate::typed_bindings::context_admission::exports::eliot::current::admission::AdmissionMeasurement,
    bound: &mut TypedBound,
) -> Result<(), TypedExecutionError> {
    bound.text(&value.measurement_id)?;
    bound.text(&value.atom_id)?;
    bound_measurement_binding(&value.binding, bound)?;
    bound_measured_cost(&value.cost, bound)?;
    if let Some(observation) = value.observation.as_ref() {
        bound_measured_cost(observation, bound)?;
    }
    Ok(())
}

fn bound_expansion_handle(
    value: &crate::typed_bindings::context_admission::exports::eliot::current::admission::ExpansionHandle,
    bound: &mut TypedBound,
) -> Result<(), TypedExecutionError> {
    bound.text(&value.atom_id)?;
    bound.text(&value.decision_digest)?;
    bound.text(&value.task_id)?;
    bound.text(&value.scope_id)?;
    bound.text(&value.fence_epoch)?;
    bound.text(&value.source_revision)?;
    bound.text(&value.handle)?;
    Ok(())
}

fn bound_supplied_omission_binding(
    value: &crate::typed_bindings::context_admission::exports::eliot::current::admission::SuppliedOmissionBinding,
    bound: &mut TypedBound,
) -> Result<(), TypedExecutionError> {
    bound.text(&value.atom_id)?;
    if let Some(expansion) = value.expansion.as_ref() {
        bound_expansion_handle(expansion, bound)?;
    }
    bound.text(&value.authorization_requirement)?;
    bound.text(&value.privacy_requirement)?;
    bound.text(&value.proof_requirement)?;
    if let Some(expires) = value.expires.as_ref() {
        bound.text(expires)?;
    }
    if let Some(invalidation) = value.invalidation.as_ref() {
        bound.text(invalidation)?;
    }
    Ok(())
}

fn bound_learning_ticket(
    value: &crate::typed_bindings::context_admission::exports::eliot::current::admission::LearningTicket,
    bound: &mut TypedBound,
) -> Result<(), TypedExecutionError> {
    bound.text(&value.source_campaign_id)?;
    bound.text(&value.target_task_id)?;
    bound.text(&value.fence_epoch)?;
    if let Some(overlay) = value.overlay_id.as_ref() {
        bound.text(overlay)?;
    }
    if let Some(candidate) = value.candidate_id.as_ref() {
        bound.text(candidate)?;
    }
    bound.text(&value.scope_ref)?;
    bound.text(&value.authority_ref)?;
    bound.text(&value.retention_ref)?;
    bound.text(&value.evaluator_ref)?;
    bound.text(&value.rollback_ref)?;
    bound.text(&value.digest)?;
    Ok(())
}

fn bound_admitted_atom_ref(
    value: &crate::typed_bindings::context_assembly::exports::eliot::current::assembly::AdmittedAtomRef,
    bound: &mut TypedBound,
) -> Result<(), TypedExecutionError> {
    bound.text(&value.atom_id)?;
    bound.text(&value.representation_digest)?;
    bound.text(&value.source_digest)?;
    Ok(())
}

fn bound_serialized_measurement(
    value: &crate::typed_bindings::context_assembly::exports::eliot::current::assembly::SerializedMeasurement,
    bound: &mut TypedBound,
) -> Result<(), TypedExecutionError> {
    bound.text(&value.serializer)?;
    bound.text(&value.schema_revision)?;
    bound.text(&value.input_digest)?;
    bound.text(&value.output_digest)?;
    Ok(())
}

fn bound_seed_cue(
    value: &crate::typed_bindings::cue_activation::exports::eliot::current::activation::SeedCue,
    bound: &mut TypedBound,
) -> Result<(), TypedExecutionError> {
    bound.text(&value.cue_id)?;
    bound.text(&value.comparison_key)?;
    bound.text(&value.normalization_profile)?;
    Ok(())
}

fn bound_relation_edge(
    value: &crate::typed_bindings::cue_activation::exports::eliot::current::activation::RelationEdge,
    bound: &mut TypedBound,
) -> Result<(), TypedExecutionError> {
    bound.text(&value.edge_id)?;
    bound.text(&value.from_handle)?;
    bound.text(&value.to_handle)?;
    Ok(())
}

fn bound_dimension_verdict(
    value: &crate::typed_bindings::dreamer_handler::exports::eliot::current::handler::DimensionVerdict,
    bound: &mut TypedBound,
) -> Result<(), TypedExecutionError> {
    bound.text(&value.note)?;
    Ok(())
}

fn bound_handler_subtype(
    value: &crate::typed_bindings::dreamer_handler::exports::eliot::current::handler::HandlerSubtype,
    bound: &mut TypedBound,
) -> Result<(), TypedExecutionError> {
    use crate::typed_bindings::dreamer_handler::exports::eliot::current::handler::HandlerSubtype as S;
    match value {
        S::Orientation(payload) => bound_orientation_payload(payload, bound),
        S::ResearchSynthesis(payload) => bound_research_payload(payload, bound),
        S::Curation(payload) => bound_curation_request_ref(payload, bound),
        S::Unsupported(payload) => bound_unsupported_subtype(payload, bound),
    }
}

fn bound_orientation_payload(
    value: &crate::typed_bindings::dreamer_handler::exports::eliot::current::handler::OrientationPayload,
    bound: &mut TypedBound,
) -> Result<(), TypedExecutionError> {
    bound.text(&value.summary)?;
    bound.texts(&value.findings)?;
    bound.texts(&value.unknowns)?;
    Ok(())
}

fn bound_research_payload(
    value: &crate::typed_bindings::dreamer_handler::exports::eliot::current::handler::ResearchPayload,
    bound: &mut TypedBound,
) -> Result<(), TypedExecutionError> {
    bound_research_pack_ref(&value.pack, bound)?;
    bound_research_brief(&value.brief, bound)?;
    Ok(())
}

fn bound_source_card(
    value: &crate::typed_bindings::dreamer_handler::exports::eliot::current::handler::SourceCard,
    bound: &mut TypedBound,
) -> Result<(), TypedExecutionError> {
    bound.text(&value.handle)?;
    bound.text(&value.competence)?;
    bound.text(&value.privacy_class)?;
    bound.text(&value.allowed_use)?;
    bound.text(&value.lineage_group)?;
    Ok(())
}

fn bound_omitted_source(
    value: &crate::typed_bindings::dreamer_handler::exports::eliot::current::handler::OmittedSource,
    bound: &mut TypedBound,
) -> Result<(), TypedExecutionError> {
    bound.text(&value.handle)?;
    bound.text(&value.reason)?;
    Ok(())
}

fn bound_research_pack_ref(
    value: &crate::typed_bindings::dreamer_handler::exports::eliot::current::handler::ResearchPackRef,
    bound: &mut TypedBound,
) -> Result<(), TypedExecutionError> {
    bound.text(&value.pack_digest)?;
    bound.text(&value.question)?;
    bound.text(&value.task_id)?;
    bound.text(&value.scope_id)?;
    bound.text(&value.fence_epoch)?;
    bound.text(&value.bundle_digest)?;
    bound.text(&value.manifest_digest)?;
    bound.list(&value.sources)?;
    for source in &value.sources {
        bound_source_card(source, bound)?;
    }
    bound.texts(&value.source_denominator)?;
    bound.texts(&value.missing_source_classes)?;
    bound.list(&value.omitted_sources)?;
    for omitted in &value.omitted_sources {
        bound_omitted_source(omitted, bound)?;
    }
    bound.texts(&value.authorized_sources)?;
    Ok(())
}

fn bound_research_claim(
    value: &crate::typed_bindings::dreamer_handler::exports::eliot::current::handler::ResearchClaim,
    bound: &mut TypedBound,
) -> Result<(), TypedExecutionError> {
    bound.text(&value.claim_id)?;
    bound.texts(&value.support)?;
    bound.texts(&value.counter_evidence)?;
    bound.texts(&value.citations)?;
    bound.texts(&value.lineage_groups)?;
    bound.texts(&value.precision_notes)?;
    bound.text(&value.absence_basis)?;
    Ok(())
}

fn bound_rival_position(
    value: &crate::typed_bindings::dreamer_handler::exports::eliot::current::handler::RivalPosition,
    bound: &mut TypedBound,
) -> Result<(), TypedExecutionError> {
    bound.text(&value.rival_id)?;
    bound.text(&value.position)?;
    bound.text(&value.target_claim)?;
    bound.texts(&value.evidence)?;
    Ok(())
}

fn bound_recommended_probe(
    value: &crate::typed_bindings::dreamer_handler::exports::eliot::current::handler::RecommendedProbe,
    bound: &mut TypedBound,
) -> Result<(), TypedExecutionError> {
    bound.text(&value.probe_id)?;
    bound.texts(&value.discriminates)?;
    bound.texts(&value.outcomes)?;
    bound.text(&value.verifier)?;
    bound.text(&value.owner)?;
    bound.text(&value.cost_class)?;
    bound.text(&value.applicability)?;
    Ok(())
}

fn bound_probe_residue(
    value: &crate::typed_bindings::dreamer_handler::exports::eliot::current::handler::ProbeResidue,
    bound: &mut TypedBound,
) -> Result<(), TypedExecutionError> {
    bound.text(&value.probe_id)?;
    bound.text(&value.detail)?;
    Ok(())
}

fn bound_dependence_group(
    value: &crate::typed_bindings::dreamer_handler::exports::eliot::current::handler::DependenceGroup,
    bound: &mut TypedBound,
) -> Result<(), TypedExecutionError> {
    bound.text(&value.lineage_group)?;
    bound.texts(&value.members)?;
    Ok(())
}

fn bound_concilium_recommendation(
    value: &crate::typed_bindings::dreamer_handler::exports::eliot::current::handler::ConciliumRecommendation,
    bound: &mut TypedBound,
) -> Result<(), TypedExecutionError> {
    bound.text(&value.owner)?;
    bound.texts(&value.evidence_refs)?;
    bound.texts(&value.positions)?;
    bound.text(&value.review_objective)?;
    Ok(())
}

fn bound_coverage_report(
    value: &crate::typed_bindings::dreamer_handler::exports::eliot::current::handler::CoverageReport,
    bound: &mut TypedBound,
) -> Result<(), TypedExecutionError> {
    bound.texts(&value.missing_classes)?;
    bound.list(&value.omitted_sources)?;
    for omitted in &value.omitted_sources {
        bound_omitted_source(omitted, bound)?;
    }
    bound.texts(&value.represented_sources)?;
    bound.texts(&value.cited_sources)?;
    Ok(())
}

fn bound_brief_omission(
    value: &crate::typed_bindings::dreamer_handler::exports::eliot::current::handler::BriefOmission,
    bound: &mut TypedBound,
) -> Result<(), TypedExecutionError> {
    bound.text(&value.detail)?;
    Ok(())
}

fn bound_preservation_verdict(
    value: &crate::typed_bindings::dreamer_handler::exports::eliot::current::handler::PreservationVerdict,
    bound: &mut TypedBound,
) -> Result<(), TypedExecutionError> {
    bound.text(&value.note)?;
    Ok(())
}

fn bound_research_brief(
    value: &crate::typed_bindings::dreamer_handler::exports::eliot::current::handler::ResearchBrief,
    bound: &mut TypedBound,
) -> Result<(), TypedExecutionError> {
    bound.text(&value.brief_id)?;
    bound_research_pack_ref(&value.pack, bound)?;
    bound.text(&value.pack_digest)?;
    bound.text(&value.question)?;
    bound.list(&value.claims)?;
    for claim in &value.claims {
        bound_research_claim(claim, bound)?;
    }
    bound.list(&value.rivals)?;
    for rival in &value.rivals {
        bound_rival_position(rival, bound)?;
    }
    bound.texts(&value.unknowns)?;
    bound.list(&value.probes)?;
    for probe in &value.probes {
        bound_recommended_probe(probe, bound)?;
    }
    bound.list(&value.probe_residue)?;
    for residue in &value.probe_residue {
        bound_probe_residue(residue, bound)?;
    }
    bound_concilium_recommendation(&value.concilium, bound)?;
    bound_coverage_report(&value.coverage, bound)?;
    bound.list(&value.dependence)?;
    for group in &value.dependence {
        bound_dependence_group(group, bound)?;
    }
    bound.list(&value.preservation)?;
    for verdict in &value.preservation {
        bound_preservation_verdict(verdict, bound)?;
    }
    bound.list(&value.omitted)?;
    for omission in &value.omitted {
        bound_brief_omission(omission, bound)?;
    }
    bound.text(&value.raw_digest)?;
    bound.text(&value.semantic_digest)?;
    Ok(())
}

fn bound_classification_payload(
    value: &crate::typed_bindings::dreamer_handler::exports::eliot::current::handler::ClassificationPayload,
    bound: &mut TypedBound,
) -> Result<(), TypedExecutionError> {
    bound.text(&value.label)?;
    bound.texts(&value.targets)?;
    bound.texts(&value.evidence_refs)?;
    Ok(())
}

fn bound_relation_payload(
    value: &crate::typed_bindings::dreamer_handler::exports::eliot::current::handler::RelationPayload,
    bound: &mut TypedBound,
) -> Result<(), TypedExecutionError> {
    bound.text(&value.from_handle)?;
    bound.text(&value.to_handle)?;
    bound.text(&value.predicate)?;
    bound.texts(&value.evidence_refs)?;
    Ok(())
}

fn bound_generic_curation_payload(
    value: &crate::typed_bindings::dreamer_handler::exports::eliot::current::handler::GenericCurationPayload,
    bound: &mut TypedBound,
) -> Result<(), TypedExecutionError> {
    bound.texts(&value.targets)?;
    bound.texts(&value.evidence_refs)?;
    bound.text(&value.note)?;
    Ok(())
}

fn bound_curation_payload(
    value: &crate::typed_bindings::dreamer_handler::exports::eliot::current::handler::CurationPayload,
    bound: &mut TypedBound,
) -> Result<(), TypedExecutionError> {
    use crate::typed_bindings::dreamer_handler::exports::eliot::current::handler::CurationPayload as P;
    match value {
        P::Classification(payload) => bound_classification_payload(payload, bound),
        P::Relation(payload) => bound_relation_payload(payload, bound),
        P::Generic(payload) => bound_generic_curation_payload(payload, bound),
    }
}

fn bound_curation_request_ref(
    value: &crate::typed_bindings::dreamer_handler::exports::eliot::current::handler::CurationRequestRef,
    bound: &mut TypedBound,
) -> Result<(), TypedExecutionError> {
    bound.list(&value.kinds)?;
    bound.text(&value.handler_id)?;
    bound.text(&value.registry_digest)?;
    bound_curation_payload(&value.payload, bound)?;
    Ok(())
}

fn bound_unsupported_subtype(
    value: &crate::typed_bindings::dreamer_handler::exports::eliot::current::handler::UnsupportedSubtype,
    bound: &mut TypedBound,
) -> Result<(), TypedExecutionError> {
    bound.text(&value.want_kind)?;
    bound.text(&value.human_detail)?;
    Ok(())
}

fn bound_source_member(
    value: &crate::typed_bindings::memory_curation_screen::exports::eliot::current::screen::SourceMember,
    bound: &mut TypedBound,
) -> Result<(), TypedExecutionError> {
    bound.text(&value.member_id)?;
    bound.texts(&value.provenance)?;
    bound.texts(&value.conflict)?;
    Ok(())
}

fn bound_pending_request(
    value: &crate::typed_bindings::dreamer_cycle::exports::eliot::current::cycle::PendingRequest,
    bound: &mut TypedBound,
) -> Result<(), TypedExecutionError> {
    bound.text(&value.request_id)?;
    bound.text(&value.operation_id)?;
    bound.text(&value.idempotency_key)?;
    Ok(())
}

fn bound_observed_outcome(
    value: &crate::typed_bindings::dreamer_cycle::exports::eliot::current::cycle::ObservedOutcome,
    bound: &mut TypedBound,
) -> Result<(), TypedExecutionError> {
    bound.text(&value.request_id)?;
    bound.text(&value.operation_id)?;
    bound.text(&value.evidence_digest)?;
    Ok(())
}

fn bound_dreamer_state(
    value: &crate::typed_bindings::dreamer_cycle::exports::eliot::current::cycle::DreamerState,
    bound: &mut TypedBound,
) -> Result<(), TypedExecutionError> {
    bound.text(&value.state_digest)?;
    bound.text(&value.fence_epoch)?;
    bound.list(&value.pending)?;
    for pending in &value.pending {
        bound_pending_request(pending, bound)?;
    }
    bound.list(&value.observed)?;
    for observed in &value.observed {
        bound_observed_outcome(observed, bound)?;
    }
    Ok(())
}

/// Pre-lift bound of the raw typed input. The request arrives as generated
/// WIT types: the CLI takes no serialized fixture on this path, so there is
/// no outer JSON/string/tree format to mistake for an opaque WIT ABI escape
/// (P3.4, #758). Every string/list leaf below — top-level fields, nested
/// records, list elements, and optional strings — is measured here, before
/// the host lowers any of it into guest memory; the total is then checked
/// against the admitted input ceiling by the caller (item 9, #758). Scalar,
/// enum, and boolean leaves carry no heap allocation and need no bound.
fn bound_request(
    world: TypedWorld,
    request: &TypedDomainRequest,
    admitted: &TypedDomainAdmission,
    bound: &mut TypedBound,
) -> Result<(), TypedExecutionError> {
    match (world, request) {
        (TypedWorld::ContextAdmission, TypedDomainRequest::Admission(value)) => {
            bound_admission_request(value, admitted, bound)
        }
        (TypedWorld::ContextAssembly, TypedDomainRequest::Assembly(value)) => {
            bound_assembly_request(value, admitted, bound)
        }
        (TypedWorld::CueActivation, TypedDomainRequest::CueActivation(value)) => {
            bound_cue_activation_request(value, admitted, bound)
        }
        (TypedWorld::DreamerHandler, TypedDomainRequest::DreamerHandler(value)) => {
            bound_dreamer_handler_request(value, admitted, bound)
        }
        (TypedWorld::MemoryCurationScreen, TypedDomainRequest::MemoryCurationScreen(value)) => {
            bound_memory_curation_screen_request(value, admitted, bound)
        }
        (TypedWorld::DreamerCycle, TypedDomainRequest::DreamerCycle(value)) => {
            bound_dreamer_cycle_request(value, admitted, bound)
        }
        // `TypedDomainRequest::world()` was compared with the selection above,
        // so no unhandled pairing reaches this point.
        _ => Err(TypedExecutionError::WorldSelection {
            reason: "request-world".to_owned(),
        }),
    }
}

/// Production caller for the audit-5884499327 admission closure: walks
/// every heap leaf of `wit/typed/context-admission.wit::record
/// admission-request` — binding, candidates, floor with member
/// dependencies, priority policy, admission rule, measurement-composition
/// profile, supplied omission bindings, full typed measurements with
/// measured cost, and learning tickets — into the pre-lift bound checked
/// by [`execute_domain_experimental`]. Boring adapter only (I2.19):
/// leaves are measured, never interpreted; scalar/enum leaves carry no
/// heap and need no bound. Removing or renaming a walked WIT field breaks
/// this production path, not just the contract suite.
fn bound_admission_request(
    value: &crate::typed_bindings::context_admission::exports::eliot::current::admission::AdmissionRequest,
    admitted: &TypedDomainAdmission,
    bound: &mut TypedBound,
) -> Result<(), TypedExecutionError> {
    check_echo(&value.operation_id, &admitted.operation_id, "operation-id")?;
    check_echo(&value.task_id, &admitted.task_id, "task-id")?;
    check_echo(&value.scope_id, &admitted.scope_id, "scope-id")?;
    check_echo(&value.fence_epoch, &admitted.fence_epoch, "fence-epoch")?;
    bound.text(&value.operation_id)?;
    bound.text(&value.task_id)?;
    bound.text(&value.attempt_id)?;
    bound.text(&value.scope_id)?;
    bound.text(&value.fence_epoch)?;
    bound_context_binding(&value.binding, bound)?;
    bound.list(&value.candidates)?;
    for candidate in &value.candidates {
        bound_context_candidate(candidate, bound)?;
    }
    bound.text(&value.recipe_digest)?;
    bound.text(&value.recipe_revision)?;
    bound.list(&value.provider_denominator)?;
    for slot in &value.provider_denominator {
        bound_provider_role(slot, bound)?;
    }
    bound_safety_floor_identity(&value.floor, bound)?;
    bound_priority_policy(&value.priority, bound)?;
    bound_admission_rule(&value.rule, bound)?;
    bound_measurement_composition_profile(&value.measurement_profile, bound)?;
    bound.list(&value.supplied_omissions)?;
    for supplied in &value.supplied_omissions {
        bound_supplied_omission_binding(supplied, bound)?;
    }
    bound.list(&value.measurements)?;
    for measurement in &value.measurements {
        bound_admission_measurement(measurement, bound)?;
    }
    bound.list(&value.learning_tickets)?;
    for ticket in &value.learning_tickets {
        bound_learning_ticket(ticket, bound)?;
    }
    if let Some(digest) = value.predecessor_digest.as_ref() {
        bound.text(digest)?;
    }
    if let Some(note) = value.invalidation.as_ref() {
        bound.text(note)?;
    }
    Ok(())
}

fn bound_assembly_request(
    value: &crate::typed_bindings::context_assembly::exports::eliot::current::assembly::AssemblyRequest,
    admitted: &TypedDomainAdmission,
    bound: &mut TypedBound,
) -> Result<(), TypedExecutionError> {
    check_echo(&value.operation_id, &admitted.operation_id, "operation-id")?;
    check_echo(&value.task_id, &admitted.task_id, "task-id")?;
    check_echo(&value.scope_id, &admitted.scope_id, "scope-id")?;
    check_echo(&value.fence_epoch, &admitted.fence_epoch, "fence-epoch")?;
    bound.text(&value.operation_id)?;
    bound.text(&value.task_id)?;
    bound.text(&value.scope_id)?;
    bound.text(&value.fence_epoch)?;
    bound.text(&value.admitted_digest)?;
    bound.text(&value.recipe_digest)?;
    bound.list(&value.admitted)?;
    for atom in &value.admitted {
        bound_admitted_atom_ref(atom, bound)?;
    }
    bound_serialized_measurement(&value.measurement, bound)?;
    if let Some(digest) = value.predecessor_digest.as_ref() {
        bound.text(digest)?;
    }
    Ok(())
}

fn bound_cue_activation_request(
    value: &crate::typed_bindings::cue_activation::exports::eliot::current::activation::ActivationRequest,
    admitted: &TypedDomainAdmission,
    bound: &mut TypedBound,
) -> Result<(), TypedExecutionError> {
    // The activation world carries no task/scope field; its echoed
    // operation identity is the WIT `request-id`.
    check_echo(&value.request_id, &admitted.operation_id, "operation-id")?;
    check_echo(&value.fence_epoch, &admitted.fence_epoch, "fence-epoch")?;
    bound.text(&value.request_id)?;
    bound.text(&value.snapshot_id)?;
    bound.text(&value.fence_epoch)?;
    bound.text(&value.normalization_profile)?;
    bound.list(&value.seeds)?;
    for seed in &value.seeds {
        bound_seed_cue(seed, bound)?;
    }
    bound.list(&value.relation_edges)?;
    for edge in &value.relation_edges {
        bound_relation_edge(edge, bound)?;
    }
    Ok(())
}

fn bound_dreamer_handler_request(
    value: &crate::typed_bindings::dreamer_handler::exports::eliot::current::handler::ValidatedCandidate,
    admitted: &TypedDomainAdmission,
    bound: &mut TypedBound,
) -> Result<(), TypedExecutionError> {
    check_echo(&value.operation_id, &admitted.operation_id, "operation-id")?;
    check_echo(&value.task_id, &admitted.task_id, "task-id")?;
    check_echo(&value.scope_id, &admitted.scope_id, "scope-id")?;
    check_echo(&value.fence_epoch, &admitted.fence_epoch, "fence-epoch")?;
    bound.text(&value.operation_id)?;
    bound.text(&value.task_id)?;
    bound.text(&value.attempt_id)?;
    bound.text(&value.scope_id)?;
    bound.text(&value.fence_epoch)?;
    bound.text(&value.bundle_digest)?;
    bound.text(&value.manifest_digest)?;
    bound.text(&value.grounding_digest)?;
    bound.text(&value.validation_receipt)?;
    bound.text(&value.requester.principal)?;
    bound.text(&value.requester.session)?;
    bound.list(&value.preservation.verdicts)?;
    for verdict in &value.preservation.verdicts {
        bound_dimension_verdict(verdict, bound)?;
    }
    bound_handler_subtype(&value.subtype, bound)?;
    Ok(())
}

fn bound_memory_curation_screen_request(
    value: &crate::typed_bindings::memory_curation_screen::exports::eliot::current::screen::ScreenRequest,
    admitted: &TypedDomainAdmission,
    bound: &mut TypedBound,
) -> Result<(), TypedExecutionError> {
    check_echo(&value.operation_id, &admitted.operation_id, "operation-id")?;
    check_echo(&value.task_id, &admitted.task_id, "task-id")?;
    check_echo(&value.scope_id, &admitted.scope_id, "scope-id")?;
    check_echo(&value.fence_epoch, &admitted.fence_epoch, "fence-epoch")?;
    bound.text(&value.operation_id)?;
    bound.text(&value.task_id)?;
    bound.text(&value.scope_id)?;
    bound.text(&value.fence_epoch)?;
    bound.text(&value.source_id)?;
    bound.text(&value.snapshot_revision)?;
    bound.text(&value.profile_id)?;
    bound.list(&value.members)?;
    for member in &value.members {
        bound_source_member(member, bound)?;
    }
    bound.texts(&value.rule_ids)?;
    if let Some(digest) = value.predecessor_digest.as_ref() {
        bound.text(digest)?;
    }
    Ok(())
}

fn bound_dreamer_cycle_request(
    value: &crate::typed_bindings::dreamer_cycle::exports::eliot::current::cycle::CycleStepInput,
    admitted: &TypedDomainAdmission,
    bound: &mut TypedBound,
) -> Result<(), TypedExecutionError> {
    check_echo(&value.operation_id, &admitted.operation_id, "operation-id")?;
    check_echo(&value.task_id, &admitted.task_id, "task-id")?;
    check_echo(&value.scope_id, &admitted.scope_id, "scope-id")?;
    check_echo(&value.fence_epoch, &admitted.fence_epoch, "fence-epoch")?;
    bound.text(&value.operation_id)?;
    bound.text(&value.task_id)?;
    bound.text(&value.scope_id)?;
    bound.text(&value.fence_epoch)?;
    bound.text(&value.policy.policy_revision)?;
    bound_dreamer_state(&value.state, bound)?;
    if let Some(digest) = value.predecessor_digest.as_ref() {
        bound.text(digest)?;
    }
    Ok(())
}

const fn ceiling_admission(
    value: crate::typed_bindings::context_admission::exports::eliot::current::admission::ProofCeiling,
) -> u8 {
    use crate::typed_bindings::context_admission::exports::eliot::current::admission::ProofCeiling as V;
    match value {
        V::Observation => 0,
        V::CandidateOnly => 1,
        V::Admission => 2,
        V::Assembly => 3,
        V::Activation => 4,
        V::Screen => 5,
        V::Cycle => 6,
        V::Handler => 7,
    }
}

const fn ceiling_assembly(
    value: crate::typed_bindings::context_assembly::exports::eliot::current::assembly::ProofCeiling,
) -> u8 {
    use crate::typed_bindings::context_assembly::exports::eliot::current::assembly::ProofCeiling as V;
    match value {
        V::Observation => 0,
        V::CandidateOnly => 1,
        V::Admission => 2,
        V::Assembly => 3,
        V::Activation => 4,
        V::Screen => 5,
        V::Cycle => 6,
        V::Handler => 7,
    }
}

const fn ceiling_activation(
    value: crate::typed_bindings::cue_activation::exports::eliot::current::activation::ProofCeiling,
) -> u8 {
    use crate::typed_bindings::cue_activation::exports::eliot::current::activation::ProofCeiling as V;
    match value {
        V::Observation => 0,
        V::CandidateOnly => 1,
        V::Admission => 2,
        V::Assembly => 3,
        V::Activation => 4,
        V::Screen => 5,
        V::Cycle => 6,
        V::Handler => 7,
    }
}

const fn ceiling_handler(
    value: crate::typed_bindings::dreamer_handler::exports::eliot::current::handler::ProofCeiling,
) -> u8 {
    use crate::typed_bindings::dreamer_handler::exports::eliot::current::handler::ProofCeiling as V;
    match value {
        V::Observation => 0,
        V::CandidateOnly => 1,
        V::Admission => 2,
        V::Assembly => 3,
        V::Activation => 4,
        V::Screen => 5,
        V::Cycle => 6,
        V::Handler => 7,
    }
}

const fn ceiling_screen(
    value: crate::typed_bindings::memory_curation_screen::exports::eliot::current::screen::ProofCeiling,
) -> u8 {
    use crate::typed_bindings::memory_curation_screen::exports::eliot::current::screen::ProofCeiling as V;
    match value {
        V::Observation => 0,
        V::CandidateOnly => 1,
        V::Admission => 2,
        V::Assembly => 3,
        V::Activation => 4,
        V::Screen => 5,
        V::Cycle => 6,
        V::Handler => 7,
    }
}

const fn ceiling_cycle(
    value: crate::typed_bindings::dreamer_cycle::exports::eliot::current::cycle::ProofCeiling,
) -> u8 {
    use crate::typed_bindings::dreamer_cycle::exports::eliot::current::cycle::ProofCeiling as V;
    match value {
        V::Observation => 0,
        V::CandidateOnly => 1,
        V::Admission => 2,
        V::Assembly => 3,
        V::Activation => 4,
        V::Screen => 5,
        V::Cycle => 6,
        V::Handler => 7,
    }
}

/// Rejects a domain result that carries a foreign operation/task/scope/fence,
/// raises the admitted proof ceiling, or exceeds the admitted output bound.
/// Only the identity fields the world's own result record echoes are compared;
/// a field the WIT result does not echo cannot be observed and is not invented.
fn check_result(
    result: &TypedDomainResult,
    admitted: &TypedDomainAdmission,
    bound: &mut TypedBound,
) -> Result<(), TypedExecutionError> {
    match result {
        TypedDomainResult::Outcome(outcome) => match outcome.as_ref() {
            TypedDomainOutcome::Admission(value) => check_admission_result(value, admitted, bound),
            TypedDomainOutcome::Assembly(value) => check_assembly_result(value, admitted, bound),
            TypedDomainOutcome::CueActivation(value) => {
                check_activation_result(value, admitted, bound)
            }
            TypedDomainOutcome::DreamerHandler(value) => {
                check_handler_result(value, admitted, bound)
            }
            TypedDomainOutcome::MemoryCurationScreen(value) => {
                check_screen_result(value, admitted, bound)
            }
            TypedDomainOutcome::DreamerCycle(value) => check_cycle_result(value, admitted, bound),
        },
        // A guest's own typed error carries no outcome identity and no proof
        // ceiling to compare; it is retained verbatim as the terminal result.
        TypedDomainResult::GuestError(_) => Ok(()),
    }
}

fn check_admission_result(
    value: &crate::typed_bindings::context_admission::exports::eliot::current::admission::AdmissionResult,
    admitted: &TypedDomainAdmission,
    bound: &mut TypedBound,
) -> Result<(), TypedExecutionError> {
    use crate::typed_bindings::context_admission::exports::eliot::current::admission::AdmissionResult as R;
    match value {
        R::Admitted(set) => {
            check_echo(&set.operation_id, &admitted.operation_id, "operation-id")?;
            check_echo(&set.task_id, &admitted.task_id, "task-id")?;
            check_echo(&set.scope_id, &admitted.scope_id, "scope-id")?;
            check_echo(&set.fence_epoch, &admitted.fence_epoch, "fence-epoch")?;
            check_ceiling(
                ceiling_admission(set.proof_ceiling),
                admitted.proof_ceiling,
                "proof-ceiling",
            )?;
            bound.text(&set.operation_id)?;
            bound.text(&set.task_id)?;
            bound.text(&set.attempt_id)?;
            bound.text(&set.scope_id)?;
            bound.text(&set.fence_epoch)?;
            bound.text(&set.recipe_digest)?;
            bound.text(&set.recipe_revision)?;
            bound.text(&set.canonical_digest)?;
            bound.list(&set.members)?;
            bound.list(&set.dispositions)?;
            bound.list(&set.omissions)?;
            bound.list(&set.frontier)?;
        }
        R::Incomplete(incomplete) => {
            check_ceiling(
                ceiling_admission(incomplete.proof_ceiling),
                admitted.proof_ceiling,
                "proof-ceiling",
            )?;
            bound.text(&incomplete.failed_floor_rule)?;
            bound.list(&incomplete.missing)?;
            bound.list(&incomplete.stale)?;
            bound.list(&incomplete.blocked)?;
            bound.list(&incomplete.unavailable)?;
            bound.list(&incomplete.omitted)?;
            bound.list(&incomplete.exhausted)?;
            bound.list(&incomplete.unknown)?;
            bound.list(&incomplete.known_empty)?;
            bound.list(&incomplete.partial)?;
            bound.list(&incomplete.provider_gaps)?;
            bound.list(&incomplete.oversized)?;
            bound.list(&incomplete.measurements)?;
            bound.list(&incomplete.reopening_requirements)?;
        }
    }
    Ok(())
}

fn check_assembly_result(
    value: &crate::typed_bindings::context_assembly::exports::eliot::current::assembly::AssemblyResult,
    admitted: &TypedDomainAdmission,
    bound: &mut TypedBound,
) -> Result<(), TypedExecutionError> {
    use crate::typed_bindings::context_assembly::exports::eliot::current::assembly::AssemblyResult as R;
    let R::Assembled(view) = value;
    check_echo(&view.operation_id, &admitted.operation_id, "operation-id")?;
    check_echo(&view.task_id, &admitted.task_id, "task-id")?;
    check_echo(&view.scope_id, &admitted.scope_id, "scope-id")?;
    check_echo(&view.fence_epoch, &admitted.fence_epoch, "fence-epoch")?;
    check_ceiling(
        ceiling_assembly(view.proof_ceiling),
        admitted.proof_ceiling,
        "proof-ceiling",
    )?;
    check_ceiling(
        ceiling_assembly(view.measurement.proof_ceiling),
        admitted.proof_ceiling,
        "proof-ceiling",
    )?;
    bound.text(&view.operation_id)?;
    bound.text(&view.task_id)?;
    bound.text(&view.scope_id)?;
    bound.text(&view.fence_epoch)?;
    bound.text(&view.admitted_digest)?;
    bound.text(&view.canonical_digest)?;
    bound.text(&view.measurement.serializer)?;
    bound.text(&view.measurement.schema_revision)?;
    bound.text(&view.measurement.input_digest)?;
    bound.text(&view.measurement.output_digest)?;
    bound.list(&view.members)?;
    bound.list(&view.quality.results)?;
    bound.list(&view.omission_evidence)?;
    bound.list(&view.frontier)?;
    Ok(())
}

fn check_activation_result(
    value: &crate::typed_bindings::cue_activation::exports::eliot::current::activation::ActivationOutcome,
    admitted: &TypedDomainAdmission,
    bound: &mut TypedBound,
) -> Result<(), TypedExecutionError> {
    use crate::typed_bindings::cue_activation::exports::eliot::current::activation::ActivationOutcome as R;
    // The activation world carries no task/scope field; its echoed operation
    // identity is the WIT `request-id`.
    let R::Activated(body) = value;
    check_echo(&body.request_id, &admitted.operation_id, "operation-id")?;
    check_ceiling(
        ceiling_activation(body.proof_ceiling),
        admitted.proof_ceiling,
        "proof-ceiling",
    )?;
    bound.text(&body.request_id)?;
    bound.text(&body.snapshot_id)?;
    bound.text(&body.result_digest)?;
    bound.list(&body.direct)?;
    bound.list(&body.derived)?;
    bound.list(&body.trace.steps)?;
    bound.list(&body.frontier)?;
    Ok(())
}

fn check_handler_result(
    value: &crate::typed_bindings::dreamer_handler::exports::eliot::current::handler::HandlerOutcome,
    admitted: &TypedDomainAdmission,
    bound: &mut TypedBound,
) -> Result<(), TypedExecutionError> {
    use crate::typed_bindings::dreamer_handler::exports::eliot::current::handler::HandlerOutcome as R;
    let R::Handled(body) = value;
    check_echo(&body.operation_id, &admitted.operation_id, "operation-id")?;
    check_ceiling(
        ceiling_handler(body.proof_ceiling),
        admitted.proof_ceiling,
        "proof-ceiling",
    )?;
    bound.text(&body.operation_id)?;
    bound.text(&body.output_digest)?;
    bound.list(&body.frontier)?;
    bound.list(&body.preservation.verdicts)?;
    Ok(())
}

fn check_screen_result(
    value: &crate::typed_bindings::memory_curation_screen::exports::eliot::current::screen::ScreenOutcome,
    admitted: &TypedDomainAdmission,
    bound: &mut TypedBound,
) -> Result<(), TypedExecutionError> {
    use crate::typed_bindings::memory_curation_screen::exports::eliot::current::screen::ScreenOutcome as R;
    let R::Screened(body) = value;
    check_echo(&body.operation_id, &admitted.operation_id, "operation-id")?;
    check_echo(&body.task_id, &admitted.task_id, "task-id")?;
    check_echo(&body.scope_id, &admitted.scope_id, "scope-id")?;
    check_echo(&body.fence_epoch, &admitted.fence_epoch, "fence-epoch")?;
    check_ceiling(
        ceiling_screen(body.proof_ceiling),
        admitted.proof_ceiling,
        "proof-ceiling",
    )?;
    bound.text(&body.operation_id)?;
    bound.text(&body.task_id)?;
    bound.text(&body.scope_id)?;
    bound.text(&body.fence_epoch)?;
    bound.text(&body.result_digest)?;
    bound.list(&body.protection)?;
    bound.list(&body.findings)?;
    Ok(())
}

fn check_cycle_result(
    value: &crate::typed_bindings::dreamer_cycle::exports::eliot::current::cycle::CycleOutcome,
    admitted: &TypedDomainAdmission,
    bound: &mut TypedBound,
) -> Result<(), TypedExecutionError> {
    use crate::typed_bindings::dreamer_cycle::exports::eliot::current::cycle::CycleOutcome as R;
    let R::Stepped(body) = value;
    check_echo(&body.operation_id, &admitted.operation_id, "operation-id")?;
    check_echo(
        &body.state.fence_epoch,
        &admitted.fence_epoch,
        "fence-epoch",
    )?;
    check_ceiling(
        ceiling_cycle(body.proof_ceiling),
        admitted.proof_ceiling,
        "proof-ceiling",
    )?;
    bound.text(&body.operation_id)?;
    bound.text(&body.state.state_digest)?;
    bound.text(&body.state.fence_epoch)?;
    bound.text(&body.result_digest)?;
    bound.list(&body.state.pending)?;
    bound.list(&body.state.observed)?;
    bound.list(&body.emitted)?;
    bound.list(&body.frontier)?;
    Ok(())
}

fn dispatch_domain(
    world: TypedWorld,
    engine: &wasmtime::Engine,
    component: &wasmtime::component::Component,
    limits: &InvocationLimits,
    request: &TypedDomainRequest,
) -> Result<(TypedDescriptor, TypedDomainResult, ObservedUsage), TypedExecutionError> {
    match (world, request) {
        (TypedWorld::ContextAdmission, TypedDomainRequest::Admission(value)) => {
            let ((descriptor, result), usage) = call_admission(engine, component, limits, value)?;
            Ok((descriptor, result, usage))
        }
        (TypedWorld::ContextAssembly, TypedDomainRequest::Assembly(value)) => {
            let ((descriptor, result), usage) = call_assembly(engine, component, limits, value)?;
            Ok((descriptor, result, usage))
        }
        (TypedWorld::CueActivation, TypedDomainRequest::CueActivation(value)) => {
            let ((descriptor, result), usage) =
                call_cue_activation(engine, component, limits, value)?;
            Ok((descriptor, result, usage))
        }
        (TypedWorld::DreamerHandler, TypedDomainRequest::DreamerHandler(value)) => {
            let ((descriptor, result), usage) =
                call_dreamer_handler(engine, component, limits, value)?;
            Ok((descriptor, result, usage))
        }
        (TypedWorld::MemoryCurationScreen, TypedDomainRequest::MemoryCurationScreen(value)) => {
            let ((descriptor, result), usage) =
                call_memory_curation_screen(engine, component, limits, value)?;
            Ok((descriptor, result, usage))
        }
        (TypedWorld::DreamerCycle, TypedDomainRequest::DreamerCycle(value)) => {
            let ((descriptor, result), usage) =
                call_dreamer_cycle(engine, component, limits, value)?;
            Ok((descriptor, result, usage))
        }
        _ => Err(TypedExecutionError::WorldSelection {
            reason: "request-world".to_owned(),
        }),
    }
}

fn call_admission(
    engine: &wasmtime::Engine,
    component: &wasmtime::component::Component,
    limits: &InvocationLimits,
    request: &crate::typed_bindings::context_admission::exports::eliot::current::admission::AdmissionRequest,
) -> Result<((TypedDescriptor, TypedDomainResult), ObservedUsage), TypedExecutionError> {
    use crate::typed_bindings::context_admission::ContextAdmission;
    run_guarded(engine, limits, |store| {
        let linker = wasmtime::component::Linker::new(engine);
        let instance =
            ContextAdmission::instantiate(&mut *store, component, &linker).map_err(|error| {
                staged(
                    TypedStage::Instantiate,
                    map_instantiate_error(&error, store.data().limit_hit),
                )
            })?;
        let interface = instance.eliot_current_admission();
        let raw = interface.call_describe(&mut *store).map_err(|error| {
            staged(
                TypedStage::Descriptor,
                map_call_error("describe", &error, store.data().limit_hit),
            )
        })?;
        let descriptor = TypedDescriptor {
            world_name: raw.world_name,
            package_id: raw.package_id,
            abi_revision: raw.abi_revision,
            native_contract: raw.native_contract,
            native_revision: raw.native_revision,
            abi_digest: raw.abi_digest,
        };
        // P5.5 (#758): deny a lying descriptor before the domain export runs.
        validate_descriptor(
            TypedWorld::ContextAdmission,
            &descriptor,
            limits.max_output_bytes,
        )
        .map_err(|error| staged(TypedStage::Descriptor, error))?;
        validate_descriptor_abi_digest(&descriptor)
            .map_err(|error| staged(TypedStage::Descriptor, error))?;
        let called = interface
            .call_admit(&mut *store, request)
            .map_err(|error| {
                staged(
                    TypedStage::Invoke,
                    map_call_error("admit", &error, store.data().limit_hit),
                )
            })?;
        let domain = match called {
            Ok(value) => {
                TypedDomainResult::Outcome(Box::new(TypedDomainOutcome::Admission(Box::new(value))))
            }
            Err(error) => TypedDomainResult::GuestError(Box::new(TypedDomainError::Admission(
                Box::new(error),
            ))),
        };
        Ok((descriptor, domain))
    })
}

fn call_assembly(
    engine: &wasmtime::Engine,
    component: &wasmtime::component::Component,
    limits: &InvocationLimits,
    request: &crate::typed_bindings::context_assembly::exports::eliot::current::assembly::AssemblyRequest,
) -> Result<((TypedDescriptor, TypedDomainResult), ObservedUsage), TypedExecutionError> {
    use crate::typed_bindings::context_assembly::ContextAssembly;
    run_guarded(engine, limits, |store| {
        let linker = wasmtime::component::Linker::new(engine);
        let instance =
            ContextAssembly::instantiate(&mut *store, component, &linker).map_err(|error| {
                staged(
                    TypedStage::Instantiate,
                    map_instantiate_error(&error, store.data().limit_hit),
                )
            })?;
        let interface = instance.eliot_current_assembly();
        let raw = interface.call_describe(&mut *store).map_err(|error| {
            staged(
                TypedStage::Descriptor,
                map_call_error("describe", &error, store.data().limit_hit),
            )
        })?;
        let descriptor = TypedDescriptor {
            world_name: raw.world_name,
            package_id: raw.package_id,
            abi_revision: raw.abi_revision,
            native_contract: raw.native_contract,
            native_revision: raw.native_revision,
            abi_digest: raw.abi_digest,
        };
        // P5.5 (#758): deny a lying descriptor before the domain export runs.
        validate_descriptor(
            TypedWorld::ContextAssembly,
            &descriptor,
            limits.max_output_bytes,
        )
        .map_err(|error| staged(TypedStage::Descriptor, error))?;
        validate_descriptor_abi_digest(&descriptor)
            .map_err(|error| staged(TypedStage::Descriptor, error))?;
        let called = interface
            .call_assemble(&mut *store, request)
            .map_err(|error| {
                staged(
                    TypedStage::Invoke,
                    map_call_error("assemble", &error, store.data().limit_hit),
                )
            })?;
        let domain = match called {
            Ok(value) => {
                TypedDomainResult::Outcome(Box::new(TypedDomainOutcome::Assembly(Box::new(value))))
            }
            Err(error) => {
                TypedDomainResult::GuestError(Box::new(TypedDomainError::Assembly(Box::new(error))))
            }
        };
        Ok((descriptor, domain))
    })
}

fn call_cue_activation(
    engine: &wasmtime::Engine,
    component: &wasmtime::component::Component,
    limits: &InvocationLimits,
    request: &crate::typed_bindings::cue_activation::exports::eliot::current::activation::ActivationRequest,
) -> Result<((TypedDescriptor, TypedDomainResult), ObservedUsage), TypedExecutionError> {
    use crate::typed_bindings::cue_activation::CueActivation;
    run_guarded(engine, limits, |store| {
        let linker = wasmtime::component::Linker::new(engine);
        let instance =
            CueActivation::instantiate(&mut *store, component, &linker).map_err(|error| {
                staged(
                    TypedStage::Instantiate,
                    map_instantiate_error(&error, store.data().limit_hit),
                )
            })?;
        let interface = instance.eliot_current_activation();
        let raw = interface.call_describe(&mut *store).map_err(|error| {
            staged(
                TypedStage::Descriptor,
                map_call_error("describe", &error, store.data().limit_hit),
            )
        })?;
        let descriptor = TypedDescriptor {
            world_name: raw.world_name,
            package_id: raw.package_id,
            abi_revision: raw.abi_revision,
            native_contract: raw.native_contract,
            native_revision: raw.native_revision,
            abi_digest: raw.abi_digest,
        };
        // P5.5 (#758): deny a lying descriptor before the domain export runs.
        validate_descriptor(
            TypedWorld::CueActivation,
            &descriptor,
            limits.max_output_bytes,
        )
        .map_err(|error| staged(TypedStage::Descriptor, error))?;
        validate_descriptor_abi_digest(&descriptor)
            .map_err(|error| staged(TypedStage::Descriptor, error))?;
        let called = interface
            .call_activate(&mut *store, request)
            .map_err(|error| {
                staged(
                    TypedStage::Invoke,
                    map_call_error("activate", &error, store.data().limit_hit),
                )
            })?;
        let domain = match called {
            Ok(value) => TypedDomainResult::Outcome(Box::new(TypedDomainOutcome::CueActivation(
                Box::new(value),
            ))),
            Err(error) => TypedDomainResult::GuestError(Box::new(TypedDomainError::CueActivation(
                Box::new(error),
            ))),
        };
        Ok((descriptor, domain))
    })
}

fn call_dreamer_handler(
    engine: &wasmtime::Engine,
    component: &wasmtime::component::Component,
    limits: &InvocationLimits,
    request: &crate::typed_bindings::dreamer_handler::exports::eliot::current::handler::ValidatedCandidate,
) -> Result<((TypedDescriptor, TypedDomainResult), ObservedUsage), TypedExecutionError> {
    use crate::typed_bindings::dreamer_handler::DreamerHandler;
    run_guarded(engine, limits, |store| {
        let linker = wasmtime::component::Linker::new(engine);
        let instance =
            DreamerHandler::instantiate(&mut *store, component, &linker).map_err(|error| {
                staged(
                    TypedStage::Instantiate,
                    map_instantiate_error(&error, store.data().limit_hit),
                )
            })?;
        let interface = instance.eliot_current_handler();
        let raw = interface.call_describe(&mut *store).map_err(|error| {
            staged(
                TypedStage::Descriptor,
                map_call_error("describe", &error, store.data().limit_hit),
            )
        })?;
        let descriptor = TypedDescriptor {
            world_name: raw.world_name,
            package_id: raw.package_id,
            abi_revision: raw.abi_revision,
            native_contract: raw.native_contract,
            native_revision: raw.native_revision,
            abi_digest: raw.abi_digest,
        };
        // P5.5 (#758): deny a lying descriptor before the domain export runs.
        validate_descriptor(
            TypedWorld::DreamerHandler,
            &descriptor,
            limits.max_output_bytes,
        )
        .map_err(|error| staged(TypedStage::Descriptor, error))?;
        validate_descriptor_abi_digest(&descriptor)
            .map_err(|error| staged(TypedStage::Descriptor, error))?;
        let called = interface
            .call_handle(&mut *store, request)
            .map_err(|error| {
                staged(
                    TypedStage::Invoke,
                    map_call_error("handle", &error, store.data().limit_hit),
                )
            })?;
        let domain = match called {
            Ok(value) => TypedDomainResult::Outcome(Box::new(TypedDomainOutcome::DreamerHandler(
                Box::new(value),
            ))),
            Err(error) => TypedDomainResult::GuestError(Box::new(
                TypedDomainError::DreamerHandler(Box::new(error)),
            )),
        };
        Ok((descriptor, domain))
    })
}

fn call_memory_curation_screen(
    engine: &wasmtime::Engine,
    component: &wasmtime::component::Component,
    limits: &InvocationLimits,
    request: &crate::typed_bindings::memory_curation_screen::exports::eliot::current::screen::ScreenRequest,
) -> Result<((TypedDescriptor, TypedDomainResult), ObservedUsage), TypedExecutionError> {
    use crate::typed_bindings::memory_curation_screen::MemoryCurationScreen;
    run_guarded(engine, limits, |store| {
        let linker = wasmtime::component::Linker::new(engine);
        let instance = MemoryCurationScreen::instantiate(&mut *store, component, &linker).map_err(
            |error| {
                staged(
                    TypedStage::Instantiate,
                    map_instantiate_error(&error, store.data().limit_hit),
                )
            },
        )?;
        let interface = instance.eliot_current_screen();
        let raw = interface.call_describe(&mut *store).map_err(|error| {
            staged(
                TypedStage::Descriptor,
                map_call_error("describe", &error, store.data().limit_hit),
            )
        })?;
        let descriptor = TypedDescriptor {
            world_name: raw.world_name,
            package_id: raw.package_id,
            abi_revision: raw.abi_revision,
            native_contract: raw.native_contract,
            native_revision: raw.native_revision,
            abi_digest: raw.abi_digest,
        };
        // P5.5 (#758): deny a lying descriptor before the domain export runs.
        validate_descriptor(
            TypedWorld::MemoryCurationScreen,
            &descriptor,
            limits.max_output_bytes,
        )
        .map_err(|error| staged(TypedStage::Descriptor, error))?;
        validate_descriptor_abi_digest(&descriptor)
            .map_err(|error| staged(TypedStage::Descriptor, error))?;
        let called = interface
            .call_screen(&mut *store, request)
            .map_err(|error| {
                staged(
                    TypedStage::Invoke,
                    map_call_error("screen", &error, store.data().limit_hit),
                )
            })?;
        let domain = match called {
            Ok(value) => TypedDomainResult::Outcome(Box::new(
                TypedDomainOutcome::MemoryCurationScreen(Box::new(value)),
            )),
            Err(error) => TypedDomainResult::GuestError(Box::new(
                TypedDomainError::MemoryCurationScreen(Box::new(error)),
            )),
        };
        Ok((descriptor, domain))
    })
}

fn call_dreamer_cycle(
    engine: &wasmtime::Engine,
    component: &wasmtime::component::Component,
    limits: &InvocationLimits,
    request: &crate::typed_bindings::dreamer_cycle::exports::eliot::current::cycle::CycleStepInput,
) -> Result<((TypedDescriptor, TypedDomainResult), ObservedUsage), TypedExecutionError> {
    use crate::typed_bindings::dreamer_cycle::DreamerCycle;
    run_guarded(engine, limits, |store| {
        let linker = wasmtime::component::Linker::new(engine);
        let instance =
            DreamerCycle::instantiate(&mut *store, component, &linker).map_err(|error| {
                staged(
                    TypedStage::Instantiate,
                    map_instantiate_error(&error, store.data().limit_hit),
                )
            })?;
        let interface = instance.eliot_current_cycle();
        let raw = interface.call_describe(&mut *store).map_err(|error| {
            staged(
                TypedStage::Descriptor,
                map_call_error("describe", &error, store.data().limit_hit),
            )
        })?;
        let descriptor = TypedDescriptor {
            world_name: raw.world_name,
            package_id: raw.package_id,
            abi_revision: raw.abi_revision,
            native_contract: raw.native_contract,
            native_revision: raw.native_revision,
            abi_digest: raw.abi_digest,
        };
        // P5.5 (#758): deny a lying descriptor before the domain export runs.
        validate_descriptor(
            TypedWorld::DreamerCycle,
            &descriptor,
            limits.max_output_bytes,
        )
        .map_err(|error| staged(TypedStage::Descriptor, error))?;
        validate_descriptor_abi_digest(&descriptor)
            .map_err(|error| staged(TypedStage::Descriptor, error))?;
        let called = interface.call_step(&mut *store, request).map_err(|error| {
            staged(
                TypedStage::Invoke,
                map_call_error("step", &error, store.data().limit_hit),
            )
        })?;
        let domain = match called {
            Ok(value) => TypedDomainResult::Outcome(Box::new(TypedDomainOutcome::DreamerCycle(
                Box::new(value),
            ))),
            Err(error) => TypedDomainResult::GuestError(Box::new(TypedDomainError::DreamerCycle(
                Box::new(error),
            ))),
        };
        Ok((descriptor, domain))
    })
}

/// Six frozen worlds driven through their own real domain export and the
/// #760 neutral capsule pair (issue #758 case 3).
///
/// This drive lives inside the crate on purpose and changes no production
/// line above it. `TypedDomainRequest`'s payloads are the generated bindgen
/// types behind the crate-private `crate::typed_bindings`, so no `tests/`
/// target can construct one and no visibility is expanded for this proof.
/// What this module adds is only the real per-world driver the issue's matrix
/// requires: the checked-in per-world component fixture is parsed with `wat`,
/// preflighted, bound into a real [`ModuleContractKit`] and a real
/// [`ModuleTestCapsule`], and executed once per world by the real Wasmtime
/// provider through both domain entries. No mock engine, no second engine, no
/// legacy byte-runner fallback.
///
/// FIXTURE VALUES: every string written into a request record below is a test
/// fixture value owned by this module and is never production data. Each is
/// bounded, printable and non-empty; every leaf that is not an admitted
/// identity echo is exactly one printable byte, so the whole measured record
/// stays inside the admitted input ceiling [`default_experimental_limits`]
/// sets. That ceiling is the real one and is not widened, relaxed or tuned
/// here. Only the five admitted identity leaves are meaningful to the host:
/// they are copied verbatim out of the [`TypedDomainAdmission`] the same call
/// enforces, so the guest echo checks compare values the guest really read.
///
/// What this module is evidence of is exactly one thing: the real engine
/// executed each world's real domain export once through the neutral capsule.
/// The request contents are test inputs, not evidence of any admission,
/// activation, screening, handling or cycle semantics.
#[cfg(test)]
mod six_world_capsule_drive {
    use super::{
        ExecutionMode, ModuleContractKit, ModuleTestCapsule, ProofCeiling, Sha256Digest,
        TypedDomainAdmission, TypedDomainError, TypedDomainOutcome, TypedDomainRequest,
        TypedDomainResult, TypedExecutionError, TypedReceipt, TypedStage, TypedWorld,
        default_experimental_limits, execute_capsule_domain_experimental,
        execute_describe_experimental, execute_domain_experimental, preflight_bytes,
        typed_wit_digest,
    };
    use crate::contour::PINNED_WASMTIME_VERSION;
    use crate::typed_bindings::context_admission::exports::eliot::current::admission as admission_wit;
    use crate::typed_bindings::context_assembly::exports::eliot::current::assembly as assembly_wit;
    use crate::typed_bindings::cue_activation::exports::eliot::current::activation as activation_wit;
    use crate::typed_bindings::dreamer_cycle::exports::eliot::current::cycle as cycle_wit;
    use crate::typed_bindings::dreamer_handler::exports::eliot::current::handler as handler_wit;
    use crate::typed_bindings::memory_curation_screen::exports::eliot::current::screen as screen_wit;
    use crate::typed_bindings::{TYPED_PACKAGE_ID, export_matches_interface};
    use eliot_wasm_runtime::component_contract::{
        AbiDescriptor, TYPED_ENGINE_VERSION, TypedWorld as NeutralWorld,
    };
    use eliot_wasm_runtime::{CapabilityId, InvocationLimits, ProofStage};

    /// Admitted identity leaves. Two printable bytes each; every request record
    /// copies these verbatim from the admitted envelope.
    const OPERATION_ID: &str = "op";
    const TASK_ID: &str = "tk";
    const SCOPE_ID: &str = "sc";
    const FENCE_EPOCH: &str = "fe";
    const POLICY_ID: &str = "pl";

    /// One-byte bounded fixture leaves, named after the field they carry.
    const ATTEMPT: &str = "a";
    const DECISION: &str = "d";
    const REVISION: &str = "r";
    const FLOOR: &str = "i";
    const DIGEST: &str = "g";
    const RULE: &str = "u";
    const PRIORITY: &str = "o";
    const PROFILE: &str = "p";
    const SERIALIZER: &str = "z";
    const SERIALIZER_VERSION: &str = "y";
    const OPTIONS: &str = "x";
    const ROUTE: &str = "w";
    const MODEL: &str = "m";
    const QUALIFICATION: &str = "q";
    const RULE_EVIDENCE: &str = "e";
    const SNAPSHOT: &str = "n";
    const NORMALIZATION: &str = "v";
    const SOURCE: &str = "s";
    const PRINCIPAL: &str = "h";
    const SESSION: &str = "j";
    const SUMMARY: &str = "t";
    const BUNDLE: &str = "b";
    const RECEIPT: &str = "k";
    const STATE_DIGEST: &str = "c";

    /// Unwraps a real construction result with an explicit failure message.
    fn must<T, E: std::fmt::Debug>(result: Result<T, E>) -> T {
        match result {
            Ok(value) => value,
            Err(error) => {
                panic!("#758/3 typed capsule drive could not build a real value: {error:?}")
            }
        }
    }

    /// Maps a host world selection onto the neutral #760 world it is bound to.
    const fn neutral_world(world: TypedWorld) -> NeutralWorld {
        match world {
            TypedWorld::ContextAdmission => NeutralWorld::ContextAdmission,
            TypedWorld::ContextAssembly => NeutralWorld::ContextAssembly,
            TypedWorld::CueActivation => NeutralWorld::CueActivation,
            TypedWorld::DreamerHandler => NeutralWorld::DreamerHandler,
            TypedWorld::MemoryCurationScreen => NeutralWorld::MemoryCurationScreen,
            TypedWorld::DreamerCycle => NeutralWorld::DreamerCycle,
        }
    }

    /// Checked-in component fixture under this crate's typed fixture directory,
    /// named by its file stem. `load_fixture` selects one by world name; the
    /// inputs that are deliberately NOT a world's success fixture are named
    /// here.
    fn load_fixture_file(name: &str) -> Vec<u8> {
        let path = format!("tests/data/typed-components/{name}.wat");
        match wat::parse_file(&path) {
            Ok(bytes) => bytes,
            Err(error) => {
                panic!("#758 typed fixture {path} must be a parseable component: {error}")
            }
        }
    }

    /// Checked-in per-world component fixture for this world.
    fn load_fixture(world: TypedWorld) -> Vec<u8> {
        load_fixture_file(world.world_name())
    }

    /// The exact frozen WIT bytes that declare this world's exported
    /// interface, measured for the kit's interface identity.
    fn world_interface_bytes(world: TypedWorld) -> &'static [u8] {
        match world {
            TypedWorld::ContextAdmission => include_bytes!("../wit/typed/context-admission.wit"),
            TypedWorld::ContextAssembly => include_bytes!("../wit/typed/context-assembly.wit"),
            TypedWorld::CueActivation => include_bytes!("../wit/typed/cue-activation.wit"),
            TypedWorld::DreamerHandler => include_bytes!("../wit/typed/dreamer-handler.wit"),
            TypedWorld::MemoryCurationScreen => {
                include_bytes!("../wit/typed/memory-curation-screen.wit")
            }
            TypedWorld::DreamerCycle => include_bytes!("../wit/typed/dreamer-cycle.wit"),
        }
    }

    /// Real #760 contract kit for one world, bound to that world's measured
    /// fixture bytes.
    ///
    /// Every field satisfies a real comparison the capsule entry performs:
    /// package identity and the ABI descriptor (`ModuleContractKit::validate`),
    /// `artifact_digest`/`artifact_len` against the same buffer's preflight
    /// (`execute_capsule_domain_experimental`'s "artifact-digest" /
    /// "artifact-length" checks), empty `declared_imports` and exactly
    /// `[world.interface_name()]` in `declared_exports`, and
    /// `governed: false` for this explicitly selected local experiment.
    fn world_kit(world: TypedWorld, artifact: &[u8]) -> ModuleContractKit {
        let preflight = must(preflight_bytes(artifact));
        let neutral = neutral_world(world);
        ModuleContractKit {
            package_id: TYPED_PACKAGE_ID.to_owned(),
            world: neutral,
            abi: must(AbiDescriptor::new(
                neutral,
                format!("758/3-fixture-native/{}", world.world_name()),
                "758/3-fixture-native-revision-1".to_owned(),
                // The frozen WIT digest the guest `describe` export must report.
                typed_wit_digest(),
            )),
            artifact_digest: preflight.digest,
            artifact_len: preflight.byte_len,
            interface_digest: Sha256Digest::of_bytes(world_interface_bytes(world)),
            declared_imports: Vec::new(),
            declared_exports: vec![neutral.interface_name().to_owned()],
            // No frozen typed world declares a state contract: each interface
            // is a pure per-call function over its own request/result records.
            // The field is still bound to an exact measured digest of that
            // frozen fact rather than left unset.
            state_contract_digest: Sha256Digest::of_bytes(
                format!("758/3-no-state-contract/{}/v1", world.world_name()).as_bytes(),
            ),
            // Bound below to the ceiling this call actually enforces; a kit
            // that claims a higher ceiling is denied, not projected.
            proof_ceiling: ProofCeiling::Observation,
            governed: false,
        }
    }

    /// Real #760 test capsule for one world's kit, on the same admitted
    /// envelope the call enforces. `fixture`/`expected` are bounded size
    /// evidence only — exactly as `execute_capsule_domain_experimental`
    /// documents, they are never parsed into a request and are not an engine
    /// report.
    fn world_capsule(
        world: TypedWorld,
        kit: &ModuleContractKit,
        limits: &InvocationLimits,
    ) -> ModuleTestCapsule {
        ModuleTestCapsule {
            kit_digest: must(kit.digest()),
            component: must(CapabilityId::new(format!(
                "758/3-typed-fixture/{}",
                world.world_name()
            ))),
            world: neutral_world(world),
            operation: world.domain_func().to_owned(),
            stage: ProofStage::Invocation,
            fixture: format!(
                "758/3-capsule-fixture/{}/{}",
                world.world_name(),
                world.domain_func()
            )
            .into_bytes(),
            expected: format!(
                "758/3-capsule-expected/{}/{}",
                world.world_name(),
                world.domain_func()
            )
            .into_bytes(),
            // Declared bounds are the admitted envelope's own ceilings, never
            // above them: the capsule entry denies a capsule above them.
            max_input_bytes: limits.max_input_bytes,
            max_output_bytes: limits.max_output_bytes,
            max_work: limits.max_fuel,
            oracle: format!("758/3-capsule-oracle/{}", world.world_name()),
        }
    }

    /// The admitted envelope every world is driven under. Its `proof_ceiling`
    /// equals the governing kit's, which is the binding the capsule entry
    /// enforces before delegation.
    fn admitted_record() -> TypedDomainAdmission {
        TypedDomainAdmission {
            operation_id: OPERATION_ID.to_owned(),
            task_id: TASK_ID.to_owned(),
            scope_id: SCOPE_ID.to_owned(),
            fence_epoch: FENCE_EPOCH.to_owned(),
            policy_id: POLICY_ID.to_owned(),
            proof_ceiling: ProofCeiling::Observation,
        }
    }

    fn capacity_limits() -> admission_wit::CapacityLimits {
        admission_wit::CapacityLimits {
            total_capacity: 0,
            fixed_overhead: 0,
            output_reserve: 0,
            review_reserve: 0,
        }
    }

    fn decision_revision() -> admission_wit::DecisionRevision {
        admission_wit::DecisionRevision {
            decision_id: DECISION.to_owned(),
            recipe_revision: REVISION.to_owned(),
            policy_sha256: DIGEST.to_owned(),
        }
    }

    fn context_binding(admitted: &TypedDomainAdmission) -> admission_wit::ContextBinding {
        admission_wit::ContextBinding {
            task_id: admitted.task_id.clone(),
            attempt_id: ATTEMPT.to_owned(),
            scope_id: admitted.scope_id.clone(),
            fence_epoch: admitted.fence_epoch.clone(),
            fence_generation: 0,
            decision_id: DECISION.to_owned(),
            operation_id: None,
        }
    }

    /// The world's own generated request record, built from its own WIT
    /// surface only (`wit/typed/context-admission.wit::admission-request`).
    fn admission_request(admitted: &TypedDomainAdmission) -> admission_wit::AdmissionRequest {
        admission_wit::AdmissionRequest {
            schema_revision: 1,
            operation_id: admitted.operation_id.clone(),
            task_id: admitted.task_id.clone(),
            attempt_id: ATTEMPT.to_owned(),
            scope_id: admitted.scope_id.clone(),
            fence_epoch: admitted.fence_epoch.clone(),
            fence_generation: 0,
            binding: context_binding(admitted),
            candidates: Vec::new(),
            recipe_digest: DIGEST.to_owned(),
            recipe_revision: REVISION.to_owned(),
            provider_denominator: Vec::new(),
            capacity: capacity_limits(),
            floor: admission_wit::SafetyFloorIdentity {
                floor_id: FLOOR.to_owned(),
                decision: decision_revision(),
                floor: admission_wit::SafetyFloor {
                    binding: context_binding(admitted),
                    mandatory_atoms: Vec::new(),
                    mandatory_roles: Vec::new(),
                    providers: admission_wit::ProviderDenominator {
                        requested: Vec::new(),
                        dispositions: Vec::new(),
                    },
                    members: Vec::new(),
                    interpretation_dependencies: Vec::new(),
                    rule_evidence: RULE_EVIDENCE.to_owned(),
                    capacity: capacity_limits(),
                },
            },
            priority: admission_wit::PriorityPolicy {
                policy_id: PRIORITY.to_owned(),
                decision: decision_revision(),
                priorities: Vec::new(),
            },
            rule: admission_wit::AdmissionRule {
                rule_id: RULE.to_owned(),
                decision: decision_revision(),
                rule_sha256: DIGEST.to_owned(),
            },
            measurement_profile: admission_wit::MeasurementCompositionProfile {
                profile_id: PROFILE.to_owned(),
                schema_version: 1,
                serializer_id: SERIALIZER.to_owned(),
                serializer_version: SERIALIZER_VERSION.to_owned(),
                serializer_options_digest: OPTIONS.to_owned(),
                route_id: ROUTE.to_owned(),
                model_id: MODEL.to_owned(),
                unit: admission_wit::MeasurementUnit::Utf8Bytes,
                aggregation: admission_wit::MeasurementAggregation::QualifiedUtf8Contribution,
                qualification: QUALIFICATION.to_owned(),
                capacity: capacity_limits(),
            },
            supplied_omissions: Vec::new(),
            measurements: Vec::new(),
            learning_tickets: Vec::new(),
            deadline_ms: None,
            cancelled: false,
            predecessor_digest: None,
            invalidation: None,
        }
    }

    /// `wit/typed/context-assembly.wit::assembly-request`.
    fn assembly_request(admitted: &TypedDomainAdmission) -> assembly_wit::AssemblyRequest {
        assembly_wit::AssemblyRequest {
            schema_revision: 1,
            operation_id: admitted.operation_id.clone(),
            task_id: admitted.task_id.clone(),
            scope_id: admitted.scope_id.clone(),
            fence_epoch: admitted.fence_epoch.clone(),
            fence_generation: 0,
            admitted: Vec::new(),
            admitted_digest: DIGEST.to_owned(),
            recipe_digest: DIGEST.to_owned(),
            measurement: assembly_wit::SerializedMeasurement {
                byte_count: 0,
                stu_estimate: None,
                exact_token_count: None,
                serializer: SERIALIZER.to_owned(),
                schema_revision: REVISION.to_owned(),
                input_digest: DIGEST.to_owned(),
                output_digest: DIGEST.to_owned(),
                proof_ceiling: assembly_wit::ProofCeiling::Observation,
            },
            deadline_ms: None,
            cancelled: false,
            predecessor_digest: None,
        }
    }

    /// `wit/typed/cue-activation.wit::activation-request`. This world echoes
    /// its WIT `request-id` as the admitted operation identity and carries no
    /// task or scope field.
    fn activation_request(admitted: &TypedDomainAdmission) -> activation_wit::ActivationRequest {
        activation_wit::ActivationRequest {
            schema_revision: 1,
            request_id: admitted.operation_id.clone(),
            seeds: Vec::new(),
            snapshot_id: SNAPSHOT.to_owned(),
            relation_edges: Vec::new(),
            bounds: activation_wit::ActivationBounds {
                max_depth: 0,
                max_fanout: 0,
                max_results: 0,
                max_nodes: 0,
                max_edges: 0,
                max_work: 0,
                max_path_len: 0,
                max_seeds: 0,
                max_direct: 0,
                max_derived: 0,
                max_trace_steps: 0,
                max_output_bytes: 0,
                activation_threshold: 0,
            },
            fence_epoch: admitted.fence_epoch.clone(),
            fence_generation: 0,
            normalization_profile: NORMALIZATION.to_owned(),
            observed_at_ms: 0,
            deadline_ms: None,
            cancelled: false,
        }
    }

    /// `wit/typed/dreamer-handler.wit::validated-candidate`, carrying the
    /// orientation subtype payload its own WIT variant declares.
    fn handler_request(admitted: &TypedDomainAdmission) -> handler_wit::ValidatedCandidate {
        handler_wit::ValidatedCandidate {
            schema_revision: 1,
            operation_id: admitted.operation_id.clone(),
            job: handler_wit::JobClass::Orientation,
            requester: handler_wit::Requester {
                principal: PRINCIPAL.to_owned(),
                origin: handler_wit::RequesterOrigin::Human,
                session: SESSION.to_owned(),
            },
            task_id: admitted.task_id.clone(),
            attempt_id: ATTEMPT.to_owned(),
            scope_id: admitted.scope_id.clone(),
            fence_epoch: admitted.fence_epoch.clone(),
            fence_generation: 0,
            bundle_digest: BUNDLE.to_owned(),
            manifest_digest: DIGEST.to_owned(),
            grounding_digest: DIGEST.to_owned(),
            validation_receipt: RECEIPT.to_owned(),
            subtype: handler_wit::HandlerSubtype::Orientation(handler_wit::OrientationPayload {
                summary: SUMMARY.to_owned(),
                findings: Vec::new(),
                unknowns: Vec::new(),
            }),
            budget: handler_wit::BudgetLimits {
                max_input_bytes: 0,
                max_output_bytes: 0,
                max_candidates: 0,
                max_work: 0,
                max_depth: 0,
            },
            preservation: handler_wit::PreservationReport {
                verdicts: Vec::new(),
            },
            deadline_ms: None,
            cancelled: false,
        }
    }

    /// `wit/typed/memory-curation-screen.wit::screen-request`.
    fn screen_request(admitted: &TypedDomainAdmission) -> screen_wit::ScreenRequest {
        screen_wit::ScreenRequest {
            schema_revision: 1,
            operation_id: admitted.operation_id.clone(),
            task_id: admitted.task_id.clone(),
            scope_id: admitted.scope_id.clone(),
            fence_epoch: admitted.fence_epoch.clone(),
            fence_generation: 0,
            source_id: SOURCE.to_owned(),
            snapshot_revision: REVISION.to_owned(),
            members: Vec::new(),
            availability: screen_wit::SourceAvailability::Available,
            profile_id: PROFILE.to_owned(),
            rule_ids: Vec::new(),
            deadline_ms: None,
            cancelled: false,
            predecessor_digest: None,
        }
    }

    /// `wit/typed/dreamer-cycle.wit::cycle-step-input`. Its result echoes the
    /// request's own `state.fence-epoch`, so both carry the admitted fence.
    fn cycle_request(admitted: &TypedDomainAdmission) -> cycle_wit::CycleStepInput {
        cycle_wit::CycleStepInput {
            schema_revision: 1,
            operation_id: admitted.operation_id.clone(),
            task_id: admitted.task_id.clone(),
            scope_id: admitted.scope_id.clone(),
            fence_epoch: admitted.fence_epoch.clone(),
            fence_generation: 0,
            state: cycle_wit::DreamerState {
                schema_version: 1,
                phase: cycle_wit::CyclePhase::Validated,
                revision: 0,
                state_digest: STATE_DIGEST.to_owned(),
                pending: Vec::new(),
                observed: Vec::new(),
                fence_epoch: admitted.fence_epoch.clone(),
                fence_generation: 0,
            },
            policy: cycle_wit::CyclePolicy {
                schema_version: 1,
                policy_revision: REVISION.to_owned(),
                max_records: 0,
                max_requests: 0,
                max_canonical_bytes: 0,
            },
            deadline_ms: None,
            cancelled: false,
            predecessor_digest: None,
        }
    }

    /// The one generated request value for this world, in its own typed
    /// carrier. Each world's record is built by its own builder above, so a
    /// world can never be driven with another world's payload.
    fn world_request(world: TypedWorld, admitted: &TypedDomainAdmission) -> TypedDomainRequest {
        match world {
            TypedWorld::ContextAdmission => {
                TypedDomainRequest::Admission(Box::new(admission_request(admitted)))
            }
            TypedWorld::ContextAssembly => {
                TypedDomainRequest::Assembly(Box::new(assembly_request(admitted)))
            }
            TypedWorld::CueActivation => {
                TypedDomainRequest::CueActivation(Box::new(activation_request(admitted)))
            }
            TypedWorld::DreamerHandler => {
                TypedDomainRequest::DreamerHandler(Box::new(handler_request(admitted)))
            }
            TypedWorld::MemoryCurationScreen => {
                TypedDomainRequest::MemoryCurationScreen(Box::new(screen_request(admitted)))
            }
            TypedWorld::DreamerCycle => {
                TypedDomainRequest::DreamerCycle(Box::new(cycle_request(admitted)))
            }
        }
    }

    /// True when the retained terminal result is this world's own typed
    /// outcome variant. A guest error, a foreign world's payload or a lifted
    /// trap terminal all fail this.
    fn is_world_outcome(world: TypedWorld, result: &TypedDomainResult) -> bool {
        let TypedDomainResult::Outcome(outcome) = result else {
            return false;
        };
        matches!(
            (world, outcome.as_ref()),
            (
                TypedWorld::ContextAdmission,
                TypedDomainOutcome::Admission(_)
            ) | (TypedWorld::ContextAssembly, TypedDomainOutcome::Assembly(_))
                | (
                    TypedWorld::CueActivation,
                    TypedDomainOutcome::CueActivation(_)
                )
                | (
                    TypedWorld::DreamerHandler,
                    TypedDomainOutcome::DreamerHandler(_)
                )
                | (
                    TypedWorld::MemoryCurationScreen,
                    TypedDomainOutcome::MemoryCurationScreen(_)
                )
                | (
                    TypedWorld::DreamerCycle,
                    TypedDomainOutcome::DreamerCycle(_)
                )
        )
    }

    /// The same world-binding question for the OTHER terminal, asked of a guest's
    /// OWN typed error. `is_world_outcome` above deliberately refuses it: a
    /// `GuestError` is a completed call only in the sense that the guest
    /// returned a typed `Err`, and the host must never read one as an outcome.
    /// This sibling says which world's error it is, so a caller can tell "this
    /// world's guest refused" from "a foreign world's value arrived here".
    fn is_world_guest_error(world: TypedWorld, result: &TypedDomainResult) -> bool {
        let TypedDomainResult::GuestError(error) = result else {
            return false;
        };
        matches!(
            (world, error.as_ref()),
            (TypedWorld::ContextAdmission, TypedDomainError::Admission(_))
                | (TypedWorld::ContextAssembly, TypedDomainError::Assembly(_))
                | (
                    TypedWorld::CueActivation,
                    TypedDomainError::CueActivation(_)
                )
                | (
                    TypedWorld::DreamerHandler,
                    TypedDomainError::DreamerHandler(_)
                )
                | (
                    TypedWorld::MemoryCurationScreen,
                    TypedDomainError::MemoryCurationScreen(_)
                )
                | (TypedWorld::DreamerCycle, TypedDomainError::DreamerCycle(_))
        )
    }

    /// Everything one world's drive binds, so every assertion helper below sees
    /// the exact measured values this world's own fixture produced rather than
    /// a hand-copied subset of them.
    struct WorldDrive {
        world: TypedWorld,
        artifact: Vec<u8>,
        digest: Sha256Digest,
        byte_len: u64,
        limits: InvocationLimits,
        kit: ModuleContractKit,
        kit_digest: Sha256Digest,
        capsule: ModuleTestCapsule,
        admitted: TypedDomainAdmission,
        request: TypedDomainRequest,
    }

    /// Builds one world's drive from its checked-in fixture: the same bounded
    /// buffer is preflighted, the kit and the capsule are bound to its measured
    /// bytes, and the request is that world's own generated record.
    fn world_drive(world: TypedWorld) -> WorldDrive {
        let artifact = load_fixture(world);
        let preflight = must(preflight_bytes(&artifact));
        let limits = default_experimental_limits(preflight.digest.clone());
        let kit = world_kit(world, &artifact);
        let kit_digest = must(kit.digest());
        let capsule = world_capsule(world, &kit, &limits);
        let admitted = admitted_record();
        let request = world_request(world, &admitted);
        WorldDrive {
            world,
            artifact,
            digest: preflight.digest,
            byte_len: preflight.byte_len,
            limits,
            kit,
            kit_digest,
            capsule,
            admitted,
            request,
        }
    }

    /// The pair is bound to this fixture's measured bytes and to the ceiling
    /// this call enforces; nothing is pasted from elsewhere.
    fn assert_kit_capsule_binding(drive: &WorldDrive) {
        assert_eq!(drive.kit.artifact_digest, drive.digest);
        assert_eq!(drive.kit.artifact_len, drive.byte_len);
        assert_eq!(
            drive.kit.declared_exports,
            vec![drive.world.interface_name().to_owned()]
        );
        assert!(drive.kit.declared_imports.is_empty());
        assert!(!drive.kit.governed);
        assert!(drive.kit.validate().is_ok());
        assert_eq!(drive.capsule.kit_digest, drive.kit_digest);
        assert!(drive.capsule.validate(&drive.kit).is_ok());
        assert_eq!(drive.capsule.world, drive.kit.world);
        assert_eq!(drive.capsule.operation.as_str(), drive.world.domain_func());
        assert_eq!(drive.admitted.proof_ceiling, drive.kit.proof_ceiling);
    }

    /// The identity leaves one world's returned record carries. `None` means that
    /// world's frozen WIT result record declares no such leaf, so there is
    /// nothing to read back and nothing is asserted for it.
    struct GuestEcho<'a> {
        operation_id: Option<&'a str>,
        task_id: Option<&'a str>,
        fence_epoch: Option<&'a str>,
    }

    impl GuestEcho<'_> {
        const fn none() -> Self {
            Self {
                operation_id: None,
                task_id: None,
                fence_epoch: None,
            }
        }
    }

    /// The identity leaves the GUEST itself returned in its result record, read
    /// back out of the retained typed outcome.
    ///
    /// This is deliberately NOT this module's `OPERATION_ID`/`TASK_ID`/
    /// `FENCE_EPOCH` constants. Those old comparisons were not unfalsifiable; a
    /// production edit at the receipt-construction lines would have failed them.
    /// But each reduced to a COPY check: the receipt's identity fields are
    /// assigned from the admitted record at :2163-2166, and the admitted record is
    /// built from those same constants at :4278-4287, so the expected side was a
    /// constant the host already shared with the value under test. Reading the
    /// value back out of the guest's own returned record makes the expected side an
    /// OBSERVED value with a second origin: the bytes the guest wrote into its own
    /// linear memory, which production lifts in `check_result` (`check_echo`,
    /// :907-916). The comparison can then distinguish "the receipt carries what the
    /// guest returned" from "the receipt carries a value that happens to equal our
    /// own constant".
    ///
    /// Each leaf is an `Option` because the six frozen WIT result records do
    /// not declare the same fields: the activation world spells its echoed
    /// operation identity `request-id` (`activation-result-body`,
    /// wit/typed/cue-activation.wit:105) and declares no task or fence leaf at
    /// all (:104-114); `handler-result-body`
    /// (wit/typed/dreamer-handler.wit:466-475) declares only `operation-id`
    /// among the three; and `cycle-step-result`
    /// (wit/typed/dreamer-cycle.wit:133-144) carries `fence-epoch` only inside
    /// its `state` record (:124), not at the top level. `admission-result`'s
    /// `incomplete` case (`wit/typed/context-admission.wit:538`) declares no
    /// identity leaf either, so a world returning that case reads back as all
    /// `None` rather than inventing a value; the caller's guard is what turns
    /// that into the honest failure "this world returned no identity record"
    /// instead of a `Some`-versus-`None` mismatch against the host's own copy.
    fn guest_echo(world: TypedWorld, result: &TypedDomainResult) -> GuestEcho<'_> {
        let TypedDomainResult::Outcome(outcome) = result else {
            panic!("#758/3 only a retained outcome carries a guest-returned identity");
        };
        match (world, outcome.as_ref()) {
            (TypedWorld::ContextAdmission, TypedDomainOutcome::Admission(value)) => {
                match value.as_ref() {
                    admission_wit::AdmissionResult::Admitted(set) => GuestEcho {
                        operation_id: Some(set.operation_id.as_str()),
                        task_id: Some(set.task_id.as_str()),
                        fence_epoch: Some(set.fence_epoch.as_str()),
                    },
                    admission_wit::AdmissionResult::Incomplete(_) => GuestEcho::none(),
                }
            }
            (TypedWorld::ContextAssembly, TypedDomainOutcome::Assembly(value)) => {
                let assembly_wit::AssemblyResult::Assembled(view) = value.as_ref();
                GuestEcho {
                    operation_id: Some(view.operation_id.as_str()),
                    task_id: Some(view.task_id.as_str()),
                    fence_epoch: Some(view.fence_epoch.as_str()),
                }
            }
            (TypedWorld::CueActivation, TypedDomainOutcome::CueActivation(value)) => {
                let activation_wit::ActivationOutcome::Activated(body) = value.as_ref();
                GuestEcho {
                    operation_id: Some(body.request_id.as_str()),
                    task_id: None,
                    fence_epoch: None,
                }
            }
            (TypedWorld::DreamerHandler, TypedDomainOutcome::DreamerHandler(value)) => {
                let handler_wit::HandlerOutcome::Handled(body) = value.as_ref();
                GuestEcho {
                    operation_id: Some(body.operation_id.as_str()),
                    task_id: None,
                    fence_epoch: None,
                }
            }
            (TypedWorld::MemoryCurationScreen, TypedDomainOutcome::MemoryCurationScreen(value)) => {
                let screen_wit::ScreenOutcome::Screened(body) = value.as_ref();
                GuestEcho {
                    operation_id: Some(body.operation_id.as_str()),
                    task_id: Some(body.task_id.as_str()),
                    fence_epoch: Some(body.fence_epoch.as_str()),
                }
            }
            (TypedWorld::DreamerCycle, TypedDomainOutcome::DreamerCycle(value)) => {
                let cycle_wit::CycleOutcome::Stepped(body) = value.as_ref();
                GuestEcho {
                    operation_id: Some(body.operation_id.as_str()),
                    task_id: None,
                    fence_epoch: Some(body.state.fence_epoch.as_str()),
                }
            }
            _ => panic!("#758/3 a foreign world's outcome reached the identity read-back"),
        }
    }

    /// The host receipt the one real typed invocation actually produced, bound
    /// to this world's own artifact, ABI and admitted identity.
    ///
    /// The terminal result is deliberately NOT a parameter: the receipt's
    /// `terminal` is assigned from `result.terminal()` inside the production
    /// entry, so comparing the two here would compare a value with the
    /// expression it was assigned from. `receipt.terminal == "Completed"`
    /// stands on its own instead — a `GuestError` call reaching this helper
    /// fails it.
    ///
    /// The retained `result` IS a parameter, because the identity leaves below
    /// are compared against the identity the guest itself returned rather than
    /// against this module's own literals; see the block comment at the
    /// `guest_echo` call for the vacuity proof that forced that.
    fn assert_host_receipt(drive: &WorldDrive, receipt: &TypedReceipt, result: &TypedDomainResult) {
        assert_eq!(receipt.world, drive.world.world_name());
        assert_eq!(receipt.package_id, TYPED_PACKAGE_ID);
        assert_eq!(receipt.proof, ExecutionMode::LocalExperimental.proof());
        assert_eq!(receipt.artifact_digest, drive.digest);
        assert_eq!(receipt.artifact_bytes, drive.byte_len);
        // `receipt.engine_version` is bound to the two INDEPENDENT declarations
        // of the pinned engine generation, never to `super::ENGINE_VERSION`.
        //
        // PROVENANCE, stated exactly. There was NO assertion on this field
        // before this one. HEAD carried a comment in its place, recording a
        // deliberate NON-assertion, and its text was:
        //
        //   "`receipt.engine_version` is deliberately NOT asserted here: it is
        //    assigned `ENGINE_VERSION.to_owned()` at both receipt construction
        //    sites (:1049 and :2150), so comparing it against that same constant
        //    is a self-comparison that no production change can fail.
        //    `tests/typed_execution.rs` asserts the receipt's engine version
        //    against independent sources instead, which is the only form that
        //    can."
        //
        // The reasoning in that comment about the self-comparison was correct,
        // and this change does not reinstate the self-comparison it rejected.
        // But the conclusion drawn from it — that `tests/typed_execution.rs`
        // covers the field "instead", so nothing is lost here — did not hold for
        // THIS lane: the six-world capsule drive builds and reads the host
        // receipt only in-crate, and it is the only caller of these helpers, so
        // the in-crate non-assertion left the whole domain lane with no
        // comparison of `receipt.engine_version` at all. That is a coverage
        // hole, not a proof: an identity that is bound but never compared BY
        // VALUE is unproven.
        //
        // The two sides come from different owners and can differ:
        //   - `crate::contour::PINNED_WASMTIME_VERSION` (src/contour.rs:49), the
        //     package's own I14.19 baseline pin, documented there as "Must
        //     match the exact workspace pin";
        //   - `eliot_wasm_runtime::component_contract::TYPED_ENGINE_VERSION`
        //     (crates/modules/eliot-wasm-runtime/src/component_contract.rs:37),
        //     the neutral #760 contract's own pin, which production itself
        //     compares a real engine binding against at
        //     component_contract.rs:502 and capsule.rs:153.
        // Both are separate declarations from the `ENGINE_VERSION` constant at
        // :40 that the field is assigned from, so a drift between this receipt's
        // reported engine version and either owner's pin fails here — which the
        // in-crate non-assertion could not detect at all.
        assert_eq!(receipt.engine_version, PINNED_WASMTIME_VERSION);
        assert_eq!(receipt.engine_version, TYPED_ENGINE_VERSION);
        assert_eq!(receipt.wit_digest, typed_wit_digest());
        assert!(receipt.actual_imports.is_empty());
        // `actual_exports` is the component's REAL export name, copied
        // unmodified by `preflight_component_type` (this file, :1148) into the
        // receipt (:2154), and the admission gate accepts BOTH frozen spellings
        // through the owner `export_matches_interface`
        // (`src/typed_bindings.rs:181-187`). Every checked-in fixture exports
        // `eliot:current/<interface>@0.1.0` (e.g.
        // `tests/data/typed-components/dreamer-cycle.wat:217`), so this binds
        // through that same owner instead of hardcoding one spelling — the
        // rule `tests/typed_execution.rs:81-89` (`accepted_export_spellings`)
        // already applies. Strength is unchanged: exactly one export, and it
        // must name THIS world's interface in a spelling the host accepts. A
        // bare interface or a foreign package still fails.
        assert_eq!(receipt.actual_exports.len(), 1);
        assert!(
            export_matches_interface(&receipt.actual_exports[0], drive.world.interface_name()),
            "unexpected export spelling: {:?}",
            receipt.actual_exports[0]
        );
        assert_eq!(receipt.instances, 1);

        // The identity leaves below used to be compared against this module's OWN
        // literals (`OPERATION_ID`, `TASK_ID`, `FENCE_EPOCH`, :4105-4109).
        //
        // Those assertions were WEAKER than they looked, but they were not
        // unfalsifiable, and the honest description is narrower than "a
        // tautology". Each reduced, TRANSITIVELY, to a copy check rather than a
        // binding check: production's `check_echo` already forces the guest's
        // returned value to equal the admitted value upstream (:3466, :3520,
        // :3560, :3583, :3603, :3629 for `operation-id`, and the parallel sites
        // for the other leaves), and the admitted record is built from those
        // same module literals (`admitted_record`, :4278-4287). So
        // `receipt.<leaf> == <module literal>` confirmed that the receipt copy
        // matched a constant, and could not distinguish "production echoed the
        // admitted identity" from "production echoed a value that happens to
        // equal the admitted identity".
        //
        // They WERE still falsifiable, and specifically against a change at the
        // receipt-construction lines: a production edit at :2163-2166 assigning
        // anything other than the admitted leaf would have failed the old
        // assertion. So this is a strengthening of what the comparison can
        // DISTINGUISH, not the repair of a check that could never fail.
        //
        // What it buys: the second side is now an OBSERVED value rather than a
        // constant. It is read back out of the retained result record, so it is
        // the value the guest wrote into its own linear memory and the host
        // lifted, not a literal this module also used to build the request. The
        // receipt copy at :2163-2166 is therefore compared against the guest's
        // own returned bytes, and a future production change that stopped
        // comparing an identity upstream — dropping or weakening a `check_echo`
        // call — becomes visible here instead of hiding behind a constant that
        // both sides already shared. `guest_echo` below is that read-back.
        let echo = guest_echo(drive.world, result);
        // Why `operation-id` is compared UNCONDITIONALLY and the other two
        // conditionally: the conditional arms below exist only because those
        // WIT result records declare no such leaf, so there is no value to read
        // back and nothing to compare — `None` there is a property of the
        // frozen WIT, not an observation about this call. `operation-id` has no
        // such arm, so a `None` for it would NOT be a WIT fact but the
        // assertion below failing on the host/guest split. This guard is what
        // keeps that honest and makes the read-back total: a world that returns
        // no identity record at all (reachable — `admission-result`'s
        // `incomplete` case, wit/typed/context-admission.wit:538, declares no
        // identity leaf) fails HERE with the true reason, instead of comparing
        // the host's `Some(admitted.operation_id.clone())` (:2163) against a
        // `None` and reporting a mismatch that has nothing to do with identity
        // echo. A `None` therefore never silently bypasses this block: it is
        // only tolerated per-leaf where the WIT declares no leaf, and a world
        // that stops echoing fails the guard rather than skipping the compare.
        assert!(
            echo.operation_id.is_some() || echo.task_id.is_some() || echo.fence_epoch.is_some(),
            "#758/3 {} returned no identity record to read back",
            drive.world.world_name()
        );
        assert_eq!(receipt.operation_id.as_deref(), echo.operation_id);
        // `task-id` and `fence-epoch` are compared only for the worlds whose
        // own WIT result record declares them, because there is nothing to
        // read back for the others: `admitted-context-set`
        // (context-admission.wit:520 :523), `active-view`
        // (context-assembly.wit:104 :106) and `screen-result-body`
        // (memory-curation-screen.wit:103 :105) carry both, while
        // `activation-result-body` (cue-activation.wit:104-114) and
        // `handler-result-body` (dreamer-handler.wit:466-475) declare neither,
        // and `cycle-step-result` (dreamer-cycle.wit:133-144) carries
        // `fence-epoch` only inside `state` (:124). The `operation-id`
        // comparison is unconditional and the other two are conditional
        // because `None` is only ever tolerated per-leaf where the frozen WIT
        // declares no such leaf; the guard immediately above the unconditional
        // compare is what rules out a `None` that would mean anything else.
        if let Some(task_id) = echo.task_id {
            assert_eq!(receipt.task_id.as_deref(), Some(task_id));
        }
        if let Some(fence_epoch) = echo.fence_epoch {
            assert_eq!(receipt.fence_epoch.as_deref(), Some(fence_epoch));
        }
        // `receipt.policy_id` is KEPT as a literal comparison, and it is the one
        // identity leaf that CANNOT be rewired onto an observed value. The
        // reason is structural, not a shortcut: no WIT RESULT record anywhere
        // declares `policy-id`. The only declaration in the whole typed surface
        // is `priority-policy.policy-id`
        // (wit/typed/context-admission.wit:234), which sits in the REQUEST's
        // `priority` field. The guest therefore has no `policy-id` to echo and
        // the host has no observed value to compare against, so
        // `guest_echo` cannot supply a second origin for this leaf and the
        // module literal is the only available expected value.
        //
        // It is still worth asserting, and it is falsifiable: production assigns
        // the field `Some(admitted.policy_id.clone())` at :2166, so a production
        // edit at that line assigning anything else fails here. What it cannot
        // do is prove the BINDING, only the copy, and that limitation is
        // recorded rather than papered over. Card 758 line 26 forbids weakening
        // a case, so the assertion stays and the gap is stated beside it.
        //
        // What production does verify about this leaf is real and is not lost
        // with it: the field is shape-validated — non-empty, bounded by
        // `MAX_DESCRIPTOR_STRING_BYTES`, and free of control characters
        // (`TypedDomainAdmission::validate`, :167-185, where `policy_id` is the
        // fifth checked leaf at :173) — and it is folded into the request's
        // input digest (`input_digest`, :2387), so changing it changes the
        // measured input binding.
        assert_eq!(receipt.policy_id.as_deref(), Some(POLICY_ID));
        assert_eq!(receipt.terminal, "Completed");
        assert!(receipt.input_bytes > 0);
        assert!(receipt.output_bytes > 0);
        assert_ne!(
            receipt.semantic_digest,
            Sha256Digest::of_bytes(b"typed-semantic-pending")
        );
    }

    /// The projected #760 shared receipt for that same call, bound to the
    /// governing kit digest and to the ceiling that call enforced.
    fn assert_shared_projection(
        drive: &WorldDrive,
        receipt: &TypedReceipt,
        shared: &eliot_wasm_runtime::TypedReceipt,
    ) {
        assert_eq!(shared.kit_digest, drive.kit_digest);
        assert_eq!(shared.world, neutral_world(drive.world));
        assert_eq!(shared.package_id, TYPED_PACKAGE_ID);
        assert_eq!(shared.artifact_digest, drive.digest);
        assert_eq!(shared.input_digest, receipt.input_digest);
        assert_eq!(shared.output_digest.as_ref(), Some(&receipt.output_digest));
        assert_eq!(shared.output_bytes, receipt.output_bytes);
        assert_eq!(shared.stage, ProofStage::Receipt);
        assert_eq!(shared.proof_ceiling, drive.kit.proof_ceiling);
        assert_eq!(shared.terminal, "Completed");
        assert!(shared.validate().is_ok());
    }

    /// Negative half of the ceiling binding: a kit claiming a higher proof
    /// ceiling than the admission this call enforces is denied instead of being
    /// projected. Kit validation never bounds the ceiling, so the capsule is
    /// re-bound to the raised kit's own digest and the denial is the host's own
    /// comparison.
    fn assert_raised_ceiling_denial(drive: &WorldDrive) {
        let mut raised = drive.kit.clone();
        raised.proof_ceiling = ProofCeiling::CandidateOnly;
        let raised_digest = must(raised.digest());
        let raised_capsule = world_capsule(drive.world, &raised, &drive.limits);
        assert!(raised.validate().is_ok());
        assert_eq!(raised_capsule.kit_digest, raised_digest);
        assert!(raised_capsule.validate(&raised).is_ok());
        assert_ne!(raised_digest, drive.kit_digest);
        assert_ne!(raised.proof_ceiling, drive.admitted.proof_ceiling);
        match execute_capsule_domain_experimental(
            &raised,
            &raised_capsule,
            &drive.artifact,
            &drive.limits,
            &drive.request,
            &drive.admitted,
        ) {
            Ok(_) => panic!("#758/3 a kit above the enforced proof ceiling must be denied"),
            Err(TypedExecutionError::AdmissionMismatch(reason)) => {
                assert_eq!(reason, "proof-ceiling");
            }
            Err(other) => panic!("#758/3 a raised kit ceiling denied as {other}"),
        }
    }

    /// Drives ONE world end to end: its real component executes once through
    /// the kit-owned entry, once through the forwarding entry, and the raised
    /// kit ceiling is denied for the same kit/capsule pair.
    fn drive_world(world: TypedWorld) {
        let drive = world_drive(world);
        assert_eq!(drive.request.world(), drive.world);
        assert_kit_capsule_binding(&drive);

        // The one real typed invocation of this world's real domain export,
        // through the real Wasmtime provider, with the projected #760 shared
        // receipt for the same call.
        let (receipt, result, shared) = must(
            execute_capsule_domain_experimental(
                &drive.kit,
                &drive.capsule,
                &drive.artifact,
                &drive.limits,
                &drive.request,
                &drive.admitted,
            )
            .map_err(|error| error.to_string()),
        );

        assert_host_receipt(&drive, &receipt, &result);
        // The retained terminal result is this world's own typed outcome.
        assert!(is_world_outcome(world, &result));

        let Some(shared_receipt) = shared else {
            panic!("#758/3 the kit-owned lane must project a shared receipt");
        };
        assert_shared_projection(&drive, &receipt, &shared_receipt);

        // The second domain entry forwards the same projection unchanged.
        let (forwarded, forwarded_result, forwarded_shared) = must(
            execute_domain_experimental(
                world,
                &drive.artifact,
                &drive.limits,
                &drive.request,
                &drive.admitted,
                Some((&drive.kit, &drive.capsule)),
            )
            .map_err(|error| error.to_string()),
        );
        assert_eq!(forwarded_shared, Some(shared_receipt));
        assert_eq!(forwarded.semantic_digest, receipt.semantic_digest);
        assert_eq!(forwarded_result.terminal(), result.terminal());
        assert!(is_world_outcome(world, &forwarded_result));

        assert_raised_ceiling_denial(&drive);
    }

    /// #758 marker 17, the half an integration test cannot reach (`mod
    /// typed_bindings` is private outside this crate, so only in-crate code can
    /// build the generated request records and actually invoke the domain
    /// export): the REAL engine runs a guest that RETURNS its own typed `Err`
    /// on the domain leg, and the EXECUTED outcome alone tells that apart from
    /// a guest the engine TERMINATES. Nothing here reads the source text of any
    /// file to decide which branch ran.
    fn assert_guest_typed_error_is_a_distinct_executed_outcome_from_a_trap() {
        // Branch one, the guest's OWN typed error: this world's real request,
        // the same admitted envelope, kit and capsule the six-world drive binds,
        // and the checked-in `guest-typed-error` component, whose `screen`
        // export returns the `err` arm of the world's own
        // `result<screen-outcome, screen-error>` carrying a real
        // `screen-error`. It does not trap.
        let world = TypedWorld::MemoryCurationScreen;
        let artifact = load_fixture_file("guest-typed-error");
        let preflight = must(preflight_bytes(&artifact));
        let limits = default_experimental_limits(preflight.digest.clone());
        let kit = world_kit(world, &artifact);
        let capsule = world_capsule(world, &kit, &limits);
        let admitted = admitted_record();
        let request = world_request(world, &admitted);

        let (_receipt, result, _) = must(
            execute_capsule_domain_experimental(
                &kit, &capsule, &artifact, &limits, &request, &admitted,
            )
            .map_err(|error| error.to_string()),
        );

        // EXECUTED VALUE ONE: the retained terminal result is a `GuestError`
        // carrying THIS world's own `screen-error`, in the very case the guest
        // itself returned. A trap can produce neither, because a trap never
        // returns a terminal result at all.
        let TypedDomainResult::GuestError(guest_error) = &result else {
            panic!("#758/17 the guest's own typed error must be the retained result");
        };
        let TypedDomainError::MemoryCurationScreen(screen_error) = guest_error.as_ref() else {
            panic!("#758/17 the retained guest error must be this world's screen-error");
        };
        // The PAYLOAD, not just the case. The fixture plants the `human-detail`
        // itself — `guest-typed-error.wat` stores ptr 2304 / len 1 and lays the
        // byte down at 2304 — and `wit/typed/memory-curation-screen.wit` declares
        // `record screen-cancelled { human-detail: string }`. Matching the case
        // with a wildcard would prove only that the guest-chosen discriminant
        // round-tripped: a host that decoded the variant correctly and then
        // zeroed or substituted the detail would still pass. So the retained
        // value is compared against the byte the guest actually wrote, which is
        // what "retained verbatim" in that fixture's header claims.
        let screen_wit::ScreenError::CancelledScreen(cancelled) = screen_error.as_ref() else {
            panic!("#758/17 the retained guest error must be the cancelled-screen case");
        };
        assert_eq!(
            cancelled.human_detail, "x",
            "#758/17 the guest's own error payload must survive the lift"
        );
        // The world-binding predicate gets BOTH cases, because either alone can
        // be satisfied by a broken predicate: a hardcoded `false` passes the
        // refusal case, and a predicate that ignored its `world` argument passes
        // nothing else. The positive case is falsifiable by DELETING an arm from
        // `is_world_guest_error`'s own `matches!` list - the destructures above
        // fix the argument, not what the function answers - and the refusal case
        // is falsifiable by a predicate that dropped its world comparison. That
        // is also why `assert!(!is_world_outcome(world, &result))` is NOT here:
        // `is_world_outcome` returns false on the wrong variant by its own guard,
        // so that line was a check that could not fail.
        assert!(
            is_world_guest_error(world, &result),
            "#758/17 this world's own guest error must read as this world's"
        );
        assert!(
            !is_world_guest_error(TypedWorld::DreamerCycle, &result),
            "#758/17 the guest-error predicate must bind the world it names"
        );

        // Branch two, the trap: the same kit-owned entry and the same admitted
        // envelope, on a checked-in component whose `describe` has no exit. The
        // engine really terminates it.
        let spinner = load_fixture_file("looping-describe");
        let spinner_preflight = must(preflight_bytes(&spinner));
        let spinner_limits = default_experimental_limits(spinner_preflight.digest.clone());
        // Which typed cause is expected is decided by the admitted policy, not
        // forced by this test: the default experimental envelope selects
        // `EpochAndFuel`, so the store is fuel-metered and the endless loop
        // raises the engine's own out-of-fuel trap.
        assert_eq!(
            spinner_limits.epoch.cancellation,
            eliot_wasm_runtime::CancellationPolicy::EpochAndFuel
        );
        let spinner_kit = world_kit(TypedWorld::DreamerCycle, &spinner);
        let spinner_capsule =
            world_capsule(TypedWorld::DreamerCycle, &spinner_kit, &spinner_limits);
        let Err(denial) = execute_capsule_domain_experimental(
            &spinner_kit,
            &spinner_capsule,
            &spinner,
            &spinner_limits,
            &world_request(TypedWorld::DreamerCycle, &admitted),
            &admitted,
        ) else {
            panic!("#758/17 a terminated guest must not produce a terminal result");
        };

        // EXECUTED VALUE TWO: a staged typed denial naming the engine
        // termination that actually happened, at the stage it reached. It is
        // not a `GuestError`, and there is no terminal result to read as one.
        let TypedExecutionError::Staged { stage, cause } = &denial else {
            panic!("#758/17 the trap denial must be staged, got {denial}");
        };
        assert_eq!(*stage, TypedStage::Descriptor);
        assert_eq!(
            **cause,
            TypedExecutionError::Engine(format!(
                "{:?}",
                eliot_wasm_runtime::EngineTermination::FuelExhausted
            ))
        );
        assert_eq!(denial.to_string(), "STAGE:descriptor:ENGINE:FuelExhausted");
        // The two branches are told apart by the EXECUTED VALUE alone, and the
        // thing that separates them is the SHAPE of what came back, not a string
        // comparison: the first branch had to destructure a retained
        // `GuestError` terminal result or panic, and this one had to destructure
        // a staged denial or panic. An earlier draft also asserted
        // `denial.to_string() != receipt.terminal` here; that was dead, because a
        // staged-denial rendering can never equal a terminal code, so it was
        // removed rather than left in as a check that cannot fail.
    }

    /// #758 case 16's host-lifting half, and P7.3 (a host-lifted result is
    /// length-bounded by the host's own ceiling, not accepted because it
    /// lifted): the REAL engine runs a checked-in component whose domain result
    /// carries MORE list items than the host admits, and the host REFUSES the
    /// result with its own typed denial at the stage the call reached.
    ///
    /// Only in-crate code can observe this, and for the same reachability
    /// reason as the marker-17 helper above: the ceilings live in the private
    /// `TypedBound`, which `execute_domain_lane` is the only caller of, and
    /// `mod typed_bindings` is private in `src/lib.rs`, so no `tests/` target
    /// can build the `TypedDomainRequest` those entries take. Nothing here
    /// reads any file's source text to decide which branch ran.
    fn assert_host_lifted_list_ceiling_denies_the_real_result() {
        // The checked-in hostile `dreamer-cycle` component: an honest fixture
        // except that its `step` export returns a 300-element `state.pending`.
        // Every earlier check passes — `describe` reports the frozen
        // descriptor, the result echoes the admitted operation id and fence
        // epoch, and the reported proof ceiling is the lowest — so the list
        // item ceiling is provably the denial and not a substitute for it.
        let world = TypedWorld::DreamerCycle;
        let artifact = load_fixture_file("host-lifting-list");
        let preflight = must(preflight_bytes(&artifact));
        let limits = default_experimental_limits(preflight.digest.clone());
        let kit = world_kit(world, &artifact);
        let capsule = world_capsule(world, &kit, &limits);
        let admitted = admitted_record();

        // A returned result is a failure here: an over-long lifted list must be
        // refused, never handed back as a terminal result.
        let Err(denial) = execute_capsule_domain_experimental(
            &kit,
            &capsule,
            &artifact,
            &limits,
            &world_request(world, &admitted),
            &admitted,
        ) else {
            panic!("#758/16 a lifted list above the item ceiling must be denied");
        };

        // EXECUTED VALUE: the host's own item ceiling, at the stage this one
        // call reached. `TypedBound::list` refuses `count > MAX_TYPED_LIST_ITEMS`
        // with `LimitDenied("typed-list")`, and `execute_domain_lane` stages it
        // at `Output`. The destructure below is what proves this is the host's
        // own ceiling and not an engine or resource termination: only a
        // `Staged` denial can reach these assertions at all, and the cause is
        // then compared against the exact production value. An earlier draft
        // also asserted `!matches!(&denial, Engine(_))` here; that was dead,
        // because the narrowing had already happened, so it was removed rather
        // than left in as a check that can never fail.
        let TypedExecutionError::Staged { stage, cause } = &denial else {
            panic!("#758/16 the lifted-list denial must be staged, got {denial}");
        };
        assert_eq!(*stage, TypedStage::Output);
        assert_eq!(
            **cause,
            TypedExecutionError::LimitDenied("typed-list".to_owned())
        );
        assert_eq!(denial.to_string(), "STAGE:output:LIMIT_DENIED:typed-list");

        // POSITIVE CONTROL, so the assertion above cannot pass for the wrong
        // reason: the same world, the same kit-owned entry, the same admitted
        // envelope and the same ceiling over that world's honest checked-in
        // fixture. Its `step` result leaves `state.pending` unwritten, so the
        // very same `TypedBound::list` accepts it and the one call completes.
        let honest = load_fixture(world);
        let honest_preflight = must(preflight_bytes(&honest));
        let honest_limits = default_experimental_limits(honest_preflight.digest.clone());
        let honest_kit = world_kit(world, &honest);
        let honest_capsule = world_capsule(world, &honest_kit, &honest_limits);
        let (_receipt, result, _) = must(
            execute_capsule_domain_experimental(
                &honest_kit,
                &honest_capsule,
                &honest,
                &honest_limits,
                &world_request(world, &admitted),
                &admitted,
            )
            .map_err(|error| error.to_string()),
        );

        let TypedDomainResult::Outcome(outcome) = &result else {
            panic!("#758/16 an in-ceiling lifted list must be the retained outcome");
        };
        let TypedDomainOutcome::DreamerCycle(outcome) = outcome.as_ref() else {
            panic!("#758/16 the retained outcome must be this world's cycle outcome");
        };
        let cycle_wit::CycleOutcome::Stepped(stepped) = &**outcome;
        // The control's EXECUTED item count: empty, so inside the same ceiling
        // the denial above turns on. Read from the retained result, not from
        // the fixture text.
        assert!(stepped.state.pending.is_empty());
    }

    /// #758 item 9 / P6.2's string half, the sibling of the lifted-list leg
    /// above: the REAL engine runs a checked-in component whose domain result
    /// carries a lifted string LONGER than the host admits per string, and the
    /// host REFUSES the result with its own typed denial at the stage the call
    /// reached. The list leg proves the item ceiling; this leg proves the
    /// per-string ceiling next to it, which is a distinct production value
    /// (`MAX_TYPED_STRING_BYTES`, :50) refusing through a distinct production
    /// branch (`TypedBound::text`, :845-853).
    ///
    /// Only in-crate code can observe this, for the same reachability reason as
    /// the leg above: both ceilings live in the private `TypedBound`, whose
    /// only caller is `execute_domain_lane` (:2085), and `mod typed_bindings` is
    /// private in `src/lib.rs`, so no `tests/` target can build the
    /// `TypedDomainRequest` those entries take. Nothing here reads any file's
    /// source text to decide which branch ran.
    fn assert_host_lifted_string_ceiling_denies_the_real_result() {
        // The checked-in hostile `dreamer-cycle` component: an honest fixture
        // except that its `step` export returns a 4097-byte
        // `state.state-digest`, exactly one byte above the host's per-string
        // ceiling. Every earlier check passes — `describe` reports the frozen
        // descriptor, the result echoes the admitted operation id and fence
        // epoch, the reported proof ceiling is the lowest, and every list leaf
        // is empty — so within `check_cycle_result` (:3622-3649) the only
        // charge before the string is the two-byte echoed `operation-id`, and
        // the per-string ceiling is provably the denial and not a substitute
        // for it.
        let world = TypedWorld::DreamerCycle;
        let artifact = load_fixture_file("host-lifting-string");
        let preflight = must(preflight_bytes(&artifact));
        let limits = default_experimental_limits(preflight.digest.clone());
        let kit = world_kit(world, &artifact);
        let capsule = world_capsule(world, &kit, &limits);
        let admitted = admitted_record();

        // A returned result is a failure here: an over-long lifted string must
        // be refused, never handed back as a terminal result.
        let Err(denial) = execute_capsule_domain_experimental(
            &kit,
            &capsule,
            &artifact,
            &limits,
            &world_request(world, &admitted),
            &admitted,
        ) else {
            panic!("#758/9 a lifted string above the string ceiling must be denied");
        };

        // EXECUTED VALUE: the host's own per-string ceiling, at the stage this
        // one call reached. `TypedBound::text` refuses
        // `value.len() > MAX_TYPED_STRING_BYTES` with
        // `LimitDenied("typed-string")`, and `execute_domain_lane` stages the
        // `check_result` failure at `Output`. The destructure below is what
        // proves this is the host's own per-string ceiling rather than the
        // adjacent list-item ceiling above or an engine termination: only a
        // `Staged` denial reaches these assertions at all, the stage pins
        // where it was refused, and the cause is then compared against the
        // exact production value.
        let TypedExecutionError::Staged { stage, cause } = &denial else {
            panic!("#758/9 the lifted-string denial must be staged, got {denial}");
        };
        assert_eq!(*stage, TypedStage::Output);
        assert_eq!(
            **cause,
            TypedExecutionError::LimitDenied("typed-string".to_owned())
        );
        // The exact rendered denial. It is compared whole, so it already proves this
        // is not the adjacent lifted-list ceiling's `typed-list` rendering; no
        // second assertion against that string is added here, because this
        // equality can never leave it able to fail.
        let rendered = denial.to_string();
        assert_eq!(rendered, "STAGE:output:LIMIT_DENIED:typed-string");

        // POSITIVE CONTROL, so the assertion above cannot pass for the wrong
        // reason: the same world, the same kit-owned entry, the same admitted
        // envelope and the same ceiling over that world's honest checked-in
        // fixture. Its `step` result leaves `state.state-digest` short, so the
        // very same `TypedBound::text` accepts it and the one call completes.
        let honest = load_fixture(world);
        let honest_preflight = must(preflight_bytes(&honest));
        let honest_limits = default_experimental_limits(honest_preflight.digest.clone());
        let honest_kit = world_kit(world, &honest);
        let honest_capsule = world_capsule(world, &honest_kit, &honest_limits);
        let (_receipt, result, _) = must(
            execute_capsule_domain_experimental(
                &honest_kit,
                &honest_capsule,
                &honest,
                &honest_limits,
                &world_request(world, &admitted),
                &admitted,
            )
            .map_err(|error| error.to_string()),
        );

        let TypedDomainResult::Outcome(outcome) = &result else {
            panic!("#758/9 an in-ceiling lifted string must be the retained outcome");
        };
        let TypedDomainOutcome::DreamerCycle(outcome) = outcome.as_ref() else {
            panic!("#758/9 the retained outcome must be this world's outcome");
        };
        let cycle_wit::CycleOutcome::Stepped(stepped) = &**outcome;
        // The control's EXECUTED string length: this world's honest fixture
        // leaves `state.state-digest` unwritten, so the lifted value is empty
        // and inside the very same ceiling the denial above turns on. Read
        // from the retained result, not from the fixture text.
        assert!(stepped.state.state_digest.is_empty());
        // Every other charged string leaf of this world is echoed from the
        // admitted envelope, so the control's whole charged string set is
        // inside the ceiling the denial above exceeded.
        assert_eq!(stepped.operation_id.as_str(), OPERATION_ID);
        assert_eq!(stepped.state.fence_epoch.as_str(), FENCE_EPOCH);
    }

    /// The identity-echo REFUSAL half, the `operation-id` case: the REAL engine
    /// runs a checked-in `dreamer-cycle` component that keeps every request-side
    /// value honest but returns a FOREIGN `operation-id` in its result record,
    /// and the host must DENY the result with its own typed denial at the
    /// `Output` stage.
    ///
    /// This is the half no earlier leg proves. Every checked-in fixture the
    /// six-world drive executes echoes the admitted identity honestly, so the
    /// `check_echo` call sites were previously shown to EXECUTE but never to
    /// DENY. The gate under test is `check_echo` (:907-916), whose whole body
    /// is `if observed != admitted { return Err(OutputViolation(field)) }` —
    /// the audit's governing point being that a predictable name is not
    /// ownership, so only a foreign value exercises it.
    ///
    /// The production path, in call order:
    ///   - `check_cycle_result` (:3622) is selected by `check_result`'s
    ///     `TypedDomainOutcome::DreamerCycle` arm (:3450) and binds
    ///     `let R::Stepped(body) = value;` (:3628);
    ///   - `check_echo(&body.operation_id, &admitted.operation_id,
    ///     "operation-id")?` at :3629 is the comparison that fires, returning
    ///     `TypedExecutionError::OutputViolation("operation-id")`;
    ///   - `execute_domain_lane` stages that failure at `TypedStage::Output`
    ///     through `staged` (:2130-2131, `staged` at :797-806), producing
    ///     `Staged { stage: Output, cause: Box::new(OutputViolation(..)) }` —
    ///     note the `Box` on the cause field (:303).
    ///
    /// Nothing here reads the fixture's source text to decide which branch ran:
    /// the branch is fixed by the destructuring `let Err(denial) = .. else`,
    /// and every asserted value is the typed denial the host itself returned.
    ///
    /// Only in-crate code can observe this, for the same reachability reason as
    /// the lifted-listing legs above: `check_result`'s echo gate is reached only
    /// through `execute_domain_lane`, and `mod typed_bindings` is private in
    /// `src/lib.rs`, so no `tests/` target can build the `TypedDomainRequest`
    /// both domain entries require.
    fn assert_foreign_result_operation_id_is_denied_by_the_echo_gate() {
        // The checked-in hostile `dreamer-cycle` component. HONEST: the request
        // side (the host builds that record from the admitted envelope, and
        // `bound_dreamer_cycle_request`'s own `check_echo` sites pass), the
        // `describe` export (copied verbatim from the honest sibling), and the
        // result's `state.fence-epoch`, which this fixture still echoes out of
        // the lowered request (`foreign-result-operation-id.wat:336-337`).
        // FOREIGN: exactly one store pair, `cycle-step-result.operation-id`,
        // which the fixture fills from its own 36-byte data-segment literal
        // instead of the request (`foreign-result-operation-id.wat:313-314`,
        // literal at :345). Because the forgery is result-side only, the first
        // check that can fail is the :3629 echo comparison and not an earlier
        // request-path check.
        let world = TypedWorld::DreamerCycle;
        let artifact = load_fixture_file("foreign-result-operation-id");
        let preflight = must(preflight_bytes(&artifact));
        let limits = default_experimental_limits(preflight.digest.clone());
        let kit = world_kit(world, &artifact);
        let capsule = world_capsule(world, &kit, &limits);
        let admitted = admitted_record();

        // A returned result is a failure here. The binding is what excludes
        // every other outcome, not a later check: a guest's own typed `Err` is
        // NOT an `Err` from this entry at all (`check_result` returns `Ok(())`
        // for `GuestError`, :3454, so it is handed back as a retained terminal
        // result), a trap is a staged `Engine` cause, and host success is the
        // `Ok` arm this `let .. else` rejects.
        let Err(denial) = execute_capsule_domain_experimental(
            &kit,
            &capsule,
            &artifact,
            &limits,
            &world_request(world, &admitted),
            &admitted,
        ) else {
            panic!("#758/3 a foreign result operation-id must be denied, not returned");
        };

        // EXECUTED VALUE: the host's own echo-ownership denial, whole. Only a
        // `Staged` denial reaches these assertions at all, and both halves are
        // compared against the exact production values rather than a wildcard,
        // so a generic denial, a wrongly staged denial, or the adjacent
        // lifted-list/string `LimitDenied` ceilings cannot satisfy them.
        assert_eq!(
            denial,
            TypedExecutionError::Staged {
                stage: TypedStage::Output,
                cause: Box::new(TypedExecutionError::OutputViolation(
                    "operation-id".to_owned()
                )),
            }
        );
        // The exact rendering, derived from the production `Display` impls and
        // not guessed: `Staged` renders `STAGE:{stage}:{cause}` (:323),
        // `OutputViolation` renders `OUTPUT_VIOLATION:{reason}` (:322), and
        // `TypedStage::Output` renders `output` (as_str, :133).
        assert_eq!(
            denial.to_string(),
            "STAGE:output:OUTPUT_VIOLATION:operation-id"
        );

        // POSITIVE CONTROL, so the denial above cannot pass for the wrong
        // reason: the same world, the same kit-owned entry, the same admitted
        // envelope over that world's HONEST checked-in fixture, whose `step`
        // result echoes the admitted operation id out of the request. The very
        // same `check_echo` at :3629 therefore accepts it and the one call
        // completes.
        let honest = load_fixture(world);
        let honest_preflight = must(preflight_bytes(&honest));
        let honest_limits = default_experimental_limits(honest_preflight.digest.clone());
        let honest_kit = world_kit(world, &honest);
        let honest_capsule = world_capsule(world, &honest_kit, &honest_limits);
        let (_receipt, result, _) = must(
            execute_capsule_domain_experimental(
                &honest_kit,
                &honest_capsule,
                &honest,
                &honest_limits,
                &world_request(world, &admitted),
                &admitted,
            )
            .map_err(|error| error.to_string()),
        );
        let TypedDomainResult::Outcome(outcome) = &result else {
            panic!("#758/3 an honestly echoed operation-id must be the retained outcome");
        };
        let TypedDomainOutcome::DreamerCycle(outcome) = outcome.as_ref() else {
            panic!("#758/3 the retained outcome must be this world's cycle outcome");
        };
        let cycle_wit::CycleOutcome::Stepped(stepped) = &**outcome;
        // Read from the retained result, not from the fixture text: the honest
        // fixture's returned operation id, which the same gate accepted.
        assert_eq!(stepped.operation_id.as_str(), OPERATION_ID);
    }

    /// The identity-echo REFUSAL half, the `scope-id` case, and deliberately a
    /// DIFFERENT world and a DIFFERENT production call site from the
    /// `operation-id` case above: the REAL engine runs a checked-in
    /// `memory-curation-screen` component that keeps every request-side value
    /// honest but returns a FOREIGN `scope-id`, and the host must DENY it with
    /// its own typed denial at `Output`.
    ///
    /// It is a separate world on purpose. `check_echo` has 37 call sites in
    /// production, spread over the six per-world request binders and the six
    /// per-world `check_*_result` functions, and one world's denial says
    /// nothing about the other five; this case therefore also covers
    /// `scope-id`, which the six-world drive never asserts at all because
    /// `TypedReceipt` has no `scope_id` field to carry it.
    ///
    /// The production path:
    ///   - `check_screen_result` (:3596) is selected by `check_result`'s
    ///     `TypedDomainOutcome::MemoryCurationScreen` arm (:3447) and binds
    ///     `let R::Screened(body) = value;` (:3602);
    ///   - `check_echo(&body.scope_id, &admitted.scope_id, "scope-id")?` at
    ///     :3605 fires, returning
    ///     `TypedExecutionError::OutputViolation("scope-id")`;
    ///   - `execute_domain_lane` stages it at `TypedStage::Output`
    ///     (:2130-2131), giving `Staged { stage: Output, cause: Box::new(..) }`.
    ///
    /// The forged field is the LAST of the four echoes this world makes, so
    /// the three honest echoes ahead of it (:3603 operation-id, :3604 task-id)
    /// prove the gate was reached with everything else already accepted — the
    /// `scope-id` gate specifically is what refuses, not a substitute.
    ///
    /// Only in-crate code can observe this, for the same reachability reason as
    /// the leg above.
    fn assert_foreign_result_scope_id_is_denied_by_the_echo_gate() {
        // HONEST: the request side, the `describe` export, and the result's
        // `operation-id`, `task-id` and `fence-epoch`, all echoed out of the
        // lowered request
        // (`foreign-result-scope-id.wat:331-342` and :356-361). FOREIGN:
        // exactly one store pair, `screen-result-body.scope-id`, filled from
        // this fixture's own 32-byte data-segment literal instead of the
        // request (`foreign-result-scope-id.wat:354-355`, literal at :369).
        let world = TypedWorld::MemoryCurationScreen;
        let artifact = load_fixture_file("foreign-result-scope-id");
        let preflight = must(preflight_bytes(&artifact));
        let limits = default_experimental_limits(preflight.digest.clone());
        let kit = world_kit(world, &artifact);
        let capsule = world_capsule(world, &kit, &limits);
        let admitted = admitted_record();

        // Same binding as the case above, and for the same reasons: a guest
        // typed `Err` is a retained result rather than an `Err` from this entry
        // (:3454), a trap stages an `Engine` cause, and the `Ok` arm is the one
        // this `let .. else` rejects.
        let Err(denial) = execute_capsule_domain_experimental(
            &kit,
            &capsule,
            &artifact,
            &limits,
            &world_request(world, &admitted),
            &admitted,
        ) else {
            panic!("#758/4 a foreign result scope-id must be denied, not returned");
        };

        assert_eq!(
            denial,
            TypedExecutionError::Staged {
                stage: TypedStage::Output,
                cause: Box::new(TypedExecutionError::OutputViolation("scope-id".to_owned())),
            }
        );
        // The exact rendering, from the same production `Display` impls (:322,
        // :323 and `TypedStage::as_str`, :133).
        assert_eq!(denial.to_string(), "STAGE:output:OUTPUT_VIOLATION:scope-id");

        // POSITIVE CONTROL over this world's honest fixture, so the denial
        // above cannot pass for the wrong reason: its `screen` result echoes all
        // four identity fields honestly, so the very same `check_screen_result`
        // accepts it and the one call completes.
        let honest = load_fixture(world);
        let honest_preflight = must(preflight_bytes(&honest));
        let honest_limits = default_experimental_limits(honest_preflight.digest.clone());
        let honest_kit = world_kit(world, &honest);
        let honest_capsule = world_capsule(world, &honest_kit, &honest_limits);
        let (_receipt, result, _) = must(
            execute_capsule_domain_experimental(
                &honest_kit,
                &honest_capsule,
                &honest,
                &honest_limits,
                &world_request(world, &admitted),
                &admitted,
            )
            .map_err(|error| error.to_string()),
        );
        let TypedDomainResult::Outcome(outcome) = &result else {
            panic!("#758/4 an honestly echoed scope-id must be the retained outcome");
        };
        let TypedDomainOutcome::MemoryCurationScreen(outcome) = outcome.as_ref() else {
            panic!("#758/4 the retained outcome must be this world's screen outcome");
        };
        let screen_wit::ScreenOutcome::Screened(screened) = &**outcome;
        // Read from the retained result, not from the fixture text: the honest
        // fixture's returned scope id, which the same gate accepted.
        assert_eq!(screened.scope_id.as_str(), SCOPE_ID);
    }

    use super::check_cache_identity;
    use eliot_wasm_runtime::component_contract::TYPED_ABI_REVISION;

    /// The three DERIVED slots of one cache identity — engine configuration,
    /// frozen ABI binding and admitted policy — re-derived here from the
    /// documented composition and from nothing else.
    ///
    /// INDEPENDENCE, stated exactly. This function calls NONE of the five
    /// production functions that build the cache identity, and that is the
    /// whole point:
    ///
    ///   - not `TypedCacheIdentity::digest` (src/typed_execution.rs:617-627),
    ///     the five-slot composition the enclosing `assert_eq!` is about;
    ///   - not `typed_cache_identity` (:696-709), the binder that fills the
    ///     struct's five fields;
    ///   - not `typed_engine_configuration_digest` (:639-650);
    ///   - not `typed_policy_digest` (:656-678);
    ///   - not `typed_abi_digest` (:683-692).
    ///
    /// Each canonical descriptor below is re-written from what the production
    /// doc comments state it binds — :592-599 for the identity as a whole,
    /// :630-634 engine version/config/target, :652-655 the limit/policy
    /// envelope and its allow-list, :680-682 world/package/revision/WIT — and
    /// hashed with the SAME primitive production uses
    /// (`Sha256Digest::of_bytes`,
    /// crates/modules/eliot-wasm-runtime/src/types.rs:89). Sharing the hash
    /// primitive is deliberate and is not the sharing that would make this a
    /// tautology: the claim under test is WHICH BYTES ARE COMPOSED, not
    /// whether a hash function is available. If any of those five functions
    /// were called here, both sides of the `assert_eq!` would be the same
    /// value and the assertion could not fail.
    ///
    /// WHICH CONSTANT EACH SIDE READS. `wasmtime=` is the independent
    /// `crate::contour::PINNED_WASMTIME_VERSION` (src/contour.rs:49) — the
    /// package's own I14.19 baseline pin — NOT this file's `ENGINE_VERSION`
    /// (:40), which is a second declaration of the same generation.
    /// `max_wasm_stack=` reads the provider's own
    /// `crate::wasmtime_provider::PROVIDER_STACK_SIZE`
    /// (`src/wasmtime_provider.rs:29`), the constant the fresh engine is
    /// actually configured with (`src/wasmtime_provider.rs:804`). PRODUCTION
    /// READS A DIFFERENT DECLARATION: the bare `PROVIDER_STACK_SIZE` in its own
    /// format string (:641) resolves to this file's `const PROVIDER_STACK_SIZE: u64` at :41,
    /// not to the provider's `usize` at `wasmtime_provider.rs:29`. Both hold
    /// 8192 today, so the assertion passes, but drift in :41 ALONE would not
    /// fail it - so this is a cross-declaration comparison, not a proof that
    /// production and this expectation read one owner.
    /// `package=`, `wit=` and `abi_revision=` are the frozen identity owners:
    /// `crate::typed_bindings::TYPED_PACKAGE_ID` (`src/typed_bindings.rs:24`),
    /// `typed_wit_digest` (`src/typed_bindings.rs:193`) and
    /// `eliot_wasm_runtime::component_contract::TYPED_ABI_REVISION`
    /// (crates/modules/eliot-wasm-runtime/src/component_contract.rs:24). Each
    /// is an identity the composition CLAIMS to bind, owned outside the
    /// function under test.
    ///
    /// STATED LIMIT, not papered over: the memory- and table-COUNT ceilings
    /// (`memories=`, `tables=`) have no second declaration anywhere in the
    /// package, so this expected value reads the same two constants
    /// production reads (:55, :58). Drift in those two numbers ALONE would not
    /// fail this assertion. It does not touch the claim under test, which is
    /// the five-slot composition and its binding, and the engine-executed leg
    /// below is what the composition is compared against in production.
    fn expected_cache_identity_slots(
        world: TypedWorld,
        limits: &InvocationLimits,
    ) -> (Sha256Digest, Sha256Digest, Sha256Digest) {
        // `consume_fuel=` re-derived from the admitted cancellation policy
        // directly, matching `typed_fuel_budget`'s own two-arm match
        // (:1407-1412) without calling it.
        let engine = Sha256Digest::of_bytes(
            format!(
                "typed-engine/v1;wasmtime={version};target={os}/{arch};component_model=true;consume_fuel={consume};epoch_interruption=true;max_wasm_stack={stack};memories={memories};tables={tables};memory_bytes={memory};table_elements={table_elements};instances={instances}",
                version = PINNED_WASMTIME_VERSION,
                os = std::env::consts::OS,
                arch = std::env::consts::ARCH,
                consume = matches!(
                    limits.epoch.cancellation,
                    eliot_wasm_runtime::CancellationPolicy::EpochAndFuel
                ),
                stack = crate::wasmtime_provider::PROVIDER_STACK_SIZE,
                memories = super::MAX_TYPED_MEMORIES,
                tables = super::MAX_TYPED_TABLES,
                memory = limits.max_memory_bytes,
                table_elements = limits.max_table_elements,
                instances = limits.max_instances,
            )
            .as_bytes(),
        );

        // Every scalar ceiling plus the allow-listed artifact digests, which
        // `artifact_access.allowed_digests` keeps in sorted order
        // (crates/modules/eliot-wasm-runtime/src/types.rs:244, a `BTreeSet`),
        // so this iteration is the same deterministic one production performs.
        let mut policy_descriptor = format!(
            "typed-policy/v1;max_input_bytes={};max_output_bytes={};max_host_calls={};max_fuel={};max_memory_bytes={};max_table_elements={};max_instances={};max_stack_bytes={};wall_deadline_ms={};epoch_deadline_ticks={};epoch_cancellation={:?};artifact_max_reads={};artifact_max_bytes={}",
            limits.max_input_bytes,
            limits.max_output_bytes,
            limits.max_host_calls,
            limits.max_fuel,
            limits.max_memory_bytes,
            limits.max_table_elements,
            limits.max_instances,
            limits.max_stack_bytes,
            limits.wall_deadline_ms,
            limits.epoch.deadline_ticks,
            limits.epoch.cancellation,
            limits.artifact_access.max_reads,
            limits.artifact_access.max_bytes,
        );
        for digest in &limits.artifact_access.allowed_digests {
            policy_descriptor.push(';');
            policy_descriptor.push_str(digest.as_str());
        }
        let policy = Sha256Digest::of_bytes(policy_descriptor.as_bytes());

        let abi = Sha256Digest::of_bytes(
            format!(
                "typed-abi/v1;world={};package={};abi_revision={};wit={}",
                world.world_name(),
                TYPED_PACKAGE_ID,
                TYPED_ABI_REVISION,
                typed_wit_digest().as_str(),
            )
            .as_bytes(),
        );
        (engine, abi, policy)
    }

    /// The WHOLE documented cache identity, re-derived: artifact digest, exact
    /// artifact length, and the three derived slots above, folded into the
    /// labelled five-slot form at :618-626. Calls
    /// [`expected_cache_identity_slots`] and the hash primitive, and no
    /// production identity function at all.
    fn expected_cache_identity(
        world: TypedWorld,
        artifact_digest: &Sha256Digest,
        artifact_bytes: u64,
        limits: &InvocationLimits,
    ) -> Sha256Digest {
        let (engine, abi, policy) = expected_cache_identity_slots(world, limits);
        Sha256Digest::of_bytes(
            format!(
                "758-typed-cache-identity|{artifact}|{bytes}|{engine}|{abi}|{policy}",
                artifact = artifact_digest.as_str(),
                bytes = artifact_bytes,
                engine = engine.as_str(),
                abi = abi.as_str(),
                policy = policy.as_str(),
            )
            .as_bytes(),
        )
    }

    /// #758 marker 22's EXECUTED half: what the cache identity IS, not only
    /// that each input changes it. The marker stays in the acceptance file
    /// `tests/typed_execution.rs` (where five `assert_ne!` legs and five
    /// source-text assertions cover case 22); this is the half only in-crate
    /// code can run, for the same reachability reason as the marker-17 and
    /// marker-16 helpers above: `check_cache_identity`, the private
    /// `TypedCacheIdentity`, and the generated per-world request records both
    /// domain entries require are all reachable only from this crate.
    ///
    /// The differential legs in the acceptance file cannot distinguish a
    /// CORRECT composition from any other function of the same five inputs
    /// that also changes — one that omits a slot, reorders two, or binds the
    /// wrong value passes all five of them. This helper closes that by
    /// comparing the production value against a value computed independently,
    /// whole, with `assert_eq!`.
    fn assert_cache_identity_is_the_documented_composition() {
        assert_cache_identity_over_every_frozen_world();
        assert_cache_identity_artifact_slot_through_the_real_engine();
        assert_cache_identity_abi_world_slot_at_the_gate();
    }

    /// Leg one, and the two wrong compositions this leg is checked AGAINST
    /// rather than merely next to: for EVERY frozen world, over its own
    /// checked-in real component, the identity production's own revalidation
    /// gate builds is equal to the value re-derived here from the documented
    /// composition, which is the whole of what distinguishes a CORRECT fold
    /// from any other function of the same five inputs that also changes.
    fn assert_cache_identity_over_every_frozen_world() {
        // Leg one: for EVERY frozen world, over its own checked-in real
        // component, the identity production's own revalidation gate builds is
        // equal to the value re-derived from the documented composition.
        //
        // The production side is `check_cache_identity` (:722-742), not a
        // hand-built struct: it is the gate the domain lane executes at :2114
        // before any engine exists, and it re-hashes the presented buffer
        // independently of preflight (:728) and refuses a buffer outside the
        // admitted allow-list (:734). So the value compared here is the value
        // the receipt binds at :2152.
        for world in TypedWorld::all() {
            let artifact = load_fixture(world);
            let preflight = must(preflight_bytes(&artifact));
            let limits = default_experimental_limits(preflight.digest.clone());
            let identity = must(
                check_cache_identity(world, &artifact, &preflight.digest, &limits)
                    .map_err(|error| error.to_string()),
            );
            assert_eq!(
                identity.digest(),
                expected_cache_identity(world, &preflight.digest, preflight.byte_len, &limits),
                "#758/22 {} cache identity is not the documented composition",
                world.world_name(),
            );
            // The two artifact slots are the ones production takes from the
            // presented buffer itself. Of the two, only the LENGTH assertion can fail:
            // `identity.artifact` is already forced equal to the re-hash at
            // :729-733, which returns `Err` before this point, so comparing it
            // again here would be a check that cannot fail. `identity.artifact_bytes`
            // is a SEPARATE measurement (:739) and is asserted below.
            assert_eq!(identity.artifact_bytes, preflight.byte_len);
        }

        // The comparison above can tell a correct composition from a wrong one,
        // which the differential `assert_ne!` legs in the acceptance file
        // cannot. The two wrong compositions a reader should have expected to
        // see rejected here are the ABI and policy slots SWAPPED, and the
        // artifact-LENGTH slot OMITTED. Each is built in THIS module rather
        // than produced by production, and each differs STRUCTURALLY from the
        // composition production folds — four separators against five, and two
        // slots transposed — so an inequality between such a value and a
        // production identity holds for EVERY possible production state and
        // CANNOT fail. Production folds its own five slots in
        // `impl TypedCacheIdentity { fn digest }`, so a composition that really
        // did swap those slots or drop the length slot folds a different
        // digest, fails the whole-value `assert_eq!` against
        // `expected_cache_identity` in the loop above, and makes either
        // inequality a corollary of that failure rather than evidence for it.
        // The pair of `assert_ne!` that stood here is therefore REMOVED rather
        // than relabelled, for the same reason the pairwise receipt comparison
        // in `assert_cache_identity_abi_world_slot_at_the_gate` was: a
        // comparison that follows from another comparison can only ever repeat
        // it. The `swapped` and `omitted` values go with it, because a value
        // built only as an operand of an assertion that cannot fail carries no
        // evidence of its own and would only be dead weight here.
        //
        // WHAT CARRIES THE OBLIGATION. The whole-value `assert_eq!` in the loop
        // above, for EVERY frozen world and over production's own gate output.
        // `TypedWorld::ContextAdmission` is the first of the six in
        // `TypedWorld::all()`, so the world these two compositions were built
        // over is already bound there to a value re-derived from the documented
        // five-slot composition. What the two wrong compositions now document
        // is which folds a reader should have expected here, and that they
        // were considered.
    }

    /// Leg two, kept as its own function so each leg's proof ceiling is legible
    /// on its own rather than buried in one oversized body.
    fn assert_cache_identity_artifact_slot_through_the_real_engine() {
        // Leg two: the ARTIFACT slot, ISOLATED and executed through the REAL
        // engine. One world, ONE admitted envelope admitting both measured
        // digests, two different real checked-in components — so the world
        // slot and the policy slot are byte-identical on both calls and the
        // artifact pair is the only input that can differ. Both receipts come
        // from a real Wasmtime instantiation of the buffer whose identity is
        // being compared; nothing here re-hashes a string in the test to get
        // the receipt.
        let screen = TypedWorld::MemoryCurationScreen;
        let honest = load_fixture(screen);
        let altered = load_fixture_file("guest-typed-error");
        let honest_preflight = must(preflight_bytes(&honest));
        let altered_preflight = must(preflight_bytes(&altered));
        // The artifact PAIR is what differs, and the digest half of that pair
        // is what proves it: two different component buffers hash to two
        // different digests. The length half is not separately asserted to
        // differ, because nothing observed here can execute-verify that the
        // two buffers also differ in LENGTH, and asserting it would be a claim
        // this module cannot falsify on its own. The length slot is still bound
        // and still proven below: each executed receipt is compared against an
        // expected value carrying ITS OWN measured length, so a composition
        // that dropped or mis-bound `artifact_bytes` fails both of those.
        assert_ne!(honest_preflight.digest, altered_preflight.digest);
        // `default_experimental_limits` allow-lists exactly one measured digest
        // (:480); the second is added here so the POLICY slot is identical on
        // both calls. No ceiling is widened, relaxed or invented, and
        // `validate_limits` admits an allow-list that contains the presented
        // digest (:506).
        let mut shared_limits = default_experimental_limits(honest_preflight.digest.clone());
        shared_limits
            .artifact_access
            .allowed_digests
            .insert(altered_preflight.digest.clone());
        let admitted = admitted_record();
        let screen_request = world_request(screen, &admitted);

        let honest_kit = world_kit(screen, &honest);
        let honest_capsule = world_capsule(screen, &honest_kit, &shared_limits);
        let altered_kit = world_kit(screen, &altered);
        let altered_capsule = world_capsule(screen, &altered_kit, &shared_limits);

        let (honest_receipt, _, _) = must(
            execute_capsule_domain_experimental(
                &honest_kit,
                &honest_capsule,
                &honest,
                &shared_limits,
                &screen_request,
                &admitted,
            )
            .map_err(|error| error.to_string()),
        );
        let (altered_receipt, _, _) = must(
            execute_capsule_domain_experimental(
                &altered_kit,
                &altered_capsule,
                &altered,
                &shared_limits,
                &screen_request,
                &admitted,
            )
            .map_err(|error| error.to_string()),
        );
        // Each executed receipt really did compile the buffer whose identity it
        // binds, so the two identities below differ only in their artifact
        // pair.
        assert_eq!(honest_receipt.artifact_digest, honest_preflight.digest);
        assert_eq!(altered_receipt.artifact_digest, altered_preflight.digest);
        assert_ne!(
            honest_receipt.cache_identity,
            altered_receipt.cache_identity
        );
        // ... and each is equal to its OWN independently re-derived value, so
        // this leg is not a differential pair alone.
        assert_eq!(
            honest_receipt.cache_identity,
            expected_cache_identity(
                screen,
                &honest_preflight.digest,
                honest_preflight.byte_len,
                &shared_limits,
            )
        );
        assert_eq!(
            altered_receipt.cache_identity,
            expected_cache_identity(
                screen,
                &altered_preflight.digest,
                altered_preflight.byte_len,
                &shared_limits,
            )
        );
    }

    /// Leg three, the ABI/world slot isolated at the production gate. It is not
    /// reachable through the real engine for one buffer under two worlds, and
    /// that limit is stated rather than papered over.
    fn assert_cache_identity_abi_world_slot_at_the_gate() {
        // `admitted_record()` is a pure constructor over this module's own
        // constants, so it is bound here as well: each helper below is a
        // separate `fn` and shares no locals with its siblings.
        let admitted = admitted_record();
        // Leg three: the ABI/WORLD slot, ISOLATED at the production
        // revalidation gate. One artifact buffer and one admitted envelope,
        // two worlds, so the world is the only input that changes. This
        // reaches the same production call the engine lane executes at :2114.
        //
        // REACHABILITY, stated: this leg CANNOT be executed through the real
        // engine, and is not faked as if it could. Each checked-in fixture
        // exports exactly one world's interface, so driving one buffer under
        // two worlds is denied by `preflight_component_type`'s signature and
        // export checks (:2119) before any receipt exists. The isolated world
        // leg is therefore the production gate itself, plus the corroborating
        // engine leg below.
        let shared_artifact = load_fixture(TypedWorld::ContextAdmission);
        let shared_preflight = must(preflight_bytes(&shared_artifact));
        let shared_world_limits = default_experimental_limits(shared_preflight.digest.clone());
        let admission_identity = must(
            check_cache_identity(
                TypedWorld::ContextAdmission,
                &shared_artifact,
                &shared_preflight.digest,
                &shared_world_limits,
            )
            .map_err(|error| error.to_string()),
        );
        let cycle_identity = must(
            check_cache_identity(
                TypedWorld::DreamerCycle,
                &shared_artifact,
                &shared_preflight.digest,
                &shared_world_limits,
            )
            .map_err(|error| error.to_string()),
        );
        // Same buffer, so these two are NOT assertions about production: both
        // identities were built from `shared_artifact`, and comparing them
        // proves only that the gate is deterministic. They are kept as the
        // control that isolates the ABI slot, and are labelled as such rather
        // than counted as evidence.
        assert_eq!(admission_identity.artifact, cycle_identity.artifact);
        assert_eq!(
            admission_identity.artifact_bytes,
            cycle_identity.artifact_bytes
        );
        assert_ne!(admission_identity.digest(), cycle_identity.digest());
        // Which slot separates them, FROM THE TEST'S OWN RE-DERIVATION. This
        // compares `expected_cache_identity_slots` against itself, so it cannot
        // detect production putting the world name into the engine or policy
        // slot. Its value is documentary: it records that the re-derived
        // composition attributes the difference to the ABI slot. The production
        // comparison that decides that slot is NOT the isolated
        // `check_cache_identity` call above — that call only shows that two
        // production identities differ — but the whole-value `assert_eq!`
        // between the REAL-engine `cycle_receipt.cache_identity` and
        // `expected_cache_identity(cycle_world, ...)` at the end of this
        // function: production folds its own five slots in
        // `impl TypedCacheIdentity { fn digest }` - it pushes `self.artifact`,
        // `self.artifact_bytes`, `self.engine`, `self.abi` and `self.policy`
        // into one canonical buffer - so a world name in the engine or
        // policy slot changes that executed receipt value and fails that
        // assertion. There is deliberately no per-slot assertion against
        // production here: `pub struct TypedReceipt` carries only the folded
        // `pub cache_identity: Sha256Digest` field, and the per-slot values live
        // on the private `struct TypedCacheIdentity`, whose fields the domain
        // lane drops when it builds the receipt literal
        // (`cache_identity: cache_identity.digest()`). Cited by
        // SYMBOL and by quoted field name rather than by line number, because
        // this file is edited underneath these comments and a bare line range
        // goes stale silently.
        let (admission_engine, admission_abi, admission_policy) =
            expected_cache_identity_slots(TypedWorld::ContextAdmission, &shared_world_limits);
        let (cycle_engine, cycle_abi, cycle_policy) =
            expected_cache_identity_slots(TypedWorld::DreamerCycle, &shared_world_limits);
        assert_eq!(admission_engine, cycle_engine);
        assert_eq!(admission_policy, cycle_policy);
        assert_ne!(admission_abi, cycle_abi);

        // Corroborating WORLD leg executed through the REAL engine for a second
        // frozen world. It is NOT isolated — the two honest fixtures are
        // different components, so their artifact slots differ too — and it is
        // offered only as the executed counterpart of the isolated leg above.
        let cycle_world = TypedWorld::DreamerCycle;
        let cycle_artifact = load_fixture(cycle_world);
        let cycle_preflight = must(preflight_bytes(&cycle_artifact));
        let cycle_limits = default_experimental_limits(cycle_preflight.digest.clone());
        let cycle_kit = world_kit(cycle_world, &cycle_artifact);
        let cycle_capsule = world_capsule(cycle_world, &cycle_kit, &cycle_limits);
        let (cycle_receipt, _, _) = must(
            execute_capsule_domain_experimental(
                &cycle_kit,
                &cycle_capsule,
                &cycle_artifact,
                &cycle_limits,
                &world_request(cycle_world, &admitted),
                &admitted,
            )
            .map_err(|error| error.to_string()),
        );
        assert_eq!(cycle_receipt.world, cycle_world.world_name());
        // The second receipt is executed HERE rather than borrowed from the
        // sibling helper above, because separate `fn` items share no locals.
        // What the pair of receipts below carries is TWO SEPARATE EXECUTED
        // identities, each bound to its own re-derived whole value — NOT a
        // pairwise inequality between them: they are two DIFFERENT fixtures
        // (`cycle_artifact` and the admission fixture above) under two DIFFERENT
        // limit envelopes, so the artifact digest, the artifact length and the
        // policy slot already differ before any world is considered. Comparing
        // the two receipts to each other therefore cannot fail on account of the
        // world. The load-bearing assertions for that slot are the two whole-value
        // `assert_eq!` at the end of this function, one per executed receipt,
        // against `expected_cache_identity(cycle_world, ...)` and
        // `expected_cache_identity(admission_world, ...)`.
        let admission_world = TypedWorld::ContextAdmission;
        let admission_kit = world_kit(admission_world, &shared_artifact);
        let admission_capsule =
            world_capsule(admission_world, &admission_kit, &shared_world_limits);
        let (admission_receipt, _, _) = must(
            execute_capsule_domain_experimental(
                &admission_kit,
                &admission_capsule,
                &shared_artifact,
                &shared_world_limits,
                &world_request(admission_world, &admitted),
                &admitted,
            )
            .map_err(|error| error.to_string()),
        );
        // Same labelling rule as the two legs above, applied to the pair of
        // EXECUTED receipts: they were built from DIFFERENT fixtures under
        // DIFFERENT limits, so the artifact digest, the artifact length and the
        // policy slot differ before any world is considered. An `assert_ne!`
        // between the two identities therefore holds for every possible
        // production state: it is a COROLLARY of the two whole-value `assert_eq!`
        // below and not evidence for the abi/world slot. It is REMOVED rather
        // than relabelled, because a comparison that follows from two other
        // comparisons can only ever repeat them.
        //
        // What each executed receipt is instead bound to, on this reachable
        // seam, is its OWN whole value re-derived here from the documented
        // five-slot composition: this buffer's measured digest and length, the
        // three derived slots, and THIS world's abi slot. Both assertions can
        // fail. Production folds its own five slots in `impl TypedCacheIdentity
        // { fn digest }`, so a composition that put the world name in the engine
        // or policy slot, dropped the world, dropped the artifact-LENGTH slot or
        // transposed two slots would fold a different digest into the executed
        // receipt and fail the comparison here. The world therefore reaches the
        // receipt only through the abi slot, on the receipt the REAL engine
        // produced, with no fabricated flag, switch or test-only export.
        assert_eq!(
            cycle_receipt.cache_identity,
            expected_cache_identity(
                cycle_world,
                &cycle_preflight.digest,
                cycle_preflight.byte_len,
                &cycle_limits,
            )
        );
        assert_eq!(
            admission_receipt.cache_identity,
            expected_cache_identity(
                admission_world,
                &shared_preflight.digest,
                shared_preflight.byte_len,
                &shared_world_limits,
            )
        );
    }

    // No `WORK_UNIT_CASE` marker here on purpose: case 3 of #758 is marked once,
    // in the acceptance file `tests/typed_execution.rs`, so the declared
    // denominator stays exactly 1..26 with one marker per case. This in-crate
    // test is the half an integration test cannot reach: `mod typed_bindings`
    // is private in `src/lib.rs`, so only code inside this crate can build the
    // generated per-world request types and actually invoke
    // `execute_capsule_domain_experimental`.
    #[test]
    fn every_frozen_world_executes_its_real_domain_export_through_the_neutral_capsule() {
        let worlds = TypedWorld::all();
        let mut driven: Vec<&str> = Vec::new();

        for world in worlds {
            drive_world(world);
            driven.push(world.world_name());
        }

        // Denominator: all six frozen worlds ran, in contract order, once per
        // entry. No world is skipped, retried on another world, or served from
        // a cached compilation.
        assert_eq!(driven, worlds.map(TypedWorld::world_name).to_vec());

        // #758/17, in this same real-engine test because only in-crate code can
        // build the generated request records: a guest's own typed `Err` is an
        // EXECUTED outcome and a trap is a typed denial, told apart by the
        // executed value alone. The one marker for case 17 stays in
        // `tests/typed_execution.rs`.
        assert_guest_typed_error_is_a_distinct_executed_outcome_from_a_trap();
        // #758/16's host-lifting half and P7.3, in this same real-engine test
        // for the same reachability reason as the call above: only in-crate
        // code can build the generated request record that reaches the
        // host-lifting list ceiling, so both the lifted-list denial and its
        // in-ceiling positive control are executed here. The one marker for
        // case 16 stays in `tests/typed_execution.rs`.
        assert_host_lifted_list_ceiling_denies_the_real_result();
        // #758 item 9 / P6.2's per-string half, beside the call above for the
        // same reachability reason: only in-crate code can build the generated
        // request record that reaches the host-lifting per-string ceiling, so
        // both the lifted-string denial and its in-ceiling positive control
        // are executed here, next to the lifted-item denial they are distinct
        // from. No `WORK_UNIT_CASE` marker is added by this leg.
        assert_host_lifted_string_ceiling_denies_the_real_result();
        // The identity-echo REFUSAL halves, beside the calls above for the same
        // reachability reason: `check_echo` is reachable only through
        // `execute_domain_lane`, and `mod typed_bindings` is private in
        // `src/lib.rs`, so no `tests/` target can build the `TypedDomainRequest`
        // both domain entries require. Every checked-in fixture the six-world
        // drive executes echoes the admitted identity honestly, so without these
        // two legs the `check_echo` sites would be shown to execute but never
        // to deny. They run on two different worlds and two different
        // production call sites (`check_cycle_result`'s `operation-id` and
        // `check_screen_result`'s `scope-id`), each with its own exact typed
        // denial, exact rendering and honest-fixture positive control. The one
        // marker for case 3, and the one for case 4, both stay in
        // `tests/typed_execution.rs`; no `WORK_UNIT_CASE` marker is added here.
        assert_foreign_result_operation_id_is_denied_by_the_echo_gate();
        assert_foreign_result_scope_id_is_denied_by_the_echo_gate();
        // #758 marker 22's composition half, in this same real-engine test for
        // the same reachability reason as the calls above: the cache identity's
        // revalidation gate and the private `TypedCacheIdentity` are reachable
        // only in-crate. The one marker for case 22, and its five executed
        // `assert_ne!` legs, stay in `tests/typed_execution.rs`; what runs here
        // is the one thing those legs cannot do — the identity is compared to a
        // value re-derived from the documented composition WITHOUT calling
        // `digest`, `typed_cache_identity`, `typed_engine_configuration_digest`,
        // `typed_policy_digest` or `typed_abi_digest`, so a composition that
        // omitted a slot, swapped two or bound the wrong value fails here.
        // No `WORK_UNIT_CASE` marker is added by this leg.
        assert_cache_identity_is_the_documented_composition();
    }

    /// Real engine, real CHECKED-IN input: `instantiation-start-loop.wat` is a
    /// real `dreamer-cycle` component whose core module declares a
    /// `(start $init)` whose loop has no exit. Component initialization is
    /// untrusted execution and runs inside the same guarded envelope as the
    /// descriptor call, so the engine genuinely terminates this instantiation
    /// and the denial carries the SAME owner-typed terminal cause the later
    /// domain leg reports — not the untyped `instantiate:component-error`
    /// string the pinned trap message could never be told apart from any other
    /// unknown instantiation fault.
    #[test]
    fn nonterminating_component_initialization_denies_with_the_typed_fuel_cause() {
        let path = "tests/data/typed-components/instantiation-start-loop.wat";
        let spinner = match wat::parse_file(path) {
            Ok(bytes) => bytes,
            Err(error) => panic!("#758/13 fixture {path} must be a parseable component: {error}"),
        };
        let limits = default_experimental_limits(Sha256Digest::of_bytes(&spinner));

        // Which typed cause is asserted is decided by the admitted policy, not
        // forced by the test. The default experimental envelope selects
        // `EpochAndFuel` (`default_experimental_limits`), so
        // `typed_fuel_budget` arms the Store's fuel meter with `max_fuel` on
        // the fuel-meters engine leg, and the engine raises
        // `wasmtime::Trap::OutOfFuel`. The epoch driver also runs here, but its
        // 100-tick deadline needs 100ms of wall clock while a tight non-arming
        // loop burns the whole 50_000-fuel budget in a tiny fraction of that, so
        // fuel is what terminates this instantiation.
        assert_eq!(
            limits.epoch.cancellation,
            eliot_wasm_runtime::CancellationPolicy::EpochAndFuel
        );

        let Err(denial) =
            execute_describe_experimental(TypedWorld::DreamerCycle, &spinner, &limits)
        else {
            panic!("#758/13 a non-terminating start function must be denied");
        };

        // The staged attribution is unchanged: the call really did reach
        // instantiation and never reached `describe`.
        let TypedExecutionError::Staged { stage, cause } = &denial else {
            panic!("#758/13 the denial must be staged, got {denial}");
        };
        assert_eq!(*stage, TypedStage::Instantiate);
        assert_eq!(
            **cause,
            TypedExecutionError::Engine(format!(
                "{:?}",
                eliot_wasm_runtime::EngineTermination::FuelExhausted
            ))
        );
        assert_eq!(denial.to_string(), "STAGE:instantiate:ENGINE:FuelExhausted");

        // The untyped catch-all this used to produce is not reachable for a
        // fuel-terminated instantiation any more.
        assert_ne!(
            denial.to_string(),
            "STAGE:instantiate:ENGINE:instantiate:component-error"
        );
    }
}
