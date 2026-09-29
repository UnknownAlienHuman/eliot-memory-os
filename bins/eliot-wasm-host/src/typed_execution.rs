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
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use std::thread;
use std::time::{Duration, Instant};

use eliot_wasm_runtime::component_contract::{ProofCeiling, TYPED_ABI_REVISION};
use eliot_wasm_runtime::{
    CancellationPolicy, EngineTermination, EpochPolicy, InvocationLimits, MAX_EPOCH_DEADLINE_TICKS,
    Sha256Digest,
};

use crate::artifact_preflight::{PreflightError, preflight_bytes};
use crate::contour::CAPABILITY_INTRODUCTION_REQUIRED;
use crate::typed_bindings::{TypedWorld, typed_wit_digest};

const ENGINE_VERSION: &str = "47.0.4";
const PROVIDER_STACK_SIZE: u64 = 8 * 1024;
const MAX_DESCRIPTOR_STRING_BYTES: usize = 512;
/// Per-string ceiling for lifted typed input and output. Enforced before the
/// host lowers a request into guest memory and immediately after a guest
/// result is lifted, never only after the whole result exists.
const MAX_TYPED_STRING_BYTES: usize = 4_096;
/// Per-list ceiling for lifted typed input and output, counted in items.
const MAX_TYPED_LIST_ITEMS: usize = 256;
/// Memory-COUNT ceiling. `InvocationLimits` bounds memory bytes and instance
/// count but carries no memory count, so the Host fixes it here.
const MAX_TYPED_MEMORIES: usize = 1;
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
/// deterministic semantic digest.
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
    /// method is absent (canonical introduction-required denial).
    MissingExport(String),
    /// Actual forbidden import observed before instantiation: the empty
    /// linker introduces nothing (canonical introduction-required denial).
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
pub fn execute_governed_refusal() -> Result<(), TypedExecutionError> {
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
        || !limits.artifact_access.allowed_digests.contains(digest)
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

fn semantic_digest(
    world: TypedWorld,
    artifact_digest: &Sha256Digest,
    artifact_bytes: u64,
    output_digest: &Sha256Digest,
    output_bytes: u64,
    terminal: &str,
) -> Sha256Digest {
    let canonical = format!(
        "758|{}|{}|{artifact_bytes}|{}|{output_bytes}|{terminal}|{}",
        world.world_name(),
        artifact_digest.as_str(),
        output_digest.as_str(),
        typed_wit_digest().as_str()
    );
    Sha256Digest::of_bytes(canonical.as_bytes())
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
/// before the host lowers it into guest memory and a result is bounded while
/// its leaves are read. Nested records are bounded transitively by the store
/// memory ceiling, which is the total host-allocation policy the pinned typed
/// API offers for a not-yet-lifted result.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct TypedBound {
    bytes: u64,
    items: u64,
}

impl TypedBound {
    fn text(&mut self, value: &str) -> Result<(), TypedExecutionError> {
        if value.len() > MAX_TYPED_STRING_BYTES {
            return Err(TypedExecutionError::LimitDenied("typed-string".to_owned()));
        }
        self.bytes += u64::try_from(value.len()).unwrap_or(u64::MAX);
        self.items += 1;
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
        self.items = self.items.saturating_add(count);
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

/// Executes the typed `describe` descriptor for one world through the real
/// Wasmtime component engine under deny-by-default sandbox policy.
///
/// Reads nothing: the caller supplies the exact immutable buffer. The same
/// buffer is hashed (preflight) and compiled; the path is never reread.
/// Zero ambient imports, full resource limits, and output checks apply to
/// descriptor/initialization execution exactly like a domain call, including
/// the descriptor ABI-digest check [`execute_domain_experimental`] applies.
/// The admitted typed domain operation is executed by
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

    let mut config = wasmtime::Config::new();
    config.wasm_component_model(true);
    config.consume_fuel(true);
    config.epoch_interruption(true);
    config.max_wasm_stack(usize::try_from(PROVIDER_STACK_SIZE).unwrap_or(8192));
    let engine = wasmtime::Engine::new(&config)
        .map_err(|_| TypedExecutionError::Engine("config:invalid".to_owned()))?;
    let component = wasmtime::component::Component::new(&engine, artifact)
        .map_err(|error| staged(TypedStage::Compile, map_compile_error(&error)))?;

    // Inspect the exact component type before any instance is created or any
    // guest function is called. Generated bindings provide the expected WIT
    // function signatures; the Wasmtime ComponentFunc type checker compares
    // them against the compiled component metadata.
    let (imports, exports) = preflight_component_type(world, &engine, &component)?;

    let (descriptor, usage) = dispatch_describe(world, &engine, &component, limits)?;
    let (output_digest, output_bytes) =
        validate_descriptor(world, &descriptor, limits.max_output_bytes)
            .map_err(|error| staged(TypedStage::Output, error))?;
    validate_descriptor_abi_digest(&descriptor)
        .map_err(|error| staged(TypedStage::Output, error))?;

    let elapsed_ms = u64::try_from(start.elapsed().as_millis()).unwrap_or(u64::MAX);
    let input_digest = Sha256Digest::of_bytes(&[]);
    let terminal = format!("{:?}", EngineTermination::Completed);
    let receipt = TypedReceipt {
        proof: ExecutionMode::LocalExperimental.proof().to_owned(),
        world: world.world_name().to_owned(),
        package_id: crate::typed_bindings::TYPED_PACKAGE_ID.to_owned(),
        artifact_digest: preflight.digest.clone(),
        artifact_bytes: preflight.byte_len,
        engine_version: ENGINE_VERSION.to_owned(),
        wit_digest: typed_wit_digest(),
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
        semantic_digest: semantic_digest(
            world,
            &preflight.digest,
            preflight.byte_len,
            &output_digest,
            output_bytes,
            &terminal,
        ),
    };
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

fn map_call_error(
    call: &str,
    error: &wasmtime::Error,
    limit_hit: Option<ResourceLimitHit>,
) -> TypedExecutionError {
    if let Some(hit) = limit_hit {
        return resource_limit_error(hit);
    }
    let Some(trap) = error.downcast_ref::<wasmtime::Trap>() else {
        return TypedExecutionError::Engine(format!("{call}:component-call"));
    };
    let termination = match *trap {
        wasmtime::Trap::OutOfFuel => EngineTermination::FuelExhausted,
        wasmtime::Trap::Interrupt => EngineTermination::EpochDeadline,
        wasmtime::Trap::StackOverflow => EngineTermination::StackLimit,
        _ => return TypedExecutionError::Engine(format!("{call}:guest-trap")),
    };
    TypedExecutionError::Engine(format!("{termination:?}"))
}

fn map_instantiate_error(
    error: &wasmtime::Error,
    limit_hit: Option<ResourceLimitHit>,
) -> TypedExecutionError {
    if let Some(hit) = limit_hit {
        return resource_limit_error(hit);
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
    store
        .set_fuel(limits.max_fuel)
        .map_err(|_| TypedExecutionError::LimitDenied("fuel".to_owned()))?;
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
}

/// Runs one descriptor closure with fuel, memory/table/instance limits,
/// and epoch interruption driven by both a tick pump and the wall
/// deadline. No clock, randomness, or ambient capability reaches the guest.
fn run_guarded<T>(
    engine: &wasmtime::Engine,
    limits: &InvocationLimits,
    invoke: impl FnOnce(&mut wasmtime::Store<StoreState>) -> Result<T, TypedExecutionError>,
) -> Result<(T, ObservedUsage), TypedExecutionError> {
    let mut store = new_store(engine, limits)?;
    let wall_deadline = Instant::now() + Duration::from_millis(limits.wall_deadline_ms);
    let stop = Arc::new(AtomicBool::new(false));
    let engine_clone = engine.clone();
    let stop_clone = Arc::clone(&stop);
    let epoch_deadline = limits.epoch.deadline_ticks;
    // Same interruption mechanism as the legacy provider: a bounded driver
    // thread advances the epoch and forces the deadline once the wall
    // clock expires. Guests observe only interruption, never time.
    let driver = thread::Builder::new()
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
    let outcome = invoke(&mut store);
    stop.store(true, Ordering::Release);
    let _ = driver.join();
    let remaining_fuel = store.get_fuel().unwrap_or(0);
    let fuel_consumed = limits.max_fuel.saturating_sub(remaining_fuel);
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
        let instance = ContextAdmission::instantiate(&mut *store, component, &linker)
            .map_err(|error| map_instantiate_error(&error, store.data().limit_hit))?;
        let raw = instance
            .eliot_current_admission()
            .call_describe(&mut *store)
            .map_err(|error| map_call_error("describe", &error, store.data().limit_hit))?;
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
        let instance = ContextAssembly::instantiate(&mut *store, component, &linker)
            .map_err(|error| map_instantiate_error(&error, store.data().limit_hit))?;
        let raw = instance
            .eliot_current_assembly()
            .call_describe(&mut *store)
            .map_err(|error| map_call_error("describe", &error, store.data().limit_hit))?;
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
        let instance = CueActivation::instantiate(&mut *store, component, &linker)
            .map_err(|error| map_instantiate_error(&error, store.data().limit_hit))?;
        let raw = instance
            .eliot_current_activation()
            .call_describe(&mut *store)
            .map_err(|error| map_call_error("describe", &error, store.data().limit_hit))?;
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
        let instance = DreamerHandler::instantiate(&mut *store, component, &linker)
            .map_err(|error| map_instantiate_error(&error, store.data().limit_hit))?;
        let raw = instance
            .eliot_current_handler()
            .call_describe(&mut *store)
            .map_err(|error| map_call_error("describe", &error, store.data().limit_hit))?;
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
        let instance = MemoryCurationScreen::instantiate(&mut *store, component, &linker)
            .map_err(|error| map_instantiate_error(&error, store.data().limit_hit))?;
        let raw = instance
            .eliot_current_screen()
            .call_describe(&mut *store)
            .map_err(|error| map_call_error("describe", &error, store.data().limit_hit))?;
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
        let instance = DreamerCycle::instantiate(&mut *store, component, &linker)
            .map_err(|error| map_instantiate_error(&error, store.data().limit_hit))?;
        let raw = instance
            .eliot_current_cycle()
            .call_describe(&mut *store)
            .map_err(|error| map_call_error("describe", &error, store.data().limit_hit))?;
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

/// Executes the admitted typed domain operation for one world through the real
/// Wasmtime component engine: the same bounded buffer is hashed and compiled,
/// the exact component type is inspected before instantiation, the component
/// is instantiated on the existing empty linker inside the existing guarded
/// envelope, the registered descriptor is called and its identity validated,
/// and the domain export is then called EXACTLY ONCE with the generated
/// request type of the selected world.
pub fn execute_domain_experimental(
    world: TypedWorld,
    artifact: &[u8],
    limits: &InvocationLimits,
    request: &TypedDomainRequest,
    admitted: &TypedDomainAdmission,
) -> Result<(TypedReceipt, TypedDomainResult), TypedExecutionError> {
    let start = Instant::now();
    admitted.validate()?;
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

    let mut config = wasmtime::Config::new();
    config.wasm_component_model(true);
    config.consume_fuel(true);
    config.epoch_interruption(true);
    config.max_wasm_stack(usize::try_from(PROVIDER_STACK_SIZE).unwrap_or(8192));
    let engine = wasmtime::Engine::new(&config)
        .map_err(|_| TypedExecutionError::Engine("config:invalid".to_owned()))?;
    let component = wasmtime::component::Component::new(&engine, artifact)
        .map_err(|error| staged(TypedStage::Compile, map_compile_error(&error)))?;

    let (imports, exports) = preflight_component_type(world, &engine, &component)?;

    let (descriptor, result, usage) = dispatch_domain(world, &engine, &component, limits, request)?;

    let (descriptor_digest, descriptor_bytes) =
        validate_descriptor(world, &descriptor, limits.max_output_bytes)
            .map_err(|error| staged(TypedStage::Descriptor, error))?;
    validate_descriptor_abi_digest(&descriptor)
        .map_err(|error| staged(TypedStage::Descriptor, error))?;

    let mut output_bound = TypedBound::default();
    check_result(&result, admitted, &mut output_bound)
        .map_err(|error| staged(TypedStage::Output, error))?;
    let output_bytes = descriptor_bytes
        + output_bound
            .finish(limits.max_output_bytes)
            .map_err(|error| staged(TypedStage::Output, error))?;

    let elapsed_ms = u64::try_from(start.elapsed().as_millis()).unwrap_or(u64::MAX);
    let terminal = result.terminal().to_owned();
    let receipt = TypedReceipt {
        proof: ExecutionMode::LocalExperimental.proof().to_owned(),
        world: world.world_name().to_owned(),
        package_id: crate::typed_bindings::TYPED_PACKAGE_ID.to_owned(),
        artifact_digest: preflight.digest.clone(),
        artifact_bytes: preflight.byte_len,
        engine_version: ENGINE_VERSION.to_owned(),
        wit_digest: typed_wit_digest(),
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
        semantic_digest: semantic_digest(
            world,
            &preflight.digest,
            preflight.byte_len,
            &descriptor_digest,
            output_bytes,
            &terminal,
        ),
    };
    Ok((receipt, result))
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

fn bound_request(
    world: TypedWorld,
    request: &TypedDomainRequest,
    admitted: &TypedDomainAdmission,
    bound: &mut TypedBound,
) -> Result<(), TypedExecutionError> {
    match (world, request) {
        (TypedWorld::ContextAdmission, TypedDomainRequest::Admission(value)) => {
            check_echo(&value.operation_id, &admitted.operation_id, "operation-id")?;
            check_echo(&value.task_id, &admitted.task_id, "task-id")?;
            check_echo(&value.scope_id, &admitted.scope_id, "scope-id")?;
            check_echo(&value.fence_epoch, &admitted.fence_epoch, "fence-epoch")?;
            bound.text(&value.operation_id)?;
            bound.text(&value.task_id)?;
            bound.text(&value.attempt_id)?;
            bound.text(&value.scope_id)?;
            bound.text(&value.fence_epoch)?;
            bound.text(&value.recipe_digest)?;
            bound.text(&value.recipe_revision)?;
            bound.list(&value.candidates)?;
            bound.list(&value.provider_denominator)?;
            bound.list(&value.measurements)?;
            Ok(())
        }
        (TypedWorld::ContextAssembly, TypedDomainRequest::Assembly(value)) => {
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
            Ok(())
        }
        (TypedWorld::CueActivation, TypedDomainRequest::CueActivation(value)) => {
            // The activation world carries no task/scope field; its echoed
            // operation identity is the WIT `request-id`.
            check_echo(&value.request_id, &admitted.operation_id, "operation-id")?;
            check_echo(&value.fence_epoch, &admitted.fence_epoch, "fence-epoch")?;
            bound.text(&value.request_id)?;
            bound.text(&value.snapshot_id)?;
            bound.text(&value.fence_epoch)?;
            bound.text(&value.normalization_profile)?;
            bound.list(&value.seeds)?;
            bound.list(&value.relation_edges)?;
            Ok(())
        }
        (TypedWorld::DreamerHandler, TypedDomainRequest::DreamerHandler(value)) => {
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
            Ok(())
        }
        (TypedWorld::MemoryCurationScreen, TypedDomainRequest::MemoryCurationScreen(value)) => {
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
            bound.list(&value.rule_ids)?;
            Ok(())
        }
        (TypedWorld::DreamerCycle, TypedDomainRequest::DreamerCycle(value)) => {
            check_echo(&value.operation_id, &admitted.operation_id, "operation-id")?;
            check_echo(&value.task_id, &admitted.task_id, "task-id")?;
            check_echo(&value.scope_id, &admitted.scope_id, "scope-id")?;
            check_echo(&value.fence_epoch, &admitted.fence_epoch, "fence-epoch")?;
            bound.text(&value.operation_id)?;
            bound.text(&value.task_id)?;
            bound.text(&value.scope_id)?;
            bound.text(&value.fence_epoch)?;
            bound.text(&value.state.state_digest)?;
            bound.text(&value.state.fence_epoch)?;
            bound.text(&value.policy.policy_revision)?;
            bound.list(&value.state.pending)?;
            bound.list(&value.state.observed)?;
            Ok(())
        }
        // `TypedDomainRequest::world()` was compared with the selection above,
        // so no unhandled pairing reaches this point.
        _ => Err(TypedExecutionError::WorldSelection {
            reason: "request-world".to_owned(),
        }),
    }
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
