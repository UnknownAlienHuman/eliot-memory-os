//! Typed sandboxed execution for the six frozen worlds.
//!
//! Default governed mode refuses without actual Kernel admission
//! (`KERNEL_ADMISSION_REQUIRED`). An explicitly selected local-experimental
//! path instantiates and executes a typed component through the frozen WIT
//! world with deny-by-default Wasmtime policy and zero ambient imports.
//! After the `describe` identity gate, the experimental path consumes #760's
//! neutral operation capsule ([`ModuleContractKit`] +
//! [`ModuleTestCapsule`]): the kit binds package/world/ABI/artifact and the
//! closed-world declaration, the capsule binds the exact world/operation and
//! the input/output bounds, and the generated domain export is invoked
//! exactly once under the same limits/cancellation policy. The typed terminal
//! result (success, first-class incomplete, or guest error) is retained
//! exactly; traps, limit, and output violations keep their own classes.

use std::fmt;
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use std::thread;
use std::time::{Duration, Instant};

use eliot_wasm_runtime::capsule::{ModuleContractKit, ModuleTestCapsule};
use eliot_wasm_runtime::component_contract::{ProofCeiling, TYPED_PACKAGE_ID, TypedContractError};
use eliot_wasm_runtime::{
    CancellationPolicy, CapabilityId, EngineTermination, EpochPolicy, InvocationLimits,
    MAX_EPOCH_DEADLINE_TICKS, ProofStage, Sha256Digest,
};

use crate::artifact_preflight::{PreflightError, preflight_bytes};
use crate::contour::CAPABILITY_INTRODUCTION_REQUIRED;
use crate::typed_bindings::{TypedWorld, typed_wit_digest};

const ENGINE_VERSION: &str = "47.0.4";
const PROVIDER_STACK_SIZE: u64 = 8 * 1024;
const MAX_DESCRIPTOR_STRING_BYTES: usize = 512;

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
    /// Digest of the exact enforced engine settings (recomputed from
    /// [`typed_configuration_descriptor`], never pasted). Together with
    /// the engine version, artifact, ABI, and policy this names the
    /// execution identity a cache entry would have to match; no cache
    /// bypass exists because no compiled artifact is retained.
    pub engine_config_digest: Sha256Digest,
    /// Digest of the frozen WIT bytes.
    pub wit_digest: Sha256Digest,
    /// Actual component imports observed (must be empty).
    pub actual_imports: Vec<String>,
    /// Actual component exports observed (exactly one interface).
    pub actual_exports: Vec<String>,
    /// Digest of the (empty) describe input.
    pub input_digest: Sha256Digest,
    /// Digest of the validated descriptor fields.
    pub output_digest: Sha256Digest,
    /// Measured descriptor output bytes (sum of reported string bytes).
    pub output_bytes: u64,
    /// Configured per-invocation limit envelope enforced by the Stores.
    pub configured: InvocationLimits,
    /// Pipeline stages completed on the successful path, in order. The
    /// describe-only path records every stage except `invoke`; the domain
    /// path records all six.
    pub stages: Vec<String>,
    /// Domain operation invoked after the descriptor gate, or empty when
    /// only the descriptor ran.
    pub domain_operation: String,
    /// Digest of the canonical domain-input encoding.
    pub domain_input_digest: Sha256Digest,
    /// Digest of the canonical domain-output encoding.
    pub domain_output_digest: Sha256Digest,
    /// Measured domain-output bytes (canonical encoding length).
    pub domain_output_bytes: u64,
    /// Neutral proof ceiling carried by the domain result, or empty when
    /// the terminal outcome carries none (guest error) or no domain call
    /// ran.
    pub domain_ceiling: String,
    /// Fuel consumed by describe execution.
    pub fuel_consumed: u64,
    /// Peak memory bytes observed, when reported.
    pub peak_memory_bytes: Option<u64>,
    /// Table elements observed, when reported.
    pub table_elements: Option<u32>,
    /// Component instances created (always 1 on success).
    pub instances: u32,
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
    /// Neutral contract-kit/capsule validation denied the domain call.
    CapsuleDenied(String),
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
            Self::CapsuleDenied(reason) => write!(formatter, "CAPSULE_DENIED:{reason}"),
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
/// The input envelope fits the fixed canonical domain probe (below
/// one kilobyte); it stays a finite bound, not an open tap.
#[must_use]
pub fn default_experimental_limits(artifact_digest: Sha256Digest) -> InvocationLimits {
    InvocationLimits {
        max_input_bytes: 4_096,
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

/// Deterministic semantic digest over the receipt's identity fields.
/// Observation timing (`elapsed_ms`) never enters: two runs of the same call
/// share the digest. Takes the finished receipt so the parameter list stays
/// a single identity instead of one argument per field.
fn semantic_digest(receipt: &TypedReceipt) -> Sha256Digest {
    let canonical = format!(
        "758|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}",
        receipt.world,
        receipt.artifact_digest.as_str(),
        receipt.artifact_bytes,
        receipt.engine_config_digest.as_str(),
        receipt.output_digest.as_str(),
        receipt.output_bytes,
        receipt.terminal,
        receipt.domain_operation,
        receipt.domain_output_digest.as_str(),
        receipt.domain_output_bytes,
        receipt.domain_ceiling,
        receipt.wit_digest.as_str(),
    );
    Sha256Digest::of_bytes(canonical.as_bytes())
}

/// Executes the typed `describe` descriptor for one world through the real
/// Wasmtime component engine under deny-by-default sandbox policy.
///
/// Reads nothing: the caller supplies the exact immutable buffer. The same
/// buffer is hashed (preflight) and compiled; the path is never reread.
/// Zero ambient imports, full resource limits, and output checks apply to
/// descriptor/initialization execution exactly like a domain call. The
/// domain operation itself runs through [`execute_domain_experimental`],
/// which reuses this descriptor gate before the single domain invocation.
pub fn execute_describe_experimental(
    world: TypedWorld,
    artifact: &[u8],
    limits: &InvocationLimits,
) -> Result<(TypedReceipt, TypedDescriptor), TypedExecutionError> {
    let start = Instant::now();
    // Same-buffer hash/compile: preflight once, compile the same slice.
    let preflight = preflight_bytes(artifact)?;
    validate_limits(limits, &preflight.digest)?;

    let engine = configured_engine()?;
    let component = wasmtime::component::Component::new(&engine, artifact)
        .map_err(|error| map_compile_error(&error))?;

    // Inspect the exact component type before any instance is created or any
    // guest function is called. Generated bindings provide the expected WIT
    // function signatures; the Wasmtime ComponentFunc type checker compares
    // them against the compiled component metadata.
    let (imports, exports) = preflight_component_type(world, &engine, &component)?;

    let (descriptor, usage) = dispatch_describe(world, &engine, &component, limits)?;
    let (output_digest, output_bytes) =
        validate_descriptor(world, &descriptor, limits.max_output_bytes)?;

    let elapsed_ms = u64::try_from(start.elapsed().as_millis()).unwrap_or(u64::MAX);
    let input_digest = Sha256Digest::of_bytes(&[]);
    let terminal = format!("{:?}", EngineTermination::Completed);
    let empty_digest = Sha256Digest::of_bytes(&[]);
    let engine_config_digest = typed_engine_binding().engine_configuration_digest;
    let mut receipt = TypedReceipt {
        proof: ExecutionMode::LocalExperimental.proof().to_owned(),
        world: world.world_name().to_owned(),
        package_id: crate::typed_bindings::TYPED_PACKAGE_ID.to_owned(),
        artifact_digest: preflight.digest.clone(),
        artifact_bytes: preflight.byte_len,
        engine_version: ENGINE_VERSION.to_owned(),
        engine_config_digest,
        wit_digest: typed_wit_digest(),
        actual_imports: imports,
        actual_exports: exports,
        input_digest,
        output_digest,
        output_bytes,
        configured: limits.clone(),
        stages: vec![
            "compile".to_owned(),
            "instantiate".to_owned(),
            "descriptor".to_owned(),
            "output".to_owned(),
            "cleanup".to_owned(),
        ],
        domain_operation: String::new(),
        domain_input_digest: empty_digest.clone(),
        domain_output_digest: empty_digest,
        domain_output_bytes: 0,
        domain_ceiling: String::new(),
        fuel_consumed: usage.fuel_consumed,
        peak_memory_bytes: usage.peak_memory_bytes,
        table_elements: usage.table_elements,
        instances: 1,
        elapsed_ms,
        terminal,
        semantic_digest: Sha256Digest::of_bytes(&[]),
    };
    receipt.semantic_digest = semantic_digest(&receipt);
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

/// Builds the single configured Wasmtime engine used by both the
/// descriptor and the domain call. One engine per execution, never a second
/// engine beside the provider path: describe and domain share it while each
/// runs in its own Store under the same full limit envelope.
fn configured_engine() -> Result<wasmtime::Engine, TypedExecutionError> {
    let mut config = wasmtime::Config::new();
    config.wasm_component_model(true);
    config.consume_fuel(true);
    config.epoch_interruption(true);
    config.max_wasm_stack(usize::try_from(PROVIDER_STACK_SIZE).unwrap_or(8192));
    wasmtime::Engine::new(&config)
        .map_err(|_| TypedExecutionError::Engine("config:invalid".to_owned()))
}

/// Canonical descriptor of the exact typed-engine settings enforced by
/// [`configured_engine`]. The digest names these settings and changes if
/// and only if they change; it is recomputed, never pasted.
fn typed_configuration_descriptor() -> &'static [u8] {
    b"wasmtime=47.0.4;component_model=true;typed=describe+domain;consume_fuel=true;epoch_interruption=true;max_wasm_stack=8192"
}

/// Provider binding carried for the typed path: the pinned implementation
/// and version, the fixture-scoped engine identity (Wasmtime links
/// statically, so no measured production engine artifact is claimed), the
/// recomputed configuration digest, and the frozen WIT digest.
fn typed_engine_binding() -> eliot_wasm_runtime::EngineBinding {
    eliot_wasm_runtime::EngineBinding {
        implementation_id: "wasmtime-component".to_owned(),
        exact_version: ENGINE_VERSION.to_owned(),
        engine_artifact_digest: Sha256Digest::of_bytes(b"wasmtime-component/47.0.4"),
        engine_configuration_digest: Sha256Digest::of_bytes(typed_configuration_descriptor()),
        wit_interface_digest: typed_wit_digest(),
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
    operation: &str,
    error: &wasmtime::Error,
    limit_hit: Option<ResourceLimitHit>,
) -> TypedExecutionError {
    if let Some(hit) = limit_hit {
        return resource_limit_error(hit);
    }
    let Some(trap) = error.downcast_ref::<wasmtime::Trap>() else {
        return TypedExecutionError::Engine(format!("{operation}:component-call"));
    };
    let termination = match *trap {
        wasmtime::Trap::OutOfFuel => EngineTermination::FuelExhausted,
        wasmtime::Trap::Interrupt => EngineTermination::EpochDeadline,
        wasmtime::Trap::StackOverflow => EngineTermination::StackLimit,
        _ => return TypedExecutionError::Engine(format!("{operation}:guest-trap")),
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

/// Runs one guarded closure with fuel, memory/table/instance limits,
/// and epoch interruption driven by both a tick pump and the wall
/// deadline. No clock, randomness, or ambient capability reaches the guest.
/// The descriptor call and the domain call each run under the same full
/// envelope in their own Store; usage is observed per call.
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
                Err(resource_limit_error(hit))
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

/// Retained terminal outcome of one typed domain invocation. A guest error
/// or first-class incomplete outcome is a retained domain result, never a
/// Host-success rewrite and never a trap: each keeps its own disposition
/// class.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DomainTerminal {
    /// Domain operation invoked (`admit`, `assemble`, `activate`,
    /// `handle`, `screen`, `step`).
    pub operation: String,
    /// Terminal disposition: `COMPLETED`, `INCOMPLETE:<code>`, or
    /// `GUEST_ERROR:<case>`.
    pub disposition: String,
    /// Neutral proof ceiling carried by the result, or empty when the
    /// terminal outcome carries none (guest error).
    pub proof_ceiling: String,
}

/// Fixed canonical identity carried by every experimental domain probe.
/// These values are Host-chosen constants: they bind no Kernel, task, or
/// user identity and admit nothing. A result that echoes foreign
/// operation/scope/fence identity is rejected.
const PROBE_OPERATION_ID: &str = "758-experimental-probe";
const PROBE_TASK_ID: &str = "758-experimental-task";
const PROBE_ATTEMPT_ID: &str = "758-experimental-attempt";
const PROBE_SCOPE_ID: &str = "758-experimental-scope";
const PROBE_FENCE_EPOCH: &str = "758-experimental-fence";
const PROBE_REQUEST_ID: &str = "758-experimental-request";
/// Canonical "no measurement" digest-hex marker: 64 zero nibbles. A valid
/// lowercase hex shape that claims no provenance.
const PROBE_ZERO_HEX: &str = "0000000000000000000000000000000000000000000000000000000000000000";
/// Oracle identity bound into every experimental test capsule.
const PROBE_ORACLE: &str = "eliot-wasm-host-experimental-probe";
/// Stateless marker hashed into the experimental kit state-contract digest.
const PROBE_STATELESS_MARKER: &[u8] = b"eliot-758-experimental-stateless/v1";

/// Overflow of a bounded canonical encoding budget.
struct CanonicalOverflow;

/// Bounded canonical writer for typed domain inputs and outputs. Every byte
/// is debited from a finite budget before it is stored, so a hostile
/// lifted length can never allocate first and be checked later: exhaustion
/// fails the encoding. Field order follows WIT declaration order;
/// enum/variant discriminants are declaration-order indexes.
struct CanonicalWriter {
    bytes: Vec<u8>,
    remaining: u64,
}

impl CanonicalWriter {
    fn new(budget: u64) -> Self {
        Self {
            bytes: Vec::new(),
            remaining: budget,
        }
    }

    fn put(&mut self, bytes: &[u8]) -> Result<(), CanonicalOverflow> {
        let len = u64::try_from(bytes.len()).map_err(|_| CanonicalOverflow)?;
        self.remaining = self.remaining.checked_sub(len).ok_or(CanonicalOverflow)?;
        self.bytes.extend_from_slice(bytes);
        Ok(())
    }

    fn val_bool(&mut self, value: bool) -> Result<(), CanonicalOverflow> {
        self.put(&[u8::from(value)])
    }

    fn val_u8(&mut self, value: u8) -> Result<(), CanonicalOverflow> {
        self.put(&[value])
    }

    fn val_u16(&mut self, value: u16) -> Result<(), CanonicalOverflow> {
        self.put(&value.to_be_bytes())
    }

    fn val_u32(&mut self, value: u32) -> Result<(), CanonicalOverflow> {
        self.put(&value.to_be_bytes())
    }

    fn val_u64(&mut self, value: u64) -> Result<(), CanonicalOverflow> {
        self.put(&value.to_be_bytes())
    }

    fn val_i64(&mut self, value: i64) -> Result<(), CanonicalOverflow> {
        self.put(&value.to_be_bytes())
    }

    fn val_str(&mut self, value: &str) -> Result<(), CanonicalOverflow> {
        let bytes = value.as_bytes();
        let len = u64::try_from(bytes.len()).map_err(|_| CanonicalOverflow)?;
        self.put(&len.to_be_bytes())?;
        self.put(bytes)
    }

    fn val_disc(&mut self, index: u32) -> Result<(), CanonicalOverflow> {
        self.put(&index.to_be_bytes())
    }

    fn val_opt<T>(
        &mut self,
        value: Option<&T>,
        encode: impl Fn(&mut Self, &T) -> Result<(), CanonicalOverflow>,
    ) -> Result<(), CanonicalOverflow> {
        match value {
            None => self.put(&[0]),
            Some(inner) => {
                self.put(&[1])?;
                encode(self, inner)
            }
        }
    }

    fn finish(self) -> Vec<u8> {
        self.bytes
    }
}

/// Maps a neutral contract error to a stable bounded denial code. Only the
/// variant identity crosses into the receipt; no payload, path, or secret.
fn capsule_denied(error: &TypedContractError) -> TypedExecutionError {
    let code = match error {
        TypedContractError::UnknownWorld(_) => "unknown-world",
        TypedContractError::LegacyRejected(_) => "legacy-rejected",
        TypedContractError::PackageMismatch { .. } => "package",
        TypedContractError::WorldMismatch { .. } => "world",
        TypedContractError::VersionMismatch { .. } => "version",
        TypedContractError::AbiMismatch { .. } => "abi",
        TypedContractError::DescriptorField(_) => "descriptor-field",
        TypedContractError::ImportMismatch => "import",
        TypedContractError::ExportMismatch => "export",
        TypedContractError::EngineMismatch => "engine",
        TypedContractError::ArtifactMismatch => "artifact",
        TypedContractError::InterfaceMismatch => "interface",
        TypedContractError::LimitDenied => "limit",
        TypedContractError::ReportMismatch => "report",
        TypedContractError::EngineDenied => "engine-denied",
        TypedContractError::EngineUnavailable => "engine-unavailable",
        TypedContractError::EngineUnknown => "engine-unknown",
        TypedContractError::EnvelopeTooLarge => "envelope",
        TypedContractError::InvalidKit(_) => "kit",
        TypedContractError::InvalidCapsule(_) => "capsule",
        TypedContractError::Serialization(_) => "serialization",
    };
    TypedExecutionError::CapsuleDenied(code.to_owned())
}

/// Parses the neutral world for one Host-selected world through #760's own
/// contract parser. The canonical WIT name is the only input; unknown or
/// legacy spellings fail closed inside the neutral parser.
fn neutral_world(
    world: TypedWorld,
) -> Result<eliot_wasm_runtime::component_contract::TypedWorld, TypedExecutionError> {
    eliot_wasm_runtime::component_contract::TypedWorld::parse(world.world_name())
        .map_err(|error| capsule_denied(&error))
}

/// Builds the Governor-free experimental contract kit for one world from
/// the validated guest descriptor and the preflighted artifact. The kit is
/// explicitly non-governed with a candidate-only ceiling: local experiments
/// stay non-governed and can never imply admission. The declared
/// import/export identity is the closed world (zero imports, one bare
/// interface); the qualified engine-observed export is matched against it
/// by the component-type preflight before this kit is built.
fn experimental_kit(
    world: TypedWorld,
    descriptor: &TypedDescriptor,
    artifact_digest: &Sha256Digest,
    artifact_bytes: u64,
) -> Result<ModuleContractKit, TypedExecutionError> {
    let neutral = neutral_world(world)?;
    let abi_digest = Sha256Digest::new(descriptor.abi_digest.clone())
        .map_err(|_| TypedExecutionError::OutputViolation("abi-digest".to_owned()))?;
    let abi = eliot_wasm_runtime::component_contract::AbiDescriptor::new(
        neutral,
        descriptor.native_contract.clone(),
        descriptor.native_revision.clone(),
        abi_digest,
    )
    .map_err(|error| capsule_denied(&error))?;
    let kit = ModuleContractKit {
        package_id: TYPED_PACKAGE_ID.to_owned(),
        world: neutral,
        abi,
        artifact_digest: artifact_digest.clone(),
        artifact_len: artifact_bytes,
        interface_digest: typed_wit_digest(),
        declared_imports: Vec::new(),
        declared_exports: vec![world.interface_name().to_owned()],
        state_contract_digest: Sha256Digest::of_bytes(PROBE_STATELESS_MARKER),
        proof_ceiling: ProofCeiling::CandidateOnly,
        governed: false,
    };
    kit.validate().map_err(|error| capsule_denied(&error))?;
    if kit.artifact_digest != *artifact_digest || kit.artifact_len != artifact_bytes {
        return Err(TypedExecutionError::CapsuleDenied("artifact".to_owned()));
    }
    Ok(kit)
}

/// Builds the experimental test capsule binding one kit digest, the exact
/// canonical probe-input bytes that will be executed, the enforced bounds,
/// and the oracle identity. The capsule operation must be the world's
/// domain operation; validation rejects any other binding.
fn experimental_capsule(
    world: TypedWorld,
    kit: &ModuleContractKit,
    limits: &InvocationLimits,
    fixture: Vec<u8>,
) -> Result<ModuleTestCapsule, TypedExecutionError> {
    let neutral = neutral_world(world)?;
    let component = CapabilityId::new(format!("758-experimental-{}", world.world_name()))
        .map_err(|_| TypedExecutionError::CapsuleDenied("component".to_owned()))?;
    let capsule = ModuleTestCapsule {
        kit_digest: kit.digest().map_err(|error| capsule_denied(&error))?,
        component,
        world: neutral,
        operation: world.domain_func().to_owned(),
        stage: ProofStage::Invocation,
        fixture,
        expected: Vec::new(),
        max_input_bytes: limits.max_input_bytes,
        max_output_bytes: limits.max_output_bytes,
        max_work: limits.max_fuel,
        oracle: PROBE_ORACLE.to_owned(),
    };
    capsule
        .validate(kit)
        .map_err(|error| capsule_denied(&error))?;
    if capsule.max_input_bytes > limits.max_input_bytes
        || capsule.max_output_bytes > limits.max_output_bytes
        || capsule.max_work > limits.max_fuel
    {
        return Err(TypedExecutionError::CapsuleDenied("limit".to_owned()));
    }
    Ok(capsule)
}

/// Numeric rank of a neutral proof ceiling in declaration order. A guest
/// result carrying a ceiling above the kit ceiling is an escalation and is
/// rejected; candidate-only never implies admission.
fn ceiling_rank(ceiling: ProofCeiling) -> u8 {
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

/// Rejects a guest ceiling above the experimental candidate-only ceiling.
fn check_ceiling(ceiling: ProofCeiling) -> Result<String, TypedExecutionError> {
    if ceiling_rank(ceiling) > ceiling_rank(ProofCeiling::CandidateOnly) {
        return Err(TypedExecutionError::OutputViolation(
            "proof-ceiling".to_owned(),
        ));
    }
    Ok(format!("{ceiling:?}"))
}

/// Rejects a result identity field that does not echo the probe identity.
/// Only the fixed label crosses into the receipt; guest content never does.
fn check_identity(field: &'static str, got: &str, want: &str) -> Result<(), TypedExecutionError> {
    if got != want {
        return Err(TypedExecutionError::OutputViolation(field.to_owned()));
    }
    Ok(())
}

/// Fixed Host-chosen probe constants beyond the identities above. These bind
/// no Kernel, task, or user identity and admit nothing; a result echoing
/// foreign values is rejected by [`check_identity`].
const PROBE_SNAPSHOT_ID: &str = "758-experimental-snapshot";
const PROBE_RECIPE_REVISION: &str = "758-experimental-recipe";
const PROBE_SERIALIZER: &str = "758-experimental-serializer";
const PROBE_SCHEMA_REVISION: &str = "0.1.0";
const PROBE_SOURCE_ID: &str = "758-experimental-source";
const PROBE_PROFILE_ID: &str = "758-experimental-profile";
const PROBE_PRINCIPAL: &str = "758-experimental-principal";
const PROBE_SESSION_ID: &str = "758-experimental-session";
const PROBE_WANT_KIND: &str = "758-experimental-kind";
const PROBE_DETAIL: &str = "758-experimental-probe";

/// Output-limit terminal used when a bounded canonical encoding exhausts
/// its budget: the encoding is debited before any byte is stored, so a
/// hostile lifted length fails here instead of allocating first.
fn output_limit() -> TypedExecutionError {
    TypedExecutionError::Engine(format!("{:?}", EngineTermination::OutputLimit))
}

/// Validates a guest-supplied digest-hex shape without trusting its content.
/// Only the shape is checked; the value is the guest's own claim.
fn check_digest_hex(field: &'static str, value: &str) -> Result<(), TypedExecutionError> {
    Sha256Digest::new(value.to_owned())
        .map_err(|_| TypedExecutionError::OutputViolation(field.to_owned()))?;
    Ok(())
}

/// Maps a generated WIT `proof-ceiling` variant (by its exact Debug
/// identity, which carries no guest content) to the neutral ceiling. Any
/// other spelling fails closed; escalation above candidate-only is rejected
/// separately by [`check_ceiling`].
fn neutral_ceiling(debug_name: &str) -> Result<ProofCeiling, TypedExecutionError> {
    match debug_name {
        "Observation" => Ok(ProofCeiling::Observation),
        "CandidateOnly" => Ok(ProofCeiling::CandidateOnly),
        "Admission" => Ok(ProofCeiling::Admission),
        "Assembly" => Ok(ProofCeiling::Assembly),
        "Activation" => Ok(ProofCeiling::Activation),
        "Screen" => Ok(ProofCeiling::Screen),
        "Cycle" => Ok(ProofCeiling::Cycle),
        "Handler" => Ok(ProofCeiling::Handler),
        _ => Err(TypedExecutionError::OutputViolation(
            "proof-ceiling".to_owned(),
        )),
    }
}

/// Canonical fixture bytes for the fixed experimental probe of one world.
/// Every sequence below mirrors the typed probe built in the matching
/// `invoke_*` function field for field from the same `PROBE_*` constants:
/// empty lists encode as a zero count, absent options as a zero byte, and
/// every string is a Host-chosen constant. The budget is debited before any
/// byte is stored, so encoding can never exceed `max_input_bytes`.
fn domain_probe_fixture(world: TypedWorld, budget: u64) -> Result<Vec<u8>, TypedExecutionError> {
    let mut out = CanonicalWriter::new(budget);
    let overflow = |_| output_limit();
    let name_len = u32::try_from(world.world_name().len()).map_err(|_| output_limit())?;
    out.val_u32(name_len).map_err(overflow)?;
    out.put(world.world_name().as_bytes()).map_err(overflow)?;
    out.val_str(world.domain_func()).map_err(overflow)?;
    out.val_u32(1).map_err(overflow)?;
    match world {
        TypedWorld::ContextAdmission => probe_fixture_admission(&mut out)?,
        TypedWorld::ContextAssembly => probe_fixture_assembly(&mut out)?,
        TypedWorld::CueActivation => probe_fixture_activation(&mut out)?,
        TypedWorld::DreamerHandler => probe_fixture_handler(&mut out)?,
        TypedWorld::MemoryCurationScreen => probe_fixture_screen(&mut out)?,
        TypedWorld::DreamerCycle => probe_fixture_cycle(&mut out)?,
    }
    Ok(out.finish())
}

fn probe_fixture_admission(out: &mut CanonicalWriter) -> Result<(), TypedExecutionError> {
    let overflow = |_| output_limit();
    out.val_str(PROBE_OPERATION_ID).map_err(overflow)?;
    out.val_str(PROBE_TASK_ID).map_err(overflow)?;
    out.val_str(PROBE_ATTEMPT_ID).map_err(overflow)?;
    out.val_str(PROBE_SCOPE_ID).map_err(overflow)?;
    out.val_str(PROBE_FENCE_EPOCH).map_err(overflow)?;
    out.val_u64(0).map_err(overflow)?;
    out.val_u64(0).map_err(overflow)?;
    out.val_str(PROBE_ZERO_HEX).map_err(overflow)?;
    out.val_str(PROBE_RECIPE_REVISION).map_err(overflow)?;
    out.val_u64(0).map_err(overflow)?;
    out.val_u64(4_096).map_err(overflow)?;
    out.val_u64(0).map_err(overflow)?;
    out.val_u64(0).map_err(overflow)?;
    out.val_u64(0).map_err(overflow)?;
    out.val_u64(0).map_err(overflow)?;
    out.put(&[0]).map_err(overflow)?;
    out.val_bool(false).map_err(overflow)?;
    out.put(&[0]).map_err(overflow)?;
    out.put(&[0]).map_err(overflow)?;
    Ok(())
}

fn probe_fixture_assembly(out: &mut CanonicalWriter) -> Result<(), TypedExecutionError> {
    let overflow = |_| output_limit();
    out.val_str(PROBE_OPERATION_ID).map_err(overflow)?;
    out.val_str(PROBE_TASK_ID).map_err(overflow)?;
    out.val_str(PROBE_SCOPE_ID).map_err(overflow)?;
    out.val_str(PROBE_FENCE_EPOCH).map_err(overflow)?;
    out.val_u64(0).map_err(overflow)?;
    out.val_u64(0).map_err(overflow)?;
    out.val_str(PROBE_ZERO_HEX).map_err(overflow)?;
    out.val_str(PROBE_ZERO_HEX).map_err(overflow)?;
    out.val_u64(0).map_err(overflow)?;
    out.val_opt(None::<&u64>, |writer, _| writer.val_u64(0))
        .map_err(overflow)?;
    out.val_opt(None::<&u64>, |writer, _| writer.val_u64(0))
        .map_err(overflow)?;
    out.val_str(PROBE_SERIALIZER).map_err(overflow)?;
    out.val_str(PROBE_SCHEMA_REVISION).map_err(overflow)?;
    out.val_str(PROBE_ZERO_HEX).map_err(overflow)?;
    out.val_str(PROBE_ZERO_HEX).map_err(overflow)?;
    out.val_disc(1).map_err(overflow)?;
    out.put(&[0]).map_err(overflow)?;
    out.val_bool(false).map_err(overflow)?;
    out.put(&[0]).map_err(overflow)?;
    Ok(())
}

fn probe_fixture_activation(out: &mut CanonicalWriter) -> Result<(), TypedExecutionError> {
    let overflow = |_| output_limit();
    out.val_str(PROBE_REQUEST_ID).map_err(overflow)?;
    out.val_u64(0).map_err(overflow)?;
    out.val_str(PROBE_SNAPSHOT_ID).map_err(overflow)?;
    out.val_u64(0).map_err(overflow)?;
    out.val_u8(4).map_err(overflow)?;
    out.val_u16(8).map_err(overflow)?;
    out.val_u16(8).map_err(overflow)?;
    out.val_u32(16).map_err(overflow)?;
    out.val_u32(16).map_err(overflow)?;
    out.val_u64(1_024).map_err(overflow)?;
    out.val_u16(8).map_err(overflow)?;
    out.val_u16(4).map_err(overflow)?;
    out.val_u16(4).map_err(overflow)?;
    out.val_u16(4).map_err(overflow)?;
    out.val_u16(8).map_err(overflow)?;
    out.val_u32(1_024).map_err(overflow)?;
    out.val_u16(0).map_err(overflow)?;
    out.val_str(PROBE_FENCE_EPOCH).map_err(overflow)?;
    out.val_u64(0).map_err(overflow)?;
    out.val_str(PROBE_PROFILE_ID).map_err(overflow)?;
    out.val_i64(0).map_err(overflow)?;
    out.put(&[0]).map_err(overflow)?;
    out.val_bool(false).map_err(overflow)?;
    Ok(())
}

fn probe_fixture_handler(out: &mut CanonicalWriter) -> Result<(), TypedExecutionError> {
    let overflow = |_| output_limit();
    out.val_str(PROBE_OPERATION_ID).map_err(overflow)?;
    out.val_disc(0).map_err(overflow)?;
    out.val_str(PROBE_PRINCIPAL).map_err(overflow)?;
    out.val_disc(0).map_err(overflow)?;
    out.val_str(PROBE_SESSION_ID).map_err(overflow)?;
    out.val_str(PROBE_TASK_ID).map_err(overflow)?;
    out.val_str(PROBE_ATTEMPT_ID).map_err(overflow)?;
    out.val_str(PROBE_SCOPE_ID).map_err(overflow)?;
    out.val_str(PROBE_FENCE_EPOCH).map_err(overflow)?;
    out.val_u64(0).map_err(overflow)?;
    out.val_str(PROBE_ZERO_HEX).map_err(overflow)?;
    out.val_str(PROBE_ZERO_HEX).map_err(overflow)?;
    out.val_str(PROBE_ZERO_HEX).map_err(overflow)?;
    out.val_str(PROBE_ZERO_HEX).map_err(overflow)?;
    out.val_disc(3).map_err(overflow)?;
    out.val_str(PROBE_WANT_KIND).map_err(overflow)?;
    out.val_str(PROBE_DETAIL).map_err(overflow)?;
    out.val_u32(4_096).map_err(overflow)?;
    out.val_u32(16_384).map_err(overflow)?;
    out.val_u16(1).map_err(overflow)?;
    out.val_u64(50_000).map_err(overflow)?;
    out.val_u8(8).map_err(overflow)?;
    out.val_u64(0).map_err(overflow)?;
    out.put(&[0]).map_err(overflow)?;
    out.val_bool(false).map_err(overflow)?;
    Ok(())
}

fn probe_fixture_screen(out: &mut CanonicalWriter) -> Result<(), TypedExecutionError> {
    let overflow = |_| output_limit();
    out.val_str(PROBE_OPERATION_ID).map_err(overflow)?;
    out.val_str(PROBE_TASK_ID).map_err(overflow)?;
    out.val_str(PROBE_SCOPE_ID).map_err(overflow)?;
    out.val_str(PROBE_FENCE_EPOCH).map_err(overflow)?;
    out.val_u64(0).map_err(overflow)?;
    out.val_str(PROBE_SOURCE_ID).map_err(overflow)?;
    out.val_str(PROBE_SCHEMA_REVISION).map_err(overflow)?;
    out.val_u64(0).map_err(overflow)?;
    out.val_disc(0).map_err(overflow)?;
    out.val_str(PROBE_PROFILE_ID).map_err(overflow)?;
    out.val_u64(0).map_err(overflow)?;
    out.put(&[0]).map_err(overflow)?;
    out.val_bool(false).map_err(overflow)?;
    out.put(&[0]).map_err(overflow)?;
    Ok(())
}

fn probe_fixture_cycle(out: &mut CanonicalWriter) -> Result<(), TypedExecutionError> {
    let overflow = |_| output_limit();
    out.val_str(PROBE_OPERATION_ID).map_err(overflow)?;
    out.val_str(PROBE_TASK_ID).map_err(overflow)?;
    out.val_str(PROBE_SCOPE_ID).map_err(overflow)?;
    out.val_str(PROBE_FENCE_EPOCH).map_err(overflow)?;
    out.val_u64(0).map_err(overflow)?;
    out.val_u32(1).map_err(overflow)?;
    out.val_disc(0).map_err(overflow)?;
    out.val_u32(0).map_err(overflow)?;
    out.val_str(PROBE_ZERO_HEX).map_err(overflow)?;
    out.val_u64(0).map_err(overflow)?;
    out.val_u64(0).map_err(overflow)?;
    out.val_str(PROBE_FENCE_EPOCH).map_err(overflow)?;
    out.val_u64(0).map_err(overflow)?;
    out.val_u32(1).map_err(overflow)?;
    out.val_str(PROBE_PROFILE_ID).map_err(overflow)?;
    out.val_u16(4).map_err(overflow)?;
    out.val_u16(4).map_err(overflow)?;
    out.val_u32(1_024).map_err(overflow)?;
    out.put(&[0]).map_err(overflow)?;
    out.val_bool(false).map_err(overflow)?;
    out.put(&[0]).map_err(overflow)?;
    Ok(())
}

/// Retained typed outcome of the single domain invocation, one variant per
/// world. A `Result` value here is the guest's own typed return: `Ok` is a
/// domain result (success or first-class incomplete) and `Err` is a guest
/// error. Traps, fuel/deadline/resource exhaustion, and output violations
/// never appear here; they keep their own [`TypedExecutionError`] classes.
enum DomainOutput {
    Admission(
        Box<
            Result<
                crate::typed_bindings::context_admission::exports::eliot::current::admission::AdmissionResult,
                crate::typed_bindings::context_admission::exports::eliot::current::admission::AdmissionError,
            >,
        >,
    ),
    Assembly(
        Box<
            Result<
                crate::typed_bindings::context_assembly::exports::eliot::current::assembly::AssemblyResult,
                crate::typed_bindings::context_assembly::exports::eliot::current::assembly::AssemblyError,
            >,
        >,
    ),
    Activation(
        Box<
            Result<
                crate::typed_bindings::cue_activation::exports::eliot::current::activation::ActivationOutcome,
                crate::typed_bindings::cue_activation::exports::eliot::current::activation::ActivationError,
            >,
        >,
    ),
    Handler(
        Box<
            Result<
                crate::typed_bindings::dreamer_handler::exports::eliot::current::handler::HandlerOutcome,
                crate::typed_bindings::dreamer_handler::exports::eliot::current::handler::HandlerError,
            >,
        >,
    ),
    Screen(
        Box<
            Result<
                crate::typed_bindings::memory_curation_screen::exports::eliot::current::screen::ScreenOutcome,
                crate::typed_bindings::memory_curation_screen::exports::eliot::current::screen::ScreenError,
            >,
        >,
    ),
    Cycle(
        Box<
            Result<
                crate::typed_bindings::dreamer_cycle::exports::eliot::current::cycle::CycleOutcome,
                crate::typed_bindings::dreamer_cycle::exports::eliot::current::cycle::CycleError,
            >,
        >,
    ),
}

fn invoke_context_admission(
    engine: &wasmtime::Engine,
    component: &wasmtime::component::Component,
    limits: &InvocationLimits,
) -> Result<(DomainOutput, ObservedUsage), TypedExecutionError> {
    use crate::typed_bindings::context_admission::ContextAdmission;
    use crate::typed_bindings::context_admission::exports::eliot::current::admission as wit;
    let request = wit::AdmissionRequest {
        schema_revision: 1,
        operation_id: PROBE_OPERATION_ID.to_owned(),
        task_id: PROBE_TASK_ID.to_owned(),
        attempt_id: PROBE_ATTEMPT_ID.to_owned(),
        scope_id: PROBE_SCOPE_ID.to_owned(),
        fence_epoch: PROBE_FENCE_EPOCH.to_owned(),
        fence_generation: 0,
        candidates: Vec::new(),
        recipe_digest: PROBE_ZERO_HEX.to_owned(),
        recipe_revision: PROBE_RECIPE_REVISION.to_owned(),
        provider_denominator: Vec::new(),
        capacity: wit::CapacityLimits {
            total_capacity: 4_096,
            fixed_overhead: 0,
            output_reserve: 0,
            review_reserve: 0,
        },
        measurements: Vec::new(),
        deadline_ms: None,
        cancelled: false,
        predecessor_digest: None,
        invalidation: None,
    };
    let (outcome, usage) = run_guarded(engine, limits, |store| {
        let linker = wasmtime::component::Linker::new(engine);
        let instance = ContextAdmission::instantiate(&mut *store, component, &linker)
            .map_err(|error| map_instantiate_error(&error, store.data().limit_hit))?;
        let outcome = instance
            .eliot_current_admission()
            .call_admit(&mut *store, &request)
            .map_err(|error| map_call_error("admit", &error, store.data().limit_hit))?;
        Ok(outcome)
    })?;
    Ok((DomainOutput::Admission(Box::new(outcome)), usage))
}

fn invoke_context_assembly(
    engine: &wasmtime::Engine,
    component: &wasmtime::component::Component,
    limits: &InvocationLimits,
) -> Result<(DomainOutput, ObservedUsage), TypedExecutionError> {
    use crate::typed_bindings::context_assembly::ContextAssembly;
    use crate::typed_bindings::context_assembly::exports::eliot::current::assembly as wit;
    let request = wit::AssemblyRequest {
        schema_revision: 1,
        operation_id: PROBE_OPERATION_ID.to_owned(),
        task_id: PROBE_TASK_ID.to_owned(),
        scope_id: PROBE_SCOPE_ID.to_owned(),
        fence_epoch: PROBE_FENCE_EPOCH.to_owned(),
        fence_generation: 0,
        admitted: Vec::new(),
        admitted_digest: PROBE_ZERO_HEX.to_owned(),
        recipe_digest: PROBE_ZERO_HEX.to_owned(),
        measurement: wit::SerializedMeasurement {
            byte_count: 0,
            stu_estimate: None,
            exact_token_count: None,
            serializer: PROBE_SERIALIZER.to_owned(),
            schema_revision: PROBE_SCHEMA_REVISION.to_owned(),
            input_digest: PROBE_ZERO_HEX.to_owned(),
            output_digest: PROBE_ZERO_HEX.to_owned(),
            proof_ceiling: wit::ProofCeiling::CandidateOnly,
        },
        deadline_ms: None,
        cancelled: false,
        predecessor_digest: None,
    };
    let (outcome, usage) = run_guarded(engine, limits, |store| {
        let linker = wasmtime::component::Linker::new(engine);
        let instance = ContextAssembly::instantiate(&mut *store, component, &linker)
            .map_err(|error| map_instantiate_error(&error, store.data().limit_hit))?;
        let outcome = instance
            .eliot_current_assembly()
            .call_assemble(&mut *store, &request)
            .map_err(|error| map_call_error("assemble", &error, store.data().limit_hit))?;
        Ok(outcome)
    })?;
    Ok((DomainOutput::Assembly(Box::new(outcome)), usage))
}

fn invoke_cue_activation(
    engine: &wasmtime::Engine,
    component: &wasmtime::component::Component,
    limits: &InvocationLimits,
) -> Result<(DomainOutput, ObservedUsage), TypedExecutionError> {
    use crate::typed_bindings::cue_activation::CueActivation;
    use crate::typed_bindings::cue_activation::exports::eliot::current::activation as wit;
    let request = wit::ActivationRequest {
        schema_revision: 1,
        request_id: PROBE_REQUEST_ID.to_owned(),
        seeds: Vec::new(),
        snapshot_id: PROBE_SNAPSHOT_ID.to_owned(),
        relation_edges: Vec::new(),
        bounds: wit::ActivationBounds {
            max_depth: 4,
            max_fanout: 8,
            max_results: 8,
            max_nodes: 16,
            max_edges: 16,
            max_work: 1_024,
            max_path_len: 8,
            max_seeds: 4,
            max_direct: 4,
            max_derived: 4,
            max_trace_steps: 8,
            max_output_bytes: 1_024,
            activation_threshold: 0,
        },
        fence_epoch: PROBE_FENCE_EPOCH.to_owned(),
        fence_generation: 0,
        normalization_profile: PROBE_PROFILE_ID.to_owned(),
        observed_at_ms: 0,
        deadline_ms: None,
        cancelled: false,
    };
    let (outcome, usage) = run_guarded(engine, limits, |store| {
        let linker = wasmtime::component::Linker::new(engine);
        let instance = CueActivation::instantiate(&mut *store, component, &linker)
            .map_err(|error| map_instantiate_error(&error, store.data().limit_hit))?;
        let outcome = instance
            .eliot_current_activation()
            .call_activate(&mut *store, &request)
            .map_err(|error| map_call_error("activate", &error, store.data().limit_hit))?;
        Ok(outcome)
    })?;
    Ok((DomainOutput::Activation(Box::new(outcome)), usage))
}

fn invoke_dreamer_handler(
    engine: &wasmtime::Engine,
    component: &wasmtime::component::Component,
    limits: &InvocationLimits,
) -> Result<(DomainOutput, ObservedUsage), TypedExecutionError> {
    use crate::typed_bindings::dreamer_handler::DreamerHandler;
    use crate::typed_bindings::dreamer_handler::exports::eliot::current::handler as wit;
    let candidate = wit::ValidatedCandidate {
        schema_revision: 1,
        operation_id: PROBE_OPERATION_ID.to_owned(),
        job: wit::JobClass::Orientation,
        requester: wit::Requester {
            principal: PROBE_PRINCIPAL.to_owned(),
            origin: wit::RequesterOrigin::Human,
            session: PROBE_SESSION_ID.to_owned(),
        },
        task_id: PROBE_TASK_ID.to_owned(),
        attempt_id: PROBE_ATTEMPT_ID.to_owned(),
        scope_id: PROBE_SCOPE_ID.to_owned(),
        fence_epoch: PROBE_FENCE_EPOCH.to_owned(),
        fence_generation: 0,
        bundle_digest: PROBE_ZERO_HEX.to_owned(),
        manifest_digest: PROBE_ZERO_HEX.to_owned(),
        grounding_digest: PROBE_ZERO_HEX.to_owned(),
        validation_receipt: PROBE_ZERO_HEX.to_owned(),
        subtype: wit::HandlerSubtype::Unsupported(wit::UnsupportedSubtype {
            want_kind: PROBE_WANT_KIND.to_owned(),
            human_detail: PROBE_DETAIL.to_owned(),
        }),
        budget: wit::BudgetLimits {
            max_input_bytes: 4_096,
            max_output_bytes: 16_384,
            max_candidates: 1,
            max_work: 50_000,
            max_depth: 8,
        },
        preservation: wit::PreservationReport {
            verdicts: Vec::new(),
        },
        deadline_ms: None,
        cancelled: false,
    };
    let (outcome, usage) = run_guarded(engine, limits, |store| {
        let linker = wasmtime::component::Linker::new(engine);
        let instance = DreamerHandler::instantiate(&mut *store, component, &linker)
            .map_err(|error| map_instantiate_error(&error, store.data().limit_hit))?;
        let outcome = instance
            .eliot_current_handler()
            .call_handle(&mut *store, &candidate)
            .map_err(|error| map_call_error("handle", &error, store.data().limit_hit))?;
        Ok(outcome)
    })?;
    Ok((DomainOutput::Handler(Box::new(outcome)), usage))
}

fn invoke_memory_curation_screen(
    engine: &wasmtime::Engine,
    component: &wasmtime::component::Component,
    limits: &InvocationLimits,
) -> Result<(DomainOutput, ObservedUsage), TypedExecutionError> {
    use crate::typed_bindings::memory_curation_screen::MemoryCurationScreen;
    use crate::typed_bindings::memory_curation_screen::exports::eliot::current::screen as wit;
    let request = wit::ScreenRequest {
        schema_revision: 1,
        operation_id: PROBE_OPERATION_ID.to_owned(),
        task_id: PROBE_TASK_ID.to_owned(),
        scope_id: PROBE_SCOPE_ID.to_owned(),
        fence_epoch: PROBE_FENCE_EPOCH.to_owned(),
        fence_generation: 0,
        source_id: PROBE_SOURCE_ID.to_owned(),
        snapshot_revision: PROBE_SCHEMA_REVISION.to_owned(),
        members: Vec::new(),
        availability: wit::SourceAvailability::Available,
        profile_id: PROBE_PROFILE_ID.to_owned(),
        rule_ids: Vec::new(),
        deadline_ms: None,
        cancelled: false,
        predecessor_digest: None,
    };
    let (outcome, usage) = run_guarded(engine, limits, |store| {
        let linker = wasmtime::component::Linker::new(engine);
        let instance = MemoryCurationScreen::instantiate(&mut *store, component, &linker)
            .map_err(|error| map_instantiate_error(&error, store.data().limit_hit))?;
        let outcome = instance
            .eliot_current_screen()
            .call_screen(&mut *store, &request)
            .map_err(|error| map_call_error("screen", &error, store.data().limit_hit))?;
        Ok(outcome)
    })?;
    Ok((DomainOutput::Screen(Box::new(outcome)), usage))
}

fn invoke_dreamer_cycle(
    engine: &wasmtime::Engine,
    component: &wasmtime::component::Component,
    limits: &InvocationLimits,
) -> Result<(DomainOutput, ObservedUsage), TypedExecutionError> {
    use crate::typed_bindings::dreamer_cycle::DreamerCycle;
    use crate::typed_bindings::dreamer_cycle::exports::eliot::current::cycle as wit;
    let input = wit::CycleStepInput {
        schema_revision: 1,
        operation_id: PROBE_OPERATION_ID.to_owned(),
        task_id: PROBE_TASK_ID.to_owned(),
        scope_id: PROBE_SCOPE_ID.to_owned(),
        fence_epoch: PROBE_FENCE_EPOCH.to_owned(),
        fence_generation: 0,
        state: wit::DreamerState {
            schema_version: 1,
            phase: wit::CyclePhase::Validated,
            revision: 0,
            state_digest: PROBE_ZERO_HEX.to_owned(),
            pending: Vec::new(),
            observed: Vec::new(),
            fence_epoch: PROBE_FENCE_EPOCH.to_owned(),
            fence_generation: 0,
        },
        policy: wit::CyclePolicy {
            schema_version: 1,
            policy_revision: PROBE_PROFILE_ID.to_owned(),
            max_records: 4,
            max_requests: 4,
            max_canonical_bytes: 1_024,
        },
        deadline_ms: None,
        cancelled: false,
        predecessor_digest: None,
    };
    let (outcome, usage) = run_guarded(engine, limits, |store| {
        let linker = wasmtime::component::Linker::new(engine);
        let instance = DreamerCycle::instantiate(&mut *store, component, &linker)
            .map_err(|error| map_instantiate_error(&error, store.data().limit_hit))?;
        let outcome = instance
            .eliot_current_cycle()
            .call_step(&mut *store, &input)
            .map_err(|error| map_call_error("step", &error, store.data().limit_hit))?;
        Ok(outcome)
    })?;
    Ok((DomainOutput::Cycle(Box::new(outcome)), usage))
}

/// Invokes the world's domain export exactly once in its own Store under
/// the same full limit envelope as the descriptor gate. Never retries
/// another world or a second invocation after uncertainty.
fn dispatch_domain(
    world: TypedWorld,
    engine: &wasmtime::Engine,
    component: &wasmtime::component::Component,
    limits: &InvocationLimits,
) -> Result<(DomainOutput, ObservedUsage), TypedExecutionError> {
    match world {
        TypedWorld::ContextAdmission => invoke_context_admission(engine, component, limits),
        TypedWorld::ContextAssembly => invoke_context_assembly(engine, component, limits),
        TypedWorld::CueActivation => invoke_cue_activation(engine, component, limits),
        TypedWorld::DreamerHandler => invoke_dreamer_handler(engine, component, limits),
        TypedWorld::MemoryCurationScreen => {
            invoke_memory_curation_screen(engine, component, limits)
        }
        TypedWorld::DreamerCycle => invoke_dreamer_cycle(engine, component, limits),
    }
}

/// Builds the terminal outcome plus the bounded canonical output encoding
/// for one retained domain result. Identity echoes must match the probe,
/// the ceiling must not exceed candidate-only, and every encoded byte is
/// debited from `max_output_bytes` before it is stored. Guest-error payloads
/// never cross: only the variant case name becomes the disposition.
fn check_domain_output(
    output: &DomainOutput,
    max_output_bytes: u64,
) -> Result<(DomainTerminal, Sha256Digest, u64), TypedExecutionError> {
    let mut out = CanonicalWriter::new(max_output_bytes);
    let terminal = match output {
        DomainOutput::Admission(outcome) => check_admission(outcome, &mut out)?,
        DomainOutput::Assembly(outcome) => check_assembly(outcome, &mut out)?,
        DomainOutput::Activation(outcome) => check_activation(outcome, &mut out)?,
        DomainOutput::Handler(outcome) => check_handler(outcome, &mut out)?,
        DomainOutput::Screen(outcome) => check_screen(outcome, &mut out)?,
        DomainOutput::Cycle(outcome) => check_cycle(outcome, &mut out)?,
    };
    let bytes = out.finish();
    let len = u64::try_from(bytes.len()).map_err(|_| output_limit())?;
    let digest = Sha256Digest::of_bytes(&bytes);
    Ok((terminal, digest, len))
}

fn check_admission(
    outcome: &Result<crate::typed_bindings::context_admission::exports::eliot::current::admission::AdmissionResult, crate::typed_bindings::context_admission::exports::eliot::current::admission::AdmissionError>,
    out: &mut CanonicalWriter,
) -> Result<DomainTerminal, TypedExecutionError> {
    use crate::typed_bindings::context_admission::exports::eliot::current::admission as wit_admission;
    let overflow = |_| output_limit();
    match outcome {
        Ok(result) => match result {
            wit_admission::AdmissionResult::Admitted(set) => {
                check_identity("operation-id", &set.operation_id, PROBE_OPERATION_ID)?;
                check_identity("task-id", &set.task_id, PROBE_TASK_ID)?;
                check_identity("attempt-id", &set.attempt_id, PROBE_ATTEMPT_ID)?;
                check_identity("scope-id", &set.scope_id, PROBE_SCOPE_ID)?;
                check_identity("fence-epoch", &set.fence_epoch, PROBE_FENCE_EPOCH)?;
                check_digest_hex("canonical-digest", &set.canonical_digest)?;
                let ceiling = neutral_ceiling(&format!("{:?}", set.proof_ceiling))?;
                let ceiling_name = check_ceiling(ceiling)?;
                out.val_str("admitted").map_err(overflow)?;
                out.val_str(&set.operation_id).map_err(overflow)?;
                out.val_str(&set.task_id).map_err(overflow)?;
                out.val_str(&set.scope_id).map_err(overflow)?;
                out.val_str(&set.fence_epoch).map_err(overflow)?;
                out.val_str(&ceiling_name).map_err(overflow)?;
                out.val_str(&set.canonical_digest).map_err(overflow)?;
                Ok(DomainTerminal {
                    operation: TypedWorld::ContextAdmission.domain_func().to_owned(),
                    disposition: "COMPLETED".to_owned(),
                    proof_ceiling: ceiling_name,
                })
            }
            wit_admission::AdmissionResult::Incomplete(decision) => {
                let code = match format!("{:?}", decision.code).as_str() {
                    "DecisionContextIncomplete" => "decision-context-incomplete",
                    _ => {
                        return Err(TypedExecutionError::OutputViolation(
                            "incomplete-code".to_owned(),
                        ));
                    }
                };
                let ceiling = neutral_ceiling(&format!("{:?}", decision.proof_ceiling))?;
                let ceiling_name = check_ceiling(ceiling)?;
                out.val_str("incomplete").map_err(overflow)?;
                out.val_disc(0).map_err(overflow)?;
                for list_len in [
                    decision.missing.len(),
                    decision.stale.len(),
                    decision.blocked.len(),
                    decision.unavailable.len(),
                    decision.omitted.len(),
                    decision.exhausted.len(),
                    decision.unknown.len(),
                    decision.known_empty.len(),
                    decision.partial.len(),
                    decision.provider_gaps.len(),
                    decision.oversized.len(),
                    decision.measurements.len(),
                ] {
                    out.val_u64(u64::try_from(list_len).map_err(|_| output_limit())?)
                        .map_err(overflow)?;
                }
                out.val_str(&ceiling_name).map_err(overflow)?;
                Ok(DomainTerminal {
                    operation: TypedWorld::ContextAdmission.domain_func().to_owned(),
                    disposition: format!("INCOMPLETE:{code}"),
                    proof_ceiling: ceiling_name,
                })
            }
        },
        Err(error) => {
            let case = match error {
                wit_admission::AdmissionError::Malformed(_) => "malformed",
                wit_admission::AdmissionError::DenominatorMismatch(_) => "denominator-mismatch",
                wit_admission::AdmissionError::StaleFence(_) => "stale-fence",
                wit_admission::AdmissionError::CapacityExceeded(_) => "capacity-exceeded",
                wit_admission::AdmissionError::UnknownMeasurement(_) => "unknown-measurement",
                wit_admission::AdmissionError::OmissionHandleInvalid(_) => {
                    "omission-handle-invalid"
                }
                wit_admission::AdmissionError::EconomyMismatch(_) => "economy-mismatch",
                wit_admission::AdmissionError::UnsupportedSchema(_) => "unsupported-schema",
                wit_admission::AdmissionError::Internal(_) => "internal",
            };
            Ok(guest_error_terminal(TypedWorld::ContextAdmission, case))
        }
    }
}

fn check_assembly(
    outcome: &Result<
        crate::typed_bindings::context_assembly::exports::eliot::current::assembly::AssemblyResult,
        crate::typed_bindings::context_assembly::exports::eliot::current::assembly::AssemblyError,
    >,
    out: &mut CanonicalWriter,
) -> Result<DomainTerminal, TypedExecutionError> {
    use crate::typed_bindings::context_assembly::exports::eliot::current::assembly as wit_assembly;
    let overflow = |_| output_limit();
    match outcome {
        Ok(result) => match result {
            wit_assembly::AssemblyResult::Assembled(view) => {
                check_identity("operation-id", &view.operation_id, PROBE_OPERATION_ID)?;
                check_identity("task-id", &view.task_id, PROBE_TASK_ID)?;
                check_identity("scope-id", &view.scope_id, PROBE_SCOPE_ID)?;
                check_identity("fence-epoch", &view.fence_epoch, PROBE_FENCE_EPOCH)?;
                check_digest_hex("canonical-digest", &view.canonical_digest)?;
                let ceiling = neutral_ceiling(&format!("{:?}", view.proof_ceiling))?;
                let ceiling_name = check_ceiling(ceiling)?;
                out.val_str("assembled").map_err(overflow)?;
                out.val_str(&view.operation_id).map_err(overflow)?;
                out.val_str(&view.task_id).map_err(overflow)?;
                out.val_str(&view.scope_id).map_err(overflow)?;
                out.val_str(&view.fence_epoch).map_err(overflow)?;
                out.val_str(&ceiling_name).map_err(overflow)?;
                out.val_str(&view.canonical_digest).map_err(overflow)?;
                Ok(DomainTerminal {
                    operation: TypedWorld::ContextAssembly.domain_func().to_owned(),
                    disposition: "COMPLETED".to_owned(),
                    proof_ceiling: ceiling_name,
                })
            }
        },
        Err(error) => {
            let case = match error {
                wit_assembly::AssemblyError::Malformed(_) => "malformed",
                wit_assembly::AssemblyError::SelectionMismatch(_) => "selection-mismatch",
                wit_assembly::AssemblyError::QualityIncomplete(_) => "quality-incomplete",
                wit_assembly::AssemblyError::MeasurementMismatch(_) => "measurement-mismatch",
                wit_assembly::AssemblyError::UnsupportedSchema(_) => "unsupported-schema",
                wit_assembly::AssemblyError::Internal(_) => "internal",
            };
            Ok(guest_error_terminal(TypedWorld::ContextAssembly, case))
        }
    }
}

fn check_activation(
    outcome: &Result<crate::typed_bindings::cue_activation::exports::eliot::current::activation::ActivationOutcome, crate::typed_bindings::cue_activation::exports::eliot::current::activation::ActivationError>,
    out: &mut CanonicalWriter,
) -> Result<DomainTerminal, TypedExecutionError> {
    use crate::typed_bindings::cue_activation::exports::eliot::current::activation as wit_activation;
    let overflow = |_| output_limit();
    match outcome {
        Ok(result) => match result {
            wit_activation::ActivationOutcome::Activated(body) => {
                check_identity("request-id", &body.request_id, PROBE_REQUEST_ID)?;
                check_identity("snapshot-id", &body.snapshot_id, PROBE_SNAPSHOT_ID)?;
                check_digest_hex("result-digest", &body.result_digest)?;
                let ceiling = neutral_ceiling(&format!("{:?}", body.proof_ceiling))?;
                let ceiling_name = check_ceiling(ceiling)?;
                out.val_str("activated").map_err(overflow)?;
                out.val_str(&body.request_id).map_err(overflow)?;
                out.val_str(&body.snapshot_id).map_err(overflow)?;
                out.val_str(&ceiling_name).map_err(overflow)?;
                out.val_str(&body.result_digest).map_err(overflow)?;
                Ok(DomainTerminal {
                    operation: TypedWorld::CueActivation.domain_func().to_owned(),
                    disposition: "COMPLETED".to_owned(),
                    proof_ceiling: ceiling_name,
                })
            }
        },
        Err(error) => {
            let case = match error {
                wit_activation::ActivationError::Malformed(_) => "malformed",
                wit_activation::ActivationError::BoundExceeded(_) => "bound-exceeded",
                wit_activation::ActivationError::StaleSnapshot(_) => "stale-snapshot",
                wit_activation::ActivationError::UnsupportedSchema(_) => "unsupported-schema",
                wit_activation::ActivationError::Internal(_) => "internal",
            };
            Ok(guest_error_terminal(TypedWorld::CueActivation, case))
        }
    }
}

fn check_handler(
    outcome: &Result<
        crate::typed_bindings::dreamer_handler::exports::eliot::current::handler::HandlerOutcome,
        crate::typed_bindings::dreamer_handler::exports::eliot::current::handler::HandlerError,
    >,
    out: &mut CanonicalWriter,
) -> Result<DomainTerminal, TypedExecutionError> {
    use crate::typed_bindings::dreamer_handler::exports::eliot::current::handler as wit_handler;
    let overflow = |_| output_limit();
    match outcome {
        Ok(result) => match result {
            wit_handler::HandlerOutcome::Handled(body) => {
                check_identity("operation-id", &body.operation_id, PROBE_OPERATION_ID)?;
                check_digest_hex("output-digest", &body.output_digest)?;
                let ceiling = neutral_ceiling(&format!("{:?}", body.proof_ceiling))?;
                let ceiling_name = check_ceiling(ceiling)?;
                out.val_str("handled").map_err(overflow)?;
                out.val_str(&body.operation_id).map_err(overflow)?;
                out.val_str(&ceiling_name).map_err(overflow)?;
                out.val_str(&body.output_digest).map_err(overflow)?;
                Ok(DomainTerminal {
                    operation: TypedWorld::DreamerHandler.domain_func().to_owned(),
                    disposition: "COMPLETED".to_owned(),
                    proof_ceiling: ceiling_name,
                })
            }
        },
        Err(error) => {
            let case = match error {
                wit_handler::HandlerError::Malformed(_) => "malformed",
                wit_handler::HandlerError::KindMismatch(_) => "kind-mismatch",
                wit_handler::HandlerError::UnsupportedSubtypeError(_) => {
                    "unsupported-subtype-error"
                }
                wit_handler::HandlerError::BudgetExceeded(_) => "budget-exceeded",
                wit_handler::HandlerError::UnsupportedSchema(_) => "unsupported-schema",
                wit_handler::HandlerError::Internal(_) => "internal",
            };
            Ok(guest_error_terminal(TypedWorld::DreamerHandler, case))
        }
    }
}

fn check_screen(
    outcome: &Result<crate::typed_bindings::memory_curation_screen::exports::eliot::current::screen::ScreenOutcome, crate::typed_bindings::memory_curation_screen::exports::eliot::current::screen::ScreenError>,
    out: &mut CanonicalWriter,
) -> Result<DomainTerminal, TypedExecutionError> {
    use crate::typed_bindings::memory_curation_screen::exports::eliot::current::screen as wit_screen;
    let overflow = |_| output_limit();
    match outcome {
        Ok(result) => match result {
            wit_screen::ScreenOutcome::Screened(body) => {
                check_identity("operation-id", &body.operation_id, PROBE_OPERATION_ID)?;
                check_identity("task-id", &body.task_id, PROBE_TASK_ID)?;
                check_identity("scope-id", &body.scope_id, PROBE_SCOPE_ID)?;
                check_identity("fence-epoch", &body.fence_epoch, PROBE_FENCE_EPOCH)?;
                check_digest_hex("result-digest", &body.result_digest)?;
                let ceiling = neutral_ceiling(&format!("{:?}", body.proof_ceiling))?;
                let ceiling_name = check_ceiling(ceiling)?;
                out.val_str("screened").map_err(overflow)?;
                out.val_str(&body.operation_id).map_err(overflow)?;
                out.val_str(&body.task_id).map_err(overflow)?;
                out.val_str(&body.scope_id).map_err(overflow)?;
                out.val_str(&body.fence_epoch).map_err(overflow)?;
                out.val_str(&ceiling_name).map_err(overflow)?;
                out.val_str(&body.result_digest).map_err(overflow)?;
                Ok(DomainTerminal {
                    operation: TypedWorld::MemoryCurationScreen.domain_func().to_owned(),
                    disposition: "COMPLETED".to_owned(),
                    proof_ceiling: ceiling_name,
                })
            }
        },
        Err(error) => {
            let case = match error {
                wit_screen::ScreenError::Malformed(_) => "malformed",
                wit_screen::ScreenError::CancelledScreen(_) => "cancelled-screen",
                wit_screen::ScreenError::UnsupportedSchema(_) => "unsupported-schema",
                wit_screen::ScreenError::Internal(_) => "internal",
            };
            Ok(guest_error_terminal(TypedWorld::MemoryCurationScreen, case))
        }
    }
}

fn check_cycle(
    outcome: &Result<
        crate::typed_bindings::dreamer_cycle::exports::eliot::current::cycle::CycleOutcome,
        crate::typed_bindings::dreamer_cycle::exports::eliot::current::cycle::CycleError,
    >,
    out: &mut CanonicalWriter,
) -> Result<DomainTerminal, TypedExecutionError> {
    use crate::typed_bindings::dreamer_cycle::exports::eliot::current::cycle as wit_cycle;
    let overflow = |_| output_limit();
    match outcome {
        Ok(result) => match result {
            wit_cycle::CycleOutcome::Stepped(body) => {
                check_identity("operation-id", &body.operation_id, PROBE_OPERATION_ID)?;
                check_digest_hex("result-digest", &body.result_digest)?;
                let ceiling = neutral_ceiling(&format!("{:?}", body.proof_ceiling))?;
                let ceiling_name = check_ceiling(ceiling)?;
                out.val_str("stepped").map_err(overflow)?;
                out.val_str(&body.operation_id).map_err(overflow)?;
                out.val_str(&ceiling_name).map_err(overflow)?;
                out.val_str(&body.result_digest).map_err(overflow)?;
                Ok(DomainTerminal {
                    operation: TypedWorld::DreamerCycle.domain_func().to_owned(),
                    disposition: "COMPLETED".to_owned(),
                    proof_ceiling: ceiling_name,
                })
            }
        },
        Err(error) => {
            let case = match error {
                wit_cycle::CycleError::Malformed(_) => "malformed",
                wit_cycle::CycleError::StaleTransition(_) => "stale-transition",
                wit_cycle::CycleError::BoundExceeded(_) => "bound-exceeded",
                wit_cycle::CycleError::UnsupportedSchema(_) => "unsupported-schema",
                wit_cycle::CycleError::Internal(_) => "internal",
            };
            Ok(guest_error_terminal(TypedWorld::DreamerCycle, case))
        }
    }
}

/// Retained guest-error terminal: the exact domain result is kept as its own
/// disposition class, never rewritten to Host success and never confused
/// with a trap. No payload, path, or secret crosses; the case name is the
/// whole content.
fn guest_error_terminal(world: TypedWorld, case: &'static str) -> DomainTerminal {
    DomainTerminal {
        operation: world.domain_func().to_owned(),
        disposition: format!("GUEST_ERROR:{case}"),
        proof_ceiling: String::new(),
    }
}

/// Executes the descriptor gate and then the single typed domain invocation
/// for one world through the real Wasmtime component engine.
///
/// Reads nothing: the caller supplies the exact immutable buffer, which is
/// hashed (preflight) and compiled once. After the `describe` identity gate,
/// the experimental path consumes #760's neutral operation capsule
/// ([`ModuleContractKit`] + [`ModuleTestCapsule`]): the kit binds
/// package/world/ABI/artifact with a candidate-only non-governed ceiling,
/// the capsule binds the exact world/operation, the canonical probe-input
/// bytes, and the enforced bounds, and the generated domain export is
/// invoked exactly once under the same limits/cancellation policy. The typed
/// terminal result (success, first-class incomplete, or guest error) is
/// retained exactly; traps, limit, and output violations keep their own
/// classes. Observed usage in the receipt is the single bounded domain
/// call, which is the call the receipt succeeds or fails on.
pub fn execute_domain_experimental(
    world: TypedWorld,
    artifact: &[u8],
    limits: &InvocationLimits,
) -> Result<(TypedReceipt, TypedDescriptor, DomainTerminal), TypedExecutionError> {
    let start = Instant::now();
    let preflight = preflight_bytes(artifact)?;
    validate_limits(limits, &preflight.digest)?;

    let engine = configured_engine()?;
    let component = wasmtime::component::Component::new(&engine, artifact)
        .map_err(|error| map_compile_error(&error))?;

    let (imports, exports) = preflight_component_type(world, &engine, &component)?;

    let (descriptor, _) = dispatch_describe(world, &engine, &component, limits)?;
    let (output_digest, output_bytes) =
        validate_descriptor(world, &descriptor, limits.max_output_bytes)?;

    let kit = experimental_kit(world, &descriptor, &preflight.digest, preflight.byte_len)?;
    let fixture = domain_probe_fixture(world, limits.max_input_bytes)?;
    let input_digest = Sha256Digest::of_bytes(&fixture);
    let capsule = experimental_capsule(world, &kit, limits, fixture)?;
    if capsule.operation != world.domain_func() {
        return Err(TypedExecutionError::CapsuleDenied("operation".to_owned()));
    }

    let (output, usage) = dispatch_domain(world, &engine, &component, limits)?;
    let (terminal_outcome, domain_output_digest, domain_output_bytes) =
        check_domain_output(&output, limits.max_output_bytes)?;

    let elapsed_ms = u64::try_from(start.elapsed().as_millis()).unwrap_or(u64::MAX);
    let terminal = terminal_outcome.disposition.clone();
    let mut receipt = TypedReceipt {
        proof: ExecutionMode::LocalExperimental.proof().to_owned(),
        world: world.world_name().to_owned(),
        package_id: crate::typed_bindings::TYPED_PACKAGE_ID.to_owned(),
        artifact_digest: preflight.digest.clone(),
        artifact_bytes: preflight.byte_len,
        engine_version: ENGINE_VERSION.to_owned(),
        engine_config_digest: typed_engine_binding().engine_configuration_digest,
        wit_digest: typed_wit_digest(),
        actual_imports: imports,
        actual_exports: exports,
        input_digest: input_digest.clone(),
        output_digest: output_digest.clone(),
        output_bytes,
        configured: limits.clone(),
        stages: vec![
            "compile".to_owned(),
            "instantiate".to_owned(),
            "descriptor".to_owned(),
            "invoke".to_owned(),
            "output".to_owned(),
            "cleanup".to_owned(),
        ],
        domain_operation: world.domain_func().to_owned(),
        domain_input_digest: input_digest,
        domain_output_digest: domain_output_digest.clone(),
        domain_output_bytes,
        domain_ceiling: terminal_outcome.proof_ceiling.clone(),
        fuel_consumed: usage.fuel_consumed,
        peak_memory_bytes: usage.peak_memory_bytes,
        table_elements: usage.table_elements,
        instances: 1,
        elapsed_ms,
        terminal,
        semantic_digest: Sha256Digest::of_bytes(&[]),
    };
    receipt.semantic_digest = semantic_digest(&receipt);
    Ok((receipt, descriptor, terminal_outcome))
}
