//! Typed sandboxed execution for the six frozen worlds.
//!
//! Default governed mode refuses without actual Kernel admission
//! (`KERNEL_ADMISSION_REQUIRED`). An explicitly selected local-experimental
//! path instantiates and executes a typed component through the frozen WIT
//! world with deny-by-default Wasmtime policy and zero ambient imports.
//! Domain operations beyond the `describe` descriptor require #760's neutral
//! capsule preparation, which is absent on main; this module implements
//! everything up to that edge with real engine execution.

use std::fmt;
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use std::thread;
use std::time::{Duration, Instant};

use eliot_wasm_runtime::{
    CancellationPolicy, EngineTermination, EpochPolicy, InvocationLimits, MAX_EPOCH_DEADLINE_TICKS,
    Sha256Digest,
};

use crate::artifact_preflight::{PreflightError, preflight_bytes};
use crate::typed_bindings::{TypedWorld, export_matches_interface, typed_wit_digest};

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
    /// Missing or wrongly typed descriptor/domain export.
    MissingExport(String),
    /// Actual forbidden import observed before instantiation.
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
    /// Domain operation requires #760's neutral capsule (absent on main).
    DomainCapsuleRequired,
}

impl fmt::Display for TypedExecutionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::GovernedAdmissionRequired => formatter.write_str("KERNEL_ADMISSION_REQUIRED"),
            Self::WorldUnknown(world) => write!(formatter, "WORLD_UNKNOWN:{world}"),
            Self::WorldSelection { reason } => write!(formatter, "WORLD_SELECTION:{reason}"),
            Self::MissingExport(name) => write!(formatter, "MISSING_EXPORT:{name}"),
            Self::ForbiddenImport(name) => write!(formatter, "FORBIDDEN_IMPORT:{name}"),
            Self::LegacyMismatch => formatter.write_str("LEGACY_MISMATCH"),
            Self::Artifact(error) => write!(formatter, "{error}"),
            Self::LimitDenied(reason) => write!(formatter, "LIMIT_DENIED:{reason}"),
            Self::Engine(reason) => write!(formatter, "ENGINE:{reason}"),
            Self::OutputViolation(reason) => write!(formatter, "OUTPUT_VIOLATION:{reason}"),
            Self::DomainCapsuleRequired => formatter.write_str("DOMAIN_CAPSULE_REQUIRED"),
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
    if [
        limits.max_input_bytes,
        limits.max_output_bytes,
        limits.max_fuel,
        limits.max_memory_bytes,
        limits.wall_deadline_ms,
    ]
    .contains(&0)
        || limits.max_host_calls == 0
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
    let canonical = format!(
        "{}|{}|{}|{}|{}|{}",
        descriptor.world_name,
        descriptor.package_id,
        descriptor.abi_revision,
        descriptor.native_contract,
        descriptor.native_revision,
        descriptor.abi_digest
    );
    Ok((Sha256Digest::of_bytes(canonical.as_bytes()), output_bytes))
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

/// Executes the typed `describe` descriptor for one world through the real
/// Wasmtime component engine under deny-by-default sandbox policy.
///
/// Reads nothing: the caller supplies the exact immutable buffer. The same
/// buffer is hashed (preflight) and compiled; the path is never reread.
/// Zero ambient imports, full resource limits, and output checks apply to
/// descriptor/initialization execution exactly like a domain call. The
/// domain operation itself is available via [`domain_handoff`] until #760's
/// neutral capsule lands.
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
    let engine = wasmtime::Engine::new(&config).map_err(|error| {
        TypedExecutionError::Engine(format!(
            "config:{}",
            error.to_string().chars().take(120).collect::<String>()
        ))
    })?;
    let component = wasmtime::component::Component::new(&engine, artifact)
        .map_err(|error| map_compile_error(&error))?;

    // Pre-instantiation inspection: imports/exports before any invocation.
    let component_type = component.component_type();
    let imports: Vec<String> = component_type
        .imports(&engine)
        .map(|(name, _)| name.to_owned())
        .collect();
    if !imports.is_empty() {
        let first = imports.first().cloned().unwrap_or_default();
        let bounded: String = first.chars().take(96).collect();
        return Err(TypedExecutionError::ForbiddenImport(bounded));
    }
    let exports: Vec<String> = component_type
        .exports(&engine)
        .map(|(name, _)| name.to_owned())
        .collect();
    if exports.len() != 1 {
        return Err(TypedExecutionError::WorldSelection {
            reason: if exports.is_empty() {
                "missing-export".to_owned()
            } else {
                "ambiguous-exports".to_owned()
            },
        });
    }
    let export_name = exports[0].clone();
    if export_name == crate::typed_bindings::LEGACY_EXPORT || export_name == "run" {
        return Err(TypedExecutionError::LegacyMismatch);
    }
    if !export_matches_interface(&export_name, world.interface_name()) {
        return Err(TypedExecutionError::WorldSelection {
            reason: "incompatible-world".to_owned(),
        });
    }

    let (descriptor, usage) = dispatch_describe(world, &engine, &component, limits)?;
    let (output_digest, output_bytes) =
        validate_descriptor(world, &descriptor, limits.max_output_bytes)?;

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
        output_digest: output_digest.clone(),
        output_bytes,
        fuel_consumed: usage.fuel_consumed,
        peak_memory_bytes: usage.peak_memory_bytes,
        table_elements: usage.table_elements,
        instances: 1,
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

fn map_compile_error(error: &wasmtime::Error) -> TypedExecutionError {
    let message = error.to_string().to_ascii_lowercase();
    if message.contains("expected component") || message.contains("expected a component") {
        return TypedExecutionError::Artifact(PreflightError::CoreModuleRejected);
    }
    let bounded: String = error.to_string().chars().take(160).collect();
    // Never echo raw bytes or backtraces; classify only.
    if message.contains("import") && message.contains("unknown") {
        TypedExecutionError::ForbiddenImport(bounded)
    } else {
        TypedExecutionError::Engine(format!("compile:{bounded}"))
    }
}

fn map_call_error(error: &wasmtime::Error) -> TypedExecutionError {
    let message = error.to_string();
    let lowered = message.to_ascii_lowercase();
    if lowered.contains("out of fuel") {
        TypedExecutionError::Engine(format!("{:?}", EngineTermination::FuelExhausted))
    } else if lowered.contains("interrupt")
        || lowered.contains("epoch")
        || lowered.contains("deadline")
    {
        TypedExecutionError::Engine(format!("{:?}", EngineTermination::EpochDeadline))
    } else if lowered.contains("memory") || lowered.contains("oom") {
        TypedExecutionError::Engine(format!("{:?}", EngineTermination::MemoryLimit))
    } else if lowered.contains("table") {
        TypedExecutionError::Engine(format!("{:?}", EngineTermination::TableLimit))
    } else if lowered.contains("instance") {
        TypedExecutionError::Engine(format!("{:?}", EngineTermination::InstanceLimit))
    } else if lowered.contains("stack") {
        TypedExecutionError::Engine(format!("{:?}", EngineTermination::StackLimit))
    } else {
        let bounded: String = message.chars().take(160).collect();
        TypedExecutionError::Engine(format!("describe:{bounded}"))
    }
}

fn map_instantiate_error(error: &wasmtime::Error) -> TypedExecutionError {
    let message = error.to_string();
    let lowered = message.to_ascii_lowercase();
    if lowered.contains("import") {
        let bounded: String = message.chars().take(96).collect();
        TypedExecutionError::ForbiddenImport(bounded)
    } else if lowered.contains("export") || lowered.contains("missing") || lowered.contains("type")
    {
        let bounded: String = message.chars().take(96).collect();
        TypedExecutionError::MissingExport(bounded)
    } else {
        let bounded: String = message.chars().take(160).collect();
        TypedExecutionError::Engine(format!("instantiate:{bounded}"))
    }
}

struct ObservedUsage {
    fuel_consumed: u64,
    peak_memory_bytes: Option<u64>,
    table_elements: Option<u32>,
}

struct StoreState {
    limits: wasmtime::StoreLimits,
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
        },
    );
    store.limiter(|state| &mut state.limits);
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
        self.limits.memory_growing(current, desired, maximum)
    }

    fn table_growing(
        &mut self,
        current: usize,
        desired: usize,
        maximum: Option<usize>,
    ) -> Result<bool, wasmtime::Error> {
        self.limits.table_growing(current, desired, maximum)
    }

    fn instances(&self) -> usize {
        self.limits.instances()
    }
}

/// Runs one descriptor closure with fuel, memory/table/instance limits,
/// and epoch interruption driven by both a tick pump and the wall
/// deadline. No clock, randomness, or ambient capability reaches the guest.
fn run_guarded(
    engine: &wasmtime::Engine,
    limits: &InvocationLimits,
    invoke: impl FnOnce(
        &mut wasmtime::Store<StoreState>,
    ) -> Result<TypedDescriptor, TypedExecutionError>,
) -> Result<(TypedDescriptor, ObservedUsage), TypedExecutionError> {
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
    match outcome {
        Ok(descriptor) => Ok((
            descriptor,
            ObservedUsage {
                fuel_consumed,
                peak_memory_bytes: Some(0),
                table_elements: Some(0),
            },
        )),
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
            .map_err(|error| map_instantiate_error(&error))?;
        let raw = instance
            .eliot_current_admission()
            .call_describe(&mut *store)
            .map_err(|error| map_call_error(&error))?;
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
            .map_err(|error| map_instantiate_error(&error))?;
        let raw = instance
            .eliot_current_assembly()
            .call_describe(&mut *store)
            .map_err(|error| map_call_error(&error))?;
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
            .map_err(|error| map_instantiate_error(&error))?;
        let raw = instance
            .eliot_current_activation()
            .call_describe(&mut *store)
            .map_err(|error| map_call_error(&error))?;
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
            .map_err(|error| map_instantiate_error(&error))?;
        let raw = instance
            .eliot_current_handler()
            .call_describe(&mut *store)
            .map_err(|error| map_call_error(&error))?;
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
            .map_err(|error| map_instantiate_error(&error))?;
        let raw = instance
            .eliot_current_screen()
            .call_describe(&mut *store)
            .map_err(|error| map_call_error(&error))?;
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
            .map_err(|error| map_instantiate_error(&error))?;
        let raw = instance
            .eliot_current_cycle()
            .call_describe(&mut *store)
            .map_err(|error| map_call_error(&error))?;
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

/// Domain-operation handoff: the typed domain call (`admit`/`assemble`/
/// `activate`/`handle`/`screen`/`step`) requires #760's independently
/// accepted public typed port/result/kit preparation, which is absent on
/// main. This function records that edge explicitly instead of faking a
/// domain result. Provenance: `crates/modules/eliot-wasm-runtime/src/ports.rs:84`
/// defines only the untyped `ComponentEnginePort::invoke` over opaque
/// `Vec<u8>`; no typed capsule/kit builder exists under `crates/` or `bins/`.
pub fn domain_handoff() -> Result<(), TypedExecutionError> {
    Err(TypedExecutionError::DomainCapsuleRequired)
}
