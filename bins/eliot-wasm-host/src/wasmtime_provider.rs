use std::io;
use std::sync::{
    Arc,
    atomic::{AtomicBool, AtomicU64, Ordering},
};
use std::thread;
use std::time::{Duration, Instant};

use eliot_wasm_runtime::{
    ComponentEnginePort, EngineBinding, EngineInvocation, EngineReport, EngineTermination,
    EngineUsage, InvocationLimits, MAX_EPOCH_DEADLINE_TICKS, PortError, Sha256Digest, TrapClass,
};
use wasmtime::component::{Component, Linker};
use wasmtime::{Config, Engine, ResourceLimiter, Store, StoreLimits, StoreLimitsBuilder};

const WASMTIME_VERSION: &str = "47.0.4";
const WIT_VERSION: &str = "1.0.0";
const WIT_WORLD: &str = "eliot:wasm/guest";
const RUN_EXPORT: &str = "run";
const PROVIDER_STACK_SIZE: usize = 8 * 1024;
const EPOCH_DRIVER_THREAD_PREFIX: &str = "eliot-wasm-epoch";
#[cfg(test)]
const COMPONENT_CONFIGURATION: &[u8] =
    b"component=guest;world=eliot:wasm/guest;export=run;imports=closed";

wasmtime::component::bindgen!({
    path: "wit/guest.wit",
    world: "guest",
});

struct StoreState {
    limits: StoreLimits,
    peak_memory_bytes: Option<u64>,
    table_elements: Option<u32>,
    limit_hit: Option<ResourceLimitHit>,
}

#[derive(Clone, Copy)]
enum ResourceLimitHit {
    Memory,
    Table,
}

impl ResourceLimiter for StoreState {
    fn memory_growing(
        &mut self,
        current: usize,
        desired: usize,
        maximum: Option<usize>,
    ) -> Result<bool, wasmtime::Error> {
        self.peak_memory_bytes = Some(
            self.peak_memory_bytes
                .unwrap_or(current as u64)
                .max(desired as u64),
        );
        let allowed = self.limits.memory_growing(current, desired, maximum)?;
        if !allowed {
            self.limit_hit = Some(ResourceLimitHit::Memory);
        }
        Ok(allowed)
    }

    fn table_growing(
        &mut self,
        current: usize,
        desired: usize,
        maximum: Option<usize>,
    ) -> Result<bool, wasmtime::Error> {
        self.table_elements = Some(
            self.table_elements
                .unwrap_or(u32::try_from(current).unwrap_or(u32::MAX))
                .max(u32::try_from(desired).unwrap_or(u32::MAX)),
        );
        let allowed = self.limits.table_growing(current, desired, maximum)?;
        if !allowed {
            self.limit_hit = Some(ResourceLimitHit::Table);
        }
        Ok(allowed)
    }

    fn instances(&self) -> usize {
        self.limits.instances()
    }
}

struct EpochDriverTask {
    stop: Arc<AtomicBool>,
    wall_interrupted: Arc<AtomicBool>,
    epoch_ticks: Arc<AtomicU64>,
    engine: Engine,
    wall_deadline_ms: u64,
    effective_epoch_deadline: u64,
}

impl EpochDriverTask {
    fn run(self) {
        let wall_deadline = Instant::now() + Duration::from_millis(self.wall_deadline_ms);
        while !self.stop.load(Ordering::Acquire) {
            thread::sleep(Duration::from_millis(1));
            if Instant::now() >= wall_deadline {
                self.wall_interrupted.store(true, Ordering::Release);
                let emitted = self.epoch_ticks.load(Ordering::Acquire);
                let remaining = self.effective_epoch_deadline.saturating_sub(emitted);
                for _ in 0..remaining {
                    self.engine.increment_epoch();
                    self.epoch_ticks.fetch_add(1, Ordering::AcqRel);
                }
                break;
            }
            self.engine.increment_epoch();
            self.epoch_ticks.fetch_add(1, Ordering::AcqRel);
        }
    }
}

struct EpochDriverOwner {
    identity: String,
    stop: Arc<AtomicBool>,
    wall_interrupted: Arc<AtomicBool>,
    epoch_ticks: Arc<AtomicU64>,
    join_handle: thread::JoinHandle<()>,
}

struct EpochDriverObservation {
    identity: String,
    joined: bool,
    wall_interrupted: bool,
    epoch_ticks: u64,
}

impl EpochDriverOwner {
    fn finish(self) -> EpochDriverObservation {
        self.stop.store(true, Ordering::Release);
        let joined = self.join_handle.join().is_ok();
        EpochDriverObservation {
            identity: self.identity,
            joined,
            wall_interrupted: self.wall_interrupted.load(Ordering::Acquire),
            epoch_ticks: self.epoch_ticks.load(Ordering::Acquire),
        }
    }
}

fn epoch_driver_identity(request_digest: &Sha256Digest) -> String {
    let digest = request_digest.as_str();
    let suffix = digest.get(..12).unwrap_or(digest);
    format!("{EPOCH_DRIVER_THREAD_PREFIX}-{suffix}")
}

fn spawn_epoch_driver(
    identity: &str,
    task: EpochDriverTask,
) -> io::Result<thread::JoinHandle<()>> {
    thread::Builder::new()
        .name(identity.to_owned())
        .spawn(move || task.run())
}

/// Concrete typed Wasmtime Component Model provider for one admitted artifact.
/// The linker is deliberately empty: this world has no host imports or WASI.
pub struct WasmtimeComponentEngine {
    epoch_engine: Engine,
    epoch_component: Component,
    fuel_engine: Engine,
    fuel_component: Component,
    binding: EngineBinding,
    artifact_digest: Sha256Digest,
    component_configuration_digest: Sha256Digest,
    artifact_bytes: u64,
}

impl std::fmt::Debug for WasmtimeComponentEngine {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("WasmtimeComponentEngine")
            .field("implementation", &self.binding.implementation_id)
            .field("version", &self.binding.exact_version)
            .field("artifact_digest", &self.artifact_digest)
            .finish_non_exhaustive()
    }
}

#[derive(Debug, thiserror::Error)]
pub enum WasmtimeBuildError {
    #[error("wasmtime configuration failed: {0}")]
    Config(#[source] wasmtime::Error),
    #[error("component compilation failed: {0}")]
    Compile(#[source] wasmtime::Error),
    #[error("engine binding must identify Wasmtime {WASMTIME_VERSION}")]
    VersionMismatch,
    #[error("artifact digest does not match supplied bytes")]
    ArtifactDigestMismatch,
    #[error("WIT interface digest does not match checked-in WIT bytes")]
    WitDigestMismatch,
    #[error("engine configuration digest does not match provider settings")]
    ConfigurationDigestMismatch,
    #[error("component configuration digest does not match supplied bytes")]
    ComponentConfigurationDigestMismatch,
}

impl WasmtimeComponentEngine {
    /// Compiles one immutable component artifact with the exact provider bind.
    pub fn new(
        binding: EngineBinding,
        artifact_digest: Sha256Digest,
        artifact: &[u8],
        component_configuration: &[u8],
    ) -> Result<Self, WasmtimeBuildError> {
        if binding.implementation_id != "wasmtime-component"
            || binding.exact_version != WASMTIME_VERSION
        {
            return Err(WasmtimeBuildError::VersionMismatch);
        }
        if Sha256Digest::of_bytes(artifact) != artifact_digest {
            return Err(WasmtimeBuildError::ArtifactDigestMismatch);
        }
        if binding.wit_interface_digest
            != Sha256Digest::of_bytes(include_bytes!("../wit/guest.wit"))
        {
            return Err(WasmtimeBuildError::WitDigestMismatch);
        }
        if binding.engine_configuration_digest != configuration_digest() {
            return Err(WasmtimeBuildError::ConfigurationDigestMismatch);
        }
        let component_configuration_digest = Sha256Digest::of_bytes(component_configuration);
        let epoch_engine = configured_engine(false)?;
        let fuel_engine = configured_engine(true)?;
        let epoch_component =
            Component::new(&epoch_engine, artifact).map_err(WasmtimeBuildError::Compile)?;
        let fuel_component =
            Component::new(&fuel_engine, artifact).map_err(WasmtimeBuildError::Compile)?;
        Ok(Self {
            epoch_engine,
            epoch_component,
            fuel_engine,
            fuel_component,
            binding,
            artifact_digest,
            component_configuration_digest,
            artifact_bytes: artifact.len() as u64,
        })
    }

    fn invoke_component(
        &self,
        request_digest: &Sha256Digest,
        limits: &InvocationLimits,
        input: &[u8],
        post_commit_known: bool,
    ) -> Result<EngineReport, PortError> {
        self.invoke_component_with_epoch_driver(
            request_digest,
            limits,
            input,
            post_commit_known,
            spawn_epoch_driver,
        )
    }

    #[allow(clippy::too_many_lines)]
    fn invoke_component_with_epoch_driver<F>(
        &self,
        request_digest: &Sha256Digest,
        limits: &InvocationLimits,
        input: &[u8],
        post_commit_known: bool,
        spawn_driver: F,
    ) -> Result<EngineReport, PortError>
    where
        F: FnOnce(&str, EpochDriverTask) -> io::Result<thread::JoinHandle<()>>,
    {
        validate_epoch_policy(limits)?;
        let (invocation_engine, component) = match limits.epoch.cancellation {
            eliot_wasm_runtime::CancellationPolicy::EpochInterruption => {
                (&self.epoch_engine, &self.epoch_component)
            }
            eliot_wasm_runtime::CancellationPolicy::EpochAndFuel => {
                (&self.fuel_engine, &self.fuel_component)
            }
        };
        let start = Instant::now();
        let mut store = Store::new(
            invocation_engine,
            StoreState {
                limits: StoreLimitsBuilder::new()
                    .memory_size(usize::try_from(limits.max_memory_bytes).unwrap_or(usize::MAX))
                    .table_elements(
                        usize::try_from(limits.max_table_elements).unwrap_or(usize::MAX),
                    )
                    .instances(usize::try_from(limits.max_instances).unwrap_or(usize::MAX))
                    .build(),
                peak_memory_bytes: Some(0),
                table_elements: Some(0),
                limit_hit: None,
            },
        );
        store.limiter(|state| state);
        let mut instances = 0;
        let fuel_set = matches!(
            limits.epoch.cancellation,
            eliot_wasm_runtime::CancellationPolicy::EpochAndFuel
        ) && store.set_fuel(limits.max_fuel).is_ok();
        // The provider has no negotiation path. After the explicit ceiling
        // check above, the exact admitted policy is the effective policy: it
        // is neither clamped nor otherwise rewritten before Store execution.
        let effective_epoch_deadline = limits.epoch.deadline_ticks;
        store.set_epoch_deadline(effective_epoch_deadline);

        let stop_epoch = Arc::new(AtomicBool::new(false));
        let wall_interrupted = Arc::new(AtomicBool::new(false));
        let epoch_ticks = Arc::new(AtomicU64::new(0));
        let epoch_driver_identity = epoch_driver_identity(request_digest);
        let epoch_driver_task = EpochDriverTask {
            stop: Arc::clone(&stop_epoch),
            wall_interrupted: Arc::clone(&wall_interrupted),
            epoch_ticks: Arc::clone(&epoch_ticks),
            engine: invocation_engine.clone(),
            wall_deadline_ms: limits.wall_deadline_ms,
            effective_epoch_deadline,
        };
        let epoch_driver = match spawn_driver(&epoch_driver_identity, epoch_driver_task) {
            Ok(join_handle) => EpochDriverOwner {
                identity: epoch_driver_identity,
                stop: stop_epoch,
                wall_interrupted,
                epoch_ticks,
                join_handle,
            },
            Err(_) => {
                return Ok(epoch_driver_spawn_failure_report(
                    request_digest,
                    limits,
                    start,
                ));
            }
        };

        let (termination, output, attempted_output_bytes) = if fuel_set
            || matches!(
                limits.epoch.cancellation,
                eliot_wasm_runtime::CancellationPolicy::EpochInterruption
            ) {
            let linker = Linker::new(invocation_engine);
            let call = Guest::instantiate(&mut store, component, &linker).and_then(|instance| {
                instances = 1;
                instance.call_run(&mut store, input)
            });
            match call {
                Ok(Ok(value)) if value.len() as u64 <= limits.max_output_bytes => {
                    let length = value.len() as u64;
                    (EngineTermination::Completed, value, length)
                }
                Ok(Ok(value)) => (
                    EngineTermination::OutputLimit,
                    Vec::new(),
                    value.len() as u64,
                ),
                Ok(Err(_)) => (EngineTermination::Trap(TrapClass::GuestTrap), Vec::new(), 0),
                Err(error) => {
                    let termination = match store.data().limit_hit {
                        Some(ResourceLimitHit::Memory) => EngineTermination::MemoryLimit,
                        Some(ResourceLimitHit::Table) => EngineTermination::TableLimit,
                        None if is_instance_limit_error(&error) => EngineTermination::InstanceLimit,
                        None => classify_trap(&error),
                    };
                    (termination, Vec::new(), 0)
                }
            }
        } else {
            (
                EngineTermination::Trap(TrapClass::HostContractViolation),
                Vec::new(),
                0,
            )
        };
        let epoch_observation = epoch_driver.finish();
        debug_assert!(
            epoch_observation
                .identity
                .starts_with(EPOCH_DRIVER_THREAD_PREFIX)
        );
        let remaining_fuel = store.get_fuel().unwrap_or(0);
        let peak_memory_bytes = store.data().peak_memory_bytes;
        let table_elements = store.data().table_elements;
        drop(store);
        let elapsed_ms = u64::try_from(start.elapsed().as_millis()).unwrap_or(u64::MAX);
        let fuel_consumed = if matches!(
            limits.epoch.cancellation,
            eliot_wasm_runtime::CancellationPolicy::EpochAndFuel
        ) {
            limits.max_fuel.saturating_sub(remaining_fuel)
        } else {
            0
        };
        let termination = match termination {
            EngineTermination::EpochDeadline if epoch_observation.wall_interrupted => {
                EngineTermination::Deadline
            }
            other => other,
        };
        Ok(EngineReport {
            request_digest: request_digest.clone(),
            termination,
            usage: EngineUsage {
                attempted_output_bytes,
                output_bytes: output.len() as u64,
                host_calls: 0,
                fuel_consumed,
                peak_memory_bytes,
                table_elements,
                instances,
                stack_bytes: None,
                enforced_stack_limit_bytes: Some(limits.max_stack_bytes),
                elapsed_ms,
                effective_epoch_policy: limits.epoch,
                epoch_ticks: Some(epoch_observation.epoch_ticks),
                artifact_reads: 1,
                artifact_bytes: self.artifact_bytes,
                accessed_artifact_digests: vec![self.artifact_digest.clone()],
            },
            output,
            host_calls: Vec::new(),
            proposed_effects: Vec::new(),
            observed_state_delta: Vec::new(),
            post_commit_known: epoch_observation.joined
                && post_commit_known
                && !matches!(
                    termination,
                    EngineTermination::Partial | EngineTermination::PostCommitUnknown
                ),
        })
    }
}

fn epoch_driver_spawn_failure_report(
    request_digest: &Sha256Digest,
    limits: &InvocationLimits,
    start: Instant,
) -> EngineReport {
    EngineReport {
        request_digest: request_digest.clone(),
        termination: EngineTermination::Trap(TrapClass::HostContractViolation),
        usage: EngineUsage {
            attempted_output_bytes: 0,
            output_bytes: 0,
            host_calls: 0,
            fuel_consumed: 0,
            peak_memory_bytes: Some(0),
            table_elements: Some(0),
            instances: 0,
            stack_bytes: None,
            enforced_stack_limit_bytes: Some(limits.max_stack_bytes),
            elapsed_ms: u64::try_from(start.elapsed().as_millis()).unwrap_or(u64::MAX),
            effective_epoch_policy: limits.epoch,
            epoch_ticks: Some(0),
            artifact_reads: 0,
            artifact_bytes: 0,
            accessed_artifact_digests: Vec::new(),
        },
        output: Vec::new(),
        host_calls: Vec::new(),
        proposed_effects: Vec::new(),
        observed_state_delta: Vec::new(),
        post_commit_known: true,
    }
}

impl ComponentEnginePort for WasmtimeComponentEngine {
    fn binding(&self) -> &EngineBinding {
        &self.binding
    }

    fn invoke(&mut self, invocation: &EngineInvocation) -> Result<EngineReport, PortError> {
        let manifest = &invocation.manifest;
        let expected_export =
            eliot_wasm_runtime::CapabilityId::new(RUN_EXPORT).map_err(|_| PortError::Denied)?;
        if invocation.input.len() as u64 > invocation.limits.max_input_bytes
            || self.artifact_bytes > invocation.limits.artifact_access.max_bytes
            || !invocation
                .limits
                .artifact_access
                .allowed_digests
                .contains(&self.artifact_digest)
            || manifest.artifact_digest != self.artifact_digest
            || manifest.engine != self.binding
            || manifest.configuration_digest != self.component_configuration_digest
            || usize::try_from(invocation.limits.max_stack_bytes).ok() != Some(PROVIDER_STACK_SIZE)
            || manifest.world.as_str() != WIT_WORLD
            || manifest.wit_version != WIT_VERSION
            || !manifest.imports.is_empty()
            || manifest.exports.len() != 1
            || !manifest.exports.contains(&expected_export)
        {
            return Err(PortError::Denied);
        }
        self.invoke_component(
            &invocation.request_digest,
            &invocation.limits,
            &invocation.input,
            invocation.manifest.imports.is_empty(),
        )
    }

    fn reconcile(&mut self, _invocation: &EngineInvocation) -> Result<EngineReport, PortError> {
        Err(PortError::UnknownOutcome)
    }
}

fn validate_epoch_policy(limits: &InvocationLimits) -> Result<(), PortError> {
    if limits.epoch.deadline_ticks == 0
        || limits.epoch.deadline_ticks > MAX_EPOCH_DEADLINE_TICKS
    {
        Err(PortError::Denied)
    } else {
        Ok(())
    }
}

fn classify_trap(error: &wasmtime::Error) -> EngineTermination {
    let Some(trap) = error.downcast_ref::<wasmtime::Trap>() else {
        return EngineTermination::Trap(TrapClass::InvalidComponent);
    };
    match *trap {
        wasmtime::Trap::OutOfFuel => EngineTermination::FuelExhausted,
        wasmtime::Trap::Interrupt => EngineTermination::EpochDeadline,
        wasmtime::Trap::StackOverflow => EngineTermination::StackLimit,
        _ => EngineTermination::Trap(TrapClass::GuestTrap),
    }
}

fn is_instance_limit_error(error: &wasmtime::Error) -> bool {
    let message = error.to_string().to_ascii_lowercase();
    message.contains("instance") && (message.contains("limit") || message.contains("maximum"))
}

fn configuration_digest() -> Sha256Digest {
    Sha256Digest::of_bytes(canonical_configuration_descriptor())
}

fn canonical_configuration_descriptor() -> &'static [u8] {
    b"wasmtime=47.0.4;component_model=true;typed_abi=guest.run;max_wasm_stack=8192;max_epoch_deadline_ticks=1024;epoch_only.consume_fuel=false;epoch_only.epoch_interruption=true;epoch_and_fuel.consume_fuel=true;epoch_and_fuel.epoch_interruption=true"
}

fn configured_engine(consume_fuel: bool) -> Result<Engine, WasmtimeBuildError> {
    let mut config = Config::new();
    config.wasm_component_model(true);
    config.consume_fuel(consume_fuel);
    config.epoch_interruption(true);
    config.max_wasm_stack(PROVIDER_STACK_SIZE);
    Engine::new(&config).map_err(WasmtimeBuildError::Config)
}

#[cfg(test)]
mod tests {
    use super::*;
    use eliot_wasm_runtime::EngineBinding;

    fn binding() -> EngineBinding {
        EngineBinding {
            implementation_id: "wasmtime-component".to_owned(),
            exact_version: WASMTIME_VERSION.to_owned(),
            engine_artifact_digest: Sha256Digest::of_bytes(b"engine"),
            engine_configuration_digest: configuration_digest(),
            wit_interface_digest: Sha256Digest::of_bytes(include_bytes!("../wit/guest.wit")),
        }
    }

    #[test]
    fn checked_in_guest_component_is_compiled_and_digest_bound() -> Result<(), String> {
        let artifact =
            wat::parse_file("tests/fixtures/guest.wat").map_err(|error| error.to_string())?;
        let wrong_digest = Sha256Digest::of_bytes(b"different");
        assert!(matches!(
            WasmtimeComponentEngine::new(
                binding(),
                wrong_digest,
                &artifact,
                COMPONENT_CONFIGURATION
            ),
            Err(WasmtimeBuildError::ArtifactDigestMismatch)
        ));
        let digest = Sha256Digest::of_bytes(&artifact);
        let mut false_version = binding();
        false_version.exact_version = "40.0.0".to_owned();
        assert!(matches!(
            WasmtimeComponentEngine::new(
                false_version,
                digest.clone(),
                &artifact,
                COMPONENT_CONFIGURATION
            ),
            Err(WasmtimeBuildError::VersionMismatch)
        ));
        WasmtimeComponentEngine::new(binding(), digest, &artifact, COMPONENT_CONFIGURATION)
            .map_err(|error| format!("{error:?}"))?;
        Ok(())
    }

    #[test]
    fn checked_in_guest_executes_typed_input_and_output() -> Result<(), String> {
        let artifact =
            wat::parse_file("tests/fixtures/guest.wat").map_err(|error| error.to_string())?;
        let digest = Sha256Digest::of_bytes(&artifact);
        let engine = WasmtimeComponentEngine::new(
            binding(),
            digest.clone(),
            &artifact,
            COMPONENT_CONFIGURATION,
        )
        .map_err(|error| error.to_string())?;
        let limits = InvocationLimits {
            max_input_bytes: 64,
            max_output_bytes: 64,
            max_host_calls: 1,
            max_fuel: 10_000,
            max_memory_bytes: 65_536,
            max_table_elements: 1,
            max_instances: 2,
            max_stack_bytes: 8 * 1024,
            wall_deadline_ms: 500,
            epoch: eliot_wasm_runtime::EpochPolicy {
                deadline_ticks: 100,
                cancellation: eliot_wasm_runtime::CancellationPolicy::EpochAndFuel,
            },
            artifact_access: eliot_wasm_runtime::ArtifactAccessLimits {
                allowed_digests: [digest].into_iter().collect(),
                max_reads: 1,
                max_bytes: 65_536,
            },
        };
        let report = engine
            .invoke_component(
                &Sha256Digest::of_bytes(b"request"),
                &limits,
                b"typed guest input",
                true,
            )
            .map_err(|error| error.to_string())?;
        assert_eq!(report.termination, EngineTermination::Completed);
        assert_eq!(report.output, b"typed guest input");
        assert_eq!(report.usage.enforced_stack_limit_bytes, Some(8 * 1024));
        assert_eq!(report.usage.effective_epoch_policy, limits.epoch);
        assert!(report.usage.stack_bytes.is_none());
        Ok(())
    }

    #[test]
    fn output_limit_and_fuel_are_reported_from_execution() -> Result<(), String> {
        let artifact =
            wat::parse_file("tests/fixtures/guest.wat").map_err(|error| error.to_string())?;
        let digest = Sha256Digest::of_bytes(&artifact);
        let engine = WasmtimeComponentEngine::new(
            binding(),
            digest.clone(),
            &artifact,
            COMPONENT_CONFIGURATION,
        )
        .map_err(|error| error.to_string())?;
        let mut limits = test_limits(digest);
        limits.max_output_bytes = 3;
        let output_limited = engine
            .invoke_component(
                &Sha256Digest::of_bytes(b"output-limit"),
                &limits,
                b"typed guest input",
                true,
            )
            .map_err(|error| error.to_string())?;
        assert_eq!(output_limited.termination, EngineTermination::OutputLimit);
        assert_eq!(output_limited.output, Vec::<u8>::new());
        assert_eq!(output_limited.usage.output_bytes, 0);
        assert_eq!(output_limited.usage.attempted_output_bytes, 17);
        assert!(output_limited.usage.peak_memory_bytes.unwrap_or(0) <= limits.max_memory_bytes);

        limits.max_output_bytes = 64;
        limits.max_fuel = 1;
        let fuel_limited = engine
            .invoke_component(
                &Sha256Digest::of_bytes(b"fuel-limit"),
                &limits,
                b"typed guest input",
                true,
            )
            .map_err(|error| error.to_string())?;
        assert_eq!(fuel_limited.termination, EngineTermination::FuelExhausted);
        Ok(())
    }

    #[test]
    fn epoch_deadline_ceiling_is_exact_and_fail_closed() -> Result<(), String> {
        let artifact =
            wat::parse_file("tests/fixtures/guest.wat").map_err(|error| error.to_string())?;
        let digest = Sha256Digest::of_bytes(&artifact);
        let engine = WasmtimeComponentEngine::new(
            binding(),
            digest.clone(),
            &artifact,
            COMPONENT_CONFIGURATION,
        )
        .map_err(|error| error.to_string())?;
        let mut limits = test_limits(digest);
        limits.epoch.deadline_ticks = MAX_EPOCH_DEADLINE_TICKS;
        let accepted = engine
            .invoke_component(
                &Sha256Digest::of_bytes(b"epoch-boundary-accepted"),
                &limits,
                b"typed guest input",
                true,
            )
            .map_err(|error| error.to_string())?;
        assert_eq!(accepted.termination, EngineTermination::Completed);

        limits.epoch.deadline_ticks = MAX_EPOCH_DEADLINE_TICKS + 1;
        assert!(matches!(
            engine.invoke_component(
                &Sha256Digest::of_bytes(b"epoch-boundary-rejected"),
                &limits,
                b"typed guest input",
                true,
            ),
            Err(PortError::Denied)
        ));
        Ok(())
    }

    #[test]
    fn epoch_driver_spawn_failure_is_fail_closed_before_guest_execution() -> Result<(), String> {
        let artifact =
            wat::parse_file("tests/fixtures/guest.wat").map_err(|error| error.to_string())?;
        let digest = Sha256Digest::of_bytes(&artifact);
        let engine = WasmtimeComponentEngine::new(
            binding(),
            digest.clone(),
            &artifact,
            COMPONENT_CONFIGURATION,
        )
        .map_err(|error| error.to_string())?;
        let limits = test_limits(digest);
        let request_digest = Sha256Digest::of_bytes(b"epoch-driver-spawn-failure");
        let expected_identity = epoch_driver_identity(&request_digest);
        let mut observed_identity = None;

        let report = engine
            .invoke_component_with_epoch_driver(
                &request_digest,
                &limits,
                b"typed guest input",
                true,
                |identity, _task| {
                    observed_identity = Some(identity.to_owned());
                    Err(io::Error::other("injected epoch driver spawn failure"))
                },
            )
            .map_err(|error| error.to_string())?;

        assert_eq!(observed_identity.as_deref(), Some(expected_identity.as_str()));
        assert_eq!(
            report.termination,
            EngineTermination::Trap(TrapClass::HostContractViolation)
        );
        assert_eq!(report.usage.instances, 0);
        assert_eq!(report.usage.host_calls, 0);
        assert_eq!(report.usage.output_bytes, 0);
        assert_eq!(report.usage.attempted_output_bytes, 0);
        assert_eq!(report.usage.fuel_consumed, 0);
        assert_eq!(report.usage.epoch_ticks, Some(0));
        assert_eq!(report.usage.effective_epoch_policy, limits.epoch);
        assert_eq!(report.usage.artifact_reads, 0);
        assert!(report.usage.accessed_artifact_digests.is_empty());
        assert!(report.output.is_empty());
        assert!(report.host_calls.is_empty());
        assert!(report.proposed_effects.is_empty());
        assert!(report.observed_state_delta.is_empty());
        assert!(report.post_commit_known);
        Ok(())
    }

    #[test]
    fn wall_deadline_interrupts_a_looping_guest() -> Result<(), String> {
        let started = Instant::now();
        let artifact =
            wat::parse_file("tests/fixtures/guest_loop.wat").map_err(|error| error.to_string())?;
        let digest = Sha256Digest::of_bytes(&artifact);
        let engine = WasmtimeComponentEngine::new(
            binding(),
            digest.clone(),
            &artifact,
            COMPONENT_CONFIGURATION,
        )
        .map_err(|error| error.to_string())?;
        let mut limits = test_limits(digest);
        limits.wall_deadline_ms = 10;
        limits.epoch.deadline_ticks = MAX_EPOCH_DEADLINE_TICKS;
        limits.max_fuel = u64::MAX;
        let report = engine
            .invoke_component(&Sha256Digest::of_bytes(b"deadline"), &limits, b"", true)
            .map_err(|error| error.to_string())?;
        assert_eq!(report.termination, EngineTermination::Deadline);
        let epoch_ticks = report.usage.epoch_ticks.unwrap_or(0);
        assert!(epoch_ticks > 0);
        assert!(epoch_ticks <= limits.epoch.deadline_ticks);
        assert!(started.elapsed() < Duration::from_secs(2));
        Ok(())
    }

    #[test]
    fn epoch_interruption_does_not_use_fuel_as_a_hidden_termination() -> Result<(), String> {
        let artifact =
            wat::parse_file("tests/fixtures/guest_loop.wat").map_err(|error| error.to_string())?;
        let digest = Sha256Digest::of_bytes(&artifact);
        let engine = WasmtimeComponentEngine::new(
            binding(),
            digest.clone(),
            &artifact,
            COMPONENT_CONFIGURATION,
        )
        .map_err(|error| error.to_string())?;
        let mut limits = test_limits(digest);
        limits.wall_deadline_ms = 10;
        limits.max_fuel = 1;
        limits.epoch.cancellation = eliot_wasm_runtime::CancellationPolicy::EpochInterruption;
        let report = engine
            .invoke_component(&Sha256Digest::of_bytes(b"epoch-only"), &limits, b"", true)
            .map_err(|error| error.to_string())?;
        assert!(matches!(
            report.termination,
            EngineTermination::Deadline | EngineTermination::EpochDeadline
        ));
        Ok(())
    }

    #[test]
    fn instance_limit_is_observed_from_component_instantiation() -> Result<(), String> {
        let artifact = wat::parse_file("tests/fixtures/guest_instances.wat")
            .map_err(|error| error.to_string())?;
        let digest = Sha256Digest::of_bytes(&artifact);
        let engine = WasmtimeComponentEngine::new(
            binding(),
            digest.clone(),
            &artifact,
            COMPONENT_CONFIGURATION,
        )
        .map_err(|error| error.to_string())?;
        let mut limits = test_limits(digest);
        limits.max_instances = 1;
        let report = engine
            .invoke_component(
                &Sha256Digest::of_bytes(b"instances"),
                &limits,
                b"",
                true,
            )
            .map_err(|error| error.to_string())?;
        assert_eq!(report.termination, EngineTermination::InstanceLimit);
        Ok(())
    }

    #[test]
    fn wrong_wit_and_configuration_digests_are_rejected_before_composition() -> Result<(), String> {
        let artifact =
            wat::parse_file("tests/fixtures/guest.wat").map_err(|error| error.to_string())?;
        let digest = Sha256Digest::of_bytes(&artifact);
        let mut wrong_wit = binding();
        wrong_wit.wit_interface_digest = Sha256Digest::of_bytes(b"wrong-wit");
        assert!(matches!(
            WasmtimeComponentEngine::new(
                wrong_wit,
                digest.clone(),
                &artifact,
                COMPONENT_CONFIGURATION
            ),
            Err(WasmtimeBuildError::WitDigestMismatch)
        ));
        let mut wrong_config = binding();
        wrong_config.engine_configuration_digest = Sha256Digest::of_bytes(b"wrong-config");
        assert!(matches!(
            WasmtimeComponentEngine::new(wrong_config, digest, &artifact, COMPONENT_CONFIGURATION),
            Err(WasmtimeBuildError::ConfigurationDigestMismatch)
        ));
        Ok(())
    }

    fn test_limits(digest: Sha256Digest) -> InvocationLimits {
        InvocationLimits {
            max_input_bytes: 64,
            max_output_bytes: 64,
            max_host_calls: 1,
            max_fuel: 10_000,
            max_memory_bytes: 65_536,
            max_table_elements: 1,
            max_instances: 2,
            max_stack_bytes: 8 * 1024,
            wall_deadline_ms: 500,
            epoch: eliot_wasm_runtime::EpochPolicy {
                deadline_ticks: 100,
                cancellation: eliot_wasm_runtime::CancellationPolicy::EpochAndFuel,
            },
            artifact_access: eliot_wasm_runtime::ArtifactAccessLimits {
                allowed_digests: [digest].into_iter().collect(),
                max_reads: 1,
                max_bytes: 65_536,
            },
        }
    }
}
