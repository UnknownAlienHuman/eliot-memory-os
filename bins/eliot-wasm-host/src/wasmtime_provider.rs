use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use std::thread;
use std::time::{Duration, Instant};

use eliot_wasm_runtime::{
    ComponentEnginePort, EngineBinding, EngineInvocation, EngineReport, EngineTermination,
    EngineUsage, InvocationLimits, PortError, Sha256Digest, TrapClass,
};
use wasmtime::component::{Component, Linker};
use wasmtime::{Config, Engine, ResourceLimiter, Store, StoreLimits, StoreLimitsBuilder};

const WASMTIME_VERSION: &str = "47.0.0";
const WIT_VERSION: &str = "1.0.0";
const WIT_WORLD: &str = "eliot:wasm/guest";
const RUN_EXPORT: &str = "run";
const MAX_EFFECTIVE_EPOCH_DEADLINE: u64 = 1024;

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
}

/// Concrete typed Wasmtime Component Model provider for one admitted artifact.
/// The linker is deliberately empty: this world has no host imports or WASI.
pub struct WasmtimeComponentEngine {
    artifact: Vec<u8>,
    binding: EngineBinding,
    artifact_digest: Sha256Digest,
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
}

impl WasmtimeComponentEngine {
    /// Compiles one immutable component artifact with the exact provider bind.
    pub fn new(
        binding: EngineBinding,
        artifact_digest: Sha256Digest,
        artifact: &[u8],
    ) -> Result<Self, WasmtimeBuildError> {
        if binding.implementation_id != "wasmtime-component"
            || binding.exact_version != WASMTIME_VERSION
        {
            return Err(WasmtimeBuildError::VersionMismatch);
        }
        if Sha256Digest::of_bytes(artifact) != artifact_digest {
            return Err(WasmtimeBuildError::ArtifactDigestMismatch);
        }
        let mut config = Config::new();
        config.wasm_component_model(true);
        config.consume_fuel(true);
        config.epoch_interruption(true);
        let engine = Engine::new(&config).map_err(WasmtimeBuildError::Config)?;
        Component::new(&engine, artifact).map_err(WasmtimeBuildError::Compile)?;
        Ok(Self {
            artifact: artifact.to_vec(),
            binding,
            artifact_digest,
            artifact_bytes: artifact.len() as u64,
        })
    }

    #[allow(clippy::too_many_lines)]
    fn invoke_component(
        &self,
        request_digest: &Sha256Digest,
        limits: &InvocationLimits,
        input: &[u8],
        post_commit_known: bool,
    ) -> EngineReport {
        let stack_size = usize::try_from(limits.max_stack_bytes).unwrap_or(usize::MAX);
        let mut config = Config::new();
        config.wasm_component_model(true);
        config.consume_fuel(true);
        config.epoch_interruption(true);
        config.max_wasm_stack(stack_size);
        config.async_stack_size(stack_size);
        let Ok(invocation_engine) = Engine::new(&config) else {
            return host_contract_report(request_digest, self.artifact_bytes);
        };
        let Ok(component) = Component::new(&invocation_engine, &self.artifact) else {
            return host_contract_report(request_digest, self.artifact_bytes);
        };
        let mut store = Store::new(
            &invocation_engine,
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
        let start = Instant::now();
        let mut instances = 0;
        let fuel_set = store.set_fuel(limits.max_fuel).is_ok();
        let wall_ticks = limits.wall_deadline_ms;
        let effective_epoch_deadline = limits
            .epoch
            .deadline_ticks
            .min(MAX_EFFECTIVE_EPOCH_DEADLINE);
        store.set_epoch_deadline(effective_epoch_deadline);
        let stop_epoch = Arc::new(AtomicBool::new(false));
        let epoch_stop = Arc::clone(&stop_epoch);
        let wall_interrupted = Arc::new(AtomicBool::new(false));
        let wall_interrupted_thread = Arc::clone(&wall_interrupted);
        let epoch_ticks = Arc::new(std::sync::atomic::AtomicU64::new(0));
        let observed_epoch_ticks = Arc::clone(&epoch_ticks);
        let epoch_engine = invocation_engine.clone();
        let epoch_thread = thread::spawn(move || {
            let wall_deadline = Instant::now() + Duration::from_millis(wall_ticks);
            while !epoch_stop.load(Ordering::Acquire) {
                thread::sleep(Duration::from_millis(1));
                if Instant::now() >= wall_deadline {
                    wall_interrupted_thread.store(true, Ordering::Release);
                    for _ in 0..=MAX_EFFECTIVE_EPOCH_DEADLINE {
                        epoch_engine.increment_epoch();
                        observed_epoch_ticks.fetch_add(1, Ordering::AcqRel);
                    }
                    break;
                }
                epoch_engine.increment_epoch();
                observed_epoch_ticks.fetch_add(1, Ordering::AcqRel);
            }
        });

        let (termination, output) = if fuel_set {
            let linker = Linker::new(&invocation_engine);
            let call = Guest::instantiate(&mut store, &component, &linker).and_then(|instance| {
                instances = 1;
                instance.call_run(&mut store, input)
            });
            match call {
                Ok(Ok(value)) if value.len() as u64 <= limits.max_output_bytes => {
                    (EngineTermination::Completed, value)
                }
                Ok(Ok(_)) => (EngineTermination::OutputLimit, Vec::new()),
                Ok(Err(_)) => (EngineTermination::Trap(TrapClass::GuestTrap), Vec::new()),
                Err(error) => {
                    let termination = match store.data().limit_hit {
                        Some(ResourceLimitHit::Memory) => EngineTermination::MemoryLimit,
                        Some(ResourceLimitHit::Table) => EngineTermination::TableLimit,
                        None => classify_trap(&error),
                    };
                    (termination, Vec::new())
                }
            }
        } else {
            (
                EngineTermination::Trap(TrapClass::HostContractViolation),
                Vec::new(),
            )
        };
        stop_epoch.store(true, Ordering::Release);
        let epoch_joined = epoch_thread.join().is_ok();
        let epoch_ticks = epoch_ticks.load(Ordering::Acquire);
        let remaining_fuel = store.get_fuel().unwrap_or(0);
        let peak_memory_bytes = store.data().peak_memory_bytes;
        let table_elements = store.data().table_elements;
        drop(store);
        let elapsed_ms = u64::try_from(start.elapsed().as_millis()).unwrap_or(u64::MAX);
        let fuel_consumed = limits.max_fuel.saturating_sub(remaining_fuel);
        let termination = match termination {
            EngineTermination::EpochDeadline if wall_interrupted.load(Ordering::Acquire) => {
                EngineTermination::Deadline
            }
            other => other,
        };
        EngineReport {
            request_digest: request_digest.clone(),
            termination,
            usage: EngineUsage {
                output_bytes: output.len() as u64,
                host_calls: 0,
                fuel_consumed,
                peak_memory_bytes,
                table_elements,
                instances,
                stack_bytes: None,
                enforced_stack_limit_bytes: Some(limits.max_stack_bytes),
                elapsed_ms,
                epoch_ticks: Some(epoch_ticks),
                artifact_reads: 1,
                artifact_bytes: self.artifact_bytes,
                accessed_artifact_digests: vec![self.artifact_digest.clone()],
            },
            output,
            host_calls: Vec::new(),
            proposed_effects: Vec::new(),
            observed_state_delta: Vec::new(),
            reaped: epoch_joined,
            post_commit_known: epoch_joined
                && post_commit_known
                && !matches!(
                    termination,
                    EngineTermination::Partial | EngineTermination::PostCommitUnknown
                ),
        }
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
            || manifest.world.as_str() != WIT_WORLD
            || manifest.wit_version != WIT_VERSION
            || !manifest.imports.is_empty()
            || manifest.exports.len() != 1
            || !manifest.exports.contains(&expected_export)
        {
            return Err(PortError::Denied);
        }
        Ok(self.invoke_component(
            &invocation.request_digest,
            &invocation.limits,
            &invocation.input,
            invocation.manifest.imports.is_empty(),
        ))
    }

    fn reconcile(&mut self, _invocation: &EngineInvocation) -> Result<EngineReport, PortError> {
        Err(PortError::UnknownOutcome)
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

fn host_contract_report(request_digest: &Sha256Digest, artifact_bytes: u64) -> EngineReport {
    EngineReport {
        request_digest: request_digest.clone(),
        termination: EngineTermination::Trap(TrapClass::HostContractViolation),
        usage: EngineUsage {
            output_bytes: 0,
            host_calls: 0,
            fuel_consumed: 0,
            peak_memory_bytes: Some(0),
            table_elements: Some(0),
            instances: 0,
            stack_bytes: None,
            enforced_stack_limit_bytes: None,
            elapsed_ms: 0,
            epoch_ticks: Some(0),
            artifact_reads: 1,
            artifact_bytes,
            accessed_artifact_digests: Vec::new(),
        },
        output: Vec::new(),
        host_calls: Vec::new(),
        proposed_effects: Vec::new(),
        observed_state_delta: Vec::new(),
        reaped: true,
        post_commit_known: true,
    }
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
            engine_configuration_digest: Sha256Digest::of_bytes(b"config"),
            wit_interface_digest: Sha256Digest::of_bytes(include_bytes!("../wit/guest.wit")),
        }
    }

    #[test]
    fn checked_in_guest_component_is_compiled_and_digest_bound() -> Result<(), String> {
        let artifact =
            wat::parse_file("tests/fixtures/guest.wat").map_err(|error| error.to_string())?;
        let wrong_digest = Sha256Digest::of_bytes(b"different");
        assert!(matches!(
            WasmtimeComponentEngine::new(binding(), wrong_digest, &artifact),
            Err(WasmtimeBuildError::ArtifactDigestMismatch)
        ));
        let digest = Sha256Digest::of_bytes(&artifact);
        WasmtimeComponentEngine::new(binding(), digest, &artifact)
            .map_err(|error| format!("{error:?}"))?;
        Ok(())
    }

    #[test]
    fn checked_in_guest_executes_typed_input_and_output() -> Result<(), String> {
        let artifact =
            wat::parse_file("tests/fixtures/guest.wat").map_err(|error| error.to_string())?;
        let digest = Sha256Digest::of_bytes(&artifact);
        let engine = WasmtimeComponentEngine::new(binding(), digest.clone(), &artifact)
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
        let report = engine.invoke_component(
            &Sha256Digest::of_bytes(b"request"),
            &limits,
            b"typed guest input",
            true,
        );
        assert_eq!(report.termination, EngineTermination::Completed);
        assert_eq!(report.output, b"typed guest input");
        assert_eq!(report.usage.enforced_stack_limit_bytes, Some(8 * 1024));
        assert!(report.usage.stack_bytes.is_none());
        Ok(())
    }

    #[test]
    fn output_limit_and_fuel_are_reported_from_execution() -> Result<(), String> {
        let artifact =
            wat::parse_file("tests/fixtures/guest.wat").map_err(|error| error.to_string())?;
        let digest = Sha256Digest::of_bytes(&artifact);
        let engine = WasmtimeComponentEngine::new(binding(), digest.clone(), &artifact)
            .map_err(|error| error.to_string())?;
        let mut limits = test_limits(digest);
        limits.max_output_bytes = 3;
        let output_limited = engine.invoke_component(
            &Sha256Digest::of_bytes(b"output-limit"),
            &limits,
            b"typed guest input",
            true,
        );
        assert_eq!(output_limited.termination, EngineTermination::OutputLimit);

        limits.max_output_bytes = 64;
        limits.max_fuel = 1;
        let fuel_limited = engine.invoke_component(
            &Sha256Digest::of_bytes(b"fuel-limit"),
            &limits,
            b"typed guest input",
            true,
        );
        assert_eq!(fuel_limited.termination, EngineTermination::FuelExhausted);
        Ok(())
    }

    #[test]
    fn wall_deadline_interrupts_a_looping_guest() -> Result<(), String> {
        let started = Instant::now();
        let artifact =
            wat::parse_file("tests/fixtures/guest_loop.wat").map_err(|error| error.to_string())?;
        let digest = Sha256Digest::of_bytes(&artifact);
        let engine = WasmtimeComponentEngine::new(binding(), digest.clone(), &artifact)
            .map_err(|error| error.to_string())?;
        let mut limits = test_limits(digest);
        limits.wall_deadline_ms = 10;
        limits.epoch.deadline_ticks = u64::MAX;
        limits.max_fuel = u64::MAX;
        let report =
            engine.invoke_component(&Sha256Digest::of_bytes(b"deadline"), &limits, b"", true);
        assert_eq!(report.termination, EngineTermination::Deadline);
        assert!(report.usage.epoch_ticks.unwrap_or(0) > 0);
        assert!(started.elapsed() < Duration::from_secs(2));
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
