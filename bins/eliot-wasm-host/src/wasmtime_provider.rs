use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use std::thread;
use std::time::{Duration, Instant};

use eliot_wasm_runtime::{
    ComponentEnginePort, EngineBinding, EngineInvocation, EngineReport, EngineTermination,
    EngineUsage, PortError, Sha256Digest, TrapClass,
};
use wasmtime::component::{Component, Linker};
use wasmtime::{Config, Engine, Store, StoreLimits, StoreLimitsBuilder};

const WASMTIME_VERSION: &str = "47.0.0";
const WIT_VERSION: &str = "1.0.0";
const WIT_WORLD: &str = "eliot:wasm/guest";
const RUN_EXPORT: &str = "run";

wasmtime::component::bindgen!({
    path: "wit/guest.wit",
    world: "guest",
});

struct StoreState {
    limits: StoreLimits,
}

/// Concrete typed Wasmtime Component Model provider for one admitted artifact.
/// The linker is deliberately empty: this world has no host imports or WASI.
pub struct WasmtimeComponentEngine {
    engine: Engine,
    component: Component,
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
        let mut config = Config::new();
        config.wasm_component_model(true);
        config.consume_fuel(true);
        config.epoch_interruption(true);
        let engine = Engine::new(&config).map_err(WasmtimeBuildError::Config)?;
        let component = Component::new(&engine, artifact).map_err(WasmtimeBuildError::Compile)?;
        Ok(Self {
            engine,
            component,
            binding,
            artifact_digest,
            artifact_bytes: artifact.len() as u64,
        })
    }

    fn invoke_component(&self, invocation: &EngineInvocation) -> EngineReport {
        let limits = &invocation.limits;
        let mut store = Store::new(
            &self.engine,
            StoreState {
                limits: StoreLimitsBuilder::new()
                    .memory_size(usize::try_from(limits.max_memory_bytes).unwrap_or(usize::MAX))
                    .table_elements(
                        usize::try_from(limits.max_table_elements).unwrap_or(usize::MAX),
                    )
                    .instances(usize::try_from(limits.max_instances).unwrap_or(usize::MAX))
                    .build(),
            },
        );
        store.limiter(|state| &mut state.limits);
        let start = Instant::now();
        let mut instances = 0;
        let fuel_set = store.set_fuel(limits.max_fuel).is_ok();
        store.set_epoch_deadline(limits.epoch.deadline_ticks);
        let stop_epoch = Arc::new(AtomicBool::new(false));
        let epoch_stop = Arc::clone(&stop_epoch);
        let epoch_engine = self.engine.clone();
        let epoch_thread = thread::spawn(move || {
            while !epoch_stop.load(Ordering::Acquire) {
                thread::sleep(Duration::from_millis(1));
                epoch_engine.increment_epoch();
            }
        });

        let (termination, output) = if fuel_set {
            let linker = Linker::new(&self.engine);
            let call =
                Guest::instantiate(&mut store, &self.component, &linker).and_then(|instance| {
                    instances = 1;
                    instance.call_run(&mut store, &invocation.input)
                });
            match call {
                Ok(Ok(value)) if value.len() as u64 <= limits.max_output_bytes => {
                    (EngineTermination::Completed, value)
                }
                Ok(Ok(_)) => (EngineTermination::OutputLimit, Vec::new()),
                Ok(Err(_)) => (EngineTermination::Trap(TrapClass::GuestTrap), Vec::new()),
                Err(error) => (classify_trap(&error), Vec::new()),
            }
        } else {
            (
                EngineTermination::Trap(TrapClass::HostContractViolation),
                Vec::new(),
            )
        };
        stop_epoch.store(true, Ordering::Release);
        let _ = epoch_thread.join();
        let elapsed_ms = u64::try_from(start.elapsed().as_millis()).unwrap_or(u64::MAX);
        let fuel_consumed = limits
            .max_fuel
            .saturating_sub(store.get_fuel().unwrap_or(0));
        EngineReport {
            request_digest: invocation.request_digest.clone(),
            termination,
            usage: EngineUsage {
                output_bytes: output.len() as u64,
                host_calls: 0,
                fuel_consumed,
                peak_memory_bytes: 0,
                table_elements: 0,
                instances,
                stack_bytes: 0,
                elapsed_ms,
                epoch_ticks: 0,
                artifact_reads: 0,
                artifact_bytes: 0,
                accessed_artifact_digests: Vec::new(),
            },
            output,
            host_calls: Vec::new(),
            proposed_effects: Vec::new(),
            observed_state_delta: Vec::new(),
            reaped: true,
            post_commit_known: instances > 0,
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
        Ok(self.invoke_component(invocation))
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
        _ => EngineTermination::Trap(TrapClass::GuestTrap),
    }
}
