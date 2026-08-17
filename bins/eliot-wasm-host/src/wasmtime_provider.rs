use std::time::Instant;

use eliot_wasm_runtime::{
    ComponentEnginePort, EngineBinding, EngineInvocation, EngineReport, EngineTermination,
    EngineUsage, PortError, Sha256Digest, TrapClass,
};
use wasmtime::component::{Component, Linker, Val};
use wasmtime::{Config, Engine, Store, StoreLimits, StoreLimitsBuilder};

const WASMTIME_VERSION: &str = "47.0.0";
const RUN_EXPORT: &str = "run";

struct StoreState {
    limits: StoreLimits,
}

/// Concrete Wasmtime Component Model provider for an admitted component.
///
/// No WASI linker is installed. Consequently filesystem, network, process,
/// environment, clock, and secret authority are absent unless a future
/// versioned ELIOT WIT world explicitly adds a bounded host interface.
pub struct WasmtimeComponentEngine {
    engine: Engine,
    component: Component,
    binding: EngineBinding,
    artifact_digest: Sha256Digest,
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
        })
    }

    fn invoke_component(&mut self, invocation: &EngineInvocation) -> EngineReport {
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
        let _ = store.set_fuel(limits.max_fuel);
        store.set_epoch_deadline(limits.epoch.deadline_ticks);
        let linker = Linker::new(&self.engine);
        let start = Instant::now();
        let mut output = [Val::U32(0)];
        let call = linker
            .instantiate(&mut store, &self.component)
            .and_then(|instance| {
                instance
                    .get_func(&mut store, RUN_EXPORT)
                    .ok_or_else(|| wasmtime::Error::msg("missing versioned run export"))
            })
            .and_then(|run| {
                run.call(
                    &mut store,
                    &[Val::U32(
                        u32::try_from(invocation.input.len()).unwrap_or(u32::MAX),
                    )],
                    &mut output,
                )
            });
        let elapsed_ms = u64::try_from(start.elapsed().as_millis()).unwrap_or(u64::MAX);
        let (termination, output) = match call {
            Ok(()) => match output[0] {
                Val::U32(value) => (EngineTermination::Completed, value.to_le_bytes().to_vec()),
                _ => (
                    EngineTermination::Trap(TrapClass::HostContractViolation),
                    Vec::new(),
                ),
            },
            Err(error) => (classify_trap(&error), Vec::new()),
        };
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
                instances: 1,
                stack_bytes: 0,
                elapsed_ms,
                epoch_ticks: 0,
                artifact_reads: 1,
                artifact_bytes: 0,
                accessed_artifact_digests: vec![self.artifact_digest.clone()],
            },
            output,
            host_calls: Vec::new(),
            proposed_effects: Vec::new(),
            observed_state_delta: Vec::new(),
            reaped: true,
            post_commit_known: true,
        }
    }
}

impl ComponentEnginePort for WasmtimeComponentEngine {
    fn binding(&self) -> &EngineBinding {
        &self.binding
    }

    fn invoke(&mut self, invocation: &EngineInvocation) -> Result<EngineReport, PortError> {
        if invocation.manifest.artifact_digest != self.artifact_digest
            || invocation.manifest.engine != self.binding
            || !invocation.manifest.imports.is_empty()
            || !invocation.manifest.exports.contains(
                &eliot_wasm_runtime::CapabilityId::new(RUN_EXPORT)
                    .map_err(|_| PortError::Denied)?,
            )
        {
            return Err(PortError::Denied);
        }
        Ok(self.invoke_component(invocation))
    }

    fn reconcile(&mut self, invocation: &EngineInvocation) -> Result<EngineReport, PortError> {
        self.invoke(invocation)
    }
}

fn classify_trap(error: &wasmtime::Error) -> EngineTermination {
    let text = error.to_string();
    if text.contains("fuel") {
        EngineTermination::FuelExhausted
    } else if text.contains("epoch") {
        EngineTermination::EpochDeadline
    } else if text.contains("memory") {
        EngineTermination::MemoryLimit
    } else if text.contains("table") {
        EngineTermination::TableLimit
    } else {
        EngineTermination::Trap(TrapClass::GuestTrap)
    }
}
