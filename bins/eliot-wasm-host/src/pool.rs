//! Compiled-component cache and instance-pool owner (issue #21, W1).
//!
//! Normative basis: I1.3 (`eliot-wasm-host` owns compiled component caches,
//! instance pools, Store limits, and shadow/canary execution); A13.3
//! (cache rebuild is an automatic-safe repair); the crates/modules/AGENTS.md
//! hard boundary (caches/pools are rebuildable acceleration and never carry
//! proof, authority, freshness, or old-generation resources across
//! restart/cutover).
//!
//! [`ComponentPool`] is the single owner behind Wasmtime engine
//! construction: it builds the pooled epoch/fuel [`Engine`] pair from the
//! admitted [`InvocationLimits`] and compiles each immutable artifact
//! through a digest-keyed cache. Cache keys carry the exact artifact,
//! component-configuration, and engine-configuration digests — never name,
//! path, or version strings alone (hardening 3). The pool holds no
//! generation, epoch, fence, proof, or authority value by construction (the
//! key has no such field); a fresh pool per process carries nothing across
//! restart/cutover, and dropping the pool is the rebuild. Pool capacity
//! mirrors the admitted Store ceilings one for one (the provider enforces
//! the same numbers per Store through `StoreLimitsBuilder`), so anything
//! the Store admits the pool admits; structural per-module knobs keep
//! wasmtime defaults and are named as such in the pooled descriptor.
//!
//! Production caller: `WasmtimeComponentEngine::new_for_admitted_limits`
//! over the child-held admitted limits.

use std::collections::HashMap;

use eliot_wasm_runtime::{InvocationLimits, MAX_EPOCH_DEADLINE_TICKS, Sha256Digest};
use wasmtime::component::Component;
use wasmtime::{Config, Engine, InstanceAllocationStrategy, PoolingAllocationConfig};

use crate::contour::PINNED_WASMTIME_VERSION;
use crate::wasmtime_provider::PROVIDER_STACK_SIZE;

/// Digest-keyed compiled-component cache identity: the exact artifact, the
/// component configuration bound at build, and the pooled engine settings
/// below. No name, path, version, generation, epoch, fence, proof, or
/// authority value participates in the key.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct PoolCacheKey {
    /// Digest of the exact immutable component artifact bytes.
    pub artifact: Sha256Digest,
    /// Digest of the component configuration bound at build.
    pub component_configuration: Sha256Digest,
    /// Digest of the pooled engine settings (naming pool capacity).
    pub engine_configuration: Sha256Digest,
}

/// Instance-pool capacity derived from the admitted limit envelope. Every
/// capacity knob mirrors one admitted Store ceiling one for one; structural
/// per-module knobs are not limits and keep wasmtime defaults.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InstancePoolConfig {
    /// Pool slots per engine: component/core instances, memories, and
    /// tables. Mirrors `max_instances`. (No stack slots: the provider is
    /// synchronous, and stack pooling is async-only in wasmtime.)
    pub total_instances: u32,
    /// Pool slot size for one linear memory in bytes. Mirrors
    /// `max_memory_bytes`.
    pub max_memory_bytes: u64,
    /// Pool table elements per table. Mirrors `max_table_elements`.
    pub max_table_elements: u32,
}

impl InstancePoolConfig {
    /// Derives pool capacity from the admitted per-invocation limits. The
    /// limits arrive from the Governor-admitted envelope (manifest limits
    /// through the staged child argv); the pool interprets them as capacity,
    /// never as authority.
    #[must_use]
    pub fn from_limits(limits: &InvocationLimits) -> Self {
        Self {
            total_instances: limits.max_instances,
            max_memory_bytes: limits.max_memory_bytes,
            max_table_elements: limits.max_table_elements,
        }
    }

    /// Builds one pooled engine configuration: the exact provider settings
    /// (component model, epoch interruption, provider stack ceiling) plus
    /// the pooling allocator bounded by this capacity.
    fn engine_config(&self, consume_fuel: bool) -> Config {
        let mut pool = PoolingAllocationConfig::default();
        pool.total_component_instances(self.total_instances);
        pool.total_core_instances(self.total_instances);
        pool.total_memories(self.total_instances);
        pool.total_tables(self.total_instances);
        pool.max_memory_size(usize::try_from(self.max_memory_bytes).unwrap_or(usize::MAX));
        pool.table_elements(usize::try_from(self.max_table_elements).unwrap_or(usize::MAX));
        let mut config = Config::new();
        config.wasm_component_model(true);
        config.consume_fuel(consume_fuel);
        config.epoch_interruption(true);
        config.max_wasm_stack(PROVIDER_STACK_SIZE);
        config.allocation_strategy(InstanceAllocationStrategy::Pooling(pool));
        config
    }
}

/// Returns the canonical digest of the exact pooled engine settings for one
/// pool capacity. The digest names the pinned Wasmtime generation, the fixed
/// provider settings, and the capacity numbers; it changes if and only if
/// those settings change. Structural knobs are recorded as wasmtime
/// defaults, never silently absorbed.
#[must_use]
pub fn pooled_configuration_digest(pool: &InstancePoolConfig) -> Sha256Digest {
    Sha256Digest::of_bytes(pooled_configuration_descriptor(pool).as_bytes())
}

/// Canonical pooled-settings descriptor. Written out (not hashed incrementally)
/// so the bound settings stay inspectable in receipts and reviews.
fn pooled_configuration_descriptor(pool: &InstancePoolConfig) -> String {
    format!(
        "wasmtime={PINNED_WASMTIME_VERSION};component_model=true;typed_abi=guest.run;max_wasm_stack={};max_epoch_deadline_ticks={MAX_EPOCH_DEADLINE_TICKS};allocation=pooling;pool_total_instances={};pool_max_memory_bytes={};pool_table_elements={};pool_structural=wasmtime-default;epoch_only.consume_fuel=false;epoch_only.epoch_interruption=true;epoch_and_fuel.consume_fuel=true;epoch_and_fuel.epoch_interruption=true",
        PROVIDER_STACK_SIZE, pool.total_instances, pool.max_memory_bytes, pool.max_table_elements,
    )
}

/// Compiled-component cache over one pooled engine pair. Components are
/// engine-bound, so the cache and its engines share one owner and one
/// lifetime: entries are valid exactly while the pool lives, and a fresh
/// pool rebuilds from artifact bytes (never from a previous pool,
/// generation, or proof).
pub struct ComponentPool {
    epoch_engine: Engine,
    fuel_engine: Engine,
    cache: HashMap<PoolCacheKey, (Component, Component)>,
}

impl std::fmt::Debug for ComponentPool {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ComponentPool")
            .field("cached_pairs", &self.cache.len())
            .finish_non_exhaustive()
    }
}

impl ComponentPool {
    /// Builds the pooled epoch/fuel engine pair with an empty cache. Cache
    /// entries accumulate only through [`Self::compile`]; nothing is
    /// restored from disk, a previous generation, or another pool.
    pub fn new(pool: &InstancePoolConfig) -> Result<Self, wasmtime::Error> {
        Ok(Self {
            epoch_engine: Engine::new(&pool.engine_config(false))?,
            fuel_engine: Engine::new(&pool.engine_config(true))?,
            cache: HashMap::new(),
        })
    }

    /// Compiles one immutable artifact under both pooled engines through
    /// the digest-keyed cache: a cache hit returns the previously compiled
    /// pair without recompiling; a miss compiles, inserts under the exact
    /// key, and returns the fresh pair.
    pub fn compile(
        &mut self,
        key: &PoolCacheKey,
        artifact: &[u8],
    ) -> Result<(Component, Component), wasmtime::Error> {
        if let Some(compiled) = self.cache.get(key) {
            return Ok(compiled.clone());
        }
        let epoch_component = Component::new(&self.epoch_engine, artifact)?;
        let fuel_component = Component::new(&self.fuel_engine, artifact)?;
        self.cache.insert(
            key.clone(),
            (epoch_component.clone(), fuel_component.clone()),
        );
        Ok((epoch_component, fuel_component))
    }

    /// Releases the pooled engines to the constructed engine; the cache
    /// drops with the pool, which is the rebuild: no entry outlives the
    /// compilation it served.
    pub fn into_engines(self) -> (Engine, Engine) {
        (self.epoch_engine, self.fuel_engine)
    }
}
