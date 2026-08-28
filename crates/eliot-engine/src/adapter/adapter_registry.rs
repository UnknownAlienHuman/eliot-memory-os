//! Bounded adapter-registry service cluster — registry, capability-manifest and health projection.
//!
//! Architecture anchors: `A10` (adapter/swarm runtime) and `ARCH-MOD-01` (small living Kernel).
//! Implementation anchors: `I10.15` (adapter contracts) and `I16.1` (reports are projections).
//!
//! This child owns only in-memory adapter registration, manifest validation/inspection and
//! derived health projection (`report`). It does not execute providers, supervise processes,
//! mutate circuits beyond the projection, or hold canonical write/patch/finish authority.
//! Source-backed ownership remains in `eliot-engine` (`adapter.rs`); canonical stores and
//! `AdapterSupervisor` stay authoritative.

use std::collections::BTreeMap;
use std::sync::Arc;

use time::OffsetDateTime;

use crate::EngineError;
use eliot_types::{AdapterCapability, CapabilityManifest};

use super::adapter_rejected;
use super::{Adapter, AdapterRegistryReport, AdapterSupervisor};
use super::{
    HealthAdapter, TestEchoAdapter, TestFailingAdapter, TestLargeOutputAdapter, TestSlowAdapter,
};

#[derive(Clone)]
pub struct AdapterRegistry {
    adapters: BTreeMap<String, Arc<dyn Adapter>>,
}

impl AdapterRegistry {
    pub fn new() -> Self {
        Self {
            adapters: BTreeMap::new(),
        }
    }

    pub fn builtin() -> Result<Self, EngineError> {
        let mut registry = Self::new();
        registry.register(HealthAdapter::new())?;
        registry.register(TestEchoAdapter::new())?;
        registry.register(TestFailingAdapter::new())?;
        registry.register(TestSlowAdapter::new())?;
        registry.register(TestLargeOutputAdapter::new())?;
        Ok(registry)
    }

    pub fn register<A>(&mut self, adapter: A) -> Result<(), EngineError>
    where
        A: Adapter + 'static,
    {
        self.validate_manifest(adapter.manifest())?;
        self.adapters
            .insert(adapter.id().to_owned(), Arc::new(adapter));
        Ok(())
    }

    pub fn manifests(&self) -> Vec<CapabilityManifest> {
        self.adapters
            .values()
            .map(|adapter| adapter.manifest().clone())
            .collect()
    }

    pub fn adapter(&self, adapter_id: &str) -> Result<Arc<dyn Adapter>, EngineError> {
        self.adapters
            .get(adapter_id)
            .cloned()
            .ok_or_else(|| adapter_rejected(format!("unknown adapter: {adapter_id}")))
    }

    pub fn inspect(&self, adapter_id: &str) -> Result<CapabilityManifest, EngineError> {
        Ok(self.adapter(adapter_id)?.manifest().clone())
    }

    pub fn validate_manifest(&self, manifest: &CapabilityManifest) -> Result<(), EngineError> {
        if manifest.adapter_id.trim().is_empty() {
            return Err(adapter_rejected("adapter_id is required"));
        }
        if manifest.name.trim().is_empty() {
            return Err(adapter_rejected("adapter name is required"));
        }
        if manifest.version.trim().is_empty() {
            return Err(adapter_rejected("adapter version is required"));
        }
        if manifest.authority_profile.can_write_truth
            || manifest.authority_profile.can_request_patch
            || manifest.authority_profile.can_finish_task
        {
            return Err(adapter_rejected(
                "adapter authority cannot grant truth, patch, or finish authority",
            ));
        }
        if manifest
            .capabilities
            .iter()
            .any(|capability| capability.is_forbidden_authority())
        {
            return Err(adapter_rejected(
                "adapter capability cannot grant truth, patch, or finish authority",
            ));
        }
        if manifest
            .authority_profile
            .allowed_capabilities
            .iter()
            .any(|capability| capability.is_forbidden_authority())
        {
            return Err(adapter_rejected(
                "adapter authority profile cannot allow truth, patch, or finish capability",
            ));
        }
        if manifest.limits.max_concurrent_requests == 0 {
            return Err(adapter_rejected("max_concurrent_requests must be positive"));
        }
        Ok(())
    }

    pub fn validate_capability_names(
        values: &[String],
    ) -> Result<Vec<AdapterCapability>, EngineError> {
        values
            .iter()
            .map(|value| {
                AdapterCapability::from_wire_name(value)
                    .ok_or_else(|| adapter_rejected(format!("unknown adapter capability: {value}")))
            })
            .collect()
    }

    pub async fn report(&self) -> AdapterRegistryReport {
        let health = AdapterSupervisor::new(self.clone()).health_all().await;
        AdapterRegistryReport {
            component: "adapter_registry".to_owned(),
            adapters: self.manifests(),
            manifests_loaded: self.adapters.len(),
            unknown_capabilities_denied: Self::validate_capability_names(&["raw_shell".to_owned()])
                .is_err(),
            authority_bypass_denied: self
                .adapters
                .values()
                .all(|adapter| self.validate_manifest(adapter.manifest()).is_ok()),
            health,
            generated_at: OffsetDateTime::now_utc(),
        }
    }
}

impl Default for AdapterRegistry {
    fn default() -> Self {
        Self::new()
    }
}
