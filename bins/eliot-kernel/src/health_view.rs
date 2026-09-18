//! Kernel health and recovery view closure.
//!
//! Traceability: Architecture A2.3, A12.2, A12.3, A13.2, A13.3;
//! Implementation I2.15, I2.16, I5.1, I7.2, I7.14, I14.10, I14.21, I14.24,
//! and I15.8. This ordinary module is view-only: it reports authenticated
//! Kernel state and bounded Store health, but does not perform dispatch,
//! daemon readiness, runtime supervision, or recovery mutation. The module
//! remains below the `<10k LOC` split invariant; this is an implementation
//! invariant for maintainability, not a claimed Architecture numeric rule.

use super::*;

/// F-LOG-KERNEL-4 (#903 slice B): health-view boundary observations.
///
/// Observation only, via #895's facade: fixed `kernel.health.*` event names
/// plus a bounded stable outcome. This module stays view-only: observations
/// record that a health projection was read and which evidence was
/// missing/stale, but never change health derivation, never invent
/// measurements, and never carry digests, generations, epochs, Store payloads,
/// or owner error strings (I15.4, I07.20, I01.10). Terminal ownership stays
/// with the dispatch owners, which map `TransportError`/`KernelServiceError`
/// into their typed terminal codes; views emit no terminal here so one failed
/// operation keeps exactly one terminal record.
fn observe_health(event: &'static str, outcome: &'static str) {
    use super::kernel_diagnostics::{KERNEL_DIAGNOSTICS_TARGET, bound_field};
    let event_bound = bound_field(event);
    let outcome_bound = bound_field(outcome);
    tracing::info!(
        target: KERNEL_DIAGNOSTICS_TARGET,
        event = event_bound.text(),
        outcome = outcome_bound.text(),
        "health view observation"
    );
}

impl KernelComposition {
    pub(super) fn daemon_health_response(health: &StoreHealth) -> serde_json::Value {
        observe_health("kernel.health.response_projected", "known");
        serde_json::json!({
            "status": "known",
            "value": {
                "kind": "health",
                "value": health,
            },
            "recovery": null,
        })
    }

    pub(super) fn daemon_snapshot(&self) -> Result<serde_json::Value, TransportError> {
        let Ok(policy) = self.front_door_policy.lock() else {
            observe_health("kernel.health.snapshot_omitted", "fenced");
            return Err(TransportError::SessionFenced);
        };
        let Some(kernel_artifact_digest) = policy
            .config_snapshot
            .get("artifact_digest")
            .and_then(serde_json::Value::as_str)
            .filter(|value| !value.trim().is_empty())
        else {
            observe_health("kernel.health.snapshot_omitted", "missing_artifact");
            return Err(TransportError::SessionFenced);
        };
        let protected_snapshot_digest = policy
            .config_snapshot
            .get("protected_snapshot_digest")
            .and_then(serde_json::Value::as_str);
        if let Some(value) = protected_snapshot_digest {
            if !is_lower_sha256(value) {
                observe_health("kernel.health.snapshot_omitted", "invalid_protected");
                return Err(TransportError::SessionFenced);
            }
        } else if self.daemon_launch.is_some() {
            observe_health("kernel.health.snapshot_omitted", "missing_protected");
            return Err(TransportError::SessionFenced);
        }
        let mut snapshot = serde_json::json!({
            "service": SERVICE_NAME,
            "protocol": PROTOCOL_VERSION,
            "generation": policy.module_generation.generation.value(),
            "authority_epoch": policy.module_generation.state_fence.authority_epoch.clone(),
            // This is the Kernel peer artifact domain. The daemon child
            // artifact remains in module_generation.artifact_id and ClientHello.
            "artifact_digest": kernel_artifact_digest,
        });
        if let Some(protected_snapshot_digest) = protected_snapshot_digest {
            snapshot["protected_snapshot_digest"] =
                serde_json::Value::String(protected_snapshot_digest.to_owned());
        }
        observe_health("kernel.health.snapshot_projected", "success");
        Ok(snapshot)
    }

    #[cfg(windows)]
    pub(super) async fn daemon_health(
        &self,
    ) -> Result<eliot_store_api::StoreHealth, KernelServiceError> {
        let gateway = if let Ok(gateway) = self.canonical_store_gateway.lock() {
            gateway.clone()
        } else {
            observe_health("kernel.health.store_unavailable", "fenced");
            return Err(KernelServiceError::Platform(
                "store gateway lock poisoned".to_owned(),
            ));
        };
        let Some(gateway) = gateway else {
            observe_health("kernel.health.store_absent", "unknown");
            return Err(KernelServiceError::ReadinessNotProven);
        };
        match gateway.health().await {
            Ok(health) => {
                observe_health("kernel.health.store_reported", "success");
                Ok(health)
            }
            Err(error) => {
                observe_health("kernel.health.store_unavailable", "unknown");
                Err(KernelServiceError::Platform(error))
            }
        }
    }

    #[cfg(not(windows))]
    pub(super) async fn daemon_health(
        &self,
    ) -> Result<eliot_store_api::StoreHealth, KernelServiceError> {
        observe_health("kernel.health.store_absent", "unknown");
        Err(KernelServiceError::ReadinessNotProven)
    }

    /// Returns the current Kernel service lifecycle state.
    pub fn service_state(&self) -> Result<KernelServiceState, KernelServiceError> {
        let Ok(service) = self.service.lock() else {
            observe_health("kernel.health.service_state_omitted", "fenced");
            return Err(KernelServiceError::Platform(
                "service lock poisoned".to_owned(),
            ));
        };
        let state = service.state();
        observe_health("kernel.health.service_state_observed", "success");
        Ok(state)
    }
}
