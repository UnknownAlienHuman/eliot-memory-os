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

impl KernelComposition {
    pub(super) fn daemon_health_response(health: &StoreHealth) -> serde_json::Value {
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
        let policy = self
            .front_door_policy
            .lock()
            .map_err(|_| TransportError::SessionFenced)?;
        let kernel_artifact_digest = policy
            .config_snapshot
            .get("artifact_digest")
            .and_then(serde_json::Value::as_str)
            .filter(|value| !value.trim().is_empty())
            .ok_or(TransportError::SessionFenced)?;
        let protected_snapshot_digest = policy
            .config_snapshot
            .get("protected_snapshot_digest")
            .and_then(serde_json::Value::as_str);
        if let Some(value) = protected_snapshot_digest {
            if !is_lower_sha256(value) {
                return Err(TransportError::SessionFenced);
            }
        } else if self.daemon_launch.is_some() {
            return Err(TransportError::SessionFenced);
        }
        let mut snapshot = serde_json::json!({
            "service": SERVICE_NAME,
            "protocol": PROTOCOL_VERSION,
            "generation": policy.module_generation.generation.value(),
            "authority_epoch": policy.module_generation.state_fence.authority_epoch.value(),
            // This is the Kernel peer artifact domain. The daemon child
            // artifact remains in module_generation.artifact_id and ClientHello.
            "artifact_digest": kernel_artifact_digest,
        });
        if let Some(protected_snapshot_digest) = protected_snapshot_digest {
            snapshot["protected_snapshot_digest"] =
                serde_json::Value::String(protected_snapshot_digest.to_owned());
        }
        Ok(snapshot)
    }

    #[cfg(windows)]
    pub(super) async fn daemon_health(
        &self,
    ) -> Result<eliot_store_api::StoreHealth, KernelServiceError> {
        let gateway = self
            .canonical_store_gateway
            .lock()
            .map_err(|_| KernelServiceError::Platform("store gateway lock poisoned".to_owned()))?
            .clone()
            .ok_or(KernelServiceError::ReadinessNotProven)?;
        gateway.health().await.map_err(KernelServiceError::Platform)
    }

    #[cfg(not(windows))]
    pub(super) async fn daemon_health(
        &self,
    ) -> Result<eliot_store_api::StoreHealth, KernelServiceError> {
        Err(KernelServiceError::ReadinessNotProven)
    }

    /// Returns the current Kernel service lifecycle state.
    pub fn service_state(&self) -> Result<KernelServiceState, KernelServiceError> {
        Ok(self
            .service
            .lock()
            .map_err(|_| KernelServiceError::Platform("service lock poisoned".to_owned()))?
            .state())
    }
}
