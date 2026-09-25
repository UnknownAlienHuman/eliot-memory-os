//! Kernel health and recovery view closure.
//!
//! Traceability: Architecture A2.3, A12.2, A12.3, A13.2, A13.3;
//! Implementation I2.15, I2.16, I5.1, I7.2, I7.14, I14.10, I14.21, I14.24,
//! and I15.8. This ordinary module is view-only: it reports authenticated
//! Kernel state and bounded Store health, but does not perform dispatch,
//! daemon readiness, runtime supervision, or recovery mutation. The module
//! remains below the `<10k LOC` split invariant; this is an implementation
//! invariant for maintainability, not a claimed Architecture numeric rule.

use super::kernel_unavailability::{
    KernelAvailability, RecoveryDeferral, RecoveryView, semantic_task_recovery_deferral,
};
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

/// Bounded Kernel activation / generation / governance / lease / drain
/// projection (I1.5 diagnostics requirement).
///
/// Every field is a closed vocabulary code. The projection therefore cannot
/// leak a lease identity, digest, epoch value, generation string, or owner
/// error text (I15.4), and it never reports liveness as readiness.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct KernelActivationView {
    /// Kernel service lifecycle state code.
    pub service_state: &'static str,
    /// Whether an approved runtime generation is bound to the front door.
    pub generation: &'static str,
    /// Governance posture derived from the observed lease census.
    pub governance: &'static str,
    /// Active lease state code from the exact-fence census.
    pub lease_state: &'static str,
    /// Durable drain disposition code.
    pub drain_disposition: &'static str,
}

impl KernelActivationView {
    /// The single answer used when the service state itself is unreadable.
    pub(crate) const FENCED: Self = Self {
        service_state: "fenced",
        generation: "unbound",
        governance: "unsupervised",
        lease_state: "unavailable",
        drain_disposition: "proceed",
    };
}

/// Bounded observation code for the Kernel service lifecycle state.
const fn kernel_service_state_code(state: KernelServiceState) -> &'static str {
    match state {
        KernelServiceState::Cold => "cold",
        KernelServiceState::Reconciling => "reconciling",
        KernelServiceState::ShadowNoAuthority => "shadow-no-authority",
        KernelServiceState::HandoffPrepared => "handoff-prepared",
        KernelServiceState::Activating => "activating",
        KernelServiceState::Ready => "ready",
        KernelServiceState::Degraded => "degraded",
        KernelServiceState::Draining => "draining",
        KernelServiceState::Stopped => "stopped",
        KernelServiceState::Failed => "failed",
        KernelServiceState::ManualRecovery => "manual-recovery",
    }
}

/// Projects the activation view onto the Kernel shutdown/control diagnostics
/// through the same bounded-field helpers the rest of the binary uses
/// (F-LOG-KERNEL-3, I15.4). One fixed event plus bounded codes only; never an
/// identity, digest, generation value, or owner error string.
pub(crate) fn observe_shutdown_observation(event: &'static str, outcome: &'static str) {
    use crate::kernel_diagnostics::{KERNEL_DIAGNOSTICS_TARGET, bound_field};
    let event_bound = bound_field(event);
    let outcome_bound = bound_field(outcome);
    tracing::info!(
        target: KERNEL_DIAGNOSTICS_TARGET,
        event = event_bound.text(),
        outcome = outcome_bound.text(),
        "activation observation"
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

    /// Projects the Kernel's own activation state, generation, governance
    /// posture, active lease state and drain disposition (I1.5 "Expose the
    /// resulting activation state, generation, governance profile, active lease
    /// state, and drain disposition through the existing minimal operational
    /// diagnostics rather than relying on process liveness alone").
    ///
    /// View-only and bounded: every field is a closed vocabulary code, so the
    /// projection can never leak a lease identity, digest, epoch value, or
    /// owner error string (I15.4). It derives nothing from a live process, an
    /// open pipe, or a heartbeat.
    #[must_use]
    pub fn activation_operational_view(&self) -> KernelActivationView {
        let state = match self.service_state() {
            Ok(state) => state,
            Err(_) => {
                observe_health("kernel.activation.view_projected", "fenced");
                return KernelActivationView::FENCED;
            }
        };
        let generation_bound = self
            .front_door_policy
            .lock()
            .map(|policy| policy.module_generation.generation.value() != 0)
            .unwrap_or(false);
        let census = self.idle_lease_census();
        let view = KernelActivationView {
            service_state: kernel_service_state_code(state),
            generation: if generation_bound { "bound" } else { "unbound" },
            governance: if census == KernelIdleLeaseCensus::SupervisionLeased {
                "independently-supervised"
            } else {
                "unsupervised"
            },
            lease_state: census.observation_code(),
            drain_disposition: crate::coordinator_for(&self.work_root).drain_disposition(),
        };
        observe_health("kernel.activation.view_projected", view.lease_state);
        view
    }

    /// Projects blob demand-controller state into the I1.10 health vocabulary
    /// (#1969). View-only: fixed manifest/process/large-payload labels only;
    /// carries no digests, generations, paths, or payloads. Consumed by the
    /// health dispatch route; the dispatch wiring itself is owned there.
    #[must_use]
    pub fn blob_capability_projection(&self) -> serde_json::Value {
        match self.blob_probe_status() {
            None => {
                observe_health("kernel.health.blob_projected", "absent");
                serde_json::json!({
                    "manifest": "absent",
                    "process": "not_started",
                    "large_payload": "degraded",
                })
            }
            Some(BlobProbeStatus::ManifestValidated) => {
                observe_health("kernel.health.blob_projected", "standby");
                serde_json::json!({
                    "manifest": "validated",
                    "process": "not_started",
                    "large_payload": "standby",
                })
            }
            Some(BlobProbeStatus::Ready { .. }) => {
                observe_health("kernel.health.blob_projected", "ready");
                serde_json::json!({
                    "manifest": "validated",
                    "process": "started",
                    "large_payload": "ready",
                })
            }
            Some(BlobProbeStatus::Degraded { .. }) => {
                observe_health("kernel.health.blob_projected", "degraded");
                serde_json::json!({
                    "manifest": "validated",
                    "process": "started",
                    "large_payload": "degraded",
                })
            }
        }
    }

    /// Projects the restricted Recovery View for surviving Host/Watchdog
    /// interactions while the Kernel is unavailable (I1.13).
    ///
    /// The projection carries only build, generation, ORS, and incident
    /// state. Semantic task recovery is never projected here; callers use
    /// [`Self::deferred_semantic_recovery`] instead, which waits for
    /// canonical access.
    pub fn recovery_view_response(view: &RecoveryView) -> serde_json::Value {
        observe_health("kernel.health.recovery_view_projected", "known");
        view.to_json()
    }

    /// Defers semantic task recovery pending canonical access (I1.13).
    ///
    /// Reachable from the Recovery View path so no route can imply that a
    /// semantic action completed without canonical access. The Kernel
    /// argument keeps the deferral tied to the shared availability guard:
    /// while the Kernel is unavailable the deferral always applies, and the
    /// observation records it.
    pub fn deferred_semantic_recovery(kernel: KernelAvailability) -> RecoveryDeferral {
        if kernel == KernelAvailability::Unavailable {
            observe_health("kernel.health.semantic_recovery_deferred", "known");
        }
        semantic_task_recovery_deferral()
    }
}
