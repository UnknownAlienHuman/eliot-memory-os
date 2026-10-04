//! Kernel health and recovery view closure.
//!
//! Traceability: Architecture A2.3, A12.2, A12.3, A13.2, A13.3;
//! Implementation I2.15, I2.16, I5.1, I7.2, I7.14, I14.10, I14.21, I14.24,
//! and I15.8. This ordinary module is view-only: it reports authenticated
//! Kernel state and bounded Store health, but does not perform dispatch,
//! daemon readiness, runtime supervision, or recovery mutation. The module
//! remains below the `<10k LOC` split invariant; this is an implementation
//! invariant for maintainability, not a claimed Architecture numeric rule.

use std::collections::BTreeMap;

use super::kernel_audit::AuditEventKind;
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
        drain_disposition: "unavailable",
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
        let kernel_artifact_digest = policy
            .config_snapshot
            .get("artifact_digest")
            .and_then(serde_json::Value::as_str)
            .filter(|value| !value.trim().is_empty())
            .map(str::to_owned);
        let protected_snapshot_digest = policy
            .config_snapshot
            .get("protected_snapshot_digest")
            .and_then(serde_json::Value::as_str)
            .map(str::to_owned);
        let generation = policy.module_generation.generation.value();
        let authority_epoch = policy.module_generation.state_fence.authority_epoch.clone();
        drop(policy);
        let Some(kernel_artifact_digest) = kernel_artifact_digest else {
            observe_health("kernel.health.snapshot_omitted", "missing_artifact");
            return Err(TransportError::SessionFenced);
        };
        if let Some(value) = protected_snapshot_digest.as_deref() {
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
            "generation": generation,
            "authority_epoch": authority_epoch,
            // This is the Kernel peer artifact domain. The daemon child
            // artifact remains in module_generation.artifact_id and ClientHello.
            "artifact_digest": kernel_artifact_digest,
        });
        if let Some(protected_snapshot_digest) = protected_snapshot_digest {
            snapshot["protected_snapshot_digest"] =
                serde_json::Value::String(protected_snapshot_digest);
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
        drop(service);
        observe_health("kernel.health.service_state_observed", "success");
        Ok(state)
    }

    /// Returns exclusive access to the lifecycle owner so an out-of-crate
    /// harness can publish the same ready receipt `activate_harness_candidate`
    /// publishes for a composition-owned candidate.
    ///
    /// This adds no lifecycle transition and weakens no production gate: every
    /// mutation it permits is one `KernelService` already exposes publicly, and
    /// the composition's own arm still refuses any state but `Ready`.
    pub fn service_mut(&self) -> std::sync::MutexGuard<'_, eliot_kernel_service::KernelService> {
        self.service
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
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
        let Ok(state) = self.service_state() else {
            observe_health("kernel.activation.view_projected", "fenced");
            return KernelActivationView::FENCED;
        };
        let generation_bound = self
            .front_door_policy
            .lock()
            .is_ok_and(|policy| policy.module_generation.generation.value() != 0);
        let census = self.idle_lease_census();
        let Ok(coordinator) = crate::coordinator_for(&self.work_root) else {
            observe_health("kernel.activation.view_projected", "fenced");
            return KernelActivationView::FENCED;
        };
        let view = KernelActivationView {
            service_state: kernel_service_state_code(state),
            generation: if generation_bound { "bound" } else { "unbound" },
            governance: if census.supervision_is_active() {
                "independently-supervised"
            } else {
                "unsupervised"
            },
            lease_state: census.observation_code(),
            drain_disposition: coordinator.drain_disposition(),
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

    /// Projects bounded Kernel–`eliotd` live-route metrics (issue #1839, I16.5).
    ///
    /// View-only: instantaneous queue/WIP/reservation gauges read from queue
    /// memory plus cumulative lifecycle counters folded from the single #1837
    /// audit chain and the chain head cursor for event-gap observation. There
    /// is no second counter store: cumulative counters derive from durable
    /// audit records (a closed kind set, so the map stays bounded), gauges
    /// from live queue state. A lock or chain-read failure projects
    /// `unknown` for the affected section instead of zeros, so missing
    /// telemetry never reads as an idle route (I16.11). Consumed by future
    /// health dispatch wiring like [`Self::blob_capability_projection`]; the
    /// dispatch wiring itself is owned there.
    #[must_use]
    pub fn daemon_route_metrics_projection(&self) -> serde_json::Value {
        let Ok(index) = self.host_request_connection_index.lock() else {
            observe_health("kernel.health.route_metrics_projected", "fenced");
            return serde_json::json!({"status": "unknown"});
        };
        let mut queued_query = 0_u64;
        let mut queued_campaign_packet = 0_u64;
        let mut queued_observe = 0_u64;
        let mut queued_task_controller = 0_u64;
        let mut queued_finish = 0_u64;
        let mut live_claims = 0_u64;
        let mut observe_reservations = 0_u64;
        for candidate in index.values().flatten() {
            if candidate.local_read_envelope.is_some() {
                queued_query += 1;
                if candidate.local_read_attempt.is_live() {
                    live_claims += 1;
                }
            }
            if candidate.campaign_packet_envelope.is_some() {
                queued_campaign_packet += 1;
                if candidate.campaign_packet_attempt.is_live() {
                    live_claims += 1;
                }
            }
            if candidate.observe_envelope.is_some() {
                queued_observe += 1;
                if candidate.observe_attempt.is_live() {
                    live_claims += 1;
                }
            }
            if candidate.task_controller_envelope.is_some() {
                queued_task_controller += 1;
                if candidate.task_controller_attempt.is_live() {
                    live_claims += 1;
                }
            }
            if candidate.finish_envelope.is_some() {
                queued_finish += 1;
                if candidate.finish_attempt.is_live() {
                    live_claims += 1;
                }
            }
            if candidate.observe_reservation.is_some() {
                observe_reservations += 1;
            }
        }
        drop(index);
        let gauges = serde_json::json!({
            "queued_pairs": {
                "query": queued_query,
                "campaign_packet": queued_campaign_packet,
                "observe": queued_observe,
                "task_controller": queued_task_controller,
                "finish": queued_finish,
            },
            "live_claims": live_claims,
            "observe_reservations_outstanding": observe_reservations,
        });
        let (cumulative, chain, outcome) = match self.audit_chain_records() {
            Ok(records) => {
                let mut by_kind: BTreeMap<&str, u64> = BTreeMap::new();
                // Issue #1839: distinguish the raw presentation from the
                // normalized cursor advance (I16.4) so readers can observe
                // event gaps and cursor lag against the chain head.
                let mut raw_appended = 0_u64;
                let mut cursor_advanced = 0_u64;
                let mut last_cursor_advance_seq: Option<u64> = None;
                for record in &records {
                    *by_kind.entry(record.kind.as_str()).or_default() += 1;
                    if record.kind.as_str() == AuditEventKind::RESULT_NATIVE_RAW_APPENDED {
                        raw_appended += 1;
                    } else if record.kind.as_str() == AuditEventKind::RESULT_CURSOR_ADVANCED {
                        cursor_advanced += 1;
                        last_cursor_advance_seq = Some(record.seq);
                    }
                }
                let head_seq = records.last().map(|record| record.seq);
                (
                    serde_json::to_value(&by_kind).unwrap_or(serde_json::Value::Null),
                    serde_json::json!({
                        "records": records.len(),
                        "head_seq": head_seq,
                        "cursor": {
                            "raw_appended": raw_appended,
                            "cursor_advanced": cursor_advanced,
                            "last_advance_seq": last_cursor_advance_seq,
                        },
                    }),
                    "success",
                )
            }
            Err(_) => (
                serde_json::json!({"status": "unknown"}),
                serde_json::json!({"status": "unknown"}),
                "degraded",
            ),
        };
        observe_health("kernel.health.route_metrics_projected", outcome);
        serde_json::json!({
            "gauges": gauges,
            "cumulative": cumulative,
            "chain": chain,
        })
    }

    /// Projects the latest retained Diagnostic Brief (issue #1844; I16.7).
    ///
    /// View-only: serves the brief the problem owners retained while its
    /// State Fence still authorizes it, else `unknown` — a missing or
    /// invalidated brief never reads as a healthy system (I16.11). The
    /// brief carries exact references, explicit gaps, and one next step
    /// under its fence and invalidation condition (I16.14); it never
    /// carries rolling log content or an assigned cause (I16.7). Consumed
    /// by future health dispatch wiring like
    /// [`Self::daemon_route_metrics_projection`]; the dispatch wiring
    /// itself is owned there.
    #[must_use]
    pub fn diagnostic_brief_projection(&self) -> serde_json::Value {
        if let Some(brief) = self.retained_diagnostic_brief() {
            observe_health("kernel.health.diagnostic_brief_projected", "success");
            serde_json::to_value(&brief).unwrap_or(serde_json::json!({"status": "unknown"}))
        } else {
            observe_health("kernel.health.diagnostic_brief_projected", "unknown");
            serde_json::json!({"status": "unknown"})
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
