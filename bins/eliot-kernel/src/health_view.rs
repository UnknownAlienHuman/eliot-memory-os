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

/// F-LOG-KERNEL-4 (#903 slice B) health-view boundary proof: the health input
/// denominator, the omissions those inputs can carry, and the guarantee that
/// observing any of them changes no returned byte.
///
/// Byte identity is compared once observed and once unobserved on every leg
/// these compositions can reach without a live Store: all five `daemon_snapshot`
/// legs (every input present, the omitted artifact digest, the non-canonical
/// protected digest, the absent protected digest without an admitted launch, and
/// the absent protected digest with one), all four `blob_capability_projection`
/// legs (absent, standby, probed ready, degraded), both
/// `daemon_route_metrics_projection` legs (the chain-reading leg and the
/// unreadable connection-index leg), both bounded `FENCED` legs of
/// `activation_operational_view` (the unreadable lifecycle owner and the
/// unreadable drain-disposition owner), and the absent-gateway `daemon_health`
/// refusal.
///
/// Three of those five `daemon_snapshot` legs are reached by DELETING or
/// REPLACING a value in a LIVE production owner rather than by a contour
/// production itself produces, and that is a real state, but it is not a proof
/// about the writer: each proves that the view REFUSES it, never that a
/// production writer can produce it. The omitted-artifact-digest leg deletes
/// `artifact_digest` from the live policy owner, and the `missing_artifact`
/// `daemon_snapshot` arm at `:138`-`:141` is unreachable on an unmodified
/// contour, because assembly writes that key unconditionally: it is a member of
/// the `serde_json::json!` literal at `composition_bootstrap.rs:1834`-`:1842`, and
/// its value falls back to the non-empty `"eliot-kernel-standalone"` literal at
/// `:1839`-`:1841` whenever no kernel artifact hash exists, so the `:124`-`:129`
/// read resolves it on every unmodified contour. The only other production
/// rewrite of that snapshot, `generation_recovery.rs:538`-`:549`, rebuilds it
/// without the key and restores it only when the previous snapshot carried it -
/// a preservation guard, not a contour that omits it. The `missing_protected`
/// `daemon_snapshot` arm at `:148` is unreachable on an unmodified contour for
/// the neighbouring reason: assembly writes `protected_snapshot_digest` under
/// the same `if let Some(launch)` guard
/// (`composition_bootstrap.rs:1843`-`:1846`) that admits the launch
/// `daemon_launch.is_some()` tests, so the test reaches it by deleting the key
/// from the live policy owner. The third is a replacement rather than a
/// deletion: the fixture overwrites `protected_snapshot_digest` in that same
/// owner with a hand-authored `"F".repeat(64)` to reach the `invalid_protected`
/// arm at `:144`, having first restored `artifact_digest` with a hand-authored
/// `"a".repeat(64)` so the call gets past `:138`. Whether a production writer
/// can ever place a non-canonical protected digest in `config_snapshot` is NOT
/// ESTABLISHED here: this file measures only that the view refuses the
/// substituted value, while assembly copies `launch.protected_snapshot_digest`
/// verbatim (`composition_bootstrap.rs:1844`-`:1845`), so neither direction is
/// claimed. The unreadable drain-disposition leg is the fourth owner edit of
/// this kind and the only one outside the denominator: the fixture overwrites
/// the durable drain-state owner at
/// `<work_root>/.eliot/kernel-shutdown-drain.json` with a byte the production
/// decoder cannot parse (`shutdown_drain.rs:893`), after asserting that the
/// production reader itself reports the owner unreadable. None of these four
/// proves that a production writer can produce that owner state.
///
/// The fifth `daemon_snapshot` leg is an owner edit in the opposite direction,
/// and it is scoped to this denominator: `every input present` is projected from
/// `plain_composition`, which admits no launch and whose assembly therefore
/// writes no `protected_snapshot_digest`, so that leg INSERTS a hand-authored
/// `"f".repeat(64)` into the live policy owner to reach it, and the healthy
/// reading it asserts is therefore read against a fabricated value. The
/// unmodified assembled snapshot is projected separately, on a launched
/// contour with no edit at all, at `health_view.rs:1078`-`:1130`. Only the
/// benign absent protected digest without an admitted launch needs no edit to
/// reach: it is the one leg of the five whose state is exactly what that
/// contour's own assembly produces, so the counted deletions and replacements
/// are three, and every leg of the five is named here.
///
/// Two further inputs have no leg here and are NOT proved: the poisoned
/// `front_door_policy` lock, because poisoning that process-wide mutex would
/// also break every other production read on the composition - the idle lease
/// census reads it for its exact-fence leg, so the activation view could not be
/// read at all - and the two `daemon_health` arms a gateway would serve -
/// reported and unavailable, the latter covering both the poisoned
/// `canonical_store_gateway` lock and a gateway health error - because
/// `canonical_store_gateway` can only be filled by connecting a live canonical
/// Store.
///
/// Every premise reads the same PRODUCTION owners the view itself reads - the
/// `front_door_policy` config snapshot and module generation, `daemon_launch`,
/// the blob probe port, the idle lease census, the drain coordinator and the
/// `KernelService` lifecycle owner. No premise compares a value this module
/// fabricated against a projected one; the activation-state premise
/// deliberately reuses the one production `kernel_service_state_code` mapping on
/// both sides, so it pins the owner it read rather than the mapping itself. A
/// production change therefore reddens the claim instead of the fixture - except
/// where a sentence here says the opposite, which in this module is only that one
/// mapping - and every absence claim scans the whole captured surface instead of
/// a hand-listed string set.
///
/// Five of the fourteen `kernel.*` literals this file emits are asserted INLINE,
/// read out of the captured surface as the `(event, outcome)` pair the call site
/// actually passes. The pair - not the generic sink at `:30`, which cannot tell
/// two call sites of one literal apart - is what pins the row:
/// `kernel.activation.view_projected` on its readable, lifecycle-unreadable and
/// drain-owner-unreadable legs (`:267`, `:244`, `:253`);
/// `kernel.health.route_metrics_projected` on its measured and unreadable legs
/// (`:424`, `:328`); `kernel.health.blob_projected` on all four of its arms
/// (`:279`, `:287`, `:295`, `:303`); and the two `kernel.health.service_state_*`
/// literals on the legs that select between them (`:207`, `:214`). The other nine
/// literals are pinned here only through the outcome and whole-surface counts of
/// the legs above, and the boundary map's own denominator test is what freezes
/// their exact spelling; this module does not re-assert them by name.
///
/// Proof only: no event, terminal code, reservation, health derivation or
/// state/health/error algorithm is added, moved, renamed or repaired here, and
/// no returned result is changed.
#[cfg(test)]
mod health_view_diagnostics_tests {
    #![allow(
        clippy::expect_used,
        clippy::unwrap_used,
        reason = "No expect here can turn a production fault into a silent green: every one sitting directly on the production call under test reports its alternative arm as a panic instead of absorbing it, so a production fault fails its own test. The rest are harness: fixtures come from constants this delivery wrote (the canonical-UUID lineage literal, `NonZeroU64::new(1)` at its only call site, the non-empty control-free `PlatformHandle` arguments, the descriptor digest, `KernelConfig::new` over a unique temp root), so a failure there is a fixture failure, not a verdict. Every locked expect is a field of a per-test `KernelComposition` except `sink.bytes` at `:651`, a field of this module's own `CaptureSink` that only this module writes, so poisoning needs a panic inside this module. A live Store or a cross-composition mutex would turn a firing expect into the verdict under test and must be matched, not suppressed."
    )]

    use super::*;
    use std::io::Write;
    use std::sync::{Arc, Mutex};

    use crate::kernel_diagnostics::KERNEL_DIAGNOSTICS_TARGET;

    /// The exact event literal `KernelComposition::activation_operational_view`
    /// passes at `health_view.rs:244`, `:253` and `:267`.
    const ACTIVATION_VIEW_EVENT: &str = "kernel.activation.view_projected";
    /// The exact event literal the unreadable leg of
    /// `KernelComposition::service_state` passes at `health_view.rs:207`.
    const SERVICE_STATE_OMITTED_EVENT: &str = "kernel.health.service_state_omitted";
    /// The exact event literal the readable leg of
    /// `KernelComposition::service_state` passes at `health_view.rs:214`.
    const SERVICE_STATE_OBSERVED_EVENT: &str = "kernel.health.service_state_observed";
    /// The exact event literal `KernelComposition::daemon_route_metrics_projection`
    /// passes at `health_view.rs:328` and `:424`.
    const ROUTE_METRICS_EVENT: &str = "kernel.health.route_metrics_projected";
    /// The exact event literal `KernelComposition::blob_capability_projection`
    /// passes at `health_view.rs:279`, `:287`, `:295` and `:303`.
    const BLOB_PROJECTED_EVENT: &str = "kernel.health.blob_projected";

    /// Shared in-memory sink: one bounded formatter writer per leg, installed
    /// as the thread-local default so no leg competes for the process-global
    /// subscriber and each captures exactly its own surface.
    #[derive(Clone, Default)]
    struct CaptureSink {
        bytes: Arc<Mutex<Vec<u8>>>,
    }

    impl Write for CaptureSink {
        fn write(&mut self, buffer: &[u8]) -> std::io::Result<usize> {
            self.bytes
                .lock()
                .map_err(|_| std::io::Error::other("capture lock poisoned"))?
                .extend_from_slice(buffer);
            Ok(buffer.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    fn capture_with<F, R>(run: F) -> (String, R)
    where
        F: FnOnce() -> R,
    {
        let sink = CaptureSink::default();
        let writer_sink = sink.clone();
        let result = {
            let subscriber = tracing_subscriber::fmt()
                .with_ansi(false)
                .with_writer(move || writer_sink.clone())
                .finish();
            tracing::subscriber::with_default(subscriber, run)
        };
        let bytes = sink.bytes.lock().expect("capture lock").clone();
        (String::from_utf8_lossy(&bytes).into_owned(), result)
    }

    /// Scans the WHOLE captured surface and returns every value recorded under
    /// `key`, in emission order. An absence claim built on this is a scan of
    /// what production actually emitted, never a check against a hand-listed
    /// string set.
    fn captured_field_values(text: &str, key: &str) -> Vec<String> {
        let needle = format!("{key}=");
        let mut values = Vec::new();
        for line in text.lines() {
            let mut rest = line;
            while let Some(start) = rest.find(needle.as_str()) {
                let after = &rest[start + needle.len()..];
                let Some(end) = after.find('"') else {
                    break;
                };
                values.push(after[..end].to_owned());
                rest = &after[end + 1..];
            }
        }
        values
    }

    /// Pairs every `event=` with the `outcome=` recorded on the SAME captured
    /// line, in emission order, so an assertion can name the exact literal PAIR a
    /// production call site passes. The pair is what pins a row: the generic sink
    /// at `:30` cannot tell two call sites of the same event literal apart, while
    /// `(literal, outcome)` does. It reads the same captured string
    /// `captured_field_values` reads and captures nothing itself.
    fn captured_event_outcome_pairs(text: &str) -> Vec<(String, String)> {
        let mut pairs = Vec::new();
        for line in text.lines() {
            let events = captured_field_values(line, "event");
            let outcomes = captured_field_values(line, "outcome");
            for (event, outcome) in events.into_iter().zip(outcomes) {
                pairs.push((event, outcome));
            }
        }
        pairs
    }

    fn captured_health_field_keys(record: &str) -> Vec<String> {
        let bytes = record.as_bytes();
        let mut keys = Vec::new();
        for (index, byte) in bytes.iter().enumerate() {
            if *byte != b'=' || index == 0 {
                continue;
            }
            let mut start = index;
            while start > 0
                && (bytes[start - 1].is_ascii_alphanumeric() || bytes[start - 1] == b'_')
            {
                start -= 1;
            }
            if start < index {
                keys.push(record[start..index].to_owned());
            }
        }
        keys
    }

    fn assert_health_observation_sequence(text: &str, expected: &[(&str, &str)]) {
        let expected = expected
            .iter()
            .map(|(event, outcome)| ((*event).to_owned(), (*outcome).to_owned()))
            .collect::<Vec<_>>();
        for record in text.lines() {
            assert_eq!(
                captured_health_field_keys(record),
                vec!["event".to_owned(), "outcome".to_owned()],
                "a health observation carries exactly event and outcome fields: {record}"
            );
        }
        assert_eq!(
            captured_event_outcome_pairs(text),
            expected,
            "the production health call sites must emit exactly these ordered event/outcome pairs: {text}"
        );
    }

    /// Scans the WHOLE captured surface and requires that no readiness word
    /// reaches it, so an observation can never add a claim the returned view does
    /// not itself make (map row 25's noninterference claim). Of the three words,
    /// only `ready` is a production code here - it is what
    /// `kernel_service_state_code` emits for `KernelServiceState::Ready` - and
    /// `active` and `healthy` appear nowhere in this module's bounded vocabulary,
    /// so any of them on a captured surface is a fabricated claim. Every caller
    /// pairs this absence with a positive presence assertion naming the call site
    /// that must be there.
    fn assert_captured_surface_reads_no_stronger_claim(text: &str, case: &str) {
        for word in ["ready", "active", "healthy"] {
            assert!(
                !text.contains(word),
                "{case}: the captured surface must carry no readiness claim ({word}), got: {text}"
            );
        }
    }

    struct CompositionFixture {
        kernel: KernelComposition,
        root: std::path::PathBuf,
        launch: Option<EliotdLaunchDescriptor>,
    }

    impl Drop for CompositionFixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.root);
        }
    }

    fn unique_root(case: &str) -> std::path::PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0_u128, |elapsed| elapsed.as_nanos());
        std::env::temp_dir().join(format!(
            "eliot-903-health-{case}-{}-{nanos}",
            std::process::id()
        ))
    }

    fn test_epoch(sequence: u64) -> eliot_contracts::EpochId {
        eliot_contracts::EpochId::new(
            eliot_contracts::EpochLineageId::new("550e8400-e29b-41d4-a716-446655440000")
                .expect("test lineage"),
            std::num::NonZeroU64::new(sequence).expect("test sequence"),
        )
        .expect("test epoch")
    }

    /// A Host-approved `eliotd` launch contour for the composition seam that
    /// admits it. Its `protected_snapshot_digest` is the value assembly copies
    /// into the front-door config snapshot, so it is the production provenance
    /// of one health input rather than a value this module asserts against
    /// itself.
    fn test_launch_descriptor(root: &std::path::Path) -> EliotdLaunchDescriptor {
        let executable =
            eliot_platform::PlatformHandle::new(root.join("eliotd.exe").to_string_lossy())
                .expect("eliotd executable handle");
        let config = eliot_platform::PlatformHandle::new(
            root.join("eliotd-governor.json").to_string_lossy(),
        )
        .expect("eliotd config handle");
        let working_directory = eliot_platform::PlatformHandle::new(root.to_string_lossy())
            .expect("working directory handle");
        let executable_sha256 = "a".repeat(64);
        let config_sha256 = "b".repeat(64);
        let nonce = eliot_platform::PlatformHandle::new("eliotd:0123456789abcdef0123456789abcdef")
            .expect("launch nonce handle");
        EliotdLaunchDescriptor {
            wire_id: "eliot.kernel.eliotd-launch".to_owned(),
            wire_version: EliotdLaunchDescriptor::CONTRACT_VERSION,
            executable,
            executable_sha256: executable_sha256.clone(),
            arguments: vec![
                eliot_platform::PlatformHandle::new("--config-descriptor").expect("argv one"),
                config.clone(),
                eliot_platform::PlatformHandle::new("--config-descriptor-sha256")
                    .expect("argv three"),
                eliot_platform::PlatformHandle::new(config_sha256.as_str()).expect("argv four"),
                eliot_platform::PlatformHandle::new("--launch-nonce").expect("argv five"),
                nonce.clone(),
                eliot_platform::PlatformHandle::new("--executable-sha256").expect("argv seven"),
                eliot_platform::PlatformHandle::new(executable_sha256.as_str())
                    .expect("argv eight"),
            ],
            working_directory,
            config_descriptor: config,
            config_descriptor_sha256: config_sha256,
            protected_snapshot_digest: "c".repeat(64),
            launch_nonce: nonce,
            authority_epoch: test_epoch(1),
            generation: eliot_contracts::ResourceGeneration::genesis(),
            restart_policy: None,
            job_object_limits: None,
            health_readiness_contract_ref: None,
            descriptor_sha256: String::new(),
        }
        .with_computed_digest()
        .expect("canonical launch descriptor digest")
    }

    fn plain_composition(case: &str) -> CompositionFixture {
        let root = unique_root(case);
        std::fs::create_dir_all(&root).expect("test work root");
        let kernel = KernelComposition::new(KernelConfig::new(&root)).expect("kernel composition");
        CompositionFixture {
            kernel,
            root,
            launch: None,
        }
    }

    fn launch_composition(case: &str) -> CompositionFixture {
        let root = unique_root(case);
        std::fs::create_dir_all(&root).expect("test work root");
        let launch = test_launch_descriptor(&root);
        let kernel = KernelComposition::new(
            KernelConfig::new(&root)
                .with_kernel_artifact_sha256("d".repeat(64))
                .with_daemon_launch(launch.clone()),
        )
        .expect("kernel composition with an approved daemon launch");
        CompositionFixture {
            kernel,
            root,
            launch: Some(launch),
        }
    }

    fn blob_composition(case: &str) -> CompositionFixture {
        let root = unique_root(case);
        std::fs::create_dir_all(&root).expect("test work root");
        let manifest = BlobStoreManifest {
            data_root: root.join("blobs"),
            manifest_digest: "e".repeat(64),
            format_version: BLOB_MANIFEST_FORMAT_VERSION,
            inline_threshold_bytes: BLOB_INLINE_THRESHOLD_DEFAULT_BYTES,
            approved_generation: "blob-gen-approved-903".to_owned(),
        };
        let kernel = KernelComposition::new(KernelConfig::new(&root).with_blob_manifest(manifest))
            .expect("kernel composition with an approved blob manifest");
        CompositionFixture {
            kernel,
            root,
            launch: None,
        }
    }

    /// Inserts or replaces one key in the LIVE production `front_door_policy`
    /// owner that `daemon_snapshot` reads its inputs from. The edit exists
    /// because assembly writes `artifact_digest` unconditionally with a
    /// non-empty fallback literal (`composition_bootstrap.rs:1834`-`:1842`) and
    /// copies `launch.protected_snapshot_digest` verbatim
    /// (`composition_bootstrap.rs:1844`-`:1845`), so no assembly-produced
    /// composition can otherwise reach the `invalid_protected` arm.
    ///
    /// The snapshot is a JSON OBJECT by construction, and production reads it
    /// with `.get(...)` (`health_view.rs:124`-`:134`), which answers `None` for
    /// ANY non-object. A non-object snapshot is therefore a broken premise, not
    /// a case to absorb, so it FAILS LOUDLY here instead of skipping the edit.
    /// A silent skip would leave every later assertion green while the arm under
    /// test was never reached at all, which is exactly the no-op premise this
    /// helper exists to make impossible.
    fn set_policy_field(kernel: &KernelComposition, key: &str, value: serde_json::Value) {
        let mut policy = kernel
            .front_door_policy
            .lock()
            .expect("front-door policy lock");
        assert!(
            policy.config_snapshot.is_object(),
            "set_policy_field({key}) requires an object policy config snapshot, else the edit \
             could not land and the leg under test would never be reached, got: {}",
            policy.config_snapshot
        );
        policy
            .config_snapshot
            .as_object_mut()
            .expect("the object precondition is asserted immediately above")
            .insert(key.to_owned(), value);
    }

    /// Removes one key from the LIVE production `front_door_policy` owner, for
    /// the same reason `set_policy_field` inserts. Removal is the only way to
    /// reach the `missing_artifact` and `missing_protected` arms, because
    /// assembly never omits either key on its own.
    ///
    /// Every call site removes a key that assembly is expected to have written:
    /// `artifact_digest` unconditionally, and `protected_snapshot_digest`
    /// verbatim under an admitted launch. An absent key is therefore a broken
    /// premise here too, not the "may be absent" no-op `serde_json::Map::remove`
    /// would otherwise allow, so the absence is stated rather than absorbed.
    fn clear_policy_field(kernel: &KernelComposition, key: &str) {
        let mut policy = kernel
            .front_door_policy
            .lock()
            .expect("front-door policy lock");
        assert!(
            policy.config_snapshot.is_object(),
            "clear_policy_field({key}) requires an object policy config snapshot, else the removal \
             could not land and the omission leg under test would never be reached, got: {}",
            policy.config_snapshot
        );
        let removed = policy
            .config_snapshot
            .as_object_mut()
            .expect("the object precondition is asserted immediately above")
            .remove(key);
        assert!(
            removed.is_some(),
            "clear_policy_field({key}) may only remove a key this composition actually wrote; an \
             absent key would leave the omission leg reading the healthy projection instead"
        );
    }

    /// One comparable rendering of a returned snapshot result: the projected
    /// bytes on the projected leg, the error VARIANT name on a refusal leg. No
    /// owner error text or `Display` rendering takes part in the comparison.
    fn snapshot_result_bytes(result: &Result<serde_json::Value, TransportError>) -> String {
        match result {
            Ok(value) => serde_json::to_string(value).expect("the snapshot projection serializes"),
            Err(error) => format!("error:{:?}", std::mem::discriminant(error)),
        }
    }

    /// Records one leg twice - once observed, once unobserved - and requires
    /// byte-identical returned results. The captured leg must also have really
    /// recorded something, so the comparison can never be vacuously green.
    fn assert_snapshot_byte_identical(kernel: &KernelComposition, case: &str) {
        let (captured, observed) = capture_with(|| kernel.daemon_snapshot());
        assert_eq!(
            captured_field_values(&captured, "outcome").len(),
            1,
            "{case}: the observed leg must record exactly one observation, got: {captured}"
        );
        let unobserved = kernel.daemon_snapshot();
        assert_eq!(
            snapshot_result_bytes(&observed),
            snapshot_result_bytes(&unobserved),
            "{case}: the diagnostic observation must change no returned byte"
        );
    }

    /// One comparable rendering of a `daemon_health` result: the reported health
    /// serialized on a reporting leg, the error VARIANT name on a refusal leg.
    /// No owner error text and no `Display` rendering takes part, so the
    /// comparison can only ever be about which health value was returned, never
    /// about what an owner happened to say.
    fn health_result_bytes(
        result: &Result<eliot_store_api::StoreHealth, KernelServiceError>,
    ) -> String {
        match result {
            Ok(health) => format!(
                "health:{}",
                serde_json::to_string(health).expect("a reported health serializes")
            ),
            Err(error) => format!("error:{:?}", std::mem::discriminant(error)),
        }
    }

    /// Scans the WHOLE captured surface of an omission leg and requires that no
    /// value this composition really emitted on its readable leg reappears
    /// there, and that the omission is the only observation it carries. The
    /// needles are read out of the readable capture, not written by hand.
    ///
    /// Non-vacuity is settled BEFORE any absence below is evaluated, so no
    /// absence in this helper can be satisfied by a surface that carries
    /// nothing. The three positives each cover one surface the absences scan:
    /// the omission surface must really carry its one event; that one event must
    /// really carry its own outcome on the SAME captured line, which is what
    /// makes the `outcome` scan a scan of a populated surface rather than of an
    /// empty one; and the readable leg must really have recorded the measured
    /// reading the needles are read from, so neither absence loop can iterate
    /// zero times. Every absence below therefore compares one measured reading
    /// against one measured omission.
    fn assert_no_readable_reading(
        omitted_text: &str,
        readable_events: &[String],
        readable_outcomes: &[String],
        case: &str,
    ) {
        let omitted_events = captured_field_values(omitted_text, "event");
        let omitted_outcomes = captured_field_values(omitted_text, "outcome");
        assert_eq!(
            omitted_events.len(),
            1,
            "{case}: the omission must be the only observation on the captured surface, got: {omitted_text}"
        );
        assert_eq!(
            captured_event_outcome_pairs(omitted_text).len(),
            omitted_events.len(),
            "{case}: the one observed omission must record its own outcome on the same captured line, \
             or the outcome absence below would scan a surface that carries no outcome at all, got: {omitted_text}"
        );
        assert!(
            !readable_events.is_empty() && !readable_outcomes.is_empty(),
            "{case}: the needles are read out of the readable capture, so that leg must really have \
             recorded its own measured event and outcome; an unreadable readable surface would leave \
             both absence loops below comparing against nothing, got: {omitted_text}"
        );
        for event in readable_events {
            assert!(
                !omitted_events.contains(event),
                "{case}: an omitted input must not project the readable event {event}, got: {omitted_text}"
            );
        }
        for outcome in readable_outcomes {
            assert!(
                !omitted_outcomes.contains(outcome),
                "{case}: an omitted input must not reuse the readable outcome {outcome}, got: {omitted_text}"
            );
        }
    }

    /// Projects one blob capability leg and returns its captured surface, the
    /// projection the production view returned, and every outcome it recorded.
    /// Exactly one observation is required, so a leg can never be treated as
    /// evidence while it actually recorded nothing, and that non-vacuity guard
    /// runs BEFORE the byte comparison below; the whole captured surface is then
    /// required to carry exactly the `kernel.health.blob_projected` literal, so a
    /// renamed, moved or deleted event at any of the four arms
    /// (`health_view.rs:279`, `:287`, `:295`, `:303`) reddens every leg at once.
    /// Finally the same leg is re-projected once unobserved and required to
    /// serialize to the identical bytes, so the observation-only guarantee holds
    /// on EVERY leg this helper is asked about instead of on whichever leg a
    /// caller remembered.
    fn blob_projection_capture(
        kernel: &KernelComposition,
    ) -> (String, serde_json::Value, Vec<String>) {
        let (captured, projection) = capture_with(|| kernel.blob_capability_projection());
        let outcomes = captured_field_values(&captured, "outcome");
        assert_eq!(
            outcomes.len(),
            1,
            "one blob projection leg must record exactly one observation, got: {captured}"
        );
        assert_eq!(
            captured_field_values(&captured, "event"),
            vec![BLOB_PROJECTED_EVENT.to_owned()],
            "one blob projection leg must record exactly the `kernel.health.blob_projected` event, got: {captured}"
        );
        let unobserved = kernel.blob_capability_projection();
        assert_eq!(
            serde_json::to_string(&projection).expect("the projection serializes"),
            serde_json::to_string(&unobserved).expect("the projection serializes"),
            "the diagnostic observation must change no projected byte on this leg, got: {captured}"
        );
        (captured, projection, outcomes)
    }

    /// Leaves the production lifecycle owner guard poisoned so the unreadable
    /// leg is reached through the real `service_state` refusal path rather than
    /// through a substitute owner.
    fn poison_lifecycle_owner(kernel: &KernelComposition) {
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _guard = kernel.service.lock().expect("lifecycle owner guard");
            panic!("poison the lifecycle owner guard for the omission proof");
        }));
        assert!(
            outcome.is_err(),
            "the fixture must leave the lifecycle owner guard poisoned"
        );
    }

    /// Leaves this fixture's production snapshot-policy owner poisoned so
    /// `daemon_snapshot` reaches its real unreadable-lock refusal branch.
    fn poison_front_door_policy_owner(kernel: &KernelComposition) {
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _guard = kernel
                .front_door_policy
                .lock()
                .expect("front-door policy owner guard");
            panic!("poison the front-door policy owner for snapshot omission proof");
        }));
        assert!(
            outcome.is_err(),
            "the fixture must leave the front-door policy owner guard poisoned"
        );
    }

    #[cfg(windows)]
    fn poison_canonical_store_gateway_owner(kernel: &KernelComposition) {
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _guard = kernel
                .canonical_store_gateway
                .lock()
                .expect("canonical Store gateway owner guard");
            panic!("poison the canonical Store gateway owner for health refusal proof");
        }));
        assert!(
            outcome.is_err(),
            "the fixture must leave the canonical Store gateway guard poisoned"
        );
    }

    /// Leaves the production host-request connection index guard poisoned so the
    /// unreadable leg of `daemon_route_metrics_projection` is reached through the
    /// real refusal path at `health_view.rs:327`-`:330` rather than through a
    /// substitute owner. That guard is a field of THIS composition
    /// (`lib.rs:871`, initialised empty at `composition_bootstrap.rs:2230`), not a
    /// process-wide mutex, which is exactly why this leg is reachable here while
    /// the poisoned `front_door_policy` leg is not.
    fn poison_route_index_owner(kernel: &KernelComposition) {
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _guard = kernel
                .host_request_connection_index
                .lock()
                .expect("route index owner guard");
            panic!("poison the route index owner guard for the unreadable proof");
        }));
        assert!(
            outcome.is_err(),
            "the fixture must leave the route index owner guard poisoned"
        );
    }

    /// I1.10: "Health is a vector, not one boolean: ..." and, condensed from
    /// further down the same section, "A component is `READY` only for the
    /// capabilities whose required dimensions pass." I1.8: the
    /// Kernel "verifies identity, authority, State Fence, idempotency, ordering
    /// and runtime generation".
    ///
    /// Each published field is compared with the SAME production owner the view
    /// reads it from at `health_view.rs:124`-`:137` and publishes at
    /// `health_view.rs:151`-`:163`. The protected digest is traced back to the
    /// launch descriptor assembly copied it out of, so the premise is
    /// owner-against-owner rather than fixture-against-itself.
    #[test]
    fn daemon_snapshot_projects_the_exact_assembled_health_inputs() {
        let fixture = launch_composition("assembled-inputs");
        let launch = fixture.launch.as_ref().expect("approved launch descriptor");
        assert!(
            fixture.kernel.daemon_launch.is_some(),
            "the admitted launch must be retained by the composition"
        );
        let policy = fixture
            .kernel
            .front_door_policy
            .lock()
            .expect("front-door policy lock")
            .clone();
        // Assembly provenance: this key exists only because a launch was
        // admitted, and it carries that descriptor's exact protected digest.
        assert_eq!(
            policy.config_snapshot["protected_snapshot_digest"],
            serde_json::Value::String(launch.protected_snapshot_digest.clone())
        );
        let (captured, result) = capture_with(|| fixture.kernel.daemon_snapshot());
        let snapshot = result.expect("assembled snapshot");
        assert_health_observation_sequence(
            &captured,
            &[("kernel.health.snapshot_projected", "success")],
        );
        assert_eq!(
            snapshot["artifact_digest"],
            policy.config_snapshot["artifact_digest"]
        );
        assert_eq!(
            snapshot["generation"],
            serde_json::json!(policy.module_generation.generation.value())
        );
        assert_eq!(
            snapshot["authority_epoch"],
            serde_json::to_value(&policy.module_generation.state_fence.authority_epoch)
                .expect("authority epoch projection")
        );
        assert_eq!(
            snapshot["protected_snapshot_digest"],
            policy.config_snapshot["protected_snapshot_digest"]
        );
    }

    /// I1.10: "A stale graph can be alive and compatible but not fresh; it must
    /// not advertise current impact analysis." I1.10: "A component is `READY`
    /// only for the capabilities whose required dimensions pass."
    ///
    /// The input denominator of `daemon_snapshot` is enumerable from the
    /// production reads at `health_view.rs:124`-`:137` plus the admitted launch
    /// read at `health_view.rs:147`, and every leg removes exactly ONE of them
    /// from the production policy owner. Each removal is proved to be named as
    /// an OMISSION distinct from a present-and-unhealthy value and distinct
    /// from the benign absence that follows, so no omission can be read as a
    /// healthy snapshot.
    #[test]
    fn daemon_snapshot_names_every_omitted_health_input_apart_from_a_healthy_reading() {
        let readable = plain_composition("omission-denominator");
        set_policy_field(
            &readable.kernel,
            "protected_snapshot_digest",
            serde_json::Value::String("f".repeat(64)),
        );
        let (readable_text, readable_snapshot) = capture_with(|| readable.kernel.daemon_snapshot());
        readable_snapshot.expect("a fully populated policy snapshot must project");
        let readable_events = captured_field_values(&readable_text, "event");
        let readable_outcomes = captured_field_values(&readable_text, "outcome");
        assert_health_observation_sequence(
            &readable_text,
            &[("kernel.health.snapshot_projected", "success")],
        );
        assert_eq!(
            readable_outcomes,
            vec!["success".to_owned()],
            "every input present must project exactly one healthy outcome, got: {readable_text}"
        );

        // health_view.rs:138-141 - the omitted artifact digest input.
        clear_policy_field(&readable.kernel, "artifact_digest");
        let (missing_artifact_text, missing_artifact) =
            capture_with(|| readable.kernel.daemon_snapshot());
        assert!(matches!(
            missing_artifact,
            Err(TransportError::SessionFenced)
        ));
        assert_health_observation_sequence(
            &missing_artifact_text,
            &[("kernel.health.snapshot_omitted", "missing_artifact")],
        );
        assert_no_readable_reading(
            &missing_artifact_text,
            &readable_events,
            &readable_outcomes,
            "omitted artifact digest",
        );

        // health_view.rs:142-146 - a PRESENT but non-canonical protected
        // digest, which is a rejected value rather than an omitted one.
        set_policy_field(
            &readable.kernel,
            "artifact_digest",
            serde_json::Value::String("a".repeat(64)),
        );
        set_policy_field(
            &readable.kernel,
            "protected_snapshot_digest",
            serde_json::Value::String("F".repeat(64)),
        );
        let (invalid_protected_text, invalid_protected) =
            capture_with(|| readable.kernel.daemon_snapshot());
        assert!(matches!(
            invalid_protected,
            Err(TransportError::SessionFenced)
        ));
        assert_health_observation_sequence(
            &invalid_protected_text,
            &[("kernel.health.snapshot_omitted", "invalid_protected")],
        );
        assert_no_readable_reading(
            &invalid_protected_text,
            &readable_events,
            &readable_outcomes,
            "non-canonical protected digest",
        );

        // health_view.rs:147-150 - the same absent protected digest under an
        // ADMITTED daemon launch, where the omission is no longer benign.
        let launched = launch_composition("omission-missing-protected");
        assert!(launched.kernel.daemon_launch.is_some());
        clear_policy_field(&launched.kernel, "protected_snapshot_digest");
        let (missing_protected_text, missing_protected) =
            capture_with(|| launched.kernel.daemon_snapshot());
        assert!(matches!(
            missing_protected,
            Err(TransportError::SessionFenced)
        ));
        assert_health_observation_sequence(
            &missing_protected_text,
            &[("kernel.health.snapshot_omitted", "missing_protected")],
        );
        assert_no_readable_reading(
            &missing_protected_text,
            &readable_events,
            &readable_outcomes,
            "omitted protected digest under an admitted launch",
        );

        // Denominator: three omission inputs, three distinct names, none of
        // which reuses the healthy outcome.
        let mut omissions = captured_field_values(&missing_artifact_text, "outcome");
        omissions.extend(captured_field_values(&invalid_protected_text, "outcome"));
        omissions.extend(captured_field_values(&missing_protected_text, "outcome"));
        assert_eq!(
            omissions.len(),
            3,
            "each omitted or rejected input must be named exactly once by its own production arm (`health_view.rs:139`, `:144`, `:148`), got: {omissions:?}"
        );
        for outcome in &omissions {
            assert!(
                !readable_outcomes.contains(outcome),
                "an omission must never reuse the healthy outcome, got: {omissions:?}"
            );
        }
        let mut distinct = omissions.clone();
        distinct.sort_unstable();
        distinct.dedup();
        assert_eq!(
            distinct.len(),
            omissions.len(),
            "each omission must carry a distinct name, got: {omissions:?}"
        );
    }

    /// I1.10: "A component is `READY` only for the capabilities whose required
    /// dimensions pass."
    ///
    /// `health_view.rs:147` makes the absent protected digest benign only while
    /// no daemon launch was admitted, and `health_view.rs:160`-`:163` then
    /// publishes the snapshot WITHOUT fabricating the omitted key. The same
    /// omission on the same production policy owner is therefore a stated
    /// absence here and a refusal under an admitted launch, and neither reading
    /// may claim an input the evidence does not carry.
    #[test]
    fn daemon_snapshot_absent_protected_digest_stays_a_stated_absence_without_an_admitted_launch() {
        let fixture = plain_composition("benign-absence");
        assert!(
            fixture.kernel.daemon_launch.is_none(),
            "no launch may be admitted on this contour"
        );
        set_policy_field(
            &fixture.kernel,
            "protected_snapshot_digest",
            serde_json::Value::String("f".repeat(64)),
        );
        let (readable_text, _) = capture_with(|| fixture.kernel.daemon_snapshot());
        let readable_outcomes = captured_field_values(&readable_text, "outcome");
        assert_health_observation_sequence(
            &readable_text,
            &[("kernel.health.snapshot_projected", "success")],
        );
        assert_eq!(
            readable_outcomes,
            vec!["success".to_owned()],
            "every input present must project exactly one healthy outcome, so the outcome comparison below cannot hold with both sides empty, got: {readable_text}"
        );

        clear_policy_field(&fixture.kernel, "protected_snapshot_digest");
        let (benign_text, benign_snapshot) = capture_with(|| fixture.kernel.daemon_snapshot());
        assert_health_observation_sequence(
            &benign_text,
            &[("kernel.health.snapshot_projected", "success")],
        );
        let benign_snapshot =
            benign_snapshot.expect("an absent protected digest without a launch stays projectable");
        assert_eq!(
            benign_snapshot["service"],
            serde_json::Value::String(SERVICE_NAME.to_owned()),
            "the absence below is read off a document production always populates: `health_view.rs:151`-`:159` writes `service` on the single Ok arm, independently of the protected digest, so this surface is populated, got: {benign_snapshot}"
        );
        assert!(
            benign_snapshot.get("protected_snapshot_digest").is_none(),
            "an omitted input must not be projected, and `health_view.rs:160`-`:163` publish that key only under `if let Some`, got: {benign_snapshot}"
        );
        assert_eq!(
            captured_field_values(&benign_text, "outcome"),
            readable_outcomes,
            "the benign absence keeps the readable outcome, got: {benign_text}"
        );
    }

    /// Card `MAKE`: "health input denominator and omissions from actual evidence
    /// while health algorithm results stay byte-identical."
    ///
    /// Every leg of the denominator is projected once observed and once
    /// unobserved and the returned bytes must match exactly - the projected JSON
    /// bytes on a projected leg, the error variant on a refusal leg. All five
    /// legs are compared here: every input present, the omitted artifact digest,
    /// the non-canonical protected digest, the absent protected digest on a
    /// contour with no admitted launch, and the same absence under an admitted
    /// launch, which needs its own composition because the two contours differ.
    /// A mutation that made the observation alter any verdict, state value or
    /// error value reddens here, and each observed leg is required to have
    /// recorded exactly one observation so the comparison cannot pass vacuously.
    #[test]
    fn daemon_snapshot_result_is_byte_identical_with_and_without_the_diagnostic_observation() {
        let fixture = plain_composition("snapshot-byte-identity");
        set_policy_field(
            &fixture.kernel,
            "protected_snapshot_digest",
            serde_json::Value::String("f".repeat(64)),
        );
        assert_snapshot_byte_identical(&fixture.kernel, "every input present");
        clear_policy_field(&fixture.kernel, "artifact_digest");
        assert_snapshot_byte_identical(&fixture.kernel, "omitted artifact digest");
        set_policy_field(
            &fixture.kernel,
            "artifact_digest",
            serde_json::Value::String("a".repeat(64)),
        );
        set_policy_field(
            &fixture.kernel,
            "protected_snapshot_digest",
            serde_json::Value::String("F".repeat(64)),
        );
        assert_snapshot_byte_identical(&fixture.kernel, "non-canonical protected digest");
        clear_policy_field(&fixture.kernel, "protected_snapshot_digest");
        assert_snapshot_byte_identical(&fixture.kernel, "benign absent protected digest");

        let launched = launch_composition("snapshot-byte-identity-launched");
        assert!(
            launched.kernel.daemon_launch.is_some(),
            "this leg exists only under an admitted launch"
        );
        clear_policy_field(&launched.kernel, "protected_snapshot_digest");
        assert_snapshot_byte_identical(
            &launched.kernel,
            "absent protected digest under an admitted launch",
        );
    }

    #[test]
    fn unreadable_front_door_policy_records_fenced_snapshot_omission() {
        let fixture = plain_composition("snapshot-policy-omission");
        set_policy_field(
            &fixture.kernel,
            "protected_snapshot_digest",
            serde_json::Value::String("f".repeat(64)),
        );
        let (readable_text, readable) = capture_with(|| fixture.kernel.daemon_snapshot());
        assert!(readable.is_ok(), "the live policy owner starts readable");
        assert_health_observation_sequence(
            &readable_text,
            &[("kernel.health.snapshot_projected", "success")],
        );

        poison_front_door_policy_owner(&fixture.kernel);

        let (captured, omitted) = capture_with(|| fixture.kernel.daemon_snapshot());
        assert!(
            matches!(omitted.as_ref(), Err(TransportError::SessionFenced)),
            "an unreadable policy owner must keep the typed snapshot refusal: {omitted:?}"
        );
        assert_health_observation_sequence(
            &captured,
            &[("kernel.health.snapshot_omitted", "fenced")],
        );
        let unobserved = fixture.kernel.daemon_snapshot();
        assert!(matches!(
            unobserved.as_ref(),
            Err(TransportError::SessionFenced)
        ));
        assert_eq!(
            snapshot_result_bytes(&omitted),
            snapshot_result_bytes(&unobserved),
            "the observation must not alter the unreadable owner's typed snapshot result"
        );
    }

    /// I1.10: "A component is `READY` only for the capabilities whose required
    /// dimensions pass." I1.10, condensed from one paragraph with two sentences
    /// elided: "`ServiceProcessState` describes one running process ... the two
    /// state spaces are never merged into one enum, ..."
    ///
    /// All five bounded codes of `activation_operational_view` are compared with
    /// the exact production sources `health_view.rs:243`-`:265` reads them from:
    /// the lifecycle owner, the admitted module generation, the idle lease
    /// census and the drain coordinator over this composition's own work root.
    /// That pins the OWNER each field was read from. It does NOT pin the
    /// `service_state` vocabulary: both sides call the one production
    /// `kernel_service_state_code` mapping (`health_view.rs:74`-`:88`), so a
    /// change to that mapping would move both sides together and redden nothing
    /// here. For the other four codes the expectations are derived in this test
    /// from the owner read rather than through a production mapping, so a copied
    /// or fabricated vocabulary there does redden.
    #[test]
    fn activation_operational_view_matches_every_production_source() {
        let fixture = plain_composition("activation-sources");
        let view = fixture.kernel.activation_operational_view();
        let state = fixture.kernel.service_state().expect("lifecycle state");
        assert_eq!(view.service_state, kernel_service_state_code(state));
        let generation_bound = fixture
            .kernel
            .front_door_policy
            .lock()
            .expect("front-door policy lock")
            .module_generation
            .generation
            .value()
            != 0;
        assert_eq!(
            view.generation,
            if generation_bound { "bound" } else { "unbound" }
        );
        let census = fixture.kernel.idle_lease_census();
        assert_eq!(view.lease_state, census.observation_code());
        assert_eq!(
            view.governance,
            if census.supervision_is_active() {
                "independently-supervised"
            } else {
                "unsupervised"
            }
        );
        let coordinator =
            crate::coordinator_for(&fixture.kernel.work_root).expect("drain disposition owner");
        assert_eq!(view.drain_disposition, coordinator.drain_disposition());
        assert_ne!(
            view,
            KernelActivationView::FENCED,
            "a fully readable composition must not project the total-failure disposition"
        );
    }

    /// Map row 6 (`WORK_UNIT_CASE 903/6`): span
    /// `kernel.activation.view_projected` on
    /// `KernelComposition::activation_operational_view`, stage
    /// `activation_observation`. I1.10, condensed from the one sentence it
    /// opens: "Health is a vector, not one boolean". I1.10: "A component is
    /// `READY` only for the capabilities whose required dimensions pass."
    ///
    /// Pins the CALL SITE `health_view.rs:267`, which passes `view.lease_state`
    /// - the very field the view reads from the idle lease census at `:264` -
    ///   and not the generic sink at `:30`: the assertion is on the `(event,
    ///   outcome)` pair the call site actually passes, so a renamed event, a
    ///   changed outcome, or a census that stops feeding that outcome all
    ///   redden here. The absence is paired with it: the whole captured
    ///   surface of this leg carries no readiness word, so the observation may
    ///   never add a claim the returned view does not itself make.
    #[test]
    fn activation_operational_view_records_its_own_projection_event_with_the_returned_lease_state()
    {
        let fixture = plain_composition("activation-event");
        let (captured, observed) = capture_with(|| fixture.kernel.activation_operational_view());
        let pairs = captured_event_outcome_pairs(&captured);
        assert_eq!(
            pairs
                .iter()
                .filter(|(event, outcome)| {
                    event == ACTIVATION_VIEW_EVENT && *outcome == observed.lease_state
                })
                .count(),
            1,
            "health_view.rs:267 must record the projection event exactly once, with the returned view's own lease-state code, got: {captured}"
        );
        assert_eq!(
            pairs
                .iter()
                .filter(|(event, _)| event == ACTIVATION_VIEW_EVENT)
                .count(),
            1,
            "a readable activation leg must project its view exactly once, got: {captured}"
        );
        assert_captured_surface_reads_no_stronger_claim(&captured, "the readable activation leg");
        let unobserved = fixture.kernel.activation_operational_view();
        assert_eq!(
            observed, unobserved,
            "the diagnostic observation must change no returned field of the activation view"
        );
    }

    /// Map row 25 (`WORK_UNIT_CASE 903/25`): span
    /// `kernel.activation.view_projected` against the closed fallback
    /// `KernelActivationView::FENCED` (`health_view.rs:64`-`:70`), stage
    /// `health_derivation`, noninterference "no missing, stale or unknown input
    /// may be reported as a stronger readiness or health claim than the supplied
    /// evidence supports". I1.10: "A component is `READY` only for the
    /// capabilities whose required dimensions pass." I14.24 for a Kernel
    /// failure: "separate canonical-store branch, Watchdog and platform recovery
    /// surface remain where observed" - a bounded disposition, never a stronger
    /// claim than the evidence.
    ///
    /// An unreadable lifecycle owner is named as an OMISSION at
    /// `health_view.rs:206`-`:211` and collapses to the single bounded
    /// `KernelActivationView::FENCED` answer at `health_view.rs:243`-`:246`. The
    /// event literal is pinned at the CALL SITE that fires it, `:244`, by the
    /// `(kernel.activation.view_projected, fenced)` pair, and the inner refusal
    /// that selects that arm is pinned by its own pair at `:207`; neither claim
    /// would follow from naming the sink at `:30`, which both FENCED arms share.
    /// The same composition's readable reading is captured first, so the absence
    /// scan is a comparison against what production really emitted rather than
    /// a hand-listed string set.
    #[test]
    fn unreadable_lifecycle_input_projects_the_bounded_total_disposition() {
        let fixture = plain_composition("activation-omission");
        let baseline = fixture.kernel.activation_operational_view();
        assert_ne!(
            baseline,
            KernelActivationView::FENCED,
            "the baseline reading must be a real projection"
        );
        let (baseline_text, _) = capture_with(|| fixture.kernel.activation_operational_view());
        let baseline_outcomes = captured_field_values(&baseline_text, "outcome");
        assert_eq!(
            captured_event_outcome_pairs(&baseline_text)
                .iter()
                .filter(|(event, outcome)| {
                    event == ACTIVATION_VIEW_EVENT && *outcome == baseline.lease_state
                })
                .count(),
            1,
            "health_view.rs:267 must record the readable projection event exactly once, with the returned view's own lease-state code, got: {baseline_text}"
        );
        assert_captured_surface_reads_no_stronger_claim(&baseline_text, "the readable leg");

        poison_lifecycle_owner(&fixture.kernel);

        let (omitted_capture, omitted_lifecycle) = capture_with(|| fixture.kernel.service_state());
        assert_health_observation_sequence(
            &omitted_capture,
            &[(SERVICE_STATE_OMITTED_EVENT, "fenced")],
        );
        let omitted_reason = match &omitted_lifecycle {
            Err(KernelServiceError::Platform(reason)) => reason.as_str(),
            other => panic!("an unreadable lifecycle owner must stay a typed refusal: {other:?}"),
        };
        assert_eq!(
            omitted_reason, "service lock poisoned",
            "the exact owner-lock refusal is part of the typed result"
        );
        let omitted_outcomes = captured_field_values(&omitted_capture, "outcome");
        assert_eq!(
            omitted_outcomes.len(),
            1,
            "the omission must be the only observation, got: {omitted_capture}"
        );
        assert_eq!(
            captured_event_outcome_pairs(&omitted_capture),
            vec![(SERVICE_STATE_OMITTED_EVENT.to_owned(), "fenced".to_owned())],
            "health_view.rs:207 must record the lifecycle omission exactly once, got: {omitted_capture}"
        );
        for outcome in &baseline_outcomes {
            assert!(
                !omitted_outcomes.contains(outcome),
                "an omitted lifecycle input must not reuse the readable outcome {outcome}, got: {omitted_capture}"
            );
        }
        let unobserved_lifecycle = fixture.kernel.service_state();
        let unobserved_reason = match unobserved_lifecycle {
            Err(KernelServiceError::Platform(reason)) => reason,
            other => panic!("the poisoned owner remains a typed refusal: {other:?}"),
        };
        assert_eq!(
            omitted_reason,
            unobserved_reason.as_str(),
            "the observation must not alter the unreadable owner's service-state result"
        );

        let (total_text, total) = capture_with(|| fixture.kernel.activation_operational_view());
        assert_eq!(
            total,
            KernelActivationView::FENCED,
            "an omitted lifecycle input must project the one bounded total disposition, got: {total_text}"
        );
        assert_ne!(
            total, baseline,
            "the total disposition must not repeat the readable reading"
        );
        assert_eq!(
            captured_event_outcome_pairs(&total_text)
                .iter()
                .filter(|(event, outcome)| {
                    event == ACTIVATION_VIEW_EVENT && outcome == "fenced"
                })
                .count(),
            1,
            "health_view.rs:244 must record the bounded-fallback event exactly once for the unreadable lifecycle owner, got: {total_text}"
        );
        assert_captured_surface_reads_no_stronger_claim(&total_text, "the fenced leg");
        let total_unobserved = fixture.kernel.activation_operational_view();
        assert_eq!(
            total, total_unobserved,
            "the diagnostic observation must change no returned field of the bounded fallback"
        );
    }

    /// Map row 25's second `FENCED` arm: the same span
    /// `kernel.activation.view_projected`, fired from `health_view.rs:253`
    /// because the drain-disposition owner could not be read at `:252`. I1.10:
    /// "A component is `READY` only for the capabilities whose required
    /// dimensions pass." I14.24: "read-only inspection and independent
    /// noncanonical work where honest" - an unprovable owner read is not
    /// evidence that the installation is idle.
    ///
    /// The discriminating assertion is the `(kernel.health.service_state_observed,
    /// success)` pair from `:214`: the lifecycle read SUCCEEDED on this leg, so
    /// the `:243` arm cannot have fired and the fenced projection must have come
    /// from the drain-owner read alone. That is what separates the two `FENCED`
    /// arms - a row that named only the event literal could not tell them apart.
    ///
    /// Disclosure: the premise is a real production owner state, not a substitute
    /// one, but it is not one production writes. The fixture overwrites the
    /// durable drain-state file `<work_root>/.eliot/kernel-shutdown-drain.json`
    /// (the path `shutdown_drain.rs:862` builds from the private
    /// `DRAIN_STATE_FILE` at `shutdown_drain.rs:95`) with a byte the production
    /// decoder rejects at `shutdown_drain.rs:893`, and it first requires the
    /// production reader itself to report the owner unreadable. Deleting a key
    /// from a live owner, as the `missing_protected` leg does, is the same
    /// discipline; hand-authoring a corrupt durable state file is not, so this
    /// leg proves the refusal, never that a writer can produce that file.
    #[test]
    fn unreadable_drain_disposition_owner_also_collapses_to_the_bounded_total_disposition() {
        let fixture = plain_composition("activation-drain-owner-omission");
        // The `:252` arm is only reachable when the `:243` arm did NOT fire, so
        // the lifecycle owner must read cleanly here. The pair asserted below
        // re-proves that on the captured surface rather than trusting this read.
        fixture
            .kernel
            .service_state()
            .expect("the lifecycle owner must be readable on this leg");

        let drain_state = fixture
            .kernel
            .work_root
            .join(".eliot")
            .join("kernel-shutdown-drain.json");
        std::fs::create_dir_all(
            drain_state
                .parent()
                .expect("the drain-state owner directory"),
        )
        .expect("drain-state owner directory");
        std::fs::write(&drain_state, b"{").expect("overwrite the durable drain-state owner");
        assert!(
            crate::coordinator_for(&fixture.kernel.work_root).is_err(),
            "the production drain-disposition reader must report the durable owner unreadable, or this leg proves nothing"
        );

        let (captured, view) = capture_with(|| fixture.kernel.activation_operational_view());
        assert_eq!(
            view,
            KernelActivationView::FENCED,
            "an unreadable drain-disposition owner must project the one bounded total disposition, got: {captured}"
        );
        let pairs = captured_event_outcome_pairs(&captured);
        assert_eq!(
            pairs
                .iter()
                .filter(|(event, outcome)| {
                    event == SERVICE_STATE_OBSERVED_EVENT && outcome == "success"
                })
                .count(),
            1,
            "health_view.rs:214 must record the readable lifecycle reading on this leg, so the fenced arm is not the :243 one, got: {captured}"
        );
        assert_eq!(
            pairs
                .iter()
                .filter(|(event, outcome)| {
                    event == ACTIVATION_VIEW_EVENT && outcome == "fenced"
                })
                .count(),
            1,
            "health_view.rs:253 must record the bounded-fallback event exactly once for the unreadable drain owner, got: {captured}"
        );
        assert_captured_surface_reads_no_stronger_claim(&captured, "the fenced drain-owner leg");
        let unobserved = fixture.kernel.activation_operational_view();
        assert_eq!(
            view, unobserved,
            "the diagnostic observation must change no returned field of the bounded fallback"
        );
    }

    /// I1.10: "A component is `READY` only for the capabilities whose required
    /// dimensions pass." I1.10, elided at its end: the third sentence of the
    /// final paragraph, "A process may be alive/READY while its generation is
    /// only STAGED or DEGRADED; the two state spaces are never merged into one
    /// enum". I14.24 for an unavailable Blob Store: "reject/limit large capture;
    /// do not create dangling canonical success" while "small inline operations
    /// may continue".
    ///
    /// The degraded component is driven through the production demand seam and
    /// read back from the production probe port; the whole-Kernel verdict is
    /// read from the production lifecycle owner. Neither reading may move
    /// because the other did, which is what separates component degradation
    /// from total Kernel failure.
    ///
    /// The before/after baseline is whatever `KernelService::new` starts at -
    /// `KernelServiceState::Cold` - and NOT a live `Ready` Kernel. A `Ready`
    /// baseline is not reachable here without hand-building a
    /// `KernelReadyReceipt` and its activation receipt, which is fabricated
    /// readiness, so the claim is the weaker but true one: this comparison shows
    /// the degraded component moves neither the lifecycle state nor the
    /// activation verdict away from whatever the composition legitimately holds,
    /// and `KernelActivationView::FENCED` is refused independently of that
    /// baseline.
    #[test]
    fn component_degradation_does_not_render_as_whole_kernel_failure() {
        let fixture = blob_composition("component-degradation");
        let state_before = fixture.kernel.service_state().expect("lifecycle state");
        let view_before = fixture.kernel.activation_operational_view();

        fixture
            .kernel
            .demand_blob_store(BlobDemand::NonInlineCapture, || {
                Err("blob probe transport unavailable".to_owned())
            })
            .expect("a failed probe records a degraded component, not a Kernel failure");
        assert!(matches!(
            fixture.kernel.blob_probe_status(),
            Some(BlobProbeStatus::Degraded { .. })
        ));

        let (degraded_text, projection) =
            capture_with(|| fixture.kernel.blob_capability_projection());
        assert_eq!(
            projection
                .get("large_payload")
                .and_then(serde_json::Value::as_str),
            Some("degraded"),
            "the degraded component must be published as degraded, got: {degraded_text}"
        );
        assert_eq!(
            projection
                .get("process")
                .and_then(serde_json::Value::as_str),
            Some("started"),
            "an attempted probe must stay visible as started, got: {degraded_text}"
        );

        let state_after = fixture.kernel.service_state().expect("lifecycle state");
        let view_after = fixture.kernel.activation_operational_view();
        assert_eq!(
            state_after, state_before,
            "a degraded component must not move the Kernel lifecycle state"
        );
        assert_eq!(
            view_after, view_before,
            "a degraded component must not move the activation verdict"
        );
        assert_eq!(
            view_after.service_state,
            kernel_service_state_code(state_after)
        );
        assert_ne!(
            view_after,
            KernelActivationView::FENCED,
            "a degraded component is not a total Kernel failure"
        );
    }

    /// Map row 26 (`WORK_UNIT_CASE 903/26`): span
    /// `kernel.health.blob_projected` on
    /// `KernelComposition::blob_capability_projection`, stage
    /// `component_health`. I1.10: "A stale graph can be alive and compatible
    /// but not fresh; it must not advertise current impact analysis." I14.24 for
    /// a store bridge crash: "stop canonical operations ... cached
    /// reads/independent modules where honest".
    ///
    /// The port is the production `blob_probe_status` seam and the projection is
    /// the production `blob_capability_projection` (`health_view.rs:276`). The two
    /// states that carry no proven readiness - no approved manifest at all, and a
    /// validated manifest whose process was never started - must each be named
    /// from the port's own reading, so an omitted or unstarted component can
    /// never be logged or published as a ready capability. This test pins the two
    /// CALL SITES those legs emit from, `:279` for the absent arm and `:287` for
    /// the standby arm: `blob_projection_capture` requires the whole captured
    /// surface to carry exactly the event literal, and each leg's own exact
    /// `outcome` names which of the two arms fired. Both legs are also compared
    /// observed against unobserved by `blob_projection_capture`.
    #[test]
    fn blob_capability_projection_names_the_omitted_and_unstarted_states_from_the_port() {
        let absent = plain_composition("blob-absent");
        assert_eq!(absent.kernel.blob_probe_status(), None);
        let (absent_text, absent_projection, absent_outcomes) =
            blob_projection_capture(&absent.kernel);
        assert_eq!(
            absent_projection
                .get("manifest")
                .and_then(serde_json::Value::as_str),
            Some("absent"),
            "an omitted manifest must never be published as validated, and `health_view.rs:281` is the value an omission is published under, got: {absent_text}"
        );
        assert_eq!(
            absent_outcomes,
            vec!["absent".to_owned()],
            "an omitted manifest must be named as an omission, got: {absent_text}"
        );

        let standby = blob_composition("blob-standby");
        assert_eq!(
            standby.kernel.blob_probe_status(),
            Some(BlobProbeStatus::ManifestValidated)
        );
        let (standby_text, standby_projection, standby_outcomes) =
            blob_projection_capture(&standby.kernel);
        assert_eq!(
            standby_projection
                .get("manifest")
                .and_then(serde_json::Value::as_str),
            Some("validated")
        );
        assert_eq!(
            standby_projection
                .get("process")
                .and_then(serde_json::Value::as_str),
            Some("not_started"),
            "an unstarted generation must not be published as started, and `health_view.rs:290` is the value it is published under, got: {standby_text}"
        );
        assert_eq!(
            standby_outcomes,
            vec!["standby".to_owned()],
            "a validated but unstarted generation must be named standby, got: {standby_text}"
        );
    }

    /// Map row 26's second pair of arms: span `kernel.health.blob_projected`
    /// again, this time from `health_view.rs:295` (probed ready) and `:303`
    /// (degraded). I1.10: "A component is `READY` only for the capabilities whose
    /// required dimensions pass." I1.10: "A stale graph can be alive and
    /// compatible but not fresh; it must not advertise current impact analysis."
    ///
    /// The probed-ready leg is driven through the production demand seam and read
    /// back from the production probe port; the degraded leg is driven by a
    /// failed probe over the same seam. Only the state that really probed Ready
    /// may record the ready outcome, and both legs are compared here as observed
    /// against unobserved bytes; `blob_projection_capture` performs that
    /// comparison for every leg it is handed, so the absent and standby legs of
    /// the sibling test are covered by it too.
    #[test]
    fn blob_capability_projection_names_the_probed_and_degraded_states_only_from_the_port() {
        let ready = blob_composition("blob-ready");
        ready
            .kernel
            .demand_blob_store(BlobDemand::NonInlineCapture, || {
                Ok(BlobProbeSuccess {
                    generation: "blob-gen-approved-903".to_owned(),
                    integrity_digest: "b".repeat(64),
                })
            })
            .expect("the approved generation must record its probe outcome");
        assert!(matches!(
            ready.kernel.blob_probe_status(),
            Some(BlobProbeStatus::Ready { .. })
        ));
        let (ready_text, ready_projection, ready_outcomes) = blob_projection_capture(&ready.kernel);
        assert_eq!(
            ready_outcomes,
            vec!["ready".to_owned()],
            "the only probed-ready state must be named ready, got: {ready_text}"
        );
        assert_eq!(
            ready_projection
                .get("manifest")
                .and_then(serde_json::Value::as_str),
            Some("validated"),
            "a probed manifest must be published as validated, got: {ready_text}"
        );
        assert_eq!(
            ready_projection
                .get("process")
                .and_then(serde_json::Value::as_str),
            Some("started"),
            "a probed process must be published as started, got: {ready_text}"
        );
        assert_eq!(
            ready_projection
                .get("large_payload")
                .and_then(serde_json::Value::as_str),
            Some("ready"),
            "the probed component must be published as ready, got: {ready_text}"
        );

        let degraded = blob_composition("blob-degraded");
        degraded
            .kernel
            .demand_blob_store(BlobDemand::Recovery, || {
                Err("blob probe transport unavailable".to_owned())
            })
            .expect("a failed probe records a degraded component");
        assert!(matches!(
            degraded.kernel.blob_probe_status(),
            Some(BlobProbeStatus::Degraded { .. })
        ));
        let (degraded_text, degraded_projection, degraded_outcomes) =
            blob_projection_capture(&degraded.kernel);
        assert_eq!(
            degraded_outcomes,
            vec!["degraded".to_owned()],
            "a degraded component must be named degraded, got: {degraded_text}"
        );
        assert_eq!(
            degraded_projection
                .get("process")
                .and_then(serde_json::Value::as_str),
            Some("started"),
            "an attempted probe must stay visible as started, got: {degraded_text}"
        );
        assert!(
            !degraded_outcomes.contains(&ready_outcomes[0]),
            "a degraded component must never record the probed-ready outcome, got: {degraded_outcomes:?}"
        );
    }

    /// I1.10: "A component is `READY` only for the capabilities whose required
    /// dimensions pass." I14.24 for a store bridge crash: "stop canonical
    /// operations ... cached reads/independent modules where honest."
    ///
    /// With no admitted Store gateway the component is ABSENT, so
    /// `daemon_health` (`health_view.rs:169`-`:202`) must return the typed
    /// refusal and record the reading as unknown. No health value exists on this
    /// leg at all, so the diagnostic cannot be claiming a health it does not
    /// have. The leg is then read a second time unobserved and the returned
    /// bytes must match, which is the health-axis instance of "health algorithm
    /// results stay byte-identical"; this is the only `daemon_health` leg a
    /// fixture can reach, because `canonical_store_gateway` is filled only by
    /// connecting a live canonical Store, so the reported and unavailable arms
    /// stay unproved here. The absent-gateway arm is the one case both cfg
    /// targets answer identically - the non-Windows build is this same refusal
    /// without the lock - so the comparison is not target-specific.
    #[test]
    fn absent_store_component_projects_a_typed_refusal_and_no_health_value() {
        let fixture = plain_composition("store-absent");
        let runtime = tokio::runtime::Builder::new_current_thread()
            .build()
            .expect("single-threaded test runtime");
        let (captured, result) = capture_with(|| runtime.block_on(fixture.kernel.daemon_health()));
        let error = result
            .as_ref()
            .expect_err("an absent Store gateway must refuse");
        assert!(
            matches!(error, KernelServiceError::ReadinessNotProven),
            "an absent Store gateway must stay ReadinessNotProven, the refusal sites being `health_view.rs:182` and `:201`, got: {error:?}"
        );
        assert_eq!(
            captured_field_values(&captured, "outcome"),
            vec!["unknown".to_owned()],
            "an unobserved Store health reading must be recorded as unknown, got: {captured}"
        );
        assert_health_observation_sequence(
            &captured,
            &[("kernel.health.store_absent", "unknown")],
        );
        assert_eq!(
            captured_field_values(&captured, "event").len(),
            1,
            "the absence must be the only observation on the captured surface, and it is the `store_absent` at `health_view.rs:181` (`:200` off Windows), got: {captured}"
        );
        assert!(
            captured.contains(KERNEL_DIAGNOSTICS_TARGET),
            "the observation must flow through the one facade, got: {captured}"
        );

        let unobserved = runtime.block_on(fixture.kernel.daemon_health());
        assert_eq!(
            health_result_bytes(&result),
            health_result_bytes(&unobserved),
            "the diagnostic observation must change no returned byte of the Store health result"
        );
    }

    #[test]
    #[cfg(windows)]
    fn unreadable_store_gateway_records_fenced_typed_health_refusal() {
        let fixture = plain_composition("store-gateway-fenced");
        assert!(
            fixture
                .kernel
                .canonical_store_gateway
                .lock()
                .expect("fixture Store gateway owner guard")
                .is_none(),
            "the fresh composition has no admitted Store gateway"
        );
        poison_canonical_store_gateway_owner(&fixture.kernel);

        let runtime = tokio::runtime::Builder::new_current_thread()
            .build()
            .expect("single-threaded test runtime");
        let (captured, observed) =
            capture_with(|| runtime.block_on(fixture.kernel.daemon_health()));
        let observed_reason = match &observed {
            Err(KernelServiceError::Platform(reason)) => reason.as_str(),
            other => panic!("an unreadable Store gateway must stay a typed refusal: {other:?}"),
        };
        assert_eq!(observed_reason, "store gateway lock poisoned");
        assert_health_observation_sequence(
            &captured,
            &[("kernel.health.store_unavailable", "fenced")],
        );

        let unobserved = runtime.block_on(fixture.kernel.daemon_health());
        let unobserved_reason = match &unobserved {
            Err(KernelServiceError::Platform(reason)) => reason.as_str(),
            other => panic!("the poisoned Store gateway remains a typed refusal: {other:?}"),
        };
        assert_eq!(
            observed_reason,
            unobserved_reason,
            "the observation must not alter the unreadable Store owner's result"
        );
        assert_eq!(
            health_result_bytes(&observed),
            health_result_bytes(&unobserved),
            "the observed and repeated typed Store failures must remain byte-equivalent"
        );
    }

    #[test]
    fn health_response_projects_the_typed_store_value_and_records_known() {
        let health = StoreHealth {
            status: StoreHealthStatus::Degraded,
            contract_version: eliot_store_api::CONTRACT_VERSION,
            manifest_digest: eliot_store_api::OperationManifestDigest::new("a".repeat(64))
                .expect("manifest digest"),
        };
        let health_value = serde_json::to_value(&health).expect("typed health serializes");
        let expected = serde_json::json!({
            "status": "known",
            "value": {"kind": "health", "value": health_value},
            "recovery": null,
        });

        let (captured, response) =
            capture_with(|| KernelComposition::daemon_health_response(&health));
        assert_health_observation_sequence(
            &captured,
            &[("kernel.health.response_projected", "known")],
        );
        assert_eq!(response, expected);
        assert_eq!(
            response,
            KernelComposition::daemon_health_response(&health),
            "the diagnostic observation must not alter the projected response"
        );
        assert_eq!(
            serde_json::to_value(&health).expect("typed health remains serializable"),
            expected["value"]["value"],
            "projection must not mutate the owner-supplied Store health"
        );
    }

    #[test]
    fn missing_diagnostic_brief_projects_unknown_and_records_unknown() {
        let fixture = plain_composition("brief-unknown");
        assert!(
            fixture.kernel.retained_diagnostic_brief().is_none(),
            "a fresh composition owns no retained brief to project"
        );

        let (captured, projection) =
            capture_with(|| fixture.kernel.diagnostic_brief_projection());
        assert_health_observation_sequence(
            &captured,
            &[("kernel.health.diagnostic_brief_projected", "unknown")],
        );
        assert_eq!(projection, serde_json::json!({"status": "unknown"}));
        assert_eq!(
            projection,
            fixture.kernel.diagnostic_brief_projection(),
            "the observation must not alter the missing-brief projection"
        );
    }

    #[test]
    fn recovery_view_response_projects_only_its_four_fields_and_records_known() {
        let view = RecoveryView::new(
            serde_json::json!({"artifact_digest": "a".repeat(64)}),
            serde_json::json!({"generation": 3, "authority_epoch": "epoch-canary"}),
            serde_json::json!({"status": "degraded"}),
            serde_json::json!({"status": "unknown"}),
        );
        let before = view.clone();
        let expected = serde_json::json!({
            "build": {"artifact_digest": "a".repeat(64)},
            "generation": {"generation": 3, "authority_epoch": "epoch-canary"},
            "ors": {"status": "degraded"},
            "incident": {"status": "unknown"},
        });

        let (captured, response) =
            capture_with(|| KernelComposition::recovery_view_response(&view));
        assert_health_observation_sequence(
            &captured,
            &[("kernel.health.recovery_view_projected", "known")],
        );
        assert_eq!(response, expected);
        assert_eq!(view, before, "view projection is read-only");
        assert_eq!(
            response,
            KernelComposition::recovery_view_response(&view),
            "the observation must not alter the restricted recovery projection"
        );
    }

    #[test]
    fn semantic_recovery_deferral_records_the_composition_owned_unavailability() {
        let fixture = plain_composition("semantic-recovery-deferred");
        let availability = fixture.kernel.observed_kernel_availability();
        assert_eq!(
            availability,
            KernelAvailability::Unavailable,
            "the fresh composition's own cold service provides the unavailable reading"
        );

        let (captured, deferral) = capture_with(|| {
            KernelComposition::deferred_semantic_recovery(availability)
        });
        assert_health_observation_sequence(
            &captured,
            &[("kernel.health.semantic_recovery_deferred", "known")],
        );
        assert_eq!(deferral, semantic_task_recovery_deferral());
        assert_eq!(
            deferral.reason,
            "semantic task recovery deferred pending canonical access"
        );
    }

    /// Map row 24 (`WORK_UNIT_CASE 903/24`): span
    /// `kernel.health.route_metrics_projected` on
    /// `KernelComposition::daemon_route_metrics_projection`, stage
    /// `health_denominator`. I16.11: "Silent success is forbidden." I16.5 lists
    /// "queue depth/age/bytes and WIP admission" under System and "event
    /// gaps/cursor lag/normalization loss" under Agent/Harness/Route, which is
    /// the denominator this view projects at `health_view.rs:374`-`:384` and
    /// `:385`-`:423`. I1.10: "A component is `READY` only for the capabilities
    /// whose required dimensions pass."
    ///
    /// Both CALL SITES are pinned by the pair they actually pass, not by the
    /// generic sink at `:30`: the measured leg pins `:424` with the outcome the
    /// production chain read selects, and the unreadable leg pins `:328`. The
    /// measured leg's expectation is taken from the SAME production owner's own
    /// reading (`audit_chain_records`, the call the view makes at `:385`), so the
    /// assertion is owner-against-owner and names no arm this fixture cannot
    /// justify: on a freshly built composition `KernelAuditChain::open` creates
    /// an empty retained chain (`kernel_audit.rs:2418`-`:2421`), which verifies,
    /// so the measured leg is the `"success"` arm of `:415` - the `"degraded"`
    /// arm at `:421` needs a poisoned chain guard or a retained chain that does
    /// not verify, and nothing here induces either. The unreadable leg's
    /// expectation is the fixed production projection at `:329`, and it is paired
    /// with the presence of its own `(route_metrics, fenced)` pair plus the
    /// refusal to reuse the measured leg's outcome.
    #[test]
    fn route_metrics_projection_records_its_own_event_on_both_production_call_sites() {
        let fixture = plain_composition("route-metrics-event");
        // The production reader the view consults at health_view.rs:385, read
        // directly so the expected outcome is derived, never guessed.
        let measured_outcome = match fixture.kernel.audit_chain_records() {
            Ok(_) => "success",
            Err(_) => "degraded",
        }
        .to_owned();

        let (captured, projection) =
            capture_with(|| fixture.kernel.daemon_route_metrics_projection());
        assert_eq!(
            captured_event_outcome_pairs(&captured)
                .iter()
                .filter(|(event, outcome)| {
                    event == ROUTE_METRICS_EVENT && *outcome == measured_outcome
                })
                .count(),
            1,
            "health_view.rs:424 must record the route-metrics event exactly once, with the outcome the retained chain read selects ({measured_outcome}), got: {captured}"
        );
        assert_captured_surface_reads_no_stronger_claim(
            &captured,
            "the measured route-metrics leg",
        );
        let unobserved = fixture.kernel.daemon_route_metrics_projection();
        assert_eq!(
            projection, unobserved,
            "the diagnostic observation must change no projected byte of the route metrics"
        );

        poison_route_index_owner(&fixture.kernel);

        let (omitted_text, omitted) =
            capture_with(|| fixture.kernel.daemon_route_metrics_projection());
        assert_eq!(
            omitted,
            serde_json::json!({"status": "unknown"}),
            "an unreadable connection index must project the fixed unknown answer, got: {omitted_text}"
        );
        assert_eq!(
            captured_event_outcome_pairs(&omitted_text),
            vec![(ROUTE_METRICS_EVENT.to_owned(), "fenced".to_owned())],
            "health_view.rs:328 must record the fenced route-metrics event as the only observation on this leg, got: {omitted_text}"
        );
        assert!(
            !captured_field_values(&omitted_text, "outcome").contains(&measured_outcome),
            "an unreadable connection index must never reuse the measured leg's outcome {measured_outcome}, got: {omitted_text}"
        );
        assert_captured_surface_reads_no_stronger_claim(
            &omitted_text,
            "the fenced route-metrics leg",
        );
        let omitted_unobserved = fixture.kernel.daemon_route_metrics_projection();
        assert_eq!(
            omitted, omitted_unobserved,
            "the diagnostic observation must change no projected byte on the unreadable leg either"
        );
    }
}
