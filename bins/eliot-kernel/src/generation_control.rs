//! Kernel generation control gateway.
//!
//! Closed generation-route snapshot and single cutover publish path owned by
//! [`crate::KernelComposition`]. Snapshot returns a cloned router; cutover
//! fences the composition on any persist/publish failure and never retries
//! with a stale route.
//!
//! Architecture: A5.4 Time и State Fence; A13.2 Kernel и failure domains; A13.3 Module supervision и Doctor; ARCH-AUTH-01; ARCH-RES-03; ARCH-RES-04
//! Implementation: I4.5 Generation vector and State Fence; I5.6 Admission and staging; I14.14 Module hot replacement; I14.15 Daemon hot replacement; I14.16 Kernel and Host update; I14.21 Unknown commit recovery
//! Ordinary module: I2.23 Capability-family topology and crate extraction decisions — ordinary single-file extraction (<10k LOC) owning only `KernelComposition::generation_route_snapshot` and `KernelComposition::apply_generation_cutover` plus inseparable fencing with zero external users; no new crate.
//! Forbidden authority: must not perform semantic planning, must not allow an alternate epoch owner, must not resurrect stale routes; publishes only the ORS-committed candidate via `OrsGenerationCoordinator` and fences on failure.

use super::KernelComposition;
use eliot_contracts::{EpochId, ResourceGeneration, StateFence, canonical_json_bytes, sha256_hex};
use eliot_kernel_core::{CutoverDecision, GenerationRoute, GenerationRouter, RouteScope};
use eliot_kernel_service::KernelServiceError;
use serde::{Deserialize, Serialize};

/// Authenticated daemon operation used by Governor to obtain the mechanical
/// active-generation projection for one startup window.
///
/// The operation is served by the existing authenticated daemon dispatch
/// channel. This is a selector, not a second transport or an authority.
pub const ACTIVE_GENERATION_REGISTRY_QUERY_OPERATION: &str = "daemon_generation_projection";

/// Exact request payload for [`ACTIVE_GENERATION_REGISTRY_QUERY_OPERATION`].
///
/// Governor must present the fence it is using for the startup evidence
/// observation. The authenticated session boundary supplies the peer and
/// process binding; this payload only narrows the requested route and fence.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ActiveGenerationRegistryQuery {
    /// Version of the authenticated projection request.
    pub version: u8,
    /// Exact State Fence carried by the admitted daemon session.
    pub state_fence: StateFence,
}

impl ActiveGenerationRegistryQuery {
    /// Validates the closed query shape before it reaches the route table.
    pub fn validate(&self) -> Result<(), KernelServiceError> {
        if self.version != 1 {
            return Err(KernelServiceError::InvalidField {
                field: "generation_registry.query.version",
                reason: "unsupported projection request version",
            });
        }
        self.state_fence
            .validate()
            .map_err(|_| KernelServiceError::InvalidField {
                field: "generation_registry.query.state_fence",
                reason: "state fence is invalid",
            })?;
        Ok(())
    }
}

/// Kernel-owned read projection of one active generation route.
///
/// This is a mechanical query result, not a new authority. The route comes
/// from the canonical [`GenerationRouter`], while the fence comes from the
/// live Kernel service epoch. The fingerprint therefore changes whenever the
/// route, lineage-aware epoch, or exact fence changes.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ActiveGenerationRegistryProjection {
    route_scope: String,
    active_generation: ResourceGeneration,
    authority_epoch: EpochId,
    state_fence: StateFence,
    generation_fingerprint: String,
}

/// Closed response value returned by the authenticated Governor projection
/// query. Generation and epoch remain inside the exact `StateFence`; the
/// fingerprint is the only derived scalar crossing this wire.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ActiveGenerationRegistryResponse {
    /// Version of the authenticated projection response.
    pub version: u8,
    /// Kernel-owned canonical projection fingerprint.
    pub fingerprint: String,
    /// Exact `StateFence` used to compute the fingerprint.
    pub state_fence: StateFence,
}

#[derive(Serialize)]
struct ActiveGenerationFingerprintPreimage<'a> {
    route_scope: &'a str,
    active_generation: ResourceGeneration,
    authority_epoch: &'a EpochId,
    state_fence: &'a StateFence,
}

impl ActiveGenerationRegistryProjection {
    fn from_route(
        route: &GenerationRoute,
        state_fence: StateFence,
    ) -> Result<Self, KernelServiceError> {
        // Exact tuple equality is the authorization rule (Implements #64):
        // the route carries the canonical `EpochId`, so a restore that minted
        // a different lineage at the same sequence is unrelated and is refused
        // here instead of matching on the number.
        if state_fence.resource_generation != route.active_generation()
            || !state_fence
                .authority_epoch
                .is_same_authority(route.authority_epoch())
        {
            return Err(KernelServiceError::HandshakeMismatch {
                field: "generation_registry.state_fence",
            });
        }

        let route_scope = route.route_scope().as_str().to_owned();
        let preimage = ActiveGenerationFingerprintPreimage {
            route_scope: &route_scope,
            active_generation: route.active_generation(),
            authority_epoch: &state_fence.authority_epoch,
            state_fence: &state_fence,
        };
        let bytes = canonical_json_bytes(&preimage).map_err(|_| {
            KernelServiceError::Platform(
                "generation registry fingerprint encoding failed".to_owned(),
            )
        })?;
        let generation_fingerprint = sha256_hex(&bytes);

        Ok(Self {
            route_scope,
            active_generation: route.active_generation(),
            authority_epoch: state_fence.authority_epoch.clone(),
            state_fence,
            generation_fingerprint,
        })
    }

    /// Returns the canonical route scope represented by this projection.
    #[must_use]
    pub fn route_scope(&self) -> &str {
        &self.route_scope
    }

    /// Returns the active resource generation from the Kernel route table.
    #[must_use]
    pub const fn active_generation(&self) -> ResourceGeneration {
        self.active_generation
    }

    /// Returns the lineage-aware epoch bound to the projection.
    #[must_use]
    pub fn authority_epoch(&self) -> &EpochId {
        &self.authority_epoch
    }

    /// Returns the exact fence that was used to build the projection.
    #[must_use]
    pub const fn state_fence(&self) -> &StateFence {
        &self.state_fence
    }

    /// Returns the lowercase SHA-256 fingerprint for the exact projection.
    #[must_use]
    pub fn generation_fingerprint(&self) -> &str {
        &self.generation_fingerprint
    }

    /// Projects the internal route calculation onto the closed Governor wire.
    #[must_use]
    pub fn response(&self) -> ActiveGenerationRegistryResponse {
        ActiveGenerationRegistryResponse {
            version: 1,
            fingerprint: self.generation_fingerprint.clone(),
            state_fence: self.state_fence.clone(),
        }
    }
}

fn validate_active_generation_query(
    query: &ActiveGenerationRegistryQuery,
    authenticated_session_fence: &StateFence,
) -> Result<(), KernelServiceError> {
    query.validate()?;
    if &query.state_fence != authenticated_session_fence {
        return Err(KernelServiceError::HandshakeMismatch {
            field: "generation_registry.query.session_fence",
        });
    }
    Ok(())
}

/// F-LOG-KERNEL-4 (#903): generation-gateway boundary observations.
///
/// Observation only, via #895's facade: fixed `kernel.generation.*` event
/// names plus a bounded stable outcome. Never carries route contents,
/// generation values, epoch/fence material, digests, or owner error strings
/// (I15.4, I07.20). Candidate, staged, active, and current stay distinct:
/// a snapshot read is never logged as a cutover, and a cutover request is
/// never logged as observed activation.
fn observe_generation(event: &'static str, outcome: &'static str) {
    use super::kernel_diagnostics::{KERNEL_DIAGNOSTICS_TARGET, bound_field};
    let event_bound = bound_field(event);
    let outcome_bound = bound_field(outcome);
    tracing::info!(
        target: KERNEL_DIAGNOSTICS_TARGET,
        event = event_bound.text(),
        outcome = outcome_bound.text(),
        "generation gateway observation"
    );
}

/// Maps one generation-route snapshot failure to its stable diagnostic code.
///
/// Only the variant is emitted; any `String` payload is never logged.
fn generation_snapshot_terminal_code(error: &KernelServiceError) -> &'static str {
    match error {
        KernelServiceError::InvalidField { .. } => "SNAPSHOT_INVALID_FIELD",
        KernelServiceError::IllegalTransition { .. } => "SNAPSHOT_ILLEGAL_TRANSITION",
        KernelServiceError::HandshakeMismatch { .. } => "SNAPSHOT_HANDSHAKE_MISMATCH",
        KernelServiceError::MissingContainmentEvidence => "SNAPSHOT_MISSING_CONTAINMENT",
        KernelServiceError::ReadinessNotProven => "SNAPSHOT_READINESS_NOT_PROVEN",
        KernelServiceError::AdmissionClosed(_) => "SNAPSHOT_ADMISSION_CLOSED",
        KernelServiceError::GenerationFenced => "SNAPSHOT_GENERATION_FENCED",
        KernelServiceError::RestartBudgetExhausted => "SNAPSHOT_RESTART_BUDGET_EXHAUSTED",
        KernelServiceError::ControlReserveExhausted => "SNAPSHOT_RESERVE_EXHAUSTED",
        KernelServiceError::Platform(_) => "SNAPSHOT_PLATFORM",
        KernelServiceError::Core(_) => "SNAPSHOT_CORE",
    }
}

/// Maps one generation-cutover failure to its stable diagnostic code.
///
/// Only the variant is emitted; any `String` payload (including the fence
/// reason retained by the gateway) is never logged.
fn generation_cutover_terminal_code(error: &KernelServiceError) -> &'static str {
    match error {
        KernelServiceError::InvalidField { .. } => "CUTOVER_INVALID_FIELD",
        KernelServiceError::IllegalTransition { .. } => "CUTOVER_ILLEGAL_TRANSITION",
        KernelServiceError::HandshakeMismatch { .. } => "CUTOVER_HANDSHAKE_MISMATCH",
        KernelServiceError::MissingContainmentEvidence => "CUTOVER_MISSING_CONTAINMENT",
        KernelServiceError::ReadinessNotProven => "CUTOVER_READINESS_NOT_PROVEN",
        KernelServiceError::AdmissionClosed(_) => "CUTOVER_ADMISSION_CLOSED",
        KernelServiceError::GenerationFenced => "CUTOVER_GENERATION_FENCED",
        KernelServiceError::RestartBudgetExhausted => "CUTOVER_RESTART_BUDGET_EXHAUSTED",
        KernelServiceError::ControlReserveExhausted => "CUTOVER_RESERVE_EXHAUSTED",
        KernelServiceError::Platform(_) => "CUTOVER_PLATFORM",
        KernelServiceError::Core(_) => "CUTOVER_CORE",
    }
}

fn fence_service_after_generation_failure(
    service: &std::sync::Arc<std::sync::Mutex<eliot_kernel_service::KernelService>>,
    reason: impl Into<String>,
) -> Result<(), KernelServiceError> {
    // F-LOG-KERNEL-4 (#903): subordinate fence observation; the cutover
    // gateway owns the single terminal for the failed cutover. Only the
    // fence outcome is logged, never the reason body.
    observe_generation("kernel.generation.service_fence_requested", "attempt");
    let mut service = service
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let result = service.fence_generation(reason);
    match &result {
        Ok(()) => observe_generation("kernel.generation.service_fenced", "success"),
        Err(_) => observe_generation("kernel.generation.service_fence_rejected", "rejected"),
    }
    result
}

impl KernelComposition {
    /// Executes the authenticated R4 query against the live Kernel fence and
    /// canonical `GenerationRouter`. The caller's session fence must match the
    /// query fence exactly; a compatible-but-different fence is still stale
    /// for this startup observation.
    pub fn active_generation_registry_query(
        &self,
        query: &ActiveGenerationRegistryQuery,
        authenticated_session_fence: &StateFence,
    ) -> Result<ActiveGenerationRegistryProjection, KernelServiceError> {
        validate_active_generation_query(query, authenticated_session_fence)?;
        let projection = self.active_generation_registry_projection("daemon")?;
        if projection.state_fence() != authenticated_session_fence {
            return Err(KernelServiceError::HandshakeMismatch {
                field: "generation_registry.query.live_fence",
            });
        }
        Ok(projection)
    }

    /// Reads the active generation projection from the canonical Kernel route.
    ///
    /// The route's lineage-aware epoch must be the exact same tuple as the live
    /// service epoch before a fence or fingerprint is returned. A missing
    /// route, cross-lineage epoch, poisoned boundary, or non-exact tuple fails
    /// closed.
    pub fn active_generation_registry_projection(
        &self,
        route_scope: &str,
    ) -> Result<ActiveGenerationRegistryProjection, KernelServiceError> {
        let router = self.generation_route_snapshot()?;
        let route_scope = RouteScope::new(route_scope.to_owned()).map_err(|_| {
            KernelServiceError::InvalidField {
                field: "generation_registry.route_scope",
                reason: "route scope is invalid",
            }
        })?;
        let route =
            router
                .route(&route_scope)
                .map_err(|_| KernelServiceError::HandshakeMismatch {
                    field: "generation_registry.route",
                })?;
        let live_epoch = self
            .service
            .lock()
            .map_err(|_| KernelServiceError::Platform("service lock poisoned".to_owned()))?
            .authority_epoch();
        if !route.authority_epoch().is_same_authority(&live_epoch) {
            return Err(KernelServiceError::HandshakeMismatch {
                field: "generation_registry.authority_epoch",
            });
        }
        let state_fence = StateFence::new(live_epoch, route.active_generation());
        ActiveGenerationRegistryProjection::from_route(route, state_fence)
    }

    /// Checks one authenticated Governor fingerprint against the live Kernel
    /// generation projection and its exact admitted fence.
    ///
    /// This comparison is mechanical. It does not mark startup readiness or
    /// interpret Governor capability semantics.
    pub fn verify_active_generation_registry_fingerprint(
        &self,
        route_scope: &str,
        admitted_fence: &StateFence,
        presented_fingerprint: &str,
    ) -> Result<(), KernelServiceError> {
        let projection = self.active_generation_registry_projection(route_scope)?;
        if projection.state_fence() != admitted_fence {
            return Err(KernelServiceError::HandshakeMismatch {
                field: "generation_registry.admitted_fence",
            });
        }
        if projection.generation_fingerprint() != presented_fingerprint {
            return Err(KernelServiceError::HandshakeMismatch {
                field: "generation_registry.fingerprint",
            });
        }
        Ok(())
    }

    /// Returns a cloned, read-only route projection.  Callers cannot obtain a
    /// mutable router guard or bypass the ORS transition gateway.
    ///
    /// Diagnostic wrapper (F-LOG-KERNEL-4, #903): exactly one terminal is
    /// emitted per failed read; the cloned projection versus a fenced
    /// gateway stay distinct, and no route, generation, or fence material
    /// is logged.
    pub fn generation_route_snapshot(&self) -> Result<GenerationRouter, KernelServiceError> {
        observe_generation("kernel.generation.snapshot_requested", "attempt");
        match self.generation_route_snapshot_inner() {
            Ok(router) => {
                observe_generation("kernel.generation.snapshot_committed", "success");
                Ok(router)
            }
            Err(error) => {
                observe_generation("kernel.generation.snapshot_failed", "rejected");
                super::kernel_diagnostics::observe_terminal_error(
                    generation_snapshot_terminal_code(&error),
                );
                Err(error)
            }
        }
    }

    /// Read-only clone sequence; the fence check precedes the router clone.
    /// See [`KernelComposition::generation_route_snapshot`].
    fn generation_route_snapshot_inner(&self) -> Result<GenerationRouter, KernelServiceError> {
        if let Some(reason) = self
            .generation_poison
            .lock()
            .map_err(|_| {
                KernelServiceError::Platform("generation poison lock poisoned".to_owned())
            })?
            .clone()
        {
            return Err(KernelServiceError::Platform(format!(
                "generation gateway fenced: {reason}"
            )));
        }
        self.generations
            .lock()
            .map(|router| router.clone())
            .map_err(|_| KernelServiceError::Platform("generation lock poisoned".to_owned()))
    }

    /// Persists and publishes one epoch-raising generation cutover through the
    /// sole semantic gateway.  A failed publish permanently fences this
    /// composition instance until restart/recovery proves a durable route.
    ///
    /// Diagnostic wrapper (F-LOG-KERNEL-4, #903): exactly one terminal is
    /// emitted per failed cutover; the cutover request versus the owner's
    /// durable receipt stay distinct, and no decision, route, epoch, or
    /// fence material is logged.
    pub fn apply_generation_cutover(
        &self,
        decision: &CutoverDecision,
    ) -> Result<(), KernelServiceError> {
        observe_generation("kernel.generation.cutover_requested", "attempt");
        match self.apply_generation_cutover_inner(decision) {
            Ok(()) => {
                observe_generation("kernel.generation.cutover_committed", "success");
                Ok(())
            }
            Err(error) => {
                observe_generation("kernel.generation.cutover_failed", "rejected");
                super::kernel_diagnostics::observe_terminal_error(
                    generation_cutover_terminal_code(&error),
                );
                Err(error)
            }
        }
    }

    /// Fenced persist-and-publish sequence; any publish failure fences this
    /// composition before returning. See
    /// [`KernelComposition::apply_generation_cutover`].
    fn apply_generation_cutover_inner(
        &self,
        decision: &CutoverDecision,
    ) -> Result<(), KernelServiceError> {
        let mut poison = self.generation_poison.lock().map_err(|_| {
            KernelServiceError::Platform("generation poison lock poisoned".to_owned())
        })?;
        if let Some(reason) = poison.clone() {
            return Err(KernelServiceError::Platform(format!(
                "generation gateway fenced: {reason}"
            )));
        }
        let result = (|| {
            let mut generations = self
                .generations
                .lock()
                .map_err(|_| "generation lock poisoned".to_owned())?;
            let mut service = self
                .service
                .lock()
                .map_err(|_| "service lock poisoned".to_owned())?;
            let mut policy = self
                .front_door_policy
                .lock()
                .map_err(|_| "front-door policy lock poisoned".to_owned())?;
            self.generation_gateway.persist_and_publish(
                decision,
                &mut generations,
                &mut service,
                &mut policy,
            )
        })();
        if let Err(reason) = result {
            *poison = Some(reason.clone());
            if let Err(fence_error) =
                fence_service_after_generation_failure(&self.service, reason.clone())
            {
                return Err(KernelServiceError::Platform(format!(
                    "generation cutover failed and service fencing failed: {fence_error}"
                )));
            }
            return Err(KernelServiceError::Platform(format!(
                "generation cutover fenced: {reason}"
            )));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::sync::{Arc, Mutex};

    #[derive(Clone, Default)]
    struct CaptureSink {
        bytes: Arc<Mutex<Vec<u8>>>,
    }

    impl Write for CaptureSink {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.bytes
                .lock()
                .map_err(|_| std::io::Error::other("capture lock poisoned"))?
                .extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[allow(clippy::expect_used, clippy::unwrap_used)]
    fn capture(run: impl FnOnce()) -> String {
        let sink = CaptureSink::default();
        let writer_sink = sink.clone();
        {
            let subscriber = tracing_subscriber::fmt()
                .with_ansi(false)
                .with_writer(move || writer_sink.clone())
                .finish();
            tracing::subscriber::with_default(subscriber, run);
        }
        String::from_utf8_lossy(&sink.bytes.lock().expect("capture lock")).into_owned()
    }

    #[test]
    fn poisoned_service_lock_is_recovered_and_fenced() {
        let service = std::sync::Arc::new(std::sync::Mutex::new(
            eliot_kernel_service::KernelService::new([37; 32], 2, 4)
                .unwrap_or_else(|_| unreachable!()),
        ));
        let poisoned = std::sync::Arc::clone(&service);
        let _ = std::thread::spawn(move || {
            let _guard = poisoned.lock().unwrap_or_else(|_| unreachable!());
            panic!("force service lock poisoning");
        })
        .join();

        let result = fence_service_after_generation_failure(&service, String::new());
        assert!(result.is_ok(), "unexpected fencing failure: {result:?}");

        let service = service
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        assert!(service.generation_fenced());
        assert!(matches!(
            service.failure(),
            Some(eliot_kernel_service::ServiceFailure::Contract(reason))
                if reason == "generation fence reason was invalid; canonical reason substituted"
        ));
    }

    #[test]
    fn generation_diagnostics_codes_are_stable_and_fence_observation_is_canary_free() {
        // F-LOG-KERNEL-4 (#903): snapshot and cutover failures keep distinct
        // stable codes per variant; only the code may be logged, never the
        // fence reason or any route/epoch material.
        assert_eq!(
            generation_snapshot_terminal_code(&KernelServiceError::GenerationFenced),
            "SNAPSHOT_GENERATION_FENCED"
        );
        assert_eq!(
            generation_snapshot_terminal_code(&KernelServiceError::ControlReserveExhausted),
            "SNAPSHOT_RESERVE_EXHAUSTED"
        );
        assert_eq!(
            generation_snapshot_terminal_code(&KernelServiceError::Platform(
                "fence-canary-snapshot".to_owned()
            )),
            "SNAPSHOT_PLATFORM"
        );
        assert_eq!(
            generation_cutover_terminal_code(&KernelServiceError::GenerationFenced),
            "CUTOVER_GENERATION_FENCED"
        );
        assert_eq!(
            generation_cutover_terminal_code(&KernelServiceError::ControlReserveExhausted),
            "CUTOVER_RESERVE_EXHAUSTED"
        );
        assert_eq!(
            generation_cutover_terminal_code(&KernelServiceError::ReadinessNotProven),
            "CUTOVER_READINESS_NOT_PROVEN"
        );
        assert_eq!(
            generation_cutover_terminal_code(&KernelServiceError::Platform(
                "fence-canary-cutover".to_owned()
            )),
            "CUTOVER_PLATFORM"
        );

        // The fence observation carries fixed vocabulary only: the canary
        // reason retained by the service never reaches the sink, and the
        // fencing behavior itself is unchanged.
        let service = std::sync::Arc::new(std::sync::Mutex::new(
            eliot_kernel_service::KernelService::new([41; 32], 2, 4)
                .unwrap_or_else(|_| unreachable!()),
        ));
        let text = capture(|| {
            observe_generation("kernel.generation.cutover_requested", "attempt");
            let fenced =
                fence_service_after_generation_failure(&service, "fence-canary-service-reason-903");
            assert!(fenced.is_ok());
            crate::kernel_diagnostics::observe_terminal_error(generation_cutover_terminal_code(
                &KernelServiceError::GenerationFenced,
            ));
        });
        for marker in [
            "kernel.generation.cutover_requested",
            "kernel.generation.service_fence_requested",
            "kernel.generation.service_fenced",
            "CUTOVER_GENERATION_FENCED",
        ] {
            assert!(text.contains(marker), "missing diagnostics marker {marker}");
        }
        for canary in [
            "fence-canary-service-reason-903",
            "fence-canary-snapshot",
            "fence-canary-cutover",
        ] {
            assert!(
                !text.contains(canary),
                "diagnostics leaked fenced material {canary}"
            );
        }
        assert!(
            service
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .generation_fenced()
        );
    }

    fn test_epoch(sequence: u64) -> EpochId {
        EpochId::new(
            eliot_contracts::EpochLineageId::new("550e8400-e29b-41d4-a716-446655440000")
                .expect("test lineage"),
            std::num::NonZeroU64::new(sequence).expect("test sequence"),
        )
        .expect("test epoch")
    }

    fn test_route(generation: u64) -> GenerationRoute {
        GenerationRoute::new(
            RouteScope::new("daemon").expect("test route scope"),
            ResourceGeneration::new(generation).expect("test generation"),
            test_epoch(4),
        )
        .expect("test route")
    }

    #[test]
    fn active_generation_projection_is_fenced_and_fingerprint_is_stable() {
        let epoch = test_epoch(4);
        let route = test_route(7);
        let fence = StateFence::new(epoch.clone(), route.active_generation());
        let projection = ActiveGenerationRegistryProjection::from_route(&route, fence.clone())
            .expect("matching route and fence");

        assert_eq!(projection.route_scope(), "daemon");
        assert_eq!(projection.active_generation().value(), 7);
        assert_eq!(projection.authority_epoch(), &epoch);
        assert_eq!(projection.state_fence(), &fence);
        assert_eq!(projection.generation_fingerprint().len(), 64);
        assert!(
            projection
                .generation_fingerprint()
                .chars()
                .all(|character| character.is_ascii_hexdigit() && !character.is_ascii_uppercase())
        );
        let response = serde_json::to_value(projection.response()).expect("wire response");
        let response_object = response.as_object().expect("closed response object");
        assert_eq!(response_object.len(), 3);
        assert!(response_object.contains_key("version"));
        assert!(response_object.contains_key("fingerprint"));
        assert!(response_object.contains_key("state_fence"));

        let repeat = ActiveGenerationRegistryProjection::from_route(&route, fence)
            .expect("same canonical state");
        assert_eq!(projection, repeat);

        let changed_route = test_route(8);
        let changed_fence = StateFence::new(test_epoch(4), changed_route.active_generation());
        let changed = ActiveGenerationRegistryProjection::from_route(&changed_route, changed_fence)
            .expect("changed active generation");
        assert_ne!(
            projection.generation_fingerprint(),
            changed.generation_fingerprint()
        );
    }

    #[test]
    fn active_generation_projection_rejects_cross_generation_fence() {
        let route = test_route(7);
        let foreign_fence = StateFence::new(
            test_epoch(4),
            ResourceGeneration::new(8).expect("foreign generation"),
        );

        assert!(matches!(
            ActiveGenerationRegistryProjection::from_route(&route, foreign_fence),
            Err(KernelServiceError::HandshakeMismatch {
                field: "generation_registry.state_fence"
            })
        ));
    }

    #[test]
    fn active_generation_query_accepts_exact_authenticated_fence() {
        let fence = StateFence::new(
            test_epoch(4),
            ResourceGeneration::new(7).expect("generation"),
        );
        let query = ActiveGenerationRegistryQuery {
            version: 1,
            state_fence: fence.clone(),
        };

        validate_active_generation_query(&query, &fence)
            .expect("exact authenticated fence is accepted");
    }

    #[test]
    fn active_generation_query_rejects_foreign_fence() {
        let query_fence = StateFence::new(
            test_epoch(4),
            ResourceGeneration::new(7).expect("query generation"),
        );
        let session_fence = StateFence::new(
            test_epoch(4),
            ResourceGeneration::new(8).expect("session generation"),
        );
        let query = ActiveGenerationRegistryQuery {
            version: 1,
            state_fence: query_fence,
        };

        assert!(matches!(
            validate_active_generation_query(&query, &session_fence),
            Err(KernelServiceError::HandshakeMismatch {
                field: "generation_registry.query.session_fence"
            })
        ));
    }

    #[test]
    fn active_generation_query_rejects_unsupported_version() {
        let fence = StateFence::new(
            test_epoch(4),
            ResourceGeneration::new(7).expect("generation"),
        );
        let query = ActiveGenerationRegistryQuery {
            version: 2,
            state_fence: fence.clone(),
        };

        assert!(matches!(
            validate_active_generation_query(&query, &fence),
            Err(KernelServiceError::InvalidField {
                field: "generation_registry.query.version",
                ..
            })
        ));
    }
}
