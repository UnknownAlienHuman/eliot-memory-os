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
use eliot_kernel_core::{CutoverDecision, GenerationRouter};
use eliot_kernel_service::KernelServiceError;

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
}
