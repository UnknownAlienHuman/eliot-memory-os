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

fn fence_service_after_generation_failure(
    service: &std::sync::Arc<std::sync::Mutex<eliot_kernel_service::KernelService>>,
    reason: impl Into<String>,
) -> Result<(), KernelServiceError> {
    let mut service = service
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    service.fence_generation(reason)
}

impl KernelComposition {
    /// Returns a cloned, read-only route projection.  Callers cannot obtain a
    /// mutable router guard or bypass the ORS transition gateway.
    pub fn generation_route_snapshot(&self) -> Result<GenerationRouter, KernelServiceError> {
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
    pub fn apply_generation_cutover(
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
}
